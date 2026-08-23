"""Account administration: creating accounts, changing passwords, and the
things an administrator is deliberately not allowed to do.

WHY THIS IS A MODULE AND NOT FIVE ROUTE BODIES
-----------------------------------------------
Every rule below is a refusal, and a refusal written inside a route body is a
refusal that the next route forgets. The route layer here does exactly two
things: read the session and call one of these functions.

THE THREE RULES THAT ARE NOT OBVIOUS
-------------------------------------
**A password change requires the current password**, even though the session
already proved a password and a second factor at login. Those prove who logged
in; they do not prove who is holding the cookie *now*. Without this rule a
stolen session becomes a permanent takeover — the thief sets a new password, the
owner is locked out of their own account, and the second factor does not help
because the thief never needs to pass it again. Requiring the current password
means a stolen cookie stays a stolen cookie: bad, but survivable, and it expires.

**The last administrator cannot be removed or demoted.** A password reset exists
now, but only an administrator can perform one — so an instance whose only
administrator is locked out has nobody left to ask, which is the state
`db/008_auth.sql` records as unrecoverable. Allowing the last one to be disabled
would make it reachable by a single misclick, and the only repair is hand-editing
the database of a running production system.

**An administrator creates accounts in their OWN organisation, never a chosen
one.** The org is read from the session and the caller cannot pass it. If it
were a parameter, one tenant's administrator could plant an account inside
another tenant — which is precisely the boundary migration 006 exists to hold,
defeated through the front door rather than through SQL.

WHAT AN ADMINISTRATOR IS NOT
-----------------------------
Being able to create accounts confers no authority over any estate. `core/gate.py`
decides what may be done to an asset, knows nothing about users, and is not
consulted here — `is_admin` appears nowhere in the authorisation path for
scanning. An administrator who wants to probe a host still has to verify
ownership like everybody else.

WHAT AN ADMINISTRATOR *CAN* DO, STATED PLAINLY
-----------------------------------------------
An administrator who resets both a password and a second factor can sign in as
that user. That is a real takeover path and this module does not pretend
otherwise.

An earlier version of this file did pretend otherwise. It offered no password
reset at all, on the reasoning that an administrator who cannot set a password
cannot become you — which was true, and cost more than it was worth: a forgotten
password meant a permanently dead account whose username, globally unique under
`db/008_auth.sql`, could never be reused. A product that answers "I forgot my
password" with "your account is gone" gets worked around by people sharing
credentials, which is a worse outcome than an administrator power that is
bounded and recorded.

So the power exists, and three things bound it:

- the administrator does not CHOOSE the password — it is generated here, so the
  house pattern that makes every account on an instance guessable never forms;
- the account is locked to the change form until its owner replaces it, so the
  window in which the administrator's copy is usable is as short as the user
  makes it;
- both halves are separate, deliberate actions and **both are written to the
  audit chain**, so the takeover is reconstructable afterwards even though it is
  not preventable.

`reset_second_factor` alone still issues nothing an administrator can sign in
with: it clears an enrolment so the user can enrol their own authenticator, and
produces no code, secret or recovery credential.
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional

from core import authn

#: Unambiguous by construction — no O/0, no I/l/1. An initial credential gets
#: read down a phone line or copied off a screen, and a password that cannot be
#: transcribed reliably gets replaced with a weak one the user can type.
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"

#: Four groups of four. 16 characters comfortably clears
#: `authn.MIN_PASSWORD_LENGTH`, and the grouping is what makes it transcribable.
_GROUPS, _GROUP_LEN = 4, 4


class NotPermitted(PermissionError):
    """The caller may not do this. Distinct from 'that is impossible'."""


class AccountRefused(ValueError):
    """The request is well-formed and must still not be carried out."""


def issue_initial_password() -> str:
    """A one-time credential for a new account.

    Generated here rather than chosen by the administrator, for one reason: an
    administrator choosing passwords picks a house pattern, and a house pattern
    means every account on the instance shares a guessable prefix. It is still
    a credential the administrator has seen — which is why every account created
    this way carries `must_change_password`, and is not the user's own account
    until they have changed it.
    """
    return "-".join(
        "".join(secrets.choice(_ALPHABET) for _ in range(_GROUP_LEN))
        for _ in range(_GROUPS))


def require_admin(session: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The session, if it may administer accounts. Otherwise `NotPermitted`.

    Deliberately gives the same message either way. 'You are not an
    administrator' and 'you are not logged in' are different facts, and telling
    an unauthenticated caller which one applies confirms that the endpoint is
    real and that administrators exist to be targeted.
    """
    if not session or not session.get("is_admin"):
        raise NotPermitted("account administration requires an administrator")
    return session


def plan_creation(session: Dict[str, Any], username: str,
                  display_name: str = "") -> Dict[str, Any]:
    """Validate a creation request against the caller's session.

    Returns the arguments the store should be called with — including the org,
    which comes from the session and cannot be supplied by the caller.
    """
    require_admin(session)
    name = str(username or "").strip().lower()
    if not name:
        raise AccountRefused("a username is required")
    if len(name) > 128:
        raise AccountRefused("that username is too long")
    # A username that differs from another only by whitespace or case is an
    # invitation to authorise the wrong person; the store lowercases and this
    # refuses the rest.
    if any(ch.isspace() for ch in name):
        raise AccountRefused("a username cannot contain spaces")
    return {
        "username": name,
        "display_name": str(display_name or "").strip()[:128] or name,
        "org_id": session["org_id"],
        "created_by": session["username"],
        "password": issue_initial_password(),
    }


def check_change(session: Dict[str, Any], current: str, new: str) -> None:
    """Refuse a password change before the store is touched.

    `authn.check_password_policy` owns strength. This owns the two rules that
    are about the *change* rather than the password.
    """
    if not session:
        raise NotPermitted("a session is required")
    if not current:
        # Enforced here as well as at the store, because a caller omitting the
        # field entirely must not reach a code path that could treat an empty
        # current password as 'no password set'.
        raise AccountRefused("your current password is required")
    if current == new:
        raise AccountRefused("the new password must differ from the current one")
    authn.check_password_policy(new)          # raises WeakPassword


def check_disable(session: Dict[str, Any], target: Dict[str, Any],
                  admin_count: int) -> None:
    """Refuse a disable that would lock somebody — or everybody — out."""
    require_admin(session)
    if int(target["id"]) == int(session["user_id"]):
        raise AccountRefused(
            "you cannot disable your own account; ask another administrator")
    if target.get("is_admin") and admin_count <= 1:
        raise AccountRefused(
            "that is the only administrator on this instance. Disabling it "
            "would leave nobody able to create accounts, and there is no "
            "recovery path — promote another administrator first")
    if str(target.get("org_id")) != str(session["org_id"]):
        # Should be unreachable: the store lists only the caller's org. Kept as
        # a guard because 'unreachable' is a property of today's callers.
        raise NotPermitted("that account is not in your organisation")


def check_role_change(session: Dict[str, Any], target: Dict[str, Any],
                      make_admin: bool, admin_count: int) -> None:
    """Refuse a demotion that removes the last administrator."""
    require_admin(session)
    if str(target.get("org_id")) != str(session["org_id"]):
        raise NotPermitted("that account is not in your organisation")
    if not make_admin and target.get("is_admin") and admin_count <= 1:
        raise AccountRefused(
            "that is the only administrator on this instance; promote another "
            "before demoting this one")
    if (not make_admin and int(target["id"]) == int(session["user_id"])
            and admin_count <= 1):
        raise AccountRefused("you are the only administrator")


def check_reset_password(session: Dict[str, Any],
                         target: Dict[str, Any]) -> None:
    """An administrator may issue somebody a new one-time password.

    Refused against your own account — not because it would be dangerous, but
    because it is the wrong tool: you know your current password, so
    `check_change` is the path, and it does not revoke the session you are
    sitting in.
    """
    require_admin(session)
    if str(target.get("org_id")) != str(session["org_id"]):
        raise NotPermitted("that account is not in your organisation")
    if int(target["id"]) == int(session["user_id"]):
        raise AccountRefused(
            "use the change-password form for your own account; a reset would "
            "sign you out and hand you a password you then have to change")


def check_reset_second_factor(session: Dict[str, Any],
                              target: Dict[str, Any]) -> None:
    """An administrator may clear an enrolment. That is all.

    The user then enrols their own authenticator at next login. Nothing here
    produces a code, a secret or a recovery credential that the administrator
    could use to sign in as them — an administrator who could do that would be
    able to impersonate any user in the organisation silently, which is a
    larger power than 'can create accounts' and is not the one being granted.
    """
    require_admin(session)
    if str(target.get("org_id")) != str(session["org_id"]):
        raise NotPermitted("that account is not in your organisation")


def describe(user: Dict[str, Any], *, self_id: Optional[int] = None) -> Dict[str, Any]:
    """A user as the console should see one. No secret material, ever.

    `totp_secret` and `password_hash` are not omitted by the caller remembering
    to omit them — they are absent from what this builds, so a new field added
    to the query cannot leak by default.
    """
    enrolled = user.get("totp_enrolled_at")
    return {
        "username": user["username"],
        "display_name": user.get("display_name") or user["username"],
        "is_admin": bool(user.get("is_admin")),
        "disabled": user.get("disabled_at") is not None,
        "second_factor": "enrolled" if enrolled else "not enrolled",
        "must_change_password": bool(user.get("must_change_password")),
        "created_at": (user["created_at"].isoformat()
                       if user.get("created_at") else None),
        "created_by": user.get("created_by"),
        "last_login_at": (user["last_login_at"].isoformat()
                          if user.get("last_login_at") else None),
        "is_you": self_id is not None and int(user["id"]) == int(self_id),
    }


def summarise(users: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Counts an administrator needs before deciding anything.

    `never_signed_in` is the one worth surfacing: an account created and never
    used is either a colleague who never received their credential, or an
    account nobody needed. Both want attention; neither shows up in a total.
    """
    return {
        "total": len(users),
        "administrators": sum(1 for u in users if u["is_admin"]),
        "disabled": sum(1 for u in users if u["disabled"]),
        "awaiting_second_factor": sum(
            1 for u in users
            if u["second_factor"] == "not enrolled" and not u["disabled"]),
        "never_signed_in": sum(
            1 for u in users if u["last_login_at"] is None and not u["disabled"]),
    }


__all__ = ["NotPermitted", "AccountRefused", "issue_initial_password",
           "require_admin", "plan_creation", "check_change", "check_disable",
           "check_role_change", "check_reset_password",
           "check_reset_second_factor", "describe", "summarise"]
