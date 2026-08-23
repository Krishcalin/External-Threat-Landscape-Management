"""Account administration over HTTP.

Thin by design. `core/accounts.py` owns every rule and every refusal; this
translates them into status codes and nothing else. If a decision appears in
this file that is not a status code, it is in the wrong file.

WHY THIS IS SEPARATE FROM `auth_routes.py`
-------------------------------------------
Authentication answers "who is this". Account administration answers "who may
exist". The second requires the first to have already happened, and keeping them
apart means the middleware in `auth_routes.py` — which changes the behaviour of
every route in the application — is not sitting in the same file as ordinary
CRUD that people will edit often.

THE PART WORTH READING TWICE
-----------------------------
`_target()` looks up a user and then checks the org against the caller's
session. That check is not redundant with `list_users(org_id)`: the store's
`find_user` is deliberately org-blind because login has to resolve a user
BEFORE any org is known. So any route that reaches a user by name has to do the
org check itself, and every route here goes through `_target()` to do it.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

from core import accounts, authn
from core.auth_store import LoginFailed, open_auth_store
from core.store import PostgresStore, StoreUnavailable, runtime_or_admin_dsn


class _CreateBody(BaseModel):
    username: str
    display_name: str = ""
    #: Whether the new account may itself administer accounts. Present because
    #: an instance with exactly one administrator has no recovery path if that
    #: person leaves — see `db/009_accounts.sql`.
    is_admin: bool = False


class _PasswordBody(BaseModel):
    current_password: str
    new_password: str


class _DisableBody(BaseModel):
    disabled: bool


class _RoleBody(BaseModel):
    is_admin: bool


def _store():
    try:
        return open_auth_store()
    except StoreUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _session(request: Request) -> Dict[str, Any]:
    session = getattr(request.state, "session", None)
    if session is None:
        raise HTTPException(status_code=401, detail="a session is required")
    return session


def _refuse(exc: Exception) -> HTTPException:
    """One place that maps a refusal to a status code.

    403 for 'you may not', 409 for 'this cannot be done' — a conflict with the
    state of the instance rather than with the caller's authority. A client
    retrying with different credentials fixes the first and never the second.
    """
    if isinstance(exc, accounts.NotPermitted):
        return HTTPException(status_code=403, detail=str(exc))
    return HTTPException(status_code=409, detail=str(exc))


def _audit(session: Dict[str, Any], action: str, **payload: Any) -> None:
    """Write one account action to the hash-chained log.

    THE POWERS ON THIS SURFACE ARE NOT ALL PREVENTABLE, so they have to be
    reconstructable. An administrator who resets a password and then a second
    factor can sign in as that user; nothing here stops that, and these two
    records are what make it visible afterwards.

    Exceptions propagate deliberately. `core/store.py` refuses to fall back to
    an in-process store precisely so that an unrecordable action fails loudly
    rather than succeeding unrecorded — swallowing the error here would
    reintroduce exactly what that refusal exists to prevent. The action has
    already happened by the time this runs, so the 500 is honest: it says the
    change was made and the record was not.

    `runtime_or_admin_dsn` rather than bare `open_store()`, because
    `PostgresStore` reads `SKOPOS_DATABASE_URL` directly and a Helm pod is given
    only `SKOPOS_APP_DATABASE_URL` on purpose — RLS does not apply to a
    superuser. Under the default construction every account action in that
    deployment would 500 here while working perfectly under compose.

    `migrate=False` because a migration check per audit write is a round trip
    per account action, and the app has already refused to serve at startup if
    the schema is behind.
    """
    dsn, _ = runtime_or_admin_dsn()
    if not dsn:
        raise StoreUnavailable("no database is configured, so this action "
                               "cannot be recorded and must not proceed")
    PostgresStore(dsn, migrate=False).append_audit(
        actor=str(session.get("username") or "unknown"),
        action=action,
        payload={"org_id": session.get("org_id"), **payload})


def _target(store, session: Dict[str, Any],
            username: str) -> Dict[str, Any]:
    """A user in the caller's organisation, or 404.

    404 rather than 403 when the org does not match. A caller who can tell
    'no such user' from 'not yours' can enumerate the usernames in every other
    tenant on the instance, one guess at a time.
    """
    user = store.find_user(username)
    if user is None or str(user["org_id"]) != str(session["org_id"]):
        raise HTTPException(status_code=404, detail="no such account")
    return user


def register(app: FastAPI) -> None:

    # ── your own account ────────────────────────────────────────────────────
    @app.post("/api/v1/account/password", tags=["account"])
    def change_password(body: _PasswordBody, request: Request,
                        response: Response) -> Dict[str, Any]:
        """Change your own password. Requires the current one.

        Reachable by a user who must change their password — it is on
        `auth_routes.LOCKED_ALLOWED`, and is the only thing such a session can
        do besides logging out.
        """
        session = _session(request)
        store = _store()
        try:
            accounts.check_change(session, body.current_password,
                                  body.new_password)
        except authn.WeakPassword as weak:
            raise HTTPException(status_code=400, detail=str(weak)) from weak
        except (accounts.NotPermitted, accounts.AccountRefused) as exc:
            raise _refuse(exc) from exc

        token = request.cookies.get(authn.SESSION_COOKIE, "")
        try:
            others = store.change_password(
                session["user_id"], body.current_password, body.new_password,
                keep_token=token)
        except LoginFailed as failed:
            # 401, not 403: the current password was wrong, and that is a
            # failed credential check like any other.
            raise HTTPException(status_code=401, detail=str(failed)) from failed
        except authn.WeakPassword as weak:              # pragma: no cover
            raise HTTPException(status_code=400, detail=str(weak)) from weak

        # Recorded for the same reason as the administrative actions, and with
        # the same omission: the record says a password changed, never what to.
        _audit(session, "account.password_changed",
               other_sessions_revoked=others)
        return {
            "changed": True,
            "other_sessions_revoked": others,
            # Reported so it can be shown. Somebody who sees "3 other sessions"
            # when they expected none has just learned something worth knowing,
            # and a silent revocation tells them nothing.
            "note": (f"{others} other session(s) were signed out."
                     if others else
                     "No other sessions were open."),
        }

    # ── administering accounts ──────────────────────────────────────────────
    @app.get("/api/v1/account/users", tags=["account"])
    def list_users(request: Request) -> Dict[str, Any]:
        session = _session(request)
        try:
            accounts.require_admin(session)
        except accounts.NotPermitted as exc:
            raise _refuse(exc) from exc
        store = _store()
        users = [accounts.describe(u, self_id=session["user_id"])
                 for u in store.list_users(session["org_id"])]
        return {"org_id": session["org_id"], "users": users,
                "summary": accounts.summarise(users)}

    @app.post("/api/v1/account/users", tags=["account"])
    def create_user(body: _CreateBody, request: Request) -> Dict[str, Any]:
        """Create an account and return its one-time password ONCE.

        The password is generated here and never stored in readable form, so
        there is no second chance to read it and no endpoint that will repeat
        it. If it is lost before the person receives it, the account is disabled
        and a new one made — which is the correct outcome, because a credential
        that can be retrieved later is a credential sitting in a database.
        """
        session = _session(request)
        try:
            plan = accounts.plan_creation(session, body.username,
                                          body.display_name)
        except (accounts.NotPermitted, accounts.AccountRefused) as exc:
            raise _refuse(exc) from exc

        store = _store()
        if store.find_user(plan["username"]) is not None:
            # Deliberately explicit. Username collisions are a fact an
            # administrator of this org needs, and unlike `_target` this leaks
            # nothing about who is in another tenant: it says a name is taken
            # somewhere, which they discover anyway by trying to create it.
            raise HTTPException(status_code=409,
                                detail="that username is already taken")
        try:
            store.create_user(
                username=plan["username"], password=plan["password"],
                org_id=plan["org_id"], created_by=plan["created_by"],
                display_name=plan["display_name"],
                is_admin=bool(body.is_admin), must_change_password=True)
        except authn.WeakPassword as weak:              # pragma: no cover
            raise HTTPException(status_code=500,
                                detail=f"generated password rejected: {weak}"
                                ) from weak

        # The password itself is NOT in the payload. An audit log that records
        # credentials is a credential store with worse access control.
        _audit(session, "account.created", account=plan["username"],
               is_admin=bool(body.is_admin))
        return {
            "created": plan["username"],
            "display_name": plan["display_name"],
            "is_admin": bool(body.is_admin),
            "initial_password": plan["password"],
            "shown_once": True,
            "next_steps": [
                "Give this password to the person directly. It is shown once "
                "and cannot be retrieved again.",
                "They must change it at first sign-in; until they do, the "
                "account can reach nothing else.",
                "They then enrol their own authenticator app, which you never "
                "see. Signing in as them afterwards would require resetting "
                "both their password and their second factor — possible, and "
                "recorded in the audit log if you do.",
            ],
        }

    @app.post("/api/v1/account/users/{username}/disabled", tags=["account"])
    def set_disabled(username: str, body: _DisableBody,
                     request: Request) -> Dict[str, Any]:
        """Disable or restore an account. Disabling cuts its sessions at once."""
        session = _session(request)
        store = _store()
        target = _target(store, session, username)
        if body.disabled:
            try:
                accounts.check_disable(session, target,
                                       store.admin_count(session["org_id"]))
            except (accounts.NotPermitted, accounts.AccountRefused) as exc:
                raise _refuse(exc) from exc
        else:
            try:
                accounts.require_admin(session)
            except accounts.NotPermitted as exc:
                raise _refuse(exc) from exc

        store.set_disabled(int(target["id"]), body.disabled)
        _audit(session,
               "account.disabled" if body.disabled else "account.restored",
               account=target["username"])
        return {"username": target["username"], "disabled": body.disabled,
                "note": ("Any session that account had is now revoked."
                         if body.disabled else
                         "The account may sign in again with its existing "
                         "password and authenticator.")}

    @app.post("/api/v1/account/users/{username}/role", tags=["account"])
    def set_role(username: str, body: _RoleBody,
                 request: Request) -> Dict[str, Any]:
        session = _session(request)
        store = _store()
        target = _target(store, session, username)
        try:
            accounts.check_role_change(session, target, body.is_admin,
                                       store.admin_count(session["org_id"]))
        except (accounts.NotPermitted, accounts.AccountRefused) as exc:
            raise _refuse(exc) from exc
        store.set_admin(int(target["id"]), body.is_admin)
        _audit(session,
               "account.promoted" if body.is_admin else "account.demoted",
               account=target["username"])
        return {"username": target["username"], "is_admin": body.is_admin,
                "note": ("They can now create and administer accounts. This "
                         "grants no authority over any estate — scanning is "
                         "still gated on verified ownership."
                         if body.is_admin else
                         "They can no longer administer accounts.")}

    @app.post("/api/v1/account/users/{username}/password/reset",
              tags=["account"])
    def reset_password(username: str, request: Request) -> Dict[str, Any]:
        """Issue a new one-time password to somebody who has forgotten theirs.

        The alternative — no reset at all — was the first design here, and it
        made a forgotten password a permanently dead account whose username
        could never be reused, because `db/008_auth.sql` makes usernames
        globally unique. See `core/accounts.py` for why that trade was wrong.

        This is a real power and the response says so: an administrator who
        also resets the second factor can sign in as this user. Both actions
        are written to the audit chain.
        """
        session = _session(request)
        store = _store()
        target = _target(store, session, username)
        try:
            accounts.check_reset_password(session, target)
        except (accounts.NotPermitted, accounts.AccountRefused) as exc:
            raise _refuse(exc) from exc

        issued = accounts.issue_initial_password()
        store.reset_password(int(target["id"]), issued)
        _audit(session, "account.password_reset", account=target["username"])
        return {
            "username": target["username"],
            "initial_password": issued,
            "shown_once": True,
            "next_steps": [
                "Give this to them directly. It is shown once and cannot be "
                "retrieved again.",
                "They must change it before the account can do anything else.",
                "Their existing sessions are ended; their authenticator is "
                "unchanged, so they will still need it to sign in.",
            ],
            "note": ("You have seen this password. Until they change it you "
                     "could sign in as them if you also reset their second "
                     "factor — both actions are recorded in the audit log."),
        }

    @app.post("/api/v1/account/users/{username}/second-factor/reset",
              tags=["account"])
    def reset_second_factor(username: str, request: Request) -> Dict[str, Any]:
        """Clear an enrolment so a user who lost their authenticator can enrol
        again. Issues nothing the administrator could sign in with."""
        session = _session(request)
        store = _store()
        target = _target(store, session, username)
        try:
            accounts.check_reset_second_factor(session, target)
        except (accounts.NotPermitted, accounts.AccountRefused) as exc:
            raise _refuse(exc) from exc
        store.reset_second_factor(int(target["id"]))
        _audit(session, "account.second_factor_reset",
               account=target["username"])
        return {
            "username": target["username"],
            "second_factor": "not enrolled",
            "note": ("Their next sign-in will ask them to enrol an "
                     "authenticator. Their recovery codes are void and their "
                     "sessions are revoked. Confirm you are speaking to the "
                     "right person before doing this — it is the one action "
                     "here that weakens an account."),
        }


__all__ = ["register"]
