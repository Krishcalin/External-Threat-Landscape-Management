"""Creating an organisation, and why it is not an API call.

`docs/REFUSALS.md` §11 listed multi-tenant SaaS as a gap rather than a refusal:
"Row-level security is built and proven, but an organisation can still only be
created by hand in the database." This closes it — as a tool run by whoever
holds the admin DSN, and deliberately not as an endpoint.

NO PRINCIPAL IN THE SYSTEM LEGITIMATELY HOLDS THIS AUTHORITY
---------------------------------------------------------------
Every authenticated caller in SKOPOS acts for exactly one organisation.
`app_user.org_id` is `NOT NULL REFERENCES org(id)`, and
`core/accounts.py:plan_creation` takes the org **from the session**, noting
that it "cannot be supplied by the caller" — which is the tenant boundary.

Creating an organisation cannot sit inside that boundary, in either direction:

* **An admin of org A creating org B** would make one tenant's administrator a
  platform operator. `db/009_accounts.sql` is explicit that `is_admin` is
  scoped and that "an administrator gains no authority over anybody's estate".
  Spanning tenants is a larger authority than the one that flag describes.

* **An admin of the new org** cannot authorise it either, because the org has
  no users until it exists. The first account is created *by* provisioning; it
  cannot authorise it.

Inventing a cross-tenant "platform administrator" role to resolve that would
add exactly the standing, all-tenant authority the RLS design exists to avoid —
`db/006_tenancy.sql` already rejected per-tenant Postgres roles on the same
reasoning, that "a larger and permanently-held privilege" is a worse trade than
the risk it removes.

So the authority is the one that already exists and is already scarce: the
**admin DSN**, held by whoever runs migrations. Creating a tenant is an act of
the same kind as creating the database, and it is performed the same way.

`skopos_app` has `GRANT SELECT ON org` and nothing more. That grant is not
widened here, so a compromised application cannot mint tenants.

WHAT MUST BE TRUE WHEN THIS FINISHES
---------------------------------------
**The org and its first administrator are created together or not at all.** An
org with no users is unreachable — nobody can log in to it, so nobody can
create the account that would make it usable — and it is invisible, because
every listing in the product is scoped to a session that cannot exist for it.
A half-provisioned tenant is not a partial success; it is a row that has to be
found and removed by hand later.

**The first account is an administrator, and that is not optional.** An org
whose only user cannot create users is the same dead end reached differently.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

from core import accounts as _accounts
from core import authn as _authn
from core import tenancy as _tenancy

#: Org ids the product uses for itself. `default` holds every row that predates
#: tenancy (`db/006_tenancy.sql`), so handing it to a new customer would give
#: them the instance's own history.
RESERVED_ORG_IDS = frozenset({"default"})

#: Stated on the plan and printed by the tool, so the reasoning travels with
#: the thing rather than living only in this docstring.
WHY_NOT_AN_API = (
    "Organisation creation is not an API endpoint. Every authenticated caller "
    "acts for exactly one organisation, so no principal in the system holds "
    "this authority: an admin of one tenant creating another would be a "
    "platform operator, and an admin of the new tenant cannot authorise its "
    "own creation because it does not exist yet. Inventing a cross-tenant role "
    "to resolve that would add the standing all-tenant privilege row-level "
    "security exists to avoid. The authority used instead is the admin DSN, "
    "held by whoever runs migrations."
)

#: The one-time credential is shown once and never stored in the clear.
PASSWORD_HANDLING = (
    "This password is displayed once and is not recoverable. It is stored only "
    "as a PBKDF2-SHA256 hash, and the account carries must_change_password so "
    "it is not the user's own account until they have changed it."
)


class ProvisioningRefused(ValueError):
    """The request would create a tenant that is wrong or unreachable."""


@dataclass(frozen=True)
class Plan:
    """A validated provisioning request, ready for a single transaction."""

    org_id: str
    org_name: str
    note: str
    admin_username: str
    admin_display_name: str
    #: Shown to the operator once. NEVER logged, never persisted, and
    #: deliberately not carried into `to_dict`.
    password: str
    password_hash: str
    created_by: str

    #: Not a parameter. An org whose first account cannot create accounts is
    #: unreachable, so this is a property of the plan rather than a choice the
    #: caller gets to make.
    is_admin: bool = True
    must_change_password: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Everything except the credential. Safe to log and to audit."""
        return {
            "org_id": self.org_id,
            "org_name": self.org_name,
            "note": self.note,
            "admin_username": self.admin_username,
            "admin_display_name": self.admin_display_name,
            "is_admin": self.is_admin,
            "must_change_password": self.must_change_password,
            "created_by": self.created_by,
            "why_not_an_api": WHY_NOT_AN_API,
        }


def _clean_username(raw: str) -> str:
    """The same rules `core/accounts.py:plan_creation` applies.

    Reused rather than reimplemented: a first administrator created by a
    different rule from every later account is a difference nobody would think
    to look for, and usernames are globally unique in `app_user`.
    """
    name = str(raw or "").strip().lower()
    if not name:
        raise ProvisioningRefused("an administrator username is required")
    if len(name) > 128:
        raise ProvisioningRefused("that username is too long")
    if any(ch.isspace() for ch in name):
        raise ProvisioningRefused("a username cannot contain spaces")
    return name


def plan(org_id: str, org_name: str, admin_username: str,
         display_name: str = "", note: str = "",
         created_by: str = "", password: Optional[str] = None) -> Plan:
    """Validate a provisioning request and produce the plan to execute.

    NO DATABASE ACCESS. Whether the org already exists is a question for the
    transaction that inserts it, where the primary key answers it atomically —
    checking here would be a race, and a race that reports "created" while
    doing nothing is worse than a constraint violation.
    """
    try:
        ident = _tenancy.validate(org_id)
    except _tenancy.TenancyError as exc:
        raise ProvisioningRefused(str(exc)) from exc
    if ident in RESERVED_ORG_IDS:
        raise ProvisioningRefused(
            f"{ident!r} is reserved: it holds every row that predates tenancy, "
            "so giving it to a new organisation would hand over this "
            "instance's own history")

    name = str(org_name or "").strip()
    if not name:
        raise ProvisioningRefused(
            "an organisation name is required — an id alone tells the next "
            "operator nothing about whose tenant this is")
    if len(name) > 200:
        raise ProvisioningRefused("that organisation name is too long")

    username = _clean_username(admin_username)
    # Generated rather than chosen, for the reason `accounts.py` gives: an
    # administrator choosing passwords picks a house pattern, and a house
    # pattern means every account on the instance shares a guessable prefix.
    secret = password if password is not None else _accounts.issue_initial_password()
    if not str(secret).strip():
        raise ProvisioningRefused("an empty password is not a password")

    return Plan(
        org_id=ident,
        org_name=name,
        note=str(note or "").strip(),
        admin_username=username,
        admin_display_name=str(display_name or "").strip()[:128] or username,
        password=secret,
        password_hash=_authn.hash_password(secret),
        created_by=str(created_by or "provisioning").strip() or "provisioning",
    )


#: The statements a provisioning transaction runs, in order. Exposed so the
#: tool and its tests execute the same SQL, and so a reader can see exactly
#: what a new tenant costs: two rows.
INSERT_ORG = (
    "INSERT INTO org (id, name, note) VALUES (%s, %s, %s)"
)
INSERT_ADMIN = (
    "INSERT INTO app_user (org_id, username, password_hash, display_name, "
    "created_by, is_admin, must_change_password) "
    "VALUES (%s, %s, %s, %s, %s, TRUE, TRUE) RETURNING id"
)


#: The constraints a provisioning transaction can violate, and what each
#: actually means. Matched by NAME rather than on the words "duplicate key",
#: because both violations produce that phrase — a username clash reported as
#: "that organisation already exists" sends the operator looking for a tenant
#: that is not there. Verified against the live schema.
CONSTRAINT_MEANING = {
    "org_pkey": "org_exists",
    "app_user_username_key": "username_taken",
    "app_user_pkey": "user_id_collision",
}


def classify_failure(message: str) -> str:
    """Which constraint a driver error names, or "" when none of ours."""
    text = str(message or "")
    for name, meaning in CONSTRAINT_MEANING.items():
        if name in text:
            return meaning
    return ""


def describe(plan_: Plan, existing: bool = False) -> str:
    """What the operator is told. Never includes the credential."""
    if existing:
        return (f"Organisation {plan_.org_id!r} already exists. Nothing was "
                f"created. Provisioning refuses to adopt an existing tenant, "
                f"because an org that already has users would gain an "
                f"administrator nobody in it authorised.")
    return (f"Created organisation {plan_.org_id!r} ({plan_.org_name}) with "
            f"administrator {plan_.admin_username!r}.")


def describe_username_taken(plan_: Plan) -> str:
    """A username clash. NOT an org clash, and it must not say so.

    `app_user.username` is UNIQUE across the whole instance rather than per
    tenant, so a name already used in another organisation is unavailable here
    — which is surprising enough to be worth saying outright.
    """
    return (f"Username {plan_.admin_username!r} is already taken. Nothing was "
            f"created — organisation {plan_.org_id!r} was rolled back with it. "
            f"Usernames are unique across the whole instance, not per "
            f"organisation, so a name in use by another tenant is unavailable "
            f"here. Choose another and run this again.")
