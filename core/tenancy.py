"""Which organisation a request is acting for.

WHAT THIS IS, PRECISELY
-----------------------
One value, carried per request, applied to every database connection as the
session GUC `skopos.org_id`. The row-level security policies in
`db/006_tenancy.sql` compare `org_id` against that GUC, so this module is the
only thing standing between a query and the wrong tenant's rows.

WHY A CONTEXTVAR AND NOT A PARAMETER ON EVERY CALL
---------------------------------------------------
Threading an `org` argument through every store method would work, and it would
be enforced by nothing: the first method somebody adds without the argument
compiles, runs, and reads another tenant's data. A ContextVar applied inside
`_connect()` means a NEW query written by somebody who has never heard of
tenancy is still filtered, because the filter is in the connection rather than
in the query.

ContextVar rather than a module global because ASGI serves concurrent requests
in one process: a global would be a race in which tenant A's request overwrites
tenant B's org between B's connect and B's execute.

THE FAILURE DIRECTION IS DELIBERATE
------------------------------------
If the GUC is never set, `current_setting('skopos.org_id', true)` is NULL,
`org_id = NULL` is never true, and every query returns NOTHING. An empty result
is noticed in minutes. The opposite default — unset means everything — is
noticed by a customer.

WHAT THIS DOES NOT DEFEND AGAINST
----------------------------------
A compromised application, or leaked credentials for the app role. Whoever can
execute SQL on that connection can also call `set_config` again. This is a
defence against a BUG — a forgotten filter, a new query, a bad join — and that
is a real and common failure. It is not isolation against a hostile tenant, and
calling it that would be the kind of claim this product exists not to make.
"""
from __future__ import annotations

import os
import re
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional

#: The tenant every pre-tenancy row was backfilled into by migration 006.
DEFAULT_ORG = "default"

#: Mirrors the CHECK constraint on `org.id`. Validated here as well as there
#: because the value reaches `set_config` before it ever reaches a table, and a
#: GUC is not a place to discover that an identifier was malformed.
ORG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")

#: Set once per process for a single-tenant deployment, which is what most
#: installations are. A request-scoped org overrides it.
ORG_ENV = "SKOPOS_ORG_ID"

_current: ContextVar[Optional[str]] = ContextVar("skopos_org", default=None)


class TenancyError(ValueError):
    """An organisation identifier that must not reach a connection."""


def validate(org: str) -> str:
    text = str(org or "").strip()
    if not ORG_PATTERN.match(text):
        raise TenancyError(
            f"{org!r} is not a valid organisation id. Lower-case letters, "
            f"digits, hyphen and underscore, starting with a letter or digit, "
            f"up to 63 characters — the same rule the org table enforces")
    return text


def current_org() -> str:
    """The org this call is acting for.

    Resolution order: an explicit `using()` scope, then SKOPOS_ORG_ID, then the
    default tenant. Never None — a caller that got None would have to decide
    what to do about it, and every wrong answer to that question is a
    cross-tenant read.
    """
    scoped = _current.get()
    if scoped:
        return scoped
    return validate(os.environ.get(ORG_ENV) or DEFAULT_ORG)


@contextmanager
def using(org: str) -> Iterator[str]:
    """Act as `org` for the duration of the block, then restore.

    The token-based reset matters: a plain reassignment on exit would restore
    the wrong value under concurrency, which is exactly the bug a ContextVar is
    here to prevent.
    """
    valid = validate(org)
    token = _current.set(valid)
    try:
        yield valid
    finally:
        _current.reset(token)


def apply(conn, org: Optional[str] = None) -> str:
    """Bind an open connection to an organisation. Call once, after connecting.

    Uses `set_config` rather than `SET`, because `SET` cannot take a bound
    parameter and would mean interpolating an identifier into SQL. `validate`
    already rejects anything dangerous; a parameterised call means the check is
    not the only thing standing between a hostile string and the statement.

    `is_local = false`: these stores open a connection per operation and commit
    on exit, and a `SET LOCAL` would be discarded at the first commit, leaving
    every subsequent statement on that connection unable to see any rows.
    """
    target = validate(org) if org else current_org()
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('skopos.org_id', %s, false)", (target,))
    return target


def bound_org(conn) -> Optional[str]:
    """What this connection is actually bound to. For tests and diagnostics —
    the point of a defence in the connection is that it can be inspected."""
    with conn.cursor() as cur:
        cur.execute("SELECT current_setting('skopos.org_id', true)")
        row = cur.fetchone()
    return row[0] if row and row[0] else None


#: The UNPRIVILEGED runtime DSN, connecting as `skopos_app`. When set, every
#: store uses it and the policies in migration 006 are enforced.
#:
#: When unset the stores fall back to SKOPOS_DATABASE_URL, which is the
#: superuser that owns the tables — and RLS does not apply to such a role at
#: all. That fallback keeps a single-tenant deployment working unchanged, and
#: `enforcement()` reports it rather than letting it look like tenancy.
APP_DSN_ENV = "SKOPOS_APP_DATABASE_URL"


def runtime_dsn(admin_dsn: Optional[str] = None) -> str:
    """The DSN a store should serve requests on."""
    return os.environ.get(APP_DSN_ENV) or (admin_dsn or "")


def enforcement(conn) -> str:
    """Whether row-level security actually applies on this connection.

    Worth an explicit query rather than an assumption. A superuser or a role
    with BYPASSRLS silently ignores every policy, so a deployment can have a
    perfectly correct multi-tenant schema and no tenancy whatsoever — and
    nothing in the query results says which one you have.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT current_user, rolsuper OR rolbypassrls "
            "FROM pg_roles WHERE rolname = current_user")
        row = cur.fetchone()
    if not row:
        return "unknown"
    user, bypasses = row
    if bypasses:
        return (f"NOT ENFORCED: connected as {user}, which is superuser or has "
                f"BYPASSRLS. Row-level security does not apply to such a role. "
                f"Set {APP_DSN_ENV} to connect as skopos_app")
    return f"enforced: connected as {user}, which cannot bypass RLS"


#: Stated wherever tenancy is described, because "row-level security" in a
#: feature list reads as a stronger claim than GUC-based RLS supports.
ISOLATION_MEANING = (
    "Rows are filtered by PostgreSQL row-level security against a session "
    "variable the application sets per connection, and the application connects "
    "as an unprivileged role that can neither bypass those policies nor own the "
    "tables. This prevents one tenant's data reaching another THROUGH A BUG — a "
    "forgotten filter, a new query, a bad join. It is not isolation against a "
    "compromised application: anything able to run SQL on that connection can "
    "also change the session variable. Tenants requiring that guarantee need "
    "separate databases, which this deployment model does not provide.")


__all__ = ["DEFAULT_ORG", "ORG_ENV", "ORG_PATTERN", "APP_DSN_ENV",
           "TenancyError", "validate", "runtime_dsn", "enforcement",
           "current_org", "using", "apply", "bound_org", "ISOLATION_MEANING"]
