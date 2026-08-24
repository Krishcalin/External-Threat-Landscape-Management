"""Create an organisation and its first administrator, in one transaction.

    python tools/provision_org.py --id acme --name "Acme Ltd" --admin jane

Runs on the ADMIN DSN (`SKOPOS_DATABASE_URL`), not the runtime one. See
`core/provisioning.py` for why this is a tool rather than an endpoint: no
authenticated principal in SKOPOS legitimately holds the authority to create a
tenant, and inventing a cross-tenant role to provide one would add exactly the
standing all-tenant privilege row-level security exists to avoid.

WHY THE WHOLE THING IS ONE TRANSACTION
-----------------------------------------
An organisation with no users is unreachable: nobody can log in to it, so
nobody can create the account that would make it usable — and it is invisible,
because every listing in the product is scoped to a session that cannot exist
for it. A half-provisioned tenant is not a partial success, it is a row
somebody has to find and delete by hand later.

So the org row and its first administrator are committed together or neither
is written.

WHY IT REFUSES AN EXISTING ORGANISATION
------------------------------------------
Adopting one would add an administrator that nobody already in that tenant
authorised. The primary key answers the question atomically, inside the
transaction, rather than by a SELECT beforehand — a check-then-insert is a race,
and a race that reports "created" while doing nothing is worse than a
constraint violation.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import provisioning as _provisioning   # noqa: E402

ADMIN_DSN_ENV = "SKOPOS_DATABASE_URL"


def _connect(dsn: str):
    try:
        import psycopg
    except ImportError:                                       # pragma: no cover
        try:
            import psycopg2 as psycopg                        # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "no PostgreSQL driver available: install psycopg") from exc
    return psycopg.connect(dsn)


def provision(plan, dsn: str) -> str:
    """Execute the plan. Returns the created username, or raises.

    The connection is used with an explicit transaction so a failure on the
    second statement cannot leave the first committed.
    """
    conn = _connect(dsn)
    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(_provisioning.INSERT_ORG,
                        (plan.org_id, plan.org_name, plan.note))
            cur.execute(_provisioning.INSERT_ADMIN,
                        (plan.org_id, plan.admin_username, plan.password_hash,
                         plan.admin_display_name, plan.created_by))
            row = cur.fetchone()
        conn.commit()
        return str(row[0]) if row else ""
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--id", required=True,
                        help="organisation id: lowercase, [a-z0-9_-], "
                             "63 characters or fewer")
    parser.add_argument("--name", required=True,
                        help="human-readable organisation name")
    parser.add_argument("--admin", required=True,
                        help="username of the first administrator")
    parser.add_argument("--display-name", default="",
                        help="display name for that administrator")
    parser.add_argument("--note", default="",
                        help="why this tenant exists, for whoever reads the "
                             "registry later")
    parser.add_argument("--created-by", default="",
                        help="who is provisioning this, for the record")
    parser.add_argument("--dsn", default="",
                        help=f"admin DSN (default: ${ADMIN_DSN_ENV})")
    parser.add_argument("--dry-run", action="store_true",
                        help="validate and print the plan without touching "
                             "the database")
    args = parser.parse_args(argv)

    try:
        plan = _provisioning.plan(
            org_id=args.id, org_name=args.name, admin_username=args.admin,
            display_name=args.display_name, note=args.note,
            created_by=args.created_by or os.environ.get("USER", "") or "operator")
    except _provisioning.ProvisioningRefused as exc:
        print(f"Refused: {exc}")
        return 2

    if args.dry_run:
        print("DRY RUN — nothing was written.")
        for key, value in plan.to_dict().items():
            if key == "why_not_an_api":
                continue
            print(f"  {key:22s} {value}")
        print()
        print(_provisioning.WHY_NOT_AN_API)
        return 0

    dsn = args.dsn or os.environ.get(ADMIN_DSN_ENV, "")
    if not dsn:
        print(f"Refused: {ADMIN_DSN_ENV} is not set, and no --dsn was given.")
        print("Provisioning uses the ADMIN DSN deliberately — see "
              "core/provisioning.py.")
        return 2

    try:
        provision(plan, dsn)
    except Exception as exc:                                  # noqa: BLE001
        # Matched by CONSTRAINT NAME. Both violations say "duplicate key", so
        # matching on that phrase reported a taken username as "that
        # organisation already exists" — which sent the operator looking for a
        # tenant that was not there. Found by provisioning against a real
        # database; the dry run could not have shown it.
        kind = _provisioning.classify_failure(str(exc))
        if kind == "org_exists":
            print(_provisioning.describe(plan, existing=True))
            return 3
        if kind == "username_taken":
            print(_provisioning.describe_username_taken(plan))
            return 4
        print(f"Provisioning failed, nothing was committed: {exc}")
        return 1

    print(_provisioning.describe(plan))
    print()
    print(f"  username  {plan.admin_username}")
    print(f"  password  {plan.password}")
    print()
    print(_provisioning.PASSWORD_HANDLING)
    return 0


if __name__ == "__main__":
    sys.exit(main())
