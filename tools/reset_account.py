"""Recover a locked-out account, from outside the application.

    python tools/reset_account.py --user krishnendu --password
    python tools/reset_account.py --user krishnendu --second-factor
    python tools/reset_account.py --user krishnendu --password --second-factor

Runs on the ADMIN DSN (`SKOPOS_DATABASE_URL`), and exists for exactly the case
the in-product reset cannot serve.

WHY THIS IS A TOOL AND NOT AN ENDPOINT
-----------------------------------------
`core/accounts.py` already lets an administrator reset somebody else's password
or second factor through the console, and that path is the right one whenever
it is available. It requires an administrator who can log in.

This is for when nobody can. A forgotten password, a lost authenticator, or an
instance whose only two administrators are both locked out has no principal
left inside the system to authorise the fix — the same shape
`core/provisioning.py` describes for creating an organisation. So the authority
used is the one that already exists and is already scarce: the admin DSN, held
by whoever runs migrations.

IT REUSES THE STORE RATHER THAN WRITING ITS OWN SQL
------------------------------------------------------
`PostgresAuthStore.reset_password` and `.reset_second_factor` already encode
several decisions that are easy to get wrong and expensive to get wrong quietly:

* `totp_last_counter` is set to **-1**, not NULL. The column is NOT NULL and -1
  is its sentinel for "no code has ever been accepted". This repository has
  already shipped that bug once and had to fix it.
* The TOTP **secret** is cleared, not just the timestamp — otherwise a lost
  phone that is later recovered still produces accepted codes after the reset
  performed because of it.
* Recovery codes are deleted, and live **sessions are revoked**: the reason for
  a reset is that a credential is in doubt, and a session was admitted by the
  very factor being replaced.

A second implementation here would drift from those, and the drift would not be
visible until somebody needed it to work.

THE PASSWORD IS GENERATED, NOT CHOSEN
----------------------------------------
`accounts.issue_initial_password` stays the only generator in the codebase, for
the reason it gives: an administrator choosing passwords picks a house pattern,
and a house pattern means every account on the instance shares a guessable
prefix. `must_change_password` goes back on, so the account is locked to the
change form until its owner picks something nobody else has seen.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import accounts as _accounts          # noqa: E402
from core import auth_store as _auth_store      # noqa: E402

ADMIN_DSN_ENV = "SKOPOS_DATABASE_URL"

PASSWORD_HANDLING = (
    "This password is displayed once and is not recoverable. It is stored only "
    "as a PBKDF2-SHA256 hash, and the account is locked to the change form "
    "until its owner picks something you have not seen."
)

SECOND_FACTOR_NEXT_STEPS = (
    "The authenticator enrolment is cleared and any recovery codes are gone. "
    "The account will be prompted to enrol a new authenticator at next login. "
    "Live sessions were revoked, because a session admitted by the factor you "
    "just replaced is exactly what a reset is meant to end."
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--user", required=True,
                        help="username to recover")
    parser.add_argument("--password", action="store_true",
                        help="issue a new one-time password")
    parser.add_argument("--second-factor", action="store_true",
                        help="clear the authenticator enrolment and recovery "
                             "codes so a new one can be enrolled")
    parser.add_argument("--dsn", default="",
                        help=f"admin DSN (default: ${ADMIN_DSN_ENV})")
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would change without writing")
    args = parser.parse_args(argv)

    if not (args.password or args.second_factor):
        print("Refused: choose --password, --second-factor, or both.")
        print("Doing neither is not a recovery, and defaulting to both would "
              "clear an authenticator somebody only wanted a password for.")
        return 2

    username = str(args.user or "").strip().lower()
    if not username:
        print("Refused: a username is required.")
        return 2

    dsn = args.dsn or os.environ.get(ADMIN_DSN_ENV, "")
    if not dsn:
        print(f"Refused: {ADMIN_DSN_ENV} is not set, and no --dsn was given.")
        print("Recovery uses the ADMIN DSN deliberately — see the module "
              "docstring in tools/reset_account.py.")
        return 2

    # migrate=False: recovery must not be the thing that runs a schema change.
    # Somebody reaching for this is already having a bad day.
    store = _auth_store.PostgresAuthStore(dsn, migrate=False)
    # `find_user` is the store's own accessor, so username
    # normalisation stays in one place rather than two.
    user = store.find_user(username)
    if user is None:
        # Deliberately NOT "no such user". This tool is run by whoever holds
        # the admin DSN, so there is nobody to protect the account list from —
        # and a vague message here would send them looking for a typo that is
        # not there.
        print(f"Refused: no account named {username!r} on this instance.")
        return 3

    user_id = user["id"] if isinstance(user, dict) else getattr(user, "id")
    doing = []
    if args.password:
        doing.append("issue a new one-time password")
    if args.second_factor:
        doing.append("clear the authenticator enrolment and recovery codes")

    if args.dry_run:
        print(f"DRY RUN — nothing was written. For {username!r} this would:")
        for item in doing:
            print(f"  - {item}")
        print("  - revoke every live session for that account")
        return 0

    issued = ""
    if args.password:
        issued = _accounts.issue_initial_password()
        if not store.reset_password(user_id, issued):
            print("Refused: the password was not changed — the account row "
                  "did not update. Nothing else was attempted.")
            return 1

    if args.second_factor:
        store.reset_second_factor(user_id)

    print(f"Recovered {username!r}.")
    if issued:
        print()
        print(f"  username  {username}")
        print(f"  password  {issued}")
        print()
        print(PASSWORD_HANDLING)
    if args.second_factor:
        print()
        print(SECOND_FACTOR_NEXT_STEPS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
