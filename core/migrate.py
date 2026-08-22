"""Apply schema migrations, and refuse to run against a schema that is behind.

WHY THIS EXISTS, AND WHY IT IS A P0 CORRECTION RATHER THAN P1 PLUMBING
----------------------------------------------------------------------
`docker-compose.yml` mounts `./db` at `/docker-entrypoint-initdb.d`, which
Postgres executes ONLY on an empty data directory. The compose file says so in a
comment. That was fine when there was one file and every deployment was new.

The moment a second migration exists, the arrangement fails in the worst
available way: `db/002_p1.sql` never runs on `skopos-db-1`, whose volume already
has data — so the CHECK constraints P1 depends on are simply absent in the
deployment, while the identical constraints DO exist in the throwaway databases
the tests build, because those start empty and run every file. Green tests,
missing controls, and the difference is invisible until a bad finding reaches a
customer.

So: a version table, an applier, and a refusal.

THE REFUSAL IS THE POINT. `ensure_current()` is called from `PostgresStore` and
from the API's startup hook, and a schema behind the code stops the service
rather than degrading it. That is the same posture as `open_store()` refusing to
fall back to an in-memory store: this product would rather not run than run while
quietly missing a control it claims to have.

Back-filling '001' for an existing volume is deliberate. The tables are already
there — recorded by the initdb path that predates this module — and re-running
001 would fail on the CREATE TABLE. Detecting that state and recording it is how
an existing deployment joins the scheme without being rebuilt.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "db"

#: `001_schema.sql` -> version `001`. Ordering is by this prefix, so migrations
#: apply in a defined order rather than whatever the filesystem returns.
_NAME = re.compile(r"^(\d{3})_.+\.sql$")


class SchemaBehind(RuntimeError):
    """The database is missing migrations the running code requires."""


class MigrationError(RuntimeError):
    """A migration failed to apply. Nothing was left half-applied."""


def available(directory: Optional[Path] = None) -> List[tuple]:
    """`[(version, path), ...]` in application order."""
    base = Path(directory) if directory else MIGRATIONS
    found = []
    for path in sorted(base.glob("*.sql")):
        match = _NAME.match(path.name)
        if match:
            found.append((match.group(1), path))
    return found


def _dsn(explicit: Optional[str]) -> str:
    dsn = explicit or os.environ.get("SKOPOS_DATABASE_URL")
    if not dsn:
        raise MigrationError(
            "SKOPOS_DATABASE_URL is not set; there is nothing to migrate")
    return dsn


def applied(dsn: Optional[str] = None) -> List[str]:
    """Versions already recorded, oldest first."""
    import psycopg
    with psycopg.connect(_dsn(dsn)) as conn, conn.cursor() as cur:
        cur.execute("SELECT to_regclass('public.schema_migration')")
        if cur.fetchone()[0] is None:
            return []
        cur.execute("SELECT version FROM schema_migration ORDER BY version")
        return [r[0] for r in cur.fetchall()]


def pending(dsn: Optional[str] = None,
            directory: Optional[Path] = None) -> List[str]:
    done = set(applied(dsn))
    return [v for v, _ in available(directory) if v not in done]


def ensure_current(dsn: Optional[str] = None,
                   directory: Optional[Path] = None) -> List[str]:
    """Apply every migration not yet recorded. Returns the versions applied."""
    import psycopg

    target = _dsn(dsn)
    files = available(directory)
    if not files:
        raise MigrationError(f"no migrations found in {directory or MIGRATIONS}")

    with psycopg.connect(target, autocommit=True) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migration ("
            "  version    TEXT PRIMARY KEY,"
            "  applied_at TIMESTAMPTZ NOT NULL DEFAULT now())")

        with conn.cursor() as cur:
            cur.execute("SELECT version FROM schema_migration")
            done = {r[0] for r in cur.fetchall()}

            # The existing-volume case: 001 ran through Postgres's initdb hook
            # before this table existed. Its tables are present, so re-running it
            # would fail on CREATE TABLE. Record it instead.
            if "001" not in done:
                cur.execute("SELECT to_regclass('public.scope_rule')")
                if cur.fetchone()[0] is not None:
                    cur.execute("INSERT INTO schema_migration (version) "
                                "VALUES ('001') ON CONFLICT DO NOTHING")
                    done.add("001")

    newly: List[str] = []
    for version, path in files:
        if version in done:
            continue
        sql = path.read_text(encoding="utf-8")
        # One transaction per file, so a failure leaves that migration entirely
        # unapplied rather than half-applied — the state nobody can reason about.
        with psycopg.connect(target) as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(sql)
                    cur.execute("INSERT INTO schema_migration (version) VALUES (%s)",
                                (version,))
            except Exception as exc:
                conn.rollback()
                raise MigrationError(
                    f"migration {version} ({path.name}) failed and was rolled "
                    f"back; the schema is unchanged: {exc}") from exc
        newly.append(version)
    return newly


def require_current(dsn: Optional[str] = None,
                    directory: Optional[Path] = None) -> None:
    """Raise SchemaBehind if anything is unapplied. Does not apply anything.

    For callers that must not perform DDL themselves — a read-only replica, or a
    process running as a role without CREATE. Refusing is still better than
    serving: a missing CHECK constraint does not announce itself, it just stops
    rejecting the rows it was written to reject.
    """
    outstanding = pending(dsn, directory)
    if outstanding:
        raise SchemaBehind(
            f"the database is missing migration(s) {', '.join(outstanding)}. "
            f"The code expects controls those files create — running anyway "
            f"would mean claiming constraints that are not there. "
            f"Apply them with core.migrate.ensure_current().")
