"""Live-database tests for the controls a fake store cannot prove.

MemoryStore can demonstrate that the domain rules work. It cannot demonstrate
that `audit_log` refuses UPDATE and DELETE, or that a manual attestation without
an approver is rejected by the database rather than only by Python — and those
are exactly the controls that have to hold when someone writes a migration
script, or when an injected statement reaches the connection.

Skipped when no database is reachable, so the suite still runs offline. Skipped
loudly rather than silently: a control that is never exercised because the test
quietly opted out is worse than no test.

Each run builds a THROWAWAY DATABASE and drops it afterwards. The audit log is
append-only by design, so a test that wrote into the real one would leave a
record with a fabricated hash that nothing can ever remove — permanently
breaking chain verification. Dropping the whole database is the only clean
teardown, which is itself a useful thing to have noticed.
"""
from __future__ import annotations

import os
import uuid
from datetime import date, timedelta
from pathlib import Path

import pytest

from core.audit import GENESIS
from core.ownership import Method, Verification
from core.scope import ScopeKind, ScopeRule
from core.store import PostgresStore

psycopg = pytest.importorskip("psycopg", reason="psycopg is not installed")

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "db" / "001_schema.sql"

#: Defaults to the loopback port docker-compose.yml publishes for skopos-db-1.
ADMIN_DSN = os.environ.get(
    "SKOPOS_TEST_ADMIN_DSN",
    os.environ.get("SKOPOS_DATABASE_URL",
                   "postgresql://skopos@127.0.0.1:55443/skopos"))


def _reachable(dsn: str) -> bool:
    try:
        with psycopg.connect(dsn, connect_timeout=3):
            return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _reachable(ADMIN_DSN),
    reason=f"no database at {ADMIN_DSN.rsplit('@', 1)[-1]} "
           f"(bring it up with: docker compose up -d db)")


@pytest.fixture(scope="module")
def store():
    name = f"skopos_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    test_dsn = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    try:
        with psycopg.connect(test_dsn, autocommit=True) as conn:
            conn.execute(SCHEMA.read_text(encoding="utf-8"))
        yield PostgresStore(test_dsn)
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


# -- the database-enforced append-only property ------------------------------
def test_audit_rows_survive_update_and_delete(store):
    """The control that makes the hash chain more than a detective measure."""
    record = store.append_audit("k.de", "scope.rule.added", {"value": "example.com"})

    with psycopg.connect(store._dsn, autocommit=True) as conn:
        conn.execute("UPDATE audit_log SET actor = 'attacker' WHERE seq = %s",
                     (record.seq,))
        conn.execute("DELETE FROM audit_log WHERE seq = %s", (record.seq,))

    rows = store.audit_records()
    assert len(rows) == 1, "the DELETE must not have removed it"
    assert rows[0].actor == "k.de", "the UPDATE must not have altered it"
    assert store.verify_audit().ok


def test_the_app_role_holds_only_select_and_insert_on_the_audit_log(store):
    with psycopg.connect(store._dsn) as conn:
        granted = {r[0] for r in conn.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = 'skopos_app' AND table_name = 'audit_log'")}
    assert granted == {"SELECT", "INSERT"}


def test_chain_survives_a_round_trip_through_the_database(store):
    """JSONB storage must not perturb the payload the hash was computed over."""
    store.append_audit("k.de", "ownership.verified",
                       {"asset": "example.com", "method": "dns_txt", "n": 3})
    store.append_audit("k.de", "scan.started", {"nested": {"b": 2, "a": [1, 2]}})
    verdict = store.verify_audit()
    assert verdict.ok, verdict.explain()
    assert store.audit_records()[0].prev_hash == GENESIS


# -- constraints that must not depend on the application ---------------------
def test_manual_attestation_without_an_approver_is_rejected_by_the_database(store):
    """core/ownership.py refuses this too. Both, on purpose — see FR-M0-004."""
    with psycopg.connect(store._dsn, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO ownership_verification "
                "(asset, method, verified_at, expires_at) "
                "VALUES ('example.com', 'manual', DATE '2026-08-22', "
                "        DATE '2027-02-18')")


def test_expiry_must_follow_verification(store):
    with psycopg.connect(store._dsn, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO ownership_verification "
                "(asset, method, verified_at, expires_at, approved_by) "
                "VALUES ('example.com', 'manual', DATE '2026-08-22', "
                "        DATE '2026-08-01', 'k.de')")


def test_an_unknown_scope_kind_is_rejected(store):
    with psycopg.connect(store._dsn, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO scope_rule (kind, value, created_by) "
                "VALUES ('everything', '*', 'k.de')")


# -- the store's own behaviour, against a real database ----------------------
def test_scope_round_trips(store):
    store.add_scope_rule(ScopeRule(kind=ScopeKind.WILDCARD, value="example.com"),
                         actor="k.de")
    store.add_scope_rule(ScopeRule(kind=ScopeKind.DOMAIN, value="vpn.example.com",
                                   is_exclude=True, note="third-party"), actor="k.de")
    # Re-adding must not raise; scope editing is idempotent from the UI's side.
    store.add_scope_rule(ScopeRule(kind=ScopeKind.WILDCARD, value="example.com"),
                         actor="k.de")

    scope = store.load_scope()
    assert scope.includes("api.example.com")
    assert not scope.includes("vpn.example.com")


def test_live_verification_prefers_the_newest_and_ignores_the_expired(store):
    today = date(2026, 8, 22)
    store.record_verification(
        Verification.granted("shop.example.com", Method.DNS_TXT,
                             on=today - timedelta(days=400)))
    assert store.live_verification("shop.example.com", today) is None

    store.record_verification(
        Verification.granted("shop.example.com", Method.DNS_TXT,
                             on=today - timedelta(days=100)))
    fresh = Verification.granted("shop.example.com", Method.WELL_KNOWN, on=today)
    store.record_verification(fresh)

    live = store.live_verification("shop.example.com", today)
    assert live is not None
    assert live.expires_at == fresh.expires_at
    assert live.method is Method.WELL_KNOWN


def test_asset_lookup_is_case_insensitive(store):
    today = date(2026, 8, 22)
    store.record_verification(
        Verification.granted("Case.Example.COM", Method.DNS_TXT, on=today))
    assert store.live_verification("case.example.com", today) is not None


# -- migrations --------------------------------------------------------------
def test_every_migration_is_recorded(store):
    from core import migrate
    assert migrate.pending(store._dsn) == []
    assert "001" in migrate.applied(store._dsn)


def test_ensure_current_is_idempotent(store):
    from core import migrate
    assert migrate.ensure_current(store._dsn) == [], "a second run applies nothing"


def test_an_existing_volume_is_adopted_rather_than_rebuilt():
    """The skopos-db-1 case: 001 ran via Postgres's initdb hook, before there
    was a version table. Re-running it would fail on CREATE TABLE, so it is
    detected and recorded instead."""
    from core import migrate
    name = f"skopos_adopt_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    dsn = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    try:
        # Simulate the initdb path: schema present, no schema_migration table.
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(SCHEMA.read_text(encoding="utf-8"))
            assert conn.execute(
                "SELECT to_regclass('public.schema_migration')").fetchone()[0] is None

        applied = migrate.ensure_current(dsn)
        assert applied == [], "001 must be back-filled, not re-executed"
        assert migrate.applied(dsn) == ["001"]
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def test_require_current_refuses_when_behind(tmp_path):
    """Refusing beats serving: a missing CHECK constraint does not announce
    itself, it just stops rejecting the rows it exists to reject."""
    from core import migrate
    name = f"skopos_behind_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    dsn = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    fake = tmp_path / "db"
    fake.mkdir()
    (fake / "001_schema.sql").write_text(SCHEMA.read_text(encoding="utf-8"),
                                         encoding="utf-8")
    (fake / "002_later.sql").write_text(
        "CREATE TABLE later_thing (id INT PRIMARY KEY);", encoding="utf-8")
    try:
        migrate.ensure_current(dsn, directory=fake)
        assert migrate.pending(dsn, directory=fake) == []

        # A third migration appears with the code; the database is now behind.
        (fake / "003_newer.sql").write_text(
            "CREATE TABLE newer_thing (id INT PRIMARY KEY);", encoding="utf-8")
        with pytest.raises(migrate.SchemaBehind) as exc:
            migrate.require_current(dsn, directory=fake)
        assert "003" in str(exc.value)
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def test_a_failing_migration_leaves_the_schema_unchanged(tmp_path):
    """One transaction per file: half-applied is the state nobody can reason about."""
    from core import migrate
    name = f"skopos_fail_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    dsn = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    fake = tmp_path / "db"
    fake.mkdir()
    (fake / "001_broken.sql").write_text(
        "CREATE TABLE good_thing (id INT PRIMARY KEY);\n"
        "CREATE TABLE bad_thing (id INT PRIMARY KEY, x NOTATYPE);",
        encoding="utf-8")
    try:
        with pytest.raises(migrate.MigrationError):
            migrate.ensure_current(dsn, directory=fake)
        with psycopg.connect(dsn) as conn:
            assert conn.execute(
                "SELECT to_regclass('public.good_thing')").fetchone()[0] is None, \
                "the statement before the failure must have rolled back too"
        assert migrate.applied(dsn) == []
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
