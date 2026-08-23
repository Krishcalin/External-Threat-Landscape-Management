"""The commands without which nothing else in the product runs.

Before these existed, a fresh install could not create a scope rule: the schema
seeds none, no API route makes one, and `add_scope_rule` was called from two test
files and nowhere else. `docker compose up -d && etlm discover example.com` would
refuse every operation and exit, with no supported command that fixed it — the
operator's only route was hand-writing an INSERT.

Driven as a real subprocess against a throwaway database, because the exit codes
are part of the contract and an in-process call does not produce one.
"""
from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "db" / "001_schema.sql"

psycopg = pytest.importorskip("psycopg", reason="psycopg is not installed")

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
def dsn():
    name = f"skopos_cli_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    target = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    try:
        with psycopg.connect(target, autocommit=True) as conn:
            conn.execute(SCHEMA.read_text(encoding="utf-8"))
        yield target
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def run(dsn, *args, **kwargs):
    env = dict(os.environ)
    env["SKOPOS_DATABASE_URL"] = dsn
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "main.py", *args], cwd=ROOT,
                          capture_output=True, text=True, encoding="utf-8",
                          env=env, timeout=120, **kwargs)


# -- the bootstrap problem ---------------------------------------------------
def test_an_empty_scope_says_what_to_do_about_it(dsn):
    result = run(dsn, "scope", "list")
    assert result.returncode == 0
    assert "Scope is empty" in result.stdout
    assert "scope add" in result.stdout, \
        "the empty state must name the command that fixes it"


def test_discovery_against_an_unscoped_apex_exits_3_with_the_gates_sentence(dsn):
    """A governance refusal is not a coverage gap.

    Filing it as one would tell the operator a source was down when in fact they
    never declared the domain — and hand them the wrong remedy.
    """
    result = run(dsn, "discover", "nobody-declared-this.example",
                 "--actor", "k.de", "--dry-run")
    assert result.returncode == 3, result.stderr
    assert "no scope rule mentions this asset" in result.stderr
    assert "Add it to scope" in result.stderr


def test_scope_add_then_discover_is_authorised(dsn):
    assert run(dsn, "scope", "add", "example.com", "--kind", "wildcard",
               "--actor", "k.de").returncode == 0
    result = run(dsn, "discover", "example.com", "--actor", "k.de", "--dry-run")
    assert result.returncode == 0, result.stderr
    assert "Would query" in result.stdout
    assert "ct_log_search" in result.stdout, "the operations must be named"
    assert "Nothing was contacted" in result.stdout


def test_the_dry_run_contacts_nothing(dsn):
    """A preview that reaches the network is not a preview."""
    result = run(dsn, "discover", "example.com", "--actor", "k.de", "--dry-run")
    assert "Nothing was contacted" in result.stdout
    assert "16 of" not in result.stdout, "a preview must not carry live counts"


# -- exclusions --------------------------------------------------------------
def test_an_exclusion_beats_the_include_that_covers_it(dsn):
    run(dsn, "scope", "add", "excluded.example.com", "--kind", "domain",
        "--exclude", "--note", "third-party managed", "--actor", "k.de")
    result = run(dsn, "discover", "excluded.example.com", "--actor", "k.de",
                 "--dry-run")
    assert result.returncode == 3
    assert "third-party managed" in result.stderr
    assert "deliberate instruction" in result.stderr


def test_adding_an_exclusion_says_that_it_wins(dsn):
    result = run(dsn, "scope", "add", "203.0.113.0/24", "--kind", "cidr",
                 "--exclude", "--actor", "k.de")
    assert "EXCLUDED" in result.stdout
    assert "wins over every include" in result.stdout


# -- ownership ---------------------------------------------------------------
def test_a_manual_attestation_without_an_approver_is_refused(dsn):
    result = run(dsn, "verify", "example.com", "--method", "manual",
                 "--actor", "k.de")
    assert result.returncode == 1
    assert "must record who approved it" in result.stderr


def test_verification_states_its_expiry(dsn):
    result = run(dsn, "verify", "api.example.com", "--method", "dns_txt",
                 "--actor", "k.de")
    assert result.returncode == 0, result.stderr
    assert "day(s) remaining" in result.stdout
    assert "expires" in result.stdout.lower()


def test_scope_check_shows_what_each_operation_would_do(dsn):
    """The preview that uses the verifications actually on record."""
    run(dsn, "scope", "add", "checkme.example.com", "--kind", "domain",
        "--actor", "k.de")
    result = run(dsn, "scope", "check", "checkme.example.com", "--actor", "k.de")
    assert result.returncode == 0, result.stderr
    assert "INCLUDED" in result.stdout
    assert "never verified" in result.stdout
    assert "ct_log_search" in result.stdout and "would run" in result.stdout
    # Active work is refused for an unverified asset, and the preview says so
    # rather than claiming it would run.
    active_line = [l for l in result.stdout.splitlines() if "port_scan" in l]
    assert active_line and "REFUSED" in active_line[0]


# -- the audit trail ---------------------------------------------------------
def test_every_scope_edit_lands_in_the_audit_chain(dsn):
    from core.store import PostgresStore
    run(dsn, "scope", "add", "audited.example.com", "--kind", "domain",
        "--actor", "auditor@example.com")
    store = PostgresStore(dsn, migrate=False)
    actions = [(r.actor, r.action) for r in store.audit_records()]
    assert ("auditor@example.com", "scope.rule.added") in actions
    assert store.verify_audit().ok


def test_the_actor_is_required_and_has_no_default(dsn):
    """Never getpass.getuser(). The chain records a claim, not an identity, and
    a default would quietly attribute actions to whoever ran the container."""
    result = run(dsn, "scope", "add", "x.example.com", "--kind", "domain")
    assert result.returncode != 0
    assert "--actor" in result.stderr


def test_the_help_says_the_actor_is_not_authenticated(dsn):
    result = run(dsn, "scope", "add", "--help")
    # argparse rewraps help text, so the phrase can arrive split across lines.
    # Collapse whitespace rather than asserting on argparse's line breaks.
    flattened = " ".join(result.stdout.split())
    assert "asserted, not authenticated" in flattened
