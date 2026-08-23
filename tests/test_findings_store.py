"""Findings survive a restart, and the diff that persistence makes possible.

Before this they lived in a module-level dict in api/app.py. Measured: a scan
produced 64 findings across 7 assets, `docker compose restart app` followed, and
GET /api/v1/summary answered "no scan has been run" — while scope, ownership,
the audit chain and every DNS observation survived intact.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from core.findings_store import (MemoryFindingsStore, PostgresFindingsStore,
                                 RunDiff, _diff)

ROOT = Path(__file__).resolve().parents[1]


def finding(asset, cve, teps=50.0, band="medium", ransom=False):
    return {"asset": asset, "product": "Connect Secure", "cve": cve,
            "teps": teps, "band": band, "basis": "product_match",
            "name_confidence": "strong", "known_ransomware": ransom,
            "reconciliation": None}


CATALOGUE = {"catalog_version": "2026.08.21", "age_days": 2}


# -- identity ----------------------------------------------------------------
def test_a_finding_is_identified_by_asset_and_cve_not_by_score():
    """Keying on TEPS or band would report a score move as a NEW finding and
    flood the feed with things the operator has already seen — the fastest way
    to make it unreadable. EPSS moves daily."""
    before = [finding("a.example.com", "CVE-2021-44228", teps=40.0, band="medium")]
    after = [finding("a.example.com", "CVE-2021-44228", teps=91.0, band="critical")]
    diff = _diff(before, after, previous_run=1)
    assert diff.new == []
    assert len(diff.reband) == 1
    assert diff.reband[0]["previous_band"] == "medium"


def test_a_genuinely_new_cve_is_new():
    diff = _diff([finding("a.example.com", "CVE-1111-1111")],
                 [finding("a.example.com", "CVE-1111-1111"),
                  finding("a.example.com", "CVE-2222-2222")], previous_run=1)
    assert [f["cve"] for f in diff.new] == ["CVE-2222-2222"]
    assert diff.carried == 1


def test_the_same_cve_on_a_different_asset_is_new():
    diff = _diff([finding("a.example.com", "CVE-1111-1111")],
                 [finding("b.example.com", "CVE-1111-1111")], previous_run=1)
    assert len(diff.new) == 1 and len(diff.resolved) == 1


def test_a_finding_that_went_away_is_reported_as_resolved():
    diff = _diff([finding("a.example.com", "CVE-1111-1111")], [], previous_run=1)
    assert len(diff.resolved) == 1
    assert "no longer present" in diff.headline()


def test_a_baseline_claims_nothing_is_new():
    """Nothing can be new on a first run; saying so would be a false claim about
    what changed."""
    store = MemoryFindingsStore()
    store.record_run("k.de", "x.csv", CATALOGUE, 2, 0, 0, {},
                     [finding("a.example.com", "CVE-1111-1111")])
    diff = store.diff_against_previous()
    assert diff.is_baseline
    assert "Nothing is 'new' on a baseline" in diff.headline()


# -- the store ---------------------------------------------------------------
def test_findings_are_retrievable_after_the_run_that_made_them():
    store = MemoryFindingsStore()
    store.record_run("k.de", "x.csv", CATALOGUE, 1, 0, 0, {"findings": 2},
                     [finding("a.example.com", "CVE-1111-1111", teps=80.0),
                      finding("b.example.com", "CVE-2222-2222", teps=20.0)])
    rows = store.findings()
    assert [r["teps"] for r in rows] == [80.0, 20.0], "ranked by TEPS"


def test_band_and_reconciliation_filters_apply():
    store = MemoryFindingsStore()
    store.record_run("k.de", "x.csv", CATALOGUE, 1, 0, 0, {},
                     [finding("a.example.com", "CVE-1", band="critical"),
                      finding("b.example.com", "CVE-2", band="low")])
    assert len(store.findings(band="critical")) == 1


def test_the_run_records_the_catalogue_that_answered_it():
    """A refresh between the scan and the request would otherwise silently
    re-attribute a result to a corpus that never saw it."""
    store = MemoryFindingsStore()
    store.record_run("k.de", "x.csv", CATALOGUE, 1, 0, 0, {}, [])
    assert store.latest_run()["catalog_version"] == "2026.08.21"
    assert store.latest_run()["catalog_age_days"] == 2


def test_the_run_records_what_did_not_match():
    """The honest counterpart to the finding count, stored beside it rather
    than recomputed — a later corpus refresh would change the answer."""
    store = MemoryFindingsStore()
    store.record_run("k.de", "x.csv", CATALOGUE, 400, 3, 380, {}, [])
    run = store.latest_run()
    assert run["assets_unmatched"] == 380
    assert run["rows_rejected"] == 3


# -- against the real database -----------------------------------------------
psycopg = pytest.importorskip("psycopg", reason="psycopg is not installed")

ADMIN_DSN = os.environ.get(
    "SKOPOS_TEST_ADMIN_DSN",
    os.environ.get("SKOPOS_DATABASE_URL",
                   "postgresql://skopos@127.0.0.1:55443/skopos"))


def _reachable(dsn):
    try:
        with psycopg.connect(dsn, connect_timeout=3):
            return True
    except Exception:
        return False


live = pytest.mark.skipif(
    not _reachable(ADMIN_DSN),
    reason="no database (docker compose up -d db)")


@pytest.fixture
def live_store():
    from core import migrate
    name = f"skopos_find_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    dsn = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    try:
        migrate.ensure_current(dsn)
        yield PostgresFindingsStore(dsn)
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def bound(dsn, **kw):
    """A raw connection bound to an organisation, like every store connection.

    After migration 006 a connection that never sets `skopos.org_id` writes NULL
    into org_id and is refused by NOT NULL. That is the intended failure
    direction — an unset tenant must not silently land in somebody's data — so
    tests that reach past the store and execute SQL directly have to declare
    their tenant too.
    """
    import psycopg
    conn = psycopg.connect(dsn, **kw)
    conn.execute("SELECT set_config('skopos.org_id', 'default', false)")
    return conn

@live
def test_findings_survive_a_new_connection(live_store):
    """The restart case, as close as a test can get: a completely separate
    store object reading what another one wrote."""
    run_id = live_store.record_run(
        "k.de", "x.csv", CATALOGUE, 2, 0, 0, {"findings": 1},
        [finding("a.example.com", "CVE-1111-1111")])
    fresh = PostgresFindingsStore(live_store._dsn)
    assert fresh.latest_run()["id"] == run_id
    assert len(fresh.findings()) == 1


@live
def test_the_diff_works_across_two_stored_runs(live_store):
    live_store.record_run("k.de", "x.csv", CATALOGUE, 1, 0, 0, {},
                          [finding("a.example.com", "CVE-1111-1111")])
    live_store.record_run("k.de", "x.csv", CATALOGUE, 1, 0, 0, {},
                          [finding("a.example.com", "CVE-1111-1111"),
                           finding("a.example.com", "CVE-2222-2222")])
    diff = live_store.diff_against_previous()
    assert [f["cve"] for f in diff.new] == ["CVE-2222-2222"]
    assert diff.carried == 1


@live
def test_the_database_refuses_an_invented_basis(live_store):
    """PRODUCT_MATCH vs VERSION_RANGE is the product's central claim, so the
    schema refuses a third value rather than accepting one somebody invents."""
    with bound(live_store._dsn, autocommit=True) as conn:
        conn.execute("INSERT INTO scan_run (actor, inventory, catalog_version)"
                     " VALUES ('k.de','x','v1')")
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO finding (run_id, asset, product, cve, teps, band,"
                " basis, name_confidence, payload)"
                " VALUES ((SELECT max(id) FROM scan_run),'a','p','CVE-1',1,'low',"
                "         'definitely_vulnerable','strong','{}'::jsonb)")


@live
def test_a_run_and_its_findings_are_deleted_together(live_store):
    """No orphan findings pointing at a run nobody can look up."""
    run_id = live_store.record_run("k.de", "x.csv", CATALOGUE, 1, 0, 0, {},
                                   [finding("a.example.com", "CVE-1111-1111")])
    with psycopg.connect(live_store._dsn, autocommit=True) as conn:
        conn.execute("DELETE FROM scan_run WHERE id = %s", (run_id,))
        remaining = conn.execute(
            "SELECT count(*) FROM finding WHERE run_id = %s", (run_id,)).fetchone()[0]
    assert remaining == 0
