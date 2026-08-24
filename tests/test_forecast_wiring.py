"""The forecast record actually accumulating, and every store migrating.

Both of these were built and left unconnected. Measured on the running stack:
db/004 sat unapplied while five scans completed, `forecast` and `epss_history`
did not exist, and 320 findings were produced with zero forecasts written. The
workstream sequenced FIRST because history cannot be backfilled was the one
silently doing nothing.
"""
from __future__ import annotations

import os
import uuid
from datetime import date, datetime, timedelta, timezone

import pytest

from core import forecast
from core.forecast import Forecast, Outcome, from_finding, input_vector
from core.forecast_store import MemoryForecastStore

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


live = pytest.mark.skipif(not _reachable(ADMIN_DSN),
                          reason="no database (docker compose up -d db)")


# ── the input vector ────────────────────────────────────────────────────────
def _finding():
    from core import engine
    from core.models import Asset, Confidence, Exploited, Exposure, MatchBasis
    entry = Exploited(cve="CVE-2021-44228", vendor_project="Apache",
                      product="Log4j2", name="RCE",
                      date_added=date(2021, 12, 10), short_description="x",
                      required_action="Patch.", known_ransomware=True)
    asset = Asset(identifier="app.example.com", product="Log4j2",
                  vendor="Apache", version="2.14.1", environment="production")
    return engine.score_exposure(
        Exposure(asset=asset, exploited=entry, basis=MatchBasis.PRODUCT_MATCH,
                 confidence=Confidence.STRONG, evidence=[]))


def test_the_vector_carries_inputs_not_just_the_score():
    """A score is a conclusion. The inputs are what a later model version must
    be re-run against to show it improved on anything."""
    vector = input_vector(_finding())
    for factor in ("exposure", "exploitability", "adversary_interest",
                   "business_criticality", "mitigation"):
        assert factor in vector, factor
    assert "epss" in vector and "known_ransomware" in vector


def test_the_vector_carries_the_flags_that_qualified_the_score():
    """A score computed with an unsupplied adversary factor is a different
    prediction from one computed with it, and a scorer needs to know which."""
    vector = input_vector(_finding())
    assert any("adversary interest" in f for f in vector["flags"])


def test_the_model_version_is_pinned_on_every_forecast():
    """Scoring a v1 forecast with a v2 model and publishing that as v2's
    accuracy is the most obvious way to manufacture an improvement.

    Asserted against the live constant rather than a frozen literal. This test
    previously pinned "teps-1.0.0" and correctly failed when P9 added
    `observed_in_intel` to AdversaryInterest — but what it is defending is that
    every forecast RECORDS the model that produced it, not that the model never
    changes. Freezing the string turns a real invariant into a change-detector,
    and the next person to improve the model would edit the literal without
    ever learning why the pin was there.

    The protection that actually matters lives in `core/backtest.py:score`,
    which filters to one `model_version` before computing anything — so two
    models are never pooled into one accuracy figure. `test_the_scoreboard…`
    below covers that, and this covers the wiring that makes it possible.
    """
    from core import scoring

    forecast = from_finding(_finding())
    assert forecast.model_version == scoring.MODEL_VERSION
    assert forecast.model_version, "a forecast with no model version is unscorable"


def test_a_scoreboard_never_pools_two_model_versions():
    """The invariant the pin above exists to make possible.

    Without this, adding a factor to TEPS would silently mix scores from the
    old and new models into one Brier figure — which is exactly the
    manufactured improvement the docstring above warns about.
    """
    import dataclasses

    from core import backtest

    fresh = from_finding(_finding())
    stale = dataclasses.replace(fresh, model_version="teps-0.9.0")

    board = backtest.score([stale, fresh], fresh.model_version)
    assert board.model_version == fresh.model_version
    assert board.issued == 1, "a second model version leaked into the board"


# ── the record accumulates ──────────────────────────────────────────────────
def test_recording_the_same_pairing_twice_in_a_run_writes_once():
    """Double-counting a pairing would inflate every accuracy figure."""
    store = MemoryForecastStore()
    row = from_finding(_finding())
    assert store.record([row]) == 1
    assert store.record([from_finding(_finding())]) == 0


def test_an_unresolved_forecast_is_not_scored():
    store = MemoryForecastStore()
    store.record([from_finding(_finding())])
    assert forecast.brier_score(store.all_forecasts()) is None, \
        "a Brier score over nothing resolved is the most misleading number here"


def test_a_resolved_record_produces_a_score():
    store = MemoryForecastStore()
    row = from_finding(_finding())
    store.record([row])
    store.resolve(row.asset, row.cve, row.model_version, Outcome.KEV_ADDED,
                  "CISA KEV")
    assert forecast.brier_score(store.all_forecasts()) is not None


def test_the_headline_says_when_nothing_is_resolved_yet():
    store = MemoryForecastStore()
    store.record([from_finding(_finding())])
    headline = forecast.score_record(store.all_forecasts(), "teps-1.0.0").headline()
    assert "none resolved yet" in headline
    assert "No accuracy can be claimed" in headline


def test_a_missed_lead_target_is_reported_not_omitted():
    """A predictive product that never measures its predictions is marketing."""
    now = datetime.now(timezone.utc)
    rows = [Forecast(asset="a", cve=f"CVE-{i}", model_version="teps-1.0.0",
                     inputs={}, teps=80, band="critical",
                     issued_at=now - timedelta(days=2),
                     resolved_at=now, outcome=Outcome.KEV_ADDED)
            for i in range(3)]
    accuracy = forecast.score_record(rows, "teps-1.0.0")
    assert accuracy.median_lead_days == 2
    assert "BELOW the 7-day target" in accuracy.headline()


# ── every store migrates ────────────────────────────────────────────────────
@live
def test_every_postgres_store_brings_the_schema_up_to_date():
    """The bug: ensure_current lived only in PostgresStore, so a deployment
    whose traffic went through the findings store never migrated at all."""
    from core import migrate
    from core.dns_store import PostgresDnsStore
    from core.findings_store import PostgresFindingsStore
    from core.forecast_store import PostgresForecastStore
    from core.store import PostgresStore

    for cls in (PostgresFindingsStore, PostgresDnsStore, PostgresForecastStore,
                PostgresStore):
        name = f"skopos_mig_{uuid.uuid4().hex[:10]}"
        with psycopg.connect(ADMIN_DSN, autocommit=True) as c:
            c.execute(f'CREATE DATABASE "{name}"')
        dsn = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
        try:
            migrate.forget(dsn)
            cls(dsn)
            assert migrate.pending(dsn) == [], \
                f"{cls.__name__} left the schema behind"
        finally:
            migrate.forget(dsn)
            with psycopg.connect(ADMIN_DSN, autocommit=True) as c:
                c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@live
def test_migrating_is_memoised_so_it_does_not_run_per_request():
    from core import migrate
    from core.findings_store import PostgresFindingsStore
    name = f"skopos_memo_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    dsn = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    try:
        migrate.forget(dsn)
        PostgresFindingsStore(dsn)
        assert dsn in migrate._ENSURED
        PostgresFindingsStore(dsn)          # must not raise or re-run
    finally:
        migrate.forget(dsn)
        with psycopg.connect(ADMIN_DSN, autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@live
def test_forecasts_and_epss_round_trip_through_postgres():
    from core import migrate
    from core.forecast_store import PostgresForecastStore
    name = f"skopos_fc_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    dsn = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    try:
        migrate.forget(dsn)
        store = PostgresForecastStore(dsn)
        row = from_finding(_finding())
        assert store.record([row]) == 1
        assert store.record([row]) == 0, "the same pairing must not double-count"

        # The LIVE version, not a literal. `from_finding` stamps whatever
        # core/scoring.py currently produces, so a hardcoded version here
        # queries for rows the fixture never wrote — which is exactly what
        # happened when P9 moved the model to teps-1.1.0. It went unnoticed
        # because this test only runs against a live database.
        back = store.all_forecasts(row.model_version)
        assert len(back) == 1
        assert back[0].inputs["adversary_interest"] == pytest.approx(0.15)

        assert store.resolve(row.asset, row.cve, row.model_version,
                             Outcome.KEV_ADDED, "CISA KEV")
        assert store.all_forecasts()[0].resolved

        today = date(2026, 8, 23)
        assert store.record_epss(today, {"CVE-1": {"epss": 0.3,
                                                   "percentile": 0.9}}) == 1
        assert store.record_epss(today, {"CVE-1": {"epss": 0.3}}) == 0
        assert store.epss_series("CVE-1") == [(today, 0.3)]
    finally:
        migrate.forget(dsn)
        with psycopg.connect(ADMIN_DSN, autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
