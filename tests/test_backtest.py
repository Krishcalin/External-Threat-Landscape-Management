"""The scoreboard, and the several ways it could have flattered the product.

Every test here is about a number NOT being published, or being published with
the reference that makes it readable. A Brier score on its own is unreadable,
and a Brier score over five outcomes is noise.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core import backtest
from core.backtest import (MIN_RESOLVED_TO_PUBLISH, LEAD_TIME_UNMEASURABLE,
                           due_for_resolution, score)
from core.forecast import BAND_PROBABILITY, Forecast, Outcome

NOW = datetime(2026, 8, 23, tzinfo=timezone.utc)


def fc(band="critical", outcome=None, days_ago=0, epss=0.1, cve="CVE-1"):
    return Forecast(asset="a.example.com", cve=cve, model_version="teps-1.0.0",
                    inputs={"epss": epss}, teps=80, band=band,
                    issued_at=NOW - timedelta(days=days_ago),
                    resolved_at=NOW if outcome else None, outcome=outcome)


# ── nothing is published early ──────────────────────────────────────────────
def test_an_empty_record_publishes_no_figure():
    board = score([], "teps-1.0.0")
    assert board.brier is None and not board.publishable
    assert "no accuracy figure exists" in board.headline()


def test_unresolved_forecasts_produce_no_score():
    board = score([fc() for _ in range(50)], "teps-1.0.0")
    assert board.issued == 50 and board.resolved == 0
    assert board.brier is None
    assert "NONE resolved yet" in board.headline()


def test_a_handful_of_outcomes_is_not_published():
    """A Brier over five outcomes is noise wearing the costume of a
    measurement, and publishing it spends the credibility this exists for."""
    rows = [fc(outcome=Outcome.NO_EVENT, cve=f"CVE-{i}") for i in range(5)]
    board = score(rows, "teps-1.0.0")
    assert board.resolved == 5
    assert not board.publishable
    assert f"Below {MIN_RESOLVED_TO_PUBLISH}" in board.headline()


def test_enough_outcomes_publishes():
    rows = [fc(band="low", outcome=Outcome.NO_EVENT, cve=f"CVE-{i}")
            for i in range(MIN_RESOLVED_TO_PUBLISH)]
    board = score(rows, "teps-1.0.0")
    assert board.publishable and board.brier is not None


# ── a bare Brier is unreadable, so references ship with it ──────────────────
def test_every_figure_carries_its_references():
    rows = ([fc(band="critical", outcome=Outcome.EPSS_CROSSED, cve=f"C{i}")
             for i in range(20)]
            + [fc(band="critical", outcome=Outcome.NO_EVENT, cve=f"N{i}")
               for i in range(20)])
    board = score(rows, "teps-1.0.0")
    assert board.climatology_brier is not None
    assert board.base_rate == pytest.approx(0.5)
    assert board.skill is not None
    assert board.to_dict()["uninformative_brier"] == 0.25


def test_a_model_that_does_not_beat_the_base_rate_says_so():
    """The number most worth publishing honestly."""
    # Every forecast critical (claims 0.80) but the event almost never happens.
    rows = ([fc(band="critical", outcome=Outcome.NO_EVENT, cve=f"N{i}")
             for i in range(38)]
            + [fc(band="critical", outcome=Outcome.EPSS_CROSSED, cve=f"C{i}")
               for i in range(2)])
    board = score(rows, "teps-1.0.0")
    assert board.skill < 0
    assert "DOES NOT BEAT" in board.headline()
    assert "Published because it is true" in board.headline()


def test_a_perfectly_calibrated_model_beats_climatology():
    rows = ([fc(band="critical", outcome=Outcome.EPSS_CROSSED, cve=f"C{i}")
             for i in range(20)]
            + [fc(band="informational", outcome=Outcome.NO_EVENT, cve=f"N{i}")
               for i in range(20)])
    board = score(rows, "teps-1.0.0")
    assert board.skill > 0
    assert "beats predicting the base rate" in board.headline()


# ── calibration ─────────────────────────────────────────────────────────────
def test_calibration_reports_claimed_against_observed_per_band():
    rows = ([fc(band="high", outcome=Outcome.EPSS_CROSSED, cve=f"C{i}")
             for i in range(6)]
            + [fc(band="high", outcome=Outcome.NO_EVENT, cve=f"N{i}")
               for i in range(4)])
    board = score(rows, "teps-1.0.0")
    high = [c for c in board.calibration if c.band == "high"][0]
    assert high.claimed == BAND_PROBABILITY["high"]
    assert high.actual == pytest.approx(0.6)


def test_a_hit_rate_over_two_outcomes_is_labelled_untrustworthy():
    rows = [fc(band="low", outcome=Outcome.EPSS_CROSSED, cve=f"C{i}")
            for i in range(2)]
    low = [c for c in score(rows, "teps-1.0.0").calibration if c.band == "low"][0]
    assert not low.trustworthy
    assert "too few to read anything into" in low.explain()


# ── the metric that cannot be measured ──────────────────────────────────────
def test_lead_time_is_always_reported_as_unmeasurable_with_its_reason():
    """Not omitted — an absent metric reads as an oversight. Not computed —
    every lead time in the record is negative, so a number would be a lie."""
    board = score([fc(outcome=Outcome.NO_EVENT)], "teps-1.0.0")
    assert board.lead_time == LEAD_TIME_UNMEASURABLE
    assert "UNMEASURABLE" in board.lead_time
    assert "advisory path" in board.lead_time


def test_the_reason_is_structural_not_a_data_shortage():
    assert "not for want of data" in LEAD_TIME_UNMEASURABLE
    assert "every lead time is negative" in LEAD_TIME_UNMEASURABLE


# ── the observation window ──────────────────────────────────────────────────
def test_a_forecast_inside_its_window_is_not_yet_a_miss():
    """Marking it NO_EVENT early scores the model against an event that may
    still happen."""
    assert due_for_resolution([fc(days_ago=10)], today=NOW.date(),
                              window_days=90) == []


def test_a_forecast_past_its_window_is_due():
    assert len(due_for_resolution([fc(days_ago=95)], today=NOW.date(),
                                  window_days=90)) == 1


def test_a_resolved_forecast_is_never_due_again():
    assert due_for_resolution([fc(outcome=Outcome.NO_EVENT, days_ago=200)],
                              today=NOW.date()) == []


# ── no_event is a success for a low forecast ────────────────────────────────
def test_no_event_scores_a_low_forecast_well_and_a_high_one_badly():
    """The asymmetry a Brier score exists to capture."""
    low = score([fc(band="informational", outcome=Outcome.NO_EVENT,
                    cve=f"N{i}") for i in range(MIN_RESOLVED_TO_PUBLISH)],
                "teps-1.0.0")
    high = score([fc(band="critical", outcome=Outcome.NO_EVENT, cve=f"N{i}")
                  for i in range(MIN_RESOLVED_TO_PUBLISH)], "teps-1.0.0")
    assert low.brier < high.brier


def test_only_the_named_model_version_is_scored():
    """Scoring a v1 forecast with a v2 model and publishing that as v2's
    accuracy is the obvious way to manufacture an improvement."""
    rows = [fc(outcome=Outcome.NO_EVENT, cve=f"N{i}") for i in range(5)]
    rows.append(Forecast(asset="a", cve="X", model_version="teps-2.0.0",
                         inputs={}, teps=1, band="low",
                         issued_at=NOW, resolved_at=NOW,
                         outcome=Outcome.NO_EVENT))
    assert score(rows, "teps-1.0.0").issued == 5
    assert score(rows, "teps-2.0.0").issued == 1
