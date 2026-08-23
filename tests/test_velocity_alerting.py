"""W4 EPSS velocity and W5 alerting.

Nothing here touches the network. What is under test is the judgement — which
movements count, and which changes are worth interrupting somebody for.
"""
from __future__ import annotations

from datetime import date, timedelta

import pytest

from core import alerting, velocity
from core.alerting import Alert, Policy, Trigger
from core.forecast_store import MemoryForecastStore
from core.velocity import MIN_MEANINGFUL_DELTA

TODAY = date(2026, 8, 23)


def series(*pairs):
    return [(TODAY - timedelta(days=d), v) for d, v in pairs]


# ── W4: velocity ────────────────────────────────────────────────────────────
def test_a_sharp_rise_is_accelerating():
    """0.02 to 0.31 in four days is the world changing its mind."""
    v = velocity.compute("CVE-1", series((4, 0.02), (0, 0.31)), today=TODAY)
    assert v.accelerating
    assert v.delta == pytest.approx(0.29)
    assert "changed" in v.explain()


def test_daily_jitter_is_not_a_signal():
    """A threshold of zero would make every CVE accelerate every day."""
    v = velocity.compute("CVE-1", series((4, 0.300), (0, 0.312)), today=TODAY)
    assert not v.accelerating
    assert v.delta < MIN_MEANINGFUL_DELTA


def test_a_falling_score_is_reported_as_falling():
    v = velocity.compute("CVE-1", series((7, 0.60), (0, 0.20)), today=TODAY)
    assert v.decelerating and not v.accelerating
    assert "fell" in v.explain()


def test_one_reading_gives_no_velocity_rather_than_a_zero():
    """"The score did not move" and "we have one reading" are different facts.

    A zero would let a CVE watched since yesterday sit alongside one watched
    for months, both looking equally quiet.
    """
    v = velocity.compute("CVE-1", series((0, 0.31)), today=TODAY)
    assert v.readings == 1
    assert not v.accelerating
    assert "no velocity can be computed" in v.explain()
    assert "not the same as a flat score" in v.explain()


def test_no_history_at_all_returns_none():
    assert velocity.compute("CVE-1", [], today=TODAY) is None


def test_a_short_series_says_it_covers_less_time_than_it_appears_to():
    v = velocity.compute("CVE-1", series((2, 0.10), (0, 0.40)),
                         window_days=14, today=TODAY)
    assert v.partial
    assert "shorter than the requested window" in v.explain()


def test_readings_outside_the_window_are_excluded():
    v = velocity.compute("CVE-1", series((90, 0.01), (3, 0.30), (0, 0.32)),
                         window_days=14, today=TODAY)
    assert v.readings == 2
    assert v.first == 0.30, "the 90-day-old reading must not anchor the delta"


def test_accelerating_returns_the_steepest_first():
    rows = [velocity.compute("A", series((7, 0.1), (0, 0.2)), today=TODAY),
            velocity.compute("B", series((7, 0.1), (0, 0.9)), today=TODAY),
            velocity.compute("C", series((7, 0.10), (0, 0.11)), today=TODAY)]
    top = velocity.accelerating(rows)
    assert [v.cve for v in top] == ["B", "A"], "C is noise and must not appear"


def test_coverage_states_how_much_could_not_be_computed():
    """A young EPSS history makes the accelerating set look small for a reason
    that has nothing to do with the estate."""
    rows = [velocity.compute("A", series((7, 0.1), (0, 0.5)), today=TODAY),
            velocity.compute("B", series((0, 0.3)), today=TODAY)]
    cover = velocity.coverage(rows)
    assert cover["computable"] == 1
    assert cover["insufficient_history"] == 1


# ── W4: the store ───────────────────────────────────────────────────────────
def test_recording_the_same_day_twice_writes_one_row():
    """A second reading would silently weight that day twice in every velocity."""
    store = MemoryForecastStore()
    scores = {"CVE-1": {"epss": 0.3, "percentile": 0.9}}
    assert store.record_epss(TODAY, scores) == 1
    assert store.record_epss(TODAY, scores) == 0
    assert len(store.epss_series("CVE-1")) == 1


def test_the_series_comes_back_in_order():
    store = MemoryForecastStore()
    for offset, value in ((2, 0.1), (0, 0.3), (1, 0.2)):
        store.record_epss(TODAY - timedelta(days=offset),
                          {"CVE-1": {"epss": value}})
    assert [v for _d, v in store.epss_series("CVE-1")] == [0.1, 0.2, 0.3]


# ── W5: what is worth sending ───────────────────────────────────────────────
class FakeDiff:
    def __init__(self, new=(), reband=()):
        self.new = list(new)
        self.reband = list(reband)


def finding(band="critical", cve="CVE-1", basis="product_match", **extra):
    row = {"asset": "vpn.example.com", "product": "Connect Secure", "cve": cve,
           "band": band, "teps": 88, "basis": basis, "evidence": ["names match"]}
    row.update(extra)
    return row


def test_a_new_critical_finding_alerts():
    out = alerting.build(FakeDiff(new=[finding()]))
    assert len(out["alerts"]) == 1
    assert out["alerts"][0].trigger is Trigger.NEW_FINDING


def test_a_low_band_finding_is_suppressed_but_counted():
    """Suppressed is not lost, and the operator is told which it was."""
    out = alerting.build(FakeDiff(new=[finding(band="low")]))
    assert out["alerts"] == []
    assert out["suppressed_below_band"] == 1
    assert "not lost" in out["note"]


def test_a_band_change_does_not_alert_by_default():
    """EPSS moves daily, TEPS moves with it, and a feed that fires on score
    drift is one nobody reads — the same reasoning that made (asset, cve) the
    diff key rather than the score."""
    out = alerting.build(FakeDiff(reband=[finding(previous_band="high")]))
    assert out["alerts"] == []
    assert Trigger.BAND_CHANGED not in alerting.DEFAULT_TRIGGERS


def test_a_band_change_can_be_opted_into():
    policy = Policy(triggers=(Trigger.BAND_CHANGED,))
    out = alerting.build(FakeDiff(reband=[finding(previous_band="high")]),
                         policy=policy)
    assert len(out["alerts"]) == 1


def test_the_subject_distinguishes_a_determination_from_a_worklist_entry():
    """'Confirmed vulnerable' and 'runs a product with an exploited
    vulnerability' warrant different urgency."""
    worklist = alerting.build(FakeDiff(new=[finding()]))["alerts"][0]
    confirmed = alerting.build(
        FakeDiff(new=[finding(basis="version_range")]))["alerts"][0]
    assert "version unverified" in worklist.subject
    assert "CONFIRMED by version" in confirmed.subject


def test_an_alert_carries_enough_to_act_without_the_console():
    alert = alerting.build(FakeDiff(new=[finding()]))["alerts"][0]
    for expected in ("vpn.example.com", "CVE-1", "TEPS", "Evidence"):
        assert expected in alert.body


def test_the_cap_announces_itself():
    """A cap that does not say it capped becomes a silent filter on the
    operator's view of their own estate."""
    out = alerting.build(
        FakeDiff(new=[finding(cve=f"CVE-{i}") for i in range(40)]),
        policy=Policy(max_alerts=10))
    assert len(out["alerts"]) == 10
    assert out["suppressed_by_cap"] == 30
    assert "CAPPED" in out["note"]


def test_an_unknown_band_is_alerted_rather_than_dropped():
    """A band we do not recognise is more likely a new severity than a mistake,
    and swallowing it is the wrong direction of error."""
    out = alerting.build(FakeDiff(new=[finding(band="catastrophic")]))
    assert len(out["alerts"]) == 1


def test_a_takeover_alert_repeats_the_ceiling():
    out = alerting.build(FakeDiff(), takeover_new=[{
        "name": "shop.example.com", "target": "bucket.s3.amazonaws.com",
        "verdict": "inconclusive", "target_rcode": "NXDOMAIN",
        "resolvers_agreeing": 3, "reasons": ["target does not resolve"]}])
    body = out["alerts"][0].body
    assert "never reports a subdomain as 'vulnerable'" in body


def test_a_quiet_run_says_so():
    assert "Nothing met the alert policy" in alerting.build(FakeDiff())["note"]


# ── W5: delivery ────────────────────────────────────────────────────────────
def test_a_plaintext_webhook_is_refused():
    """Findings name your unpatched systems."""
    with pytest.raises(alerting.DeliveryFailed) as exc:
        alerting.send_webhook("http://example.com/hook", [
            Alert(Trigger.NEW_FINDING, "s", "b")])
    assert "not https" in str(exc.value)


def test_no_configured_channel_is_reported_not_silent(monkeypatch):
    """Alerts computed and undelivered must not look like alerts delivered."""
    monkeypatch.delenv("SKOPOS_ALERT_WEBHOOK", raising=False)
    monkeypatch.delenv("SKOPOS_ALERT_EMAIL", raising=False)
    out = alerting.dispatch([Alert(Trigger.NEW_FINDING, "s", "b")])
    assert out["sent"] == 0
    assert "no alert channel is configured" in out["note"]


def test_dispatching_nothing_is_not_an_error():
    assert alerting.dispatch([])["sent"] == 0


def test_alert_dispatch_is_a_registered_operation():
    """It sends findings OUT, so 'where do our findings get posted' must be a
    question the audit log can answer."""
    from core import gate
    assert gate.classify("alert_dispatch") is gate.Exposure.PASSIVE
