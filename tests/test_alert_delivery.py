"""Delivery from a scan run, and the four states it must never confuse.

Three of the four are "nothing was sent", and the one that matters is the third:
delivery switched on with no channel configured. From outside it looks exactly
like a quiet run, and a silent alerting integration is worse than none because
it is mistaken for coverage.
"""
from __future__ import annotations

import pytest

from core import alerting
from core.findings_store import RunDiff

FINDING = {"asset": "fw-01.example.com", "cve": "CVE-2018-13379",
           "product": "FortiOS", "band": "critical", "teps": 88.0,
           "basis": "product_match", "evidence": ["product: fortios"],
           "owner": "Network Team"}


def diff(new=(), reband=()):
    return RunDiff(previous_run=7, new=list(new), reband=list(reband), carried=3)


# ── the switch ──────────────────────────────────────────────────────────────
def test_delivery_is_off_unless_switched_on(monkeypatch):
    monkeypatch.delenv(alerting.ON_SCAN_ENV, raising=False)
    assert alerting.delivery_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_the_switch_accepts_the_obvious_spellings(value, monkeypatch):
    monkeypatch.setenv(alerting.ON_SCAN_ENV, value)
    assert alerting.delivery_enabled() is True


@pytest.mark.parametrize("value", ["0", "false", "no", "", "  ", "maybe"])
def test_anything_else_means_off(value, monkeypatch):
    """A misspelled switch must fail CLOSED. Interpreting an unrecognised value
    as 'on' would send a customer's findings out on a typo."""
    monkeypatch.setenv(alerting.ON_SCAN_ENV, value)
    assert alerting.delivery_enabled() is False


# ── the four states ─────────────────────────────────────────────────────────
def test_a_quiet_run_is_a_result_not_a_failure():
    report = alerting.deliver_for_run(diff())
    assert report["decided"] == 0 and report["delivered"] is False
    assert "A quiet run is a result" in report["reason"]


def test_decided_but_not_delivered_says_why(monkeypatch):
    monkeypatch.delenv(alerting.ON_SCAN_ENV, raising=False)
    report = alerting.deliver_for_run(diff(new=[FINDING]))
    assert report["decided"] == 1 and report["delivered"] is False
    assert alerting.ON_SCAN_ENV in report["reason"]
    assert "consent to the first is not consent to the second" in report["reason"]


def test_switched_on_with_no_channel_is_reported_not_silent(monkeypatch):
    """The state this function exists for."""
    for name in ("SKOPOS_ALERT_WEBHOOK", "SKOPOS_ALERT_EMAIL"):
        monkeypatch.delenv(name, raising=False)
    report = alerting.deliver_for_run(diff(new=[FINDING]), enabled=True)
    assert report["delivered"] is False and report["channels"] == {}
    assert "NO CHANNEL IS CONFIGURED" in report["reason"]
    assert "looks identical to a quiet run" in report["reason"]


def test_a_plaintext_webhook_is_refused_at_delivery(monkeypatch):
    for name in ("SKOPOS_ALERT_WEBHOOK", "SKOPOS_ALERT_EMAIL"):
        monkeypatch.delenv(name, raising=False)
    report = alerting.deliver_for_run(diff(new=[FINDING]), enabled=True,
                                      webhook_url="http://plain.example/hook")
    assert report["delivered"] is False
    assert "not https" in report["channels"]["webhook"]["error"]


def test_a_channel_failure_is_returned_rather_than_logged_and_forgotten(monkeypatch):
    for name in ("SKOPOS_ALERT_WEBHOOK", "SKOPOS_ALERT_EMAIL"):
        monkeypatch.delenv(name, raising=False)

    def boom(url, alerts, timeout=10.0):
        raise alerting.DeliveryFailed("the endpoint refused the connection")

    monkeypatch.setattr(alerting, "send_webhook", boom)
    report = alerting.deliver_for_run(diff(new=[FINDING]), enabled=True,
                                      webhook_url="https://hook.example/x")
    assert report["delivered"] is False
    assert "channel(s) failed: webhook" in report["reason"]
    assert "worst state available" in report["reason"]


def test_a_successful_delivery_reports_the_count(monkeypatch):
    for name in ("SKOPOS_ALERT_WEBHOOK", "SKOPOS_ALERT_EMAIL"):
        monkeypatch.delenv(name, raising=False)
    sent = {}

    def capture(url, alerts, timeout=10.0):
        sent["url"] = url
        sent["alerts"] = alerts
        return len(alerts)

    monkeypatch.setattr(alerting, "send_webhook", capture)
    report = alerting.deliver_for_run(diff(new=[FINDING]), enabled=True,
                                      webhook_url="https://hook.example/x")
    assert report["delivered"] is True
    assert "delivered 1 alert(s)" in report["reason"]
    assert sent["alerts"][0].detail["asset"] == "fw-01.example.com"


def test_the_payload_carries_enough_to_act_without_the_console(monkeypatch):
    """A notification saying '3 new critical findings' is a prompt to go and
    look, which is what the console is for. It is not an alert."""
    for name in ("SKOPOS_ALERT_WEBHOOK", "SKOPOS_ALERT_EMAIL"):
        monkeypatch.delenv(name, raising=False)
    captured = {}
    monkeypatch.setattr(alerting, "send_webhook",
                        lambda url, alerts, timeout=10.0: captured.setdefault(
                            "a", alerts) and len(alerts))
    alerting.deliver_for_run(diff(new=[FINDING]), enabled=True,
                             webhook_url="https://hook.example/x")
    body = captured["a"][0].as_dict()
    # The structured payload is under `detail`, for a webhook consumer that
    # routes on it rather than parsing the prose in `body`.
    assert body["detail"]["asset"] and body["detail"]["cve"]
    assert body["subject"] and body["body"]
    assert "fortios" in str(body).lower()


# ── the suppression counts travel with the decision ─────────────────────────
def test_suppressed_counts_survive_into_the_report(monkeypatch):
    monkeypatch.delenv(alerting.ON_SCAN_ENV, raising=False)
    low = dict(FINDING, band="low")
    report = alerting.deliver_for_run(diff(new=[FINDING, low]))
    assert report["decided"] == 1
    assert report["suppressed_below_band"] == 1


def test_a_band_change_does_not_deliver_by_default(monkeypatch):
    """EPSS moves daily. A feed that fires on score boundaries trains the
    reader to ignore it."""
    monkeypatch.delenv(alerting.ON_SCAN_ENV, raising=False)
    report = alerting.deliver_for_run(diff(reband=[FINDING]))
    assert report["decided"] == 0


# ── the scan route ──────────────────────────────────────────────────────────
def test_the_scan_route_never_takes_delivery_from_the_request():
    """If the caller could ask for delivery, anyone who can reach the endpoint
    could choose the moment the estate is described to a third party."""
    import inspect

    from api import app as api_app
    source = inspect.getsource(api_app.run_scan)
    assert "deliver_for_run(diff)" in source
    for leak in ("deliver=", "alert=", "notify="):
        assert leak not in source, leak


def test_a_delivery_failure_does_not_fail_the_scan():
    """The findings are already persisted and correct; what failed is telling
    somebody about them."""
    import inspect

    from api import app as api_app
    source = inspect.getsource(api_app.run_scan)
    assert "except Exception" in source
    assert "alerting failed" in source
