"""The ITSM connector, and the two ways it would get switched off in week two.

A ticket per finding per run, and a ticket that reads as a determination when
nobody compared a version. Most of these tests keep both impossible.
"""
from __future__ import annotations

import pytest

from core import itsm

WORKLIST = {"asset": "fw-01.example", "cve": "CVE-2018-13379",
            "product": "FortiOS", "band": "critical", "teps": 88.0,
            "basis": "product_match", "evidence": ["product: fortios"],
            "owner": "Network Team", "due_date": "2022-05-03",
            "required_action": "Apply updates.", "vulnerability": "Path Traversal"}
DETERMINED = dict(WORKLIST, asset="web-01.example", cve="CVE-2021-44228",
                  basis="version_range")


# ── the switch ──────────────────────────────────────────────────────────────
def test_ticketing_is_off_unless_switched_on(monkeypatch):
    monkeypatch.delenv(itsm.ON_SCAN_ENV, raising=False)
    assert itsm.enabled() is False


@pytest.mark.parametrize("value", ["0", "false", "no", "", "maybe"])
def test_an_unrecognised_switch_value_means_off(value, monkeypatch):
    """A typo must not write a customer's unpatched systems into another
    company's database."""
    monkeypatch.setenv(itsm.ON_SCAN_ENV, value)
    assert itsm.enabled() is False


def test_no_caller_can_trigger_ticketing():
    """Now enforced in core/scan.py, which both the route and the scheduler
    call — so this is stronger than it was: no caller can reach the decision,
    not merely no route."""
    import inspect

    from api import app as api_app
    from core import scan

    assert "file_for_run(diff.new)" in inspect.getsource(scan.execute)
    for leak in ("ticket=", "file_tickets=", "itsm="):
        assert leak not in inspect.getsource(scan.execute), leak
    for name in inspect.signature(scan.execute).parameters:
        assert "ticket" not in name and "itsm" not in name, name
    assert "file_for_run" not in inspect.getsource(api_app.run_scan)


# ── a ticket must not read as a determination ───────────────────────────────
def test_a_worklist_entry_says_so_in_the_title():
    """A queue is read as a list of titles; the body is opened after somebody
    has already decided to act."""
    ticket = itsm.build_ticket(WORKLIST)
    assert "CHECK VERSION" in ticket.title


def test_a_determination_says_so_in_the_title():
    assert "confirmed" in itsm.build_ticket(DETERMINED).title


def test_the_body_leads_with_the_distinction():
    body = itsm.build_ticket(WORKLIST).body
    first = body.splitlines()[0]
    assert "THE VERSION WAS NOT COMPARED" in body
    assert "not a confirmation" in body
    assert "known-exploited" in first


def test_a_retired_determination_is_not_treated_as_confirmed():
    retired = dict(DETERMINED, evidence=["RETIRED: 9.9 outside every range"])
    assert "CHECK VERSION" in itsm.build_ticket(retired).title


def test_the_due_date_is_labelled_as_cisas_not_the_readers():
    body = itsm.build_ticket(WORKLIST).body
    assert "CISA" in body and "US federal agencies" in body
    assert "not necessarily yours" in body


def test_the_batch_payload_repeats_the_caveat(monkeypatch):
    """A consumer's automation sees the payload, not this codebase."""
    captured = {}

    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(request, timeout=None, context=None):
        captured["body"] = request.data.decode()
        return _Response()

    monkeypatch.setattr(itsm.urllib.request, "urlopen", fake_urlopen)
    itsm.post_tickets("https://itsm.example/hook", [itsm.build_ticket(WORKLIST)])
    assert "WORKLIST ENTRIES" in captured["body"]
    assert "Do not treat them as confirmed vulnerabilities" in captured["body"]
    assert "deduplicate_on" in captured["body"]


# ── identity is (asset, cve), never the score ───────────────────────────────
def test_a_finding_already_ticketed_is_not_ticketed_again():
    """A scan runs daily. 64 findings would be 64 tickets on Monday and 64 more
    on Tuesday, which is how an integration gets switched off."""
    result = itsm.select([WORKLIST], already=[("fw-01.example", "CVE-2018-13379")])
    assert result["tickets"] == []
    assert result["skipped_already_ticketed"] == 1


def test_identity_ignores_the_score():
    moved = dict(WORKLIST, teps=42.0, band="high")
    result = itsm.select([moved], already=[itsm.identity(WORKLIST)])
    assert result["tickets"] == [], "a score moving is not a new problem"


def test_identity_is_case_insensitive_on_both_halves():
    shouty = dict(WORKLIST, asset="FW-01.EXAMPLE", cve="cve-2018-13379")
    assert itsm.identity(shouty) == itsm.identity(WORKLIST)


# ── the counts are not optional ─────────────────────────────────────────────
def test_below_band_findings_are_counted_not_dropped_silently():
    result = itsm.select([dict(WORKLIST, band="low")])
    assert result["tickets"] == [] and result["skipped_below_band"] == 1
    assert "left on the worklist" in result["note"]


def test_an_unknown_band_is_ticketed_rather_than_dropped():
    """A band this build does not recognise is a reason to look, not a reason
    to stay silent."""
    result = itsm.select([dict(WORKLIST, band="catastrophic")])
    assert len(result["tickets"]) == 1


def test_the_cap_announces_itself():
    many = [dict(WORKLIST, asset=f"h{i}.example") for i in range(30)]
    result = itsm.select(many)
    assert len(result["tickets"]) == itsm.MAX_TICKETS_PER_RUN
    assert result["skipped_by_cap"] == 30 - itsm.MAX_TICKETS_PER_RUN
    assert "announced rather than applied silently" in result["note"]


# ── the four states ─────────────────────────────────────────────────────────
def test_a_quiet_run_is_a_result():
    report = itsm.file_for_run([])
    assert report["filed"] is False
    assert "A quiet run is a result" in report["reason"]


def test_decided_but_not_filed_says_why(monkeypatch):
    monkeypatch.delenv(itsm.ON_SCAN_ENV, raising=False)
    report = itsm.file_for_run([WORKLIST])
    assert report["decided"] == 1 and report["filed"] is False
    assert "needs its own consent" in report["reason"]


def test_switched_on_with_no_endpoint_is_reported_not_silent(monkeypatch):
    """The state this exists for: indistinguishable from a quiet run outside."""
    monkeypatch.delenv(itsm.ENDPOINT_ENV, raising=False)
    report = itsm.file_for_run([WORKLIST], switched_on=True)
    assert report["filed"] is False
    assert "indistinguishable from a quiet run" in report["reason"]


def test_a_plaintext_endpoint_is_refused(monkeypatch):
    monkeypatch.delenv(itsm.ENDPOINT_ENV, raising=False)
    report = itsm.file_for_run([WORKLIST], switched_on=True,
                               endpoint="http://itsm.example/hook")
    assert report["filed"] is False and "not https" in report["reason"]


def test_a_failure_is_reported_rather_than_swallowed(monkeypatch):
    monkeypatch.delenv(itsm.ENDPOINT_ENV, raising=False)

    def boom(*a, **k):
        raise itsm.TicketingFailed("endpoint refused")

    monkeypatch.setattr(itsm, "post_tickets", boom)
    report = itsm.file_for_run([WORKLIST], switched_on=True,
                               endpoint="https://itsm.example/hook")
    assert report["filed"] is False
    assert "The findings are recorded and correct" in report["reason"]


def test_ticket_create_is_a_registered_operation():
    from core import gate
    assert gate.OPERATIONS["ticket_create"] is gate.Exposure.PASSIVE
