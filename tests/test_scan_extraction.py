"""One scan implementation, called from two places.

The route and the scheduler must not drift. Those 178 lines carry the alerting
decision, the ticketing decision and the forecast record — a second copy would
agree on the day it was written and stop agreeing quietly, exactly as four stale
ON CONFLICT targets and one unapplied migration already did here.
"""
from __future__ import annotations

import inspect

import pytest

from core import scan


def test_the_route_holds_no_scanning_logic():
    """If the route grows a second implementation, this fails."""
    from api import app as api_app
    source = inspect.getsource(api_app.run_scan)
    assert "scan.execute(" in source or "_scan.execute(" in source
    for logic in ("engine.rank", "inventory.load", "forecast.from_finding",
                  "deliver_for_run", "file_for_run"):
        assert logic not in source, f"the route reimplements {logic}"


def test_the_scheduler_calls_the_same_function():
    from tools import scheduled_scan
    source = inspect.getsource(scheduled_scan.main)
    assert "scan.execute(" in source
    for logic in ("engine.rank", "inventory.load", "deliver_for_run"):
        assert logic not in source, f"the scheduler reimplements {logic}"


def test_neither_caller_can_ask_for_delivery():
    """Alert delivery and ticket filing are read from the environment inside
    core/scan.py. If a caller could request them, anyone reaching the API could
    choose the moment the estate is described to a third party."""
    signature = inspect.signature(scan.execute)
    for leak in ("deliver", "alert", "ticket", "notify", "send"):
        assert not any(leak in name for name in signature.parameters), leak


def test_delivery_is_decided_inside_the_shared_implementation():
    source = inspect.getsource(scan.execute)
    assert "deliver_for_run" in source and "file_for_run" in source


# ── the errors it raises are domain errors, not HTTP ────────────────────────
def test_a_missing_inventory_is_an_input_error_not_a_crash():
    with pytest.raises(scan.ScanInputError):
        scan.execute(inventory_path="does-not-exist-anywhere.csv")


def test_input_and_availability_errors_are_distinguishable():
    """A 400 and a 503 are different answers, and core/ must not know which."""
    assert issubclass(scan.ScanInputError, scan.ScanError)
    assert issubclass(scan.ScanUnavailable, scan.ScanError)
    assert not issubclass(scan.ScanInputError, scan.ScanUnavailable)


def test_core_does_not_import_the_api_layer():
    """A layering inversion, and a circular import: api imports core."""
    source = inspect.getsource(scan)
    assert "from api" not in source and "import api" not in source
    assert "HTTPException" not in source


# ── the scheduler's own refusals ────────────────────────────────────────────
def test_no_inventory_configured_says_so_rather_than_running_quietly():
    """A scheduler with no inventory is a misconfiguration, not an estate with
    nothing in it."""
    from tools import scheduled_scan
    source = inspect.getsource(scheduled_scan.main)
    assert "did NOT run" in source
    assert "misconfiguration to fix" in source


def test_the_scheduler_warns_when_the_forecast_record_is_not_accumulating():
    """A scan that completes while the record is not accumulating looks
    identical to one that is, and the difference is only visible months later
    when there is nothing to score."""
    from tools import scheduled_scan
    source = inspect.getsource(scheduled_scan.main)
    assert "is NOT accumulating" in source


def test_the_scheduler_reports_what_did_not_match():
    """0 findings and 0 findings with 400 assets that matched nothing are
    different sentences."""
    from tools import scheduled_scan
    source = inspect.getsource(scheduled_scan.main)
    assert "NOT the same as being unaffected" in source


def test_switching_on_the_scan_does_not_switch_on_delivery():
    """Running a scan describes the estate to yourself; alerting and ticketing
    describe it to somebody else, and each keeps its own consent."""
    from tools import scheduled_scan
    assert "SKOPOS_ALERT_ON_SCAN" not in inspect.getsource(scheduled_scan)
    assert "SKOPOS_ITSM_ON_SCAN" not in inspect.getsource(scheduled_scan)
