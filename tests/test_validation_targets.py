"""The handoff to a validation platform — and the two things it must never say.

SKOPOS refuses the CTEM validation stage outright. This module is the scoping
input for a platform that covers it, and most of these tests exist to keep it
from drifting into pretending to do the validating itself.
"""
from __future__ import annotations

import json

import pytest

from core import validation

REACHABLE_WORKLIST = {"asset": "web.example.com", "cve": "CVE-2021-44228",
                      "product": "Log4j", "version": "",
                      "basis": "product_match", "reachable": True}
REACHABLE_DETERMINED = {"asset": "db.example.com", "cve": "CVE-2020-1",
                        "product": "X", "version": "1.0",
                        "basis": "version_range", "reachable": True}
UNPROBED = {"asset": "dark.example.com", "cve": "CVE-2019-1", "product": "Y",
            "version": "", "basis": "product_match", "reachable": None}
CLOSED = {"asset": "closed.example.com", "cve": "CVE-2018-1", "product": "Z",
          "version": "2", "basis": "product_match", "reachable": False}
ALL = [CLOSED, UNPROBED, REACHABLE_DETERMINED, REACHABLE_WORKLIST]


# ── what it must never contain ──────────────────────────────────────────────
def test_no_attack_technique_ever_appears():
    """SKOPOS holds no technique mapping. P3 measured CVE-to-technique-to-group
    at a median of 57 groups per CVE and closed the line — so a target list
    with techniques in it would be inventing them under SKOPOS's name."""
    payload = validation.targets(ALL)
    flat = json.dumps(payload)
    assert "T1" not in flat.replace("CVE", "")
    assert "attack_pattern" not in flat and "attack-pattern" not in flat
    for key in ("technique", "techniques", "payload", "inject"):
        assert key not in payload


def test_the_absent_techniques_are_explained_not_merely_absent():
    """A validation platform receiving a target list with no techniques would
    otherwise assume the field was dropped by accident."""
    payload = validation.targets(ALL)
    assert "NO ATT&CK techniques" in payload["no_techniques"]
    assert "median of 57 groups" in payload["no_techniques"]
    assert "already knows that from MITRE" in payload["no_techniques"]


def test_it_states_that_it_is_not_validation():
    payload = validation.targets(ALL)
    assert "does not validate and will not" in payload["not_validation"]
    assert "FR-GOV-007" in payload["not_validation"]
    assert "never a claim that an attack would succeed" in payload["not_validation"]


def test_the_refusal_names_the_tool_to_use_instead():
    """A refusal that names the alternative is more credible than one that
    does not."""
    from core import refusals
    entry = refusals.BY_ID["control_validation"]
    assert "OPENAEV" in entry.because.upper()
    assert "Apache 2.0" in entry.because


def test_the_module_cannot_reach_a_prohibited_operation():
    """Parsed, not grepped.

    This module NAMES `exploit_attempt` and `credential_replay` in its
    docstring, because explaining what it refuses is the point of it. A
    substring check therefore fires on the disclaimer that exists to prevent
    the thing — a mistake this repository has now made four times. What
    actually matters is structural: no call to the gate, no network, no
    subprocess.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(validation))

    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called.add(ast.unparse(node.func))
    for forbidden in ("authorise", "gate.authorise", "http_get", "urlopen",
                      "subprocess.run", "Popen"):
        assert not any(forbidden in name for name in called), forbidden

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    for forbidden in ("subprocess", "socket", "urllib", "collect.egress"):
        assert forbidden not in imported, forbidden


# ── three-valued reachability ───────────────────────────────────────────────
def test_unprobed_is_null_and_never_false():
    """`core/reach.py` is three-valued and the third value matters. Collapsing
    null to False tells a validation platform an asset is unreachable when the
    truth is that SKOPOS was not allowed to look."""
    payload = validation.targets([UNPROBED])
    assert payload["targets"][0]["reachable"] is None


def test_null_reachability_is_explained_as_the_gate_working():
    payload = validation.targets(ALL)
    assert "the gate working" in payload["reachability_note"]
    assert "never as" in payload["reachability_note"]


def test_unknown_reachability_is_counted():
    assert validation.targets(ALL)["unknown_reachability"] == 1


@pytest.mark.parametrize("value,expected", [
    (True, True), (False, False), (None, None)])
def test_reachability_passes_through_unchanged(value, expected):
    row = dict(REACHABLE_WORKLIST, reachable=value)
    assert validation.targets([row])["targets"][0]["reachable"] is expected


# ── ordering: what to TEST, not what to FIX ─────────────────────────────────
def test_reachable_worklist_entries_lead():
    """A determination is already believed; validating it confirms a control
    rather than resolving a doubt. An unresolved worklist entry on something
    that answers from outside is where simulation time earns itself."""
    order = [t["asset"] for t in validation.targets(ALL)["targets"]]
    assert order[0] == "web.example.com"
    assert order.index("db.example.com") < order.index("dark.example.com")


def test_unprobed_outranks_confirmed_unreachable():
    """Unknown means find out. Closed means SKOPOS looked and nothing
    answered — a weaker candidate than one nobody has checked."""
    order = [t["asset"] for t in validation.targets(ALL)["targets"]]
    assert order.index("dark.example.com") < order.index("closed.example.com")


def test_the_ordering_says_it_is_not_teps():
    """TEPS ranks what to fix. These are different questions and conflating
    them would send a simulation programme after the wrong things."""
    payload = validation.targets(ALL)
    assert "NOT TEPS order" in payload["ordering"]
    assert "worth fixing is a different question" in payload["ordering"]


def test_ordering_is_stable_for_identical_inputs():
    first = validation.targets(ALL)["targets"]
    again = validation.targets(list(reversed(ALL)))["targets"]
    assert [t["asset"] for t in first] == [t["asset"] for t in again]


# ── each target says why it is worth testing ────────────────────────────────
def test_a_worklist_entry_says_nobody_compared_the_version():
    payload = validation.targets([REACHABLE_WORKLIST])
    reason = payload["targets"][0]["why_test_this"]
    assert "NOBODY HAS COMPARED THE VERSION" in reason
    assert "faster than reading a banner" in reason


def test_a_determination_says_validation_answers_a_different_question():
    """The asset IS affected. What a simulation adds is whether your controls
    would stop exploitation."""
    payload = validation.targets([REACHABLE_DETERMINED])
    reason = payload["targets"][0]["why_test_this"]
    assert "different question from the finding" in reason


def test_an_unprobed_target_says_the_gate_refused():
    payload = validation.targets([UNPROBED])
    assert "gate working correctly" in payload["targets"][0]["why_test_this"]


# ── the cap, and coverage gaps ──────────────────────────────────────────────
def test_the_cap_announces_what_it_dropped():
    """Simulation time is finite, but a silent truncation reads as a complete
    list — the same reason core/itsm.py announces its cap."""
    many = [dict(REACHABLE_WORKLIST, asset=f"h{i}.example") for i in range(250)]
    payload = validation.targets(many)
    assert payload["count"] == validation.MAX_TARGETS
    assert payload["dropped_by_cap"] == 250 - validation.MAX_TARGETS
    assert payload["considered"] == 250


def test_coverage_gaps_are_listed_rather_than_omitted():
    """Borrowed from OpenCTI's handoff to OpenAEV, which generates placeholder
    injects for coverage it cannot test so gaps are visible artifacts."""
    gaps = {g["gap"] for g in validation.coverage_gaps(ALL)}
    assert gaps == {"reachability_unknown", "no_version_observed"}


def test_a_gap_says_what_to_do_about_it():
    gap = next(g for g in validation.coverage_gaps(ALL)
               if g["gap"] == "reachability_unknown")
    assert "Prove ownership and rescan" in gap["means"]


def test_no_gaps_on_a_fully_characterised_estate():
    assert validation.coverage_gaps([REACHABLE_DETERMINED]) == []


# ── ordinary shape ──────────────────────────────────────────────────────────
def test_a_row_missing_an_asset_or_cve_is_skipped():
    assert validation.targets([{"cve": "CVE-1"}])["count"] == 0
    assert validation.targets([{"asset": "a.example"}])["count"] == 0


def test_an_empty_estate_still_carries_both_statements():
    """The two disclaimers are not conditional on there being targets."""
    payload = validation.targets([])
    assert payload["count"] == 0
    assert payload["no_techniques"] and payload["not_validation"]


def test_the_payload_is_a_dict_so_the_disclaimers_cannot_be_dropped():
    """Returning a bare list would let a caller take it and lose both
    statements by accident."""
    assert isinstance(validation.targets(ALL), dict)


def test_the_route_is_registered():
    from api import app as api_app
    assert "/api/v1/export/validation-targets" in {
        r.path for r in api_app.app.routes}
