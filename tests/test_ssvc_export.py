"""SSVC in the export, and the outcome this product refuses to compute.

SSVC is the one ranking input SKOPOS carries that nothing else in the
open-source field does — a README grep across Osmedeus, Nemo, ScopeSentry, BBOT
and Amass returns zero hits, and OpenCTI has no field for it anywhere in its
schema. So how it travels matters more here than for KEV or EPSS, which arrive
in OpenCTI by other routes already.
"""
from __future__ import annotations

import json

import pytest

from core import stix

POINTS = {"exploitation": "active", "automatable": "no",
          "technical_impact": "total"}
EVIDENCE = ["product: log4j",
            "CISA SSVC: automatable=no, exploitation=active, "
            "technical impact=total"]


# ── labels, not only a custom property ──────────────────────────────────────
def test_decision_points_become_standard_stix_labels():
    """`labels` is a standard STIX property that survives any conformant
    importer. Whether OpenCTI preserves `x_`-prefixed properties is UNVERIFIED,
    and a silent drop would lose the differentiating field entirely."""
    obj = stix.vulnerability("CVE-2021-44228", ssvc=POINTS)
    assert obj["labels"] == ["ssvc:automatable/no", "ssvc:exploitation/active",
                             "ssvc:technical-impact/total"]


def test_labels_are_namespaced_so_a_consumer_needs_no_skopos_knowledge():
    labels = stix.ssvc_labels(POINTS)
    assert all(l.startswith("ssvc:") for l in labels)


def test_the_value_follows_a_slash_so_it_parses_unambiguously():
    """A decision point's value can contain a hyphen but never a slash."""
    for label in stix.ssvc_labels(POINTS):
        name, _, value = label.partition("/")
        assert value and "/" not in value
        assert name.startswith("ssvc:")


def test_the_points_are_also_carried_as_fields_for_convenience():
    """Belt and braces. If `x_` survives, both work; if it does not, the labels
    still do."""
    obj = stix.vulnerability("CVE-2021-44228", ssvc=POINTS)
    assert obj["x_skopos_ssvc"] == POINTS


def test_a_cve_with_no_ssvc_carries_no_labels():
    """CISA has not adjudicated every CVE. An absent point is absent, not
    guessed at."""
    obj = stix.vulnerability("CVE-2020-99999")
    assert "labels" not in obj
    assert "x_skopos_ssvc" not in obj


def test_a_partial_ssvc_record_exports_only_what_exists():
    obj = stix.vulnerability("CVE-1", ssvc={"exploitation": "active"})
    assert obj["labels"] == ["ssvc:exploitation/active"]


def test_the_timestamp_is_not_exported_as_a_decision_point():
    """`data/ssvc.json` carries a timestamp beside the three points. It is
    metadata about the adjudication, not an input to the tree."""
    obj = stix.vulnerability("CVE-1", ssvc=dict(POINTS, timestamp="2025-02-07"))
    assert not any("timestamp" in l for l in obj["labels"])
    assert "timestamp" not in obj["x_skopos_ssvc"]


# ── the outcome this product will not compute ───────────────────────────────
def test_no_ssvc_outcome_is_ever_emitted():
    """The decision tree takes FOUR inputs and CISA publishes three. The
    fourth — Mission and Well-being — is a judgement about what the affected
    system is worth to the organisation that runs it, which an outside-in
    product does not know."""
    obj = stix.vulnerability("CVE-2021-44228", ssvc=POINTS)
    assert obj["x_skopos_ssvc_outcome"] is None
    flat = json.dumps(obj).lower()
    for outcome in ('"act"', '"attend"', '"track"', '"track*"'):
        assert outcome not in flat, outcome


def test_the_refusal_explains_which_input_is_missing():
    text = stix.SSVC_NO_OUTCOME
    assert "MISSION AND WELL-BEING" in text
    assert "must not guess" in text
    assert "Supply it yourself" in text


def test_the_refusal_travels_in_the_bundle_caveat():
    """A consumer receiving decision points with no outcome would otherwise
    assume the producer simply forgot to compute one."""
    bundle = stix.bundle([{"asset": "a.example.com", "cve": "CVE-1",
                           "basis": "product_match", "evidence": EVIDENCE}],
                         org="acme")
    assert "MISSION AND WELL-BEING" in json.dumps(bundle)


def test_the_missing_input_is_named_as_a_constant():
    """So somebody adding it later has one place to look."""
    assert stix.SSVC_MISSING_INPUT == "mission_and_wellbeing"
    assert stix.SSVC_MISSING_INPUT not in stix.SSVC_POINTS


# ── recovering the points the engine already renders ────────────────────────
def test_points_are_recovered_from_the_engine_s_evidence_line():
    """`core/engine.py` renders them as a sentence for a human. Parsing it back
    keeps this change inside the export rather than in the scoring path."""
    assert stix.ssvc_from_evidence(EVIDENCE) == POINTS


def test_evidence_without_an_ssvc_line_yields_nothing():
    assert stix.ssvc_from_evidence(["product: nginx"]) == {}
    assert stix.ssvc_from_evidence([]) == {}
    assert stix.ssvc_from_evidence(None) == {}


def test_a_malformed_ssvc_line_does_not_raise():
    assert stix.ssvc_from_evidence(["CISA SSVC: nonsense"]) == {}


def test_an_explicit_ssvc_key_wins_over_the_evidence_line():
    """Threading a dict through is cleaner where a caller has one."""
    finding = {"asset": "a.example.com", "cve": "CVE-1",
               "basis": "product_match", "evidence": EVIDENCE,
               "ssvc": {"exploitation": "poc"}}
    bundle = stix.bundle([finding], org="acme")
    vuln = next(o for o in bundle["objects"] if o["type"] == "vulnerability")
    assert vuln["labels"] == ["ssvc:exploitation/poc"]


def test_the_bundle_carries_ssvc_end_to_end():
    bundle = stix.bundle([{"asset": "a.example.com", "cve": "CVE-2002-0367",
                           "basis": "product_match", "evidence": EVIDENCE}],
                         org="acme")
    vuln = next(o for o in bundle["objects"] if o["type"] == "vulnerability")
    assert "ssvc:exploitation/active" in vuln["labels"]


# ── why this matters more than KEV or EPSS ──────────────────────────────────
def test_the_vendored_corpus_actually_has_decision_points():
    """1,674 of them, from CISA-ADP's vulnrichment container."""
    import pathlib
    payload = json.loads((pathlib.Path(stix.__file__).resolve().parents[1]
                          / "data" / "ssvc.json").read_text(encoding="utf-8"))
    inner = payload.get("ssvc") or {}
    assert len(inner) > 1000
    sample = next(iter(inner.values()))
    assert set(stix.SSVC_POINTS) <= set(sample)


def test_ssvc_is_recorded_as_a_refusal_nowhere_and_a_capability_here():
    """Sanity check on the positioning: SSVC is something SKOPOS DOES, unlike
    the ten entries in the refusal register."""
    from core import refusals
    assert not any("ssvc" in r.id.lower() for r in refusals.REFUSALS)
