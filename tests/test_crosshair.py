"""Convergence, and the claim this screen must never make.

A screen called Crosshair invites the reading "these are the people coming for
you". SKOPOS cannot support that — the one open CVE-to-actor mapping implicates
a median of 57 threat groups per CVE — so most of these tests are about the
product declining to say it.
"""
from __future__ import annotations

from datetime import date

import pytest

from core import crosshair
from core.crosshair import Signal, Tier, build, read

TODAY = date(2026, 8, 23)


def finding(cve="CVE-1", ransomware=False, basis="product_match",
            version="1.0", evidence=None, due="2020-01-01", **extra):
    row = {"asset": "fw-01.example.com", "cve": cve, "product": "FortiOS",
           "owner": "Network", "teps": 57, "band": "medium", "basis": basis,
           "known_ransomware": ransomware, "version": version,
           "due_date": due, "evidence": evidence or ["names correspond"]}
    row.update(extra)
    return row


# ── the claim it refuses to make ────────────────────────────────────────────
def test_the_response_states_that_it_is_not_targeting():
    view = build([finding()]).to_dict()
    assert "does NOT claim anyone is targeting you" in view["not_targeting"]
    assert "median of 57 groups" in view["not_targeting"]


def test_no_signal_names_a_threat_actor():
    """If a Signal ever names an actor, the product has started claiming
    attribution it cannot support."""
    words = " ".join(s.value + s.meaning for s in Signal).lower()
    for forbidden in ("apt", "group", "actor", "adversary", "attacker is"):
        assert forbidden not in words.replace("attackers", ""), forbidden


def test_sprayed_is_described_as_not_aimed():
    """The distinction that makes the screen honest."""
    text = Signal.SPRAYED.meaning
    assert "not aimed at you" in text
    assert "sprayed at everything" in text


# ── convergence is counted, not scored ──────────────────────────────────────
def test_a_single_signal_is_the_floor_not_a_finding():
    entry = read(finding(due=None), automatable=False)
    assert entry.tier is Tier.PRESENT
    assert Signal.EXPLOITED in entry.signals


def test_present_says_it_is_not_the_same_as_safe():
    assert "NOT the same as safe" in Tier.PRESENT.meaning


def test_signals_accumulate_into_tiers():
    entry = read(finding(ransomware=True, basis="version_range"),
                 automatable=True, accelerating=True, today=TODAY)
    assert {Signal.EXPLOITED, Signal.RANSOMWARE, Signal.CONFIRMED,
            Signal.SPRAYED, Signal.ACCELERATING, Signal.OVERDUE} <= set(entry.signals)
    assert entry.tier is Tier.CONVERGED


def test_two_signals_is_elevated_not_converged():
    entry = read(finding(ransomware=True, due=None), automatable=False,
                 today=TODAY)
    assert entry.tier is Tier.ELEVATED


def test_a_retired_finding_is_not_confirmed():
    """A published range removed it from the worklist; it must not then count
    as a confirming signal."""
    entry = read(finding(basis="version_range",
                         evidence=["RETIRED: 9.9 falls outside every range"]),
                 automatable=False, today=TODAY)
    assert Signal.CONFIRMED not in entry.signals


# ── the unknowns are OUR gaps, and are named ────────────────────────────────
def test_an_undecided_automatable_is_a_stated_unknown():
    entry = read(finding(), automatable=None, today=TODAY)
    assert any("has not decided" in u for u in entry.unknown)
    assert Signal.SPRAYED not in entry.signals


def test_a_missing_version_says_it_is_our_gap_not_their_safety():
    entry = read(finding(version=None), automatable=False, today=TODAY)
    gap = [u for u in entry.unknown if "version" in u][0]
    assert "gap in what we know, not evidence of safety" in gap


def test_never_probed_is_not_unreachable():
    entry = read(finding(evidence=["no positive reachability signal"]),
                 automatable=False, today=TODAY)
    assert any("not the same as unreachable" in u for u in entry.unknown)
    assert Signal.REACHABLE not in entry.signals


def test_a_port_that_answered_is_a_signal():
    entry = read(finding(evidence=["answered on 443"]), automatable=False,
                 today=TODAY)
    assert Signal.REACHABLE in entry.signals


# ── an empty top tier must not read as good news ────────────────────────────
def test_an_empty_converged_tier_on_an_uninstrumented_estate_says_why():
    """The failure this panel exists to avoid: ranking the well-instrumented
    parts of an estate as the dangerous ones."""
    view = build([finding(due=None) for _ in range(5)],
                 automatable={}, today=TODAY)
    assert view.of_tier(Tier.CONVERGED) == []
    assert "statement about our coverage rather than about your risk" in view.headline()


def test_coverage_gaps_are_counted_as_a_fix_list_for_us():
    view = build([finding(cve=f"CVE-{i}", version=None) for i in range(4)],
                 automatable={}, today=TODAY)
    gaps = view.coverage_gaps
    assert gaps, "an uninstrumented estate must produce a fix-list"
    assert max(gaps.values()) == 4


def test_a_fully_instrumented_finding_produces_no_gaps():
    entry = read(finding(basis="version_range", evidence=["answered on 443"]),
                 automatable=True, today=TODAY)
    assert entry.unknown == []


# ── ordering ────────────────────────────────────────────────────────────────
def test_more_signals_sort_first():
    weak = finding(cve="CVE-WEAK", due=None)
    strong = finding(cve="CVE-STRONG", ransomware=True, basis="version_range")
    view = build([weak, strong], automatable={"CVE-STRONG": True}, today=TODAY)
    assert view.entries[0].cve == "CVE-STRONG"


def test_the_headline_counts_every_tier():
    view = build([finding(cve=f"CVE-{i}") for i in range(3)],
                 automatable={}, today=TODAY)
    assert "across 3 finding(s)" in view.headline()


def test_thresholds_are_blunt_counts_not_weights():
    """A weighted score would need tuning, and the tuning would become the
    product's real opinion where nobody could inspect it."""
    assert isinstance(crosshair.CONVERGED_AT, int)
    assert crosshair.ELEVATED_AT < crosshair.CONVERGED_AT
