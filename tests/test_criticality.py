"""P3: making TEPS discriminate, and being honest about the factor it cannot fill.

Measured against the running deployment before this: all 64 findings scored
exactly 50 in one band, because every factor was constant across the estate.
The ordered tuple in `engine.rank()` was doing all the work and the score itself
was decorative.
"""
from __future__ import annotations

from datetime import date

import pytest

from core import criticality, engine, scoring
from core.criticality import Tier, TierSource
from core.models import Asset, Confidence, Exploited, Exposure, MatchBasis
from core.scoring import AdversaryInterest, W_ADVERSARY


def asset(environment="", **extra):
    return Asset(identifier="h.example.com", product="Log4j2", vendor="Apache",
                 version="2.14.1", environment=environment, **extra)


def exposure(environment="", ransomware=False):
    entry = Exploited(cve="CVE-2021-44228", vendor_project="Apache",
                      product="Log4j2", name="RCE",
                      date_added=date(2021, 12, 10), short_description="x",
                      required_action="Patch.", known_ransomware=ransomware)
    return Exposure(asset=asset(environment), exploited=entry,
                    basis=MatchBasis.PRODUCT_MATCH,
                    confidence=Confidence.STRONG, evidence=[])


# ── the tier is read per asset ──────────────────────────────────────────────
@pytest.mark.parametrize("text,expected", [
    ("1", 1), ("Tier 2", 2), ("3", 3), ("5", 5),
])
def test_an_explicit_tier_is_believed_as_given(text, expected):
    tier = criticality.parse(text)
    assert tier.value == expected
    assert tier.source is TierSource.EXPLICIT


@pytest.mark.parametrize("text,expected", [
    ("business critical", 1), ("production", 2), ("prod", 2),
    ("staging", 3), ("dev", 4), ("sandbox", 5),
])
def test_a_word_is_derived_and_labelled_as_a_guess(text, expected):
    tier = criticality.parse(text)
    assert tier.value == expected
    assert tier.source is TierSource.DERIVED
    assert "guess at your vocabulary" in tier.explain


def test_longest_match_wins_so_a_qualifier_is_not_swallowed():
    """'business critical' must not be scored the same as a generic label."""
    assert criticality.parse("business critical").value == 1
    assert criticality.parse("critical").value == 1
    assert criticality.parse("not very important").value is None


def test_an_unrecognised_word_yields_absence_not_a_default():
    tier = criticality.parse("banana")
    assert tier.value is None
    assert tier.source is TierSource.ABSENT


def test_absence_is_scored_at_the_midpoint_not_as_harmless():
    """An asset nobody has tiered is one nobody has assessed."""
    assert scoring.business_criticality(None) == 0.5
    assert "midpoint" in criticality.parse("").explain


def test_a_run_default_never_overwrites_what_the_asset_records():
    """The bug this fixes: one query parameter applied to every asset."""
    stated = criticality.for_asset(asset(environment="production"), fallback=5)
    assert stated.value == 2, "the asset's own value must win"
    silent = criticality.for_asset(asset(environment=""), fallback=5)
    assert silent.value == 5, "the fallback applies only where nothing is said"


def test_an_explicit_attribute_beats_the_environment_column():
    a = asset(environment="dev", attributes={"tier": "1"})
    assert criticality.for_asset(a).value == 1


def test_a_flat_estate_is_visible_in_the_distribution():
    """An estate where everything resolves to one tier scores every finding
    identically, and the operator should be told rather than shown a ranking
    that is not one."""
    flat = criticality.distribution([Tier(2, TierSource.DERIVED)] * 5)
    assert flat == {"tier 2": 5}
    mixed = criticality.distribution(
        [Tier(1, TierSource.EXPLICIT), Tier(4, TierSource.DERIVED),
         Tier(None, TierSource.ABSENT)])
    assert mixed == {"tier 1": 1, "tier 4": 1, "untiered": 1}


# ── the adversary factor is honest ──────────────────────────────────────────
def test_the_triad_is_unsupplied_not_zero():
    """ATT&CK carries no CVE linkage and no structured targeting, so the three
    legs cannot be filled from open data. 'No adversary is interested' and 'we
    have no data' are different statements."""
    assert AdversaryInterest().triad_unsupplied
    assert AdversaryInterest.from_catalogue(True).triad_unsupplied


def test_ransomware_use_is_a_real_observation_and_is_used():
    linked = AdversaryInterest.from_catalogue(True)
    unlinked = AdversaryInterest.from_catalogue(False)
    assert linked.value() > unlinked.value()
    assert linked.value() == pytest.approx(0.15)


def test_the_unsupplied_triad_is_flagged_because_it_is_a_quarter_of_the_score():
    """A number computed from three of four factors must not present itself as
    a complete one."""
    finding = engine.score_exposure(exposure())
    flagged = [f for f in finding.score.flags if "adversary interest" in f]
    assert flagged, finding.score.flags
    assert "UNSUPPLIED" in flagged[0]
    assert f"{W_ADVERSARY:.0%}" in flagged[0]


def test_a_supplied_triad_is_not_flagged():
    supplied = AdversaryInterest(sector_match=1.0, geo_match=0.5,
                                 tech_match=0.5, supplied=True)
    result = scoring.score(exposure=scoring.Exposure(reachability=1.0),
                           exploitability=scoring.Exploitability(in_kev=True),
                           adversary=supplied, asset_tier=2)
    assert not any("adversary interest" in f for f in result.flags)


# ── the outcome: TEPS discriminates ─────────────────────────────────────────
def test_teps_now_varies_with_what_the_inventory_says():
    """Before this, all 64 live findings scored exactly 50 in one band."""
    scores = {
        engine.score_exposure(exposure("business critical", True)).score.teps,
        engine.score_exposure(exposure("production", True)).score.teps,
        engine.score_exposure(exposure("production", False)).score.teps,
        engine.score_exposure(exposure("dev", False)).score.teps,
    }
    assert len(scores) == 4, f"expected four distinct scores, got {scores}"


def test_a_more_critical_asset_outranks_a_less_critical_one():
    critical = engine.score_exposure(exposure("business critical")).score.teps
    sandbox = engine.score_exposure(exposure("sandbox")).score.teps
    assert critical > sandbox


def test_ransomware_linkage_raises_the_score_on_an_identical_asset():
    linked = engine.score_exposure(exposure("production", True)).score.teps
    unlinked = engine.score_exposure(exposure("production", False)).score.teps
    assert linked > unlinked


def test_the_srs_worked_example_still_reproduces():
    """§9.1's published example, unchanged by any of this: A = 0.850 from a
    fully supplied triad."""
    supplied = AdversaryInterest(sector_match=1.0, geo_match=1.0,
                                 tech_match=1.0, named_mention=0.0)
    assert round(supplied.value(), 3) == 0.850
