"""TEPS is normative, so it is golden-tested.

The load-bearing test is `test_the_srs_worked_example_reproduces_exactly`: the
SRS publishes a worked example with an exact answer of 78, and if this file
cannot reproduce it then either the specification or the implementation is wrong
and nobody should be looking at scores until that is settled.

The rest cover the properties a scoring function has to have to be trusted:
determinism, decomposability, and refusing to let a control argue an observed
exploitation down to nothing.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.scoring import (AdversaryInterest, Exploitability,      # noqa: E402
                          Exposure, MAX_MITIGATION, W_ADVERSARY,
                          W_BUSINESS, W_EXPLOIT, W_EXPOSURE,
                          band_for, business_criticality, score)


def srs_example():
    """§9.1: internet-facing SAP portal, shadow asset, exposed 47 days,
    KEV-listed CVE, actor cluster targeting energy in South Asia using the same
    product, Tier-1 asset, WAF present."""
    return dict(
        exposure=Exposure(reachability=1.0, service_sensitivity=0.7,
                          auth_exposure=0.7, shadow=True, days_exposed=47),
        exploitability=Exploitability(in_kev=True),
        adversary=AdversaryInterest(sector_match=1.0, geo_match=1.0,
                                    tech_match=1.0, named_mention=0.0),
        asset_tier=1,
        mitigation=0.15,
        match_confidence="confirmed",
    )


# ── the golden test ──────────────────────────────────────────────────────────

def test_the_srs_worked_example_reproduces_exactly():
    """SKOPOS-SRS-v1.0 §9.1 publishes this example and its answer: 78."""
    result = score(**srs_example())
    assert result.teps == 78, result.explain()
    assert result.band == "high"


def test_the_intermediate_factors_match_the_srs_arithmetic():
    """Not just the total. A wrong E and a compensating wrong X would produce
    the right answer for the wrong reason, and the next input would expose it."""
    result = score(**srs_example())
    assert round(result.exposure, 3) == 0.817
    assert result.exploitability == 1.000
    assert round(result.adversary, 3) == 0.850
    assert result.business == 1.000


def test_the_weights_sum_to_one():
    """An unnormalised weight set silently rescales every score in the product."""
    assert W_EXPOSURE + W_EXPLOIT + W_ADVERSARY + W_BUSINESS == pytest.approx(1.0)


# ── properties a score must have to be trusted ───────────────────────────────

def test_scoring_is_deterministic():
    """FR-M10-007. Identical inputs and model version, identical output."""
    assert len({score(**srs_example()).teps for _ in range(5)}) == 1


def test_every_score_decomposes():
    """FR-M10-002 — no black-box number is permitted anywhere in the product."""
    result = score(**srs_example())
    contributions = result.contributions()
    assert set(contributions) == {"exposure", "exploitability",
                                  "adversary_interest", "business_criticality"}
    # The parts must reconstruct the whole, before mitigation.
    total = sum(contributions.values())
    assert round(100 * total * (1 - result.mitigation)) == result.teps


def test_kev_membership_cannot_be_argued_down():
    """KEV is an OBSERVATION that exploitation is happening. No probability
    should be able to reduce it — a low EPSS on a KEV entry means the model is
    wrong, not that the exploitation stopped."""
    kev = Exploitability(in_kev=True, epss=0.001, cvss=1.0)
    assert kev.value() == 1.0


def test_mitigation_cannot_absolve():
    """A control is a reduction, never an absolution: capped at 60%, so a live
    exposure can never be discounted to nothing."""
    args = dict(srs_example(), mitigation=0.99)
    result = score(**args)
    assert result.mitigation == MAX_MITIGATION
    assert result.teps > 0
    assert any("capped" in f for f in result.flags)


# ── the honesty flags ────────────────────────────────────────────────────────

def test_an_unscored_cve_is_flagged_and_never_treated_as_zero():
    """§9.1's mandatory missing-data rule. Absent CVSS must not read as safe."""
    absent = Exploitability(epss=0.5, cvss=None)
    present_low = Exploitability(epss=0.5, cvss=0.0)
    assert absent.value() > present_low.value()
    result = score(exposure=Exposure(reachability=1.0),
                   exploitability=absent,
                   adversary=AdversaryInterest(), asset_tier=3,
                   match_confidence="confirmed")
    assert any("assumed" in f for f in result.flags)


def test_an_untiered_asset_is_flagged_rather_than_assumed_harmless():
    """An asset nobody has tiered is one nobody has assessed. Defaulting it to
    least-critical is how the unassessed become invisible."""
    assert business_criticality(None) == 0.5
    assert business_criticality(1) == 1.0
    assert business_criticality(5) == 0.2
    result = score(exposure=Exposure(), exploitability=Exploitability(),
                   adversary=AdversaryInterest(), asset_tier=None,
                   match_confidence="confirmed")
    assert any("no criticality tier" in f for f in result.flags)


def test_a_heuristic_match_says_so_on_the_score():
    """The flag the SRS does not have, and the one the measured data says
    matters: CPE is absent from most new CVEs, so identity is the field that
    degrades. A score presented without that caveat is the industry failure this
    product exists to avoid."""
    result = score(exposure=Exposure(reachability=1.0),
                   exploitability=Exploitability(in_kev=True),
                   adversary=AdversaryInterest(), asset_tier=1,
                   match_confidence="possible")
    assert any("identity unresolved" in f for f in result.flags)
    # And a confirmed match carries no such caveat.
    confirmed = score(exposure=Exposure(reachability=1.0),
                      exploitability=Exploitability(in_kev=True),
                      adversary=AdversaryInterest(), asset_tier=1,
                      match_confidence="confirmed")
    assert not any("identity unresolved" in f for f in confirmed.flags)


# ── bands ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("teps,expected", [
    (100, "critical"), (85, "critical"), (84, "high"), (70, "high"),
    (69, "medium"), (50, "medium"), (49, "low"), (30, "low"),
    (29, "informational"), (0, "informational"),
])
def test_severity_bands_match_the_srs(teps, expected):
    assert band_for(teps) == expected
