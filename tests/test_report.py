"""The degradation vocabulary. Every distinction here is one a boolean loses."""
from __future__ import annotations

import pytest

from collect.report import Coverage, Outcome, SourceReport, overlap


def report(name, outcome, contributed=0, returned=0, detail=""):
    return SourceReport(name, outcome, contributed, returned, detail)


# -- the distinctions a boolean cannot make ----------------------------------
def test_the_six_outcomes_are_distinguishable():
    """Each of these renders as a small estate under `ok: bool`."""
    assert len({o.value for o in Outcome}) == 6


def test_partial_counts_as_answered_but_still_degrades():
    """Data plus a stated limit is data. It is also not full coverage."""
    partial = report("hackertarget", Outcome.PARTIAL, 50, 50, "capped at 50")
    assert partial.answered
    assert not partial.ok
    assert Coverage([partial]).degraded


def test_unconfigured_narrows_but_does_not_degrade():
    """Folding this into `degraded` leaves every keyless install permanently
    degraded, and a flag that is always on is a flag nobody reads."""
    coverage = Coverage([report("otx", Outcome.UNCONFIGURED, detail="no API key"),
                         report("certspotter", Outcome.OK, 12, 40)])
    assert coverage.narrowed
    assert not coverage.degraded
    assert not coverage.refused


def test_refused_is_its_own_flag():
    """The gate saying no is a governance event, not an outage."""
    coverage = Coverage([report("crt.sh", Outcome.REFUSED, detail="excluded")])
    assert coverage.refused
    assert not coverage.degraded
    assert not coverage.narrowed


def test_blackout_is_not_an_empty_estate():
    coverage = Coverage([report("a", Outcome.FAILED), report("b", Outcome.FAILED)])
    assert coverage.blackout
    note = coverage.note(0)
    assert "NOT an empty estate" in note
    assert "no evidence either way" in note


def test_a_source_that_answered_prevents_blackout():
    coverage = Coverage([report("a", Outcome.FAILED),
                         report("b", Outcome.OK, 3, 3)])
    assert not coverage.blackout
    assert coverage.degraded


# -- contributed vs returned -------------------------------------------------
def test_contributed_and_returned_are_different_questions():
    """A 500-SAN shared-CDN certificate of which 3 names are in-apex is not a
    source that did badly — it is a source that handed back 497 names belonging
    to other people."""
    row = report("certspotter", Outcome.OK, contributed=3, returned=500)
    assert row.contributed == 3 and row.returned == 500
    assert "3 of 500" in row.line()


def test_returned_is_never_below_contributed():
    """Guards a caller that filled one field and forgot the other."""
    row = report("x", Outcome.OK, contributed=7, returned=0)
    assert row.returned == 7


def test_the_note_states_the_union_not_a_sum():
    """Summing `contributed` triple-counts a name three sources all found, and
    the inflated number is exactly the reassurance this product must not give."""
    coverage = Coverage([report("a", Outcome.OK, 10, 10),
                         report("b", Outcome.OK, 10, 10)])
    note = coverage.note(12)      # union is 12, not 20
    assert "12 names" in note
    assert "20" not in note


def test_a_degraded_note_says_the_estate_may_be_larger():
    """The sentence that stops a degraded result being read as a clean one."""
    coverage = Coverage([report("crt.sh", Outcome.FAILED, detail="HTTP 502"),
                         report("certspotter", Outcome.OK, 3, 3)])
    note = coverage.note(3)
    assert "may be larger than shown" in note
    assert "HTTP 502" in note


def test_a_healthy_note_says_so_plainly():
    coverage = Coverage([report("certspotter", Outcome.OK, 3, 3)])
    note = coverage.note(3)
    assert "Every source answered in full" in note
    assert "failed" not in note


# -- the boolean shim --------------------------------------------------------
@pytest.mark.parametrize("value,expected", [(True, Outcome.OK),
                                            (False, Outcome.FAILED)])
def test_the_boolean_shim_still_accepts_p0_callers(value, expected):
    assert SourceReport("x", value).outcome is expected


def test_a_string_outcome_is_coerced():
    assert SourceReport("x", "partial").outcome is Outcome.PARTIAL


def test_an_unknown_outcome_raises_rather_than_defaulting():
    with pytest.raises(ValueError):
        SourceReport("x", "probably-fine")


# -- overlap -----------------------------------------------------------------
def test_overlap_reports_what_only_one_source_knew():
    """The number that decides whether a source is worth its terms and rate limit."""
    unique = overlap({
        "certspotter": {"a.example.com", "b.example.com"},
        "crt.sh": {"b.example.com", "c.example.com"},
        "anubis": {"b.example.com"},
    })
    assert unique == {"certspotter": 1, "crt.sh": 1, "anubis": 0}


def test_overlap_is_order_independent():
    """Computed from the full picture after the merge, not as sources arrive."""
    data = {"a": {"1", "2"}, "b": {"2", "3"}, "c": {"3"}}
    forward = overlap(data)
    backward = overlap({k: data[k] for k in reversed(list(data))})
    assert forward == backward
