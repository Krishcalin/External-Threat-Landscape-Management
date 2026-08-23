"""The time-to-attack question, resolved by refusing to answer it as asked.

P3 names a "time-to-attack forecaster". A forecaster returns a time. Measured
over the 228 usable artefact->KEV pairs in the 2023+ window, only one of four
reference classes has a spread narrow enough to support any statement:

    ransomware  weaponised    n   p25  median   p75
    no          yes         129    10     120  1713   useless
    YES         YES          58     1       8   124   usable
    no          no           31  -145     -14  1380   useless
    yes         no           10   -45     -30  2360   too few

So most of these tests are about the product declining to produce a number.
"""
from __future__ import annotations

import pytest

from core import latency
from core.latency import (MAX_USEFUL_SPREAD_DAYS, MIN_SAMPLE, Latency,
                          ReferenceClass, build, lookup)


def observations(ransomware, weaponised, values):
    return [(ransomware, weaponised, v) for v in values]


# ── it refuses when it should ───────────────────────────────────────────────
def test_a_tiny_sample_says_nothing():
    classes = build(observations(True, False, [1, 2, 3, 4, 5]))
    row = lookup(classes, True, False)
    assert not row.usable
    assert "too few to say anything" in row.explain()


def test_a_wide_spread_says_nothing_even_with_a_large_sample():
    """The failure this module exists to prevent: a median of 120 days drawn
    from an interquartile range of 10 to 1,713."""
    wide = list(range(0, 2000, 4))          # n=500, enormous spread
    row = lookup(build(observations(False, True, wide)), False, True)
    assert row.samples >= MIN_SAMPLE
    assert not row.usable
    assert "NO estimate is offered" in row.explain()
    assert "no information a reader could act on" in row.explain()


def test_an_unknown_class_returns_an_empty_answer_not_a_guess():
    row = lookup({}, True, True)
    assert row.samples == 0 and not row.usable


def test_the_thresholds_are_stated_not_implicit():
    assert MIN_SAMPLE >= 20
    assert MAX_USEFUL_SPREAD_DAYS <= 400


# ── it speaks when it can ───────────────────────────────────────────────────
def test_a_tight_well_sampled_class_gives_a_base_rate():
    tight = [5, 6, 7, 8, 8, 9, 10, 11, 12] * 4      # n=36, narrow
    row = lookup(build(observations(True, True, tight)), True, True)
    assert row.usable
    assert row.median == 8
    assert "median of 8 day(s)" in row.explain()


def test_the_answer_always_carries_its_spread_and_sample_size():
    """A bare median is the thing this module refuses to produce."""
    tight = [5, 6, 7, 8, 8, 9, 10, 11, 12] * 4
    row = lookup(build(observations(True, True, tight)), True, True)
    text = row.explain()
    assert "middle half fell between" in text
    assert f"{row.samples} comparable" in text


def test_it_says_what_happened_to_others_not_what_will_happen_to_you():
    tight = [5, 6, 7, 8, 8, 9, 10, 11, 12] * 4
    row = lookup(build(observations(True, True, tight)), True, True)
    assert "what happened to OTHERS, not a prediction about yours" in row.explain()


def test_the_module_caveat_says_it_is_not_a_forecast():
    assert "BASE RATE" in latency.NOT_A_FORECAST
    assert "not a prediction about yours" in latency.NOT_A_FORECAST
    assert "none is made" in latency.NOT_A_FORECAST


# ── negative latency is a finding, not an error ─────────────────────────────
def test_a_negative_median_is_reported_as_exploitation_first():
    """CISA listed the CVE before public code appeared — the signature of
    targeted use. Clamping it to zero would erase the distinction between
    'code first, then attacks' and 'attacks first, code later'."""
    early = [-8, -7, -6, -5, -5, -4, -3, -2, -1] * 4
    row = lookup(build(observations(False, False, early)), False, False)
    assert row.usable and row.median < 0
    assert "observed BEFORE public code existed" in row.explain()


def test_negative_values_are_not_clamped():
    row = lookup(build(observations(True, True, [-100] * 40)), True, True)
    assert row.median == -100


# ── the reference class is deliberately coarse ──────────────────────────────
def test_only_two_attributes_stratify():
    """Artefact type was tried and produced medians from -32 to 3,639 days
    across six combinations — a split that fine slices the sample into noise
    while looking more sophisticated."""
    fields = ReferenceClass.__dataclass_fields__
    assert set(fields) == {"ransomware", "weaponised"}


def test_the_label_reads_as_english():
    assert ReferenceClass(True, True).label == \
        "ransomware-linked, packaged exploit module"
    assert ReferenceClass(False, False).label == \
        "not ransomware-linked, no packaged module"


def test_classes_are_kept_separate():
    rows = (observations(True, True, [1, 2, 3] * 10)
            + observations(False, True, [900, 1000, 1100] * 10))
    classes = build(rows)
    assert lookup(classes, True, True).median < 10
    assert lookup(classes, False, True).median > 500
