"""Version-range evaluation — the step that earns the word "determination".

THE ASYMMETRY THIS FILE PROTECTS. Saying AFFECTED wrongly costs somebody an
afternoon. Saying NOT_AFFECTED wrongly costs them the breach. So the tests that
matter most here are the ones asserting UNKNOWN — that the code refuses to
conclude when it cannot read the evidence.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.affected import (Verdict, affected_products,       # noqa: E402
                           evaluate, parse_version)


def affected(*entries):
    return list(entries)


# ── parsing ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("5.3.9", (5, 3, 9)), ("10.1.20", (10, 1, 20)), ("2.7", (2, 7)),
    ("v9.0.65", (9, 0, 65)), ("  1.0  ", (1, 0)), ("7", (7,)),
])
def test_ordinary_versions_parse(text, expected):
    assert parse_version(text) == expected


@pytest.mark.parametrize("text", [
    "1.0.0-beta", "2023-04-01", "R80.40", "latest", "", None, "8.8.15p1",
])
def test_a_version_that_cannot_be_ordered_is_refused(text):
    """Refused, not coerced. `1.0.0-beta` versus `1.0.0` is a judgement about a
    vendor's release policy, not an arithmetic, and guessing produces a
    determination nobody can defend."""
    assert parse_version(text) is None


def test_shorter_versions_pad_rather_than_sort_low():
    """`2.7` and `2.7.0` are the same version to every vendor that ships them."""
    assert evaluate("2.7", affected({"version": "2.7.0", "status": "affected"})) \
        is Verdict.AFFECTED


# ── the three real shapes ────────────────────────────────────────────────────

def test_an_exact_version_matches_only_itself():
    versions = affected({"version": "2.7.0", "status": "affected"})
    assert evaluate("2.7.0", versions) is Verdict.AFFECTED
    assert evaluate("2.7.1", versions) is Verdict.NOT_AFFECTED


def test_a_half_open_range_excludes_its_upper_bound():
    """`lessThan` is the commonest range shape and it is EXCLUSIVE — the fixed
    version is the bound, so treating it as inclusive marks every patched system
    as vulnerable."""
    versions = affected({"version": "5.3", "lessThan": "5.3.9",
                         "status": "affected", "versionType": "custom"})
    assert evaluate("5.3.0", versions) is Verdict.AFFECTED
    assert evaluate("5.3.8", versions) is Verdict.AFFECTED
    assert evaluate("5.3.9", versions) is Verdict.NOT_AFFECTED   # the fix
    assert evaluate("5.2.9", versions) is Verdict.NOT_AFFECTED   # below the floor


def test_a_closed_range_includes_its_upper_bound():
    versions = affected({"version": "1.0", "lessThanOrEqual": "1.5",
                         "status": "affected"})
    assert evaluate("1.5", versions) is Verdict.AFFECTED
    assert evaluate("1.5.1", versions) is Verdict.NOT_AFFECTED


@pytest.mark.parametrize("sentinel", ["0", "*", "", "-"])
def test_the_from_the_beginning_sentinels_are_understood(sentinel):
    """CNAs write `0` or `*` for "every version up to the fix". Reading either
    as a literal version number makes the floor test reject everything."""
    versions = affected({"version": sentinel, "lessThan": "10.1.20",
                         "status": "affected", "versionType": "custom"})
    assert evaluate("3.4.5", versions) is Verdict.AFFECTED
    assert evaluate("10.1.20", versions) is Verdict.NOT_AFFECTED


def test_an_unaffected_entry_carves_an_exception():
    """`status: unaffected` entries exist to except versions from a range. They
    are not evidence of exposure."""
    assert evaluate("3.0", affected({"version": "3.0", "status": "unaffected"})) \
        is Verdict.NOT_AFFECTED


# ── failing closed, which is the point ───────────────────────────────────────

def test_an_unknown_asset_version_is_unknown_not_safe():
    assert evaluate(None, affected({"version": "1.0", "status": "affected"})) \
        is Verdict.UNKNOWN
    assert evaluate("R80.40", affected({"version": "1.0", "status": "affected"})) \
        is Verdict.UNKNOWN


def test_no_published_ranges_is_unknown_not_safe():
    assert evaluate("1.0", []) is Verdict.UNKNOWN


def test_one_unreadable_range_poisons_the_whole_verdict():
    """THE MOST IMPORTANT TEST HERE. A product with three ranges, two readable
    and missing, one unreadable, must be UNKNOWN — not NOT_AFFECTED.

    "None of the ranges I could read matched" is not "not affected", and the
    difference is the one that costs a breach rather than an afternoon."""
    versions = affected(
        {"version": "1.0", "lessThan": "1.5", "status": "affected"},
        {"version": "2.0", "lessThan": "2.5", "status": "affected"},
        {"version": "R80.40", "status": "affected"},          # unreadable
    )
    assert evaluate("9.9", versions) is Verdict.UNKNOWN


def test_a_match_still_wins_over_an_unreadable_sibling():
    """Affected is positive evidence and survives an unreadable neighbour — the
    poisoning rule exists to prevent a false NEGATIVE, not to suppress a hit."""
    versions = affected(
        {"version": "1.0", "lessThan": "1.5", "status": "affected"},
        {"version": "garbage", "status": "affected"},
    )
    assert evaluate("1.2", versions) is Verdict.AFFECTED


def test_all_readable_and_none_matching_is_a_real_negative():
    """The rule must still be able to say NOT_AFFECTED, or it is not a rule."""
    versions = affected({"version": "1.0", "lessThan": "1.5", "status": "affected"})
    assert evaluate("3.0", versions) is Verdict.NOT_AFFECTED


# ── extraction from a real record shape ──────────────────────────────────────

def test_affected_products_reads_the_cna_container_only():
    """The affected-product statement belongs to the party that published the
    vulnerability. ADP containers enrich; they do not restate what is affected."""
    record = {"containers": {
        "cna": {"affected": [
            {"vendor": "n/a", "product": "Open5GS",
             "versions": [{"version": "2.7.0", "status": "affected"}]},
            {"vendor": "x", "product": "NoVersions", "versions": []},
        ]},
        "adp": [{"affected": [{"vendor": "wrong", "product": "WRONG",
                               "versions": [{"version": "9", "status": "affected"}]}]}],
    }}
    products = affected_products(record)
    assert [p["product"] for p in products] == ["Open5GS"]
    assert products[0]["versions"][0]["version"] == "2.7.0"
