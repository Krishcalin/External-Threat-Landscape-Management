"""W1: the determination tier, and the retirement it makes live.

`core/affected.py` was written in P1 and never fired, because nothing passed
`affected_versions`. Turning it on also turns on the path where a published
range RETIRES a finding — removing an entry from a customer's worklist, which is
the most consequential thing this product does.
"""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from core import engine, intel
from core.affected import Verdict, evaluate
from core.models import (Asset, Confidence, Exploited, Exposure, MatchBasis)

ROOT = Path(__file__).resolve().parents[1]


def exploited(cve="CVE-2021-44228", product="Log4j2", vendor="Apache"):
    return Exploited(cve=cve, vendor_project=vendor, product=product,
                     name="RCE", date_added=date(2021, 12, 10),
                     short_description="Remote code execution.",
                     required_action="Patch.")


def exposure(version=None, cve="CVE-2021-44228"):
    asset = Asset(identifier="app.example.com", product="Log4j2",
                  vendor="Apache", version=version)
    return Exposure(asset=asset, exploited=exploited(cve),
                    basis=MatchBasis.PRODUCT_MATCH,
                    confidence=Confidence.STRONG,
                    evidence=["product names correspond"])


RANGE = [{"version": "2.0", "lessThan": "2.15.0", "status": "affected"}]
EXACT = [{"version": "2.14.1", "status": "affected"}]


# -- the tier fires ----------------------------------------------------------
def test_a_version_inside_a_published_range_becomes_a_determination():
    finding = engine.score_exposure(exposure("2.14.1"), affected_versions=RANGE)
    assert finding.basis is MatchBasis.VERSION_RANGE
    assert any("falls in a published affected range" in e
               for e in finding.evidence)


def test_an_exact_version_match_is_also_a_determination():
    """37.5% of KEV carries exact versions rather than ranges — measured. An
    equality comparison is still arithmetic over two outside facts."""
    finding = engine.score_exposure(exposure("2.14.1"), affected_versions=EXACT)
    assert finding.basis is MatchBasis.VERSION_RANGE


def test_without_ranges_nothing_changes():
    """P1 behaviour must survive: no range data means a worklist entry, which
    is correct and merely less useful."""
    finding = engine.score_exposure(exposure("2.14.1"))
    assert finding.basis is MatchBasis.PRODUCT_MATCH


# -- the retirement ----------------------------------------------------------
def test_a_version_outside_every_range_retires_the_finding():
    finding = engine.score_exposure(exposure("2.17.1"), affected_versions=RANGE)
    assert finding.basis is MatchBasis.VERSION_RANGE
    assert evaluate("2.17.1", RANGE) is Verdict.NOT_AFFECTED


def test_a_retirement_is_never_silent():
    """Removing an entry from a worklist without saying why is the one thing
    this tier must not do."""
    finding = engine.score_exposure(exposure("2.17.1"), affected_versions=RANGE)
    retired = [e for e in finding.evidence if e.startswith("RETIRED:")]
    assert retired, "a retirement must state itself"
    assert "2.17.1" in retired[0], "and the version it compared"
    assert "2.15.0" in retired[0], "and the range it compared against"


def test_a_determination_cites_the_range_it_rests_on():
    finding = engine.score_exposure(exposure("2.14.1"), affected_versions=RANGE)
    cited = [e for e in finding.evidence if "2.0 <= v < 2.15.0" in e]
    assert cited, f"evidence did not carry the range: {finding.evidence}"


def test_many_ranges_are_capped_and_the_cap_announces_itself():
    """A truncated basis that does not say it was truncated reads as the whole
    reason for the verdict."""
    many = [{"version": f"{i}.0", "lessThan": f"{i}.9", "status": "affected"}
            for i in range(1, 8)]
    finding = engine.score_exposure(exposure("3.5"), affected_versions=many)
    joined = " ".join(finding.evidence)
    assert "and 4 more" in joined


# -- what must NOT reach the tier -------------------------------------------
def test_an_asset_with_no_version_cannot_be_determined():
    """A CT-discovered, fingerprinted host carries version=None by design."""
    finding = engine.score_exposure(exposure(None), affected_versions=RANGE)
    assert finding.basis is MatchBasis.PRODUCT_MATCH
    assert any("carries no version" in e for e in finding.evidence)


def test_a_fingerprinted_version_cannot_reach_the_evaluator():
    """D17, and W1 is what makes it load-bearing rather than theoretical.

    A banner version lands in obs_version, which is not an alias of `version`,
    so a target that claims a high version cannot retire its own finding.
    """
    from core import inventory
    from core.identity import Fingerprint

    row = Fingerprint(host="app.example.com", product="Log4j2", vendor="Apache",
                      observed_version="99.0").inventory_row()
    assert row["obs_version"] == "99.0"
    assert "obsversion" not in inventory.ALIASES["version"]

    spoofed = Asset(identifier="app.example.com", product="Log4j2",
                    vendor="Apache", version=None, attributes=row)
    finding = engine.score_exposure(
        Exposure(asset=spoofed, exploited=exploited(),
                 basis=MatchBasis.PRODUCT_MATCH, confidence=Confidence.STRONG,
                 evidence=[]),
        affected_versions=RANGE)
    assert finding.basis is MatchBasis.PRODUCT_MATCH, \
        "a target must not be able to retire its own finding"


def test_an_uncomparable_range_leaves_the_worklist_entry_alone():
    """~32.5% of KEV carries `n/a` or a prose blob. Those must not silently
    become determinations, and must not be confused with 'not affected'."""
    prose = [{"version": "n/a", "status": "affected"}]
    finding = engine.score_exposure(exposure("2.14.1"), affected_versions=prose)
    assert finding.basis is MatchBasis.PRODUCT_MATCH
    assert any("could not be compared" in e for e in finding.evidence)


def test_could_not_compare_reads_differently_from_does_not_apply():
    could_not = engine.score_exposure(exposure(None), affected_versions=RANGE)
    does_not = engine.score_exposure(exposure("2.17.1"), affected_versions=RANGE)
    assert " ".join(could_not.evidence) != " ".join(does_not.evidence)


# -- the summary -------------------------------------------------------------
def test_the_summary_splits_the_three_verdicts():
    findings = [
        engine.score_exposure(exposure("2.14.1"), affected_versions=RANGE),
        engine.score_exposure(exposure("2.17.1"), affected_versions=RANGE),
        engine.score_exposure(exposure("2.14.1")),
    ]
    verdicts = engine.summarise(findings)["version_verdicts"]
    assert verdicts == {"affected": 1, "retired": 1, "not_compared": 1}


# -- the corpus --------------------------------------------------------------
def test_a_corpus_without_range_data_says_so_rather_than_looking_cautious():
    corpus = intel.Corpus({"vulnerabilities": [{"cveID": "CVE-1"}]}, {}, {})
    assert corpus.has_affected is False
    assert corpus.determinable_share is None
    assert corpus.version_ranges_for("CVE-1") == []


def test_the_corpus_flattens_ranges_ready_for_the_evaluator():
    corpus = intel.Corpus(
        {"vulnerabilities": [{"cveID": "CVE-1"}]}, {},
        {"_meta": {"determinable_share": 0.675},
         "affected": {"CVE-1": [{"vendor": "Apache", "product": "Log4j2",
                                 "versions": RANGE}]}})
    assert corpus.has_affected
    assert corpus.determinable_share == 0.675
    assert corpus.version_ranges_for("cve-1") == RANGE


@pytest.mark.skipif(not (ROOT / "data" / "affected.json").is_file(),
                    reason="run tools/refresh_intel.py to vendor affected.json")
def test_the_vendored_corpus_matches_what_was_measured():
    """Catches a COLLAPSE, not a precise value.

    Two samples disagreed badly — a 40-CVE random draw gave 67.5%, an
    age-stratified draw implied ~41% — so this deliberately does not pin a
    number it cannot justify. What it does catch is the failure that matters: a
    refresh whose parser silently stops recognising version data, which would
    take the share to near zero and quietly turn every determination back into a
    worklist entry without anything looking broken.
    """
    corpus = intel.load()
    assert corpus.has_affected
    share = corpus.determinable_share
    assert share is not None
    assert 0.15 < share < 0.98, (
        f"determinable share {share} is outside any plausible range — either "
        f"the parser broke or the CVE Program changed its schema")
