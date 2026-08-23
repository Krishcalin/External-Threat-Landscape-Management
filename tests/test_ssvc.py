"""SSVC: CISA's own decision points, used where they can actually matter.

The ATT&CK triad was attempted and abandoned on measurement — see the commit and
`core/scoring.py:AdversaryInterest`. This is what the same investigation turned
up that does work: structured, per-CVE, 100% coverage on the sample, and a
genuine discriminator where the triad offered none.
"""
from __future__ import annotations

from datetime import date

import pytest

from core import engine, intel, match
from core.models import Asset, Confidence, Exploited, Exposure, MatchBasis
from core.scoring import Exploitability


def entry(cve, ransomware=False, epss=0.5, due=None):
    return Exploited(cve=cve, vendor_project="V", product="P", name="n",
                     date_added=date(2024, 1, 1), short_description="s",
                     required_action="a", known_ransomware=ransomware,
                     epss=epss, due_date=due or date(2024, 2, 1))


def exposure(cve, **kw):
    return Exposure(asset=Asset(identifier="h", product="P", version="1.0"),
                    exploited=entry(cve, **kw),
                    basis=MatchBasis.PRODUCT_MATCH,
                    confidence=Confidence.STRONG, evidence=[])


# ── it does NOT go where it would be discarded ──────────────────────────────
def test_ssvc_cannot_change_exploitability_for_a_kev_entry():
    """The trap this avoids, and the one W3's artefacts fell into. KEV
    membership short-circuits exploitability to 1.0, so an SSVC input there is
    silently discarded for every entry in this corpus."""
    on = Exploitability(in_kev=True, epss=0.5, ssvc_automatable=1.0).value()
    off = Exploitability(in_kev=True, epss=0.5, ssvc_automatable=0.0).value()
    assert on == off == 1.0


def test_it_would_matter_for_a_non_kev_entry():
    """Which is why the field stays — the advisory path reaches it."""
    on = Exploitability(in_kev=False, epss=0.5, ssvc_automatable=1.0).value()
    off = Exploitability(in_kev=False, epss=0.5, ssvc_automatable=0.0).value()
    assert on > off


# ── it goes where discrimination actually happens ───────────────────────────
def test_automatable_outranks_non_automatable_at_equal_everything_else():
    rows = [exposure("CVE-B"), exposure("CVE-A")]
    ordered = match.rank(rows, automatable={"CVE-A": True, "CVE-B": False})
    assert [e.exploited.cve for e in ordered] == ["CVE-A", "CVE-B"]


def test_unknown_sorts_between_yes_and_no():
    """A CVE nobody has assessed must not be pushed to the bottom behind a
    decision that was never made."""
    rows = [exposure("CVE-NO"), exposure("CVE-UNK"), exposure("CVE-YES")]
    ordered = match.rank(rows, automatable={"CVE-YES": True, "CVE-NO": False})
    assert [e.exploited.cve for e in ordered] == ["CVE-YES", "CVE-UNK", "CVE-NO"]


def test_an_observation_outranks_a_forecast():
    """SSVC is CISA's decision; EPSS predicts. This product puts observations
    ahead of predictions everywhere, and the worklist order is where that
    preference costs something."""
    low_epss_automatable = exposure("CVE-A", epss=0.01)
    high_epss_not = exposure("CVE-B", epss=0.99)
    ordered = match.rank([high_epss_not, low_epss_automatable],
                         automatable={"CVE-A": True, "CVE-B": False})
    assert ordered[0].exploited.cve == "CVE-A"


def test_ransomware_still_outranks_automatable():
    """It changes what a breach costs, not merely how fast it arrives."""
    ordered = match.rank([exposure("CVE-A"), exposure("CVE-R", ransomware=True)],
                         automatable={"CVE-A": True, "CVE-R": False})
    assert ordered[0].exploited.cve == "CVE-R"


def test_ranking_without_decisions_is_unchanged():
    """P2 behaviour survives: no SSVC data means the previous order."""
    rows = [exposure("CVE-B", epss=0.1), exposure("CVE-A", epss=0.9)]
    assert [e.exploited.cve for e in match.rank(rows)] == ["CVE-A", "CVE-B"]


def test_engine_rank_breaks_ties_within_a_score():
    findings = [engine.score_exposure(exposure("CVE-B")),
                engine.score_exposure(exposure("CVE-A"))]
    assert findings[0].score.teps == findings[1].score.teps, "fixture must tie"
    ordered = engine.rank(findings, automatable={"CVE-A": True, "CVE-B": False})
    assert [f.exploited.cve for f in ordered] == ["CVE-A", "CVE-B"]


# ── it is shown, not merely used ────────────────────────────────────────────
def test_ssvc_appears_as_evidence():
    """'CISA judged this automatable' is a fact an operator can act on: it means
    everything vulnerable gets found by a scanner, not by somebody choosing to
    look at you."""
    finding = engine.score_exposure(
        exposure("CVE-A"),
        ssvc={"exploitation": "active", "automatable": "yes",
              "technical_impact": "total", "timestamp": "2024-01-10"})
    line = [e for e in finding.evidence if e.startswith("CISA SSVC:")]
    assert line, finding.evidence
    assert "automatable=yes" in line[0]
    assert "timestamp" not in line[0], "the date is provenance, not a finding"


def test_no_ssvc_adds_no_evidence():
    finding = engine.score_exposure(exposure("CVE-A"))
    assert not any(e.startswith("CISA SSVC:") for e in finding.evidence)


# ── the corpus accessor ─────────────────────────────────────────────────────
def test_unassessed_is_none_not_false():
    """"Not automatable" and "nobody assessed it" order differently."""
    corpus = intel.Corpus({"vulnerabilities": [{"cveID": "CVE-1"}]}, {}, {}, {})
    assert corpus.automatable("CVE-1") is None
    assert corpus.has_ssvc is False


def test_the_corpus_reads_a_decision():
    corpus = intel.Corpus(
        {"vulnerabilities": [{"cveID": "CVE-1"}]}, {}, {},
        {"ssvc": {"CVE-1": {"automatable": "yes", "exploitation": "active"}}})
    assert corpus.has_ssvc
    assert corpus.automatable("cve-1") is True
    assert corpus.ssvc_for("CVE-1")["exploitation"] == "active"


def test_a_no_decision_is_false_not_none():
    corpus = intel.Corpus({"vulnerabilities": []}, {}, {},
                          {"ssvc": {"CVE-1": {"automatable": "no"}}})
    assert corpus.automatable("CVE-1") is False
