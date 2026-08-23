"""P4: the India compliance pack, and the claims it must never make.

Two things could go badly wrong in a compliance feature, and both are the
default behaviour of the category:

  * starting a regulatory clock on a finding, pushing users toward
    over-reporting to a national CERT
  * showing a coverage percentage against a control framework, which gets
    summed and shown to a board

Most of these tests exist to keep both impossible.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core import cert_in, controls
from core.cert_in import (Category, Clock, Declaration, DeclarationInvalid,
                          Detectability, REPORTING_WINDOW)

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


def declaration(hours_ago=1, by="soc-lead@example.com",
                category=Category.CRITICAL_SYSTEM_COMPROMISE, summary="x"):
    return Declaration(category=category,
                       became_aware_at=NOW - timedelta(hours=hours_ago),
                       declared_by=by, summary=summary)


# ── an exposure is not an incident ──────────────────────────────────────────
def test_the_clock_requires_a_human_declaration():
    """There is deliberately no function that opens a clock from a finding.

    A tool that started a six-hour countdown on every unpatched perimeter
    service would push its users toward over-reporting to a national CERT.
    """
    assert not hasattr(cert_in, "clock_from_finding")
    assert not hasattr(cert_in, "start_clock")
    # The only constructor takes a Declaration, which requires a person.
    assert Clock(declaration()).declaration.declared_by


def test_the_reason_is_stated_not_merely_implemented():
    assert "will not" in cert_in.WHY_NOT_AUTOMATIC
    assert "over-reporting to a national CERT" in cert_in.WHY_NOT_AUTOMATIC
    assert "statement about your estate" in cert_in.WHY_NOT_AUTOMATIC


def test_almost_nothing_reportable_is_observable_from_outside():
    """Seven of eight. A compliance feature whose main output is 'we cannot
    tell you this' is unusual and is the correct answer."""
    observable = [c for c, d in cert_in.OBSERVABILITY.items()
                  if d is not Detectability.NOT_OBSERVABLE]
    assert len(observable) == 1
    assert cert_in.OBSERVABILITY[Category.TARGETED_SCANNING] is \
        Detectability.NOT_OBSERVABLE, "somebody scanning YOU is not visible here"


def test_the_note_warns_against_the_claim_competitors_make():
    summary = cert_in.observability_note()["summary"]
    assert "automatic CERT-In incident detection" in summary
    assert "the data does not support" in summary


# ── the declaration is a record, not a form ─────────────────────────────────
def test_an_unattributed_declaration_is_refused():
    with pytest.raises(DeclarationInvalid) as exc:
        declaration(by="  ")
    assert "who made it" in str(exc.value)


def test_a_declaration_without_a_summary_is_refused():
    """This product cannot write the sentence describing what happened."""
    with pytest.raises(DeclarationInvalid) as exc:
        declaration(summary="")
    assert "cannot write that sentence for you" in str(exc.value)


def test_a_naive_timestamp_is_refused():
    """A six-hour deadline computed from an ambiguous time is worse than none."""
    with pytest.raises(DeclarationInvalid) as exc:
        Declaration(category=Category.DATA_BREACH,
                    became_aware_at=datetime(2026, 8, 23, 12, 0),
                    declared_by="a", summary="b")
    assert "timezone" in str(exc.value)


# ── the clock itself ────────────────────────────────────────────────────────
def test_the_window_is_six_hours():
    assert REPORTING_WINDOW == timedelta(hours=6)


def test_the_deadline_runs_from_awareness_not_from_declaration():
    """The directive's clock runs from becoming aware, and only a human knows
    when that was — it may be well before the record was typed."""
    clock = Clock(declaration(hours_ago=5))
    assert clock.deadline == NOW - timedelta(hours=5) + REPORTING_WINDOW
    assert "1h remaining" in clock.explain(NOW)


def test_an_expired_window_says_so_plainly():
    """A tool that softened this would help somebody misunderstand their own
    position."""
    text = Clock(declaration(hours_ago=9)).explain(NOW)
    assert "closed 3h ago" in text
    assert "not legal advice" in text


def test_the_directive_is_cited_with_its_number_and_date():
    assert "20(3)/2022-CERT-In" in cert_in.DIRECTIVE
    assert "28 April 2022" in cert_in.DIRECTIVE


def test_the_category_list_carries_a_review_date():
    """A regulatory list with no review date silently ages into a false claim."""
    assert cert_in.REVIEWED_ON


# ── controls: supporting is not satisfying ──────────────────────────────────
def test_no_coverage_figure_is_produced_against_any_control():
    """It would be summed, shown to a board, and the board would be receiving a
    number this product has no basis to produce.

    Checks for a numeric FIELD rather than the word: the disclaimer says
    "no coverage percentage here", and a crude word-ban would fire on the
    sentence that exists to prevent the thing.
    """
    import re
    payload = controls.mapping()
    for key in payload:
        assert "score" not in key.lower(), key
        assert "coverage" not in key.lower(), key
    for control in payload["controls"]:
        numeric = [v for v in control.values() if isinstance(v, (int, float))]
        assert not numeric, f"{control['id']} carries a numeric field"
        # No "80% covered" style claim in the prose either.
        assert not re.search(r"\d+\s*%\s*(cover|complian|comple)",
                             str(control), re.I), control["id"]


def test_every_control_says_what_it_does_not_do():
    for control in controls.ALL:
        assert control.does_not.strip(), control.identifier
        assert len(control.does_not) > 40, f"{control.identifier} is too vague"


def test_every_control_names_where_the_evidence_comes_from():
    """So a claim can be checked rather than trusted."""
    for control in controls.ALL:
        assert control.evidence_from, control.identifier


def test_the_disclaimer_distinguishes_supporting_from_satisfying():
    text = controls.SUPPORTS_IS_NOT_SATISFIES
    assert "does not satisfy them" in text
    assert "cannot make you compliant" in text


@pytest.mark.parametrize("identifier,title", [
    ("A.5.7", "Threat intelligence"),
    ("A.5.21", "Managing information security in the ICT supply chain"),
    ("A.5.22", "Monitoring, review and change management of supplier services"),
    ("A.5.23", "Information security for use of cloud services"),
    ("A.8.8", "Management of Technical Vulnerabilities"),
])
def test_iso_titles_are_verbatim(identifier, title):
    """Paraphrasing a control title is how a mapping drifts into describing
    something the standard does not say."""
    found = [c for c in controls.ISO_27001_2022 if c.identifier == identifier]
    assert found, identifier
    assert found[0].title == title


def test_the_a88_entry_admits_the_determination_limit():
    """The most over-claimed control in the industry."""
    a88 = [c for c in controls.ISO_27001_2022 if c.identifier == "A.8.8"][0]
    assert "47.5%" in a88.does_not
    assert "does not patch" in a88.does_not.lower()


def test_the_threat_intelligence_entry_refuses_attribution():
    a57 = [c for c in controls.ISO_27001_2022 if c.identifier == "A.5.7"][0]
    assert "median of 57 threat groups" in a57.does_not


def test_the_mapping_is_small_on_purpose():
    """A mapping claiming forty controls would be mostly padding, and padding
    makes the honest entries unreadable."""
    assert len(controls.ALL) <= 12


def test_frameworks_are_named_by_their_published_titles():
    assert "ISO/IEC 27001:2022" in controls.mapping()["frameworks"]
    assert "NIST CSF 2.0" in controls.mapping()["frameworks"]
