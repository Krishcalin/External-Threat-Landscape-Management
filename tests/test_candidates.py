"""The triage queue, and the count nobody else shows.

The interesting behaviour here is all about the UNDECIDED state: that a
deferral does not stop the clock, that a disown needs a reason, and that a claim
does not put anything in scope.
"""
from __future__ import annotations

from datetime import date

import pytest

from core import candidates as c

TODAY = date(2026, 8, 23)


def make(name, **kw):
    base = dict(name=name, source="ct", first_seen="2026-08-20",
                last_seen="2026-08-23")
    base.update(kw)
    return c.Candidate(**base)


# ── the undecided state ─────────────────────────────────────────────────────
def test_a_new_candidate_is_undecided():
    assert make("a.example").undecided is True


def test_a_deferral_does_not_stop_the_clock():
    """Somebody looked and did not answer, which leaves the asset in exactly
    the state this queue exists to surface."""
    deferred = make("a.example", decision="deferred", decided_by="x")
    assert deferred.undecided is True


def test_claiming_or_disowning_ends_the_undecided_state():
    for decision in ("claimed", "disowned"):
        assert make("a.example", decision=decision,
                    decided_by="x", reason="r").undecided is False


def test_a_candidate_ages_from_when_it_was_first_seen():
    assert make("a.example", first_seen="2026-07-24").age_days(TODAY) == 30


def test_an_undecided_candidate_becomes_stale_at_the_threshold():
    """Thirty days is one monthly review cycle. Something nobody decided about
    across a whole cycle was not waiting, it was forgotten."""
    assert make("a.example", first_seen="2026-07-24").stale(TODAY) is True
    assert make("a.example", first_seen="2026-08-01").stale(TODAY) is False


def test_a_decided_candidate_never_goes_stale():
    old = make("a.example", first_seen="2020-01-01",
               decision="claimed", decided_by="x")
    assert old.stale(TODAY) is False


def test_a_deferred_candidate_does_go_stale():
    old = make("a.example", first_seen="2020-01-01",
               decision="deferred", decided_by="x")
    assert old.stale(TODAY) is True


def test_an_unparseable_first_seen_ages_to_zero_rather_than_raising():
    assert make("a.example", first_seen="whenever").age_days(TODAY) == 0


# ── the three decisions ─────────────────────────────────────────────────────
def test_disowning_requires_a_reason():
    """'Not ours' with no reason is indistinguishable six months later from
    'nobody looked'."""
    with pytest.raises(c.CandidateRefused, match="requires a reason"):
        c.check_decision("disowned", "someone@example.com")


def test_disowning_with_a_reason_is_accepted():
    assert c.check_decision("disowned", "x@example.com",
                            "managed by a third party") is c.Decision.DISOWNED


def test_claiming_needs_no_reason():
    assert c.check_decision("claimed", "x@example.com") is c.Decision.CLAIMED


def test_a_decision_needs_somebody_to_have_made_it():
    with pytest.raises(c.CandidateRefused, match="needs somebody"):
        c.check_decision("claimed", "")


def test_an_invented_decision_is_refused_and_lists_the_real_ones():
    with pytest.raises(c.CandidateRefused, match="is not a decision"):
        c.check_decision("maybe", "x@example.com")


def test_only_three_decisions_exist():
    """A fourth would be somebody avoiding the question the queue asks."""
    assert {d.value for d in c.Decision} == {"claimed", "disowned", "deferred"}


def test_every_decision_explains_itself():
    for decision in c.Decision:
        assert len(c.DECISION_MEANING[decision]) > 60


# ── the summary ─────────────────────────────────────────────────────────────
def test_the_summary_separates_undecided_from_stale():
    """A queue reported as a total reads as administrative work. Reported as
    '9 undecided, 4 older than a month' it reads as what it is."""
    rows = [make("a.example", first_seen="2026-07-01"),
            make("b.example", first_seen="2026-08-22"),
            make("c.example", decision="claimed", decided_by="x")]
    summary = c.summarise(rows, TODAY)
    assert summary["total"] == 3
    assert summary["undecided"] == 2
    assert summary["stale"] == 1


def test_the_summary_explains_what_stale_means():
    summary = c.summarise([make("a.example", first_seen="2026-07-01")], TODAY)
    assert "shadow IT" in summary["stale_means"]
    assert "nobody is scanning" in summary["stale_means"]


def test_the_summary_states_that_claiming_does_not_scope():
    """Nothing in this product may decide what it is allowed to scan."""
    summary = c.summarise([], TODAY)
    assert "does NOT add it to scope" in summary["claim_does_not_scope"]


def test_the_summary_counts_by_source():
    """'Certificate transparency saw it' and 'somebody's CSV mentioned it'
    justify very different amounts of attention."""
    rows = [make("a.example", source="ct"), make("b.example", source="csv")]
    assert c.summarise(rows, TODAY)["by_source"] == {"csv": 1, "ct": 1}


def test_an_empty_queue_still_reports_the_threshold():
    assert c.summarise([], TODAY)["threshold_days"] == c.AGE_THRESHOLD_DAYS


def test_stale_candidates_come_back_oldest_first():
    rows = [make("new.example", first_seen="2026-07-20"),
            make("old.example", first_seen="2026-01-01")]
    assert [x.name for x in c.stale_candidates(rows, TODAY)] == [
        "old.example", "new.example"]


# ── the boundary ────────────────────────────────────────────────────────────
def test_this_module_cannot_write_scope():
    """core/scope.py stays the only writer of scope rules. A tool that
    auto-promoted discovered names would be deciding what it may scan."""
    import inspect
    source = inspect.getsource(c)
    for forbidden in ("ScopeRule", "add_scope", "scope.add"):
        assert forbidden not in source, forbidden


def test_the_migration_requires_a_reason_at_the_database_too():
    """Two places, deliberately: the constraint is the guarantee, and the
    Python check is the one that can explain itself to a user."""
    import pathlib
    sql = (pathlib.Path(c.__file__).resolve().parents[1]
           / "db" / "010_candidates.sql").read_text(encoding="utf-8")
    assert "disown_needs_a_reason" in sql
    assert "decision_needs_a_decider" in sql


def test_the_table_is_tenanted_like_everything_migration_006_touched():
    import pathlib
    sql = (pathlib.Path(c.__file__).resolve().parents[1]
           / "db" / "010_candidates.sql").read_text(encoding="utf-8")
    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "FORCE ROW LEVEL SECURITY" in sql
    assert "UNIQUE (org_id, name)" in sql
