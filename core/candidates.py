"""The triage queue: discovered names nobody has decided about yet.

WHY THIS IS A FINDING AND NOT A BACKLOG
-----------------------------------------
An undecided candidate is the state that shadow IT and forgotten subsidiaries
actually live in. Nobody claims them and nobody disowns them, so they sit
outside scope, are never scanned, and never appear in any count — which is why a
product can report zero findings on an estate with a forgotten staging server on
the internet.

`AGE_THRESHOLD_DAYS` turns that into something visible. A candidate untouched
for 30 days is reported, and the Executive projection carries the undecided
count beside the claimed and disowned ones, because the undecided number is the
one nobody else shows.

THREE DECISIONS, AND ONLY THREE
---------------------------------
**claim** — this is ours. Records the decision; a person then adds it to scope.
**disown** — this is not ours, and WHY. The reason is required at the database
level, because "not ours" with no reason is indistinguishable six months later
from "nobody looked".
**defer** — a real answer, kept because forcing a binary choice produces bad
claims. A deferral ages like an undecided candidate; it does not stop the clock.

WHAT THIS MODULE CANNOT DO
----------------------------
It cannot put anything in scope. `core/scope.py` stays the only writer of scope
rules, and a claim here records a human decision that a person then carries out.
An attack-surface tool that auto-promoted discovered names would be deciding
what it is allowed to scan, which is the one thing `core/gate.py` exists to stop
it doing.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

#: Above this, an undecided candidate stops being a queue item and becomes a
#: finding in its own right. Thirty days is one monthly review cycle: something
#: nobody decided about across a whole cycle was not waiting, it was forgotten.
AGE_THRESHOLD_DAYS = 30


class Decision(str, enum.Enum):
    CLAIMED = "claimed"
    DISOWNED = "disowned"
    DEFERRED = "deferred"


DECISION_MEANING = {
    Decision.CLAIMED: (
        "somebody decided this asset belongs to the organisation. It is NOT "
        "yet in scope — a person still has to add it, because nothing here may "
        "decide what SKOPOS is allowed to scan."),
    Decision.DISOWNED: (
        "somebody decided this asset is not the organisation's, and recorded "
        "why. The reason is required: 'not ours' with no reason is "
        "indistinguishable six months later from 'nobody looked'."),
    Decision.DEFERRED: (
        "somebody looked and could not decide. A real answer, and it ages "
        "exactly like an undecided candidate — deferring does not stop the "
        "clock."),
}


class CandidateRefused(ValueError):
    """The decision cannot be recorded as asked."""


@dataclass(frozen=True)
class Candidate:
    name: str
    source: str
    first_seen: str
    last_seen: str
    times_seen: int = 1
    decision: Optional[str] = None
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    reason: Optional[str] = None

    @property
    def undecided(self) -> bool:
        # A deferral is not a decision for ageing purposes. Somebody looked and
        # did not answer, which leaves the asset in exactly the state this
        # queue exists to surface.
        return self.decision in (None, Decision.DEFERRED.value)

    def age_days(self, today: Optional[date] = None) -> int:
        try:
            then = date.fromisoformat(str(self.first_seen)[:10])
        except (TypeError, ValueError):
            return 0
        return ((today or datetime.now(timezone.utc).date()) - then).days

    def stale(self, today: Optional[date] = None) -> bool:
        return self.undecided and self.age_days(today) >= AGE_THRESHOLD_DAYS

    def to_dict(self, today: Optional[date] = None) -> Dict[str, Any]:
        return {
            "name": self.name, "source": self.source,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "times_seen": self.times_seen,
            "decision": self.decision, "decided_at": self.decided_at,
            "decided_by": self.decided_by, "reason": self.reason,
            "undecided": self.undecided,
            "age_days": self.age_days(today),
            "stale": self.stale(today),
        }


def check_decision(decision: str, actor: str,
                   reason: str = "") -> Decision:
    """Validate a decision before the store is touched.

    The reason requirement is enforced here AND as a database constraint. Two
    places, deliberately: the constraint is the guarantee, and this is the one
    that can explain itself to a user.
    """
    try:
        parsed = Decision(str(decision or "").strip().lower())
    except ValueError:
        raise CandidateRefused(
            f"{decision!r} is not a decision. Use one of: "
            f"{', '.join(d.value for d in Decision)}") from None
    if not str(actor or "").strip():
        raise CandidateRefused(
            "a decision needs somebody to have made it; --actor is not "
            "optional here for the same reason it is not optional anywhere else")
    if parsed is Decision.DISOWNED and not str(reason or "").strip():
        raise CandidateRefused(
            "disowning an asset requires a reason. 'Not ours' with no reason "
            "is indistinguishable six months later from 'nobody looked', and "
            "the next person to see this name will have to start again.")
    return parsed


def summarise(candidates: Sequence[Candidate],
              today: Optional[date] = None) -> Dict[str, Any]:
    """Counts an operator needs, and the one nobody else shows.

    `undecided` and `stale` are the point. A queue reported only as a total
    reads as administrative work; reported as "9 undecided, 4 of them older
    than a month" it reads as what it is.
    """
    rows = list(candidates)
    undecided = [c for c in rows if c.undecided]
    stale = [c for c in undecided if c.stale(today)]
    by_decision: Dict[str, int] = {}
    for candidate in rows:
        key = candidate.decision or "undecided"
        by_decision[key] = by_decision.get(key, 0) + 1
    by_source: Dict[str, int] = {}
    for candidate in rows:
        by_source[candidate.source] = by_source.get(candidate.source, 0) + 1

    return {
        "total": len(rows),
        "undecided": len(undecided),
        "stale": len(stale),
        "by_decision": dict(sorted(by_decision.items())),
        "by_source": dict(sorted(by_source.items())),
        "oldest_undecided_days": max((c.age_days(today) for c in undecided),
                                     default=0),
        "threshold_days": AGE_THRESHOLD_DAYS,
        "stale_means": (
            f"{len(stale)} discovered asset(s) have gone {AGE_THRESHOLD_DAYS} "
            f"days with nobody deciding whether they belong to this "
            f"organisation. That is not a backlog — it is the state shadow IT "
            f"and forgotten subsidiaries live in, and an asset nobody has "
            f"claimed is an asset nobody is scanning, patching or watching."),
        "claim_does_not_scope": (
            "Claiming an asset here records a decision. It does NOT add it to "
            "scope: nothing in this product may decide what it is allowed to "
            "scan, so a person still has to make that change."),
    }


def stale_candidates(candidates: Sequence[Candidate],
                     today: Optional[date] = None) -> List[Candidate]:
    return sorted((c for c in candidates if c.stale(today)),
                  key=lambda c: c.age_days(today), reverse=True)


__all__ = ["Candidate", "Decision", "DECISION_MEANING", "CandidateRefused",
           "AGE_THRESHOLD_DAYS", "check_decision", "summarise",
           "stale_candidates"]
