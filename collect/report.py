"""One vocabulary for "what did this source actually give us".

Used by passive discovery, the DNS sweep and the fingerprint run alike. Three
subsystems each invented their own version of this — `SourceReport`,
`ResolverReport`, `Refusal` — and the triplication was the single largest source
of problems found reviewing them, because each one drew the line between
"answered" and "did not" in a slightly different place.

WHY A BOOLEAN IS NOT ENOUGH
---------------------------
`ok: bool` cannot distinguish these, and every one of them renders as a small
estate:

    the source answered and there is genuinely nothing
    the source answered but capped us at 50 rows
    the source is down
    nobody configured its API key
    we left it off because its terms forbid automation
    the gate refused the request

The first is a finding. The next four are coverage gaps of very different
severity. The last is a governance event that belongs in the audit log. A
product whose characteristic failure is an estate that looks smaller than it is
cannot afford to collapse them.

THREE FLAGS, NOT ONE
--------------------
`degraded` means something broke and re-running may help. `narrowed` means
nothing broke and coverage is smaller by choice. `refused` means the gate said
no. Folding UNCONFIGURED into `degraded` would leave every install without an
optional API key permanently degraded — and a flag that is always on is a flag
nobody reads.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set


class Outcome(str, enum.Enum):
    OK = "ok"                      # answered in full
    PARTIAL = "partial"            # answered, and told us it was cut off
    FAILED = "failed"              # tried, could not
    UNCONFIGURED = "unconfigured"  # needs a credential nobody supplied
    DISABLED = "disabled"          # left out by configuration or by its terms
    REFUSED = "refused"            # the gate said no — scope or exclusion


@dataclass
class SourceReport:
    """What one source did, in enough detail to argue with."""

    name: str
    outcome: Outcome = Outcome.OK
    #: Rows that survived filtering — the count that means something to a reader.
    contributed: int = 0
    #: Rows the source handed back, before containment. A shared-CDN certificate
    #: with 500 SANs of which 3 are in-apex reports returned=500, contributed=3.
    #: Without both numbers, moving containment into the shared merge silently
    #: changes what the single number meant.
    returned: int = 0
    detail: str = ""

    def __post_init__(self) -> None:
        # Coercion shim for callers written against the P0 boolean field.
        # REMOVE BY 2026-12-31 — an undated shim is a permanent one.
        if isinstance(self.outcome, bool):
            self.outcome = Outcome.OK if self.outcome else Outcome.FAILED
        elif not isinstance(self.outcome, Outcome):
            self.outcome = Outcome(str(self.outcome))
        if self.returned < self.contributed:
            # Not an error worth raising, but it means a caller filled one field
            # and forgot the other, and the ratio would read as nonsense.
            self.returned = self.contributed

    @property
    def ok(self) -> bool:
        """Answered in full. Preserves the P0 meaning of the boolean it replaced."""
        return self.outcome is Outcome.OK

    @property
    def answered(self) -> bool:
        """Gave us something. PARTIAL counts; it is data plus a stated limit."""
        return self.outcome in (Outcome.OK, Outcome.PARTIAL)

    @property
    def attempted(self) -> bool:
        """We actually reached out. Distinguishes a failure from an abstention."""
        return self.outcome in (Outcome.OK, Outcome.PARTIAL, Outcome.FAILED)

    def line(self) -> str:
        state = self.outcome.value.upper() if not self.ok else "ok"
        counts = f"{self.contributed}"
        if self.returned != self.contributed:
            counts = f"{self.contributed} of {self.returned}"
        return (f"{self.name:18} {state:13} {counts:>10}"
                + (f"  {self.detail}" if self.detail else ""))


@dataclass
class Coverage:
    """The reports for one run, and the honest summary of them."""

    reports: List[SourceReport] = field(default_factory=list)

    def add(self, report: SourceReport) -> SourceReport:
        self.reports.append(report)
        return report

    # -- the three flags ----------------------------------------------------
    @property
    def degraded(self) -> bool:
        """Something broke. Re-running may produce more."""
        return any(r.outcome in (Outcome.FAILED, Outcome.PARTIAL)
                   for r in self.reports)

    @property
    def narrowed(self) -> bool:
        """Nothing broke; coverage is smaller by choice."""
        return any(r.outcome in (Outcome.UNCONFIGURED, Outcome.DISABLED)
                   for r in self.reports)

    @property
    def refused(self) -> bool:
        """The gate said no. A governance event, not an outage."""
        return any(r.outcome is Outcome.REFUSED for r in self.reports)

    @property
    def answered(self) -> List[SourceReport]:
        return [r for r in self.reports if r.answered]

    @property
    def blackout(self) -> bool:
        """No source answered at all. The caller decides that this is fatal."""
        return not self.answered

    def note(self, found: int, unit: str = "name") -> str:
        """One paragraph an operator can act on.

        States the union rather than a sum. `contributed` must never be summed
        across sources — the same name found by three sources would be counted
        three times, and the inflated number is exactly the reassurance this
        product exists not to give.
        """
        answered = self.answered
        total = len(self.reports)
        parts = [f"{found} {unit}{'s' if found != 1 else ''} from "
                 f"{len(answered)} of {total} source{'s' if total != 1 else ''}"]

        if self.blackout:
            return ("No source answered. This is NOT an empty estate — it is no "
                    "evidence either way, and the two look identical.")

        broken = [r for r in self.reports
                  if r.outcome in (Outcome.FAILED, Outcome.PARTIAL)]
        if broken:
            # The wording matters and is deliberate: this estate MAY BE LARGER
            # than shown. A thin result from a degraded lookup looks exactly
            # like a small estate, and the second is far more comfortable to
            # believe — which is why the sentence says it outright rather than
            # leaving the reader to infer it from a status column.
            parts.append(
                f"{len(broken)} of {total} source(s) failed or was truncated: "
                + "; ".join(f"{r.name} {r.outcome.value}"
                            + (f" ({r.detail})" if r.detail else "")
                            for r in broken)
                + ". This estate may be larger than shown.")

        quiet = [r for r in self.reports
                 if r.outcome in (Outcome.UNCONFIGURED, Outcome.DISABLED)]
        if quiet:
            parts.append(
                "Narrower by choice: "
                + "; ".join(f"{r.name} {r.outcome.value}" for r in quiet)
                + ". Nothing failed; these were not consulted.")

        blocked = [r for r in self.reports if r.outcome is Outcome.REFUSED]
        if blocked:
            parts.append(
                "Refused by the gate: "
                + "; ".join(f"{r.name}"
                            + (f" ({r.detail})" if r.detail else "")
                            for r in blocked)
                + ". This is a scope decision, not a failure.")

        if not (broken or quiet or blocked):
            parts.append("Every source answered in full.")
        return " ".join(parts)


def overlap(per_source: Dict[str, Set[str]]) -> Dict[str, int]:
    """How many items only ONE source knew about.

    Computed after the merge from the full picture, so it does not depend on the
    order sources were consulted. Answers the question that decides whether a
    source is worth its terms and its rate limit.
    """
    unique: Dict[str, int] = {}
    for name, items in per_source.items():
        others: Set[str] = set()
        for other, values in per_source.items():
            if other != name:
                others |= values
        unique[name] = len(items - others)
    return unique


__all__ = ["Outcome", "SourceReport", "Coverage", "overlap"]
