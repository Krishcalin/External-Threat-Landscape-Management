"""What changed since the last time we could actually see it.

THE FIRST RUN IS A NAMED BASELINE
---------------------------------
Both obvious answers misrepresent what happened. Reporting every name as new
makes run one the noisiest report the customer will ever receive, on a day when
none of it is actionable — which trains them to dismiss the feed before the
first true change arrives. Reporting nothing is indistinguishable from a failed
run. So the first observation of a name is `FIRST_OBSERVED`, the comparison is
labelled `BASELINE`, and the headline counts what was actually established.

DIFF AGAINST THE LAST CONCLUSIVE OBSERVATION, NOT THE LAST RUN
--------------------------------------------------------------
A run may be partial. Run-to-run comparison breaks the first time one is, and
the breakage looks exactly like change. Comparing against the last conclusive
observation also yields the more useful sentence: "changed since 14 August, the
last time we could see it" — which is why every change carries
`previous_observed_at` and `gap_days`.

"WE COULD NOT LOOK" AND "WE WERE TOLD NOT TO" ARE DIFFERENT
------------------------------------------------------------
`UNOBSERVED` is our outage. `NOT_LOOKED_AT` is the operator's exclusion. Without
the second, adding an exclusion on Monday makes Tuesday's sweep report forty
names DISAPPEARED — "your DNS records were deleted" — on a day when nothing
changed at all.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional, Sequence, Tuple


class ChangeKind(str, enum.Enum):
    FIRST_OBSERVED = "first_observed"   # our coverage grew
    APPEARED = "appeared"               # already watched; now resolves
    DISAPPEARED = "disappeared"         # conclusively gone
    MODIFIED = "modified"               # the record set changed
    INDETERMINATE = "indeterminate"     # resolvers disagreed; no quorum
    UNOBSERVED = "unobserved"           # WE could not look — our outage
    NOT_LOOKED_AT = "not_looked_at"     # the GATE refused it — deliberate


CHANGE_MEANING: Dict[str, str] = {
    ChangeKind.FIRST_OBSERVED.value:
        "the first time this product could see this name — our coverage grew, "
        "which is not the same as the record being new",
    ChangeKind.APPEARED.value:
        "a name we were already watching now resolves where it previously did not",
    ChangeKind.DISAPPEARED.value:
        "conclusively gone: a resolver answered, and answered that it no longer "
        "exists",
    ChangeKind.MODIFIED.value:
        "the record set changed. TTL is excluded from the comparison, so this is "
        "a real change and not a counter ticking down",
    ChangeKind.INDETERMINATE.value:
        "the resolvers disagreed and none reached quorum. Reported rather than "
        "dropped: a discarded disagreement makes a noisy name look like a quiet "
        "one",
    ChangeKind.UNOBSERVED.value:
        "WE could not look. Our outage, not a change in their DNS — and it never "
        "supersedes what we last saw",
    ChangeKind.NOT_LOOKED_AT.value:
        "the gate refused it, because somebody excluded it on purpose. Not a "
        "failure, and emphatically not a disappearance",
}


class Comparison(str, enum.Enum):
    BASELINE = "baseline"
    AGAINST_LAST_CONCLUSIVE = "against_last_conclusive"


@dataclass(frozen=True)
class Observation:
    """One stored, conclusive sighting of one (name, rrtype)."""

    name: str
    rrtype: str
    rcode: str
    digest: str
    values: Tuple[str, ...] = ()
    observed_at: Optional[date] = None

    @property
    def state(self) -> Tuple[str, str]:
        return (self.rcode, self.digest)

    @property
    def exists(self) -> bool:
        """Did the name resolve to anything?"""
        return self.rcode == "NOERROR" and bool(self.values)


@dataclass
class NameChange:
    name: str
    rrtype: str
    kind: ChangeKind
    before: Optional[Observation] = None
    after: Optional[Observation] = None
    detail: str = ""
    previous_observed_at: Optional[date] = None
    gap_days: Optional[int] = None

    def explain(self) -> str:
        base = f"{self.name} {self.rrtype}: {CHANGE_MEANING[self.kind.value]}"
        if self.previous_observed_at:
            base += (f" (last seen {self.previous_observed_at}"
                     + (f", {self.gap_days} day(s) ago)" if self.gap_days
                        is not None else ")"))
        return base + (f" — {self.detail}" if self.detail else "")


@dataclass
class ChangeReport:
    comparison: Comparison
    changes: List[NameChange] = field(default_factory=list)
    #: Pairs baselined on this run. The number the headline is built from.
    established: int = 0
    attempted: int = 0
    quorum_failed: int = 0
    unobserved: int = 0
    not_looked_at: int = 0
    resolver_note: str = ""

    def of_kind(self, kind: ChangeKind) -> List[NameChange]:
        return [c for c in self.changes if c.kind is kind]

    def headline(self) -> str:
        """Built from `established`, never from `attempted`.

        A baseline sentence asserting 412 first observations when 32 actually
        succeeded is a false claim about coverage, and coverage is the thing
        this product is for.
        """
        if self.comparison is Comparison.BASELINE:
            line = (f"First observation of {self.established} of "
                    f"{self.attempted} (name, rrtype) pair(s).")
            missing = self.attempted - self.established
            if missing > 0:
                line += (f" {missing} could not be resolved"
                         + (f" ({self.resolver_note})" if self.resolver_note else "")
                         + " and are NOT baselined — they will baseline on the "
                           "first run that can see them.")
            return line

        real = [c for c in self.changes
                if c.kind in (ChangeKind.APPEARED, ChangeKind.DISAPPEARED,
                              ChangeKind.MODIFIED)]
        line = (f"{len(real)} change(s) across {self.attempted} "
                f"(name, rrtype) pair(s).")
        if self.quorum_failed:
            line += f" {self.quorum_failed} indeterminate (resolvers disagreed)."
        if self.unobserved:
            line += (f" {self.unobserved} could not be observed — our outage, "
                     f"not their change.")
        if self.not_looked_at:
            line += (f" {self.not_looked_at} were not looked at because the "
                     f"gate refused them.")
        return line


def diff(sweep, previous: Dict[Tuple[str, str], Observation],
         today: Optional[date] = None) -> ChangeReport:
    """Compare a sweep against the last CONCLUSIVE observations.

    `previous` is keyed `(name, rrtype)`. An empty mapping means baseline.
    """
    from collect.dns_records import Refusal   # local: avoids a cycle

    now = today or date.today()
    baseline = not previous
    report = ChangeReport(
        comparison=Comparison.BASELINE if baseline
        else Comparison.AGAINST_LAST_CONCLUSIVE,
        attempted=len(sweep.agreements))

    for agreement in sweep.agreements:
        key = (agreement.name, agreement.rrtype.name)
        prior = previous.get(key)

        if not agreement.agreed:
            conclusive_any = any(r.conclusive for r in agreement.responses)
            if conclusive_any:
                report.quorum_failed += 1
                report.changes.append(NameChange(
                    agreement.name, agreement.rrtype.name,
                    ChangeKind.INDETERMINATE, before=prior,
                    detail=agreement.disagreement))
            else:
                report.unobserved += 1
                report.changes.append(NameChange(
                    agreement.name, agreement.rrtype.name,
                    ChangeKind.UNOBSERVED, before=prior,
                    detail=agreement.disagreement))
            # Deliberately does NOT supersede `prior`. A resolver outage must
            # never read as the customer's DNS being deleted overnight.
            continue

        winning = agreement.winning
        after = Observation(name=agreement.name, rrtype=agreement.rrtype.name,
                            rcode=winning.rcode.name, digest=winning.digest,
                            values=tuple(winning.values), observed_at=now)

        if prior is None:
            report.established += 1
            report.changes.append(NameChange(
                agreement.name, agreement.rrtype.name,
                ChangeKind.FIRST_OBSERVED, after=after))
            continue

        report.established += 1
        if prior.state == after.state:
            continue

        gap = ((now - prior.observed_at).days
               if prior.observed_at is not None else None)
        if not prior.exists and after.exists:
            kind = ChangeKind.APPEARED
        elif prior.exists and not after.exists:
            kind = ChangeKind.DISAPPEARED
        else:
            kind = ChangeKind.MODIFIED
        report.changes.append(NameChange(
            agreement.name, agreement.rrtype.name, kind,
            before=prior, after=after,
            previous_observed_at=prior.observed_at, gap_days=gap,
            detail=f"{prior.rcode}/{list(prior.values)[:3]} -> "
                   f"{after.rcode}/{list(after.values)[:3]}"))

    for refusal in getattr(sweep, "refusals", []):
        report.not_looked_at += 1
        report.changes.append(NameChange(
            refusal.name, "*", ChangeKind.NOT_LOOKED_AT, detail=refusal.reason))

    failed = [r for r in getattr(sweep, "reports", []) if not r.ok]
    if failed:
        report.resolver_note = f"{len(failed)} resolver report(s) not OK"
    return report


def supersede(previous: Dict[Tuple[str, str], Observation],
              report: ChangeReport) -> Dict[Tuple[str, str], Observation]:
    """The new stored state. ONLY conclusive observations replace anything."""
    updated = dict(previous)
    for change in report.changes:
        if change.after is not None:
            updated[(change.name, change.rrtype)] = change.after
    return updated


__all__ = ["ChangeKind", "CHANGE_MEANING", "Comparison", "Observation",
           "NameChange", "ChangeReport", "diff", "supersede"]
