"""Run the enabled sources under permits, and report honestly about all of it.

THE ONLY PLACE `authorise()` IS CALLED FOR DISCOVERY. Eight source modules each
asking the gate for themselves is the pattern `core/gate.py` exists to reject:
it holds for exactly the sources that remembered, and a plugin author who
forgets produces a module that works and simply collects things it should not.

THE REFUSAL TAXONOMY, WHICH IS NOT THE SAME AS DEGRADATION
----------------------------------------------------------
Three causes, three behaviours, and conflating them hands the operator the wrong
remedy:

  OperationRefused        a BUILD ERROR — an unregistered or prohibited
                          operation. Propagates uncaught, exits 3. A developer
                          who forgets gate.OPERATIONS must not get a one-line
                          footnote next to "you didn't set an API key"; that
                          inverts classify()'s promise to fail loudly on the
                          first run.
  NotInScope on the apex  propagates, exits 3. "You never declared this domain"
                          is not "a source was down".
  NotInScope on one name  degrades that item to REFUSED and the run continues.
                          One name of many being out of scope is a normal,
                          reportable fact.

BLACKOUT RAISES, BUT THE AUDIT IS WRITTEN FIRST
-----------------------------------------------
`run_sources()` always RETURNS the result; the caller audits and then raises.
The run where every source failed is precisely the run where "who did we
contact, and what did they say" is the entire question, so it must not be the
one run with no per-source record.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from collect import egress, names as name_sources
from collect.ct import from_certspotter, from_crtsh
from collect.discovery import DiscoveryResult, NameObservation, merge
from collect.registry import BY_NAME, Source, enabled, unknown_names
from collect.report import Outcome, SourceReport
from core import gate
from core.scope import Decision, Scope, ScopeKind


class DiscoveryUnavailable(RuntimeError):
    """No source answered. Not an empty estate — no evidence either way."""


FETCHERS = dict(name_sources.FETCHERS)
FETCHERS["certspotter"] = from_certspotter
FETCHERS["crt.sh"] = from_crtsh


def authorise_apex(apex: str, actor: str, scope: Scope,
                   sources: Sequence[Source]) -> Dict[str, gate.Permit]:
    """One permit per distinct operation, before anything is contacted.

    The apex is resolved with `kind=DOMAIN` explicitly. Without it a `repo_org`
    rule valued `example.com` resolves INCLUDED for the DNS name — a GitHub-org
    rule authorising DNS discovery.
    """
    permits: Dict[str, gate.Permit] = {}
    for source in sources:
        if source.operation not in permits:
            permits[source.operation] = gate.authorise(
                apex, source.operation, actor, scope, kind=ScopeKind.DOMAIN)
    return permits


def run_sources(apex: str, actor: str, scope: Scope,
                requested: Optional[Sequence[str]] = None,
                allow_noncommercial: bool = False,
                budget=None, limiter=None) -> DiscoveryResult:
    """Query every enabled source. Always returns; never raises on degradation."""
    apex = str(apex).strip().lower().rstrip(".")
    if not apex:
        raise ValueError("an apex domain is required")

    if requested:
        unknown = unknown_names(requested)
        if unknown:
            # A misspelled --source that silently narrowed the run to nothing
            # would be the exact failure this module exists to prevent.
            raise ValueError(
                f"unknown source(s): {', '.join(unknown)}. "
                f"Registered: {', '.join(sorted(BY_NAME))}")

    chosen, prereports = enabled(requested, allow_noncommercial)
    permits = authorise_apex(apex, actor, scope, chosen)

    limiter = limiter or egress.Limiter(budget or egress.Budget())
    observations: List[NameObservation] = []
    # Prereports FIRST, and carried through. Dropping them makes `narrowed`
    # structurally dead for the two states it was invented for, and an install
    # querying 5 of 7 registered sources reports as fully covered.
    reports: List[SourceReport] = list(prereports)

    for source in chosen:
        fetch = FETCHERS.get(source.name)
        if fetch is None:
            reports.append(SourceReport(source.name, Outcome.FAILED, 0, 0,
                                        "registered but not implemented"))
            continue
        try:
            rows, report = fetch(apex, permits[source.operation], budget, limiter)
        except egress.BudgetExhausted as exc:
            reports.append(SourceReport(source.name, Outcome.PARTIAL, 0, 0,
                                        str(exc)[:100]))
            continue

        # CT sources return (name, date) tuples; the newer ones return
        # NameObservations. Normalise here rather than rewriting ct.py's shape,
        # which several tests depend on.
        for row in rows:
            if isinstance(row, NameObservation):
                observations.append(row)
            else:
                name, seen = row
                observations.append(NameObservation(
                    name=name, source=source.name, data_class=source.data_class,
                    first_seen=seen))
        reports.append(report)

    merged, excluded = merge(observations, apex, scope)
    return DiscoveryResult(names=merged, sources=reports, excluded=excluded,
                           apex=apex)


def plan(apex: str, actor: str, scope: Scope,
         requested: Optional[Sequence[str]] = None,
         allow_noncommercial: bool = False) -> Dict[str, object]:
    """What a run would do, contacting nothing.

    Resolves scope and asks the gate — so an unscoped apex is refused here, in a
    preview, rather than after the operator has waited for a run.
    """
    chosen, prereports = enabled(requested, allow_noncommercial)
    permits = authorise_apex(apex, actor, scope, chosen)
    return {
        "apex": apex,
        "sources": [s.name for s in chosen],
        "operations": sorted(permits),
        "not_querying": [(r.name, r.outcome.value, r.detail) for r in prereports],
        "rationale": next(iter(permits.values())).rationale if permits else "",
    }


__all__ = ["DiscoveryUnavailable", "run_sources", "plan", "authorise_apex",
           "FETCHERS"]
