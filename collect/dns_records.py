"""Ask several resolvers what a name is, and record where they disagree.

AGREEMENT IS PER (name, rrtype), NOT PER NAME
---------------------------------------------
Measured across the default resolvers, `www.microsoft.com` returns three
disjoint address sets from 1.1.1.1, 8.8.8.8 and 9.9.9.9 — that is geo-balancing
working, not an anomaly. A name-level rollup would let that routine A-record
disagreement suppress a perfectly solid CNAME-based takeover finding, on
evidence from a record type the finding does not use.

QUORUM FAILURE IS NEVER SILENCE
-------------------------------
When no answer reaches quorum, the sweep emits an INDETERMINATE result carrying
the per-resolver digests, and counts it. Dropping it would exclude geo-balanced
names from the change list while still counting them observed, so
"observed 400/400, 0 changes" would read as a quiet night when in fact the
noisiest names were quietly discarded.

REFUSALS ARE FIRST-CLASS
------------------------
A name the gate refused is not a name that failed to resolve. Without the
distinction, adding an exclusion on Monday makes Tuesday's sweep report forty
records DISAPPEARED — "your DNS was deleted" — on a day when nothing changed.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from collect import egress
from collect.dns_wire import (DEFAULT_RRTYPES, Rcode, RRType, Response,
                              build_query, parse_response)
from collect.report import Coverage, Outcome, SourceReport
from core import gate
from core.scope import Decision, Scope, ScopeKind

#: Third-party recursive resolvers. Deliberately not the customer's — see the
#: reasoning on `dns_resolve_recursive` in core/gate.py.
DEFAULT_RESOLVERS: Tuple[str, ...] = egress.DEFAULT_RESOLVERS

OPERATION = "dns_resolve_recursive"

#: Two of three. One resolver can be poisoned, censored or simply wrong, and a
#: finding built on a single answer is a finding built on one party's word.
QUORUM = 2


@dataclass(frozen=True)
class Refusal:
    """The gate said no. Carried as a row, not a bare string."""

    name: str
    reason: str
    exception: str = ""


@dataclass
class Agreement:
    """What the resolvers said about one (name, rrtype)."""

    name: str
    rrtype: RRType
    responses: List[Response] = field(default_factory=list)

    @property
    def by_state(self) -> Dict[Tuple[str, str], List[Response]]:
        grouped: Dict[Tuple[str, str], List[Response]] = {}
        for response in self.responses:
            if response.conclusive:
                grouped.setdefault(response.state, []).append(response)
        return grouped

    @property
    def quorum_state(self) -> Optional[Tuple[str, str]]:
        grouped = self.by_state
        if not grouped:
            return None
        state, agreeing = max(grouped.items(), key=lambda kv: len(kv[1]))
        return state if len(agreeing) >= QUORUM else None

    @property
    def agreed(self) -> bool:
        return self.quorum_state is not None

    @property
    def winning(self) -> Optional[Response]:
        state = self.quorum_state
        if state is None:
            return None
        return self.by_state[state][0]

    @property
    def disagreement(self) -> str:
        return "; ".join(f"{r.resolver}={r.rcode.name}/{r.digest[:8]}"
                         for r in self.responses)


@dataclass
class DnsSweep:
    agreements: List[Agreement] = field(default_factory=list)
    refusals: List[Refusal] = field(default_factory=list)
    reports: List[SourceReport] = field(default_factory=list)
    resolvers: Tuple[str, ...] = DEFAULT_RESOLVERS

    @property
    def coverage(self) -> Coverage:
        return Coverage(list(self.reports))

    # Counters are per (name, rrtype) PAIR, stated explicitly — per-name
    # counting lets a name with five of six rrtypes failed report as fully
    # observed.
    @property
    def attempted(self) -> int:
        return len(self.agreements)

    @property
    def observed(self) -> int:
        return sum(1 for a in self.agreements if a.agreed)

    @property
    def quorum_failed(self) -> int:
        return sum(1 for a in self.agreements
                   if not a.agreed and any(r.conclusive for r in a.responses))

    @property
    def unobserved(self) -> int:
        return sum(1 for a in self.agreements
                   if not any(r.conclusive for r in a.responses))

    @property
    def degraded(self) -> bool:
        return bool(self.refusals) or self.unobserved > 0 or self.coverage.degraded

    def note(self) -> str:
        parts = [f"{self.observed} of {self.attempted} (name, rrtype) pair(s) "
                 f"observed across {len(self.resolvers)} resolver(s)"]
        if self.quorum_failed:
            parts.append(
                f"{self.quorum_failed} pair(s) had NO QUORUM — the resolvers "
                f"disagreed. Those are reported as indeterminate rather than "
                f"dropped, because a discarded disagreement makes a noisy name "
                f"look like a quiet one.")
        if self.unobserved:
            parts.append(f"{self.unobserved} pair(s) could not be resolved at "
                         f"all. That is our outage, not a change in their DNS.")
        if self.refusals:
            parts.append(f"{len(self.refusals)} name(s) were NOT LOOKED AT — "
                         f"the gate refused them. A deliberate instruction, not "
                         f"a failure and not a disappearance.")
        joined = ". ".join(p.rstrip(".") for p in parts)
        return joined + "."


def _target_scope(name: str) -> Scope:
    """A one-rule scope admitting exactly one CNAME target.

    Built per target rather than by skipping the gate, so the permit still
    exists, still names the asset, and still appears in an audit record. A
    collector that bypasses `authorise()` entirely is the thing core/gate.py is
    written to make impossible, and "except for this one case" is how that
    starts.
    """
    from core.scope import ScopeRule
    return Scope([ScopeRule(kind=ScopeKind.DOMAIN, value=name)])


def resolve_one(permit, name: str, rrtype: RRType, resolver: str,
                budget=None, limiter=None) -> Response:
    """One question to one resolver, through the egress choke point."""
    packet, txid = build_query(name, rrtype, recursion=True)
    try:
        data = egress.udp(permit, OPERATION, resolver, 53, packet,
                          budget=budget, limiter=limiter,
                          allowed=DEFAULT_RESOLVERS)
    except egress.PermitMismatch:
        raise
    except Exception as exc:                       # noqa: BLE001
        return Response(name=name, rrtype=rrtype, rcode=Rcode.SERVFAIL,
                        resolver=resolver, unreadable=True,
                        detail=(str(exc) or type(exc).__name__)[:80])
    return parse_response(data, name, rrtype, txid, resolver)


def sweep(names: Sequence[str], actor: str, scope: Scope,
          rrtypes: Sequence[RRType] = DEFAULT_RRTYPES,
          resolvers: Sequence[str] = DEFAULT_RESOLVERS,
          budget=None, limiter=None,
          permit_override: bool = False) -> DnsSweep:
    """Resolve every name across every resolver, refusing what scope refuses.

    `permit_override` is for resolving CNAME TARGETS, which are by definition
    somebody else's names and will never be in the customer's scope. It is still
    a PASSIVE recursive lookup through a third-party resolver — no packet
    reaches the target's own infrastructure — and it is the only way takeover
    assessment can establish whether a target resolves. The permit is taken
    against the resolver operation rather than against a name nobody declared.
    """
    limiter = limiter or egress.Limiter(budget or egress.Budget())
    result = DnsSweep(resolvers=tuple(resolvers))
    counts: Counter = Counter()

    for name in names:
        try:
            # kind=DOMAIN explicitly. Without it a repo_org rule valued the same
            # string would authorise DNS resolution.
            permit = gate.authorise(name, OPERATION, actor,
                                    _target_scope(name) if permit_override
                                    else scope,
                                    kind=ScopeKind.DOMAIN)
        except (gate.NotInScope, gate.OperationRefused) as exc:
            result.refusals.append(Refusal(name, str(exc), type(exc).__name__))
            counts["refused"] += 1
            continue

        for rrtype in rrtypes:
            agreement = Agreement(name=name, rrtype=rrtype)
            for resolver in resolvers:
                try:
                    agreement.responses.append(
                        resolve_one(permit, name, rrtype, resolver,
                                    budget, limiter))
                except egress.BudgetExhausted as exc:
                    result.reports.append(SourceReport(
                        "budget", Outcome.PARTIAL, result.observed,
                        len(names) * len(rrtypes), str(exc)[:100]))
                    return result
            result.agreements.append(agreement)
            counts["observed" if agreement.agreed else "unresolved"] += 1

    for resolver in resolvers:
        answered = sum(1 for a in result.agreements
                       for r in a.responses
                       if r.resolver == resolver and r.conclusive)
        total = len(result.agreements)
        result.reports.append(SourceReport(
            resolver,
            Outcome.OK if answered == total else
            (Outcome.PARTIAL if answered else Outcome.FAILED),
            answered, total,
            "" if answered == total else f"answered {answered} of {total}"))
    if result.refusals:
        result.reports.append(SourceReport(
            "scope", Outcome.REFUSED, 0, len(result.refusals),
            f"{len(result.refusals)} name(s) refused by the gate"))
    return result


__all__ = ["DEFAULT_RESOLVERS", "OPERATION", "QUORUM", "Refusal", "Agreement",
           "DnsSweep", "resolve_one", "sweep"]
