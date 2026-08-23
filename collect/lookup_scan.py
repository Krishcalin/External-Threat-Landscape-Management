"""Collect what a typed target publishes. Passive, and structurally so.

NO NEW EGRESS DOOR, AND NO NEW EXPOSURE CLASS. Every lookup here routes through
`collect/dns_records.sweep` and `collect/ct.py`, both of which go through
`collect/egress.py` and take a permit. This module holds no socket code and
carries no `# NETWORK-BOUNDARY:` marker because it performs no I/O of its own.

WHY A TYPED TARGET CANNOT ESCALATE
-----------------------------------
The direction asked for a box you type any domain into. The obvious
implementation loosens scope, and that is exactly wrong: scope governs what the
ACTIVE collectors may touch, so widening it to serve a passive lookup would
widen port scanning and banner reads at the same time.

Instead this takes the route CNAME targets and supplier domains already take —
a one-rule scope built per name, so the permit still exists, still names the
asset, and still lands in the audit record. Every operation reachable from here
is PASSIVE and travels to a public resolver or a public log, never to the
target. The gate refuses all four active operations against an unverified asset
before scope is consulted, and nothing here can route around that.

WHAT AN ADDRESS YIELDS, WHICH IS LESS THAN A DOMAIN
----------------------------------------------------
No certificate transparency, no SPF, no DMARC — those are properties of a name.
What is left is the PTR record and whatever RDAP says about the allocation. Open
ports and running services need an active probe, which is refused, or a third
party who already scanned it, which needs a key. That is reported as an
unavailable source rather than omitted.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Sequence

from collect import dns_records, registry
from collect.dns_wire import RRType
from collect.report import Outcome, SourceReport
from collect.supplier_scan import POSTURE_RRTYPES, derived_names
from core import lookup as _lookup
from core.scope import Scope

#: The keyed sources a lookup would consult if it could. Reported as unavailable
#: when no key is configured, because a result that silently omits Shodan reads
#: as "no open ports".
KEYED = ("shodan", "virustotal")


def unavailable_sources(target: _lookup.Target) -> List[Dict[str, str]]:
    """What could not be consulted, and what each would have added.

    Built from `collect/registry.py`, so a source added there appears here
    automatically rather than needing somebody to remember this list.
    """
    out: List[Dict[str, str]] = []
    for name in KEYED:
        source = registry.BY_NAME.get(name)
        if source is None or source.configured:
            continue
        out.append({
            "source": name,
            "why": f"{source.credential_env} is not set",
            "cost": ("open ports and running services cannot be seen at all. "
                     "SKOPOS may not probe a target whose ownership is "
                     "unproven, so a third party who already scanned it is the "
                     "only passive route"
                     if name == "shodan" else
                     "no third-party reputation or detection history"),
            "terms": source.terms.value,
        })
    return out


def observe(target: _lookup.Target, actor: str,
            resolvers: Optional[Sequence[str]] = None,
            budget=None, limiter=None) -> Dict[str, Any]:
    """Everything passively available about one target."""
    if target.is_network:
        return _observe_network(target, actor, resolvers, budget, limiter)
    return _observe_name(target, actor, resolvers, budget, limiter)


def _sweep(names: Sequence[str], rrtypes, actor: str, resolvers, budget, limiter):
    kwargs: Dict[str, Any] = {"budget": budget, "limiter": limiter}
    if resolvers:
        kwargs["resolvers"] = tuple(resolvers)
    # permit_override: a name somebody typed will never be in the customer's own
    # scope, and the permit is taken per name against the PASSIVE recursive
    # operation. See the module docstring.
    return dns_records.sweep(list(names), actor=actor, scope=Scope([]),
                             rrtypes=rrtypes, permit_override=True, **kwargs)


def _concluded(sweep) -> Dict[tuple, List[str]]:
    """Only agreements that reached quorum. A lookup that did not conclude is
    left OUT of the mapping, so the reasoning layer reads it as UNOBSERVED
    rather than as an absent record."""
    out: Dict[tuple, List[str]] = {}
    for agreement in sweep.agreements:
        winning = agreement.winning
        if winning is not None:
            out[(agreement.name, agreement.rrtype)] = list(winning.values)
    return out


def _observe_name(target, actor, resolvers, budget, limiter) -> Dict[str, Any]:
    names = [target.value]
    for fqdn in derived_names(target.value).values():
        names.append(fqdn)

    sweep = _sweep(names, POSTURE_RRTYPES, actor, resolvers, budget, limiter)
    concluded = _concluded(sweep)

    records: Dict[str, List[str]] = {}
    for rrtype in POSTURE_RRTYPES:
        values = concluded.get((target.value, rrtype))
        if values is not None:
            records[rrtype.name] = values
    for key, fqdn in derived_names(target.value).items():
        values = concluded.get((fqdn, RRType.TXT))
        if values is not None:
            records[key] = values

    reports = list(sweep.reports)
    reports.append(SourceReport(
        "lookup_dns",
        Outcome.OK if sweep.observed == sweep.attempted else Outcome.PARTIAL,
        sweep.observed, sweep.attempted,
        f"{sweep.quorum_failed} disagreed, {sweep.unobserved} unobserved"))

    return {
        "records": records,
        "names": [],          # certificate transparency is layered in by the API
        "reverse_dns": {},
        "reports": reports,
        "refused": [{"name": r.name, "reason": r.reason} for r in sweep.refusals],
        "attempted": sweep.attempted,
        "observed": sweep.observed,
    }


def _observe_network(target, actor, resolvers, budget, limiter) -> Dict[str, Any]:
    """PTR for every address in the block.

    Bounded by `lookup.MAX_CIDR_HOSTS` at parse time, so this cannot be handed a
    /16 and quietly examine the first 256.
    """
    pointers = {}
    for address in target.addresses:
        try:
            pointers[ipaddress.ip_address(address).reverse_pointer] = address
        except ValueError:
            continue

    sweep = _sweep(list(pointers), (RRType.PTR,), actor, resolvers, budget,
                   limiter)
    concluded = _concluded(sweep)

    reverse: Dict[str, str] = {}
    for pointer, address in pointers.items():
        values = concluded.get((pointer, RRType.PTR))
        if values:
            reverse[address] = values[0]

    reports = list(sweep.reports)
    reports.append(SourceReport(
        "lookup_ptr",
        Outcome.OK if sweep.observed == sweep.attempted else Outcome.PARTIAL,
        len(reverse), len(pointers),
        f"{len(pointers) - len(reverse)} address(es) have no PTR record, which "
        f"is normal and is not evidence they are unused"))

    return {
        "records": {},        # a name's posture records do not exist for an IP
        "names": [],
        "reverse_dns": reverse,
        "reports": reports,
        "refused": [{"name": r.name, "reason": r.reason} for r in sweep.refusals],
        "attempted": sweep.attempted,
        "observed": sweep.observed,
    }


__all__ = ["observe", "unavailable_sources", "KEYED"]
