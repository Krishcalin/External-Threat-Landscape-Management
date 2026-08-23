"""Collect what a supplier publishes, without touching them.

NO NEW EGRESS DOOR. Every lookup here goes through `collect/dns_records.sweep`,
which goes through `collect/egress.py`, which takes a permit. This module holds
no socket code and carries no `# NETWORK-BOUNDARY:` marker, because it performs
no I/O of its own — adding a second door for suppliers is exactly the drift
`core/gate.py` exists to prevent.

WHY A SUPPLIER DOMAIN IS NOT IN THE CUSTOMER'S SCOPE, AND WHAT IS DONE INSTEAD
------------------------------------------------------------------------------
Scope answers "which names are my attack surface". A supplier's domain is not:
it belongs to somebody else, and putting it in scope would quietly widen every
other collector's idea of what it may touch — including the active ones.

So supplier lookups take the same route CNAME-target resolution already takes
(`dns_records._target_scope`): a one-rule scope built per name, so the permit
STILL EXISTS, still names the asset, and still lands in the audit record. The
gate is not bypassed; it is asked a narrower question.

That is only defensible because every operation reachable from here is PASSIVE
and travels to a public recursive resolver rather than to the supplier. No
packet from this product reaches their infrastructure. The measurement in
`docs/P6-SCOPE.md` shows the gate refusing all four active operations against an
unverified third party, and nothing here can route around that.

WHY NOT SIMPLY ADD MX TO DEFAULT_RRTYPES
-----------------------------------------
The scope document said "one constant". On writing it, that turned out to be the
wrong constant: `DEFAULT_RRTYPES` drives the customer's own sweep across every
discovered name, so adding a type there spends 20% more of the rate budget on
every future run to serve a feature about somebody else's domains. `sweep()`
already accepts `rrtypes`, so the supplier collector passes its own set and the
customer's sweep is untouched.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from collect import dns_records
from collect.dns_wire import RRType
from collect.report import Outcome, SourceReport
from core.scope import Scope
from core.suppliers import Supplier

#: What a posture assessment asks for at the apex. Deliberately NOT
#: `DEFAULT_RRTYPES`: no A/AAAA, because an address tells a posture assessment
#: nothing it is allowed to act on, and every rrtype costs rate budget.
POSTURE_RRTYPES = (RRType.TXT, RRType.NS, RRType.MX, RRType.CAA)

#: Records that live at a derived name rather than the apex. Both are TXT.
DERIVED = {"_dmarc": "_dmarc", "_mta-sts": "_mta-sts"}


def derived_names(domain: str) -> Dict[str, str]:
    """`{key: fqdn}` for the records that are not at the apex."""
    base = str(domain).strip(".").lower()
    return {key: f"{prefix}.{base}" for key, prefix in DERIVED.items()}


def observe(suppliers: Sequence[Supplier], actor: str,
            resolvers: Optional[Sequence[str]] = None,
            budget=None, limiter=None) -> Dict[str, Any]:
    """Look up every declared supplier. Returns observations plus coverage.

    THE SHAPE OF THE RETURN IS LOAD-BEARING. `records` omits a key entirely when
    a lookup did not conclude, and includes it with an empty list when the
    lookup succeeded and found nothing. `core/suppliers.assess` reads exactly
    that distinction to separate "they have not configured this" from "we could
    not see" — collapsing them would turn our coverage gap into their finding.
    """
    observations: Dict[str, Dict[str, Any]] = {}
    reports: List[SourceReport] = []
    refused: List[Dict[str, str]] = []

    names: List[str] = []
    plan: Dict[str, List[tuple]] = {}
    for supplier in suppliers:
        domain = supplier.domain.strip(".").lower()
        names.append(domain)
        plan.setdefault(domain, []).append((domain, "apex"))
        for key, fqdn in derived_names(domain).items():
            names.append(fqdn)
            plan[domain].append((fqdn, key))

    kwargs: Dict[str, Any] = {"budget": budget, "limiter": limiter}
    if resolvers:
        kwargs["resolvers"] = tuple(resolvers)

    # permit_override: a supplier's domain will never be in the customer's own
    # scope, and the permit is taken per name against the PASSIVE recursive
    # operation. See the module docstring.
    sweep = dns_records.sweep(names, actor=actor, scope=Scope([]),
                              rrtypes=POSTURE_RRTYPES, permit_override=True,
                              **kwargs)

    concluded: Dict[tuple, List[str]] = {}
    for agreement in sweep.agreements:
        winning = agreement.winning
        if winning is None:
            # No quorum, or nothing conclusive. The key is left OUT so it reads
            # as unobserved rather than as an absent record.
            continue
        concluded[(agreement.name, agreement.rrtype)] = list(winning.values)

    for supplier in suppliers:
        domain = supplier.domain.strip(".").lower()
        records: Dict[str, List[str]] = {}
        for fqdn, role in plan[domain]:
            if role == "apex":
                for rrtype in POSTURE_RRTYPES:
                    values = concluded.get((fqdn, rrtype))
                    if values is not None:
                        records[rrtype.name] = values
            else:
                values = concluded.get((fqdn, RRType.TXT))
                if values is not None:
                    records[role] = values
        observations[domain] = {"records": records}

    for refusal in sweep.refusals:
        refused.append({"name": refusal.name, "reason": refusal.reason})

    reports.extend(sweep.reports)
    reports.append(SourceReport(
        "supplier_dns",
        Outcome.OK if sweep.observed == sweep.attempted else Outcome.PARTIAL,
        sweep.observed, sweep.attempted,
        f"{sweep.quorum_failed} disagreed, {sweep.unobserved} unobserved"))

    return {
        "observations": observations,
        "refused": refused,
        "reports": reports,
        "attempted": sweep.attempted,
        "observed": sweep.observed,
        # Stated rather than implied. A supplier assessment built on a sweep
        # that half failed is a different claim from one built on a clean sweep,
        # and nothing in the posture rows says which you are holding.
        "note": (
            f"{sweep.observed} of {sweep.attempted} (name, rrtype) lookups "
            f"reached quorum. Anything that did not is reported as UNOBSERVED "
            f"against that supplier, never as a record they have not configured."),
    }


__all__ = ["POSTURE_RRTYPES", "DERIVED", "derived_names", "observe"]
