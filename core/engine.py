"""Composition: inventory + cloud context + intelligence -> scored findings.

This is the only place the pieces meet, and it is deliberately thin. `match`
decides what corresponds, `affected` decides whether a version is in range,
`scoring` decides what it is worth, and `overwatch` supplies what the outside
cannot see. Each of those is testable alone; this assembles them and adds no
judgement of its own beyond how evidence maps onto TEPS factors — which is
written out below rather than buried.

HOW EVIDENCE BECOMES A SCORE
----------------------------
Every TEPS input is derived from something observed, and where nothing was
observed the input is not invented — it takes a stated default and the finding
carries a flag saying so. The mapping:

    reachability          confirmed by BOTH methods -> 1.0
                          one method only           -> 0.6
                          neither                   -> 0.2
    service_sensitivity   from the ports the cloud model reports open
    auth_exposure         unknown from outside; 0.7 unless evidence says else
    shadow                asset absent from the declared inventory
    exposure_age          days since first seen
    mitigation            CloudFront/ALB/WAF in front, per §9.1

`auth_exposure` is the weakest of these and is marked as such: SKOPOS cannot see
whether a login page enforces MFA, so it assumes the middle value rather than the
best or worst. Assuming the worst would inflate every score in the product;
assuming the best would hide the findings it exists to surface.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from core import scoring
from core.affected import Verdict, evaluate
from core.models import Asset, Confidence, Exploited, Exposure, MatchBasis
from core.overwatch import (CloudAsset, InternalReachability, Reconciliation,
                            reconcile)

#: Ports whose exposure raises `service_sensitivity`. Mirrors the sensitive-port
#: set OverWatch's exposure oracle already uses, so the two tools agree about
#: which services are dangerous to publish.
SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 21: "FTP", 3389: "RDP", 445: "SMB", 135: "RPC",
    139: "NetBIOS", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
    1521: "Oracle", 27017: "MongoDB", 6379: "Redis", 11211: "Memcached",
    9200: "Elasticsearch", 5984: "CouchDB", 502: "Modbus", 20000: "DNP3",
    102: "S7comm", 47808: "BACnet", 44818: "EtherNet/IP",
}

#: SKOPOS cannot see authentication strength from outside. The middle value is
#: taken deliberately — see the module docstring.
ASSUMED_AUTH_EXPOSURE = 0.7


@dataclass
class Finding:
    """One scored exposure, carrying everything needed to justify it."""

    asset: Asset
    exploited: Exploited
    basis: MatchBasis
    confidence: Confidence
    match_confidence: str
    score: scoring.Score
    evidence: List[str] = field(default_factory=list)
    cloud: Optional[Dict[str, Any]] = None
    reconciliation: Optional[Reconciliation] = None

    @property
    def cve(self) -> str:
        return self.exploited.cve

    def to_dict(self) -> Dict[str, Any]:
        s = self.score
        return {
            "asset": self.asset.identifier,
            "product": self.asset.product,
            "version": self.asset.version,
            "owner": self.asset.owner,
            "environment": self.asset.environment,
            "cve": self.exploited.cve,
            "vulnerability": self.exploited.name,
            "known_ransomware": self.exploited.known_ransomware,
            "due_date": str(self.exploited.due_date) if self.exploited.due_date else None,
            "epss": self.exploited.epss,
            "required_action": self.exploited.required_action,
            "teps": s.teps,
            "band": s.band,
            "factors": s.contributions(),
            "factor_values": {
                "exposure": round(s.exposure, 4),
                "exploitability": round(s.exploitability, 4),
                "adversary_interest": round(s.adversary, 4),
                "business_criticality": round(s.business, 4),
                "mitigation": round(s.mitigation, 4),
            },
            "flags": s.flags,
            "model_version": s.model_version,
            "basis": self.basis.value,
            "match_confidence": self.match_confidence,
            "name_confidence": self.confidence.value,
            "evidence": self.evidence,
            "cloud": self.cloud,
            "reconciliation": self.reconciliation.value if self.reconciliation else None,
        }


def _match_confidence(basis: MatchBasis, verdict: Optional[Verdict]) -> str:
    """FR-M2-010's three-value confidence, derived rather than asserted.

    `confirmed` is reserved for a version actually compared against a published
    affected range. A product-name correspondence is `possible` however strongly
    the names agree, because agreeing names are not an affected version.
    """
    if verdict is Verdict.AFFECTED and basis is MatchBasis.VERSION_RANGE:
        return "confirmed"
    if verdict is Verdict.UNKNOWN:
        return "possible"
    return "probable" if basis is MatchBasis.VERSION_RANGE else "possible"


def build_exposure_factors(asset: Asset,
                           cloud: Optional[CloudAsset],
                           external_reachable: Optional[bool],
                           days_exposed: int,
                           shadow: bool) -> Tuple[scoring.Exposure, List[str]]:
    """TEPS `E`, and the evidence for each part of it."""
    notes: List[str] = []

    internal = (cloud.context.internal_reachability if cloud
                else InternalReachability.UNKNOWN)
    both = external_reachable is True and internal is InternalReachability.REACHABLE
    either = external_reachable is True or internal is InternalReachability.REACHABLE
    if both:
        reachability = 1.0
        notes.append("reachability confirmed by both external probe and cloud model")
    elif either:
        reachability = 0.6
        notes.append("reachability observed by one method only")
    else:
        reachability = 0.2
        notes.append("no positive reachability evidence")

    ports = cloud.context.exposed_ports if cloud else ()
    hits = [SENSITIVE_PORTS[p] for p in ports if p in SENSITIVE_PORTS]
    if hits:
        sensitivity = 1.0
        notes.append(f"sensitive service(s) exposed: {', '.join(sorted(set(hits)))}")
    elif ports:
        sensitivity = 0.4
        notes.append(f"{len(ports)} port(s) open, none on the sensitive list")
    else:
        sensitivity = 0.4
        notes.append("no port data; assumed a public web surface")

    notes.append("authentication strength is not observable from outside; "
                 f"assumed {ASSUMED_AUTH_EXPOSURE}")

    return scoring.Exposure(
        reachability=reachability,
        service_sensitivity=sensitivity,
        auth_exposure=ASSUMED_AUTH_EXPOSURE,
        shadow=shadow,
        days_exposed=days_exposed,
    ), notes


def score_exposure(exposure: Exposure,
                   cloud: Optional[CloudAsset] = None,
                   external_reachable: Optional[bool] = None,
                   affected_versions: Optional[Sequence[Dict[str, Any]]] = None,
                   adversary: Optional[scoring.AdversaryInterest] = None,
                   asset_tier: Optional[int] = None,
                   days_exposed: int = 0,
                   shadow: bool = False) -> Finding:
    """One correspondence, scored."""
    asset = exposure.asset
    entry = exposure.exploited

    verdict: Optional[Verdict] = None
    basis = exposure.basis
    evidence = list(exposure.evidence)
    if affected_versions:
        verdict = evaluate(asset.version, affected_versions)
        if verdict is Verdict.NOT_AFFECTED:
            # A published range says this version is not affected. That is a
            # determination and it retires the finding rather than lowering it.
            basis = MatchBasis.VERSION_RANGE
        elif verdict is Verdict.AFFECTED:
            basis = MatchBasis.VERSION_RANGE
            evidence.append(f"version {asset.version} falls in a published "
                            f"affected range for {entry.cve}")
        else:
            evidence.append("published affected ranges could not be compared "
                            "against this version")

    exposure_factors, notes = build_exposure_factors(
        asset, cloud, external_reachable, days_exposed, shadow)
    evidence.extend(notes)

    mitigation = cloud.context.mitigation if cloud else 0.0
    if mitigation:
        evidence.append(f"fronted by {', '.join(cloud.context.fronted_by)} "
                        f"— §9.1 mitigation {mitigation:.0%}")

    match_conf = _match_confidence(basis, verdict)
    result = scoring.score(
        exposure=exposure_factors,
        exploitability=scoring.Exploitability(
            in_kev=True,                    # every catalogue entry is KEV
            epss=entry.epss or 0.0,
        ),
        adversary=adversary or scoring.AdversaryInterest(),
        asset_tier=asset_tier,
        mitigation=mitigation,
        match_confidence=match_conf,
    )

    cloud_dict = None
    reconciliation = None
    if cloud:
        ctx = cloud.context
        reconciliation = reconcile(external_reachable, ctx.internal_reachability)
        cloud_dict = {
            "resource_id": ctx.resource_id,
            "kind": ctx.kind,
            "account": ctx.account,
            "region": ctx.region,
            "internal_reachability": ctx.internal_reachability.value,
            "exposed_ports": list(ctx.exposed_ports),
            "fronted_by": list(ctx.fronted_by),
        }

    return Finding(asset=asset, exploited=entry, basis=basis,
                   confidence=exposure.confidence, match_confidence=match_conf,
                   score=result, evidence=evidence, cloud=cloud_dict,
                   reconciliation=reconciliation)


def rank(findings: Iterable[Finding]) -> List[Finding]:
    """TEPS descending, then ransomware, then CVE for a stable order.

    A stable tiebreak matters more than it looks: without it the same scan
    renders in a different order each run and a reader cannot tell whether
    anything actually changed.
    """
    return sorted(findings,
                  key=lambda f: (-f.score.teps,
                                 0 if f.exploited.known_ransomware else 1,
                                 f.exploited.cve))


def summarise(findings: Sequence[Finding],
              unmatched: int = 0,
              unmappable: int = 0) -> Dict[str, Any]:
    """The posture roll-up the console leads with."""
    bands: Dict[str, int] = {}
    for f in findings:
        bands[f.score.band] = bands.get(f.score.band, 0) + 1
    recon: Dict[str, int] = {}
    for f in findings:
        if f.reconciliation:
            recon[f.reconciliation.value] = recon.get(f.reconciliation.value, 0) + 1
    return {
        "findings": len(findings),
        "assets_affected": len({f.asset.identifier for f in findings}),
        "bands": bands,
        "ransomware_linked": sum(1 for f in findings if f.exploited.known_ransomware),
        "determinations": sum(1 for f in findings if f.match_confidence == "confirmed"),
        "worklist": sum(1 for f in findings if f.match_confidence != "confirmed"),
        "reconciliation": recon,
        # The two honesty counters. A console that shows findings without these
        # reads as a complete picture when it may be a partial one.
        "assets_matched_nothing": unmatched,
        "cloud_resources_unmappable": unmappable,
    }
