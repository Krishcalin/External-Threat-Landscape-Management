"""The refusals, structured — so the console and the STIX bundle carry them too.

`docs/REFUSALS.md` is the long form for a human reading the repository. This is
the same list as data, because a refusal recorded only in a markdown file is a
refusal nobody encounters at the moment they need it: on screen, comparing this
product to one that sells the capability, or in a bundle handed to a consumer
who will otherwise assume the absence is an oversight.

A REFUSAL IS NOT A GAP, and the distinction is carried in the type. A gap is
something not yet built. A refusal is something built far enough to measure,
measured, and then declined — or something a rule forbids. `GAPS` at the bottom
holds the other kind, so the two are never confused by being listed together.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence


class Ground(str, enum.Enum):
    """Why the refusal stands. The distinction matters to a reader deciding
    whether it might change."""

    #: Built, measured, and the measurement killed it. Could reopen only if the
    #: measurement changed.
    MEASURED = "measured"
    #: A governance rule forbids it. Will not change without that rule changing.
    GOVERNANCE = "governance"
    #: The experiment that would establish it is one this product will not run.
    CAPABILITY = "capability"
    #: The claim belongs to somebody else — a government, a regulator, a person.
    AUTHORITY = "authority"
    #: Presenting it would mislead, regardless of whether it could be computed.
    HONESTY = "honesty"


@dataclass(frozen=True)
class Refusal:
    id: str
    title: str
    ground: Ground
    #: What a competitor sells here. Named so the reader knows this was
    #: considered rather than overlooked.
    sold_elsewhere: str
    #: The measurement or rule that produced the refusal. This is the field
    #: that makes the entry worth reading.
    because: str
    recorded_in: str

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "title": self.title, "ground": self.ground.value,
                "sold_elsewhere": self.sold_elsewhere, "because": self.because,
                "recorded_in": self.recorded_in}


REFUSALS: Sequence[Refusal] = (
    Refusal(
        "actor_attribution", "Threat actor attribution", Ground.MEASURED,
        "Recorded Future tracks 4,000+ actor organisations and 430 nation-state "
        "groups; most platforms in this category answer 'who is targeting you'.",
        "Built far enough to measure in P3: 0 CVE references in ATT&CK "
        "external_references, and resolving technique to group implicates a "
        "MEDIAN OF 57 GROUPS per CVE, up to 139 of 191. An attribution naming "
        "57 groups is a list of everybody. SSVC shipped in its place because it "
        "is a stated judgement with a named author.",
        "docs/P3-SCOPE.md"),
    Refusal(
        "risk_score", "A single 0-99 risk score", Ground.HONESTY,
        "Recorded Future produces a 0-99 score from 40+ risk rules, banded into "
        "three words.",
        "The number is what survives into a board deck, and by then nobody can "
        "say which of the forty rules produced it. TEPS stays decomposed into "
        "four factors and core/rules.py publishes all 39 checks individually "
        "with per-rule evidence — the same information without the collapse.",
        "core/rules.py"),
    Refusal(
        "dark_web", "Dark web forum and market collection", Ground.GOVERNANCE,
        "Hundreds of Tor sites, IRC channels, forums, shops, markets and paste "
        "sites, with deep NLP in 12 languages.",
        "FR-GOV-003 prohibits authenticating to, transacting on, or scraping "
        "access-controlled criminal forums. It permits public index pages, so "
        "SKOPOS takes ransomware leak-site indexes and stops there. What "
        "remains uncovered — credential markets, broker listings, forum chatter "
        "— is a real gap that is not going to close.",
        "collect/leaksites.py"),
    Refusal(
        "control_validation", "Validating that an exposure is exploitable",
        Ground.GOVERNANCE,
        "Adversarial Exposure Validation platforms — Filigran's OpenAEV, "
        "Pentera, Cymulate, Picus — execute real payloads against real "
        "endpoints and report whether your controls caught them. Gartner "
        "merged breach-and-attack simulation and automated pentesting into "
        "this category in 2025.",
        "core/gate.py classifies `exploit_attempt` and `credential_replay` as "
        "PROHIBITED unconditionally under FR-GOV-007, before scope or "
        "ownership are consulted. SKOPOS establishes that an asset runs a "
        "product with an exploited vulnerability; it does not and will not "
        "establish that an attack would succeed. USE OPENAEV FOR THIS — it is "
        "open source, Apache 2.0, and covers the CTEM validation stage SKOPOS "
        "deliberately does not. `/api/v1/export/validation-targets` produces "
        "the asset list to point it at.",
        "core/gate.py"),
    Refusal(
        "takeover_confirmation", "Confirming a subdomain takeover",
        Ground.CAPABILITY,
        "Scanners routinely report a dangling record as 'vulnerable to "
        "takeover'.",
        "The only experiment that would establish claimability is REGISTERING "
        "THE RESOURCE, an act against a third party's namespace. FR-GOV-007 "
        "prohibits offensive capability. The strongest passive statement is "
        "registrable_domain_unregistered, and the reason given on screen is "
        "capability rather than caution.",
        "core/takeover.py"),
    Refusal(
        "regulatory_clock", "Starting a CERT-In six-hour clock from a finding",
        Ground.AUTHORITY,
        "Compliance tools commonly open a countdown on detection.",
        "Measured: 1 OF 8 CERT-In Annexure I categories is observable from "
        "outside an estate. Seven describe something an adversary did. The only "
        "clock constructor takes a Declaration requiring a named person and a "
        "timezone-aware time of awareness — the determination that an incident "
        "occurred is the reporter's.",
        "docs/P4-SCOPE.md"),
    Refusal(
        "cii_designation", "Declaring an asset critical infrastructure",
        Ground.AUTHORITY,
        "Vendors infer criticality from hostnames and asset tags.",
        "Under s.70 of the IT Act, 2000 the appropriate Government declares a "
        "protected system BY NOTIFICATION IN THE OFFICIAL GAZETTE. That is a "
        "legal status, not something inferable. The register records what the "
        "organisation stated, and refuses a gazette basis with no notification "
        "reference.",
        "core/cii.py"),
    Refusal(
        "coverage_percentage", "A compliance coverage percentage",
        Ground.HONESTY,
        "Almost every GRC product shows a percentage against a framework.",
        "It would be summed, shown to a board, and the board would be receiving "
        "a number no external scanner has the basis to produce. The mapping "
        "states contribution, non-contribution and evidence instead, with no "
        "percentage in any field or sentence.",
        "core/controls.py"),
    Refusal(
        "supplier_vulnerabilities", "Supplier vulnerability findings",
        Ground.GOVERNANCE,
        "Third-party risk platforms report vulnerabilities on vendor estates.",
        "Structural, not a policy choice: a supplier's estate belongs to "
        "somebody else, the customer cannot prove ownership, and the gate "
        "refuses every active operation against an unverified asset. No probe "
        "means no fingerprint means no product name means no vulnerability. "
        "Measured: SPF 8/8 and DMARC 8/8 across real domains, so presence "
        "separates nobody — enforcement, CAA and MTA-STS lead instead.",
        "core/suppliers.py"),
    Refusal(
        "latency_three_cells", "Three of four time-to-attack forecast cells",
        Ground.MEASURED,
        "Predictive windows are a standard threat-intelligence claim.",
        "Only 1 of 4 reference classes has usable data (n=58, median 8 days, "
        "IQR 1-124). The others span 1,380-2,360 days. MIN_SAMPLE=20 and "
        "MAX_USEFUL_SPREAD_DAYS=400 are enforced IN THE TYPE, so an unusable "
        "cell cannot be rendered as a prediction.",
        "core/latency.py"),
    Refusal(
        "awareness_training", "Adaptive awareness training", Ground.HONESTY,
        "Listed as pillar M8 in this project's own SRS.",
        "Read carefully it was six branded slogans with no mechanism and no "
        "output, even in the original. Dropped rather than deferred: building a "
        "hollow pillar to claim parity is the one thing this plan should not "
        "do. Eight pillars of substance rather than nine of coverage.",
        "docs/P6-SCOPE.md"),
)

#: The OTHER kind. Absent because unbuilt, not because declined. Listed
#: separately and never merged, because presenting a gap as a principled
#: refusal is exactly the dishonesty this module exists to avoid.
GAPS: Sequence[str] = (
    "A 13-billion-entity intelligence graph across a million sources — "
    "collection infrastructure, not code.",
    "Malware intelligence and sandbox detonation — a different product.",
    "Geopolitical intelligence — an analyst organisation, not software.",
    "Identity intelligence at scale. Domain-level breach exposure is planned; "
    "monitoring a million external identities is not.",
    "Multi-tenant SaaS. Row-level security is built and proven, but an "
    "organisation can still only be created by hand in the database.",
)

BY_ID: Dict[str, Refusal] = {r.id: r for r in REFUSALS}


def payload() -> Dict[str, Any]:
    grounds: Dict[str, int] = {}
    for refusal in REFUSALS:
        grounds[refusal.ground.value] = grounds.get(refusal.ground.value, 0) + 1
    return {
        "refusals": [r.to_dict() for r in REFUSALS],
        "count": len(REFUSALS),
        "by_ground": dict(sorted(grounds.items())),
        "gaps": list(GAPS),
        "note": (
            "A refusal is not a gap. A gap is something not yet built; a "
            "refusal is something built far enough to measure, measured, and "
            "then declined — or something a governance rule forbids. Most of "
            "these carry the number that produced them."),
        "document": "docs/REFUSALS.md",
    }


def caveat_lines() -> List[str]:
    """One line per refusal, for the STIX bundle's outbound caveat.

    A consumer receiving this data will otherwise assume an absence is an
    oversight. Short form only — the full reasoning stays in the document.
    """
    return [f"{r.title}: {r.ground.value} — see {r.recorded_in}"
            for r in REFUSALS]


__all__ = ["Refusal", "Ground", "REFUSALS", "GAPS", "BY_ID", "payload",
           "caveat_lines"]
