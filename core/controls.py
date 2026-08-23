"""Which controls this product helps evidence, and the claim it never makes.

SUPPORTING A CONTROL IS NOT SATISFYING IT
-----------------------------------------
A control is satisfied by an organisation doing something, sustaining it, and
being able to show they did. A tool contributes evidence toward part of that. The
entire market for compliance features runs on blurring the two, and a green tick
against "A.8.8 Management of technical vulnerabilities" because a scanner is
installed is how organisations arrive at an audit believing they are covered.

So every entry here says what SKOPOS contributes and, explicitly, what it does
NOT. There is no coverage percentage, no score, and no tick. A percentage would
be summed, the sum would be presented to a board, and the board would be
receiving a number this product has no basis to produce.

WHY THESE CONTROLS
------------------
Not a broad mapping — five ISO controls and the NIST CSF 2.0 functions the
product genuinely touches. A mapping that claimed forty controls would be mostly
padding, and padding is what makes the honest entries unreadable. Titles are
quoted verbatim from ISO/IEC 27001:2022 Annex A.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

#: When these mappings were last checked against the published standards.
REVIEWED_ON = "2026-08-23"

SUPPORTS_IS_NOT_SATISFIES = (
    "SKOPOS SUPPORTS these controls; it does not satisfy them and cannot make "
    "you compliant. A control is satisfied by your organisation doing something, "
    "sustaining it, and being able to demonstrate it to an auditor. This product "
    "contributes evidence toward part of that. There is deliberately no coverage "
    "percentage here: a percentage would be summed and shown to a board, and no "
    "tool has the basis to produce that number."
)


@dataclass(frozen=True)
class Control:
    framework: str
    identifier: str
    #: Verbatim from the standard. Paraphrasing a control title is how a mapping
    #: quietly drifts into describing something the standard does not say.
    title: str
    #: What this product actually contributes.
    contributes: str
    #: What it does not, named specifically. This field is the point of the file.
    does_not: str
    #: Which capability produces the evidence, so a claim can be checked.
    evidence_from: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {"framework": self.framework, "id": self.identifier,
                "title": self.title, "contributes": self.contributes,
                "does_not": self.does_not,
                "evidence_from": list(self.evidence_from)}


ISO_27001_2022: Sequence[Control] = (
    Control(
        framework="ISO/IEC 27001:2022", identifier="A.5.7",
        title="Threat intelligence",
        contributes=(
            "Maintains a versioned, dated corpus of actively exploited "
            "vulnerabilities and records which corpus version answered each "
            "scan, so an assessment can be reproduced rather than asserted."),
        does_not=(
            "Does not produce strategic or adversary-attribution intelligence. "
            "Measured: the one open CVE-to-actor mapping implicates a median of "
            "57 threat groups per CVE, so this product cannot tell you who is "
            "targeting you and does not pretend to."),
        evidence_from=("core/intel.py", "data/kev.json", "/api/v1/intel")),
    Control(
        framework="ISO/IEC 27001:2022", identifier="A.5.21",
        title="Managing information security in the ICT supply chain",
        contributes=(
            "Identifies third-party services in the external estate through "
            "certificate transparency, DNS and fingerprinting, including "
            "dangling records pointing at providers no longer under your "
            "control."),
        does_not=(
            "Does not assess a supplier's own security posture, contracts or "
            "practices. It sees what your DNS points at, not how the provider "
            "behind it is run."),
        evidence_from=("collect/discovery.py", "core/takeover.py",
                       "/api/v1/takeover")),
    Control(
        framework="ISO/IEC 27001:2022", identifier="A.5.22",
        title="Monitoring, review and change management of supplier services",
        contributes=(
            "Run-over-run DNS change tracking against the last CONCLUSIVE "
            "observation, distinguishing a record that changed from one this "
            "product could not see."),
        does_not=(
            "Does not monitor service levels, contractual performance or any "
            "supplier-side change. It observes DNS from outside."),
        evidence_from=("core/dns_state.py", "/api/v1/dns/changes")),
    Control(
        framework="ISO/IEC 27001:2022", identifier="A.5.23",
        title="Information security for use of cloud services",
        contributes=(
            "Reconciles outside-in observation against an inside-out cloud "
            "model from OverWatch, surfacing assets reachable from the internet "
            "that the cloud model says are closed, and vice versa."),
        does_not=(
            "Does not configure, govern or assess cloud services, and the "
            "reconciliation requires an OverWatch export — without one every "
            "verdict is inconclusive and is reported as such."),
        evidence_from=("core/overwatch.py", "/api/v1/reconciliation")),
    Control(
        framework="ISO/IEC 27001:2022", identifier="A.8.8",
        title="Management of Technical Vulnerabilities",
        contributes=(
            "Identifies externally visible assets running products with "
            "known-exploited vulnerabilities, ranks them, and where the "
            "customer supplied a version compares it against published affected "
            "ranges to reach a determination."),
        does_not=(
            "Does not patch anything, does not scan internal systems, and "
            "reaches a version determination for only part of the catalogue — "
            "measured at 47.5%, heavily weighted toward recent CVEs. The rest "
            "stays a worklist entry permanently."),
        evidence_from=("core/match.py", "core/affected.py", "/api/v1/findings")),
)

#: NIST CSF 2.0 functions. Deliberately at function level rather than a
#: subcategory-by-subcategory mapping: this product touches parts of three
#: functions, and a subcategory table would be mostly empty rows that make the
#: populated ones harder to find.
NIST_CSF_20: Sequence[Control] = (
    Control(
        framework="NIST CSF 2.0", identifier="ID.RA",
        title="Identify — Risk Assessment",
        contributes=(
            "Joins the external estate to actively exploited vulnerabilities "
            "and scores the pairing, with every factor and its uncertainty "
            "recorded alongside the result."),
        does_not=(
            "Does not assess internal risk, business impact or likelihood "
            "beyond the published signals it carries. Asset criticality comes "
            "from your inventory; where you supply none it is scored at the "
            "midpoint and flagged, never assumed harmless."),
        evidence_from=("core/scoring.py", "/api/v1/findings")),
    Control(
        framework="NIST CSF 2.0", identifier="ID.AM",
        title="Identify — Asset Management",
        contributes=(
            "Discovers externally visible names passively across certificate "
            "transparency, passive DNS, published indexes and a web archive, "
            "and reports per-source coverage so a thin result is never mistaken "
            "for a small estate."),
        does_not=(
            "Does not inventory internal assets, endpoints or software bills of "
            "materials. It sees what is visible from outside, and states what "
            "each source could not tell it."),
        evidence_from=("collect/run.py", "/api/v1/discovery")),
    Control(
        framework="NIST CSF 2.0", identifier="DE.CM",
        title="Detect — Continuous Monitoring",
        contributes=(
            "Continuous external monitoring with run-over-run diff, and alerts "
            "on new findings above a threshold, new takeover findings and "
            "conclusively disappeared DNS records."),
        does_not=(
            "Does not detect intrusions, malicious activity or anything "
            "happening inside your network. It monitors your external surface, "
            "which is a different thing from monitoring your systems."),
        evidence_from=("core/findings_store.py", "core/alerting.py",
                       "/api/v1/changes")),
)

ALL: Sequence[Control] = tuple(ISO_27001_2022) + tuple(NIST_CSF_20)


def by_framework(framework: Optional[str] = None) -> List[Control]:
    if framework is None:
        return list(ALL)
    wanted = framework.strip().lower()
    return [c for c in ALL if wanted in c.framework.lower()]


def mapping() -> Dict[str, Any]:
    """The whole mapping, with the disclaimer that makes it readable."""
    return {
        "reviewed_on": REVIEWED_ON,
        "disclaimer": SUPPORTS_IS_NOT_SATISFIES,
        # Deliberately absent: any coverage figure. See the module docstring.
        "controls": [c.to_dict() for c in ALL],
        "frameworks": sorted({c.framework for c in ALL}),
    }


__all__ = ["Control", "ISO_27001_2022", "NIST_CSF_20", "ALL", "REVIEWED_ON",
           "SUPPORTS_IS_NOT_SATISFIES", "by_framework", "mapping"]
