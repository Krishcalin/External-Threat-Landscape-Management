"""The external exposure of assets the customer says are critical infrastructure.

WHAT SKOPOS CANNOT DO, AND THIS TIME IT IS A MATTER OF LAW
----------------------------------------------------------
NCIIPC is the national nodal agency for Critical Information Infrastructure
protection, created under Section 70A of the Information Technology Act, 2000
(as amended 2008), by gazette notification of 16 January 2014. The Act defines
CII as "those computer resource, the incapacitation or destruction of which,
shall have debilitating impact on national security, economy, public health or
safety".

Under Section 70, the appropriate Government MAY, BY NOTIFICATION IN THE
OFFICIAL GAZETTE, declare a computer resource to be a protected system. That is
where the status comes from. It is not inferred from what a host runs, how it is
named, or how exposed it looks.

So this module never designates anything. It cannot, and neither can the
customer's security team on their own — a gazette notification is not something
either party issues. The register records what the ORGANISATION states about its
own assets, with the gazette reference where one exists, and SKOPOS supplies
only what it observed from outside.

A tool that guessed CII status from a hostname would be inventing a legal
status, and an organisation that acted on the guess would either be over-
reporting to a national agency or believing itself covered when it is not.

WHAT THE REGISTER IS ACTUALLY FOR
---------------------------------
An assessor asks: which of your internet-facing assets support critical
infrastructure, what is exposed on them, and since when did you know? Every part
of that answer already exists in this product — discovery, fingerprinting,
findings, evidence, first-seen dates. The register is a view over it, filtered to
the assets the organisation has placed in scope, and carrying its own provenance
so the assessor can tell a gazette notification from somebody's opinion.

UNDECLARED ASSETS ARE RAISED AS A QUESTION, NEVER AS A FINDING
--------------------------------------------------------------
An asset in a declared critical sector that carries no designation is worth
asking about. It is NOT evidence of non-compliance, and this module phrases it
as a question for the organisation rather than a gap in a report — because the
answer may legitimately be "that one is out of scope and always was".
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Sequence

#: Section 70A of the IT Act, 2000 (amended 2008); gazette notification of
#: 16 January 2014.
AUTHORITY = ("NCIIPC, National Nodal Agency for Critical Information "
             "Infrastructure Protection, constituted under Section 70A of the "
             "Information Technology Act, 2000 (amended 2008)")

CII_DEFINITION = ("those computer resource, the incapacitation or destruction "
                  "of which, shall have debilitating impact on national "
                  "security, economy, public health or safety "
                  "— Information Technology Act, 2000")

#: When these references were last checked against the published sources.
REVIEWED_ON = "2026-08-23"


class Sector(str, enum.Enum):
    """The critical sectors NCIIPC has broadly identified."""

    POWER_ENERGY = "power_and_energy"
    BFSI = "banking_financial_services_insurance"
    TELECOM = "telecom"
    TRANSPORT = "transport"
    GOVERNMENT = "government"
    STRATEGIC_PUBLIC = "strategic_and_public_enterprises"

    @property
    def label(self) -> str:
        return {
            Sector.POWER_ENERGY: "Power & Energy",
            Sector.BFSI: "Banking, Financial Services & Insurance",
            Sector.TELECOM: "Telecom",
            Sector.TRANSPORT: "Transport",
            Sector.GOVERNMENT: "Government",
            Sector.STRATEGIC_PUBLIC: "Strategic & Public Enterprises",
        }[self]


class Basis(str, enum.Enum):
    """How an asset came to be in this register. The distinction an assessor
    cares about most, so it is a required field rather than a note."""

    #: Declared a protected system by notification in the Official Gazette
    #: under Section 70. Carries a reference.
    GAZETTE = "gazette_notification"
    #: The organisation considers this asset to support CII. A considered
    #: internal position, and explicitly not a legal designation.
    ORGANISATION_ASSESSED = "organisation_assessed"
    #: In a critical sector, with no designation recorded. A question.
    UNDECLARED = "undeclared"

    @property
    def weight(self) -> str:
        return {
            Basis.GAZETTE:
                "declared a protected system by notification in the Official "
                "Gazette under Section 70 of the IT Act",
            Basis.ORGANISATION_ASSESSED:
                "the organisation's own assessment that this asset supports "
                "critical infrastructure. NOT a legal designation — only the "
                "appropriate Government confers that, by gazette notification",
            Basis.UNDECLARED:
                "no designation recorded. Listed as a QUESTION for the "
                "organisation, not as a finding: the answer may legitimately be "
                "that it is out of scope",
        }[self]


class RegisterError(ValueError):
    """A register entry that would misrepresent an asset's legal status."""


@dataclass(frozen=True)
class Designation:
    """What the organisation states about one asset."""

    asset: str
    sector: Sector
    basis: Basis
    #: Required for GAZETTE. A claim of gazette notification with no reference
    #: is the one entry in this file that could mislead a regulator.
    gazette_reference: Optional[str] = None
    declared_by: str = ""
    declared_on: Optional[date] = None
    note: str = ""

    def __post_init__(self) -> None:
        if not str(self.asset).strip():
            raise RegisterError("a register entry must name an asset")
        if self.basis is Basis.GAZETTE and not (self.gazette_reference or "").strip():
            raise RegisterError(
                "a gazette-notified designation must carry its notification "
                "reference. Asserting protected-system status without one is "
                "the single claim in this register that could mislead a "
                "regulator, so it is refused rather than flagged")
        if self.basis is not Basis.UNDECLARED and not (self.declared_by or "").strip():
            raise RegisterError(
                "a designation must record who recorded it — an unattributed "
                "statement about an asset's CII status is not a record")

    def explain(self) -> str:
        line = f"{self.asset} ({self.sector.label}): {self.basis.weight}"
        if self.gazette_reference:
            line += f" [{self.gazette_reference}]"
        return line


@dataclass
class Entry:
    """One asset in the register, with what SKOPOS observed about it."""

    designation: Designation
    findings: List[Dict[str, Any]] = field(default_factory=list)
    #: Earliest date this product saw the asset externally. The "since when did
    #: you know" half of an assessor's question — and it is OUR first sighting,
    #: never a claim about when exposure began.
    first_observed: Optional[date] = None
    externally_reachable: Optional[bool] = None

    @property
    def determinations(self) -> int:
        return sum(1 for f in self.findings
                   if str(f.get("basis")) == "version_range"
                   and not any(str(e).startswith("RETIRED:")
                               for e in f.get("evidence") or []))

    @property
    def worklist(self) -> int:
        return len(self.findings) - self.determinations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset": self.designation.asset,
            "sector": self.designation.sector.value,
            "sector_label": self.designation.sector.label,
            "basis": self.designation.basis.value,
            "basis_meaning": self.designation.basis.weight,
            "gazette_reference": self.designation.gazette_reference,
            "declared_by": self.designation.declared_by or None,
            "declared_on": (str(self.designation.declared_on)
                            if self.designation.declared_on else None),
            "findings": len(self.findings),
            "determinations": self.determinations,
            "worklist": self.worklist,
            "first_observed_by_skopos": (str(self.first_observed)
                                         if self.first_observed else None),
            "externally_reachable": self.externally_reachable,
            "note": self.designation.note or None,
        }


@dataclass
class Register:
    entries: List[Entry] = field(default_factory=list)
    #: Assets SKOPOS found that carry no designation at all. Not in the register
    #: proper — they are the question list.
    undeclared: List[str] = field(default_factory=list)

    def of_basis(self, basis: Basis) -> List[Entry]:
        return [e for e in self.entries if e.designation.basis is basis]

    def headline(self) -> str:
        gazette = len(self.of_basis(Basis.GAZETTE))
        assessed = len(self.of_basis(Basis.ORGANISATION_ASSESSED))
        line = (f"{len(self.entries)} asset(s) in the register: {gazette} "
                f"gazette-notified, {assessed} assessed by the organisation.")
        if self.undeclared:
            line += (f" {len(self.undeclared)} externally visible asset(s) carry "
                     f"no designation — a question for you, not a finding.")
        return line

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authority": AUTHORITY,
            "cii_definition": CII_DEFINITION,
            "reviewed_on": REVIEWED_ON,
            "headline": self.headline(),
            "entries": [e.to_dict() for e in self.entries],
            "undeclared_assets": list(self.undeclared),
            "sectors": {s.value: s.label for s in Sector},
            "skopos_does_not_designate": (
                "SKOPOS does not and cannot determine whether an asset is "
                "Critical Information Infrastructure. Under Section 70 of the "
                "IT Act, 2000, the appropriate Government declares a computer "
                "resource a protected system by notification in the Official "
                "Gazette. This register records what YOUR ORGANISATION states, "
                "with its provenance, and adds only what SKOPOS observed from "
                "outside. Any tool that infers CII status from a hostname is "
                "inventing a legal status."),
        }


def build(designations: Sequence[Designation],
          findings: Sequence[Dict[str, Any]],
          observed: Optional[Dict[str, date]] = None,
          reachable: Optional[Dict[str, Optional[bool]]] = None) -> Register:
    """Join declared assets to what this product observed about them."""
    seen_dates = observed or {}
    reach = reachable or {}
    by_asset: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        by_asset.setdefault(str(finding.get("asset") or ""), []).append(finding)

    entries = [
        Entry(designation=d,
              findings=by_asset.get(d.asset, []),
              first_observed=seen_dates.get(d.asset),
              externally_reachable=reach.get(d.asset))
        for d in designations]

    declared = {d.asset for d in designations}
    undeclared = sorted(a for a in by_asset if a and a not in declared)
    entries.sort(key=lambda e: (e.designation.basis is not Basis.GAZETTE,
                                -len(e.findings), e.designation.asset))
    return Register(entries=entries, undeclared=undeclared)


__all__ = ["AUTHORITY", "CII_DEFINITION", "REVIEWED_ON", "Sector", "Basis",
           "Designation", "RegisterError", "Entry", "Register", "build"]
