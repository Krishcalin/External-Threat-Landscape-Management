"""Vulnerabilities beyond the exploited catalogue — kept structurally apart.

WHY THIS MODULE IS DEFENSIVE
----------------------------
Everything else in SKOPOS is built on ACTIVELY EXPLOITED. That is what makes the
worklist short, defensible, and different from a vulnerability scanner. OSV and
EUVD carry hundreds of thousands of advisories with no exploitation filter, and
blending them into the same list would convert this product into the thing it
was written not to be — quietly, and in a single merge.

So an advisory is a DIFFERENT TYPE from an exposure, not a flag on one. They
cannot be put in the same list by accident, `engine.rank()` will not accept an
advisory, and the API serves them from a different route. Making the unsafe
thing impossible beats documenting that it is unwise.

WHAT WAS MEASURED, AND WHAT IT CHANGED
--------------------------------------
Both sources were tested against the asset model this product actually has —
`product` and `version` strings — before anything was built on them.

**OSV joins only on PACKAGE COORDINATES.** Measured against the live API:

    {"package": {"name": "org.apache.logging.log4j:log4j-core",
                 "ecosystem": "Maven"}, "version": "2.14.1"}   -> 7 advisories
    {"package": {"name": "Apache HTTP Server"}, "version": "2.4.54"}  -> 0
    {"package": {"name": "log4j-core"}, "version": "2.14.1"}          -> 0
    {"package": {"name": "Connect Secure"}, "version": "22.3"}        -> 0

A product name returns nothing. OSV needs an ecosystem and an exact package
name, which come from an SBOM or a dependency manifest — neither of which SKOPOS
collects. So OSV is NOT a discovery source here; it is available to an operator
who supplies package coordinates, and it says so plainly when they do not,
rather than returning an empty result that reads as a clean estate.

**EUVD's text search is too loose to expand a worklist.** Measured: "Connect
Secure" returns 471 results, "Apache HTTP Server" returns 517. Those are
full-text matches across descriptions, and importing them would attach hundreds
of unrelated advisories to one asset. Its by-CVE lookup, however, is exact — so
EUVD is used as an ENRICHMENT source for CVEs already in hand, never as a way to
find new ones.

Both of those conclusions narrow this workstream considerably, and both are the
result of testing the join before writing the joiner.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


class Catalogue(str, enum.Enum):
    #: CISA KEV. Somebody observed exploitation. The product's default view.
    EXPLOITED = "exploited"
    #: OSV, EUVD, a vendor bulletin. A vulnerability exists. No claim at all is
    #: made about whether anyone is exploiting it.
    ADVISORY = "advisory"

    @property
    def meaning(self) -> str:
        return {
            Catalogue.EXPLOITED:
                "an authority observed this being exploited in the wild",
            Catalogue.ADVISORY:
                "a vulnerability was published. NOTHING here says anyone is "
                "exploiting it, and most published vulnerabilities never are",
        }[self]


class AdvisorySource(str, enum.Enum):
    OSV = "osv"
    EUVD = "euvd"


class CoordinatesMissing(ValueError):
    """OSV was asked about an asset that carries no package coordinates.

    Raised rather than returning an empty list, because "we looked and found
    nothing" and "we could not look" are the distinction this whole product is
    organised around, and an empty advisory list reads as a clean estate.
    """


@dataclass(frozen=True)
class PackageRef:
    """What OSV actually needs, as opposed to what an inventory usually has."""

    name: str
    ecosystem: str = ""
    version: str = ""

    @property
    def queryable(self) -> bool:
        # An ecosystem is required. Measured: without it even a correct package
        # name returns nothing, so a query built without one is a request that
        # cannot succeed dressed up as one that found nothing.
        return bool(self.name.strip()) and bool(self.ecosystem.strip())


@dataclass(frozen=True)
class Advisory:
    """A published vulnerability. DELIBERATELY NOT an `Exposure`.

    Different type, so it cannot enter a findings list, be ranked by
    `engine.rank()`, or be counted in a summary alongside exploited findings
    without somebody writing code that obviously converts it.
    """

    source: AdvisorySource
    identifier: str
    asset: str
    summary: str = ""
    cve: Optional[str] = None
    severity: Optional[float] = None
    published: Optional[date] = None
    #: The source's own statement about exploitation, where it makes one. Never
    #: inferred from severity — a high CVSS is not evidence of exploitation, and
    #: treating it as such is precisely the conflation this product avoids.
    exploited_per_source: bool = False
    reference: str = ""

    @property
    def catalogue(self) -> Catalogue:
        return Catalogue.ADVISORY

    def explain(self) -> str:
        return (f"{self.identifier} ({self.source.value}) on {self.asset}: "
                f"{self.summary[:110]}")


@dataclass
class CoverageResult:
    """Advisories for a run, and everything that could not be looked up."""

    advisories: List[Advisory] = field(default_factory=list)
    #: Assets skipped because they carry no package coordinates. Named, not
    #: counted silently — this is the majority case for a discovered estate.
    without_coordinates: List[str] = field(default_factory=list)
    failures: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def assets_covered(self) -> int:
        return len({a.asset for a in self.advisories})

    def note(self, total_assets: int = 0) -> str:
        parts = [f"{len(self.advisories)} advisory/ies across "
                 f"{self.assets_covered} asset(s)"]
        if self.without_coordinates:
            parts.append(
                f"{len(self.without_coordinates)} asset(s) COULD NOT BE LOOKED "
                f"UP: OSV needs an ecosystem and an exact package name, which "
                f"come from an SBOM or a dependency manifest. A discovered, "
                f"fingerprinted host carries neither, so this is a coverage "
                f"gap and not a clean result")
        if self.failures:
            parts.append(f"{len(self.failures)} lookup(s) failed")
        parts.append(
            "NONE of these is a statement that anyone is exploiting anything. "
            "That is what the exploited catalogue is for, and it is a separate "
            "list on purpose")
        return ". ".join(parts) + "."


def package_ref(asset) -> Optional[PackageRef]:
    """Package coordinates from an asset, or None.

    Read only from columns an operator supplies deliberately — `package` and
    `ecosystem`. A product name is NOT used as a package name: measured, it
    returns nothing from OSV, and guessing a mapping from "Apache HTTP Server"
    to a package would be inventing a fact about the customer's estate.
    """
    attributes = getattr(asset, "attributes", {}) or {}
    name = str(attributes.get("package") or "").strip()
    ecosystem = str(attributes.get("ecosystem") or "").strip()
    if not name:
        return None
    return PackageRef(name=name, ecosystem=ecosystem,
                      version=str(getattr(asset, "version", "") or ""))


def partition(advisories: Sequence[Advisory],
              exploited_cves: Iterable[str]) -> Dict[str, List[Advisory]]:
    """Split advisories by whether the exploited catalogue already covers them.

    An advisory whose CVE is already in KEV is not new information — it is the
    same vulnerability arriving by a second route, and showing it twice would
    inflate the estate's apparent problem count.
    """
    known = {str(c).strip().upper() for c in exploited_cves}
    already: List[Advisory] = []
    additional: List[Advisory] = []
    for advisory in advisories:
        cve = str(advisory.cve or "").strip().upper()
        (already if cve and cve in known else additional).append(advisory)
    return {"already_exploited": already, "advisory_only": additional}


#: Served rather than restated in the console, on the RECONCILIATION_MEANING
#: precedent.
CATALOGUE_MEANING: Dict[str, str] = {c.value: c.meaning for c in Catalogue}

__all__ = ["Catalogue", "AdvisorySource", "CoordinatesMissing", "PackageRef",
           "Advisory", "CoverageResult", "package_ref", "partition",
           "CATALOGUE_MEANING"]
