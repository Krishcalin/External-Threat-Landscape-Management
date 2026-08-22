"""The three things this product reasons about, and the one distinction that
decides whether a result is worth acting on.

AN EXPOSURE IS A JOIN, NOT A FINDING
------------------------------------
A scanner produces findings about a system. This product produces EXPOSURES: a
pairing of something the organisation runs with something adversaries are known
to be exploiting. Neither half is a finding on its own — an asset inventory is
not a security result, and a threat feed is not a statement about you. The join
is the product.

THE DISTINCTION THAT MATTERS MOST
---------------------------------
`MatchBasis` separates what we KNOW from what we SUSPECT, and it exists because
the alternative is the industry norm: a list of CVEs "affecting" an estate,
assembled by matching product names, presented with the confidence of a
determination. That list is mostly wrong, everybody who has worked one knows it
is mostly wrong, and the effect is that the true entries are discounted along
with the false ones.

    PRODUCT_MATCH   the asset runs a product that appears in the exploited
                    catalogue. This is a WORKLIST. It does not say the asset is
                    vulnerable, because the exploited catalogue carries no
                    affected-version data at all — 1,674 entries and not one
                    structured version range. Somebody has to check.

    VERSION_RANGE   the asset's version was compared against the vulnerability's
                    published affected range and falls inside it. This is a
                    DETERMINATION: both facts came from outside this product and
                    comparing them is arithmetic.

Phase 1 can only produce the first, and says so rather than dressing it up.
Reaching the second needs affected-range data the vendored corpus does not yet
carry, and that is a stated gap rather than a silent one.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional


class MatchBasis(str, enum.Enum):
    """How an exposure was concluded. See the module docstring."""

    #: Product names correspond. A worklist entry.
    PRODUCT_MATCH = "product_match"
    #: The asset's version falls inside a published affected range. A verdict.
    VERSION_RANGE = "version_range"

    @property
    def is_determination(self) -> bool:
        return self is MatchBasis.VERSION_RANGE


class Confidence(str, enum.Enum):
    """How strongly the product names correspond.

    Deliberately coarse. A numeric score would invite a threshold, a threshold
    would be tuned until the list looked reasonable, and the tuning would become
    the product's real opinion while nobody could see it.
    """

    #: Vendor and product both correspond.
    STRONG = "strong"
    #: Product corresponds; vendor is absent or does not.
    PARTIAL = "partial"


@dataclass(frozen=True)
class Asset:
    """Something the organisation runs and can be reached at.

    `version` is Optional and stays Optional. An inventory that does not record
    versions is the normal case, not a broken one, and a product that requires
    them in order to say anything is a product nobody can start using.
    """

    identifier: str
    product: str
    vendor: Optional[str] = None
    version: Optional[str] = None
    #: Who fixes it. The whole objective is "accountable remediation", and an
    #: exposure with no owner is a fact nobody is going to act on.
    owner: Optional[str] = None
    environment: Optional[str] = None
    #: Where this row came from — an inventory export, a collector, a CMDB.
    #: Carried so a disputed asset can be traced back rather than argued about.
    source: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not str(self.identifier).strip():
            raise ValueError("an asset with no identifier cannot be reported "
                             "against, tracked, or assigned to anybody")
        # `is None` explicitly: str(None) is "None", a four-character truthy
        # string that sails through the strip() check and then tokenises to
        # {"none"} — a placeholder the matcher would try to join on.
        if self.product is None or not str(self.product).strip():
            raise ValueError("an asset with no product cannot be joined to a "
                             "vulnerability catalogue")


@dataclass(frozen=True)
class Exploited:
    """One entry from the exploited-vulnerability catalogue, as published.

    Fields mirror CISA's own names rather than being renamed into house style.
    An auditor comparing this against the source should not have to translate,
    and a rename is a place for meaning to drift.
    """

    cve: str
    vendor_project: str
    product: str
    name: str
    date_added: date
    short_description: str
    required_action: str
    due_date: Optional[date] = None
    known_ransomware: bool = False
    notes: str = ""
    cwes: List[str] = field(default_factory=list)
    #: FIRST EPSS, where the corpus carries it. A FORECAST, used only to order
    #: this list — never to claim exploitation, which is what KEV membership
    #: already establishes far more strongly than any probability could.
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None


@dataclass(frozen=True)
class Exposure:
    """An asset joined to something being exploited in the wild."""

    asset: Asset
    exploited: Exploited
    basis: MatchBasis
    confidence: Confidence
    #: The tokens that corresponded, so a reader can judge the match instead of
    #: trusting it. A join nobody can check is a join nobody should act on.
    evidence: List[str] = field(default_factory=list)

    @property
    def is_determination(self) -> bool:
        return self.basis.is_determination

    @property
    def needs_verification(self) -> bool:
        """True while nothing has established that this asset's VERSION is
        affected. Phase 1 returns True for everything, by construction."""
        return not self.basis.is_determination
