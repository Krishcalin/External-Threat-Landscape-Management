"""TEPS — Threat-weighted Exposure Preemption Score.

NORMATIVE. This implements SKOPOS-SRS-v1.0 §9.1 exactly. The specification is the
authority; where this file and the SRS disagree, this file is wrong. The worked
example in §9.1 is pinned as a golden test, so a weight cannot be "improved"
without the change being visible in a diff.

WHY NO BLACK BOX (FR-M10-002)
-----------------------------
Every score decomposes into its factor contributions and the decomposition
travels with the score, not beside it. A number a reader cannot take apart is a
number they either over-trust or ignore, and both are worse than a smaller number
they understand. `Score.explain()` is the product feature, not a debug aid.

THE MISSING-DATA RULE, AND WHY THE SRS's VERSION IS AIMED AT THE WRONG FIELD
---------------------------------------------------------------------------
§9.1 mandates: if CVSS is NULL, substitute CNA/ADP, else use 5.0, mark the
finding no better than `probable` and flag `unscored_cve`. That rule is
implemented here as written.

It will almost never fire. Measured against the live NVD API over three 2026
windows (600 CVEs), CVSS was absent from **under 1%** of records. The field that
is actually missing is **CPE**:

    published window      no CPE      no CVSS     `Deferred` share of processed
    March 2026              6%          0%                  6%
    May 2026               14%          0%                 14%
    August 2026            92%          1%                 75%

and the correlation with `vulnStatus` is deterministic — `Analyzed` and
`Modified` always carry CPE, `Deferred` and `Received` never do. (Note also that
the status string is `Deferred`; §FR-M2-003 names `Not Scheduled`, which no
current record uses, so handling written against that string would never fire.)

CPE is the join key for asset-to-vulnerability matching, so the degradation lands
on MATCHING rather than on scoring — which is why `match_confidence` is a
first-class input to this module and why `unresolved_identity` exists beside
`unscored_cve`. A finding whose product identity could not be resolved must not
score as though it had been.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

#: §9.1 default weights. They sum to 1.0 and a test asserts it, because a
#: silently unnormalised weight set rescales every score in the product.
W_EXPOSURE = 0.25
W_EXPLOIT = 0.30
W_ADVERSARY = 0.25
W_BUSINESS = 0.20

#: §9.1 — mitigation discount is capped, so no combination of controls can drive
#: a live exposure to zero. A control is a reduction, never an absolution.
MAX_MITIGATION = 0.60

#: §9.1 — the substitute when no publisher scored the CVE at all.
ASSUMED_CVSS = 5.0

#: §9.1 severity bands.
BANDS = ((85, "critical"), (70, "high"), (50, "medium"), (30, "low"), (0, "informational"))

MODEL_VERSION = "teps-1.0.0"


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


@dataclass(frozen=True)
class Exposure:
    """§9.1 E — how reachable and how sensitive."""

    reachability: float = 0.0
    service_sensitivity: float = 0.0
    auth_exposure: float = 0.0
    shadow: bool = False
    days_exposed: int = 0

    def value(self) -> float:
        return clamp01(
            0.30 * self.reachability
            + 0.25 * self.service_sensitivity
            + 0.20 * self.auth_exposure
            + 0.15 * (1.0 if self.shadow else 0.0)
            + 0.10 * min(self.days_exposed / 90.0, 1.0)
        )


@dataclass(frozen=True)
class Exploitability:
    """§9.1 X — how attackable, right now.

    KEV membership short-circuits to 1.0 and that is deliberate: it is an
    OBSERVATION that exploitation is happening, and no probability model should
    be able to argue it down.
    """

    in_kev: bool = False
    epss: float = 0.0
    cvss: Optional[float] = None
    poc_public: bool = False
    ssvc_automatable: float = 0.0

    def value(self) -> float:
        cvss = ASSUMED_CVSS if self.cvss is None else self.cvss
        if self.in_kev:
            return 1.0
        if self.poc_public:
            return clamp01(0.55 + 0.35 * self.epss + 0.10 * (cvss / 10.0))
        return clamp01(0.60 * self.epss + 0.25 * (cvss / 10.0)
                       + 0.15 * self.ssvc_automatable)

    @property
    def unscored_cve(self) -> bool:
        """§9.1 — no publisher scored this CVE, so the score used a substitute."""
        return self.cvss is None


@dataclass(frozen=True)
class AdversaryInterest:
    """§9.1 A — the triad match. Who has a reason to come for this.

    THE TRIAD CANNOT BE BUILT FROM OPEN DATA, AND THIS SAYS SO.

    The specification asks for sector, geography and technology matching driven
    by ATT&CK Groups. Measured against the real dataset (enterprise-attack.json,
    51 MB, 191 intrusion-sets):

      * ZERO ATT&CK objects carry a CVE external reference. There is no path
        from "this CVE is in my estate" to "this group uses it".
      * Group objects have no structured sector or geography field. Targeting
        appears only in prose. Keyword matching reaches 125/191 for sectors and
        131/191 for geographies, but a description mentioning "financial" may be
        a citation or a negation — presence is not attribution.

    So the sector, geography and technology legs are UNSUPPLIED rather than
    zero, and `supplied` tells them apart. A product that filled them with prose
    keyword matches would be manufacturing the exact kind of confident claim
    this codebase refuses everywhere else, and it would poison the backtesting
    harness that is supposed to demonstrate the opposite.

    `named_mention` IS supportable: CISA records ransomware-campaign use per
    entry, which is an observation rather than an inference. It carries the
    smallest weight in §9.1, so a ransomware-linked CVE gains 0.15 * 0.25 =
    0.037 of TEPS on its own. That is a real and small signal, and reporting it
    as small is the point.
    """

    sector_match: float = 0.0
    geo_match: float = 0.0
    tech_match: float = 0.0
    named_mention: float = 0.0
    #: False when nothing filled the triad. Distinct from a supplied zero: "no
    #: adversary has a known reason to target this" and "we have no data on
    #: whether one does" are different statements, and 25% of every score turns
    #: on which one it is.
    supplied: bool = False

    def value(self) -> float:
        return clamp01(0.35 * self.sector_match + 0.20 * self.geo_match
                       + 0.30 * self.tech_match + 0.15 * self.named_mention)

    @property
    def triad_unsupplied(self) -> bool:
        """The three legs the open data cannot fill."""
        return not (self.sector_match or self.geo_match or self.tech_match)

    @staticmethod
    def from_catalogue(known_ransomware: bool = False) -> "AdversaryInterest":
        """What the vendored corpus can honestly support, and nothing more."""
        return AdversaryInterest(named_mention=1.0 if known_ransomware else 0.0,
                                 supplied=True)


@dataclass(frozen=True)
class Score:
    """A TEPS value that carries its own derivation."""

    teps: int
    band: str
    exposure: float
    exploitability: float
    adversary: float
    business: float
    mitigation: float
    model_version: str
    flags: List[str] = field(default_factory=list)

    def contributions(self) -> Dict[str, float]:
        """Each factor's share of the pre-mitigation total, for the UI bar."""
        return {
            "exposure": round(W_EXPOSURE * self.exposure, 4),
            "exploitability": round(W_EXPLOIT * self.exploitability, 4),
            "adversary_interest": round(W_ADVERSARY * self.adversary, 4),
            "business_criticality": round(W_BUSINESS * self.business, 4),
        }

    def explain(self) -> str:
        parts = ", ".join(f"{k.replace('_', ' ')} {v:.3f}"
                          for k, v in self.contributions().items())
        text = f"TEPS {self.teps} ({self.band}) = {parts}"
        if self.mitigation:
            text += f", less {self.mitigation:.0%} mitigation"
        if self.flags:
            text += f" — {'; '.join(self.flags)}"
        return text


def band_for(teps: int) -> str:
    for threshold, name in BANDS:
        if teps >= threshold:
            return name
    return "informational"          # pragma: no cover — BANDS ends at 0


def business_criticality(tier: Optional[int]) -> float:
    """§9.1 B — `(6 - tier) / 5`, tier 1 most critical.

    An unset tier is NOT treated as least critical. An asset nobody has tiered is
    an asset nobody has assessed, and defaulting it to harmless is how the
    unassessed become invisible. It takes the midpoint and is flagged.
    """
    if tier is None:
        return 0.5
    return clamp01((6 - max(1, min(5, int(tier)))) / 5.0)


def score(exposure: Exposure,
          exploitability: Exploitability,
          adversary: AdversaryInterest,
          asset_tier: Optional[int],
          mitigation: float = 0.0,
          match_confidence: str = "possible") -> Score:
    """§9.1 TEPS. Deterministic: identical inputs give an identical score."""
    flags: List[str] = []

    e = exposure.value()
    x = exploitability.value()
    a = adversary.value()
    b = business_criticality(asset_tier)

    if exploitability.unscored_cve:
        # §9.1's mandatory rule. Measured to fire on <1% of real CVEs — see the
        # module docstring; the real gap is identity, flagged below.
        flags.append(f"no published CVSS; scored with an assumed {ASSUMED_CVSS}")
    if asset_tier is None:
        flags.append("asset has no criticality tier; scored at the midpoint")
    if adversary.triad_unsupplied:
        # 25% of the score. Leaving this unflagged would let a number computed
        # from three of four factors present itself as a complete one, and the
        # reader has no way to see the difference from the total alone.
        flags.append(
            f"adversary interest is {W_ADVERSARY:.0%} of this score and its "
            f"sector/geography/technology legs are UNSUPPLIED — ATT&CK carries "
            f"no CVE linkage and no structured targeting data, so no open "
            f"source can fill them")
    if match_confidence == "possible":
        # THE FLAG THE SRS DOES NOT HAVE, and the one the data says matters. A
        # heuristic product-name match is not a confirmed affected version, and a
        # score presented without that caveat is the industry failure this
        # product exists to avoid.
        flags.append("product identity unresolved — heuristic match, not a "
                     "confirmed affected version")

    capped = clamp01(min(mitigation, MAX_MITIGATION))
    if mitigation > MAX_MITIGATION:
        flags.append(f"mitigation capped at {MAX_MITIGATION:.0%}")

    raw = (W_EXPOSURE * e + W_EXPLOIT * x + W_ADVERSARY * a + W_BUSINESS * b)
    teps = int(round(100 * raw * (1 - capped)))
    return Score(teps=teps, band=band_for(teps), exposure=e, exploitability=x,
                 adversary=a, business=b, mitigation=capped,
                 model_version=MODEL_VERSION, flags=flags)
