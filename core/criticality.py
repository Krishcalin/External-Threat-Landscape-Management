"""How critical is this asset — read per asset, not assumed for the estate.

THE PROBLEM THIS FIXES
----------------------
`asset_tier` was a single query parameter applied to every asset in a scan.
Measured against the running deployment: all 64 findings scored exactly 50, in
one band, because every factor was constant across the estate — exploitability
1.0 (KEV short-circuits, by design), adversary 0.0 (never supplied), business
0.6 (one global tier), exposure 0.3 (no per-asset reachability). The ordered
tuple in `engine.rank()` was doing all the discrimination and TEPS was doing
none.

Business criticality is the factor an operator can actually supply today, from a
column they already have, so it is the cheapest way to make the score mean
something.

A HEURISTIC, AND LABELLED AS ONE
--------------------------------
`inventory.ALIASES` already routes a `tier` or `criticality` column into
`Asset.environment`, where it arrives as free text — "prod", "1", "Tier 2",
"business critical". Mapping that to §9.1's 1–5 scale is a guess about the
customer's own vocabulary, so every derived tier carries how it was derived, and
a string this module does not recognise yields None rather than a default.

None is NOT "least critical". `scoring.business_criticality` scores an untiered
asset at the midpoint and flags it, because an asset nobody has tiered is an
asset nobody has assessed, and defaulting the unassessed to harmless is how they
become invisible.
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


class TierSource(str, enum.Enum):
    #: The operator wrote a number on the §9.1 scale. Believed as given.
    EXPLICIT = "explicit"
    #: Derived from a word like "production" or "critical". A guess about the
    #: customer's vocabulary, and reported as one.
    DERIVED = "derived"
    #: Nothing usable. Scored at the midpoint and flagged.
    ABSENT = "absent"


#: Words that map onto §9.1's 1–5 scale, tier 1 most critical. Deliberately
#: small: a long list of near-synonyms would raise the hit rate while lowering
#: the accuracy, and a wrong tier moves a score with nothing saying it was
#: guessed at.
VOCABULARY: Tuple[Tuple[str, int], ...] = (
    ("mission critical", 1), ("business critical", 1), ("crown jewel", 1),
    ("critical", 1), ("tier 1", 1), ("tier1", 1), ("p1", 1),
    ("production", 2), ("prod", 2), ("live", 2), ("tier 2", 2), ("tier2", 2),
    ("staging", 3), ("stage", 3), ("uat", 3), ("pre-prod", 3), ("preprod", 3),
    ("tier 3", 3), ("tier3", 3),
    ("test", 4), ("qa", 4), ("development", 4), ("dev", 4), ("tier 4", 4),
    ("sandbox", 5), ("lab", 5), ("scratch", 5), ("decommissioned", 5),
    ("tier 5", 5),
)

_NUMERIC = re.compile(r"^\s*(?:tier\s*)?([1-5])\s*$", re.I)


@dataclass(frozen=True)
class Tier:
    value: Optional[int]
    source: TierSource
    raw: str = ""

    @property
    def explain(self) -> str:
        if self.source is TierSource.EXPLICIT:
            return f"tier {self.value}, as recorded"
        if self.source is TierSource.DERIVED:
            return (f"tier {self.value}, DERIVED from {self.raw!r} — a guess at "
                    f"your vocabulary, not something you stated")
        return ("no criticality recorded, so this asset was scored at the "
                "midpoint rather than assumed harmless")


def parse(text) -> Tier:
    """A tier from whatever the inventory said, or an honest absence."""
    raw = str(text or "").strip()
    if not raw:
        return Tier(None, TierSource.ABSENT)

    numeric = _NUMERIC.match(raw)
    if numeric:
        return Tier(int(numeric.group(1)), TierSource.EXPLICIT, raw)

    lowered = raw.lower()
    # Longest match first, so "business critical" is not swallowed by
    # "critical" and scored the same as a generic label.
    for word, tier in sorted(VOCABULARY, key=lambda p: -len(p[0])):
        if word in lowered:
            return Tier(tier, TierSource.DERIVED, raw)
    return Tier(None, TierSource.ABSENT, raw)


def for_asset(asset, fallback: Optional[int] = None) -> Tier:
    """The tier for one asset.

    Reads `environment` — which `inventory.ALIASES` already fills from a `tier`
    or `criticality` column — then any explicit `tier` attribute an operator
    supplied. `fallback` is the run-wide default and is used ONLY when the asset
    itself says nothing, so a global setting can no longer overwrite a value the
    customer took the trouble to record.
    """
    attributes = getattr(asset, "attributes", {}) or {}
    for candidate in (attributes.get("tier"), attributes.get("criticality"),
                      getattr(asset, "environment", None)):
        tier = parse(candidate)
        if tier.value is not None:
            return tier
    if fallback is not None:
        return Tier(int(fallback), TierSource.DERIVED, f"run default {fallback}")
    return Tier(None, TierSource.ABSENT,
                str(getattr(asset, "environment", "") or ""))


def distribution(tiers) -> Dict[str, int]:
    """How the estate actually tiers, so a flat one is visible.

    An estate where every asset resolves to the same tier scores every finding
    identically, and the operator should be told that rather than shown a
    ranking that is not one.
    """
    counts: Dict[str, int] = {}
    for tier in tiers:
        key = (f"tier {tier.value}" if tier.value is not None else "untiered")
        counts[key] = counts.get(key, 0) + 1
    return counts


__all__ = ["TierSource", "Tier", "VOCABULARY", "parse", "for_asset",
           "distribution"]
