"""Joining an asset to something being exploited, without inventing the join.

THE PROBLEM EVERY TOOL IN THIS CATEGORY HAS
-------------------------------------------
An inventory says `Apache httpd 2.4.54`. The catalogue says vendor `Apache`,
product `HTTP Server`. Those are the same thing and no exact key relates them.
The industry answer is fuzzy string matching tuned until the output looks
plausible, presented without saying it was fuzzy — which produces a long list
that is mostly wrong, gets worked once, and is then ignored along with the true
entries inside it.

WHAT THIS DOES INSTEAD
----------------------
Three rules, in order, and it stops at the first that fits:

  1. an explicit CVE on the asset row wins outright. If an inventory already
     records that a host is affected by CVE-2021-44228, no name matching is
     needed and none is done.
  2. vendor AND product both correspond -> STRONG.
  3. product alone corresponds -> PARTIAL.

Correspondence is token containment over normalised names, not edit distance. A
token set is inspectable — the tokens that matched are carried on the exposure
and printed — and an edit distance is a number nobody can argue with, which is
worse than one they can.

WHAT IT REFUSES TO DO
---------------------
It never claims a version verdict. The catalogue carries NO structured
affected-version data (1,674 entries, zero version ranges), so no amount of
matching here can establish that a given version is affected. Every exposure
this module produces is `PRODUCT_MATCH`, which the models call a worklist, and
the CLI says so on every run. That is not a limitation to be worked around; it
is the honest shape of what this corpus can support, and the fix is more data
rather than more inference.

STOPWORDS EXIST FOR A REASON
----------------------------
`product` fields in the catalogue read like "Zimbra Collaboration Suite (ZCS)"
and inventories read like "zimbra". Without stripping the words that carry no
identity — Suite, Server, Software, Platform — every product containing
"Server" matches every other, and the result is thousands of joins that share
one meaningless token.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from core.models import Asset, Confidence, Exploited, Exposure, MatchBasis

#: Words that appear in product names and carry no identity. Kept short and
#: explicit: every entry here is a token that would otherwise create matches
#: between unrelated products, and a long list starts deleting real signal.
STOPWORDS: Set[str] = {
    "and", "the", "for", "inc", "corp", "corporation", "ltd", "llc", "gmbh",
    "suite", "server", "software", "platform", "system", "systems", "service",
    "services", "product", "products", "edition", "enterprise", "manager",
    "management", "solution", "solutions", "application", "applications",
    "framework", "toolkit", "client", "agent", "appliance", "gateway",
}

#: A token this short is an abbreviation or a fragment, and matching on it
#: relates products that share nothing.
MIN_TOKEN = 3

_SPLIT = re.compile(r"[^a-z0-9]+")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def tokens(text: Optional[str]) -> Set[str]:
    """Normalised, identity-bearing tokens of a product or vendor name."""
    if not text:
        return set()
    raw = _SPLIT.split(str(text).lower())
    return {t for t in raw if len(t) >= MIN_TOKEN and t not in STOPWORDS}


def _corresponds(asset_tokens: Set[str], catalogue_tokens: Set[str]) -> Set[str]:
    """The tokens that relate the two names, or an empty set.

    ONE-DIRECTIONAL CONTAINMENT: everything the ASSET claims to be must be
    accounted for by the catalogue entry. Not the reverse, and not "whichever
    side is shorter".

    BOTH OF THE OTHER RULES WERE TRIED AGAINST THE REAL CATALOGUE AND BOTH
    FAILED, in opposite directions:

      shorter-side containment produced a FALSE POSITIVE. An asset running
      `Apache Tomcat` matched catalogue entries whose product is bare `Apache`,
      because {apache} is contained in {apache, tomcat} — so an httpd
      vulnerability was reported against a Tomcat host. The extra token `tomcat`
      is exactly the identity that should have prevented the match, and the rule
      discarded it.

      requiring the asset's PRODUCT alone produced a FALSE NEGATIVE, and a worse
      one. `Ivanti Connect Secure` matched nothing, because the catalogue calls
      it `Connect Secure and Policy Secure` — the asset carries `ivanti` and the
      catalogue product does not, while the catalogue carries `policy` and the
      asset does not. Neither set contains the other. Ivanti Connect Secure has
      thirty-five entries in the catalogue and is among the most exploited
      products in it, so silently missing all of them is not a rounding error.

    The fix for the second is to compare against the vendor and product
    TOGETHER, since `ivanti` is present in the entry — just in the other field.
    The fix for the first falls out of the direction: `tomcat` is unaccounted
    for by an entry that says only `apache`, so the match is refused.

    This fails CLOSED — an inventory that writes `Apache HTTP Server prod
    cluster` will not match, because `prod` and `cluster` are unaccounted for.
    That is the deliberate trade, and it is why `unmatched_assets()` exists: a
    missed match has to be visible somewhere, and a list nobody can trust is
    worse than a list with a stated boundary.
    """
    if not asset_tokens or not catalogue_tokens:
        return set()
    return set(asset_tokens) if asset_tokens <= catalogue_tokens else set()


def declared_cves(asset: Asset) -> Set[str]:
    """CVEs the inventory itself records against this asset.

    Read from any attribute, because inventories name this column everything
    from `cve` to `known_vulns`, and an explicit statement by the customer
    outranks any name matching this module could do.
    """
    found: Set[str] = set()
    for value in list(asset.attributes.values()) + [asset.version]:
        found |= {m.group(0).upper() for m in _CVE.finditer(str(value or ""))}
    return found


def match_asset(asset: Asset, catalogue: Sequence[Exploited]) -> List[Exposure]:
    """Every exploited entry this asset corresponds to."""
    declared = declared_cves(asset)
    asset_product = tokens(asset.product)
    asset_vendor = tokens(asset.vendor)

    out: List[Exposure] = []
    for entry in catalogue:
        # 1. The customer already said so.
        if entry.cve in declared:
            out.append(Exposure(
                asset=asset, exploited=entry,
                basis=MatchBasis.PRODUCT_MATCH,
                confidence=Confidence.STRONG,
                evidence=[f"the inventory names {entry.cve} on this asset"]))
            continue

        # Vendor and product together: the catalogue splits an identity across
        # the two fields and an inventory rarely does. See `_corresponds`.
        catalogue_identity = tokens(entry.product) | tokens(entry.vendor_project)
        product_hit = _corresponds(asset_product, catalogue_identity)
        if not product_hit:
            continue

        # 2/3. Vendor agreement raises confidence; it never creates a match on
        # its own, because a vendor with many products would otherwise match
        # every one of them.
        vendor_hit = _corresponds(asset_vendor, tokens(entry.vendor_project))
        evidence = [f"product: {', '.join(sorted(product_hit))}"]
        if vendor_hit:
            evidence.append(f"vendor: {', '.join(sorted(vendor_hit))}")
        out.append(Exposure(
            asset=asset, exploited=entry,
            basis=MatchBasis.PRODUCT_MATCH,
            confidence=Confidence.STRONG if vendor_hit else Confidence.PARTIAL,
            evidence=evidence))
    return out


def match(assets: Iterable[Asset],
          catalogue: Sequence[Exploited]) -> List[Exposure]:
    """Every exposure across an inventory, ordered by what to look at first."""
    out: List[Exposure] = []
    for asset in assets:
        out.extend(match_asset(asset, catalogue))
    return rank(out)


def rank(exposures: List[Exposure]) -> List[Exposure]:
    """Order for a human working the list top-down.

    WHY THIS ORDER. Ransomware use first, because it is the one attribute that
    changes what a breach costs rather than how likely it is. Then the CISA due
    date, which is a real deadline for federal agencies and a good proxy for
    urgency for everybody else. Then EPSS, which orders within a tie. Confidence
    last: a STRONG match is worth reading before a PARTIAL one, but it should
    never outrank an actual ransomware entry.

    Deliberately NOT a composite score. A single number would need weights, the
    weights would be tuned until the top of the list looked right, and the tuning
    would become the product's real opinion where nobody could inspect it.
    """
    def key(exposure: Exposure) -> Tuple:
        entry = exposure.exploited
        return (
            0 if entry.known_ransomware else 1,
            entry.due_date or entry.date_added,
            -(entry.epss or 0.0),
            0 if exposure.confidence is Confidence.STRONG else 1,
            entry.cve,
        )

    return sorted(exposures, key=key)


def unmatched_assets(assets: Iterable[Asset],
                     exposures: Iterable[Exposure]) -> List[Asset]:
    """Assets that corresponded to nothing in the catalogue.

    THE COUNTERPART TO A FAIL-CLOSED MATCHER. `_corresponds` refuses a join it
    cannot fully account for, which means a real exposure can be missed when an
    inventory writes a product name the catalogue spells differently. That trade
    is only defensible if the misses are VISIBLE, so this is reported beside the
    results rather than left for somebody to notice.

    An empty catalogue and a clean estate produce the same exposure count. This
    is the number that tells them apart: an inventory where nothing matched is
    far more likely to be a naming problem than a secure estate, and a reader who
    sees "0 exposures, 400 assets unmatched" asks the right question.
    """
    matched = {e.asset.identifier for e in exposures}
    return [a for a in assets if a.identifier not in matched]
