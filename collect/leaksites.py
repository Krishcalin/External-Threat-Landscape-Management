"""Ransomware leak-site victim indexes, and the line this stops at.

WHY THIS IS THE ONE COLLECTION GAP WORTH CLOSING
--------------------------------------------------
A supplier appearing on an extortion site is the highest-signal observation an
outside-in product can make. It arrives *before* the disclosure letter — often
weeks before — and unlike almost everything else here it needs no inference: the
group published a claim, on a date, under its own name.

Recorded Future sells this inside Third-Party Intelligence. It is the only
capability of theirs SKOPOS was structurally able to add, and the reason is
narrow: **leak-site victim indexes are public pages.**

WHAT FR-GOV-003 PERMITS, AND EXACTLY WHERE THIS STOPS
-------------------------------------------------------
The rule prohibits authenticating to, transacting on, or scraping
access-controlled criminal forums. It permits public index pages. So:

  PERMITTED     the victim list — who a group says it hit, and when
  PROHIBITED    the negotiation portal, any login, any chat
  PROHIBITED    the published archive itself, even where it needs no credential

That last one is a choice rather than a reading of the rule, and `core/gate.py`
now carries `leak_data_download` as PROHIBITED to make it structural. The
material is stolen, it routinely contains personal data belonging to people who
are not this product's customers, and no question SKOPOS answers requires
possessing it. **Knowing a victim was listed is the finding. The archive is not.**

WHY AN AGGREGATOR RATHER THAN .onion DIRECTLY
-----------------------------------------------
Crawling Tor hidden services would mean this product running Tor, holding
circuits open to criminal infrastructure, and fetching from hosts whose content
it has just refused to download. A public aggregator that has already done the
indexing gives the same observation with none of that, and — the part that
matters more — it makes the corpus VENDORABLE, so a lookup is a dictionary
lookup rather than a network call. Same shape as `core/blocklists.py`.

WHAT A MATCH IS, AND WHY IT CARRIES CONFIDENCE
------------------------------------------------
Matching is on NAME, and names are ambiguous. "Acme Ltd" on a leak site is not
necessarily your Acme Ltd, and a product that alerted as though it were would be
telling a customer their supplier had been breached on the strength of a string.

So every match carries a confidence and the reason for it, `EXACT` is reserved
for a normalised full-string match, and the panel renders the group's own claim
verbatim rather than paraphrasing it into a finding.

THIS IS NOT AN ATTRIBUTION
----------------------------
A group claiming a victim is a claim by that group. Groups exaggerate, recycle
old data, and occasionally list victims they never breached. P3 closed actor
attribution at a median of 57 groups per CVE; this does not reopen it. What it
observes is narrower and more useful: *this name appeared on this group's
public index on this date*, which is a fact about the index.
"""
from __future__ import annotations

# NETWORK-BOUNDARY: leak_index_read

import json
import os
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = ROOT / "data" / "leaksites.json"

OPERATION = "leak_index_read"

#: The aggregator. Public API over already-indexed victim listings, so this
#: product never opens a circuit to a hidden service itself.
SOURCE_URL = "https://api.ransomware.live/v2/recentvictims"
SOURCE_NAME = "ransomware.live"
SOURCE_TERMS = ("Public aggregator of ransomware leak-site victim listings. "
                "Free, no key. Indexes what groups published themselves.")

USER_AGENT = "SKOPOS/1.0 (+https://github.com/Krishcalin; ETLM; passive read)"

#: A listing older than this is history rather than warning. Not dropped —
#: reported with its age, because "listed 14 months ago" is still a fact about a
#: supplier and its absence from a report would be a worse error.
RECENT_DAYS = 90


class Confidence(str):
    """Deliberately a plain string type rather than an enum with an ordering.

    An ordering invites comparison, comparison invites a threshold, and a
    threshold invites somebody to alert on `>= PARTIAL`. Every match is meant
    to be read, not filtered numerically.
    """


#: Strongest, and it is not a name match at all. The aggregator publishes a
#: `domain` per listing, and a domain is what the scope register actually holds
#: — so this compares like with like instead of comparing a company name to a
#: company name and hoping. Discovered by reading a real response rather than
#: the documentation, which named no such field.
DOMAIN = "domain"
EXACT = "exact"
STRONG = "strong"
PARTIAL = "partial"

CONFIDENCE_MEANING = {
    DOMAIN: ("the listing's own domain field matches a name in scope. This "
             "compares a domain to a domain rather than a company name to a "
             "company name, which removes almost all of the ambiguity — it is "
             "the strongest match available here and the only one that should "
             "be acted on without confirming first."),
    EXACT: ("the normalised victim name and the registered name are identical. "
            "Still not proof — company names are not unique across "
            "jurisdictions — but there is nothing further to check in the "
            "string itself."),
    STRONG: ("the victim name matches after removing corporate suffixes "
             "(Ltd, Inc, GmbH). Worth acting on; confirm before telling "
             "anybody their supplier was breached."),
    PARTIAL: ("one name contains the other. Frequently a coincidence — 'Delta' "
              "matches a great many companies — and shown so somebody can "
              "judge, never so a rule can fire."),
}

#: Stripped before comparison. A group writes "ACME" where the register says
#: "Acme Holdings Ltd", and a comparison that misses that misses most matches.
_SUFFIXES = ("ltd", "limited", "inc", "incorporated", "llc", "plc", "gmbh",
             "ag", "sa", "srl", "bv", "nv", "pty", "pvt", "private",
             "corporation", "corp", "co", "company", "holdings", "group",
             "international", "technologies", "technology", "solutions",
             "services", "systems")

_PUNCT = re.compile(r"[^a-z0-9 ]+")
_SPACE = re.compile(r"\s+")


class CorpusUnavailable(RuntimeError):
    """No vendored corpus. Distinct from a corpus with no matches."""


@dataclass(frozen=True)
class Listing:
    """One victim claim, as the group published it."""

    victim: str
    group: str
    published: str
    #: The victim's domain, where the aggregator resolved one. Worth more than
    #: every other field here combined: it is the only one directly comparable
    #: to what a scope register holds.
    domain: str = ""
    #: The group's own description, carried verbatim. Never paraphrased into a
    #: finding — the distinction between what was claimed and what is true is
    #: the entire content of this record.
    claim: str = ""
    country: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"victim": self.victim, "group": self.group,
                "published": self.published, "domain": self.domain,
                "claim": self.claim, "country": self.country}


@dataclass(frozen=True)
class Match:
    listing: Listing
    matched_against: str
    confidence: str
    days_old: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.listing.to_dict(),
            "matched_against": self.matched_against,
            "confidence": self.confidence,
            "confidence_means": CONFIDENCE_MEANING[self.confidence],
            "days_old": self.days_old,
            "recent": self.days_old <= RECENT_DAYS,
            "basis": (
                f"{self.listing.group} published this name on its own public "
                f"victim index. That is a CLAIM BY THAT GROUP, not a confirmed "
                f"breach: groups exaggerate, recycle old data, and occasionally "
                f"list victims they never reached. SKOPOS reports that the "
                f"listing exists and does not download what was published."),
        }


def normalise(name: str) -> str:
    """A company name reduced to something comparable."""
    text = _PUNCT.sub(" ", str(name or "").strip().lower())
    words = [w for w in _SPACE.sub(" ", text).split() if w]
    while words and words[-1] in _SUFFIXES:
        words.pop()
    return " ".join(words)


def compare_domain(listing_domain: str, known: str) -> Optional[str]:
    """A domain-to-domain comparison, which is worth more than any name match.

    Matches the registrable domain, so `mail.acme.com` in scope matches a
    listing whose domain is `acme.com`. Subdomain-level equality would miss
    most real matches: the aggregator records the company's main domain and a
    scope register frequently holds a specific host.
    """
    left = str(listing_domain or "").strip().lower().rstrip(".")
    right = str(known or "").strip().lower().rstrip(".")
    if not left or not right or "." not in left:
        return None
    if left == right:
        return DOMAIN
    # One is a suffix of the other, ON A LABEL BOUNDARY. `acme.com` matches
    # `mail.acme.com`; it must not match `notacme.com`.
    #
    # BOTH sides must contain a dot before a suffix match is allowed. Without
    # that, a scope entry of `com` matches every .com listing in the corpus,
    # because "acme.com".endswith(".com") is perfectly true — a single bare
    # label in scope would turn this from a monitor into a firehose.
    if "." not in right:
        return None
    if right.endswith("." + left) or left.endswith("." + right):
        return DOMAIN
    return None


def compare(victim: str, known: str) -> Optional[str]:
    """How well a leak-site victim name matches a name we hold, or None.

    Returns the confidence rather than a boolean, because the caller must not
    be able to treat a partial match as a match without saying so.
    """
    left, right = normalise(victim), normalise(known)
    if not left or not right:
        return None
    if left == right:
        # Exact only after normalisation of BOTH sides; raw equality would miss
        # "ACME LTD" against "Acme Ltd" and call it nothing.
        return EXACT if victim.strip().lower() == known.strip().lower() else STRONG
    # A one-word name is far too generous a substring. "Delta" appears inside
    # enough real company names to make every listing a partial match.
    if len(left) < 5 or len(right) < 5:
        return None
    if left in right or right in left:
        return PARTIAL
    return None


def _age(published: str, today: Optional[date] = None) -> int:
    try:
        then = date.fromisoformat(str(published)[:10])
    except (TypeError, ValueError):
        return 10 ** 6
    return ((today or datetime.now(timezone.utc).date()) - then).days


class LeakSites:
    """The vendored index, queried in process. No network, no Tor, no fetch."""

    def __init__(self, payload: Dict[str, Any]) -> None:
        self._meta = payload.get("_meta") or {}
        self._listings: List[Listing] = []
        for row in payload.get("listings") or []:
            victim = str(row.get("victim") or "").strip()
            if not victim:
                continue
            self._listings.append(Listing(
                victim=victim,
                group=str(row.get("group") or "unknown"),
                published=str(row.get("published") or ""),
                domain=str(row.get("domain") or "").strip().lower(),
                claim=str(row.get("claim") or ""),
                country=str(row.get("country") or "")))

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "LeakSites":
        target = Path(path or os.environ.get("SKOPOS_LEAKSITES_PATH")
                      or DEFAULT_PATH)
        if not target.exists():
            raise CorpusUnavailable(
                f"no vendored leak-site index at {target}. Run "
                f"`python tools/refresh_intel.py --only-leaksites`. Until then "
                f"SKOPOS reports leak-site coverage as ABSENT rather than "
                f"reporting that nobody was listed.")
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CorpusUnavailable(f"{target} could not be read: {exc}") from exc
        return cls(payload)

    def check(self, names: Sequence[str],
              today: Optional[date] = None) -> List[Match]:
        """Every listing matching any of these names.

        Sorted by confidence then recency, so the strongest and newest claim
        about a name is the first thing read.
        """
        order = {DOMAIN: 0, EXACT: 1, STRONG: 2, PARTIAL: 3}
        matches: List[Match] = []
        for listing in self._listings:
            best: Optional[tuple] = None
            for name in names:
                # Domain first, always. It compares like with like, so a domain
                # hit must not be shadowed by a weaker name hit on some other
                # entry in the same list.
                confidence = (compare_domain(listing.domain, name)
                              or compare(listing.victim, name))
                if confidence is None:
                    continue
                if best is None or order[confidence] < order[best[1]]:
                    best = (name, confidence)
                if confidence == DOMAIN:
                    break
            if best is not None:
                matches.append(Match(listing, best[0], best[1],
                                     _age(listing.published, today)))
        matches.sort(key=lambda m: (order[m.confidence], m.days_old))
        return matches

    @property
    def built_on(self) -> str:
        return str(self._meta.get("built_on") or "")

    def coverage(self, today: Optional[date] = None) -> Dict[str, Any]:
        groups = sorted({l.group for l in self._listings})
        ages = [_age(l.published, today) for l in self._listings
                if l.published]
        return {
            "built_on": self.built_on,
            "listings": len(self._listings),
            "groups": len(groups),
            "group_names": groups,
            "source": SOURCE_NAME,
            "newest_days_old": min(ages) if ages else None,
            "oldest_days_old": max(ages) if ages else None,
            "absence_means": describe_absence(len(self._listings)),
        }


def describe_absence(listings: int) -> str:
    """What 'not listed' is worth. Rendered wherever a zero appears.

    The most important sentence in this module. Leak sites index a fraction of
    ransomware activity: groups that do not publish, victims who paid before
    publication, and every intrusion that was not ransomware are all invisible
    here. Not being listed is the normal state of a breached organisation.
    """
    return (
        f"No name matched across {listings:,} indexed listings. This covers only "
        f"groups that RUN a public leak site and only victims they chose to "
        f"publish — organisations that paid before publication, groups that do "
        f"not publish at all, and every intrusion that was not ransomware are "
        f"all absent from it. Not being listed is the normal state of a "
        f"breached organisation and must never be shown as reassurance.")


def fetch(permit, budget=None, limiter=None) -> Dict[str, Any]:
    """Read the aggregator's public index. The ONLY network call in this module.

    Takes a permit like every other collector, so the read appears in the audit
    log under `leak_index_read` alongside the operations that were refused.
    """
    from collect import egress

    response = egress.http_get(permit, OPERATION, SOURCE_URL,
                               budget=budget, limiter=limiter,
                               headers={"User-Agent": USER_AGENT,
                                        "Accept": "application/json"})
    if response.status != 200:
        raise CorpusUnavailable(
            f"{SOURCE_NAME} returned HTTP {response.status}")
    return shape(response.text)


def shape(body: str) -> Dict[str, Any]:
    """The aggregator's JSON to a vendorable corpus. Split out so it is
    testable without a network."""
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise CorpusUnavailable(f"unparseable body: {exc}") from exc
    rows = payload if isinstance(payload, list) else payload.get("data") or []

    listings: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        victim = str(row.get("victim") or row.get("post_title") or "").strip()
        if not victim:
            continue
        # Field names taken from a REAL response, not the documentation: the
        # live records carry `attackdate` and `discovered`, and no `published`
        # at all. `attackdate` first because when the group says it happened is
        # closer to the event than when an aggregator noticed the post.
        published = str(row.get("attackdate") or row.get("discovered")
                        or row.get("published") or "")
        listings.append({
            "victim": victim,
            "group": str(row.get("group") or row.get("group_name")
                         or "unknown").strip(),
            "published": published[:10],
            "domain": str(row.get("domain") or "").strip().lower(),
            # Truncated hard. The description field on these sites carries the
            # group's boasting and occasionally fragments of stolen data; a few
            # hundred characters is enough to show what was claimed.
            "claim": str(row.get("description") or "")[:400],
            "country": str(row.get("country") or "")[:8],
        })
    return {
        "_meta": {
            "built_on": datetime.now(timezone.utc).date().isoformat(),
            "source": SOURCE_NAME,
            "source_url": SOURCE_URL,
            "terms": SOURCE_TERMS,
            "listings": len(listings),
            "note": ("Victim names published by ransomware groups on their own "
                     "public index pages. A listing is a CLAIM BY THAT GROUP. "
                     "SKOPOS reads the index and never downloads what was "
                     "published — see core/gate.py leak_data_download."),
        },
        "listings": listings,
    }


__all__ = ["LeakSites", "Listing", "Match", "OPERATION", "SOURCE_NAME",
           "SOURCE_URL", "CorpusUnavailable", "DEFAULT_PATH", "RECENT_DAYS",
           "EXACT", "STRONG", "PARTIAL", "CONFIDENCE_MEANING",
           "normalise", "compare", "fetch", "shape", "describe_absence"]
