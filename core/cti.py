"""Ingested third-party threat intelligence, and the decay that keeps it honest.

Not to be confused with `core/intel.py`, which is the KEV/EPSS/SSVC
*vulnerability* corpus. This module holds what other people publish about
indicators — addresses, names, hashes — and nothing about CVEs.

WHY SKOPOS INGESTS CTI HAVING REFUSED TO PRODUCE IT
------------------------------------------------------
`docs/REFUSALS.md` §1 refuses threat actor attribution, because P3 measured
CVE-to-technique-to-group at a **median of 57 groups per CVE**, and an
attribution naming 57 groups is a list of everybody delivered with the
confidence of a finding.

That refusal is about SKOPOS *inferring* attribution. It says nothing about
carrying somebody else's, and the distinction is the one SSVC already turns on:
a stated judgement with a named author is categorically different from an
inference this product would be making up. When CIRCL publishes an event saying
an address served a particular family, SKOPOS can repeat that **with CIRCL's
name and CIRCL's date attached** without asserting anything of its own.

So everything here is somebody else's claim, carried with its provenance. There
is no field in this module for SKOPOS's own opinion of an indicator, and adding
one would be the mistake.

THE MEASUREMENT THAT SHAPED THIS MODULE
------------------------------------------
Measured 2026-08-24 against CIRCL's OSINT feed — the default MISP feed, and the
one most deployments start with:

| Feed age            |   Events | Share |
|---------------------|---------:|------:|
| 2026                |      292 | 17.4% |
| 2025                |       31 |  1.8% |
| **older than 2020** | **1,143**| **68.0%** |

The two largest years are **2016 (20.7%) and 2017 (20.4%)**. Only 19.2% of the
feed is from 2025 or later.

Ingesting that flat would pour decade-old indicators into an estate report as
though they were current intelligence. An address that served malware in 2016
has been reassigned several times since; a hit on it today is a fact about a
2016 lease, not about whoever holds it now.

**That is why decay is the centre of this module rather than a refinement of
it.** Without decay, MISP ingestion is a machine for generating confident
nonsense.

DECAY IS PER-TYPE, BECAUSE INDICATOR TYPES AGE DIFFERENTLY
-------------------------------------------------------------
One half-life across all indicators would be wrong in both directions:

- **Addresses are leases.** Cloud and hosting ranges churn constantly. An IPv4
  indicator says who held the address then, and decays fastest.
- **Names are owned.** A registration persists, so a domain indicator stays
  meaningful considerably longer than an address.
- **Hashes are the artefact itself.** A file whose SHA-256 matched a malicious
  sample in 2014 is still that same malicious file today. There is nothing to
  decay, and applying a half-life would discard true information.

`HALF_LIFE_DAYS` therefore carries a **zero** for hash types, meaning *does not
decay*. That zero is a deliberate value, not a missing one.

WHAT A SIGHTING IS NOT
-------------------------
Identical in spirit to `core/blocklists.py`, and for the same reasons. A
sighting means: *this exact value appears in this named source's published
intelligence, dated thus.* It does not mean the asset is compromised, that the
activity is current, that the source is right, or that absence is evidence of
anything. `WHAT_A_SIGHTING_IS_NOT` states all four and travels with the export.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = ROOT / "data" / "cti.json"


class CTIUnavailable(RuntimeError):
    """No ingested corpus. Callers report the absence rather than scoring 0."""


# ── traffic light protocol ──────────────────────────────────────────────────
#: TLP is the one piece of CTI metadata with a REDISTRIBUTION consequence, so
#: it is modelled rather than carried as a free-text tag. A platform that
#: ingests TLP:RED and then exports it has broken the terms it received the
#: intelligence under, and no amount of downstream care repairs that.
#:
#: Ordered permissive → restrictive. `AMBER_STRICT` is TLP 2.0's addition,
#: meaning "your organisation only, not your clients".
TLP_ORDER: Tuple[str, ...] = ("WHITE", "CLEAR", "GREEN", "AMBER",
                              "AMBER_STRICT", "RED")

#: Above this, an indicator may not leave SKOPOS through an automated export.
#: SKOPOS exports to consumers it cannot see — a SIEM, a partner's OpenCTI — so
#: the ceiling sits where a human would have to make the call instead.
MAX_EXPORTABLE_TLP = "GREEN"


def exportable(tlp: str) -> bool:
    """Whether an indicator at this marking may leave SKOPOS automatically.

    An unrecognised marking is treated as RESTRICTED rather than permissive. A
    feed inventing a marking this does not know is far more likely to be
    tightening than loosening, and the failure direction matters more than the
    convenience.
    """
    mark = str(tlp or "").strip().upper().replace(":", "_").replace("-", "_")
    if mark.startswith("TLP_"):
        mark = mark[4:]
    if mark not in TLP_ORDER:
        return False
    return TLP_ORDER.index(mark) <= TLP_ORDER.index(MAX_EXPORTABLE_TLP)


# ── sources ─────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class CTISource:
    """One publisher of intelligence, and the terms it arrives under."""

    name: str
    url: str
    publisher: str
    licence: str
    #: What an entry from this source actually asserts, in the publisher's own
    #: terms. Rendered on every sighting — a source name alone tells a reader
    #: nothing about what membership of it means.
    means: str
    #: False where the licence excludes commercial use. Mirrors
    #: `core/blocklists.py:NONCOMMERCIAL`, so a commercial deployment can be
    #: told which parts of its corpus to drop rather than reading licences.
    commercial_use: bool = True
    #: Whether the bulk feed needs no credential. Keyless sources can be
    #: vendored and are reproducible; keyed ones are not.
    keyless: bool = True


SOURCES: Sequence[CTISource] = (
    CTISource(
        "circl_osint", "https://www.circl.lu/doc/misp/feed-osint/",
        "CIRCL", "CC-BY-SA 4.0",
        "an attribute of a published MISP event — CIRCL's curated OSINT feed, "
        "assembled from public reporting"),
    CTISource(
        "threatfox", "https://threatfox.abuse.ch/export/json/recent/",
        "abuse.ch", "CC0",
        "an indicator abuse.ch associated with a named malware family, "
        "submitted with the reporter's own confidence percentage"),
    CTISource(
        "malwarebazaar", "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "abuse.ch", "CC0",
        "the SHA-256 of a sample abuse.ch holds in its malware corpus"),
)

BY_NAME: Dict[str, CTISource] = {s.name: s for s in SOURCES}

#: Sources evaluated and NOT carried, with the measurement that excluded each.
#: Recorded rather than silently omitted, on `core/blocklists.py:EXCLUDED`'s
#: reasoning: the next person to read a blog post recommending OTX should find
#: out here why it is absent, rather than by shipping it.
EXCLUDED: Dict[str, str] = {
    "alienvault_otx":
        "Measured 2026-08-24: /api/v1/pulses/subscribed answers 403 without an "
        "API key. A keyed bulk feed cannot be vendored, so a scan against it "
        "is not reproducible by whoever reads the report. Reachable through "
        "collect/keyed_sources.py once a key exists.",
    "censys":
        "Measured 2026-08-24: /api/v2/hosts answers 401 without credentials, "
        "and the free tier excludes commercial use.",
    "virustotal":
        "An enrichment service, not a feed — there is no bulk download to "
        "vendor, and the free tier is rate-limited and non-commercial.",
    "greynoise_community":
        "Keyless and working (measured 2026-08-24: 185.220.101.1 returns "
        "classification=malicious), but it answers PER ADDRESS rather than in "
        "bulk, so it is enrichment rather than a corpus. It also answers about "
        "the internet's scanners, not about an estate's assets — the wrong "
        "direction for this module. Belongs in collect/, not here.",
}


# ── decay ───────────────────────────────────────────────────────────────────
#: Days for an indicator's weight to halve. **Zero means it does not decay.**
#:
#: These are judgements rather than measurements, and are stated as such. What
#: each encodes is how long the thing an indicator names stays the same thing.
HALF_LIFE_DAYS: Dict[str, int] = {
    # A lease. Cloud and hosting ranges churn on a scale of weeks.
    "ipv4": 30,
    "ipv6": 30,
    # A registration. Persists for years, and a malicious domain is usually
    # malicious for its whole life rather than for a window of it.
    "domain": 90,
    "hostname": 90,
    # A path on a host. Outlives the address, rarely outlives the domain.
    "url": 60,
    # An address a human keeps.
    "email": 180,
    # THE ARTEFACT ITSELF. A file that was malicious in 2014 is still that
    # file. Nothing about it has aged, so nothing is discounted. This zero is
    # a decision, not a gap.
    "md5": 0,
    "sha1": 0,
    "sha256": 0,
}

#: Weight below which an indicator is not reported at all. 0.05 is a little
#: over four half-lives — 130 days for an address, 390 for a domain. Past that
#: the indicator describes a world that has moved on, and surfacing it costs a
#: reader more attention than it returns.
REPORT_FLOOR = 0.05

#: What an unparseable date counts as. Enormous on purpose: treating a corrupt
#: stamp as "today" silently promotes junk to fresh intelligence, which is the
#: one direction this must not fail in. Mirrors `blocklists.UNDATED`.
UNDATED = 10 ** 6


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _age_days(stamp: str, today: Optional[date] = None) -> int:
    """Days between `stamp` (ISO date, optionally with a time) and today."""
    text = str(stamp or "").strip()
    if not text:
        return UNDATED
    for cut in ("T", " "):
        if cut in text:
            text = text.split(cut, 1)[0]
    try:
        when = date.fromisoformat(text)
    except ValueError:
        return UNDATED
    delta = (today or _today()) - when
    # A future date is not fresher than today. Feeds do publish them, usually
    # from a timezone error, and rewarding one would let a broken publisher
    # outrank a correct one.
    return max(0, delta.days)


def weight(kind: str, age_days: int) -> float:
    """Exponential decay: `2 ** (-age / half_life)`, clamped to [0, 1].

    Exponential rather than linear because intelligence does not expire on a
    date — it becomes progressively less likely to still describe the world. A
    linear model would treat the 89th day of a 90-day window as nearly as good
    as the first and then discard it entirely on the 91st.
    """
    half_life = HALF_LIFE_DAYS.get(str(kind or "").lower())
    if half_life is None:
        # An unknown type decays on the shortest curve rather than the longest.
        # Guessing generously about something we cannot classify is how a
        # corpus fills with indicators nobody can defend.
        half_life = min(h for h in HALF_LIFE_DAYS.values() if h > 0)
    if half_life == 0:
        return 1.0
    if age_days >= UNDATED:
        return 0.0
    return max(0.0, min(1.0, 2.0 ** (-float(age_days) / float(half_life))))


# ── the records ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Indicator:
    """One published claim, about one value, from one source, on one date."""

    value: str
    #: "ipv4" | "domain" | "url" | "sha256" | ... See HALF_LIFE_DAYS.
    kind: str
    source: str
    publisher: str
    #: The date the SOURCE attached to the claim, never the date SKOPOS fetched
    #: it. `core/blocklists.py` learned this distinction the hard way: Feodo
    #: Tracker served a list on 2026-08-23 whose own header said 2026-03-04.
    seen_on: str
    #: The source's own words for what this is — a MISP event's `info`, a
    #: ThreatFox malware family. Never SKOPOS's characterisation.
    context: str = ""
    #: The source's own tags, verbatim, including its TLP marking.
    tags: Tuple[str, ...] = ()
    tlp: str = "WHITE"
    #: The publishing organisation the source itself names, where it names one.
    #: MISP events carry `Orgc`; the abuse.ch bulk feeds do not.
    reporter: str = ""

    def age_days(self, today: Optional[date] = None) -> int:
        return _age_days(self.seen_on, today)

    def weight(self, today: Optional[date] = None) -> float:
        return weight(self.kind, self.age_days(today))

    def decays(self) -> bool:
        return HALF_LIFE_DAYS.get(self.kind.lower(), 1) != 0

    def to_dict(self, today: Optional[date] = None) -> Dict[str, Any]:
        age = self.age_days(today)
        return {
            "value": self.value,
            "kind": self.kind,
            "source": self.source,
            "publisher": self.publisher,
            "reporter": self.reporter or None,
            "seen_on": self.seen_on,
            "age_days": None if age >= UNDATED else age,
            "weight": round(self.weight(today), 4),
            "decays": self.decays(),
            "context": self.context,
            "tags": list(self.tags),
            "tlp": self.tlp,
            "exportable": exportable(self.tlp),
        }


#: Travels with every export, for the reason `core/stix.py` puts its caveat
#: inside the bundle: a caveat that stays behind in the console is not a caveat.
WHAT_A_SIGHTING_IS_NOT: Tuple[str, ...] = (
    "NOT a statement that the asset is compromised. Shared hosting, CDNs and "
    "cloud egress ranges put unrelated tenants behind one address.",
    "NOT a statement that the activity is current. The weight is how far the "
    "age discounts it — 68% of CIRCL's OSINT feed predates 2020.",
    "NOT a judgement by SKOPOS. Every field is the named source's own claim, "
    "carried with its date. SKOPOS holds no opinion about an indicator.",
    "NOT falsifiable by absence. No source observes everything, and a value "
    "appearing in none of them has not been cleared by any of them.",
)


@dataclass(frozen=True)
class Sighting:
    """An estate value matched a published indicator. An observation."""

    asset: str
    indicator: Indicator
    #: How the match was made. Stated because not all matches are equally
    #: strong and a reader deserves to know which happened.
    how: str = "exact"

    def weight(self, today: Optional[date] = None) -> float:
        return self.indicator.weight(today)

    def to_dict(self, today: Optional[date] = None) -> Dict[str, Any]:
        source = BY_NAME.get(self.indicator.source)
        return {
            "asset": self.asset,
            "how": self.how,
            "weight": round(self.weight(today), 4),
            "indicator": self.indicator.to_dict(today),
            "means": source.means if source else "",
            "not": list(WHAT_A_SIGHTING_IS_NOT),
        }


def describe_absence(indicators: int, sources: int) -> str:
    """What it means that an asset matched nothing.

    Deliberately not "clean". `core/blocklists.py:describe_absence` exists for
    the same reason: a scanner that reports absence as safety teaches its
    readers to treat silence as evidence.
    """
    return (
        f"No match across {indicators:,} live indicators from {sources} "
        "sources. This is not a clean bill of health: these sources observe a "
        "small fraction of the internet, most report only what was submitted "
        "to them, and an indicator decayed below the reporting floor is not "
        "shown even where it once matched."
    )


# ── the corpus ──────────────────────────────────────────────────────────────
class CTICorpus:
    """The vendored ingested-intelligence corpus, and lookups against it.

    VENDORED FOR THE REASON `core/blocklists.py` GIVES
    ----------------------------------------------------
    A scan that depends on a network round trip depends on a rate limit and on
    whatever the publisher served in that second, so two people scanning the
    same estate an hour apart get different answers and neither can say why.
    Refreshed deliberately by `tools/refresh_intel.py --only-cti`.
    """

    def __init__(self, payload: Dict[str, Any]) -> None:
        self._meta: Dict[str, Any] = dict(payload.get("_meta") or {})
        self._by_value: Dict[str, List[Indicator]] = {}
        self._count = 0
        for raw in payload.get("indicators") or ():
            item = Indicator(
                value=str(raw.get("value") or "").strip(),
                kind=str(raw.get("kind") or "").strip().lower(),
                source=str(raw.get("source") or ""),
                publisher=str(raw.get("publisher") or ""),
                seen_on=str(raw.get("seen_on") or ""),
                context=str(raw.get("context") or ""),
                tags=tuple(raw.get("tags") or ()),
                tlp=str(raw.get("tlp") or "WHITE"),
                reporter=str(raw.get("reporter") or ""),
            )
            if not item.value:
                continue
            self._by_value.setdefault(item.value.lower(), []).append(item)
            self._count += 1

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "CTICorpus":
        target = Path(path) if path else DEFAULT_PATH
        if not target.exists():
            raise CTIUnavailable(
                f"No ingested intelligence at {target}. Build it with "
                f"`python tools/refresh_intel.py --only-cti`.")
        with target.open("r", encoding="utf-8") as handle:
            return cls(json.load(handle))

    # -- lookups -------------------------------------------------------------
    def lookup(self, value: str,
               today: Optional[date] = None,
               floor: float = REPORT_FLOOR) -> List[Indicator]:
        """Every indicator for this exact value still above the floor.

        Sorted by weight descending, so the freshest claim leads regardless of
        which source supplied it.
        """
        found = self._by_value.get(str(value or "").strip().lower(), [])
        alive = [i for i in found if i.weight(today) >= floor]
        return sorted(alive, key=lambda i: (-i.weight(today), i.source))

    def correlate(self, assets: Iterable[str],
                  today: Optional[date] = None,
                  floor: float = REPORT_FLOOR) -> List[Sighting]:
        """Match an estate against the corpus.

        EXACT MATCHES ONLY. A suffix or substring match would turn one listed
        subdomain into a sighting against the whole registrable domain, which
        is precisely the class of overclaim this product exists to avoid.
        """
        out: List[Sighting] = []
        for asset in assets:
            name = str(asset or "").strip()
            if not name:
                continue
            for indicator in self.lookup(name, today, floor):
                out.append(Sighting(name, indicator, "exact"))
        return sorted(out, key=lambda s: (-s.weight(today), s.asset))

    # -- provenance ----------------------------------------------------------
    @property
    def built_on(self) -> str:
        return str(self._meta.get("built_on") or "")

    @property
    def count(self) -> int:
        return self._count

    def sources(self) -> List[str]:
        return sorted({i.source for items in self._by_value.values()
                       for i in items})

    def coverage(self, today: Optional[date] = None) -> Dict[str, Any]:
        """What the corpus holds, and how much of it has already decayed.

        The decayed count is reported rather than hidden. A corpus of 60,000
        indicators of which 50,000 sit below the floor is a smaller corpus than
        its headline, and the operator should be told which one they have.
        """
        live = decayed = 0
        by_source: Dict[str, int] = {}
        by_kind: Dict[str, int] = {}
        for items in self._by_value.values():
            for item in items:
                if item.weight(today) >= REPORT_FLOOR:
                    live += 1
                    by_source[item.source] = by_source.get(item.source, 0) + 1
                    by_kind[item.kind] = by_kind.get(item.kind, 0) + 1
                else:
                    decayed += 1
        return {
            "built_on": self.built_on,
            "indicators": self._count,
            "live": live,
            "decayed_below_floor": decayed,
            "report_floor": REPORT_FLOOR,
            "by_source": dict(sorted(by_source.items())),
            "by_kind": dict(sorted(by_kind.items())),
            "half_lives": dict(HALF_LIFE_DAYS),
            "excluded_sources": dict(EXCLUDED),
            "absence_means": describe_absence(live, len(by_source)),
        }


# ── promotion: sightings become findings ────────────────────────────────────
#: How old the corpus may be before absence stops meaning much. Shorter than
#: `blocklists.STALE_AFTER_DAYS` (14) would be false precision, longer would let
#: a quiet report rest on a corpus nobody refreshed. Same number, same reason.
STALE_AFTER_DAYS = 14

#: A sighting the source tied to a named actor, malware family or campaign
#: reads differently from a bare listing, so it fires a different rule. The
#: marker is what `collect/stix_ingest.py` writes into `context`.
_ATTRIBUTED = ("(threat-actor)", "(intrusion-set)", "(campaign)",
               "(malware)", "(tool)")


def _is_attributed(context: str) -> bool:
    return any(marker in str(context or "") for marker in _ATTRIBUTED)


def findings(sightings: Iterable["Sighting"],
             today: Optional[date] = None) -> List[Dict[str, Any]]:
    """Sightings → finding dicts carrying the rule that fired.

    THE SEVERITY IS THE RULE'S, NOT A COMPUTED ONE. `core/rules.py` states what
    each rule does and does not establish, and the limits travel on the finding
    so the caveat cannot be left behind in the console.

    `intel_weight` is passed through for `scoring.AdversaryInterest`. It is
    already decayed for age, so a 2016 listing contributes nothing without a
    special case anywhere downstream.
    """
    from core import rules as _rules

    out: List[Dict[str, Any]] = []
    for sighting in sightings:
        indicator = sighting.indicator
        attributed = _is_attributed(indicator.context)
        rule_id = ("cti.asset_named_by_actor_report" if attributed
                   else "cti.asset_in_intelligence")
        rule = _rules.BY_ID.get(rule_id)
        out.append({
            "rule": rule_id,
            "severity": rule.severity.value if rule else "act",
            "asset": sighting.asset,
            "source": indicator.source,
            "publisher": indicator.publisher,
            "reporter": indicator.reporter or None,
            "seen_on": indicator.seen_on,
            "age_days": (None if indicator.age_days(today) >= UNDATED
                         else indicator.age_days(today)),
            # Feeds AdversaryInterest.observed_in_intel. Already age-decayed.
            "intel_weight": round(sighting.weight(today), 4),
            "context": indicator.context,
            "actor": indicator.context if attributed else None,
            "tlp": indicator.tlp,
            "exportable": exportable(indicator.tlp),
            "limits": rule.limits if rule else "",
            "not": list(WHAT_A_SIGHTING_IS_NOT),
        })
    return sorted(out, key=lambda f: (-f["intel_weight"], f["asset"]))


def corpus_age_finding(corpus: "CTICorpus",
                       today: Optional[date] = None) -> Optional[Dict[str, Any]]:
    """A COVERAGE finding when the corpus is stale. About SKOPOS, not an asset.

    Emitted so a reader does not mistake a stale corpus for a quiet estate —
    the same failure `describe_absence` guards against, raised to a finding
    where it is old enough to matter.
    """
    age = _age_days(corpus.built_on, today)
    if age < STALE_AFTER_DAYS:
        return None
    from core import rules as _rules
    rule = _rules.BY_ID.get("cti.stale_corpus")
    return {
        "rule": "cti.stale_corpus",
        "severity": rule.severity.value if rule else "context",
        "built_on": corpus.built_on or None,
        "age_days": None if age >= UNDATED else age,
        "stale_after_days": STALE_AFTER_DAYS,
        "means": (f"The CTI corpus was built {age} days ago. A result of no "
                  "sightings reflects that age as much as it reflects the "
                  "estate. Refresh with "
                  "`python tools/refresh_intel.py --only-cti`."),
        "limits": rule.limits if rule else "",
    }


def highest_weight(sightings: Iterable["Sighting"],
                   today: Optional[date] = None) -> float:
    """The strongest surviving sighting, for `AdversaryInterest`.

    Highest rather than summed: three sources repeating one vendor's list is
    not three times the evidence, and summing would reward redundancy in a
    corpus built by aggregating aggregators.
    """
    return max((s.weight(today) for s in sightings), default=0.0)
