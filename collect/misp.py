"""Parse a published MISP feed into SKOPOS indicators.

NO NETWORK IN THIS MODULE. Like `collect/shadowserver.py`, everything here is a
pure function over bytes already fetched. `tools/refresh_intel.py:fetch_cti()`
does the retrieval, so the parser is testable against a fixture and a refresh
failure is a refresh failure rather than a scan failure.

WHAT A MISP FEED IS
----------------------
A directory of static JSON, servable from any web root and needing no MISP
instance and no credential:

    manifest.json          {event-uuid: {info, date, Orgc, Tag, ...}, ...}
    <event-uuid>.json      {"Event": {..., "Attribute": [...]}}

CIRCL's OSINT feed is the default in MISP's own configuration and the one most
deployments start with. Measured 2026-08-24: 1,680 events, served over HTTPS,
no key.

THE `to_ids` FLAG IS THE WHOLE FILTER, AND IT MATTERS MORE THAN IT LOOKS
--------------------------------------------------------------------------
MISP marks each attribute with `to_ids` — the publisher's own statement of
whether the value is suitable for automated detection, as opposed to context
recorded for a human reading the event.

Measured across the 12 most recent CIRCL events, 42,096 attributes:

| | count | share |
|---|---:|---:|
| `to_ids: true`  | 41,495 | 98.6% |
| `to_ids: false` |    601 |  1.4% |

**Every one of the 601 was type `url`**, and they are reference links — the
first attribute of the sample event is `https://api.github.com/repos/...`.
Ingesting those would have SKOPOS reporting github.com as a threat indicator
against any estate that hosts on it.

So `to_ids` is not a refinement. It is the difference between an indicator
corpus and a corpus containing GitHub.

DECAY DECIDES WHAT IS WORTH FETCHING AT ALL
----------------------------------------------
`core/cti.py` reports nothing below a weight of 0.05, which for the
longest-lived decaying type (domain, 90-day half-life) is roughly 389 days.
Measured on the same feed: only **311 of 1,680 events** fall inside that
horizon. Fetching the other 1,369 would cost 81% of the transfer to produce
indicators that are dropped on load.

`within_horizon()` applies that before any event is fetched.

BULK AUTOMATION IS FLAGGED BY THE SOURCE, SO IT IS CARRIED RATHER THAN JUDGED
-------------------------------------------------------------------------------
Within that horizon the feed is roughly half curated reporting (APT36, Secret
Blizzard, CISA advisories) and half automated bulk dumps — 162 daily "Maltrail
IOC" events of ~3,500 attributes each.

MISP already distinguishes them. Cross-tabulated across all 1,680 events:

| | `automation-level=unsupervised` | no tag |
|---|---:|---:|
| Maltrail bulk | **162** | 0 |
| everything else | 124 | 1,394 |

The tag is the publisher's own, so SKOPOS carries it and does not invent a
quality score of its own. A reader can then tell a hand-written APT report from
an unsupervised aggregation, which is a distinction they should be making and
this product should not be making for them.
"""
from __future__ import annotations

# NETWORK-BOUNDARY: cti_feed_read

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

#: MISP attribute type → the `kind` used by `core/cti.py:HALF_LIFE_DAYS`.
#:
#: Deliberately NOT exhaustive. MISP defines well over a hundred attribute
#: types, most of which SKOPOS has nothing to correlate against — a registry
#: key or a mutex says nothing about an externally observable estate. An
#: unmapped type is counted and dropped rather than guessed at.
TYPE_MAP: Dict[str, str] = {
    "ip-dst": "ip",
    "ip-src": "ip",
    "ip-dst|port": "ip",
    "ip-src|port": "ip",
    "domain": "domain",
    "domain|ip": "domain",
    "hostname": "hostname",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "filename|md5": "md5",
    "filename|sha1": "sha1",
    "filename|sha256": "sha256",
    "email-src": "email",
    "email-dst": "email",
    "email": "email",
}

#: How far back an event can be dated and still yield a reportable indicator.
#: Derived rather than chosen: `core/cti.py` drops anything below weight 0.05,
#: and the longest-lived decaying type is `domain` at a 90-day half-life, so
#: log2(1/0.05) * 90 ≈ 389 days. Hash types never decay, but MalwareBazaar is
#: a better source for those than a MISP event's incidental file attributes.
HORIZON_DAYS = 389


class FeedMalformed(ValueError):
    """The feed is not a MISP feed. Raised rather than returning nothing.

    An empty result and an unparseable document look identical to a caller,
    and one of them means the corpus should keep its previous contents.
    """


@dataclass(frozen=True)
class EventRef:
    """One line of `manifest.json` — enough to decide whether to fetch it."""

    uuid: str
    date: str
    info: str
    org: str = ""
    tags: Tuple[str, ...] = ()

    @property
    def tlp(self) -> str:
        return tlp_of(self.tags)

    @property
    def automation_level(self) -> str:
        return automation_level_of(self.tags)


@dataclass
class ParseReport:
    """What the parse kept, and everything it did not.

    Counted rather than silently dropped. `core/itsm.py` and
    `core/validation.py` announce their caps for the same reason: a truncated
    list reads as a complete one, and a filter nobody mentions reads as an
    absence of matches.
    """

    kept: int = 0
    not_to_ids: int = 0
    deleted: int = 0
    unmapped_type: int = 0
    empty_value: int = 0
    unmapped_types_seen: Dict[str, int] = field(default_factory=dict)
    capped: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kept": self.kept,
            "dropped_not_to_ids": self.not_to_ids,
            "dropped_deleted": self.deleted,
            "dropped_unmapped_type": self.unmapped_type,
            "dropped_empty_value": self.empty_value,
            "dropped_by_cap": self.capped,
            "unmapped_types": dict(sorted(self.unmapped_types_seen.items(),
                                          key=lambda kv: -kv[1])[:20]),
        }


def tlp_of(tags: Iterable[str]) -> str:
    """The TLP marking a MISP event carries, as a bare level.

    MISP writes these as `tlp:clear`, `tlp:amber+strict`. Absence is treated as
    WHITE only because a public keyless feed is by definition published for
    redistribution — a feed that meant otherwise would not be on a web root.
    `core/cti.py:exportable` is where the restrictive default lives, and it
    treats anything it does not recognise as non-exportable.
    """
    for tag in tags or ():
        text = str(tag or "").strip().lower()
        if text.startswith("tlp:"):
            return text[4:].replace("+", "_").replace("-", "_").upper()
    return "WHITE"


def automation_level_of(tags: Iterable[str]) -> str:
    """MISP's own `misp:automation-level`, verbatim, or "" where absent."""
    for tag in tags or ():
        text = str(tag or "").strip()
        if text.lower().startswith("misp:automation-level"):
            _, _, value = text.partition("=")
            return value.strip().strip('"').strip("'")
    return ""


def _tag_names(raw: Any) -> Tuple[str, ...]:
    """Tags arrive as dicts in an event and sometimes as bare strings."""
    out: List[str] = []
    for tag in raw or ():
        if isinstance(tag, dict):
            name = str(tag.get("name") or "").strip()
        else:
            name = str(tag or "").strip()
        if name:
            out.append(name)
    return tuple(out)


def parse_manifest(raw: bytes | str) -> List[EventRef]:
    """`manifest.json` → one `EventRef` per event."""
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise FeedMalformed(f"manifest is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise FeedMalformed("manifest is not a mapping of uuid to event")

    out: List[EventRef] = []
    for uuid, meta in payload.items():
        if not isinstance(meta, dict):
            continue
        out.append(EventRef(
            uuid=str(uuid),
            date=str(meta.get("date") or ""),
            info=str(meta.get("info") or ""),
            org=str((meta.get("Orgc") or {}).get("name") or ""),
            tags=_tag_names(meta.get("Tag")),
        ))
    return out


def _today() -> date:
    return datetime.now(timezone.utc).date()


def within_horizon(refs: Iterable[EventRef],
                   horizon_days: int = HORIZON_DAYS,
                   today: Optional[date] = None) -> List[EventRef]:
    """Events recent enough to still yield a reportable indicator.

    An undated event is KEPT. A missing date is not evidence of age, and
    dropping it here would silently discard a curated report because its
    publisher omitted a field.
    """
    now = today or _today()
    out: List[EventRef] = []
    for ref in refs:
        if not ref.date:
            out.append(ref)
            continue
        try:
            when = date.fromisoformat(ref.date[:10])
        except ValueError:
            out.append(ref)
            continue
        if (now - when).days <= horizon_days:
            out.append(ref)
    return sorted(out, key=lambda r: r.date, reverse=True)


def _kind_of(misp_type: str, value: str) -> Optional[str]:
    """Map a MISP type to a SKOPOS kind, resolving `ip` by inspection."""
    mapped = TYPE_MAP.get(str(misp_type or "").strip().lower())
    if mapped is None:
        return None
    if mapped != "ip":
        return mapped
    # MISP uses one type for both families. Which one it is decides the
    # half-life, so it is determined rather than assumed.
    bare = str(value or "").split("|", 1)[0].strip()
    try:
        return "ipv6" if ipaddress.ip_address(bare).version == 6 else "ipv4"
    except ValueError:
        return None


def _value_of(misp_type: str, raw: str) -> str:
    """The indicator itself, from MISP's composite types.

    `domain|ip` and `filename|sha256` pack two values into one field. The half
    SKOPOS wants depends on which type it is, and taking the wrong half yields
    an indicator that silently never matches anything.
    """
    text = str(raw or "").strip()
    kind = str(misp_type or "").strip().lower()
    if "|" not in text:
        return text
    left, _, right = text.partition("|")
    if kind.startswith("filename|"):
        return right.strip()        # the hash, not the filename
    if kind in ("domain|ip",):
        return left.strip()         # the domain, not the address
    if kind in ("ip-dst|port", "ip-src|port"):
        return left.strip()         # the address, not the port
    return left.strip()


def indicators_from_event(event: Any,
                          ref: Optional[EventRef] = None,
                          cap: Optional[int] = None,
                          report: Optional[ParseReport] = None,
                          ) -> Tuple[List[Dict[str, Any]], ParseReport]:
    """One MISP event → SKOPOS indicator dicts, plus what was dropped.

    The returned dicts are exactly the shape `core/cti.py:CTICorpus` consumes.
    """
    if isinstance(event, (bytes, str)):
        try:
            event = json.loads(event)
        except (ValueError, TypeError) as exc:
            raise FeedMalformed(f"event is not JSON: {exc}") from exc
    if not isinstance(event, dict):
        raise FeedMalformed("event is not a mapping")

    body = event.get("Event") if isinstance(event.get("Event"), dict) else event
    tally = report if report is not None else ParseReport()

    tags = _tag_names(body.get("Tag")) or (ref.tags if ref else ())
    event_date = str(body.get("date") or (ref.date if ref else ""))
    info = str(body.get("info") or (ref.info if ref else ""))
    org = str((body.get("Orgc") or {}).get("name") or (ref.org if ref else ""))
    tlp = tlp_of(tags)
    automation = automation_level_of(tags)

    out: List[Dict[str, Any]] = []
    for attribute in body.get("Attribute") or ():
        if not isinstance(attribute, dict):
            continue
        if attribute.get("deleted"):
            tally.deleted += 1
            continue
        # THE FILTER. See the module docstring — without this the corpus
        # contains github.com.
        if not attribute.get("to_ids"):
            tally.not_to_ids += 1
            continue

        misp_type = str(attribute.get("type") or "")
        value = _value_of(misp_type, attribute.get("value"))
        if not value:
            tally.empty_value += 1
            continue
        kind = _kind_of(misp_type, value)
        if kind is None:
            tally.unmapped_type += 1
            tally.unmapped_types_seen[misp_type] = (
                tally.unmapped_types_seen.get(misp_type, 0) + 1)
            continue

        if cap is not None and len(out) >= cap:
            tally.capped += 1
            continue

        # The attribute's own `last_seen` beats the event date where present:
        # a long-running event updated last week should not date its newest
        # attribute to when the event was opened.
        seen = str(attribute.get("last_seen") or "")[:10] or event_date

        entry: Dict[str, Any] = {
            "value": value,
            "kind": kind,
            "source": "circl_osint",
            "publisher": "CIRCL",
            "seen_on": seen,
            "context": info,
            "tags": list(tags),
            "tlp": tlp,
            "reporter": org,
        }
        if automation:
            # Carried, not judged. See the module docstring.
            entry["automation_level"] = automation
        comment = str(attribute.get("comment") or "").strip()
        if comment:
            entry["comment"] = comment[:200]
        out.append(entry)
        tally.kept += 1

    return out, tally

def partition_by_automation(refs: Iterable[EventRef]
                            ) -> Tuple[List[EventRef], List[EventRef]]:
    """Split events into (curated, unsupervised) using MISP's OWN tag.

    WHY THE SPLIT EXISTS, MEASURED
    ---------------------------------
    A first ingest took the 200 most recent events inside the decay horizon and
    produced 94,449 indicators, of which **92,613 came from daily automated
    "Maltrail IOC" dumps** and only 1,836 from everything else. Every single one
    carried `automation-level=unsupervised`.

    Sorting by date and truncating had systematically starved the curated
    reporting — APT36, Secret Blizzard, the CISA advisories — because an
    automated feed publishes every day and a analyst report does not. Recency
    was deciding the budget, and recency is exactly the wrong judge here.

    A tempting justification for simply dropping the bulk events would be that
    they duplicate `core/blocklists.py`. **They do not**: measured, only 59 of
    92,513 values appeared in the vendored abuse feeds. So they are cut back
    rather than excluded, and the two budgets are allocated separately by
    `tools/refresh_intel.py`.
    """
    curated: List[EventRef] = []
    bulk: List[EventRef] = []
    for ref in refs:
        (bulk if ref.automation_level == "unsupervised" else curated).append(ref)
    return curated, bulk
