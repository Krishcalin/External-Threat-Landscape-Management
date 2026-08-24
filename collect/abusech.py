"""Parse the two abuse.ch bulk feeds that carry what a blocklist cannot.

NO NETWORK IN THIS MODULE, on the same reasoning as `collect/misp.py`.

WHY THESE TWO AND NOT THE OTHERS
-----------------------------------
`core/blocklists.py` already vendors URLhaus and Feodo Tracker, and treats
membership as a bare fact: *this value appears on this list*. That is the right
shape for a blocklist, where the list itself is the whole claim.

ThreatFox and MalwareBazaar carry something a blocklist cannot express, and it
is the reason they belong in `core/cti.py` rather than alongside the others:

- **ThreatFox names the malware family**, with the submitter's own confidence
  percentage and the reporter's handle. That is an attributed claim — the kind
  §1 of `docs/REFUSALS.md` permits SKOPOS to carry precisely because somebody
  else made it and signed it.
- **MalwareBazaar is a corpus of artefacts**, so its entries never decay. A
  file whose SHA-256 matched a sample in 2014 is still that file.

THE PORT PROBLEM
-------------------
Measured 2026-08-24: ThreatFox's most common `ioc_type` is `ip:port`, and the
`ioc_value` carries the port inline — `185.157.163.138:50810`. Stored verbatim
that indicator never matches anything, because no estate inventory records an
address with a port glued to it.

`_split_port` strips it and the port is dropped rather than kept as a separate
field: SKOPOS correlates against assets it observed from outside, and an
attacker's C2 port is not a property of the estate.

MALWAREBAZAAR HAS NO PER-ENTRY DATE
--------------------------------------
The bulk export is a flat hash list under a header. There is no date per hash,
only the file's own `# Last updated:` line — the same `PUBLISHER_DATE` pattern
`core/blocklists.py` already reads, and for the same reason: a fetch date is
not a data date.

That would matter enormously for an address. For a hash it does not matter at
all, because hashes do not decay — which is why this feed is safe to carry with
a single collective date and an IP feed would not be.
"""
from __future__ import annotations

# NETWORK-BOUNDARY: cti_feed_read

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

#: ThreatFox `ioc_type` → the `kind` used by `core/cti.py:HALF_LIFE_DAYS`.
THREATFOX_TYPES: Dict[str, str] = {
    "ip:port": "ip",
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "md5",
    "sha1_hash": "sha1",
    "sha256_hash": "sha256",
}

#: abuse.ch publishes its own last-updated line. Mirrors
#: `core/blocklists.py:PUBLISHER_DATE`.
PUBLISHER_DATE = re.compile(r"#\s*Last updated:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})",
                            re.I)

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


class FeedMalformed(ValueError):
    """The feed is not what it claims to be. Raised rather than returning [].

    An empty result and an unparseable document look identical to a caller,
    and one of them means the corpus should keep its previous contents.
    """


@dataclass
class ParseReport:
    """What was kept, and everything that was not. Counted, never silent."""

    kept: int = 0
    unmapped_type: int = 0
    empty_value: int = 0
    below_confidence: int = 0
    unmapped_types_seen: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kept": self.kept,
            "dropped_unmapped_type": self.unmapped_type,
            "dropped_empty_value": self.empty_value,
            "dropped_below_confidence": self.below_confidence,
            "unmapped_types": dict(sorted(self.unmapped_types_seen.items(),
                                          key=lambda kv: -kv[1])[:20]),
        }


def _split_port(value: str) -> str:
    """`185.157.163.138:50810` → `185.157.163.138`. See the module docstring.

    IPv6 arrives bracketed as `[2001:db8::1]:443`, and splitting on the last
    colon without handling that would truncate the address itself.
    """
    text = str(value or "").strip()
    if text.startswith("["):
        end = text.find("]")
        if end > 0:
            return text[1:end]
    if text.count(":") == 1:
        left, _, right = text.rpartition(":")
        if right.isdigit():
            return left
    return text


def _ip_kind(value: str) -> Optional[str]:
    try:
        return "ipv6" if ipaddress.ip_address(value).version == 6 else "ipv4"
    except ValueError:
        return None


#: ThreatFox carries the submitter's own confidence as a percentage. Entries
#: below this are dropped.
#:
#: 50 is the midpoint rather than a measured threshold, and is stated as a
#: judgement. What makes it defensible is the direction: abuse.ch's own
#: guidance treats <50 as unreliable, and an indicator its publisher does not
#: stand behind is not one SKOPOS should repeat under that publisher's name.
MIN_CONFIDENCE = 50


def parse_threatfox(raw: bytes | str,
                    min_confidence: int = MIN_CONFIDENCE,
                    ) -> Tuple[List[Dict[str, Any]], ParseReport]:
    """ThreatFox's recent JSON export → SKOPOS indicator dicts.

    The export is a mapping of submission id to a single-element list, which is
    an odd shape to consume but is what abuse.ch publishes.
    """
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise FeedMalformed(f"threatfox export is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise FeedMalformed("threatfox export is not a mapping")

    report = ParseReport()
    out: List[Dict[str, Any]] = []

    for entries in payload.values():
        for entry in (entries if isinstance(entries, list) else [entries]):
            if not isinstance(entry, dict):
                continue

            ioc_type = str(entry.get("ioc_type") or "").strip().lower()
            mapped = THREATFOX_TYPES.get(ioc_type)
            if mapped is None:
                report.unmapped_type += 1
                report.unmapped_types_seen[ioc_type] = (
                    report.unmapped_types_seen.get(ioc_type, 0) + 1)
                continue

            value = str(entry.get("ioc_value") or "").strip()
            if mapped == "ip":
                value = _split_port(value)
                kind = _ip_kind(value)
                if kind is None:
                    report.empty_value += 1
                    continue
            else:
                kind = mapped
            if not value:
                report.empty_value += 1
                continue

            try:
                confidence = int(entry.get("confidence_level") or 0)
            except (TypeError, ValueError):
                confidence = 0
            if confidence < min_confidence:
                report.below_confidence += 1
                continue

            family = str(entry.get("malware_printable") or "").strip()
            threat = str(entry.get("threat_type") or "").strip()
            # The source's own words. SKOPOS adds no characterisation.
            context = " / ".join(p for p in (family, threat) if p) or "ThreatFox indicator"

            tags = [t for t in str(entry.get("tags") or "").split(",") if t.strip()]

            out.append({
                "value": value,
                "kind": kind,
                "source": "threatfox",
                "publisher": "abuse.ch",
                # first_seen is when abuse.ch first observed it; last_seen is
                # frequently null in this export, so first_seen is the only
                # date that is reliably present.
                "seen_on": str(entry.get("first_seen_utc") or "")[:10],
                "context": context,
                "tags": tags,
                "tlp": "WHITE",
                "reporter": str(entry.get("reporter") or ""),
                # Carried because it is the SUBMITTER's confidence, not
                # SKOPOS's. `core/cti.py` holds no opinion of an indicator; a
                # number the publisher attached is a fact about the publisher.
                "source_confidence": confidence,
            })
            report.kept += 1

    return out, report


def publisher_date(raw: bytes | str) -> str:
    """abuse.ch's own `# Last updated:` line, or "" where absent."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    match = PUBLISHER_DATE.search(text)
    return match.group(1) if match else ""


def parse_malwarebazaar(raw: bytes | str,
                        ) -> Tuple[List[Dict[str, Any]], ParseReport]:
    """MalwareBazaar's recent SHA-256 export → SKOPOS indicator dicts.

    One collective date for the whole file, which is sound ONLY because hashes
    do not decay. See the module docstring; the same shortcut on an address
    feed would be a bug.
    """
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    seen_on = publisher_date(text)
    report = ParseReport()
    out: List[Dict[str, Any]] = []
    found_any_line = False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        found_any_line = True
        # The export is one hash per line, but quoting has changed before.
        candidate = stripped.strip('"').strip("'").split(",")[0].strip()
        if not _SHA256.match(candidate):
            report.empty_value += 1
            continue
        out.append({
            "value": candidate.lower(),
            "kind": "sha256",
            "source": "malwarebazaar",
            "publisher": "abuse.ch",
            "seen_on": seen_on,
            "context": "a sample held in abuse.ch's malware corpus",
            "tags": [],
            "tlp": "WHITE",
            "reporter": "abuse.ch",
        })
        report.kept += 1

    if not found_any_line:
        raise FeedMalformed(
            "malwarebazaar export contained no data lines — the format "
            "changed, or the fetch returned only a header")
    return out, report
