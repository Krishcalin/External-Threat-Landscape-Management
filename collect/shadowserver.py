"""Shadowserver reports: free daily scanning of an estate you have PROVEN you own.

WHY THIS FITS SKOPOS AND ALMOST NOTHING ELSE
----------------------------------------------
Shadowserver will not report on a netblock until you demonstrate you control it.
For most tools that precondition is friction. Here it is machinery that already
exists — `core/ownership.py` records verifications with a 180-day expiry because
`core/gate.py` refuses every active operation against an unverified asset. The
thing that makes Shadowserver awkward elsewhere is the thing SKOPOS enforces
anyway.

It is also the ONE exception to the licence wall that governs every other free
source of scan data: Shodan's InternetDB, Censys and Netlas free tiers all
prohibit commercial use. Shadowserver is a public-benefit foundation and its
reports are free to everyone, including commercially.

WHAT THIS MODULE IS AND IS NOT
--------------------------------
It is a PARSER, not a client. Shadowserver delivers by daily download link or
e-mail to a subscribed contact; there is no public API to poll, and there is no
credential SKOPOS could hold. Subscription is an act by the organisation — see
`SUBSCRIPTION` below for exactly what to send.

So this module has **no network boundary marker**, because it performs no I/O.
It turns a CSV somebody already received into observations, and refuses to
invent the parts that are not there.

WHY EVERY ROW IS AN OBSERVATION AND NOT A FINDING
---------------------------------------------------
Shadowserver scanned the host and recorded what answered. That is a strictly
better basis than a banner-derived guess — it is a third party's direct
measurement, dated — but it is still not a version comparison against a
published affected range, which is the only thing this product calls a
determination. `core/identity.py` refuses to let an observed version reach that
field, and a CSV from a respected foundation does not get to route around it.

The one thing Shadowserver DOES give that nothing else free does: it names the
report type, so "this host answers on 11211 and is in our open-memcached report"
carries why it was flagged, not merely that it was.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

#: What the organisation must send, quoted so nobody has to go and find it.
#: This is a human action; there is nothing here to automate.
SUBSCRIPTION = {
    "who": "The Shadowserver Foundation — a non-profit; reports are free.",
    "to": "request_report@shadowserver.org",
    "include": (
        "The ASNs and/or CIDR ranges you control, the organisation name, and "
        "contact addresses to receive the daily reports. Shadowserver verifies "
        "that you actually control the space before enabling anything."
    ),
    "note": (
        "Reports run every morning for the previous 24 hours UTC and arrive as "
        "CSV. Around 76 report types exist; subscribe to the ones that match "
        "your estate rather than all of them."
    ),
    "why_not_automated": (
        "There is no public API to poll and no credential SKOPOS could hold. "
        "Subscription is a statement by the organisation that it controls the "
        "address space, which is precisely the kind of claim this product "
        "requires a human to make."
    ),
}

#: Column names Shadowserver uses across report types. Several reports spell the
#: same idea differently, which is why these are lists rather than constants —
#: parsing one report type and assuming the rest match is how this breaks.
_IP_FIELDS = ("ip", "src_ip", "ipaddress", "address")
_PORT_FIELDS = ("port", "src_port", "dst_port")
_TIME_FIELDS = ("timestamp", "ts", "first_seen", "last_seen")
_HOST_FIELDS = ("hostname", "domain", "dns_name")

#: Fields that carry a software version where a report has one.
_VERSION_FIELDS = ("version", "server_version", "product_version", "software")


class ReportUnreadable(ValueError):
    """The CSV could not be understood. Distinct from an empty report."""


@dataclass(frozen=True)
class Row:
    """One line of one report."""

    report: str
    address: str
    port: Optional[int]
    observed_on: str
    hostname: str = ""
    version: str = ""
    extra: Dict[str, str] = field(default_factory=dict)

    def to_observation(self) -> Dict[str, Any]:
        observation = {
            "kind": "shadowserver",
            "report": self.report,
            "address": self.address,
            "port": self.port,
            "observed_on": self.observed_on,
            "source": "shadowserver",
            # The refusal, restated where a reader will see it. A direct
            # measurement by a respected foundation is still not a comparison
            # against a published affected range.
            "basis": (
                "Shadowserver scanned this host and recorded what answered. A "
                "third party's direct, dated measurement — better than a banner "
                "guess, and still not a version comparison, so SKOPOS does not "
                "treat it as a determination."),
        }
        if self.hostname:
            observation["hostname"] = self.hostname
        if self.version:
            observation["version"] = self.version
        if self.extra:
            observation["fields"] = dict(self.extra)
        return observation


def _first(row: Dict[str, str], names: Sequence[str]) -> str:
    for name in names:
        value = (row.get(name) or "").strip()
        if value:
            return value
    return ""


def _as_date(text: str) -> str:
    """A Shadowserver timestamp to an ISO date, or "" if it is not one.

    Returns "" rather than today's date on a parse failure. Substituting the
    parse date would silently claim an observation was made today, which is the
    one error that makes a stale report look current.
    """
    raw = str(text or "").strip()
    if not raw:
        return ""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw[:len("2026-08-23 00:00:00")][:19],
                                     fmt).date().isoformat()
        except ValueError:
            continue
    return ""


def parse(report: str, csv_text: str) -> List[Row]:
    """One Shadowserver CSV to rows.

    `report` is the report type — `scan_memcached`, `sinkhole_http_drone`, and
    so on. It is a required argument rather than something sniffed from the
    content, because the report type is the only thing that says WHY a host is
    listed, and a parser that guessed it wrong would attach the wrong reason to
    a real observation.
    """
    name = str(report or "").strip()
    if not name:
        raise ReportUnreadable("a report type is required; it is the only "
                               "field that says why a host is listed")
    text = str(csv_text or "")
    if not text.strip():
        return []
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ReportUnreadable("no header row")

    # A file with no address column at all is not a sparse report — it is the
    # wrong file. Detected from the HEADER rather than by noticing zero rows at
    # the end, because "parsed fine, found nothing" is exactly how a wrong file
    # reads as an estate with no exposure.
    header = {(name or "").strip().lower() for name in reader.fieldnames}
    if not header & set(_IP_FIELDS):
        raise ReportUnreadable(
            f"no address column in {sorted(header)!r}; expected one of "
            f"{list(_IP_FIELDS)}. This does not look like a Shadowserver "
            f"report, and parsing it to zero rows would read as 'no exposure'.")

    known = set(_IP_FIELDS + _PORT_FIELDS + _TIME_FIELDS + _HOST_FIELDS
                + _VERSION_FIELDS)
    rows: List[Row] = []
    for record in reader:
        record = {(k or "").strip().lower(): (v or "")
                  for k, v in record.items() if k}
        address = _first(record, _IP_FIELDS)
        if not address:
            # A blank address cell inside an otherwise-valid report. Skipped
            # rather than guessed at — and the case that actually mattered, a
            # file with no address COLUMN, was already refused above from the
            # header, so this is a data-quality gap in one row rather than the
            # wrong file being read as an empty estate.
            continue
        port_text = _first(record, _PORT_FIELDS)
        try:
            port = int(port_text) if port_text else None
        except ValueError:
            port = None
        rows.append(Row(
            report=name,
            address=address,
            port=port,
            observed_on=_as_date(_first(record, _TIME_FIELDS)),
            hostname=_first(record, _HOST_FIELDS).lower().rstrip("."),
            version=_first(record, _VERSION_FIELDS),
            # Everything else is carried verbatim rather than dropped. Report
            # types differ wildly and a field this build has never seen is more
            # likely to be useful than to be noise.
            extra={k: v for k, v in record.items()
                   if k not in known and v.strip()},
        ))
    return rows


def summarise(rows: Iterable[Row], today: Optional[date] = None) -> Dict[str, Any]:
    """What a set of parsed reports contains, and what it cannot tell you."""
    rows = list(rows)
    by_report: Dict[str, int] = {}
    addresses = set()
    undated = 0
    for row in rows:
        by_report[row.report] = by_report.get(row.report, 0) + 1
        addresses.add(row.address)
        if not row.observed_on:
            undated += 1
    dates = sorted(r.observed_on for r in rows if r.observed_on)
    return {
        "rows": len(rows),
        "addresses": len(addresses),
        "reports": dict(sorted(by_report.items())),
        "observed_from": dates[0] if dates else None,
        "observed_to": dates[-1] if dates else None,
        # Counted rather than hidden: a row whose timestamp did not parse is
        # still a real observation, and silently dating it today would be worse.
        "undated_rows": undated,
        "covers": (
            "Only address space this organisation has proven to Shadowserver "
            "that it controls. Nothing here says anything about a supplier, a "
            "third party, or any asset outside the subscribed ASNs and CIDRs — "
            "and an empty report is not an estate with no exposure, it is an "
            "estate Shadowserver was not asked about."),
    }


def parse_many(reports: Dict[str, str]) -> Dict[str, Any]:
    """Several report types at once. Returns rows AND what failed.

    A failure is returned rather than raised for the same reason
    `core/inventory.py` returns its rejects: one malformed file among ten must
    not discard the nine that parsed, and it must not vanish either.
    """
    rows: List[Row] = []
    failed: Dict[str, str] = {}
    for name, text in (reports or {}).items():
        try:
            rows.extend(parse(name, text))
        except ReportUnreadable as exc:
            failed[name] = str(exc)
        except (csv.Error, UnicodeDecodeError) as exc:      # pragma: no cover
            failed[name] = f"{type(exc).__name__}: {exc}"
    summary = summarise(rows)
    summary["failed_reports"] = failed
    return {"rows": rows, "summary": summary}


def _now() -> date:                                          # pragma: no cover
    return datetime.now(timezone.utc).date()


__all__ = ["parse", "parse_many", "summarise", "Row", "ReportUnreadable",
           "SUBSCRIPTION"]
