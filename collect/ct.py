"""Certificate Transparency — passive discovery, and the earliest sensor there is.

WHY CT IS FIRST
---------------
Every other discovery method asks the internet about you. CT asks a public log
that certificate authorities are *required* to write to, so it touches nothing
belonging to the target: it is passive in the strong sense, needs no ownership
verification, and is lawful against any name.

It is also a PRE-ATTACK sensor rather than a post-attack one. A certificate is
issued before a service is published, so a name appears in CT days before it
answers a request — and a lookalike domain appears there before the phishing
campaign goes live (SRS WS-4, signal 7). Discovery and brand monitoring share
this one collector.

MULTI-SOURCE, BECAUSE THE FIRST SOURCE WAS DOWN
-----------------------------------------------
SRS R-01 anticipates a free source changing terms or rate limits and prescribes
"≥ 2 sources per critical data class". That risk materialised on the first call:
`crt.sh` returned HTTP 502 on two consecutive attempts while `certspotter`
answered normally. So this collector queries several and merges.

The rule that follows is the important one: **a source that fails contributes
nothing and is REPORTED**. It never fails the run, and it never disappears
quietly either — `DiscoveryResult.sources` records what each source returned so
a thin result can be read as "one source was down" rather than "you have a small
estate". Those two look identical in a name list and could not be more different.

POLITENESS (FR-GOV-005)
-----------------------
An honest user-agent naming the tool, a bounded timeout, and no retries beyond
one. These are public goods run on donated infrastructure; a discovery tool that
hammers them is the reason they end up behind a paywall.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

USER_AGENT = "skopos-discovery/0.1 (+open-source ETLM; passive CT lookup)"
TIMEOUT = 30


@dataclass
class SourceReport:
    """What one source actually did. Carried into the result, never swallowed."""

    name: str
    ok: bool
    names_found: int = 0
    detail: str = ""


@dataclass
class DiscoveredName:
    """A DNS name seen in a certificate, with when it was first observed."""

    name: str
    #: Earliest `not_before` across the certificates naming it. This is the
    #: closest thing to "when did this asset appear", and it feeds the
    #: `exposure_age` term in TEPS §9.1.
    first_seen: Optional[date] = None
    sources: Set[str] = field(default_factory=set)
    #: A wildcard proves a certificate exists, never that a host does.
    is_wildcard: bool = False


@dataclass
class DiscoveryResult:
    names: List[DiscoveredName]
    sources: List[SourceReport]

    @property
    def degraded(self) -> bool:
        """True when any source failed, so the caller can say so rather than
        presenting a partial estate as a complete one."""
        return any(not s.ok for s in self.sources)

    def coverage_note(self) -> str:
        failed = [s for s in self.sources if not s.ok]
        if not failed:
            return (f"{len(self.names)} name(s) from "
                    f"{len(self.sources)} certificate-transparency source(s).")
        return (f"{len(self.names)} name(s), but "
                f"{len(failed)} of {len(self.sources)} source(s) failed "
                f"({'; '.join(f'{s.name}: {s.detail}' for s in failed)}). "
                f"This estate may be larger than shown — a thin result from a "
                f"degraded lookup looks exactly like a small estate.")


def _get(url: str) -> Any:
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT, "Accept": "application/json"})
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=TIMEOUT, context=context) as response:
        return json.loads(response.read().decode("utf-8"))


def _parse_day(value: Any) -> Optional[date]:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text[:19] if "T" in text else text, fmt).date()
        except ValueError:
            continue
    return None


def _clean(name: str, apex: str) -> Optional[str]:
    """Normalise a certificate DNS name, or drop it.

    Names outside the requested apex are discarded. A certificate can carry
    unrelated SANs — shared hosting and CDN certificates routinely name dozens
    of other people's domains — and importing those would attribute somebody
    else's estate to this tenant, which is both wrong and a governance problem.
    """
    value = str(name or "").strip().lower().rstrip(".")
    if not value or " " in value:
        return None
    bare = value[2:] if value.startswith("*.") else value
    if bare != apex and not bare.endswith("." + apex):
        return None
    return value


def from_certspotter(apex: str) -> Tuple[List[Tuple[str, Optional[date]]], SourceReport]:
    """SSLMate's CertSpotter. Answered normally when crt.sh did not."""
    url = ("https://api.certspotter.com/v1/issuances"
           f"?domain={urllib.parse.quote(apex)}"
           "&include_subdomains=true&expand=dns_names")
    try:
        payload = _get(url)
    except Exception as exc:                     # noqa: BLE001 — any failure degrades
        return [], SourceReport("certspotter", False, 0, type(exc).__name__)
    if not isinstance(payload, list):
        # The API returns an object carrying a message when it refuses.
        message = (payload or {}).get("message", "unexpected response shape")
        return [], SourceReport("certspotter", False, 0, str(message)[:80])
    out: List[Tuple[str, Optional[date]]] = []
    for record in payload:
        seen = _parse_day(record.get("not_before"))
        for raw in record.get("dns_names") or []:
            name = _clean(raw, apex)
            if name:
                out.append((name, seen))
    return out, SourceReport("certspotter", True, len({n for n, _ in out}))


def from_crtsh(apex: str) -> Tuple[List[Tuple[str, Optional[date]]], SourceReport]:
    """crt.sh. Frequently unavailable — kept because when it answers it is the
    broadest source, and its absence is reported rather than hidden."""
    url = f"https://crt.sh/?q={urllib.parse.quote('%.' + apex)}&output=json"
    try:
        payload = _get(url)
    except Exception as exc:                     # noqa: BLE001
        return [], SourceReport("crt.sh", False, 0, type(exc).__name__)
    if not isinstance(payload, list):
        return [], SourceReport("crt.sh", False, 0, "unexpected response shape")
    out: List[Tuple[str, Optional[date]]] = []
    for record in payload:
        seen = _parse_day(record.get("not_before"))
        for raw in str(record.get("name_value") or "").split("\n"):
            name = _clean(raw, apex)
            if name:
                out.append((name, seen))
    return out, SourceReport("crt.sh", True, len({n for n, _ in out}))


#: Order matters only for reporting. Every source is queried regardless.
SOURCES = (from_certspotter, from_crtsh)


def discover(apex: str, sources: Optional[Iterable] = None) -> DiscoveryResult:
    """Names certificate transparency knows about, from every source that answers."""
    apex = str(apex).strip().lower().rstrip(".")
    if not apex:
        raise ValueError("an apex domain is required")

    merged: Dict[str, DiscoveredName] = {}
    reports: List[SourceReport] = []
    for source in (sources if sources is not None else SOURCES):
        rows, report = source(apex)
        reports.append(report)
        for name, seen in rows:
            existing = merged.get(name)
            if existing is None:
                merged[name] = DiscoveredName(
                    name=name, first_seen=seen, sources={report.name},
                    is_wildcard=name.startswith("*."))
            else:
                existing.sources.add(report.name)
                # Earliest observation wins: the question is when this name
                # first appeared, not when it was last re-issued.
                if seen and (existing.first_seen is None or seen < existing.first_seen):
                    existing.first_seen = seen

    names = sorted(merged.values(), key=lambda d: d.name)
    return DiscoveryResult(names=names, sources=reports)


def to_inventory_rows(result: DiscoveryResult) -> List[Dict[str, Any]]:
    """Discovery output as inventory rows the scan can read.

    DISCOVERY WRITES A FILE; THE SCAN READS IT. Keeping the network out of the
    scan path is what makes a scan reproducible and runnable offline (D1), and
    it means a discovery run can be reviewed before anything is scored against
    it.

    Wildcards are excluded: `*.example.com` proves a certificate exists, never
    that a host does, and turning it into an asset would invent one.
    """
    rows: List[Dict[str, Any]] = []
    for entry in result.names:
        if entry.is_wildcard:
            continue
        rows.append({
            "hostname": entry.name,
            # Discovery finds NAMES, not technologies. The product is left
            # unknown rather than guessed, and the vulnerability join will
            # simply not match until fingerprinting fills it in — which is the
            # honest state, not a gap to paper over.
            "product": "unknown",
            "source": "ct:" + ",".join(sorted(entry.sources)),
            "first_seen": entry.first_seen.isoformat() if entry.first_seen else "",
        })
    return rows
