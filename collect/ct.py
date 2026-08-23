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
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from collect import egress
from collect.report import Coverage, Outcome, SourceReport

USER_AGENT = "skopos-discovery/0.1 (+open-source ETLM; passive CT lookup)"

#: The operation this module performs, as registered in core.gate.OPERATIONS.
#: Named once so the permit check and the audit record cannot disagree.
OPERATION = "ct_log_search"


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


class DiscoveryUnavailable(RuntimeError):
    """No source answered at all.

    Raised rather than returned, mirroring `intel.IntelUnavailable`. A run in
    which every source was down produces the same empty output as an estate with
    nothing in it, and on the one command whose characteristic failure mode is
    "the estate looks smaller than it is", a clean-looking zero with a success
    exit code is the worst available answer.

    Degradation is NOT this. If even one source answered, that is reported and
    the run succeeds.
    """


@dataclass
class DiscoveryResult:
    names: List[DiscoveredName]
    sources: List[SourceReport]

    @property
    def coverage(self) -> Coverage:
        return Coverage(list(self.sources))

    @property
    def degraded(self) -> bool:
        """Something broke. Re-running may produce more."""
        return self.coverage.degraded

    @property
    def narrowed(self) -> bool:
        """Nothing broke; coverage is smaller by choice (terms, missing key)."""
        return self.coverage.narrowed

    @property
    def refused(self) -> bool:
        """The gate said no. A governance event, not an outage."""
        return self.coverage.refused

    @property
    def blackout(self) -> bool:
        return self.coverage.blackout

    def coverage_note(self) -> str:
        return self.coverage.note(len(self.names), "name")


def _get(permit, url: str, budget=None, limiter=None) -> Any:
    """Fetch through the one module allowed to touch the network.

    This used to call urllib.request directly. It no longer does, so the permit
    check, the HTTPS requirement, the rate buckets and the body cap all apply
    without this module remembering any of them — see collect/egress.py.
    """
    response = egress.http_get(
        permit, OPERATION, url, budget=budget, limiter=limiter,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    if response.status != 200:
        raise ValueError(f"HTTP {response.status}")
    if response.truncated:
        # Parsing a truncated body would drop names with nothing reported.
        raise ValueError("response exceeded the body cap and was truncated")
    return json.loads(response.text)


def _why(exc: Exception) -> str:
    """A detail line an operator can act on.

    `type(exc).__name__` alone says "ValueError", which tells a reader nothing
    about whether the source is down, rate-limiting, or returning something
    unexpected. Our own failures carry the status in the message; a network
    error from the stack below does not, so the class name is the fallback
    rather than the default.
    """
    message = str(exc).strip()
    return (message or type(exc).__name__)[:80]


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


def from_certspotter(apex: str, permit=None, budget=None, limiter=None):
    """SSLMate's CertSpotter. Answered normally when crt.sh did not."""
    url = ("https://api.certspotter.com/v1/issuances"
           f"?domain={urllib.parse.quote(apex)}"
           "&include_subdomains=true&expand=dns_names")
    try:
        payload = _get(permit, url, budget, limiter)
    except egress.PermitMismatch:
        # A permit problem is a BUG, not a coverage gap. Filing it as a source
        # status line would hand the operator entirely the wrong remedy.
        raise
    except Exception as exc:                     # noqa: BLE001 — any failure degrades
        return [], SourceReport("certspotter", Outcome.FAILED, 0, 0,
                                _why(exc))
    if not isinstance(payload, list):
        # The API returns an object carrying a message when it refuses.
        message = (payload or {}).get("message", "unexpected response shape")
        return [], SourceReport("certspotter", Outcome.FAILED, 0, 0,
                                str(message)[:80])
    out: List[Tuple[str, Optional[date]]] = []
    returned = 0
    for record in payload:
        seen = _parse_day(record.get("not_before"))
        for raw in record.get("dns_names") or []:
            returned += 1
            name = _clean(raw, apex)
            if name:
                out.append((name, seen))
    # contributed vs returned: a shared-CDN certificate carrying 500 SANs of
    # which 3 are in-apex is not a source that gave us 3 things badly — it is a
    # source that gave us 500, 497 of them somebody else's.
    return out, SourceReport("certspotter", Outcome.OK,
                             len({n for n, _ in out}), returned)


def certificates_from_certspotter(apex: str, permit=None, budget=None,
                                  limiter=None):
    """The FIELDS `from_certspotter` throws away.

    Discovery needs names, so that function extracts SANs and discards issuer,
    validity window, signature algorithm and subject organisation. Those are
    exactly the fields Recorded Future sells as "10+ years of historical
    SSL/TLS data" — and Certificate Transparency gives them away.

    Kept as a SEPARATE call rather than widening `from_certspotter`, because
    that function is on the discovery path where the only thing wanted is
    names, and returning richer objects there would change a contract several
    callers depend on for the sake of a use case none of them has.

    Everything returned is `Observed.ISSUED`. A CT log records issuance; it
    says nothing about deployment, and `core/certificates.py` carries that
    distinction into every result.
    """
    from core.certificates import Certificate, Observed

    url = ("https://api.certspotter.com/v1/issuances"
           f"?domain={urllib.parse.quote(apex)}"
           "&include_subdomains=true&expand=dns_names&expand=issuer")
    try:
        payload = _get(permit, url, budget, limiter)
    except egress.PermitMismatch:
        raise
    except Exception as exc:                     # noqa: BLE001
        return [], SourceReport("certspotter-certs", Outcome.FAILED, 0, 0,
                                _why(exc))
    if not isinstance(payload, list):
        message = (payload or {}).get("message", "unexpected response shape")
        return [], SourceReport("certspotter-certs", Outcome.FAILED, 0, 0,
                                str(message)[:80])

    out = []
    for record in payload:
        names = [_clean(raw, apex) for raw in record.get("dns_names") or []]
        names = [n for n in names if n]
        if not names:
            continue
        issuer = record.get("issuer") or {}
        if isinstance(issuer, dict):
            issuer_name = str(issuer.get("name") or issuer.get("friendly_name")
                              or "unknown")
        else:
            issuer_name = str(issuer or "unknown")
        out.append(Certificate(
            # The first in-apex name is the subject for our purposes. A
            # certificate covers many names and this is the one we asked about.
            host=names[0],
            issuer=issuer_name,
            not_before=str(record.get("not_before") or "")[:10],
            not_after=str(record.get("not_after") or "")[:10],
            observed=Observed.ISSUED,
            serial=str(record.get("cert_sha256") or "")[:32],
            # CertSpotter does not publish the signature algorithm on this
            # endpoint. Left empty rather than guessed — `cert.weak_signature`
            # simply will not fire from this source, which is honest.
            signature_algorithm="",
            organisation="",
            sans=tuple(names)))
    return out, SourceReport("certspotter-certs", Outcome.OK, len(out),
                             len(payload))


def from_crtsh(apex: str, permit=None, budget=None, limiter=None):
    """crt.sh. Frequently unavailable — kept because when it answers it is the
    broadest source, and its absence is reported rather than hidden."""
    url = f"https://crt.sh/?q={urllib.parse.quote('%.' + apex)}&output=json"
    try:
        payload = _get(permit, url, budget, limiter)
    except egress.PermitMismatch:
        raise
    except Exception as exc:                     # noqa: BLE001
        return [], SourceReport("crt.sh", Outcome.FAILED, 0, 0, _why(exc))
    if not isinstance(payload, list):
        return [], SourceReport("crt.sh", Outcome.FAILED, 0, 0,
                                "unexpected response shape")
    out: List[Tuple[str, Optional[date]]] = []
    returned = 0
    for record in payload:
        seen = _parse_day(record.get("not_before"))
        for raw in str(record.get("name_value") or "").split("\n"):
            returned += 1
            name = _clean(raw, apex)
            if name:
                out.append((name, seen))
    return out, SourceReport("crt.sh", Outcome.OK,
                             len({n for n, _ in out}), returned)


#: Order matters only for reporting. Every source is queried regardless.
SOURCES = (from_certspotter, from_crtsh)


def discover(apex: str, permit=None, sources: Optional[Iterable] = None,
             budget=None, limiter=None) -> DiscoveryResult:
    """Names certificate transparency knows about, from every source that answers.

    `permit` comes from `core.gate.authorise(apex, "ct_log_search", ...)`. It is
    keyword-optional only so the existing tests can inject fake sources that
    never reach `egress`; a real source will raise `PermitMismatch` without one,
    which is the correct failure and is asserted in tests/test_ct_discovery.py.
    """
    apex = str(apex).strip().lower().rstrip(".")
    if not apex:
        raise ValueError("an apex domain is required")

    merged: Dict[str, DiscoveredName] = {}
    reports: List[SourceReport] = []
    for source in (sources if sources is not None else SOURCES):
        try:
            rows, report = source(apex, permit, budget, limiter)
        except TypeError:
            # A test double with the older single-argument signature.
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
