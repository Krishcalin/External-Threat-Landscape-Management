"""Passive name sources that are not certificate transparency.

Passive DNS (a resolver actually saw the name resolve), published subdomain
indexes, and a web crawl archive. All read through `collect/egress.py`, so none
of them carries its own permit check.

TEXT ENDPOINTS PARSE POSITIVELY
-------------------------------
Several of these return text or CSV with a 200 status even when they are telling
you about an error — "API count exceeded" arrives as a 200 with a body. A parser
that special-cases one known error string leaves every OTHER 200-with-error-body
reporting OK with zero names, which is a failure wearing a success and is
indistinguishable from a clean estate.

So a row counts only if it parses positively. If nothing parses and the body is
non-empty, the source reports FAILED with the first 80 characters as the detail —
which also means a new error message this code has never seen still fails loudly.

TRUNCATION IS DETECTED PER SOURCE
---------------------------------
A capped result set that reports OK is the same lie in a different shape. Each
source has its own tell: HackerTarget returns exactly 50 rows, mnemonic returns
a count equal to the requested limit, Wayback hands back a resume key.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime
from typing import List, Optional, Sequence, Tuple

from collect import egress
from collect.discovery import NameObservation
from collect.registry import DataClass
from collect.report import Outcome, SourceReport

_HOST = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

MNEMONIC_LIMIT = 1000
HACKERTARGET_CAP = 50


def _clean(name: str, apex: str) -> Optional[str]:
    """Normalise, and discard anything outside the requested apex.

    Third-party indexes routinely return neighbours — other tenants on shared
    infrastructure, or plain noise. Importing those attributes somebody else's
    estate to this customer, which is both wrong and a governance problem.
    """
    value = str(name or "").strip().lower().rstrip(".")
    if not value or " " in value:
        return None
    bare = value[2:] if value.startswith("*.") else value
    if not _HOST.match(bare):
        return None
    if bare != apex and not bare.endswith("." + apex):
        return None
    return value


def _epoch_day(value) -> Optional[date]:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    if seconds > 1_000_000_000_000:      # milliseconds
        seconds //= 1000
    try:
        return datetime.utcfromtimestamp(seconds).date()
    except (OverflowError, OSError, ValueError):
        return None


def _why(exc: Exception) -> str:
    return (str(exc).strip() or type(exc).__name__)[:80]


# ---------------------------------------------------------------- passive DNS
def from_mnemonic(apex: str, permit=None, budget=None, limiter=None):
    """mnemonic's passive DNS: did a resolver see this name resolve, and when.

    MEASURED, AND NOT WHAT IT LOOKS LIKE. The v3 endpoint does exact-name
    lookup, not wildcard enumeration — `/pdns/v3/*.iana.org` returns count=0.
    So this is a LIVENESS source, not a discovery source: it confirms
    resolutions and dates them, and the names it enumerates are only those
    already known.

    It also returns rows where the apex appears as the ANSWER rather than the
    query — other people's domains CNAME'd at yours. Measured against iana.org
    it returned `mobilered.ga`, `nexxtyear.tk` and `freemobiworld.cf`. Those are
    somebody else's estate and `_clean` drops them; that containment is the only
    thing standing between this source and attributing three strangers' domains
    to the customer.
    """
    url = f"https://api.mnemonic.no/pdns/v3/{apex}?limit={MNEMONIC_LIMIT}"
    try:
        response = egress.http_get(permit, "passive_dns", url, budget=budget,
                                   limiter=limiter,
                                   headers={"Accept": "application/json"})
        if response.status != 200:
            return [], SourceReport("mnemonic", Outcome.FAILED, 0, 0,
                                    f"HTTP {response.status}")
        payload = json.loads(response.text)
    except egress.PermitMismatch:
        raise
    except Exception as exc:                     # noqa: BLE001
        return [], SourceReport("mnemonic", Outcome.FAILED, 0, 0, _why(exc))

    rows = payload.get("data") or []
    out: List[NameObservation] = []
    for record in rows:
        name = _clean(record.get("query"), apex)
        if not name:
            continue
        answer = str(record.get("answer") or "")
        out.append(NameObservation(
            name=name, source="mnemonic", data_class=DataClass.PASSIVE_DNS,
            first_seen=_epoch_day(record.get("firstSeenTimestamp")),
            last_seen=_epoch_day(record.get("lastSeenTimestamp")),
            addresses=(answer,) if _IP.match(answer) else ()))

    # The count equalling the limit is the tell. Reporting OK here would present
    # a capped answer as a complete one.
    truncated = len(rows) >= MNEMONIC_LIMIT
    return out, SourceReport(
        "mnemonic", Outcome.PARTIAL if truncated else Outcome.OK,
        len({o.name for o in out}), len(rows),
        f"capped at {MNEMONIC_LIMIT}; there are more" if truncated else "")


def from_otx(apex: str, permit=None, budget=None, limiter=None):
    """AlienVault OTX. Anonymous access returns a SUBSET, so never reports OK."""
    import os

    key = os.environ.get("SKOPOS_OTX_API_KEY")
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns"
    headers = {"Accept": "application/json"}
    if key:
        headers["X-OTX-API-KEY"] = key
    try:
        response = egress.http_get(permit, "passive_dns", url, budget=budget,
                                   limiter=limiter, headers=headers)
        if response.status != 200:
            return [], SourceReport("otx", Outcome.FAILED, 0, 0,
                                    f"HTTP {response.status}")
        payload = json.loads(response.text)
    except egress.PermitMismatch:
        raise
    except Exception as exc:                     # noqa: BLE001
        return [], SourceReport("otx", Outcome.FAILED, 0, 0, _why(exc))

    rows = payload.get("passive_dns") or []
    out: List[NameObservation] = []
    for record in rows:
        name = _clean(record.get("hostname"), apex)
        if not name:
            continue
        address = str(record.get("address") or "")
        out.append(NameObservation(
            name=name, source="otx", data_class=DataClass.PASSIVE_DNS,
            first_seen=_parse_iso(record.get("first")),
            last_seen=_parse_iso(record.get("last")),
            addresses=(address,) if _IP.match(address) else ()))

    return out, SourceReport(
        "otx", Outcome.OK if key else Outcome.PARTIAL,
        len({o.name for o in out}), len(rows),
        "" if key else "queried anonymously; OTX returns public data only, so "
                       "this is a subset of what a credentialed query would give")


def _parse_iso(value) -> Optional[date]:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text[:19] if "T" in text or " " in text
                                     else text, fmt).date()
        except ValueError:
            continue
    return None


# ------------------------------------------------------------- name indexes
def from_anubis(apex: str, permit=None, budget=None, limiter=None):
    """Anubis/jldc — a published index. A JSON array of bare names, no dates.

    Returned HTTP 403 when tested on 2026-08-23; it appears to filter by client.
    Left registered and on by default rather than quietly removed, because it
    may well answer from another network — and the report vocabulary exists
    precisely so a source that refuses us says FAILED with its status instead of
    contributing a silent zero.
    """
    url = f"https://jldc.me/anubis/subdomains/{apex}"
    try:
        response = egress.http_get(permit, "subdomain_index_read", url,
                                   budget=budget, limiter=limiter,
                                   headers={"Accept": "application/json"})
        if 300 <= response.status < 400:
            # egress does not follow redirects — that is deliberate, so an
            # active probe cannot be carried to a host no permit covers. Name
            # the destination so an operator can decide whether to update the
            # registered URL.
            return [], SourceReport(
                "anubis", Outcome.FAILED, 0, 0,
                f"HTTP {response.status} to "
                f"{str(response.redirect_to or 'an unstated location')[:50]}")
        if response.status == 404:
            # Anubis 404s for a domain it has never indexed. That is an answer,
            # not a failure — and calling it FAILED would make a clean result
            # look like an outage.
            return [], SourceReport("anubis", Outcome.OK, 0, 0,
                                    "no index for this domain")
        if response.status != 200:
            return [], SourceReport("anubis", Outcome.FAILED, 0, 0,
                                    f"HTTP {response.status}")
        payload = json.loads(response.text)
    except egress.PermitMismatch:
        raise
    except Exception as exc:                     # noqa: BLE001
        return [], SourceReport("anubis", Outcome.FAILED, 0, 0, _why(exc))

    if not isinstance(payload, list):
        return [], SourceReport("anubis", Outcome.FAILED, 0, 0,
                                "unexpected response shape")
    out = [NameObservation(name=n, source="anubis",
                           data_class=DataClass.NAME_INDEX)
           for n in (_clean(raw, apex) for raw in payload) if n]
    return out, SourceReport("anubis", Outcome.OK, len({o.name for o in out}),
                             len(payload))


def from_hackertarget(apex: str, permit=None, budget=None, limiter=None):
    """HackerTarget. CSV over HTTP 200, including for its own error messages."""
    url = f"https://api.hackertarget.com/hostsearch/?q={apex}"
    try:
        response = egress.http_get(permit, "subdomain_index_read", url,
                                   budget=budget, limiter=limiter,
                                   headers={"Accept": "text/plain"})
        if response.status != 200:
            return [], SourceReport("hackertarget", Outcome.FAILED, 0, 0,
                                    f"HTTP {response.status}")
        body = response.text
    except egress.PermitMismatch:
        raise
    except Exception as exc:                     # noqa: BLE001
        return [], SourceReport("hackertarget", Outcome.FAILED, 0, 0, _why(exc))

    out: List[NameObservation] = []
    lines = [line for line in body.splitlines() if line.strip()]
    for line in lines:
        parts = line.split(",")
        if len(parts) != 2:
            continue
        name = _clean(parts[0], apex)
        address = parts[1].strip()
        if name and _IP.match(address):
            out.append(NameObservation(name=name, source="hackertarget",
                                       data_class=DataClass.NAME_INDEX,
                                       addresses=(address,)))

    if not out and body.strip():
        # POSITIVE PARSING. Nothing parsed but the body is non-empty, so this is
        # an error message wearing a 200 — report it verbatim rather than
        # special-casing the one string we happen to know about.
        return [], SourceReport("hackertarget", Outcome.FAILED, 0, 0,
                                body.strip()[:80])

    truncated = len(lines) >= HACKERTARGET_CAP
    return out, SourceReport(
        "hackertarget", Outcome.PARTIAL if truncated else Outcome.OK,
        len({o.name for o in out}), len(lines),
        f"exactly {HACKERTARGET_CAP} rows — the free tier's cap, so there are "
        f"more" if truncated else "")


# -------------------------------------------------------------- web archive
def from_wayback(apex: str, permit=None, budget=None, limiter=None):
    """The Wayback CDX index. A crawl timestamp is NOT a resolution.

    Its dates never populate `last_seen` — see collect/discovery.py. A page
    crawled once in 2016 says nothing about whether the name resolves today.
    """
    url = ("https://web.archive.org/cdx/search/cdx"
           f"?url=*.{apex}&output=json&fl=original&collapse=urlkey"
           "&limit=5000&showResumeKey=true")
    try:
        response = egress.http_get(permit, "web_archive_search", url,
                                   budget=budget, limiter=limiter,
                                   headers={"Accept": "application/json"})
        if response.status != 200:
            return [], SourceReport("wayback", Outcome.FAILED, 0, 0,
                                    f"HTTP {response.status}")
        payload = json.loads(response.text) if response.text.strip() else []
    except egress.PermitMismatch:
        raise
    except Exception as exc:                     # noqa: BLE001
        return [], SourceReport("wayback", Outcome.FAILED, 0, 0, _why(exc))

    rows = payload[1:] if payload and payload[0] == ["original"] else payload
    out: List[NameObservation] = []
    resume_key = False
    for row in rows:
        if not row or (len(row) == 1 and not str(row[0]).strip()):
            resume_key = True     # the blank row before a resume key
            continue
        original = str(row[0] if isinstance(row, list) else row)
        host = re.sub(r"^https?://", "", original).split("/")[0].split(":")[0]
        name = _clean(host, apex)
        if name:
            out.append(NameObservation(name=name, source="wayback",
                                       data_class=DataClass.WEB_ARCHIVE))
    return out, SourceReport(
        "wayback", Outcome.PARTIAL if resume_key else Outcome.OK,
        len({o.name for o in out}), len(rows),
        "a resume key was returned; there are more" if resume_key else "")


FETCHERS = {
    "mnemonic": from_mnemonic,
    "otx": from_otx,
    "anubis": from_anubis,
    "hackertarget": from_hackertarget,
    "wayback": from_wayback,
}

__all__ = ["FETCHERS", "from_mnemonic", "from_otx", "from_anubis",
           "from_hackertarget", "from_wayback"]
