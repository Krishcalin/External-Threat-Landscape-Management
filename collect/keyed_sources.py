"""The licensed sources: Shodan, VirusTotal, Have I Been Pwned.

WHY THESE EXIST AT ALL, WHICH IS NOT CONVENIENCE
--------------------------------------------------
SKOPOS may not probe a target whose ownership is unproven — every active
operation fails closed against one, before scope is consulted. So for a domain
somebody typed into a box there is exactly one passive route to service-level
facts: a third party who already scanned it. That is what a Shodan key buys, and
it is the only thing that buys it.

WHAT IS VERIFIED HERE AND WHAT IS NOT — READ THIS BEFORE TRUSTING A RESULT
---------------------------------------------------------------------------
The response PARSING is tested against recorded fixtures, so the shaping,
the field extraction and every refusal path are exercised.

The LIVE CALLS ARE NOT VERIFIED. They were written against each vendor's
documented contract and have never been run against the real service, because
this build has no keys. An API that changed a field name, paginates differently
than documented, or returns a shape the docs do not mention would break here and
the fixtures would not catch it.

That is stated rather than discovered: every source reports `verified_live:
false` until somebody runs it with a real key and flips it. A first run against
a live key should be treated as the actual test.

EVERY ANSWER IS AN OBSERVATION, NEVER AN ATTRIBUTION
-----------------------------------------------------
VirusTotal says engines flagged a thing on a date. HIBP says an address appeared
in a published breach. Neither says an account is compromised now, and neither
says who is targeting anybody. P3 measured what CVE-to-actor attribution is
worth — a median of 57 threat groups per CVE — and closed it. These sources do
not reopen it, and the shapes below carry a source and a date precisely so a
reader can tell an observation from a claim.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from collect import egress, registry

#: Every keyed call is an `advisory_lookup` — a PASSIVE read of a third party's
#: published index. It never reaches the target being asked about.
OPERATION = "advisory_lookup"

#: None of these paths has been executed against the live service. Flip a source
#: to True only after a real key has been used against it and the parsing held.
VERIFIED_LIVE: Dict[str, bool] = {
    "shodan": False,
    "virustotal": False,
    "hibp": False,
}

UNVERIFIED_NOTE = (
    "This source's live call has NOT been executed against the real service. "
    "Its response parsing is covered by recorded fixtures, but a vendor API that "
    "changed a field, paginated differently, or returned an undocumented shape "
    "would break here without a fixture catching it. Treat the first run with a "
    "real key as the test.")


@dataclass
class SourceAnswer:
    """What one keyed source said, or why it said nothing.

    `available` and `answered` are separate on purpose. A source with no key is
    UNAVAILABLE; a source that ran and found nothing ANSWERED with an empty
    result. Collapsing them turns "we have no key" into "there is nothing
    there", which is the single most consequential lie this module could tell.
    """

    source: str
    available: bool
    answered: bool = False
    observations: List[Dict[str, Any]] = field(default_factory=list)
    detail: str = ""
    verified_live: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "available": self.available,
            "answered": self.answered,
            "observations": list(self.observations),
            "detail": self.detail,
            "verified_live": self.verified_live,
            "caveat": None if self.verified_live else UNVERIFIED_NOTE,
        }


def _key(source: str) -> str:
    entry = registry.BY_NAME.get(source)
    return os.environ.get(entry.credential_env or "", "") if entry else ""


def _unavailable(source: str) -> SourceAnswer:
    entry = registry.BY_NAME.get(source)
    env = entry.credential_env if entry else "the credential"
    return SourceAnswer(
        source=source, available=False,
        detail=f"{env} is not set, so this source was not consulted. That is "
               f"NOT a result — nothing here says the target is clean.")


# ── Shodan ───────────────────────────────────────────────────────────────────
def shodan_host(permit, address: str, budget=None,
                limiter=None) -> SourceAnswer:
    """Open ports and service banners somebody else already collected.

    THE ONLY PASSIVE ROUTE TO SERVICE DATA for a target this product may not
    probe. Documented contract: GET /shodan/host/{ip}?key=… returns `ports`,
    `data[]` with `port`/`transport`/`product`/`version`, and `vulns`.

    `vulns` IS DELIBERATELY NOT PROMOTED TO A FINDING. Shodan derives it from a
    banner, and this product's whole discipline is that a banner is a claim by
    the party whose patch state is the question — `core/identity.py` refuses to
    let an observed version reach the field a published range is evaluated
    against. Carrying Shodan's CVE list as a determination would route around
    that refusal through a third party. It is reported as what it is: something
    Shodan inferred, from a banner, on a date.
    """
    key = _key("shodan")
    if not key:
        return _unavailable("shodan")
    url = f"https://api.shodan.io/shodan/host/{address}?key={key}"
    try:
        response = egress.http_get(permit, OPERATION, url, budget=budget,
                                   limiter=limiter)
    except egress.PermitMismatch:
        raise
    except Exception as exc:                                    # noqa: BLE001
        return SourceAnswer("shodan", True, False,
                            detail=f"lookup failed: {type(exc).__name__}",
                            verified_live=VERIFIED_LIVE["shodan"])
    return _shape_shodan(response.status, response.text)


def _shape_shodan(status: int, body: str) -> SourceAnswer:
    """Split out so the parsing is testable without a key or a network."""
    verified = VERIFIED_LIVE["shodan"]
    if status == 404:
        # Shodan returns 404 for an address it has never scanned. That is
        # "unknown to Shodan", NOT "nothing is listening".
        return SourceAnswer("shodan", True, True, detail=(
            "Shodan has no record of this address. That means it has not been "
            "scanned or indexed, never that nothing is listening on it."),
            verified_live=verified)
    if status == 401:
        return SourceAnswer("shodan", True, False,
                            detail="the key was rejected (HTTP 401)",
                            verified_live=verified)
    if status != 200:
        return SourceAnswer("shodan", True, False,
                            detail=f"HTTP {status}", verified_live=verified)
    try:
        payload = json.loads(body)
    except ValueError:
        return SourceAnswer("shodan", True, False,
                            detail="HTTP 200 with an unparseable body",
                            verified_live=verified)

    observations: List[Dict[str, Any]] = []
    for service in payload.get("data") or []:
        observations.append({
            "kind": "service",
            "port": service.get("port"),
            "transport": service.get("transport"),
            "product": service.get("product"),
            "version": service.get("version"),
            "observed_on": str(service.get("timestamp") or "")[:10],
            "source": "shodan",
        })
    for cve in sorted(payload.get("vulns") or []):
        observations.append({
            "kind": "vuln_claim",
            "cve": cve,
            "source": "shodan",
            # The distinction that keeps this out of the findings pipeline.
            "basis": "inferred by Shodan from a banner, not a version "
                     "comparison. SKOPOS does not treat this as a determination "
                     "and does not join it to the catalogue.",
        })
    ports = sorted(payload.get("ports") or [])
    return SourceAnswer("shodan", True, True, observations,
                        detail=f"{len(ports)} port(s) indexed: "
                               f"{', '.join(str(p) for p in ports[:12])}"
                               + (" …" if len(ports) > 12 else ""),
                        verified_live=verified)


# ── VirusTotal ───────────────────────────────────────────────────────────────
def virustotal_domain(permit, domain: str, budget=None,
                      limiter=None) -> SourceAnswer:
    """Engine detections and reputation for a name.

    Documented contract: GET /api/v3/domains/{domain} with `x-apikey`, returning
    `data.attributes.last_analysis_stats` and `reputation`.

    An engine detection is an OBSERVATION by a named vendor on a date. It is not
    a verdict, vendors disagree constantly, and a single malicious flag out of
    ninety is noise rather than signal — which is why the counts are carried
    whole rather than reduced to a boolean.
    """
    key = _key("virustotal")
    if not key:
        return _unavailable("virustotal")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        response = egress.http_get(permit, OPERATION, url, budget=budget,
                                   limiter=limiter, headers={"x-apikey": key})
    except egress.PermitMismatch:
        raise
    except Exception as exc:                                    # noqa: BLE001
        return SourceAnswer("virustotal", True, False,
                            detail=f"lookup failed: {type(exc).__name__}",
                            verified_live=VERIFIED_LIVE["virustotal"])
    return _shape_virustotal(response.status, response.text)


def _shape_virustotal(status: int, body: str) -> SourceAnswer:
    verified = VERIFIED_LIVE["virustotal"]
    if status == 404:
        return SourceAnswer("virustotal", True, True,
                            detail="VirusTotal holds no record for this name.",
                            verified_live=verified)
    if status in (401, 403):
        return SourceAnswer("virustotal", True, False,
                            detail=f"the key was rejected (HTTP {status})",
                            verified_live=verified)
    if status == 429:
        # The free tier is 4 requests/minute. Reported, never retried silently.
        return SourceAnswer("virustotal", True, False,
                            detail="rate limited (HTTP 429). The free tier is "
                                   "4 requests per minute.",
                            verified_live=verified)
    if status != 200:
        return SourceAnswer("virustotal", True, False, detail=f"HTTP {status}",
                            verified_live=verified)
    try:
        attributes = (json.loads(body).get("data") or {}).get("attributes") or {}
    except ValueError:
        return SourceAnswer("virustotal", True, False,
                            detail="HTTP 200 with an unparseable body",
                            verified_live=verified)

    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    total = sum(int(v or 0) for v in stats.values()) or None
    observations = [{
        "kind": "reputation",
        "source": "virustotal",
        "malicious": malicious,
        "suspicious": suspicious,
        "engines": total,
        "reputation": attributes.get("reputation"),
        "observed_on": str(date.today()),
        "meaning": (
            f"{malicious} of {total} engines flagged this name as malicious "
            f"and {suspicious} as suspicious. Engines disagree routinely; a "
            f"handful of flags out of ninety is noise, not a verdict, and none "
            f"of it says who is behind anything."
            if total else "no engine analysis is recorded"),
    }]
    return SourceAnswer("virustotal", True, True, observations,
                        detail=f"{malicious} malicious / {suspicious} suspicious"
                               f" of {total or 'unknown'} engines",
                        verified_live=verified)


# ── Have I Been Pwned ────────────────────────────────────────────────────────
def hibp_account(permit, address: str, budget=None,
                 limiter=None) -> SourceAnswer:
    """Breach corpora an email address appears in.

    Documented contract: GET /api/v3/breachedaccount/{account}?truncateResponse=false
    with `hibp-api-key`, returning a list of breaches; 404 means not found.

    WHAT THIS DOES NOT SAY. That the account is compromised now, that the
    password is still in use, or that anything should be revoked. It says the
    address appeared in a corpus that was published on a date. The remedy is
    somebody's judgement, and it is not this product's to assert.
    """
    key = _key("hibp")
    if not key:
        return _unavailable("hibp")
    url = ("https://haveibeenpwned.com/api/v3/breachedaccount/"
           f"{address}?truncateResponse=false")
    try:
        response = egress.http_get(
            permit, OPERATION, url, budget=budget, limiter=limiter,
            headers={"hibp-api-key": key, "user-agent": "SKOPOS"})
    except egress.PermitMismatch:
        raise
    except Exception as exc:                                    # noqa: BLE001
        return SourceAnswer("hibp", True, False,
                            detail=f"lookup failed: {type(exc).__name__}",
                            verified_live=VERIFIED_LIVE["hibp"])
    return _shape_hibp(response.status, response.text)


def _shape_hibp(status: int, body: str) -> SourceAnswer:
    verified = VERIFIED_LIVE["hibp"]
    if status == 404:
        # HIBP's documented "not found". A real answer, and a good one.
        return SourceAnswer("hibp", True, True, detail=(
            "This address does not appear in any breach HIBP has indexed. That "
            "is a real answer about the corpora it holds, not a guarantee."),
            verified_live=verified)
    if status == 401:
        return SourceAnswer("hibp", True, False,
                            detail="the key was rejected (HTTP 401)",
                            verified_live=verified)
    if status == 429:
        return SourceAnswer("hibp", True, False,
                            detail="rate limited (HTTP 429)",
                            verified_live=verified)
    if status != 200:
        return SourceAnswer("hibp", True, False, detail=f"HTTP {status}",
                            verified_live=verified)
    try:
        breaches = json.loads(body)
    except ValueError:
        return SourceAnswer("hibp", True, False,
                            detail="HTTP 200 with an unparseable body",
                            verified_live=verified)

    observations = [{
        "kind": "breach",
        "source": "hibp",
        "name": entry.get("Name"),
        "title": entry.get("Title"),
        "breach_date": entry.get("BreachDate"),
        "added_on": str(entry.get("AddedDate") or "")[:10],
        "accounts": entry.get("PwnCount"),
        "data_classes": entry.get("DataClasses") or [],
        # Carried because it changes what the breach means entirely.
        "verified": entry.get("IsVerified"),
        "meaning": ("this address appeared in a corpus published on the date "
                    "shown. It does not say the account is compromised now, or "
                    "that the password is still in use."),
    } for entry in (breaches if isinstance(breaches, list) else [])]
    return SourceAnswer("hibp", True, True, observations,
                        detail=f"appears in {len(observations)} indexed breach(es)",
                        verified_live=verified)


def consult_for_target(permit_for, target, budget=None,
                       limiter=None) -> List[SourceAnswer]:
    """Ask every keyed source that applies to this kind of target.

    `permit_for` is a callable taking an operation and returning a permit, so
    this module never touches the gate itself — it cannot mint its own
    authority.
    """
    from core.lookup import Kind

    # Imported here rather than at module scope: `internetdb` imports
    # `SourceAnswer` from this module, and a top-level import would be a cycle.
    from collect import internetdb

    answers: List[SourceAnswer] = []
    if target.kind in (Kind.ADDRESS, Kind.BLOCK):
        for address in list(target.addresses)[:8]:
            # PAID SHODAN FIRST, falling through only when it is unavailable.
            # An operator who has paid for banners and continuous indexing
            # should receive them; InternetDB is the same crawl up to a week old
            # with no banners, so preferring it would quietly downgrade a paying
            # deployment.
            #
            # The test is `available`, not `answered`. A key that exists and
            # errored is a failure worth reporting, not a reason to silently ask
            # somebody else and present the substitute's answer as the first
            # one's.
            answer = shodan_host(permit_for(OPERATION), address, budget, limiter)
            answers.append(answer)
            if not answer.available:
                answers.append(internetdb.host(permit_for(OPERATION), address,
                                               budget, limiter))
    else:
        answers.append(virustotal_domain(permit_for(OPERATION), target.value,
                                         budget, limiter))
    return answers


__all__ = ["OPERATION", "VERIFIED_LIVE", "UNVERIFIED_NOTE", "SourceAnswer",
           "shodan_host", "virustotal_domain", "hibp_account",
           "consult_for_target", "_shape_shodan", "_shape_virustotal",
           "_shape_hibp"]
