"""InternetDB — Shodan's own free endpoint, and the one thing it cannot do.

WHAT THIS IS
------------
`https://internetdb.shodan.io/{ip}` answers with the same crawl that backs the
paid Shodan API, projected down to five fields and served without a key:
`ports`, `vulns`, `cpes`, `hostnames`, `tags`.

It exists here because `collect/keyed_sources.py` states the reason the paid key
was ever needed: SKOPOS may not probe a target whose ownership is unproven, so
for a domain somebody typed into a box the only passive route to service-level
facts is a third party who already scanned it. InternetDB is that third party,
for free.

WHY THIS IS OFF BY DEFAULT DESPITE NEEDING NO CREDENTIAL
---------------------------------------------------------
Shodan's terms: *"It's free for non-commercial use! If you're using the
InternetDB API to make money then you need an enterprise license."*

Whether a given deployment is making money is a fact about the operator, not
about this code — and this repository is MIT, so it is cloned by operators who
will answer differently from the one who added the file. `collect/registry.py`
already set this precedent for `hackertarget`: NONCOMMERCIAL, default off,
"SKOPOS must not make that call for the operator."

So this source is registered, reportable, and **inert until the operator sets
`SKOPOS_INTERNETDB_ACK`**. That variable is not a credential. It is an
acknowledgement, and it is named so that setting it is a deliberate act rather
than a config file someone copied.

WHAT IT GAINS OVER THE PAID API, WHICH IS NOT NOTHING
-------------------------------------------------------
The paid API returns `data[].product` and `data[].version` — free text from a
banner, which `core/signatures.py` exists to translate into catalogue spellings.
InternetDB returns `cpes` instead: `cpe:/a:apache:http_server:2.4.7` is already
vendor, product and version in the catalogue's own identifier format, with no
translation step to get wrong.

WHAT IT LOSES, WHICH IS ALSO NOT NOTHING
------------------------------------------
1. **No banners**, so no product tied to a specific port. You learn the host
   runs OpenSSH 6.6.1p1 and that 22 is open; not that they are the same service.
2. **Weekly updates**, not continuous. Stated on every answer rather than
   absorbed — the same discipline D1 applies to the vendored corpus.
3. **IPv4 addresses only.** A domain must be resolved first, and the answer is
   then about the address, not the name.

CPES ARE NOT PROMOTED TO DETERMINATIONS EITHER
------------------------------------------------
A CPE from a scanner is still a claim derived from a banner by the party whose
patch state is the question. `core/identity.py` refuses to let an observed
version reach the field a published range is evaluated against, and routing one
in through a third party's CPE string would defeat that refusal just as surely
as Shodan's `vulns` list would. Everything here is an observation carrying a
source and a date.
"""
from __future__ import annotations

# NETWORK-BOUNDARY: advisory_lookup

import ipaddress
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from collect import egress
from collect.keyed_sources import SourceAnswer

#: A passive read of a third party's published index. It never reaches the
#: target being asked about — the same operation the keyed sources use.
OPERATION = "advisory_lookup"

#: Not a credential. An acknowledgement that this deployment is non-commercial,
#: which only the operator can make.
ACK_ENV = "SKOPOS_INTERNETDB_ACK"

TERMS = ("Free for non-commercial use. Commercial use requires an enterprise "
         "licence from Shodan. SKOPOS cannot determine which applies to this "
         f"deployment, so it stays inert until {ACK_ENV} is set.")

#: Shodan states this on the API's own page. Reported with every answer, because
#: an index that is up to seven days old is a different fact from a live probe
#: and a reader who was never told has been misled.
UPDATE_INTERVAL = "weekly"

#: Cloudflare fronts this endpoint and returns 403 to Python's default urllib
#: User-Agent. Measured, not guessed. A real string is required, and identifying
#: the client honestly is better manners than borrowing a browser's.
USER_AGENT = "SKOPOS/1.0 (+https://github.com/Krishcalin; ETLM; passive lookup)"

BASE = "https://internetdb.shodan.io"


def acknowledged() -> bool:
    """Whether the operator has stated this deployment is non-commercial."""
    value = os.environ.get(ACK_ENV, "").strip().lower()
    # Fails closed on anything unrecognised, like every other switch in this
    # codebase: a typo must not silently enable a source whose terms may not
    # apply to the deployment running it.
    return value in {"1", "true", "yes", "noncommercial", "non-commercial"}


def _unacknowledged() -> SourceAnswer:
    return SourceAnswer(
        "internetdb", False, False,
        detail=("not enabled. This source is free only for non-commercial use "
                f"and SKOPOS will not decide that for you — set {ACK_ENV} if it "
                "applies, or supply SKOPOS_SHODAN_API_KEY instead."),
        verified_live=True)


def parse_cpe(cpe: str) -> Optional[Tuple[str, str, str]]:
    """`cpe:/a:apache:http_server:2.4.7` -> ("apache", "http_server", "2.4.7").

    Handles both the 2.2 URI form (`cpe:/a:v:p:ver`) and the 2.3 formatted-string
    form (`cpe:2.3:a:v:p:ver:...`), because Shodan emits the first and most
    other things emit the second, and a parser that silently returns None for
    half its inputs looks like sparse data rather than a bug.

    Returns None when there is no version — deliberately, rather than an empty
    string. A missing version is the single most consequential fact about a CPE
    here, and `("apache", "http_server", "")` invites a caller to treat it as
    present.
    """
    text = str(cpe or "").strip().lower()
    if not text.startswith("cpe:"):
        return None
    if text.startswith("cpe:2.3:"):
        parts = text.split(":")
        # cpe : 2.3 : part : vendor : product : version
        if len(parts) < 6:
            return None
        vendor, product, version = parts[3], parts[4], parts[5]
    else:
        body = text[len("cpe:"):].lstrip("/")
        parts = body.split(":")
        # part : vendor : product : version
        if len(parts) < 4:
            return None
        vendor, product, version = parts[1], parts[2], parts[3]
    # `*` and `-` are CPE's own "any" and "not applicable". Neither is a version.
    if not version or version in {"*", "-"}:
        return None
    if not vendor or not product:
        return None
    return vendor, product, version


def host(permit, address: str, budget=None, limiter=None) -> SourceAnswer:
    """Open ports, claimed CVEs and CPEs for one IPv4 address."""
    if not acknowledged():
        return _unacknowledged()
    try:
        parsed = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return SourceAnswer("internetdb", True, False,
                            detail=f"{address!r} is not an IP address; "
                                   "InternetDB indexes addresses, not names",
                            verified_live=True)
    if parsed.version != 4:
        # Stated rather than attempted. A 404 for an IPv6 address would read as
        # "nothing is listening" when the truth is "this index does not cover
        # that address family at all".
        return SourceAnswer("internetdb", True, False,
                            detail="InternetDB indexes IPv4 only; this address "
                                   "is IPv6 and its exposure is unknown here",
                            verified_live=True)

    try:
        response = egress.http_get(permit, OPERATION, f"{BASE}/{parsed}",
                                   budget=budget, limiter=limiter,
                                   headers={"User-Agent": USER_AGENT,
                                            "Accept": "application/json"})
    except egress.PermitMismatch:
        raise
    except Exception as exc:                                    # noqa: BLE001
        return SourceAnswer("internetdb", True, False,
                            detail=f"lookup failed: {type(exc).__name__}",
                            verified_live=True)
    return shape(response.status, response.text)


def shape(status: int, body: str) -> SourceAnswer:
    """Split out so the parsing is testable without a network.

    `verified_live=True` throughout, and unlike the keyed sources that is not a
    promise anybody has to take on trust: this endpoint needs no credential, so
    `tests/test_internetdb.py` runs it against the real service whenever the
    network is up.
    """
    if status == 404:
        return SourceAnswer("internetdb", True, True, detail=(
            "Shodan's index has no record of this address. That means it has "
            "not been scanned or indexed, never that nothing is listening."),
            verified_live=True)
    if status == 403:
        return SourceAnswer("internetdb", True, False, detail=(
            "HTTP 403. The endpoint is behind Cloudflare and rejects requests "
            "without a real User-Agent; this build sends one, so a 403 here "
            "means something upstream stripped it."), verified_live=True)
    if status == 429:
        return SourceAnswer("internetdb", True, False,
                            detail="rate limited (HTTP 429)", verified_live=True)
    if status != 200:
        return SourceAnswer("internetdb", True, False,
                            detail=f"HTTP {status}", verified_live=True)
    try:
        payload = json.loads(body)
    except ValueError:
        return SourceAnswer("internetdb", True, False,
                            detail="HTTP 200 with an unparseable body",
                            verified_live=True)
    if not isinstance(payload, dict):
        return SourceAnswer("internetdb", True, False,
                            detail="HTTP 200 with a non-object body",
                            verified_live=True)

    observations: List[Dict[str, Any]] = []

    for port in sorted(payload.get("ports") or []):
        observations.append({
            "kind": "port",
            "port": port,
            "source": "internetdb",
            "freshness": UPDATE_INTERVAL,
        })

    unparsed = 0
    for cpe in sorted(payload.get("cpes") or []):
        fields = parse_cpe(cpe)
        if fields is None:
            unparsed += 1
            continue
        vendor, product, version = fields
        observations.append({
            "kind": "software",
            "cpe": cpe,
            "vendor": vendor,
            "product": product,
            "version": version,
            "source": "internetdb",
            "freshness": UPDATE_INTERVAL,
            # The same refusal `core/identity.py` makes about any observed
            # version. A CPE is structured, which makes it easier to read — not
            # more authoritative about what is installed.
            "basis": "a CPE Shodan derived from a banner. Structured, but still "
                     "the scanned party's own claim about itself; SKOPOS does "
                     "not evaluate a published range against it.",
        })

    for cve in sorted(payload.get("vulns") or []):
        observations.append({
            "kind": "vuln_claim",
            "cve": cve,
            "source": "internetdb",
            "freshness": UPDATE_INTERVAL,
            "basis": "inferred by Shodan from a banner, not a version "
                     "comparison. SKOPOS does not treat this as a determination "
                     "and does not join it to the catalogue.",
        })

    for name in sorted(payload.get("hostnames") or []):
        observations.append({
            "kind": "hostname",
            "hostname": name,
            "source": "internetdb",
            "freshness": UPDATE_INTERVAL,
            # Worth a caveat of its own: a name in Shodan's reverse index is not
            # a name the estate's owner put there, and on shared hosting it is
            # routinely somebody else's.
            "basis": "a name Shodan associates with this address. On shared "
                     "infrastructure it frequently belongs to another party.",
        })

    for tag in sorted(payload.get("tags") or []):
        observations.append({"kind": "tag", "tag": tag,
                             "source": "internetdb",
                             "freshness": UPDATE_INTERVAL})

    ports = sorted(payload.get("ports") or [])
    versioned = sum(1 for o in observations if o["kind"] == "software")
    detail = (f"{len(ports)} port(s) indexed"
              + (f": {', '.join(str(p) for p in ports[:12])}" if ports else "")
              + (" …" if len(ports) > 12 else "")
              + f". {versioned} versioned CPE(s)."
              + (f" {unparsed} CPE(s) carried no version." if unparsed else "")
              + f" Index refreshed {UPDATE_INTERVAL}; this is not a live probe.")
    return SourceAnswer("internetdb", True, True, observations, detail=detail,
                        verified_live=True)


__all__ = ["host", "shape", "parse_cpe", "acknowledged", "ACK_ENV", "OPERATION",
           "TERMS", "UPDATE_INTERVAL", "USER_AGENT"]
