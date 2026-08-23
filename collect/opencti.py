"""Push SKOPOS findings into OpenCTI over TAXII 2.1.

WHY THIS IS THE RIGHT INTEGRATION AND NOT A CUSTOM API CLIENT
---------------------------------------------------------------
OpenCTI ships five built-in ingestion mechanisms, and one of them — **TAXII
Push** — accepts STIX 2.1 bundles at
`POST /taxii2/{root}/collections/{id}/objects/`. An administrator creates a
TAXII Push ingester, scopes it to a user, and that is the whole of the OpenCTI
side. **No connector code runs inside OpenCTI at all.**

The alternative, writing an `external-import` connector, means a Python service
in a Docker container registering over GraphQL, receiving RabbitMQ credentials
back from the platform, and publishing to a queue. It is the right shape when
OpenCTI must PULL on a schedule from something that cannot push. SKOPOS can
push, so it does.

WHY THIS NEEDS CONSENT AND IS OFF BY DEFAULT
----------------------------------------------
This is the same decision P5 made for alerting and P6 made for ticketing, and
the reasoning has not changed: **running a scan describes your estate to
yourself; pushing it to OpenCTI describes it to a system somebody else
administers**, even when that somebody is you. Consent to the first is not
consent to the second.

So `SKOPOS_OPENCTI_ON_SCAN` gates it, **in the environment rather than as a
request parameter**. If a caller could ask for a push, anyone who could reach
the scan endpoint could choose the moment an estate is transmitted. The switch
fails closed on any unrecognised value.

WHAT WE SEND, AND THE ONE THING WE DO NOT
-------------------------------------------
A bundle of `infrastructure`, its Cyber Observables, `vulnerability`,
`identity`, the relationships between them, and two notes carrying this
producer's caveats and refusals.

The TEPS score travels as `x_skopos_teps`, a NAMESPACED custom property, and
the namespacing is the whole point. It is a number computed under this
product's model against this corpus version; a consumer that stored it as a
native score would be holding a figure it cannot recompute, age or audit. Under
an `x_skopos_` prefix it is unmistakably somebody else's opinion, which is what
it is.

Note that OpenCTI's preservation of arbitrary `x_`-prefixed properties on STIX
import is **unverified** — it may drop silently. That is acceptable here
precisely because the score is not load-bearing: the basis is carried three
more ways (confidence, relationship type, and the description), and those are
all standard STIX that no consumer can misread.
"""
from __future__ import annotations

# NETWORK-BOUNDARY: intel_push

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Sequence

OPERATION = "intel_push"

#: The switch. Not a request parameter — see the module docstring.
ON_SCAN_ENV = "SKOPOS_OPENCTI_ON_SCAN"
URL_ENV = "SKOPOS_OPENCTI_URL"
TOKEN_ENV = "SKOPOS_OPENCTI_TOKEN"
COLLECTION_ENV = "SKOPOS_OPENCTI_COLLECTION"

#: OpenCTI's TAXII media type. Sending `application/json` gets a 415 and a
#: confusing afternoon.
MEDIA_TYPE = "application/taxii+json;version=2.1"

#: A bundle larger than this is split. OpenCTI's own guidance is that its
#: ingestion ceiling is Elasticsearch write throughput, with roughly tenfold
#: write amplification per message — so a single enormous bundle is the shape
#: most likely to stall a consumer rather than merely be slow.
MAX_OBJECTS_PER_BUNDLE = 2000

TIMEOUT = 30


class PushFailed(RuntimeError):
    """The push did not happen. Reported, never swallowed."""


def enabled() -> bool:
    """Whether pushing is switched on. Fails closed on anything unrecognised.

    A typo must not transmit a customer's estate to a system they did not mean
    to configure.
    """
    return os.environ.get(ON_SCAN_ENV, "").strip().lower() in {"1", "true", "yes"}


def _endpoint(base: str, collection: str) -> str:
    """The TAXII objects endpoint for a collection.

    Built here rather than configured whole, so an operator cannot accidentally
    point this at a URL that is not a TAXII collection and get a 200 from
    something else entirely.
    """
    root = str(base or "").rstrip("/")
    return f"{root}/taxii2/{collection}/objects/"


def split(objects: Sequence[Dict[str, Any]],
          limit: int = MAX_OBJECTS_PER_BUNDLE) -> List[List[Dict[str, Any]]]:
    """Chunk a bundle's objects, keeping each chunk self-contained enough.

    Relationships are emitted AFTER the objects they reference in this
    producer's bundles, so a naive split can put an edge in a different chunk
    from its endpoints. That is tolerable for TAXII — a consumer resolves
    references across pushes — but the chunks are kept large to make it rare.
    """
    rows = list(objects)
    if limit <= 0:
        return [rows]
    return [rows[i:i + limit] for i in range(0, len(rows), limit)] or [[]]


def push(bundle: Dict[str, Any], url: str = "", token: str = "",
         collection: str = "") -> Dict[str, Any]:
    """Send one bundle. Returns what happened; raises only on a real failure.

    THE FOUR STATES ARE REPORTED, not collapsed into a boolean, for the reason
    `core/alerting.py` gives: switched on with nothing configured looks
    identical to a quiet run from the outside, and a silent integration is
    worse than no integration because it is mistaken for coverage.
    """
    base = url or os.environ.get(URL_ENV, "")
    key = token or os.environ.get(TOKEN_ENV, "")
    name = collection or os.environ.get(COLLECTION_ENV, "")
    objects = list(bundle.get("objects") or [])

    if not objects:
        return {"pushed": False, "objects": 0,
                "reason": "the bundle was empty. A quiet run is a result, and "
                          "nothing was transmitted."}
    if not base:
        return {"pushed": False, "objects": len(objects),
                "reason": f"{URL_ENV} is not set. Pushing is switched on and "
                          f"there is nowhere to push to — which from outside "
                          f"looks exactly like a run that found nothing."}
    if not key:
        return {"pushed": False, "objects": len(objects),
                "reason": f"{TOKEN_ENV} is not set; OpenCTI would reject this."}
    if not name:
        return {"pushed": False, "objects": len(objects),
                "reason": f"{COLLECTION_ENV} is not set. It is the TAXII Push "
                          f"ingester's collection id from the OpenCTI UI."}
    if not base.lower().startswith("https://"):
        # The same refusal alerting makes. This payload is a description of an
        # estate's weaknesses and it does not travel in clear.
        return {"pushed": False, "objects": len(objects),
                "reason": f"{URL_ENV} is not https. A bundle describing where "
                          f"an estate is weak does not travel in clear."}

    endpoint = _endpoint(base, name)
    chunks = split(objects)
    sent = 0
    for chunk in chunks:
        payload = json.dumps({"type": "bundle",
                              "id": bundle.get("id"),
                              "objects": chunk}).encode()
        request = urllib.request.Request(
            endpoint, data=payload, method="POST",
            headers={"Content-Type": MEDIA_TYPE, "Accept": MEDIA_TYPE,
                     "Authorization": f"Bearer {key}"})
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                if response.status not in (200, 201, 202):
                    raise PushFailed(f"HTTP {response.status} from {endpoint}")
        except urllib.error.HTTPError as exc:
            raise PushFailed(
                f"HTTP {exc.code} from OpenCTI. 401 means the token is wrong; "
                f"404 usually means the collection id is not a TAXII Push "
                f"ingester; 415 means the media type was rejected.") from exc
        except Exception as exc:                                # noqa: BLE001
            raise PushFailed(f"{type(exc).__name__}: {exc}") from exc
        sent += len(chunk)

    return {"pushed": True, "objects": sent, "bundles": len(chunks),
            "endpoint": endpoint,
            "reason": f"{sent} object(s) pushed in {len(chunks)} bundle(s)."}


def push_for_run(findings: Sequence[Dict[str, Any]], org: str = "",
                 switched_on: Optional[bool] = None) -> Dict[str, Any]:
    """The decision, in one place, so a route and the scheduler cannot differ.

    Mirrors `core/itsm.file_for_run` deliberately: the same four states, the
    same refusal to let a caller request transmission, and the same insistence
    that a failure is reported rather than swallowed.
    """
    from core import stix

    rows = list(findings)
    if not rows:
        return {"pushed": False, "decided": 0,
                "reason": "no findings to push. A quiet run is a result."}
    if switched_on is None:
        switched_on = enabled()
    if not switched_on:
        return {
            "pushed": False, "decided": len(rows),
            "reason": (f"{len(rows)} finding(s) were ready to push and "
                       f"{ON_SCAN_ENV} is not set. Describing your estate to "
                       f"OpenCTI needs its own consent — a scan describes it "
                       f"to you, this describes it to a system somebody "
                       f"administers.")}
    try:
        result = push(stix.bundle(rows, org=org))
    except PushFailed as exc:
        return {"pushed": False, "decided": len(rows),
                "reason": (f"the push failed: {exc}. The findings are recorded "
                           f"and correct; only the transmission failed.")}
    result["decided"] = len(rows)
    return result


__all__ = ["OPERATION", "ON_SCAN_ENV", "URL_ENV", "TOKEN_ENV",
           "COLLECTION_ENV", "MEDIA_TYPE", "MAX_OBJECTS_PER_BUNDLE",
           "PushFailed", "enabled", "push", "push_for_run", "split",
           "_endpoint"]
