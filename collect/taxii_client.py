"""Poll a TAXII 2.1 server. The client half of `core/taxii.py`.

SKOPOS already SERVES TAXII (`core/taxii.py`) and PUSHES to one
(`collect/opencti.py`). This is the third leg: pulling from somebody else's, on
a schedule, without refetching what it already holds.

NO NETWORK IN THIS MODULE — THE TRANSPORT IS INJECTED
--------------------------------------------------------
`collect/egress.py` opens by declaring itself "the only module in SKOPOS that
touches the network", and every request through it is bound to a permit for a
specific estate asset. **A feed poll has no asset.** Reading somebody's
published collection touches nothing belonging to the estate under scan, which
is why `cti_feed_read` is PASSIVE and why the MISP fetch goes through
`tools/refresh_intel.py:_get` rather than the permit system.

So this module is a protocol driver: it decides what to request and what a
response means, and a `fetch` callable supplied by the caller does the I/O.
That keeps the egress invariant intact and makes every branch here testable
against a recorded document — which matters more than usual, because **four of
the five public TAXII servers this was measured against are dead**.

WHAT WAS MEASURED, 2026-08-24
--------------------------------
| Server | Result |
|---|---|
| `attack-taxii.mitre.org` | **live, keyless, readable** |
| `cti-taxii.mitre.org` | dead — MITRE retired it |
| `limo.anomali.com` | dead — the free Limo service is gone |
| `otx.alienvault.com/taxii` | HTTP 500 |
| `taxii.mcafee.com` | dead |

The free public TAXII landscape is one server. That is worth knowing before
anybody plans around it, and it is why `collect/stix_ingest.py` accepting any
bundle from any transport is the more durable capability.

THREE WAYS A REAL SERVER DIFFERS FROM THE SPECIFICATION
----------------------------------------------------------
All three are from the one server that works, so all three are load-bearing
rather than defensive programming.

**1. Discovery is at the server root, not under the API root.** Requesting
`/api/v21/taxii2/` returns `503 Not Implemented — The 'Get Status' endpoint is
not implemented`, because under an API root that path means something else
entirely. A client that builds discovery by appending to the API root gets a
503 and concludes the server is down. Discovery is `{origin}/taxii2/`.

**2. `api_roots` may be relative paths.** The specification says they are URLs;
MITRE returns `["/api/v21", "/api/v21/attack-1.0", ...]`. A client that treats
them as absolute produces `https:///api/v21`. `parse_discovery` resolves them
against the origin it was given.

**3. `next` may be an integer.** The specification says string; MITRE returns
`1`, then `2`. Coerced, because `str(1) != 1` is exactly the sort of thing that
silently ends a pagination loop after one page.

INCREMENTAL POLLING RUNS ON THE HEADER, NOT ON THE OBJECTS
-------------------------------------------------------------
The cursor for the next poll is `X-TAXII-Date-Added-Last` — when the SERVER
added the object to the collection — not any timestamp inside the STIX. An
object's `modified` is when its author changed it, which can be years before
the server received it. Bookkeeping on `modified` would re-fetch the same
backlog on every run and still miss late-arriving old objects.
"""
from __future__ import annotations

# NETWORK-BOUNDARY: cti_feed_read

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlencode, urlsplit, urlunsplit

#: The media type a TAXII 2.1 server expects and returns. `collect/opencti.py`
#: learned the hard way that a collection may ADVERTISE a type it then rejects,
#: so this is sent on requests and not inferred from a collection's own
#: `media_types` list.
MEDIA_TYPE = "application/taxii+json;version=2.1"

#: Objects per request. Servers cap this themselves and may return fewer; it is
#: a hint, not a contract.
DEFAULT_PAGE_SIZE = 100

#: Ceilings, so one poll of a large collection cannot run unbounded. Both are
#: REPORTED when hit — `core/validation.py` and `core/itsm.py` announce their
#: caps for the same reason: a truncated result that does not say so reads as
#: a complete one.
MAX_PAGES = 50
MAX_OBJECTS = 20_000


class TaxiiError(RuntimeError):
    """The server answered, and the answer was not usable."""


class TaxiiMalformed(TaxiiError):
    """The document is not TAXII. Raised rather than returning nothing.

    An empty result and an unparseable document look identical to a caller,
    and one of them means the stored cursor must not advance.
    """


#: What a transport must provide: (url, headers) -> (body, response_headers).
#: Response headers are needed because the incremental cursor lives in one.
Fetch = Callable[[str, Dict[str, str]], Tuple[bytes, Dict[str, str]]]


def _loads(raw: Any, what: str) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise TaxiiMalformed(f"{what} is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise TaxiiMalformed(f"{what} is not a mapping")
    return payload


def origin_of(url: str) -> str:
    """`https://h/api/v21/collections/` -> `https://h`."""
    parts = urlsplit(str(url or ""))
    if not parts.scheme or not parts.netloc:
        raise TaxiiError(f"not an absolute URL: {url!r}")
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def discovery_url(server_url: str) -> str:
    """Discovery is `{origin}/taxii2/` — NOT `{api_root}/taxii2/`.

    See the module docstring: the latter is a different endpoint that MITRE
    answers with `503 Not Implemented`, which reads as an outage.
    """
    return origin_of(server_url) + "/taxii2/"


@dataclass(frozen=True)
class Server:
    """A discovery response, with every API root resolved to an absolute URL."""

    title: str
    api_roots: Tuple[str, ...]
    default: str = ""
    description: str = ""

    @property
    def preferred(self) -> str:
        """The root to poll when the caller did not name one."""
        return self.default or (self.api_roots[0] if self.api_roots else "")


def parse_discovery(raw: Any, server_url: str) -> Server:
    """Discovery document -> `Server`, resolving relative API roots.

    MITRE returns `["/api/v21", ...]` where the specification says URLs. A
    client that treats those as absolute builds `https:///api/v21`.
    """
    payload = _loads(raw, "discovery document")
    origin = origin_of(server_url)

    def absolute(value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        if text.startswith(("http://", "https://")):
            return text.rstrip("/")
        return origin + "/" + text.lstrip("/").rstrip("/")

    roots = tuple(r for r in (absolute(v) for v in payload.get("api_roots") or ()) if r)
    if not roots and not payload.get("default"):
        raise TaxiiMalformed(
            "discovery document lists no api_roots and no default — a TAXII "
            "server with nothing to poll is a different document")
    return Server(
        title=str(payload.get("title") or ""),
        description=str(payload.get("description") or ""),
        api_roots=roots,
        default=absolute(payload.get("default") or ""),
    )


@dataclass(frozen=True)
class Collection:
    """One collection a server offers."""

    id: str
    title: str = ""
    description: str = ""
    can_read: bool = True
    can_write: bool = False
    media_types: Tuple[str, ...] = ()

    @property
    def readable(self) -> bool:
        return bool(self.id) and self.can_read


def collections_url(api_root: str) -> str:
    return str(api_root or "").rstrip("/") + "/collections/"


def parse_collections(raw: Any) -> List[Collection]:
    payload = _loads(raw, "collections document")
    items = payload.get("collections")
    if not isinstance(items, list):
        raise TaxiiMalformed(
            "collections document has no `collections` list — an empty list "
            "and a missing one mean different things, and only one of them "
            "means the server has nothing to offer")
    out: List[Collection] = []
    for item in items:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        out.append(Collection(
            id=str(item["id"]),
            title=str(item.get("title") or ""),
            description=str(item.get("description") or ""),
            # Absent `can_read` is treated as readable: the specification's
            # default is true, and a server that means otherwise says so.
            can_read=bool(item.get("can_read", True)),
            can_write=bool(item.get("can_write", False)),
            media_types=tuple(str(m) for m in (item.get("media_types") or ())),
        ))
    return out


def objects_url(api_root: str, collection_id: str) -> str:
    return (f"{str(api_root or '').rstrip('/')}"
            f"/collections/{collection_id}/objects/")


@dataclass(frozen=True)
class Page:
    """One envelope, plus the two headers that drive incremental polling."""

    objects: Tuple[Dict[str, Any], ...]
    more: bool = False
    next: str = ""
    date_added_first: str = ""
    date_added_last: str = ""

    def __len__(self) -> int:
        return len(self.objects)


def parse_envelope(raw: Any,
                   headers: Optional[Dict[str, str]] = None) -> Page:
    """An envelope + response headers -> `Page`.

    `next` is coerced to a string because MITRE returns an integer where the
    specification says string, and `str(1) != 1` silently ends a pagination
    loop after its first page.
    """
    payload = _loads(raw, "envelope")
    objects = payload.get("objects")
    if objects is None:
        objects = []
    if not isinstance(objects, list):
        raise TaxiiMalformed("envelope `objects` is not a list")

    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cursor = payload.get("next")
    return Page(
        objects=tuple(o for o in objects if isinstance(o, dict)),
        more=bool(payload.get("more")),
        next="" if cursor is None else str(cursor),
        date_added_first=lowered.get("x-taxii-date-added-first", ""),
        date_added_last=lowered.get("x-taxii-date-added-last", ""),
    )


@dataclass
class PollState:
    """Per-collection bookkeeping, persisted between runs.

    `added_after` is the whole point: without it every poll refetches the
    collection from the beginning, which for MITRE's Enterprise ATT&CK is tens
    of thousands of objects to learn nothing new.
    """

    server: str
    api_root: str
    collection: str
    #: `X-TAXII-Date-Added-LAST` from the previous poll. See the module
    #: docstring on why this is a header rather than an object timestamp.
    added_after: str = ""
    last_polled: str = ""
    objects_seen: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"server": self.server, "api_root": self.api_root,
                "collection": self.collection, "added_after": self.added_after,
                "last_polled": self.last_polled,
                "objects_seen": self.objects_seen}

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "PollState":
        return cls(server=str(raw.get("server") or ""),
                   api_root=str(raw.get("api_root") or ""),
                   collection=str(raw.get("collection") or ""),
                   added_after=str(raw.get("added_after") or ""),
                   last_polled=str(raw.get("last_polled") or ""),
                   objects_seen=int(raw.get("objects_seen") or 0))

    @property
    def key(self) -> str:
        return f"{self.api_root}|{self.collection}"


def request_url(api_root: str, collection_id: str,
                added_after: str = "", limit: int = DEFAULT_PAGE_SIZE,
                cursor: str = "") -> str:
    """The next URL to request, with only the parameters that apply."""
    params: List[Tuple[str, str]] = []
    if added_after:
        params.append(("added_after", added_after))
    if limit:
        params.append(("limit", str(int(limit))))
    if cursor:
        params.append(("next", cursor))
    base = objects_url(api_root, collection_id)
    return f"{base}?{urlencode(params)}" if params else base


@dataclass
class PollReport:
    """What a poll did, and everything it stopped short of."""

    pages: int = 0
    objects: int = 0
    stopped_by_page_cap: bool = False
    stopped_by_object_cap: bool = False
    stopped_by_stalled_cursor: bool = False
    incremental: bool = False
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pages": self.pages, "objects": self.objects,
            "incremental": self.incremental,
            "stopped_by_page_cap": self.stopped_by_page_cap,
            "stopped_by_object_cap": self.stopped_by_object_cap,
            "stopped_by_stalled_cursor": self.stopped_by_stalled_cursor,
            "error": self.error or None,
            "caps": {"max_pages": MAX_PAGES, "max_objects": MAX_OBJECTS},
        }


def poll(fetch: Fetch, state: PollState,
         page_size: int = DEFAULT_PAGE_SIZE,
         max_pages: int = MAX_PAGES,
         max_objects: int = MAX_OBJECTS,
         now: str = "",
         ) -> Tuple[List[Dict[str, Any]], PollState, PollReport]:
    """Page through a collection, returning STIX objects and the new state.

    THE CURSOR ADVANCES ONLY ON SUCCESS. If a page fails to parse, `added_after`
    keeps its previous value so the next run retries that ground rather than
    skipping it — a poller that advances past an error silently loses whatever
    was in the page it could not read.
    """
    collected: List[Dict[str, Any]] = []
    report = PollReport(incremental=bool(state.added_after))
    cursor = ""
    seen_cursors: set = set()
    latest_added = state.added_after

    while True:
        if report.pages >= max_pages:
            report.stopped_by_page_cap = True
            break
        url = request_url(state.api_root, state.collection,
                          added_after=state.added_after, limit=page_size,
                          cursor=cursor)
        try:
            body, headers = fetch(url, {"Accept": MEDIA_TYPE})
            page = parse_envelope(body, headers)
        except TaxiiError as exc:
            report.error = str(exc)[:200]
            break
        except Exception as exc:                              # noqa: BLE001
            report.error = f"{type(exc).__name__}: {exc}"[:200]
            break

        report.pages += 1
        collected.extend(page.objects)
        report.objects = len(collected)
        # The LAST added date across every page is the next run's floor.
        if page.date_added_last and page.date_added_last > latest_added:
            latest_added = page.date_added_last

        if len(collected) >= max_objects:
            report.stopped_by_object_cap = True
            break
        if not page.more or not page.next:
            break
        if page.next in seen_cursors:
            # A server repeating a cursor would spin forever. Treated as a
            # server fault and reported, rather than silently returning a
            # partial result that looks complete.
            report.stopped_by_stalled_cursor = True
            break
        seen_cursors.add(page.next)
        cursor = page.next

    advanced = PollState(
        server=state.server, api_root=state.api_root,
        collection=state.collection,
        # Only advance when the run produced no error. See the docstring.
        added_after=(latest_added if not report.error else state.added_after),
        last_polled=now or state.last_polled,
        objects_seen=state.objects_seen + len(collected),
    )
    return collected, advanced, report


def load_state(raw: Any) -> Dict[str, PollState]:
    """The persisted cursor file -> {key: PollState}."""
    if not raw:
        return {}
    payload = raw if isinstance(raw, dict) else json.loads(raw)
    out: Dict[str, PollState] = {}
    for item in payload.get("collections") or ():
        if not isinstance(item, dict):
            continue
        state = PollState.from_dict(item)
        if state.collection and state.api_root:
            out[state.key] = state
    return out


def dump_state(states: Sequence[PollState], built_on: str = "") -> Dict[str, Any]:
    return {
        "_meta": {
            "built_on": built_on,
            "note": ("TAXII poll cursors. `added_after` is the server's "
                     "X-TAXII-Date-Added-Last from the previous run — when the "
                     "SERVER received the object, not when its author wrote "
                     "it. See collect/taxii_client.py."),
        },
        "collections": [s.to_dict() for s in states],
    }
