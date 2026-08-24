"""Polling a TAXII 2.1 server, and the three ways a real one differs from the spec.

Every deviation asserted here was measured against `attack-taxii.mitre.org` on
2026-08-24 — the only one of five public TAXII servers still answering. They are
load-bearing behaviours, not defensive programming.

The transport is injected throughout, so none of this needs a live server. That
matters more than usual here: four of the five servers this was built against
are dead, and a test suite that depended on one would already be broken.
"""
from __future__ import annotations

import ast
import inspect
import json

import pytest

from collect import taxii_client as tc

SERVER = "https://taxii.example.org"
ROOT = "https://taxii.example.org/api/v21"
COLLECTION = "collection--abc"


def recorder(pages):
    """A fetch that replays prepared (body, headers) pairs and logs the URLs."""
    seen = []

    def fetch(url, headers):
        seen.append(url)
        body, response_headers = pages[min(len(seen) - 1, len(pages) - 1)]
        return json.dumps(body).encode(), response_headers

    fetch.urls = seen
    return fetch


def envelope(objects, more=False, nxt=None, added_last=""):
    body = {"objects": objects, "more": more}
    if nxt is not None:
        body["next"] = nxt
    headers = {"X-TAXII-Date-Added-Last": added_last} if added_last else {}
    return body, headers


# ── deviation 1: discovery is at the server root ────────────────────────────
def test_discovery_is_at_the_origin_not_under_the_api_root():
    """MITRE answers `/api/v21/taxii2/` with `503 Not Implemented — The 'Get
    Status' endpoint is not implemented`, because under an API root that path
    means something else. A client that builds discovery by appending to the
    API root reads that 503 as an outage."""
    assert tc.discovery_url(ROOT) == SERVER + "/taxii2/"
    assert tc.discovery_url(SERVER + "/api/v21/collections/") == SERVER + "/taxii2/"


def test_a_relative_url_is_refused_rather_than_guessed():
    with pytest.raises(tc.TaxiiError):
        tc.discovery_url("/api/v21")


# ── deviation 2: api_roots may be relative ──────────────────────────────────
def test_relative_api_roots_are_resolved_against_the_origin():
    """The specification says api_roots are URLs. MITRE returns
    `["/api/v21", ...]`, and a client treating those as absolute builds
    `https:///api/v21`."""
    server = tc.parse_discovery(
        {"title": "T", "api_roots": ["/api/v21", "/api/v21/attack-1.0"],
         "default": "/api/v21"}, SERVER)
    assert server.api_roots == (ROOT, ROOT + "/attack-1.0")
    assert server.default == ROOT
    assert server.preferred == ROOT


def test_absolute_api_roots_are_left_alone():
    server = tc.parse_discovery({"api_roots": [ROOT], "default": ROOT}, SERVER)
    assert server.api_roots == (ROOT,)


def test_a_discovery_document_with_nothing_to_poll_raises():
    with pytest.raises(tc.TaxiiMalformed):
        tc.parse_discovery({"title": "empty"}, SERVER)


# ── deviation 3: `next` may be an integer ───────────────────────────────────
def test_an_integer_cursor_is_coerced_to_a_string():
    """MITRE returns `1`, then `2`, where the specification says string.
    `str(1) != 1` silently ends a pagination loop after its first page."""
    page = tc.parse_envelope({"objects": [], "more": True, "next": 1})
    assert page.next == "1"


def test_a_missing_cursor_is_empty_not_none():
    assert tc.parse_envelope({"objects": []}).next == ""


# ── the cursor that makes polling incremental ───────────────────────────────
def test_the_cursor_comes_from_the_header_not_the_objects():
    """`X-TAXII-Date-Added-Last` is when the SERVER received the object. An
    object's own `modified` is when its author changed it, which can be years
    earlier — bookkeeping on that refetches the same backlog every run."""
    page = tc.parse_envelope(
        {"objects": [{"type": "indicator", "modified": "2019-01-01T00:00:00Z"}]},
        {"X-TAXII-Date-Added-Last": "2026-08-24T10:00:00.000Z"})
    assert page.date_added_last == "2026-08-24T10:00:00.000Z"


def test_response_headers_are_matched_case_insensitively():
    """HTTP header case is not significant, and libraries differ."""
    page = tc.parse_envelope({"objects": []},
                             {"x-taxii-date-added-last": "2026-08-24T00:00:00Z"})
    assert page.date_added_last == "2026-08-24T00:00:00Z"


def test_a_cold_poll_sends_no_added_after_and_a_warm_one_does():
    cold = tc.request_url(ROOT, COLLECTION, added_after="", limit=100)
    warm = tc.request_url(ROOT, COLLECTION, added_after="2026-06-01T00:00:00Z",
                          limit=100)
    assert "added_after" not in cold
    assert "added_after=2026-06-01T00%3A00%3A00Z" in warm


def test_polling_advances_the_cursor_to_the_latest_added_date():
    fetch = recorder([envelope([{"type": "indicator"}], added_last="2026-08-01T00:00:00Z")])
    state = tc.PollState(SERVER, ROOT, COLLECTION)
    _, advanced, report = tc.poll(fetch, state, now="2026-08-24")
    assert advanced.added_after == "2026-08-01T00:00:00Z"
    assert report.incremental is False


def test_a_second_poll_reports_itself_incremental():
    fetch = recorder([envelope([], added_last="2026-08-02T00:00:00Z")])
    state = tc.PollState(SERVER, ROOT, COLLECTION,
                         added_after="2026-08-01T00:00:00Z")
    _, _, report = tc.poll(fetch, state, now="2026-08-24")
    assert report.incremental is True
    assert "added_after" in fetch.urls[0]


def test_an_older_added_date_never_moves_the_cursor_backwards():
    """A server paging out of order must not rewind the floor, or the next run
    refetches ground already covered."""
    fetch = recorder([envelope([], added_last="2026-01-01T00:00:00Z")])
    state = tc.PollState(SERVER, ROOT, COLLECTION,
                         added_after="2026-08-01T00:00:00Z")
    _, advanced, _ = tc.poll(fetch, state, now="2026-08-24")
    assert advanced.added_after == "2026-08-01T00:00:00Z"


# ── failure must not lose ground ────────────────────────────────────────────
def test_the_cursor_does_not_advance_when_the_poll_errored():
    """A poller that advances past an error silently loses whatever was in the
    page it could not read — and nothing will ever go back for it."""
    def broken(url, headers):
        raise RuntimeError("server exploded")

    state = tc.PollState(SERVER, ROOT, COLLECTION,
                         added_after="2026-06-01T00:00:00Z")
    objects, advanced, report = tc.poll(broken, state, now="2026-08-24")
    assert objects == []
    assert advanced.added_after == "2026-06-01T00:00:00Z"
    assert "server exploded" in report.error


def test_a_malformed_envelope_is_an_error_not_an_empty_result():
    def garbage(url, headers):
        return b"<html>not taxii</html>", {}

    _, advanced, report = tc.poll(garbage, tc.PollState(
        SERVER, ROOT, COLLECTION, added_after="2026-06-01T00:00:00Z"))
    assert report.error
    assert advanced.added_after == "2026-06-01T00:00:00Z"


def test_a_repeated_cursor_stops_the_loop_and_says_so():
    """A server returning the same cursor forever would spin. Reported rather
    than returning a partial result that looks complete."""
    body, headers = envelope([{"type": "indicator"}], more=True, nxt="same")
    fetch = recorder([(body, headers)])
    _, _, report = tc.poll(fetch, tc.PollState(SERVER, ROOT, COLLECTION))
    assert report.stopped_by_stalled_cursor is True


# ── caps are announced ──────────────────────────────────────────────────────
def test_the_page_cap_is_reported_rather_than_applied_quietly():
    body, headers = envelope([{"type": "indicator"}], more=True, nxt="1")
    pages = [(dict(body, next=str(i)), headers) for i in range(1, 20)]
    fetch = recorder(pages)
    _, _, report = tc.poll(fetch, tc.PollState(SERVER, ROOT, COLLECTION),
                           max_pages=3)
    assert report.pages == 3 and report.stopped_by_page_cap is True
    assert report.to_dict()["caps"]["max_pages"] == tc.MAX_PAGES


def test_the_object_cap_is_reported():
    body, headers = envelope([{"type": "indicator"}] * 10, more=True, nxt="1")
    fetch = recorder([(dict(body, next=str(i)), headers) for i in range(1, 9)])
    _, _, report = tc.poll(fetch, tc.PollState(SERVER, ROOT, COLLECTION),
                           max_objects=25)
    assert report.stopped_by_object_cap is True


def test_pagination_walks_until_more_is_false():
    fetch = recorder([
        (dict(envelope([{"type": "a"}], more=True, nxt="1")[0]), {}),
        (dict(envelope([{"type": "b"}], more=True, nxt="2")[0]), {}),
        (dict(envelope([{"type": "c"}], more=False)[0]), {}),
    ])
    objects, _, report = tc.poll(fetch, tc.PollState(SERVER, ROOT, COLLECTION))
    assert report.pages == 3 and len(objects) == 3
    assert "next=1" in fetch.urls[1] and "next=2" in fetch.urls[2]


# ── collections ─────────────────────────────────────────────────────────────
def test_an_absent_can_read_defaults_to_readable():
    """The specification's default is true, and a server that means otherwise
    says so."""
    got = tc.parse_collections({"collections": [{"id": "c1", "title": "T"}]})
    assert got[0].readable is True


def test_an_unreadable_collection_is_marked_so():
    got = tc.parse_collections(
        {"collections": [{"id": "c1", "can_read": False}]})
    assert got[0].readable is False


def test_a_collections_document_without_the_list_raises():
    """An empty list and a missing one mean different things, and only one of
    them means the server has nothing to offer."""
    with pytest.raises(tc.TaxiiMalformed):
        tc.parse_collections({"title": "no list here"})
    assert tc.parse_collections({"collections": []}) == []


def test_urls_are_built_from_parts_not_configured_whole():
    assert tc.objects_url(ROOT, COLLECTION) == (
        ROOT + "/collections/" + COLLECTION + "/objects/")
    assert tc.collections_url(ROOT + "/") == ROOT + "/collections/"


# ── state round-trips ───────────────────────────────────────────────────────
def test_state_survives_a_round_trip():
    state = tc.PollState(SERVER, ROOT, COLLECTION,
                         added_after="2026-08-01T00:00:00Z",
                         last_polled="2026-08-24", objects_seen=12)
    restored = tc.load_state(tc.dump_state([state]))
    assert restored[state.key].added_after == "2026-08-01T00:00:00Z"
    assert restored[state.key].objects_seen == 12


def test_state_without_a_collection_is_dropped_rather_than_half_loaded():
    assert tc.load_state({"collections": [{"server": SERVER}]}) == {}


# ── the client stays a protocol driver ──────────────────────────────────────
def test_the_client_performs_no_network_io():
    """`collect/egress.py` is "the only module in SKOPOS that touches the
    network", and every request through it binds to a permit for an estate
    asset. A feed poll has no asset, so this drives the protocol and the caller
    supplies the transport."""
    tree = ast.parse(inspect.getsource(tc))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")

    # FULL module paths, not top-level names. `urllib.parse` is string
    # manipulation and is used here; `urllib.request` opens sockets. Comparing
    # only the first component cannot tell them apart, and a test that cannot
    # tell them apart is not enforcing anything.
    assert "urllib.parse" in imported, "expected the URL helpers"
    for banned in ("urllib.request", "urllib.error", "http.client", "socket",
                   "requests", "httpx", "subprocess", "ssl", "asyncio"):
        assert banned not in imported, f"{banned} would make this a transport"


# ── the merge must not manufacture sightings ────────────────────────────────
def test_merging_the_same_object_twice_does_not_duplicate_it():
    """Two polls of a collection that re-serves an object must not look like
    two independent sightings."""
    from tools import refresh_intel

    item = {"value": "a.example", "kind": "domain", "source": "taxii",
            "publisher": "P", "seen_on": "2026-08-01"}
    merged = refresh_intel.merge_into_cti({"indicators": [item, dict(item)]})
    assert merged["_meta"]["indicators"] >= 1
    keys = [(i["value"], i["kind"], i["source"]) for i in merged["indicators"]
            if i.get("source") == "taxii"]
    assert len(keys) == len(set(keys))


def test_the_merge_keeps_the_freshest_seen_on():
    from tools import refresh_intel

    old = {"value": "b.example", "kind": "domain", "source": "taxii",
           "publisher": "P", "seen_on": "2026-01-01"}
    new = dict(old, seen_on="2026-08-20")
    merged = refresh_intel.merge_into_cti({"indicators": [old, new]})
    kept = [i for i in merged["indicators"]
            if i["value"] == "b.example" and i["source"] == "taxii"]
    assert len(kept) == 1 and kept[0]["seen_on"] == "2026-08-20"
