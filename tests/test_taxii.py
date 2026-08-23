"""TAXII 2.1, and the one property that makes incremental polling honest.

`date_added` must not move between requests. The obvious implementation
regenerates the bundle per request with `now()` on every object, and then
`added_after` either returns everything forever or nothing ever — the consumer's
incremental poll silently stops working while the server keeps answering 200.
Several tests here exist only to keep that from regressing.
"""
from __future__ import annotations

import pytest

from core import taxii
from core.taxii import TaxiiError

STAMP = "2026-08-23T06:19:13Z"
LATER = "2026-08-24T06:19:13Z"


def obj(identifier, kind="relationship"):
    return {"id": identifier, "type": kind, "spec_version": "2.1",
            "created": STAMP, "modified": STAMP}


OBJECTS = [obj("relationship--1"), obj("vulnerability--2", "vulnerability"),
           obj("infrastructure--3", "infrastructure")]
INDEX = taxii.date_added_index(OBJECTS, STAMP)


# ── discovery and shape ─────────────────────────────────────────────────────
def test_the_media_type_carries_its_version():
    """A conforming client content-negotiates on the exact string; bare
    application/json is a different media type."""
    assert taxii.MEDIA_TYPE == "application/taxii+json;version=2.1"
    assert taxii.STIX_MEDIA_TYPE == "application/stix+json;version=2.1"


def test_discovery_points_at_its_own_api_root():
    payload = taxii.discovery()
    assert payload["default"] in payload["api_roots"]
    assert payload["default"].endswith(f"/{taxii.API_ROOT}/")


def test_the_worklist_distinction_travels_in_the_discovery_description():
    """A consumer federating several feeds sees this string and little else."""
    text = taxii.discovery()["description"]
    assert "WORKLIST ENTRY" in text and "DETERMINATION" in text
    assert "Do not treat the first as the second" in text


def test_there_is_one_api_root_because_there_is_one_population():
    assert len(taxii.discovery()["api_roots"]) == 1


def test_the_collection_id_is_stable():
    """A consumer stores it in its own configuration; a regenerated uuid would
    silently orphan every existing subscription."""
    assert taxii.collection()["id"] == taxii.FINDINGS_COLLECTION
    assert taxii.collection()["id"] == "1f1b4b6e-0e4a-5a9c-9b7d-0d2f6c8a1e30"


def test_the_collection_is_read_only():
    """Accepting objects would mean ingesting third-party claims into a product
    whose discipline is that every statement carries who made it."""
    assert taxii.collection()["can_write"] is False
    assert taxii.api_root()["max_content_length"] == 1


def test_the_collection_description_carries_the_confidence_key():
    text = taxii.collection("2026.08.21", {"determinations": 13, "worklist": 51})
    assert "confidence 90 is a DETERMINATION" in text["description"]
    assert "Confidence 40 is a WORKLIST ENTRY" in text["description"]
    assert "not a claim that the asset is vulnerable" in text["description"]
    assert "2026.08.21" in text["description"]
    assert "13 determination(s) and 51 worklist" in text["description"]


# ── date_added must not move ────────────────────────────────────────────────
def test_every_object_in_a_run_shares_the_run_stamp():
    assert set(INDEX.values()) == {STAMP}


def test_added_after_is_strictly_after():
    """Inclusive would hand a polling consumer the last object of the previous
    page on every request, forever."""
    assert taxii.filter_objects(OBJECTS, INDEX, added_after=STAMP) == []
    assert len(taxii.filter_objects(OBJECTS, INDEX,
                                    added_after="2020-01-01T00:00:00Z")) == 3


def test_a_later_run_is_what_a_consumer_picks_up():
    later = taxii.date_added_index([obj("relationship--4")], LATER)
    combined = dict(INDEX)
    combined.update(later)
    fresh = taxii.filter_objects(OBJECTS + [obj("relationship--4")], combined,
                                 added_after=STAMP)
    assert [o["id"] for o in fresh] == ["relationship--4"]


def test_a_malformed_timestamp_is_refused_not_ignored():
    """Silently ignoring it would return the whole collection to a consumer
    that believes it asked for a delta."""
    with pytest.raises(TaxiiError) as exc:
        taxii.filter_objects(OBJECTS, INDEX, added_after="yesterday")
    assert exc.value.status == 400


def test_the_error_object_reports_http_status_as_a_string():
    """TAXII 2.1 §3.6 says string. It reads like a typo and is the spec."""
    payload = TaxiiError("Not Found", "no such collection", 404).to_dict()
    assert payload["http_status"] == "404"
    assert isinstance(payload["http_status"], str)


# ── filtering ───────────────────────────────────────────────────────────────
def test_match_type_selects_one_kind():
    got = taxii.filter_objects(OBJECTS, INDEX, match_type="vulnerability")
    assert [o["id"] for o in got] == ["vulnerability--2"]


def test_match_type_accepts_a_comma_list():
    got = taxii.filter_objects(OBJECTS, INDEX,
                               match_type="vulnerability,infrastructure")
    assert len(got) == 2


def test_match_id_selects_one_object():
    got = taxii.filter_objects(OBJECTS, INDEX, match_id="relationship--1")
    assert [o["id"] for o in got] == ["relationship--1"]


def test_a_request_for_another_spec_version_returns_nothing():
    """Rather than pretending to have converted it."""
    assert taxii.filter_objects(OBJECTS, INDEX, match_spec_version="2.0") == []
    assert len(taxii.filter_objects(OBJECTS, INDEX, match_spec_version="2.1")) == 3


def test_an_explicit_version_timestamp_is_refused_with_the_reason():
    """This server keeps one version of each object; a finding is re-exported
    with the same id rather than versioned."""
    with pytest.raises(TaxiiError) as exc:
        taxii.filter_objects(OBJECTS, INDEX, match_version="2026-01-01T00:00:00Z")
    assert "one version of each object" in exc.value.description


# ── pagination ──────────────────────────────────────────────────────────────
def test_a_truncated_page_says_it_was_truncated():
    """A page that does not announce truncation reads as a whole collection."""
    page, more, token = taxii.paginate(OBJECTS, limit=2)
    assert len(page) == 2 and more is True and token == "2"


def test_the_last_page_carries_no_next():
    page, more, token = taxii.paginate(OBJECTS, limit=2, offset=2)
    assert len(page) == 1 and more is False and token is None


def test_an_envelope_never_carries_next_without_more():
    """A `more: false` with a `next` present is a contradiction a strict client
    will reject."""
    assert "next" not in taxii.envelope(OBJECTS, more=False, next_token="5")
    assert "more" not in taxii.envelope(OBJECTS, more=False)


def test_an_impossible_limit_is_refused():
    with pytest.raises(TaxiiError):
        taxii.paginate(OBJECTS, limit=taxii.MAX_PAGE + 1)


# ── manifest ────────────────────────────────────────────────────────────────
def test_the_manifest_reports_the_run_stamp_not_the_object_created():
    entries = taxii.manifest(OBJECTS, INDEX)["objects"]
    assert {e["date_added"] for e in entries} == {STAMP}
    assert {e["media_type"] for e in entries} == {taxii.STIX_MEDIA_TYPE}


def test_the_manifest_carries_no_object_bodies():
    """The point of it: a consumer decides what it needs before transferring."""
    entries = taxii.manifest(OBJECTS, INDEX)["objects"]
    assert all(set(e) == {"id", "date_added", "version", "media_type"}
               for e in entries)


# ── the routes ──────────────────────────────────────────────────────────────
def test_taxii_is_not_registered_without_a_token(monkeypatch):
    """An unset token must not leave it open, and a 401 that can be probed is
    still an admission the data exists."""
    import importlib

    monkeypatch.delenv("SKOPOS_API_TOKEN", raising=False)
    from api import app as api_app
    reloaded = importlib.reload(api_app)
    try:
        assert reloaded.TAXII_REGISTERED is False
        paths = {getattr(r, "path", "") for r in reloaded.app.routes}
        assert not any(p.startswith("/taxii2") for p in paths)
    finally:
        importlib.reload(api_app)


def test_an_unconfigured_taxii_path_is_a_404_not_the_console(monkeypatch):
    """A TAXII client that receives HTML from a discovery endpoint cannot tell
    'not configured' from 'not a TAXII server'."""
    import importlib

    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    monkeypatch.delenv("SKOPOS_API_TOKEN", raising=False)
    from api import app as api_app
    reloaded = importlib.reload(api_app)
    try:
        client = fastapi_testclient.TestClient(reloaded.app)
        response = client.get("/taxii2/")
        assert response.status_code == 404
        assert "SKOPOS_API_TOKEN" in response.text
    finally:
        importlib.reload(api_app)


@pytest.fixture
def client(monkeypatch):
    import importlib

    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    monkeypatch.setenv("SKOPOS_API_TOKEN", "token-for-the-test")
    from api import app as api_app
    reloaded = importlib.reload(api_app)

    class _Store:
        def runs(self, limit=1):
            return [{"id": 1, "scanned_at": "2026-08-23 06:19:13+00:00"}]

        def findings(self, **kw):
            return [{"asset": "a.example", "cve": "CVE-2018-13379",
                     "product": "FortiOS", "basis": "product_match",
                     "evidence": [], "vulnerability": "Path Traversal"}]

    monkeypatch.setattr(reloaded, "_findings_store", lambda: _Store())
    yield fastapi_testclient.TestClient(reloaded.app)
    importlib.reload(api_app)


AUTH = {"Authorization": "Bearer token-for-the-test"}
BASE = f"/taxii2/{taxii.API_ROOT}/collections/{taxii.FINDINGS_COLLECTION}"


def test_every_taxii_route_requires_the_token(client):
    for path in ("/taxii2/", f"/taxii2/{taxii.API_ROOT}/",
                 f"/taxii2/{taxii.API_ROOT}/collections/",
                 f"{BASE}/", f"{BASE}/objects/", f"{BASE}/manifest/"):
        assert client.get(path).status_code == 401, path


def test_the_response_carries_the_taxii_media_type(client):
    response = client.get("/taxii2/", headers=AUTH)
    assert response.headers["content-type"].startswith(taxii.MEDIA_TYPE)


def test_date_added_is_the_run_stamp_not_the_request_time(client):
    """The regression this whole module is guarding."""
    first = client.get(f"{BASE}/manifest/", headers=AUTH).json()
    second = client.get(f"{BASE}/manifest/", headers=AUTH).json()
    assert first["objects"] == second["objects"]
    assert first["objects"][0]["date_added"].startswith("2026-08-23T06:19:13")
    assert first["objects"][0]["date_added"].endswith("Z"), "RFC 3339 wants Z"


def test_polling_after_the_last_run_returns_nothing(client):
    stamp = client.get(f"{BASE}/manifest/",
                       headers=AUTH).json()["objects"][0]["date_added"]
    envelope = client.get(f"{BASE}/objects/?added_after={stamp}",
                          headers=AUTH).json()
    assert envelope["objects"] == []


def test_an_unknown_collection_is_a_404_with_the_real_one_named(client):
    response = client.get(f"/taxii2/{taxii.API_ROOT}/collections/nope/objects/",
                          headers=AUTH)
    assert response.status_code == 404
    assert taxii.FINDINGS_COLLECTION in response.json()["detail"]["description"]


def test_an_unknown_api_root_is_a_404(client):
    assert client.get("/taxii2/other/collections/",
                      headers=AUTH).status_code == 404


def test_the_caveat_note_is_inside_the_served_objects(client):
    envelope = client.get(f"{BASE}/objects/?limit=1000", headers=AUTH).json()
    notes = [o for o in envelope["objects"] if o["type"] == "note"]
    assert notes, "the caveat must travel with the objects, not stay behind"
    assert "WORKLIST" in notes[0]["content"]
