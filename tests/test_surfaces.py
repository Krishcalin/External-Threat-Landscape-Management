"""The routes in front of what used to be four unreachable modules.

`core/latency.py`, `core/artefacts.py`, `core/stix.py` and `core/alerting.py`
were all built, tested, and imported by nothing outside their own test files —
956 lines a user had no way to reach. These tests cover the surfaces added for
them, and in particular the two places where a surface could quietly say more
than the module behind it does.
"""
from __future__ import annotations

from datetime import date

import pytest

from core import artefacts, latency
from core.findings_store import RunDiff


# ── the window must not drift ───────────────────────────────────────────────
def test_the_two_window_constants_stay_equal():
    """`latency.DEFAULT_SINCE` mirrors `artefacts.DEFAULT_LATENCY_SINCE` rather
    than importing it. A silent divergence would mean two different windows
    described by one number, and the number is load-bearing: unwindowed, the
    median is 777 days and is about CISA's backlog rather than warning time."""
    assert latency.DEFAULT_SINCE == artefacts.DEFAULT_LATENCY_SINCE


# ── the corpus join ─────────────────────────────────────────────────────────
class FakeCorpus:
    """Duck-typed: `observations_from` takes anything with these two methods,
    which is what keeps `latency.py` free of a corpus dependency."""

    def __init__(self, rows):
        self._rows = rows

    def entries(self):
        return [e for e, _ in self._rows]

    def artefacts_for(self, cve):
        return dict((e.cve, a) for e, a in self._rows).get(cve, [])


class FakeEntry:
    def __init__(self, cve, added, ransomware=False):
        self.cve = cve
        self.date_added = added
        self.known_ransomware = ransomware


def artefact(kind="metasploit", published="2024-01-01"):
    return {"kind": kind, "published": published, "reference": "x"}


def test_attrition_is_returned_not_swallowed():
    """A base rate over a minority of the corpus, presented as if it covered
    everything, is the number this product exists not to print."""
    corpus = FakeCorpus([
        (FakeEntry("CVE-1", date(2024, 3, 1)), [artefact()]),
        (FakeEntry("CVE-2", date(2024, 3, 1)), []),
        (FakeEntry("CVE-3", date(2024, 3, 1)), [artefact(published="")]),
        (FakeEntry("CVE-4", date(2019, 1, 1)), [artefact()]),
    ])
    observations, lost = latency.observations_from(corpus)
    assert len(observations) == 1
    assert lost == {"no_artefact": 1, "no_usable_date": 1, "outside_window": 1}


def test_the_window_excludes_the_kev_backfill():
    corpus = FakeCorpus([(FakeEntry("CVE-1", date(2019, 6, 1)), [artefact()])])
    assert latency.observations_from(corpus)[0] == []
    assert latency.observations_from(corpus, since=date(2015, 1, 1))[0]


def test_weaponised_means_packaged_not_merely_published():
    corpus = FakeCorpus([
        (FakeEntry("CVE-1", date(2024, 3, 1)), [artefact("exploitdb")]),
        (FakeEntry("CVE-2", date(2024, 3, 1)), [artefact("metasploit")]),
    ])
    observations, _ = latency.observations_from(corpus)
    assert sorted(w for _, w, _ in observations) == [False, True]


def test_an_unknown_artefact_kind_is_skipped_not_crashed():
    corpus = FakeCorpus([(FakeEntry("CVE-1", date(2024, 3, 1)),
                          [artefact("some-new-source")])])
    observations, lost = latency.observations_from(corpus)
    assert observations == [] and lost["no_artefact"] == 1


def test_all_four_classes_are_reported_including_the_empty_ones():
    """Serving only the class that can answer would leave a caller believing
    the product has a general answer to "how long do I have"."""
    corpus = FakeCorpus([(FakeEntry("CVE-1", date(2024, 3, 1)), [artefact()])])
    payload = latency.report(corpus)
    assert payload["total_classes"] == 4
    assert payload["usable_classes"] == 0
    assert "not a prediction about yours" in payload["not_a_forecast"]


# ── the surfaces ────────────────────────────────────────────────────────────
FINDINGS = [{"asset": "fw-01.example.com", "cve": "CVE-2018-13379",
             "product": "FortiOS", "basis": "product_match", "band": "critical",
             "teps": 88.0, "evidence": ["product: fortios"], "owner": "Net",
             "vulnerability": "Path Traversal", "environment": "production"}]


@pytest.fixture
def client(monkeypatch):
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from api import app as api_app

    class _Store:
        def findings(self, **kw):
            return list(FINDINGS)

        def diff_against_previous(self, run_id=None):
            return RunDiff(previous_run=7, new=list(FINDINGS), carried=3)

    monkeypatch.setattr(api_app, "_findings_store", lambda: _Store())
    return fastapi_testclient.TestClient(api_app.app)


def test_the_latency_route_serves_the_refusals_too(client):
    payload = client.get("/api/v1/latency").json()
    assert payload["total_classes"] == 4
    unusable = [c for c in payload["classes"].values() if not c["usable"]]
    assert unusable, "the refusing classes must be visible, not filtered out"
    for entry in unusable:
        assert "NO estimate is offered" in entry["note"] or \
            "too few to say anything" in entry["note"]


def test_a_cve_outside_the_catalogue_gets_no_invented_class(client):
    response = client.get("/api/v1/latency/CVE-1999-0001")
    assert response.status_code == 404
    assert "would not be invented for it" in response.json()["detail"]["why"]


def test_the_class_is_chosen_from_the_cve_not_from_the_asset(client):
    """The same CVE gets the same answer for everybody. That is what makes it a
    base rate rather than a score about one customer's estate."""
    payload = client.get("/api/v1/latency/CVE-2018-13379").json()
    assert set(payload) >= {"known_ransomware", "weaponised", "reference_class"}
    assert "asset" not in payload and "teps" not in payload


def test_every_latency_answer_carries_the_disclaimer(client):
    payload = client.get("/api/v1/latency/CVE-2018-13379").json()
    assert "BASE RATE" in payload["not_a_forecast"]
    assert "not a prediction about yours" in payload["not_a_forecast"]


# ── STIX ────────────────────────────────────────────────────────────────────
def test_the_caveat_travels_inside_the_bundle(client):
    """A caveat that stays behind in the console is not a caveat — the bundle
    is what gets forwarded to somebody who never saw this product."""
    payload = client.get("/api/v1/export/stix").json()
    notes = [o for o in payload["bundle"]["objects"] if o["type"] == "note"]
    assert notes, "the bundle must carry its own caveat"
    assert "WORKLIST" in notes[0]["content"]


def test_a_worklist_entry_exports_at_worklist_confidence(client):
    from core import stix
    payload = client.get("/api/v1/export/stix").json()
    relationships = [o for o in payload["bundle"]["objects"]
                     if o["type"] == "relationship"]
    assert relationships
    assert all(r["confidence"] == stix.CONFIDENCE_WORKLIST
               for r in relationships), "a product match is not a determination"


def test_truncation_is_declared(client):
    payload = client.get("/api/v1/export/stix?limit=1").json()
    assert payload["truncated"] is True
    assert payload["findings_exported"] == 1


# ── alerting decides, it does not deliver ───────────────────────────────────
def test_the_alerts_route_sends_nothing(client):
    """A GET that made the server POST findings outward would let anyone who
    can reach this API choose the moment the estate is described to a third
    party. Delivery stays an operator decision made in the environment."""
    payload = client.get("/api/v1/alerts").json()
    assert payload["delivered"] is False
    assert "sent nothing" in payload["delivery"]


def test_no_route_can_trigger_dispatch(client):
    import inspect
    from api import app as api_app
    source = inspect.getsource(api_app)
    assert "alerting.dispatch" not in source
    assert "send_webhook" not in source and "send_email" not in source


def test_a_new_critical_finding_is_worth_interrupting_somebody_for(client):
    payload = client.get("/api/v1/alerts").json()
    assert len(payload["alerts"]) == 1
    assert "CVE-2018-13379" in payload["alerts"][0]["subject"]


def test_the_suppressed_counts_come_back_with_the_alerts(client):
    """An operator who sees five needs to know whether five was everything."""
    payload = client.get("/api/v1/alerts").json()
    assert "suppressed_below_band" in payload
    assert "suppressed_by_cap" in payload


def test_a_band_change_is_not_a_trigger_by_default(client):
    """EPSS moves daily, so a feed that fires on score boundaries trains the
    reader to ignore it."""
    payload = client.get("/api/v1/alerts").json()
    assert "band_changed" in payload["triggers_off_by_default"]
