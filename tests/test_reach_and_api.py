"""P1g: reachability reaching the scorer, and the API surfaces over it.

Before this, `engine.score_exposure` was always called with
`external_reachable=None`, so every finding reconciled to UNKNOWN and the
four-way matrix never had both of its inputs.
"""
from __future__ import annotations

import importlib
import os

import pytest

from core import reach
from core.identity import Attestation, Fingerprint
from core.overwatch import InternalReachability, reconcile


# -- reachability from a fingerprinted row ------------------------------------
def test_a_probed_host_that_answered_is_reachable():
    row = Fingerprint(host="a.example.com", product="Tomcat", vendor="Apache",
                      open_ports=(443,), probed_ports=(443, 80)).inventory_row()
    reachable, ports = reach.from_row(row)
    assert reachable is True
    assert ports == (443,)


def test_a_probed_host_that_answered_nothing_is_false_not_none():
    """'We looked and it is closed' is a finding. It must reach the matrix."""
    row = Fingerprint(host="a.example.com", probed_ports=(443, 80)).inventory_row()
    reachable, ports = reach.from_row(row)
    assert reachable is False
    assert ports == ()


def test_a_host_that_was_never_probed_is_none_not_false():
    """The distinction the whole reconciliation turns on.

    None cannot contradict OverWatch's inside-out verdict. False can.
    """
    reachable, ports = reach.from_row({"identifier": "a.example.com",
                                       "product": "unknown"})
    assert reachable is None
    assert ports == ()


def test_none_and_false_reconcile_differently():
    """Merging them would either invent a disagreement or hide one."""
    never_probed = reconcile(None, InternalReachability.REACHABLE)
    probed_closed = reconcile(False, InternalReachability.REACHABLE)
    assert never_probed is not probed_closed


def test_false_does_not_claim_the_host_is_unexposed():
    """We probe a narrow port set on purpose; another port is invisible to us."""
    text = reach.explain(False, (443, 80), ())
    assert "not 'not exposed'" in text
    assert "any other port" in text


def test_unknown_says_it_is_not_the_same_as_unreachable():
    assert "not the same as unreachable" in reach.explain(None, (), ())


def test_malformed_port_columns_do_not_crash_or_lie():
    reachable, ports = reach.from_row({"obs_probed_ports": "443, ,x,80",
                                       "obs_open_ports": "443"})
    assert reachable is True and ports == (443,)


# -- the API surfaces --------------------------------------------------------
@pytest.fixture
def client():
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from api.app import app
    return fastapi_testclient.TestClient(app)


def test_meaning_strings_are_served_not_hard_coded_in_the_console(client):
    """So the API, the CLI and the UI cannot drift into describing the same
    state differently."""
    for path, expected in (("/api/v1/reconciliation", "agreed"),
                           ("/api/v1/dns/change-meaning", "unobserved"),
                           ("/api/v1/takeover/meaning", "inconclusive"),
                           ("/api/v1/attestation-meaning", "self_reported")):
        response = client.get(path)
        assert response.status_code == 200, path
        body = response.json()
        assert any(expected in key for key in body), f"{path} missing {expected}"


def test_the_takeover_route_is_absent_without_a_token(client):
    """Not a 401 — ABSENT. A probeable 401 still admits the data exists."""
    from api.app import TAKEOVER_ROUTE_REGISTERED
    if TAKEOVER_ROUTE_REGISTERED:
        pytest.skip("SKOPOS_API_TOKEN is set in this environment")
    assert client.get("/api/v1/takeover").status_code == 404


def test_health_says_why_the_takeover_route_is_missing(client):
    """An operator who cannot find it needs to know it is unconfigured, not
    broken."""
    body = client.get("/api/v1/health").json()
    assert "takeover_route" in body
    assert "SKOPOS_API_TOKEN" in body["takeover_route"] or \
        body["takeover_route"] == "registered"


def test_the_takeover_route_requires_the_bearer_token(monkeypatch):
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    monkeypatch.setenv("SKOPOS_API_TOKEN", "s3cret-token-for-the-test")
    import api.app as app_module
    reloaded = importlib.reload(app_module)
    try:
        assert reloaded.TAKEOVER_ROUTE_REGISTERED
        client = fastapi_testclient.TestClient(reloaded.app)
        assert client.get("/api/v1/takeover").status_code == 401
        assert client.get("/api/v1/takeover",
                          headers={"Authorization": "Bearer wrong"}
                          ).status_code == 401
    finally:
        monkeypatch.delenv("SKOPOS_API_TOKEN", raising=False)
        importlib.reload(app_module)


def test_the_api_is_read_only_because_no_write_route_exists(client):
    """NOT because of allow_methods=['GET'].

    CORS is a browser-side control and the SPA is served same-origin, where it
    never applies. POST /api/v1/scan already exists and is callable with curl —
    a contributor who reads 'GET-only by construction' believes something false.
    """
    import api.app as app_module
    source = open(app_module.__file__, encoding="utf-8").read()
    assert "browser-side" in source.lower()
    assert "callable with curl" in source

    methods = set()
    for route in app_module.app.routes:
        if getattr(route, "path", "") == "/api/v1/scan":
            methods |= set(route.methods)
    assert "POST" in methods, "the docstring's claim must match reality"
