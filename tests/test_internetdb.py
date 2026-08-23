"""InternetDB, and the first source in this codebase that can prove itself.

Every keyed source carries `verified_live: False` because nobody here has a key.
This one needs none, so the live tests at the bottom run against the real
service whenever the network is up — and the parsing claims below are therefore
checked against what Shodan actually sends rather than against a fixture
somebody wrote from the documentation.
"""
from __future__ import annotations

import json
import os

import pytest

from collect import internetdb

# A real response, captured 2026-08-23 from 45.33.32.156 (scanme.nmap.org).
REAL = json.dumps({
    "cpes": ["cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/a:ntp:ntp:3",
             "cpe:/a:apache:http_server:2.4.7", "cpe:/o:canonical:ubuntu_linux"],
    "hostnames": ["scanme.nmap.org"],
    "ip": "45.33.32.156",
    "ports": [22, 80, 123, 31337],
    "tags": ["cloud"],
    "vulns": ["CVE-2014-0226", "CVE-2023-25690"],
})


@pytest.fixture
def acked(monkeypatch):
    monkeypatch.setenv(internetdb.ACK_ENV, "true")


# ── the acknowledgement, which is not a credential ──────────────────────────
def test_it_is_inert_without_an_acknowledgement(monkeypatch):
    """Free to call is not the same as free to use. Shodan's terms make this
    non-commercial only, and SKOPOS cannot know which a deployment is."""
    monkeypatch.delenv(internetdb.ACK_ENV, raising=False)
    assert internetdb.acknowledged() is False
    answer = internetdb.host(object(), "1.1.1.1")
    assert answer.available is False, "no acknowledgement means UNAVAILABLE"
    assert answer.answered is False
    assert "non-commercial" in answer.detail


@pytest.mark.parametrize("value", ["0", "false", "no", "", "maybe", "commercial"])
def test_an_unrecognised_acknowledgement_means_off(value, monkeypatch):
    """Fails closed like every other switch here: a typo must not enable a
    source whose licence may not cover the deployment running it."""
    monkeypatch.setenv(internetdb.ACK_ENV, value)
    assert internetdb.acknowledged() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "noncommercial",
                                   "non-commercial"])
def test_the_acknowledgement_is_accepted_in_the_obvious_spellings(value,
                                                                  monkeypatch):
    monkeypatch.setenv(internetdb.ACK_ENV, value)
    assert internetdb.acknowledged() is True


def test_the_switch_is_not_named_like_a_key():
    """`SKOPOS_INTERNETDB_API_KEY` would invite somebody to paste a credential
    into it and believe they had bought something."""
    assert "KEY" not in internetdb.ACK_ENV
    assert internetdb.ACK_ENV.endswith("_ACK")


def test_the_registry_marks_it_noncommercial_and_off():
    from collect.registry import BY_NAME, Terms
    source = BY_NAME["internetdb"]
    assert source.terms is Terms.NONCOMMERCIAL
    assert source.default_on is False
    assert source.credential_env == internetdb.ACK_ENV


def test_it_reports_unconfigured_until_acknowledged(monkeypatch):
    """Otherwise a lookup panel shows it as available and every call refuses."""
    from collect.registry import BY_NAME
    monkeypatch.delenv(internetdb.ACK_ENV, raising=False)
    assert BY_NAME["internetdb"].configured is False
    monkeypatch.setenv(internetdb.ACK_ENV, "true")
    assert BY_NAME["internetdb"].configured is True


def test_the_noncommercial_change_did_not_alter_hackertarget():
    """It has no env var, so it has no switch to check."""
    from collect.registry import BY_NAME
    assert BY_NAME["hackertarget"].configured is True


# ── CPE parsing, which is the whole gain over the paid API ──────────────────
def test_it_parses_the_uri_form_shodan_actually_sends():
    assert internetdb.parse_cpe("cpe:/a:apache:http_server:2.4.7") == (
        "apache", "http_server", "2.4.7")


def test_it_parses_the_formatted_string_form_too():
    """Shodan emits 2.2; almost everything else emits 2.3. A parser that
    returned None for half its inputs would look like sparse data."""
    assert internetdb.parse_cpe(
        "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*") == (
        "apache", "http_server", "2.4.7")


def test_a_cpe_with_no_version_is_none_not_an_empty_string():
    """`("canonical", "ubuntu_linux", "")` invites a caller to treat a missing
    version as a present one, which is the single most consequential mistake
    available here."""
    assert internetdb.parse_cpe("cpe:/o:canonical:ubuntu_linux") is None


@pytest.mark.parametrize("wildcard", ["cpe:/a:apache:http_server:*",
                                      "cpe:/a:apache:http_server:-"])
def test_cpe_wildcards_are_not_versions(wildcard):
    assert internetdb.parse_cpe(wildcard) is None


@pytest.mark.parametrize("junk", ["", "not a cpe", "cpe:", "cpe:/a", "cpe:/a:x",
                                  "cpe:2.3:a:vendor", None])
def test_malformed_cpes_return_none_rather_than_raising(junk):
    assert internetdb.parse_cpe(junk) is None


def test_parsing_is_case_normalised():
    assert internetdb.parse_cpe("CPE:/A:Apache:HTTP_Server:2.4.7") == (
        "apache", "http_server", "2.4.7")


# ── shaping ─────────────────────────────────────────────────────────────────
def test_a_real_response_yields_every_kind():
    answer = internetdb.shape(200, REAL)
    assert answer.answered is True
    kinds = {o["kind"] for o in answer.observations}
    assert kinds == {"port", "software", "vuln_claim", "hostname", "tag"}


def test_ports_come_back_sorted_and_complete():
    answer = internetdb.shape(200, REAL)
    ports = [o["port"] for o in answer.observations if o["kind"] == "port"]
    assert ports == [22, 80, 123, 31337]


def test_only_versioned_cpes_become_software():
    """Four CPEs in, three with versions. `ubuntu_linux` carries none."""
    answer = internetdb.shape(200, REAL)
    software = [o for o in answer.observations if o["kind"] == "software"]
    assert len(software) == 3
    assert {s["product"] for s in software} == {"openssh", "ntp", "http_server"}
    assert all(s["version"] for s in software)


def test_the_unversioned_cpe_is_counted_not_silently_dropped():
    answer = internetdb.shape(200, REAL)
    assert "1 CPE(s) carried no version" in answer.detail


def test_a_cve_claim_says_it_is_not_a_determination():
    """The refusal `core/identity.py` makes, restated where a reader will see
    it. Routing a banner-derived CVE in as a determination through a third
    party would defeat that refusal exactly as Shodan's would."""
    answer = internetdb.shape(200, REAL)
    claims = [o for o in answer.observations if o["kind"] == "vuln_claim"]
    assert claims
    for claim in claims:
        assert "does not treat this as a determination" in claim["basis"]
        assert "banner" in claim["basis"]


def test_a_cpe_carries_the_same_refusal():
    """Structured is easier to read, not more authoritative about what is
    installed."""
    answer = internetdb.shape(200, REAL)
    software = [o for o in answer.observations if o["kind"] == "software"]
    for entry in software:
        assert "does not evaluate a published range against it" in entry["basis"]


def test_a_hostname_is_flagged_as_possibly_somebody_elses():
    """On shared hosting, Shodan's reverse index routinely names another
    party's site."""
    answer = internetdb.shape(200, REAL)
    names = [o for o in answer.observations if o["kind"] == "hostname"]
    assert names and "another party" in names[0]["basis"]


def test_every_observation_states_its_freshness():
    """An index up to seven days old is a different fact from a live probe."""
    answer = internetdb.shape(200, REAL)
    assert all(o["freshness"] == "weekly" for o in answer.observations)
    assert "not a live probe" in answer.detail


def test_a_404_is_unknown_not_empty():
    """The distinction that stops an unindexed host reading as a clean one."""
    answer = internetdb.shape(404, "")
    assert answer.answered is True
    assert answer.observations == []
    assert "never that nothing is listening" in answer.detail


def test_a_403_explains_the_user_agent_cause():
    answer = internetdb.shape(403, "")
    assert answer.answered is False and "User-Agent" in answer.detail


def test_an_unparseable_body_is_a_failure_not_an_empty_result():
    assert internetdb.shape(200, "<html>").answered is False


def test_a_json_array_body_is_refused():
    """HTTP 200 with a list would otherwise reach `.get` and raise."""
    assert internetdb.shape(200, "[]").answered is False


def test_an_empty_but_valid_response_is_an_ok_result_with_nothing_in_it():
    answer = internetdb.shape(200, json.dumps(
        {"ip": "1.1.1.1", "ports": [], "cpes": [], "vulns": [],
         "hostnames": [], "tags": []}))
    assert answer.answered is True and answer.observations == []


def test_null_fields_do_not_crash_the_shaper():
    """Absent and null are both things a JSON API does."""
    answer = internetdb.shape(200, json.dumps(
        {"ip": "1.1.1.1", "ports": None, "cpes": None, "vulns": None}))
    assert answer.answered is True and answer.observations == []


# ── input handling ──────────────────────────────────────────────────────────
def test_a_domain_is_refused_with_the_reason(acked):
    answer = internetdb.host(object(), "example.com")
    assert answer.answered is False and "not an IP address" in answer.detail


def test_ipv6_is_refused_rather_than_attempted(acked):
    """A 404 for an IPv6 address would read as 'nothing is listening' when the
    truth is that this index does not cover the family."""
    answer = internetdb.host(object(), "2606:4700:4700::1111")
    assert answer.answered is False and "IPv4 only" in answer.detail


def test_it_is_a_passive_advisory_lookup():
    from core import gate
    assert internetdb.OPERATION == "advisory_lookup"
    assert gate.OPERATIONS["advisory_lookup"] is gate.Exposure.PASSIVE


def test_the_host_is_on_the_egress_allowlist():
    from collect import egress
    assert "internetdb.shodan.io" in egress.ALLOWED_HTTP_HOSTS


def test_the_module_declares_its_network_boundary():
    """CI enforces this marker on every module that performs I/O."""
    import pathlib
    source = pathlib.Path(internetdb.__file__).read_text(encoding="utf-8")
    assert "# NETWORK-BOUNDARY: advisory_lookup" in source


# ── live, because this one CAN be ───────────────────────────────────────────
def _online() -> bool:
    import urllib.error
    import urllib.request
    try:
        request = urllib.request.Request(
            "https://internetdb.shodan.io/1.1.1.1",
            headers={"User-Agent": internetdb.USER_AGENT})
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


live = pytest.mark.skipif(
    os.environ.get("SKOPOS_TEST_LIVE_INTERNETDB", "") not in
    {"1", "true", "yes"},
    reason="set SKOPOS_TEST_LIVE_INTERNETDB=1 to call the real service")


@live
def test_the_documented_contract_is_the_real_one():
    """The test the keyed sources cannot have.

    `collect/keyed_sources.py` warns that its live calls were written against
    documented contracts and never executed. This source needs no key, so that
    excuse does not apply to it — and a vendor that renames a field should break
    a test here rather than a customer's lookup.
    """
    if not _online():
        pytest.skip("internetdb.shodan.io is not reachable from here")
    import urllib.request
    request = urllib.request.Request(
        "https://internetdb.shodan.io/45.33.32.156",
        headers={"User-Agent": internetdb.USER_AGENT})
    with urllib.request.urlopen(request, timeout=15) as response:
        body = response.read().decode()
        status = response.status

    payload = json.loads(body)
    for field in ("ip", "ports", "cpes", "hostnames", "tags", "vulns"):
        assert field in payload, f"the documented field {field!r} is gone"

    answer = internetdb.shape(status, body)
    assert answer.answered is True
    assert answer.verified_live is True
    assert any(o["kind"] == "port" for o in answer.observations)


@live
def test_the_default_python_user_agent_really_is_rejected():
    """Documents the measured reason `USER_AGENT` exists. If Shodan ever stops
    doing this, this test fails and the header can be reconsidered — better
    than a mystery constant nobody dares remove.
    """
    import urllib.error
    import urllib.request
    if not _online():
        pytest.skip("internetdb.shodan.io is not reachable from here")
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen("https://internetdb.shodan.io/1.1.1.1", timeout=15)
    assert caught.value.code == 403
