"""The "type any domain" lookup, and the two claims it must never make.

It must never become a way to reach an unverified asset actively, and it must
never present a score drawn from what it happened to see as if it covered
everything. Most of these keep both impossible.
"""
from __future__ import annotations

import pytest

from core import gate, lookup, suppliers
from core.lookup import Kind, TargetError
from core.scope import Scope, ScopeKind, ScopeRule


# ── target parsing ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,kind,value", [
    ("example.com", Kind.DOMAIN, "example.com"),
    ("EXAMPLE.COM", Kind.DOMAIN, "example.com"),
    ("www.example.com", Kind.HOST, "www.example.com"),
    ("https://example.com/path?q=1", Kind.DOMAIN, "example.com"),
    ("example.com.", Kind.DOMAIN, "example.com"),
    ("203.0.113.4", Kind.ADDRESS, "203.0.113.4"),
    ("203.0.113.4:443", Kind.ADDRESS, "203.0.113.4"),
    ("203.0.113.0/24", Kind.BLOCK, "203.0.113.0/24"),
])
def test_what_gets_typed_is_classified(raw, kind, value):
    target = lookup.parse(raw)
    assert target.kind is kind and target.value == value


def test_a_cidr_prefix_survives_url_path_stripping():
    """Splitting on '/' unconditionally turned 203.0.113.0/24 into a single
    address and let 10.0.0.0/8 past the size guard entirely, because by the
    time the guard ran there was no prefix left to be too large."""
    assert lookup.parse("203.0.113.0/24").kind is Kind.BLOCK
    with pytest.raises(TargetError):
        lookup.parse("10.0.0.0/8")


def test_every_address_in_a_block_is_examined_including_the_network_one():
    """`.hosts()` drops the network and broadcast addresses, so 8.8.8.8/29
    examined .9 to .14 and silently skipped 8.8.8.8 — the address the user
    typed. Those carry PTR records like any other."""
    target = lookup.parse("8.8.8.8/29")
    assert "8.8.8.8" in target.addresses
    assert len(target.addresses) == 8


def test_a_block_at_the_cap_is_admitted_and_one_over_is_refused():
    assert len(lookup.parse("203.0.113.0/24").addresses) == lookup.MAX_CIDR_HOSTS
    with pytest.raises(TargetError) as exc:
        lookup.parse("203.0.112.0/23")
    assert "silently truncated" in str(exc.value)


def test_an_address_with_a_mask_names_the_block_it_is_in():
    target = lookup.parse("203.0.113.5/24")
    assert target.value == "203.0.113.0/24", "normalised, so what was examined is unambiguous"


def test_an_email_address_is_refused_with_the_reason():
    """Answering it here would mean one box quietly doing two unrelated
    things."""
    with pytest.raises(TargetError) as exc:
        lookup.parse("someone@example.com")
    assert "different question with a different source" in str(exc.value)


@pytest.mark.parametrize("bad", ["", "   ", "not a domain", "..", "-a.com"])
def test_nonsense_is_refused(bad):
    with pytest.raises(TargetError):
        lookup.parse(bad)


# ── the gate decides what a lookup may do ───────────────────────────────────
def test_a_typed_target_can_never_be_probed_actively():
    """The direction asked for a box you type any domain into. Loosening scope
    to serve it would widen what the ACTIVE collectors may touch — so the
    passive route is taken instead, and this pins that the active ones stay
    refused even with the name explicitly in scope."""
    scope = Scope([ScopeRule(kind=ScopeKind.DOMAIN, value="typed.example")])
    for operation in ("http_probe", "tls_handshake", "port_scan",
                      "service_banner_read"):
        with pytest.raises(gate.OwnershipNotVerified):
            gate.authorise(asset="typed.example", operation=operation,
                           actor="k@example.com", scope=scope, verification=None)


def test_the_passive_only_claim_is_stated_not_implied():
    text = lookup.PASSIVE_ONLY
    assert "cannot be anything else" in text
    assert "fails closed" in text
    assert "what the target PUBLISHES, and cannot report what it runs" in text


# ── the score ───────────────────────────────────────────────────────────────
def _posture(present, absent):
    supplier = suppliers.Supplier(name="x", domain="x.example",
                                  tier=suppliers.Tier.ROUTINE,
                                  declared_by="t@example.com")
    return suppliers.Posture(supplier=supplier, present=list(present),
                             absent=list(absent))


def test_a_score_refuses_below_the_factor_floor():
    """Averaging what happened to be visible produces a number that looks
    comparable to one drawn from four factors and is not."""
    found = lookup.Lookup(target=lookup.parse("example.com"),
                          posture=_posture([suppliers.Signal.CAA], []))
    score = found.score().to_dict()
    assert score["value"] is None and score["publishable"] is False
    assert "No score is shown" in score["refusal"]


def test_an_unobserved_factor_is_never_scored_as_zero():
    """The error this module's own docstring warns about, and committed within
    twenty lines of saying so: `bool(None)` scored an unread transfer-lock as a
    failure. A factor is observed only when a real boolean arrived."""
    found = lookup.Lookup(target=lookup.parse("example.com"),
                          registration={"status": "unknown", "locked": None})
    factors = found.score().factors
    assert factors["registration"] is None, "unread is not the same as unlocked"


def test_a_read_lock_is_scored():
    """`observed` is required, not just `locked`. A payload carrying a lock
    field without saying the lookup succeeded is exactly the ambiguity the
    unobserved-is-not-zero rule exists to remove."""
    found = lookup.Lookup(target=lookup.parse("example.com"),
                          registration={"observed": True, "locked": True})
    assert found.score().factors["registration"] == 1.0
    found.registration = {"observed": True, "locked": False}
    assert found.score().factors["registration"] == 0.0


def test_the_score_always_arrives_decomposed():
    """A score whose decomposition is one click away arrives alone in a
    screenshot."""
    found = lookup.Lookup(target=lookup.parse("example.com"),
                          names=["a.example.com"] * 30,
                          posture=_posture([suppliers.Signal.CAA],
                                           [suppliers.Signal.MTA_STS]),
                          registration={"observed": True, "locked": True})
    payload = found.score().to_dict()
    assert payload["value"] is not None
    for name, factor in payload["factors"].items():
        assert "measures" in factor and "cannot_see" in factor
        assert factor["inputs"] is not None


def test_every_factor_says_what_it_cannot_see():
    for factor in lookup.Factor:
        assert factor.measures and factor.cannot_see


def test_the_reputation_factor_names_the_thing_it_cannot_do():
    """Without a key there is no way to see open ports at all, and a reader
    must not take a quiet result as an empty one."""
    text = lookup.Factor.REPUTATION.cannot_see
    assert "OPEN PORTS AND RUNNING SERVICES" in text
    assert "refused" in text and "needs a key" in text


def test_posture_scores_only_the_discriminating_signals():
    """SPF 8/8 and DMARC 8/8 across real domains: presence separates nobody."""
    found = lookup.Lookup(
        target=lookup.parse("example.com"),
        posture=_posture([suppliers.Signal.SPF, suppliers.Signal.DMARC], []))
    assert found.score().factors["posture"] is None, (
        "presence-only signals must not constitute an observed factor")


def test_the_score_says_it_is_not_a_grade():
    payload = lookup.Lookup(target=lookup.parse("example.com")).score().to_dict()
    assert "not a letter grade" in payload["not_a_grade"]
    assert "does not compare organisations" in payload["not_a_grade"]


# ── unavailable sources ─────────────────────────────────────────────────────
def test_a_keyless_source_is_reported_as_unavailable_not_omitted(monkeypatch):
    """A result that silently omits Shodan reads as 'no open ports'."""
    from collect import lookup_scan
    monkeypatch.delenv("SKOPOS_SHODAN_API_KEY", raising=False)
    monkeypatch.delenv("SKOPOS_VIRUSTOTAL_API_KEY", raising=False)
    unavailable = lookup_scan.unavailable_sources(lookup.parse("example.com"))
    names = {u["source"] for u in unavailable}
    assert "shodan" in names
    shodan = [u for u in unavailable if u["source"] == "shodan"][0]
    assert "open ports" in shodan["cost"]
    assert "SKOPOS_SHODAN_API_KEY" in shodan["why"]


def test_a_configured_source_stops_being_reported(monkeypatch):
    from collect import lookup_scan
    monkeypatch.setenv("SKOPOS_SHODAN_API_KEY", "a-key")
    names = {u["source"]
             for u in lookup_scan.unavailable_sources(lookup.parse("example.com"))}
    assert "shodan" not in names


def test_the_keyed_sources_are_registered_with_their_terms():
    """Terms are the operator's to accept, not this product's."""
    from collect import registry
    for name in ("shodan", "virustotal", "hibp"):
        source = registry.BY_NAME[name]
        assert source.terms is registry.Terms.CREDENTIALED
        assert source.credential_env
        assert source.default_on is False


def test_unavailable_sources_travel_in_the_payload():
    found = lookup.Lookup(
        target=lookup.parse("example.com"),
        unavailable=[{"source": "shodan", "why": "no key", "cost": "x",
                      "terms": "credentialed"}])
    assert found.to_dict()["unavailable_sources"][0]["source"] == "shodan"
    assert "PASSIVE and cannot be anything else" in found.to_dict()["passive_only"]


# ── the licensed sources ────────────────────────────────────────────────────
def test_no_key_is_reported_as_unavailable_not_as_an_answer(monkeypatch):
    """The single most consequential lie this module could tell: 'we have no
    key' rendered as 'there is nothing there'."""
    from collect import keyed_sources
    monkeypatch.delenv("SKOPOS_SHODAN_API_KEY", raising=False)
    answer = keyed_sources.shodan_host(None, "203.0.113.4")
    assert answer.available is False and answer.answered is False
    assert "That is NOT a result" in answer.detail


def test_shodan_404_is_an_answer_and_says_what_it_means():
    """Shodan 404 means it has never scanned the address, not that nothing is
    listening on it."""
    from collect import keyed_sources
    answer = keyed_sources._shape_shodan(404, "")
    assert answer.answered is True
    assert "never that nothing is listening" in answer.detail


def test_shodan_vulns_are_never_promoted_to_a_determination():
    """Shodan derives them from a banner, and this product refuses to let an
    observed version reach the field a published range is evaluated against.
    Carrying them as findings would route around that through a third party."""
    import json

    from collect import keyed_sources
    body = json.dumps({"ports": [443], "data": [], "vulns": ["CVE-2021-23017"]})
    answer = keyed_sources._shape_shodan(200, body)
    claim = [o for o in answer.observations if o["kind"] == "vuln_claim"][0]
    assert "not a version comparison" in claim["basis"]
    assert "does not join it to the catalogue" in claim["basis"]


def test_a_rejected_key_is_distinguished_from_an_empty_answer():
    from collect import keyed_sources
    for shape, status in ((keyed_sources._shape_shodan, 401),
                          (keyed_sources._shape_virustotal, 401),
                          (keyed_sources._shape_hibp, 401)):
        answer = shape(status, "")
        assert answer.available is True and answer.answered is False
        assert "rejected" in answer.detail


def test_rate_limiting_is_reported_rather_than_retried_silently():
    from collect import keyed_sources
    assert "rate limited" in keyed_sources._shape_virustotal(429, "").detail
    assert "rate limited" in keyed_sources._shape_hibp(429, "").detail


def test_virustotal_counts_are_carried_whole_not_reduced_to_a_boolean():
    """Engines disagree constantly; two flags out of ninety is noise."""
    import json

    from collect import keyed_sources
    body = json.dumps({"data": {"attributes": {"last_analysis_stats": {
        "malicious": 2, "suspicious": 1, "harmless": 70, "undetected": 17}}}})
    observation = keyed_sources._shape_virustotal(200, body).observations[0]
    assert observation["malicious"] == 2 and observation["engines"] == 90
    assert "noise, not a verdict" in observation["meaning"]
    assert "none of it says who is behind anything" in observation["meaning"]


def test_hibp_says_what_a_breach_does_not_mean():
    import json

    from collect import keyed_sources
    body = json.dumps([{"Name": "X", "BreachDate": "2019-01-01",
                        "DataClasses": ["Passwords"], "IsVerified": True}])
    observation = keyed_sources._shape_hibp(200, body).observations[0]
    assert "does not say the account is compromised now" in observation["meaning"]


def test_hibp_404_is_a_real_answer():
    from collect import keyed_sources
    answer = keyed_sources._shape_hibp(404, "")
    assert answer.answered is True and "not a guarantee" in answer.detail


def test_no_live_path_claims_to_be_verified():
    """These were written against documented contracts and have never run
    against the real services. Every answer carries that until somebody flips
    it after a run with a real key."""
    from collect import keyed_sources
    assert not any(keyed_sources.VERIFIED_LIVE.values())
    answer = keyed_sources._shape_shodan(404, "")
    assert answer.to_dict()["caveat"] is not None
    assert "has NOT been executed against the real service" in answer.to_dict()["caveat"]


def test_a_licensed_host_is_allowlisted_but_holds_no_credential():
    """Being reachable is not being configured."""
    from collect import egress, registry
    for host in ("api.shodan.io", "www.virustotal.com", "haveibeenpwned.com"):
        assert host in egress.ALLOWED_HTTP_HOSTS
    for name in ("shodan", "virustotal", "hibp"):
        assert registry.BY_NAME[name].configured is False


# ── registration ────────────────────────────────────────────────────────────
def test_a_failed_registration_lookup_is_unobserved_not_unlocked():
    """Our outage must not render as their negligence."""
    found = lookup.Lookup(target=lookup.parse("example.com"),
                          registration={"observed": False, "detail": "timeout"})
    assert found.score().factors["registration"] is None


def test_a_redirect_off_the_allowlist_is_not_followed():
    import inspect

    from collect import takeover_scan
    source = inspect.getsource(takeover_scan.rdap_registration)
    assert "ALLOWED_HTTP_HOSTS" in source
    assert "not followed" in source
