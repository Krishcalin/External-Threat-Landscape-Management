"""The choke point. Every rule here is one a collector no longer has to remember.

These assert on `require()` and the helpers' guards rather than on live traffic —
nothing in this file touches the network (SRS §15). What is being tested is the
refusal, and a refusal is testable without a socket.
"""
from __future__ import annotations

from datetime import date

import pytest

from collect import egress
from collect.egress import Budget, Limiter, PermitMismatch
from core import gate
from core.ownership import Method, Verification
from core.scope import Scope, ScopeKind, ScopeRule

TODAY = date(2026, 8, 22)
ACTOR = "k.de"


@pytest.fixture
def scope() -> Scope:
    return Scope([
        ScopeRule(kind=ScopeKind.WILDCARD, value="example.com"),
        ScopeRule(kind=ScopeKind.CIDR, value="203.0.113.0/24"),
        ScopeRule(kind=ScopeKind.CIDR, value="104.18.0.0/16", is_exclude=True,
                  note="shared CDN"),
    ])


@pytest.fixture
def passive_permit(scope):
    return gate.authorise("example.com", "ct_log_search", ACTOR, scope, today=TODAY)


@pytest.fixture
def active_permit(scope):
    return gate.authorise_target(
        "api.example.com", ["203.0.113.10"], "port_scan", ACTOR, scope,
        verification=Verification.granted("api.example.com", Method.DNS_TXT,
                                          on=TODAY),
        today=TODAY)


# -- the permit must match the work ------------------------------------------
def test_no_permit_is_refused():
    with pytest.raises(PermitMismatch) as exc:
        egress.require(None, "ct_log_search", exposure=gate.Exposure.PASSIVE)
    assert "Collectors do not decide what they may touch" in str(exc.value)


def test_a_permit_for_another_operation_is_refused(passive_permit):
    with pytest.raises(PermitMismatch) as exc:
        egress.require(passive_permit, "port_scan", exposure=gate.Exposure.ACTIVE)
    assert "authorises 'ct_log_search'" in str(exc.value)


def test_a_permit_for_another_asset_is_refused(passive_permit):
    with pytest.raises(PermitMismatch):
        egress.require(passive_permit, "ct_log_search",
                       exposure=gate.Exposure.PASSIVE, asset="somewhere.else")


def test_operation_comparison_is_normalised(scope):
    """authorise() stores the raw operation; classify() normalises.

    A naive == would reject a permit the gate legitimately issued for
    'CT_Log_Search', which is a refusal the operator cannot act on.
    """
    permit = gate.authorise("example.com", "CT_Log_Search", ACTOR, scope, today=TODAY)
    egress.require(permit, "ct_log_search", exposure=gate.Exposure.PASSIVE)


# -- ports -------------------------------------------------------------------
def test_an_http_permit_cannot_read_a_database_greeting(scope):
    """The bypass this table exists for: reaching 3306 through the approved helper."""
    permit = gate.authorise_target(
        "api.example.com", ["203.0.113.10"], "http_probe", ACTOR, scope,
        verification=Verification.granted("api.example.com", Method.DNS_TXT,
                                          on=TODAY), today=TODAY)
    egress.require(permit, "http_probe", exposure=gate.Exposure.ACTIVE,
                   address="203.0.113.10", port=443)
    with pytest.raises(PermitMismatch) as exc:
        egress.require(permit, "http_probe", exposure=gate.Exposure.ACTIVE,
                       address="203.0.113.10", port=3306)
    assert "may not reach port 3306" in str(exc.value)


def test_every_port_table_operation_is_registered():
    """A table entry for an operation the gate refuses describes dead work."""
    unknown = sorted(set(egress.PORTS_BY_OPERATION) - set(gate.OPERATIONS))
    assert not unknown, unknown


# -- addresses ---------------------------------------------------------------
def test_active_work_needs_an_address_sealed_permit(scope):
    name_only = gate.authorise(
        "api.example.com", "port_scan", ACTOR, scope,
        verification=Verification.granted("api.example.com", Method.DNS_TXT,
                                          on=TODAY), today=TODAY)
    with pytest.raises(PermitMismatch) as exc:
        egress.require(name_only, "port_scan", exposure=gate.Exposure.ACTIVE,
                       address="203.0.113.10", port=443)
    assert "authorise_target" in str(exc.value)


def test_an_address_outside_the_permit_is_refused(active_permit):
    """Pins the check and the connection together against DNS rebinding.

    Re-resolving between authorisation and connection is the whole attack: the
    name that passed the gate is not necessarily the address you reach.
    """
    egress.require(active_permit, "port_scan", exposure=gate.Exposure.ACTIVE,
                   address="203.0.113.10", port=443)
    with pytest.raises(PermitMismatch) as exc:
        egress.require(active_permit, "port_scan", exposure=gate.Exposure.ACTIVE,
                       address="198.51.100.9", port=443)
    assert "does not cover address" in str(exc.value)


def test_a_cidr_exclusion_now_fires_for_a_hostname(scope):
    """D10 says exclude wins unconditionally; before this it lost silently.

    Measured: scope.resolve('api.example.com', DOMAIN) is INCLUDED while
    scope.resolve('104.18.5.7', CIDR) is EXCLUDED, and the name path never
    consulted the address.
    """
    verification = Verification.granted("api.example.com", Method.DNS_TXT, on=TODAY)
    with pytest.raises(gate.NotInScope) as exc:
        gate.authorise_target("api.example.com", ["104.18.5.7"], "http_probe",
                              ACTOR, scope, verification, today=TODAY)
    assert "104.18.5.7" in str(exc.value)


def test_a_sweep_needs_an_address_positively_in_scope(scope):
    """Ownership is proven over a NAME; a sweep is delivered to an ADDRESS.

    A name pointed at a SaaS tenant would otherwise authorise sweeping a third
    party who consented to nothing.
    """
    verification = Verification.granted("api.example.com", Method.DNS_TXT, on=TODAY)
    with pytest.raises(gate.NotInScope) as exc:
        gate.authorise_target("api.example.com", ["198.51.100.9"], "port_scan",
                              ACTOR, scope, verification, today=TODAY)
    assert "does not establish that you own what it points at" in str(exc.value)


def test_an_http_probe_to_an_unscoped_but_unexcluded_address_is_allowed(scope):
    """Deliberate asymmetry: a Host-routed request reaches the tenant.

    A sweep does not, which is why only the sweep needs positive inclusion.
    """
    verification = Verification.granted("api.example.com", Method.DNS_TXT, on=TODAY)
    permit = gate.authorise_target("api.example.com", ["198.51.100.9"],
                                   "http_probe", ACTOR, scope, verification,
                                   today=TODAY)
    assert permit.addresses == ("198.51.100.9",)


def test_an_asn_rule_does_not_authorise_an_address(scope):
    """Measured: resolve('203.0.113.10', ASN) is UNSCOPED — there is no
    IP-to-ASN mapping in this product, so say so rather than letting the
    operator believe their ASN rule covers the sweep."""
    with_asn = Scope(list(scope.rules) + [ScopeRule(kind=ScopeKind.ASN,
                                                    value="AS64500")])
    verification = Verification.granted("api.example.com", Method.DNS_TXT, on=TODAY)
    with pytest.raises(gate.NotInScope) as exc:
        gate.authorise_target("api.example.com", ["198.51.100.9"], "port_scan",
                              ACTOR, with_asn, verification, today=TODAY)
    assert "ASN rules" in str(exc.value)


def test_addresses_are_sealed_onto_the_permit(active_permit):
    """Otherwise the address check is advice, not a control."""
    import dataclasses
    with pytest.raises(PermissionError):
        dataclasses.replace(active_permit, addresses=("198.51.100.9",))


# -- transport rules ---------------------------------------------------------
def test_http_get_refuses_plaintext(passive_permit):
    """An on-path attacker who can silently DELETE hostnames from a plaintext
    response shrinks the reported estate with no source reporting FAILED."""
    with pytest.raises(PermitMismatch) as exc:
        egress.http_get(passive_permit, "ct_log_search",
                        "http://crt.sh/?q=example.com")
    assert "not https" in str(exc.value)


def test_passive_fetches_reach_only_registered_hosts(passive_permit):
    with pytest.raises(PermitMismatch) as exc:
        egress.http_get(passive_permit, "ct_log_search",
                        "https://attacker.example/collect")
    assert "not a registered source host" in str(exc.value)


def test_a_passive_resolver_query_cannot_be_aimed_at_the_customer(passive_permit, scope):
    """--resolvers 10.0.0.53 would be active work under a permit proving nothing."""
    permit = gate.authorise("example.com", "dns_resolve_recursive", ACTOR, scope,
                            today=TODAY)
    with pytest.raises(PermitMismatch) as exc:
        egress.udp(permit, "dns_resolve_recursive", "10.0.0.53", 53, b"")
    assert "third-party resolvers" in str(exc.value)


# -- budget and rate limiting ------------------------------------------------
def test_all_three_rate_buckets_are_traversed():
    """Per-address alone lets 400 hosts in one /22 open ~400 flows a second."""
    slept = []
    clock = iter([0.0] * 200)
    limiter = Limiter(Budget(per_address_interval=1.0, per_network_interval=0.5,
                             global_interval=0.25),
                      clock=lambda: 0.0, sleep=slept.append)
    limiter.acquire("203.0.113.1")
    limiter.acquire("203.0.113.2")     # same /24, different address
    assert slept and max(slept) >= 0.5, \
        "the /24 bucket must delay a different address in the same network"


def test_the_query_budget_is_loud_when_spent():
    limiter = Limiter(Budget(max_queries=2, per_address_interval=0,
                             per_network_interval=0, global_interval=0),
                      clock=lambda: 0.0, sleep=lambda _s: None)
    limiter.acquire("203.0.113.1")
    limiter.acquire("203.0.113.2")
    with pytest.raises(egress.BudgetExhausted) as exc:
        limiter.acquire("203.0.113.3")
    assert "reported unattempted" in str(exc.value)


def test_the_time_budget_is_loud_when_spent():
    now = [0.0]
    limiter = Limiter(Budget(run_seconds=10.0, per_address_interval=0,
                             per_network_interval=0, global_interval=0),
                      clock=lambda: now[0], sleep=lambda _s: None)
    limiter.acquire("203.0.113.1")
    now[0] = 11.0
    with pytest.raises(egress.BudgetExhausted):
        limiter.acquire("203.0.113.1")


def test_retry_after_is_capped():
    """An uncapped honour of Retry-After: 86400 hangs a synchronous CLI a day."""
    assert egress.MAX_RETRY_AFTER <= 60


def test_concurrency_has_a_hard_ceiling():
    assert egress.MAX_CONCURRENCY <= 32
    assert Budget().concurrency <= egress.MAX_CONCURRENCY
