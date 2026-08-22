"""FR-GOV-001: active collection against an unverified asset must fail closed.

Plus FR-GOV-003 and FR-GOV-007, which are refusals no authorisation can lift.
"""
from __future__ import annotations

from datetime import date, timedelta

import pytest

from core import gate
from core.gate import Exposure, NotInScope, OperationRefused, Permit, authorise
from core.ownership import Method, OwnershipNotVerified, Verification
from core.scope import Scope, ScopeKind, ScopeRule

TODAY = date(2026, 8, 22)
ACTOR = "k.de"


def scope_with(*values: str) -> Scope:
    return Scope([ScopeRule(kind=ScopeKind.WILDCARD, value=v) for v in values])


def proven(asset: str, on: date = TODAY) -> Verification:
    return Verification.granted(asset, Method.DNS_TXT, evidence="TXT record", on=on)


# -- the acceptance criterion ------------------------------------------------
def test_active_collection_without_verification_is_refused():
    """In scope is not permission. This is the whole requirement."""
    with pytest.raises(OwnershipNotVerified) as exc:
        authorise("api.example.com", "port_scan", ACTOR,
                  scope_with("example.com"), verification=None, today=TODAY)
    assert "does not establish that you control it" in str(exc.value)


def test_active_collection_with_current_verification_is_permitted():
    permit = authorise("api.example.com", "port_scan", ACTOR,
                       scope_with("example.com"),
                       verification=proven("api.example.com"), today=TODAY)
    assert permit.exposure is Exposure.ACTIVE
    assert "dns_txt" in permit.rationale


def test_expired_verification_refuses():
    """A verification proves control when it was checked, not today."""
    stale = proven("api.example.com", on=TODAY - timedelta(days=200))
    with pytest.raises(OwnershipNotVerified) as exc:
        authorise("api.example.com", "http_probe", ACTOR,
                  scope_with("example.com"), verification=stale, today=TODAY)
    assert "EXPIRED" in str(exc.value)


def test_verification_for_another_asset_does_not_transfer():
    """Otherwise one proven domain unlocks every other name in scope."""
    with pytest.raises(OwnershipNotVerified) as exc:
        authorise("api.example.com", "port_scan", ACTOR,
                  scope_with("example.com"),
                  verification=proven("other.example.com"), today=TODAY)
    assert "not this asset" in str(exc.value)


def test_verification_on_its_last_day_is_still_current():
    """The boundary, asserted rather than assumed."""
    granted = proven("api.example.com")
    assert granted.expires_at is not None
    permit = authorise("api.example.com", "port_scan", ACTOR,
                       scope_with("example.com"), verification=granted,
                       today=granted.expires_at)
    assert permit.exposure is Exposure.ACTIVE

    with pytest.raises(OwnershipNotVerified):
        authorise("api.example.com", "port_scan", ACTOR,
                  scope_with("example.com"), verification=granted,
                  today=granted.expires_at + timedelta(days=1))


# -- passive is a different question ----------------------------------------
def test_passive_collection_needs_no_ownership_proof():
    """CT logs are third-party infrastructure publishing already-public data."""
    permit = authorise("api.example.com", "ct_log_search", ACTOR,
                       scope_with("example.com"), verification=None, today=TODAY)
    assert permit.exposure is Exposure.PASSIVE


def test_passive_collection_still_respects_scope():
    with pytest.raises(NotInScope):
        authorise("someone-else.net", "ct_log_search", ACTOR,
                  scope_with("example.com"), today=TODAY)


# -- refusals no authorisation can lift --------------------------------------
@pytest.mark.parametrize("operation", ["forum_authenticate", "forum_transact",
                                       "exploit_attempt", "credential_replay"])
def test_prohibited_operations_are_refused_even_when_fully_authorised(operation):
    """FR-GOV-003 / FR-GOV-007. Proven ownership does not license these."""
    with pytest.raises(OperationRefused):
        authorise("api.example.com", operation, ACTOR, scope_with("example.com"),
                  verification=proven("api.example.com"), today=TODAY)


def test_prohibited_is_decided_before_scope():
    """The refusal must not be reachable by editing scope.

    Asserted via an out-of-scope asset: if scope were consulted first this would
    raise NotInScope, and an operator could 'fix' it by adding a scope rule.
    """
    with pytest.raises(OperationRefused):
        authorise("someone-else.net", "exploit_attempt", ACTOR, Scope(), today=TODAY)


def test_unregistered_operations_are_refused_not_assumed_passive():
    """A collector whose author forgot to register it fails loudly."""
    with pytest.raises(OperationRefused) as exc:
        authorise("api.example.com", "some_new_collector", ACTOR,
                  scope_with("example.com"), verification=proven("api.example.com"),
                  today=TODAY)
    assert "not a registered operation" in str(exc.value)


def test_every_registered_operation_has_an_explicit_classification():
    """Guards against a future entry being added with a placeholder."""
    assert all(isinstance(v, Exposure) for v in gate.OPERATIONS.values())
    assert gate.classify("definitely_not_registered") is Exposure.PROHIBITED


# -- the structural property -------------------------------------------------
def test_a_permit_cannot_be_forged():
    """The bypass FR-GOV-001 has to survive: a plugin building its own Permit."""
    with pytest.raises(PermissionError) as exc:
        Permit(asset="api.example.com", operation="port_scan",
               exposure=Exposure.ACTIVE, actor=ACTOR)
    assert "may only be issued by core.gate.authorise" in str(exc.value)


def test_excluded_asset_is_refused_with_a_message_that_says_it_was_deliberate():
    scope = Scope([ScopeRule(kind=ScopeKind.WILDCARD, value="example.com"),
                   ScopeRule(kind=ScopeKind.DOMAIN, value="vpn.example.com",
                             is_exclude=True, note="third-party managed")])
    with pytest.raises(NotInScope) as exc:
        authorise("vpn.example.com", "http_probe", ACTOR, scope,
                  verification=proven("vpn.example.com"), today=TODAY)
    message = str(exc.value)
    assert "third-party managed" in message
    assert "deliberate instruction" in message


def test_refusal_reasons_reports_every_asset_not_just_the_first():
    reasons = gate.refusal_reasons(
        ["api.example.com", "someone-else.net", "vpn.example.com"],
        "port_scan", ACTOR, scope_with("example.com"), today=TODAY)
    assert len(reasons) == 3, "an operator should see the whole list at once"
