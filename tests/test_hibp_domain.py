"""Domain-level breach exposure (P8 W5).

Two properties carry this file: that SKOPOS will not ask HIBP about a domain the
operator has not proven they control, and that no address survives the parse.
"""
from __future__ import annotations

import json

import pytest

from collect import keyed_sources as ks

# The documented shape: an object keyed by LOCAL PART. Those keys are addresses.
REAL = json.dumps({
    "alice": ["Adobe", "LinkedIn"],
    "bob": ["LinkedIn"],
    "carol": ["Adobe", "Dropbox", "LinkedIn"],
})


# ── the ownership precondition ──────────────────────────────────────────────
def test_it_refuses_without_a_verification(monkeypatch):
    """HIBP only answers for a domain you have proven you control, and SKOPOS
    already performs exactly that proof. Reusing it keeps one answer to 'is
    this ours' and stops the product asking a question it has no standing to
    ask."""
    monkeypatch.setenv("SKOPOS_HIBP_API_KEY", "k")
    answer = ks.hibp_domain(object(), "example.com", verified=False)
    assert answer.available is False
    assert "proven you control" in answer.detail


def test_it_refuses_without_a_key_before_anything_else(monkeypatch):
    monkeypatch.delenv("SKOPOS_HIBP_API_KEY", raising=False)
    answer = ks.hibp_domain(object(), "example.com", verified=True)
    assert answer.available is False
    assert "not set" in answer.detail


def test_the_verified_flag_is_required_rather_than_defaulted():
    """A default of True would make the refusal opt-in, which is backwards."""
    import inspect
    parameter = inspect.signature(ks.hibp_domain).parameters["verified"]
    assert parameter.default is inspect.Parameter.empty


# ── no address survives the parse ───────────────────────────────────────────
def test_no_address_is_carried_into_the_result():
    """The response keys ARE the addresses. A list of which colleagues appear
    in which breach is a document nobody should create casually, and
    FR-GOV-002 must not be tested by this feature."""
    answer = ks._shape_hibp_domain(200, REAL, "example.com")
    flat = json.dumps(answer.to_dict())
    for local_part in ("alice", "bob", "carol"):
        assert local_part not in flat, local_part


def test_it_reports_breaches_and_counts_instead():
    answer = ks._shape_hibp_domain(200, REAL, "example.com")
    breaches = {o["breach"]: o["addresses_affected"]
                for o in answer.observations}
    assert breaches == {"LinkedIn": 3, "Adobe": 2, "Dropbox": 1}


def test_breaches_come_back_worst_first():
    answer = ks._shape_hibp_domain(200, REAL, "example.com")
    assert answer.observations[0]["breach"] == "LinkedIn"


def test_the_detail_states_what_is_not_recorded():
    answer = ks._shape_hibp_domain(200, REAL, "example.com")
    assert "No address, password or hash is recorded" in answer.detail
    assert "3 address(es)" in answer.detail


# ── what a result means ─────────────────────────────────────────────────────
def test_a_breach_observation_is_not_a_compromise_claim():
    """It says addresses appeared in a corpus published on a date. The remedy
    is somebody's judgement and it is not this product's to assert."""
    answer = ks._shape_hibp_domain(200, REAL, "example.com")
    basis = answer.observations[0]["basis"]
    assert "NOT that any account is compromised now" in basis
    assert "somebody's judgement" in basis


def test_a_404_is_not_a_clean_bill_of_health():
    answer = ks._shape_hibp_domain(404, "", "example.com")
    assert answer.answered is True
    assert answer.observations == []
    assert "not a clean bill of health" in answer.detail


def test_a_403_explains_that_hibp_wants_its_own_proof():
    """Proving control to SKOPOS is not proving it to HIBP."""
    answer = ks._shape_hibp_domain(403, "", "example.com")
    assert answer.answered is False
    assert "verified to your account" in answer.detail


def test_a_401_is_a_key_problem_not_a_result():
    assert ks._shape_hibp_domain(401, "", "x.example").answered is False


@pytest.mark.parametrize("body", ["<html>", "[]", "null"])
def test_a_bad_body_is_a_failure_not_an_empty_result(body):
    assert ks._shape_hibp_domain(200, body, "x.example").answered is False


def test_an_empty_object_answers_with_nothing():
    answer = ks._shape_hibp_domain(200, "{}", "x.example")
    assert answer.answered is True and answer.observations == []


def test_it_remains_unverified_until_a_real_key_runs_it():
    """Every keyed source carries this until somebody runs it for real."""
    answer = ks._shape_hibp_domain(200, REAL, "example.com")
    assert answer.verified_live is False
    assert answer.to_dict()["caveat"] is not None
