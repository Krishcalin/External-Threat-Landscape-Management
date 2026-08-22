"""FR-M0-003: overlapping include/exclude resolves deterministically, exclude wins."""
from __future__ import annotations

import itertools

import pytest

from core.scope import Decision, Scope, ScopeKind, ScopeRule


def include(kind: ScopeKind, value: str) -> ScopeRule:
    return ScopeRule(kind=kind, value=value, is_exclude=False)


def exclude(kind: ScopeKind, value: str) -> ScopeRule:
    return ScopeRule(kind=kind, value=value, is_exclude=True)


# -- the acceptance criterion ------------------------------------------------
def test_exclude_beats_a_more_specific_include():
    """The case every specificity scheme gets wrong.

    `lab.example.com` is named exactly by an include and only generally by the
    exclude. Under "most specific wins" it would be in scope, and the tool would
    probe a host somebody explicitly ring-fenced.
    """
    scope = Scope([include(ScopeKind.DOMAIN, "lab.example.com"),
                   exclude(ScopeKind.WILDCARD, "example.com")])
    verdict = scope.resolve("lab.example.com")
    assert verdict.decision is Decision.EXCLUDED
    assert not verdict.in_scope


def test_exclude_wins_in_every_rule_ordering():
    """Order-independence, asserted over all permutations rather than claimed."""
    rules = [include(ScopeKind.WILDCARD, "example.com"),
             include(ScopeKind.DOMAIN, "vpn.example.com"),
             exclude(ScopeKind.DOMAIN, "vpn.example.com")]
    decisions = {Scope(list(order)).resolve("vpn.example.com").decision
                 for order in itertools.permutations(rules)}
    assert decisions == {Decision.EXCLUDED}


def test_unscoped_is_not_excluded():
    """Different states, because they are different mistakes.

    UNSCOPED means nobody has spoken about this asset — which for reporting is a
    shadow-asset signal worth surfacing. EXCLUDED means somebody said no. A
    product that collapsed them would either lose the shadow asset or treat a
    deliberate exclusion as an oversight.
    """
    scope = Scope([include(ScopeKind.WILDCARD, "example.com")])
    assert scope.resolve("elsewhere.net").decision is Decision.UNSCOPED
    assert scope.resolve("elsewhere.net").decision is not Decision.EXCLUDED


# -- matching boundaries -----------------------------------------------------
def test_wildcard_requires_the_dot():
    """`*.example.com` must not claim `notexample.com` — someone else's domain."""
    scope = Scope([include(ScopeKind.WILDCARD, "example.com")])
    assert scope.includes("api.example.com")
    assert scope.includes("example.com")          # the apex itself
    assert not scope.includes("notexample.com")
    assert not scope.includes("example.com.evil.net")


def test_domain_rule_does_not_match_subdomains():
    scope = Scope([include(ScopeKind.DOMAIN, "example.com")])
    assert scope.includes("example.com")
    assert not scope.includes("api.example.com")


def test_host_normalisation_is_forgiving_about_form_only():
    scope = Scope([include(ScopeKind.DOMAIN, "Example.COM.")])
    assert scope.includes("example.com")
    assert scope.includes("EXAMPLE.com.")


@pytest.mark.parametrize("address,expected", [
    ("10.0.0.1", True),
    ("10.0.255.254", True),
    ("10.1.0.1", False),
    ("192.168.0.1", False),
    ("not-an-address", False),
])
def test_cidr_membership(address, expected):
    scope = Scope([include(ScopeKind.CIDR, "10.0.0.0/16")])
    assert scope.includes(address) is expected


def test_cidr_family_mismatch_is_not_a_match():
    """An IPv6 address is not in an IPv4 network, and asking must not raise."""
    scope = Scope([include(ScopeKind.CIDR, "10.0.0.0/8")])
    assert not scope.includes("2001:db8::1")


def test_asn_forms_are_equivalent():
    scope = Scope([include(ScopeKind.ASN, "AS64500")])
    assert scope.includes("as64500")
    assert scope.includes("AS64500")
    assert not scope.includes("AS64501")


def test_kind_mismatch_prevents_cross_type_matching():
    """A cloud-account rule must not answer a question about a repo org."""
    scope = Scope([include(ScopeKind.CLOUD_ACCOUNT, "123456789012")])
    assert scope.includes("123456789012", ScopeKind.CLOUD_ACCOUNT)
    assert not scope.includes("123456789012", ScopeKind.REPO_ORG)


# -- the verdict has to be arguable -----------------------------------------
def test_verdict_cites_the_exclusion_that_caused_it():
    scope = Scope([include(ScopeKind.WILDCARD, "example.com"),
                   exclude(ScopeKind.DOMAIN, "vpn.example.com")])
    verdict = scope.resolve("vpn.example.com")
    assert verdict.matched[0].is_exclude, "the reason must lead the evidence"
    assert "exclusion always wins" in verdict.explain()


def test_unscoped_verdict_says_so_plainly():
    assert "no scope rule" in Scope().resolve("example.com").explain()


def test_a_rule_needs_a_value():
    with pytest.raises(ValueError):
        ScopeRule(kind=ScopeKind.DOMAIN, value="   ")
