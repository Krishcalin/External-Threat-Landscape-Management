"""Multi-source passive discovery: the merge, the scope binding, the terms.

No live network (SRS §15). Sources are injected; what is under test is what this
product does with what they say, which is where every interesting mistake lives.
"""
from __future__ import annotations

from datetime import date

import pytest

from collect import registry
from collect.discovery import (DiscoveredName, DiscoveryResult, Excluded,
                               NameObservation, merge, to_inventory_rows)
from collect.registry import DataClass, Source, Terms
from collect.report import Outcome, SourceReport
from core.scope import Decision, Scope, ScopeKind, ScopeRule


def obs(name, source="certspotter", data_class=DataClass.CT,
        first=None, last=None, addresses=()):
    return NameObservation(name=name, source=source, data_class=data_class,
                           first_seen=first, last_seen=last, addresses=addresses)


def scope_with(*rules):
    return Scope(list(rules))


WILDCARD = ScopeRule(kind=ScopeKind.WILDCARD, value="example.com")


# -- scope binds every name individually -------------------------------------
def test_an_excluded_name_is_returned_not_silently_dropped():
    scope = scope_with(WILDCARD,
                       ScopeRule(kind=ScopeKind.DOMAIN, value="vpn.example.com",
                                 is_exclude=True, note="third-party managed"))
    names, excluded = merge([obs("api.example.com"), obs("vpn.example.com")],
                            "example.com", scope)
    assert [n.name for n in names] == ["api.example.com"]
    assert len(excluded) == 1
    assert "third-party managed" in excluded[0].reason


def test_a_repo_org_rule_does_not_authorise_dns_discovery():
    """A control, not a detail.

    Measured: with kind=None, ScopeRule.matches falls through to a plain string
    comparison, so a repo_org rule valued 'example.com' resolves INCLUDED for
    the DNS name — a GitHub-org rule authorising DNS discovery. The merge passes
    kind=DOMAIN explicitly.
    """
    scope = scope_with(ScopeRule(kind=ScopeKind.REPO_ORG, value="example.com"))
    assert scope.resolve("example.com").decision is Decision.INCLUDED
    names, _ = merge([obs("example.com")], "example.com", scope)
    assert names[0].decision is Decision.UNSCOPED, \
        "a repo-org rule must not make a DNS name in-scope"


def test_an_unscoped_name_is_kept_because_that_is_a_shadow_asset():
    """Decision.UNSCOPED's own docstring says so, and it is the product's point."""
    names, excluded = merge([obs("forgotten.example.com")], "example.com",
                            Scope())
    assert len(names) == 1
    assert names[0].decision is Decision.UNSCOPED
    assert not excluded


def test_an_excluded_address_blocks_the_name_that_resolves_to_it():
    """The CDN argument justifies not EMITTING addresses as assets; it does not
    justify ignoring an operator who wrote 'never touch this network'."""
    scope = scope_with(WILDCARD,
                       ScopeRule(kind=ScopeKind.CIDR, value="104.18.0.0/16",
                                 is_exclude=True, note="shared CDN"))
    names, excluded = merge([obs("api.example.com", addresses=("104.18.5.7",))],
                            "example.com", scope)
    assert not names
    assert "observed address" in excluded[0].reason


def test_an_address_exclusion_removes_a_name_an_earlier_source_had_admitted():
    """Source order must not decide the outcome."""
    scope = scope_with(WILDCARD,
                       ScopeRule(kind=ScopeKind.CIDR, value="104.18.0.0/16",
                                 is_exclude=True))
    names, excluded = merge([
        obs("api.example.com", source="certspotter"),
        obs("api.example.com", source="mnemonic",
            data_class=DataClass.PASSIVE_DNS, addresses=("104.18.5.7",)),
    ], "example.com", scope)
    assert not names, "the exclusion must win regardless of which source came first"
    assert excluded


# -- dates carry their provenance --------------------------------------------
def test_last_seen_comes_only_from_passive_dns():
    """A crawl timestamp is not a resolution.

    Otherwise a host decommissioned in 2016 with one 2016 crawl gets
    last_seen=2016, which a liveness filter reads as 'resolved until 2016'.
    """
    names, _ = merge([
        obs("old.example.com", source="wayback",
            data_class=DataClass.WEB_ARCHIVE,
            first=date(2016, 3, 2), last=date(2016, 3, 2)),
    ], "example.com", scope_with(WILDCARD))
    assert names[0].last_seen is None
    assert names[0].first_seen == date(2016, 3, 2)
    assert names[0].liveness == "archived-only"


def test_a_passive_dns_sighting_does_set_last_seen():
    names, _ = merge([
        obs("api.example.com", source="mnemonic",
            data_class=DataClass.PASSIVE_DNS,
            first=date(2024, 1, 1), last=date(2026, 8, 1)),
    ], "example.com", scope_with(WILDCARD))
    assert names[0].last_seen == date(2026, 8, 1)
    assert names[0].liveness == "resolved"


def test_a_ct_only_name_has_unknown_liveness():
    """Stated rather than implied. A certificate is not a resolution."""
    names, _ = merge([obs("api.example.com", first=date(2025, 12, 6))],
                     "example.com", scope_with(WILDCARD))
    assert names[0].last_seen is None
    assert names[0].liveness == "unknown"


def test_first_seen_is_the_earliest_across_all_classes():
    names, _ = merge([
        obs("api.example.com", source="certspotter", first=date(2025, 12, 6)),
        obs("api.example.com", source="mnemonic",
            data_class=DataClass.PASSIVE_DNS, first=date(2024, 1, 1)),
    ], "example.com", scope_with(WILDCARD))
    assert names[0].first_seen == date(2024, 1, 1)


# -- provenance --------------------------------------------------------------
def test_the_source_column_names_the_data_class_per_source():
    """A hardcoded 'ct:' prefix would assert certificate provenance for a crawl."""
    names, _ = merge([
        obs("api.example.com", source="certspotter"),
        obs("api.example.com", source="mnemonic",
            data_class=DataClass.PASSIVE_DNS),
    ], "example.com", scope_with(WILDCARD))
    provenance = names[0].provenance
    assert "ct:certspotter" in provenance
    assert "pdns:mnemonic" in provenance


def test_rows_carry_scope_liveness_and_provenance():
    result = DiscoveryResult(
        names=merge([obs("api.example.com", first=date(2025, 1, 1))],
                    "example.com", scope_with(WILDCARD))[0],
        sources=[], apex="example.com")
    row = to_inventory_rows(result)[0]
    assert row["identifier"] == "api.example.com"
    assert row["product"] == "unknown"
    assert row["obs_liveness"] == "unknown"
    assert row["obs_scope"] == "included"
    assert row["source"] == "ct:certspotter"


def test_wildcards_never_become_assets():
    result = DiscoveryResult(
        names=merge([obs("*.example.com"), obs("api.example.com")],
                    "example.com", scope_with(WILDCARD))[0],
        sources=[], apex="example.com")
    rows = to_inventory_rows(result)
    assert [r["identifier"] for r in rows] == ["api.example.com"]


def test_wildcards_and_exclusions_are_counted_separately():
    """The old `len(names) - len(rows)` attributed every absent name to
    wildcards, so a run with 1 wildcard and 2 exclusions printed a confident
    claim about three wildcards that was true of one."""
    scope = scope_with(WILDCARD,
                       ScopeRule(kind=ScopeKind.DOMAIN, value="a.example.com",
                                 is_exclude=True),
                       ScopeRule(kind=ScopeKind.DOMAIN, value="b.example.com",
                                 is_exclude=True))
    names, excluded = merge([obs("*.example.com"), obs("a.example.com"),
                             obs("b.example.com"), obs("ok.example.com")],
                            "example.com", scope)
    result = DiscoveryResult(names=names, sources=[], excluded=excluded,
                             apex="example.com")
    rows = to_inventory_rows(result)
    wildcards = sum(1 for n in result.names if n.is_wildcard)
    assert wildcards == 1
    assert len(result.excluded) == 2
    assert wildcards == len(result.names) - len(rows)


# -- the coverage note -------------------------------------------------------
def test_an_all_unscoped_run_names_the_rule_that_would_fix_it():
    """A DOMAIN rule matches by exact equality, so every subdomain comes back
    unscoped. Correct, but at 400 rows it reads as an alarm."""
    scope = scope_with(ScopeRule(kind=ScopeKind.DOMAIN, value="example.com"))
    names, _ = merge([obs("api.example.com"), obs("shop.example.com")],
                     "example.com", scope)
    result = DiscoveryResult(names=names,
                             sources=[SourceReport("certspotter", Outcome.OK, 2, 2)],
                             apex="example.com")
    note = result.coverage_note(scope)
    assert "scope add example.com --kind wildcard" in note


def test_exclusions_are_stated_in_the_note():
    result = DiscoveryResult(names=[], sources=[SourceReport("x", Outcome.OK)],
                             excluded=[Excluded("vpn.example.com", "excluded")],
                             apex="example.com")
    assert "matched an exclusion" in result.coverage_note()


# -- the registry ------------------------------------------------------------
def test_noncommercial_sources_are_off_unless_the_operator_accepts():
    """SKOPOS may be run commercially and must not make that call for the user."""
    chosen, prereports = registry.enabled(allow_noncommercial=False)
    assert "hackertarget" not in [s.name for s in chosen]
    reasons = {r.name: r for r in prereports}
    assert reasons["hackertarget"].outcome is Outcome.DISABLED

    chosen, _ = registry.enabled(requested=["hackertarget"],
                                 allow_noncommercial=True)
    assert [s.name for s in chosen] == ["hackertarget"]


def test_a_credentialed_source_without_a_key_is_unconfigured_not_failed(monkeypatch):
    monkeypatch.delenv("SKOPOS_OTX_API_KEY", raising=False)
    _, prereports = registry.enabled(requested=["otx"])
    assert prereports[0].outcome is Outcome.UNCONFIGURED
    assert "SKOPOS_OTX_API_KEY" in prereports[0].detail


def test_unconfigured_narrows_but_does_not_degrade(monkeypatch):
    """Otherwise every keyless install is permanently degraded, and a flag that
    is always on is a flag nobody reads."""
    monkeypatch.delenv("SKOPOS_OTX_API_KEY", raising=False)
    _, prereports = registry.enabled(requested=["otx"])
    result = DiscoveryResult(names=[], sources=list(prereports) +
                             [SourceReport("certspotter", Outcome.OK, 3, 3)])
    assert result.narrowed
    assert not result.degraded


def test_prereports_reach_the_result():
    """Dropping them makes an install querying 5 of 7 sources report as fully
    covered."""
    chosen, prereports = registry.enabled()
    assert prereports, "some sources are off by default"
    result = DiscoveryResult(names=[], sources=list(prereports))
    assert len(result.sources) == len(prereports)


def test_wayback_is_off_by_default_with_its_reason():
    source = registry.BY_NAME["wayback"]
    assert not source.default_on
    assert "unsettled" in source.note


def test_an_unknown_source_name_is_reported():
    assert registry.unknown_names(["certspotter", "nope"]) == ["nope"]


def test_every_registered_source_names_a_gate_operation():
    from core import gate
    unknown = [s.name for s in registry.REGISTRY
               if s.operation not in gate.OPERATIONS]
    assert not unknown, unknown


def test_the_terms_table_records_when_it_was_read():
    """A terms field with no review date ages silently into a false claim."""
    assert registry.TERMS_REVIEWED_ON
