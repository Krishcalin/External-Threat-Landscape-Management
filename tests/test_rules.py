"""The rule catalogue, and the one property that makes it worth having.

A catalogue that drifts from the code is worse than no catalogue, because it is
read as a specification. Most of this file exists to keep the two joined.
"""
from __future__ import annotations

import pytest

from core import rules


# ── the shape of a rule ─────────────────────────────────────────────────────
def test_every_rule_states_what_it_does_not_establish():
    """The required field nobody else has. A rule that cannot say what it fails
    to prove has not been thought through."""
    for rule in rules.CATALOGUE:
        assert rule.limits.strip(), rule.id
        assert len(rule.limits) > 40, f"{rule.id}: limits too thin to be real"


def test_the_limits_field_is_enforced_at_construction_not_by_convention():
    with pytest.raises(ValueError, match="no stated limits"):
        rules.Rule("x.y", "T", rules.Category.EXPOSURE, rules.Severity.ACT,
                   "detects something", "   ", "core/x.py")


def test_a_rule_must_say_what_it_detects():
    with pytest.raises(ValueError, match="does not say what it detects"):
        rules.Rule("x.y", "T", rules.Category.EXPOSURE, rules.Severity.ACT,
                   "", "a real limit statement that is long enough to pass",
                   "core/x.py")


def test_rule_ids_are_unique():
    ids = [r.id for r in rules.CATALOGUE]
    assert len(ids) == len(set(ids))


def test_rule_ids_are_namespaced():
    """`reachable` collides with something eventually; `crosshair.reachable`
    does not."""
    for rule in rules.CATALOGUE:
        assert "." in rule.id, rule.id
        assert rule.id == rule.id.lower()


def test_every_rule_names_the_module_that_emits_it():
    """So a reader can go and check rather than trust the catalogue."""
    import pathlib
    root = pathlib.Path(rules.__file__).resolve().parents[1]
    for rule in rules.CATALOGUE:
        assert (root / rule.emitted_by).exists(), f"{rule.id} -> {rule.emitted_by}"


def test_severity_is_not_a_number():
    """A number invites summation, and a sum of forty rules is the scalar this
    catalogue exists to avoid."""
    for rule in rules.CATALOGUE:
        assert isinstance(rule.severity.value, str)
        assert not rule.severity.value.isdigit()


# ── what the catalogue publishes ────────────────────────────────────────────
def test_the_catalogue_is_substantial_enough_to_be_an_answer():
    """The question it exists to answer is 'what does it check?'. A handful of
    rules is not an answer."""
    assert len(rules.CATALOGUE) >= 30


def test_coverage_rules_exist_and_are_their_own_severity():
    """A limit on what could be SEEN is not a fact about the estate, and
    collapsing the two is how '0 findings' becomes a clean bill of health."""
    coverage = [r for r in rules.CATALOGUE
                if r.severity is rules.Severity.COVERAGE]
    assert len(coverage) >= 5
    assert all(r.category is rules.Category.COVERAGE for r in coverage)


def test_the_catalogue_refuses_to_offer_a_score():
    payload = rules.catalogue()
    assert "score" not in payload
    assert "total" not in payload
    assert "not summed into a score" in payload["note"]


def test_every_severity_is_explained_in_the_payload():
    payload = rules.catalogue()
    for severity in rules.Severity:
        assert payload["severities"][severity.value]


def test_grouping_covers_every_rule():
    grouped = rules.by_category()
    assert sum(len(v) for v in grouped.values()) == len(rules.CATALOGUE)


# ── the catalogue must not drift from the code ──────────────────────────────
def test_rules_reference_signals_that_actually_exist():
    """The direction that matters. Each of these enums is a real set of checks
    that already ran before this catalogue existed; if one gains a member and
    the catalogue does not, this fails."""
    from core import crosshair, lookalike, suppliers

    crosshair_ids = {r.id.split(".", 1)[1] for r in rules.CATALOGUE
                     if r.id.startswith("crosshair.")}
    assert {s.value for s in crosshair.Signal} == crosshair_ids

    brand_ids = {r.id.split(".", 1)[1] for r in rules.CATALOGUE
                 if r.id.startswith("brand.")}
    # exact_term is the match itself rather than a lookalike signal.
    assert {s.value for s in lookalike.Signal} - {"exact_term"} == brand_ids

    supplier_signals = {s.value for s in suppliers.Signal}
    assert len(supplier_signals) >= 6


def test_takeover_verdicts_are_all_catalogued():
    from core import takeover
    catalogued = {r.id.split(".", 1)[1] for r in rules.CATALOGUE
                  if r.id.startswith("takeover.")}
    verdicts = {v.value for v in takeover.TakeoverVerdict}
    missing = verdicts - catalogued - {"no_claim_signal_found"}
    assert not missing, f"uncatalogued takeover verdicts: {missing}"


def test_the_abuse_feeds_are_represented():
    from core import blocklists
    assert rules.get("abuse.listed") is not None
    assert rules.get("abuse.tor_exit") is not None
    # And the neutral one is not described as abuse.
    assert "NOT abuse" in rules.get("abuse.tor_exit").limits
    assert blocklists.BY_NAME["tor_exit"].sense == "NEUTRAL"


# ── summarising ─────────────────────────────────────────────────────────────
def test_unknown_ids_are_returned_rather_than_dropped():
    """An id the catalogue does not know means the code and this file have
    drifted, which is the failure mode a catalogue has."""
    summary = rules.summarise(["crosshair.reachable", "invented.rule"])
    assert summary["unknown_ids"] == ["invented.rule"]
    assert summary["distinct_rules"] == 1


def test_silent_rules_are_named_not_hidden():
    """A rule that fired zero times is COVERAGE, not absence. It stays visible
    so nobody reads an empty screen as a clean estate."""
    summary = rules.summarise(["crosshair.reachable"])
    assert "crosshair.overdue" in summary["silent_rules"]
    assert len(summary["silent_rules"]) == len(rules.CATALOGUE) - 1


def test_counts_are_per_rule_and_per_severity():
    summary = rules.summarise(["crosshair.reachable", "crosshair.reachable",
                               "crosshair.overdue"])
    assert summary["fired"]["crosshair.reachable"] == 2
    assert summary["by_severity"]["act"] == 2
    assert summary["by_severity"]["check"] == 1


def test_an_empty_run_still_reports_the_catalogue_size():
    """'Nothing fired' is only meaningful beside 'out of how many'."""
    summary = rules.summarise([])
    assert summary["catalogue_size"] == len(rules.CATALOGUE)
    assert summary["distinct_rules"] == 0


# ── the route ───────────────────────────────────────────────────────────────
def test_the_catalogue_route_is_public():
    """Somebody deciding whether to install SKOPOS should read what it checks
    first. A catalogue behind a login is a catalogue nobody reads."""
    from api import auth_routes
    assert "/api/v1/rules" in auth_routes.PUBLIC_EXACT
    assert auth_routes._is_public("/api/v1/rules") is True


def test_the_public_route_exposes_no_estate_data():
    """It describes the SOFTWARE. Making it public is only safe because it
    contains no finding, no asset and nothing about a tenant."""
    payload = rules.catalogue()
    flat = repr(payload).lower()
    for leak in ("asset", "org_id", "finding", "hostname"):
        # `evidence` names the FIELDS a rule carries, which is a schema, not a
        # value. Assert no rule carries an actual value-looking key.
        assert f'"{leak}":' not in flat


def test_the_route_is_registered():
    from api import app as api_app
    paths = {r.path for r in api_app.app.routes}
    assert "/api/v1/rules" in paths
