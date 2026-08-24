"""Consuming STIX 2.1, and the handling restrictions that must survive it.

The module this covers is what turns SKOPOS from a STIX *producer* into a STIX
peer. Most of these tests are about the two things a consumer can quietly get
wrong: extracting nothing from a pattern it should have parsed, and stripping a
marking it was given.
"""
from __future__ import annotations

import ast
import inspect
from datetime import date

import pytest

from collect import stix_ingest as si
from core import cti, stix

TODAY = date(2026, 8, 24)

AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"


def bundle(*objects):
    return {"type": "bundle", "id": "bundle--t", "objects": list(objects)}


def indicator(pattern, **over):
    base = {"type": "indicator", "id": "indicator--i1", "pattern": pattern,
            "created": "2026-08-01T00:00:00Z"}
    base.update(over)
    return base


# ── patterns: where the intelligence actually lives ─────────────────────────
@pytest.mark.parametrize("pattern,expected", [
    ("[domain-name:value = 'evil.example.com']", [("domain", "evil.example.com")]),
    ("[ipv4-addr:value = '1.2.3.4']", [("ipv4", "1.2.3.4")]),
    ("[ipv6-addr:value = '2001:db8::1']", [("ipv6", "2001:db8::1")]),
    ("[url:value = 'https://bad.example/x']", [("url", "https://bad.example/x")]),
    ("[email-addr:value = 'a@b.example']", [("email", "a@b.example")]),
])
def test_single_comparison_patterns(pattern, expected):
    assert si.extract_from_pattern(pattern)[0] == expected


def test_a_quoted_hash_path_is_read():
    """`file:hashes.'SHA-256'` is the spec's own spelling, quotes and all."""
    digest = "a" * 64
    got, status = si.extract_from_pattern(f"[file:hashes.'SHA-256' = '{digest}']")
    assert status == "ok" and got == [("sha256", digest)]


def test_an_or_pattern_yields_every_value():
    got, _ = si.extract_from_pattern(
        "[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']")
    assert got == [("ipv4", "1.2.3.4"), ("ipv4", "5.6.7.8")]


def test_a_declared_family_loses_to_the_actual_one():
    """An `ipv4-addr` carrying a v6 literal is a producer error, but the
    half-life must follow the address rather than the label."""
    got, _ = si.extract_from_pattern("[ipv4-addr:value = '2001:db8::9']")
    assert got == [("ipv6", "2001:db8::9")]


def test_behavioural_patterns_are_unsupported_not_unparsed():
    """The two are different failures. SKOPOS holds an external inventory, not
    telemetry, so it could never evaluate "three times in five minutes" — that
    is a statement about this product's inputs, not a gap in the parser."""
    _, status = si.extract_from_pattern(
        "[network-traffic:dst_port = 443] REPEATS 3 TIMES")
    assert status == "unsupported"


@pytest.mark.parametrize("pattern", [
    "[process:name != 'x']", "[file:size > 1024]", "garbage", ""])
def test_patterns_carrying_no_correlatable_value_are_unparsed(pattern):
    assert si.extract_from_pattern(pattern)[1] == "unparsed"


def test_what_failed_to_parse_is_sampled_not_only_counted():
    """A count alone cannot be acted on. An operator needs to see WHAT was
    dropped to decide whether the parser or the feed is wrong."""
    _, report = si.parse_bundle(bundle(indicator("[process:name != 'x']")))
    assert report.unparsed_pattern == 1
    assert report.to_dict()["sample_unparsed_patterns"] == ["[process:name != 'x']"]


# ── markings: the mistake with a consequence outside the software ───────────
def test_tlp_resolves_through_a_marking_definition_object():
    """MISP writes `tlp:amber` as a string; STIX writes an object and points at
    it. A consumer that ignores the ref silently strips every restriction."""
    payload = bundle(
        {"type": "marking-definition", "id": "marking-definition--m1",
         "definition": {"tlp": "amber"}},
        indicator("[domain-name:value = 'a.example']",
                  object_marking_refs=["marking-definition--m1"]))
    found, _ = si.parse_bundle(payload)
    assert found[0]["tlp"] == "AMBER"
    assert cti.exportable(found[0]["tlp"]) is False


def test_the_specifications_standard_tlp_ids_resolve_without_being_defined():
    """A bundle may reference the six standard markings without defining them.
    A consumer resolving only local definitions would treat those as unmarked."""
    found, _ = si.parse_bundle(bundle(
        indicator("[domain-name:value = 'a.example']",
                  object_marking_refs=[AMBER])))
    assert found[0]["tlp"] == "AMBER"


def test_the_most_restrictive_marking_wins():
    """An object carrying both GREEN and AMBER is AMBER. Taking the first
    would leak it."""
    payload = bundle(
        {"type": "marking-definition", "id": "marking-definition--g",
         "definition": {"tlp": "green"}},
        indicator("[domain-name:value = 'a.example']",
                  object_marking_refs=["marking-definition--g", AMBER]))
    assert si.parse_bundle(payload)[0][0]["tlp"] == "AMBER"


def test_an_unresolvable_marking_is_treated_as_red():
    """A restriction this consumer was given and cannot read is still a
    restriction. RED is the direction that cannot leak something."""
    found, _ = si.parse_bundle(bundle(
        indicator("[domain-name:value = 'a.example']",
                  object_marking_refs=["marking-definition--unknown"])))
    assert found[0]["tlp"] == "RED"
    assert cti.exportable(found[0]["tlp"]) is False


# ── provenance and lifecycle ────────────────────────────────────────────────
def test_valid_from_beats_created():
    """`created` is when the record was written; `valid_from` is when the
    intelligence begins to apply. Decay must run from the latter."""
    found, _ = si.parse_bundle(bundle(indicator(
        "[domain-name:value = 'a.example']",
        created="2026-01-01T00:00:00Z", valid_from="2026-08-01T00:00:00Z")))
    assert found[0]["seen_on"] == "2026-08-01"


def test_a_revoked_indicator_is_dropped():
    """Ingesting one would resurrect a claim its author has retracted."""
    found, report = si.parse_bundle(bundle(indicator(
        "[domain-name:value = 'a.example']", revoked=True)))
    assert found == [] and report.revoked == 1


def test_the_authors_confidence_is_carried_as_theirs():
    found, _ = si.parse_bundle(bundle(indicator(
        "[domain-name:value = 'a.example']", confidence=80)))
    assert found[0]["source_confidence"] == 80


def test_created_by_ref_resolves_to_a_named_reporter():
    payload = bundle(
        {"type": "identity", "id": "identity--1", "name": "Acme CTI"},
        indicator("[domain-name:value = 'a.example']",
                  created_by_ref="identity--1"))
    assert si.parse_bundle(payload)[0][0]["reporter"] == "Acme CTI"


# ── attribution: carried, never inferred ────────────────────────────────────
def test_an_actor_is_resolved_through_the_relationship_the_author_published():
    """THE ATTRIBUTION §1 PERMITS. SKOPOS is not inferring that this indicator
    belongs to an actor — the bundle's author said so in a relationship object
    they signed, and this repeats it with their name attached."""
    payload = bundle(
        {"type": "threat-actor", "id": "threat-actor--ta1",
         "name": "Fancy Example"},
        indicator("[domain-name:value = 'c2.example']"),
        {"type": "relationship", "id": "relationship--r", "source_ref":
         "indicator--i1", "target_ref": "threat-actor--ta1",
         "relationship_type": "indicates"})
    found, _ = si.parse_bundle(payload)
    assert found[0]["context"] == "Fancy Example (threat-actor)"


def test_entities_are_extracted_separately_from_indicators():
    """Entities must never be correlated against an estate — a threat actor's
    NAME is not something an asset can match."""
    payload = bundle(
        {"type": "identity", "id": "identity--1", "name": "Acme CTI"},
        {"type": "malware", "id": "malware--m", "name": "Remcos",
         "aliases": ["RemcosRAT"], "created_by_ref": "identity--1"})
    found, _ = si.parse_bundle(payload)
    assert found == []
    entity = si.entities(payload)[0]
    assert entity["name"] == "Remcos" and entity["kind"] == "malware"
    assert entity["asserted_by"] == "Acme CTI"


# ── observables and shape ───────────────────────────────────────────────────
def test_bare_observables_are_read_directly():
    found, report = si.parse_bundle(bundle(
        {"type": "domain-name", "id": "domain-name--d", "value": "a.example"}))
    assert found[0]["kind"] == "domain" and report.observables == 1


def test_a_file_observable_yields_every_hash_it_carries():
    found, _ = si.parse_bundle(bundle(
        {"type": "file", "id": "file--f",
         "hashes": {"MD5": "b" * 32, "SHA-256": "c" * 64}}))
    assert {f["kind"] for f in found} == {"md5", "sha256"}


def test_a_document_without_an_objects_list_raises():
    """A STIX bundle without one is not an empty bundle, it is a different
    document — and an empty result would silently replace a good corpus."""
    with pytest.raises(si.BundleMalformed):
        si.parse_bundle({"type": "bundle"})
    with pytest.raises(si.BundleMalformed):
        si.parse_bundle(b"<html>nope</html>")


def test_a_skopos_bundle_round_trips():
    """The producer and the consumer are the same codebase; they should agree.
    The SDOs are correctly NOT indicators — an infrastructure object is an
    asset, not something to correlate against one."""
    payload = stix.bundle([{
        "asset": "api.example.com", "cve": "CVE-2021-44228", "product": "Log4j",
        "version": "2.14.1", "basis": "version_range", "teps": 91.0,
        "band": "critical", "evidence": ["x"], "addresses": ["198.51.100.21"],
        "ownership_verified_on": "2026-06-01"}], org="acme")
    found, _ = si.parse_bundle(payload)
    assert {f["value"] for f in found} == {"api.example.com", "198.51.100.21"}


def test_the_parser_performs_no_network_io():
    """Parsed, not grepped — the module names URLs in its docstring."""
    tree = ast.parse(inspect.getsource(si))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    for banned in ("urllib", "http", "socket", "requests", "httpx",
                   "subprocess", "ssl"):
        assert banned not in imported


# ── promotion: sightings become findings ────────────────────────────────────
def _corpus(*items):
    return cti.CTICorpus({"_meta": {"built_on": "2026-08-24"},
                          "indicators": list(items)})


def test_a_bare_sighting_fires_the_listing_rule():
    store = _corpus({"value": "a.example", "kind": "domain",
                     "source": "threatfox", "publisher": "abuse.ch",
                     "seen_on": "2026-08-20", "context": "Remcos"})
    found = cti.findings(store.correlate(["a.example"], TODAY), TODAY)
    assert found[0]["rule"] == "cti.asset_in_intelligence"
    assert found[0]["actor"] is None


def test_an_attributed_sighting_fires_the_actor_rule():
    store = _corpus({"value": "a.example", "kind": "domain",
                     "source": "partner", "publisher": "Acme",
                     "seen_on": "2026-08-20",
                     "context": "Fancy Example (threat-actor)"})
    found = cti.findings(store.correlate(["a.example"], TODAY), TODAY)
    assert found[0]["rule"] == "cti.asset_named_by_actor_report"
    assert found[0]["actor"] == "Fancy Example (threat-actor)"


def test_every_promoted_finding_carries_its_rules_limits():
    """The caveat must not be left behind in the console."""
    store = _corpus({"value": "a.example", "kind": "domain",
                     "source": "threatfox", "publisher": "abuse.ch",
                     "seen_on": "2026-08-20", "context": "x"})
    found = cti.findings(store.correlate(["a.example"], TODAY), TODAY)[0]
    assert "NOT that the asset is compromised" in found["limits"]
    assert len(found["not"]) == 4


def test_the_intel_weight_feeding_teps_is_already_decayed():
    """So a 2016 listing contributes nothing without a special case anywhere
    downstream."""
    from core import scoring
    store = _corpus({"value": "a.example", "kind": "ipv4",
                     "source": "threatfox", "publisher": "abuse.ch",
                     "seen_on": "2026-08-24", "context": "x"})
    weight = cti.highest_weight(store.correlate(["a.example"], TODAY), TODAY)
    assert weight == 1.0
    assert scoring.AdversaryInterest.from_catalogue(
        False, weight).observed_in_intel == 1.0


def test_a_score_with_no_sighting_is_unchanged_from_the_previous_model():
    """The version bump must not move a score that has no CTI behind it."""
    from core import scoring
    assert scoring.AdversaryInterest.from_catalogue(False, 0.0).value() == 0.0


def test_redundant_sources_do_not_stack():
    """Three sources repeating one vendor's list is not three times the
    evidence. Summing would reward a corpus built by aggregating aggregators."""
    store = _corpus(
        {"value": "a.example", "kind": "domain", "source": "threatfox",
         "publisher": "abuse.ch", "seen_on": "2026-08-24", "context": "x"},
        {"value": "a.example", "kind": "domain", "source": "circl_osint",
         "publisher": "CIRCL", "seen_on": "2026-08-24", "context": "y"})
    assert cti.highest_weight(store.correlate(["a.example"], TODAY), TODAY) == 1.0


def test_a_stale_corpus_raises_a_coverage_finding_about_skopos():
    """So a reader does not mistake a stale corpus for a quiet estate."""
    stale = cti.CTICorpus({"_meta": {"built_on": "2026-06-01"},
                           "indicators": []})
    finding = cti.corpus_age_finding(stale, TODAY)
    assert finding["rule"] == "cti.stale_corpus"
    assert finding["age_days"] == 84


def test_a_fresh_corpus_raises_no_coverage_finding():
    fresh = cti.CTICorpus({"_meta": {"built_on": "2026-08-24"},
                           "indicators": []})
    assert cti.corpus_age_finding(fresh, TODAY) is None
