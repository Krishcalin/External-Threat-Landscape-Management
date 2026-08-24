"""Entity persistence, and the merge this module refuses to perform.

Most of these tests exist to keep one decision from drifting: that two sources
sharing a name are two entities and a question, never one node. Every CTI
platform does the merge; `docs/REFUSALS.md` §1 is why this one does not.
"""
from __future__ import annotations

import json

import pytest

from collect import stix_ingest as si
from core import entities as ent


def entity(**over):
    base = {"id": "threat-actor--a", "kind": "threat-actor", "name": "Group A",
            "source": "circl", "aliases": []}
    base.update(over)
    return base


def store(*items):
    return ent.EntityStore({"_meta": {"built_on": "2026-08-24"},
                            "entities": list(items)})


# ── the refusal ─────────────────────────────────────────────────────────────
def test_two_sources_sharing_an_alias_are_not_merged():
    """The whole point. A wrong merge is invisible afterwards: the two names
    become one node and the disagreement between sources disappears into a
    consensus that never existed."""
    s = store(entity(id="threat-actor--a", name="UAC-0001", source="circl",
                     aliases=["APT28"]),
              entity(id="intrusion-set--b", kind="intrusion-set", name="APT28",
                     source="partner"))
    assert s.count == 2


def test_the_overlap_is_raised_as_a_question_naming_both_sources():
    s = store(entity(id="a", name="UAC-0001", source="circl", aliases=["APT28"]),
              entity(id="b", name="APT28", source="partner"))
    questions = s.alias_questions()
    assert len(questions) == 1
    payload = questions[0].to_dict()
    assert payload["sources"] == ["circl", "partner"]
    assert "Are they the same group?" in payload["question"]
    assert "attribution judgement" in payload["skopos_will_not_answer"]


def test_one_source_using_a_name_twice_is_not_a_question():
    """That is the source's own business. Only CROSS-source overlap is a
    question for the reader."""
    s = store(entity(id="a", name="X", source="circl"),
              entity(id="b", name="X", source="circl"))
    assert s.alias_questions() == []


def test_a_name_matching_its_own_alias_is_not_a_collision():
    s = store(entity(id="a", name="Group A", source="circl",
                     aliases=["Group A"]))
    assert s.alias_questions() == []


def test_lookup_by_a_shared_name_returns_every_source_record():
    """A reader asking about APT28 must see that two sources disagree about
    what it is, rather than one arbitrarily-chosen answer."""
    s = store(entity(id="a", name="UAC-0001", source="circl", aliases=["APT28"]),
              entity(id="b", kind="intrusion-set", name="APT28",
                     source="partner"))
    got = s.by_name("APT28")
    assert {e.source for e in got} == {"circl", "partner"}


def test_by_id_returns_a_list_because_two_sources_can_publish_one_id():
    """Picking one would be the merge this refuses."""
    s = store(entity(id="shared--1", source="circl", name="A"),
              entity(id="shared--1", source="partner", name="B"))
    assert len(s.by_id("shared--1")) == 2


def test_name_comparison_ignores_case_and_punctuation():
    s = store(entity(id="a", name="APT-28", source="circl"))
    assert s.by_name("apt 28") and s.by_name("APT28")


# ── the question this answers ───────────────────────────────────────────────
def test_an_indicator_resolves_to_what_it_is_part_of():
    s = store(entity(id="threat-actor--t1", name="Fancy Example",
                     source="partner"),
              entity(id="malware--m1", kind="malware", name="Remcos",
                     source="partner"))
    got = s.for_indicator(["threat-actor--t1", "malware--m1"])
    assert [e.name for e in got] == ["Remcos", "Fancy Example"]


def test_resolution_deduplicates_repeated_refs():
    s = store(entity(id="threat-actor--t1", name="A", source="p"))
    assert len(s.for_indicator(["threat-actor--t1"] * 3)) == 1


def test_an_unknown_ref_resolves_to_nothing_rather_than_raising():
    """A bundle may reference an entity a later poll has not yet delivered."""
    assert store(entity()).for_indicator(["threat-actor--missing"]) == []


def test_entities_are_never_correlated_against_an_estate():
    """Parsed, not grepped. A threat actor's name is not something an asset
    can be, and correlating one would raise a finding on any company whose
    hostname contained a group name."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(ent))
    called = {ast.unparse(n.func) for n in ast.walk(tree)
              if isinstance(n, ast.Call)}
    for forbidden in ("correlate", "lookup", "check_address", "check_host"):
        assert not any(forbidden in name for name in called), forbidden
    assert "never matched against an estate" in ent.__doc__


# ── the structural link that makes it work across bundles ───────────────────
def test_an_indicator_carries_entity_ids_not_only_prose():
    """A context string cannot be looked up. The ids are why the answer
    survives the bundle it arrived in."""
    bundle = {"type": "bundle", "objects": [
        {"type": "threat-actor", "id": "threat-actor--t1", "name": "Fancy"},
        {"type": "indicator", "id": "indicator--i1",
         "pattern": "[domain-name:value = 'c2.example']",
         "created": "2026-08-01T00:00:00Z"},
        {"type": "relationship", "id": "relationship--r",
         "source_ref": "indicator--i1", "target_ref": "threat-actor--t1",
         "relationship_type": "indicates"}]}
    found, _ = si.parse_bundle(bundle, source="partner")
    assert found[0]["entity_refs"] == ["threat-actor--t1"]


def test_an_indicator_with_no_entity_carries_no_refs_key():
    """Absent rather than empty: an empty list reads as "we looked and it
    belongs to nothing", which is not what happened."""
    bundle = {"type": "bundle", "objects": [
        {"type": "indicator", "id": "indicator--i1",
         "pattern": "[domain-name:value = 'a.example']",
         "created": "2026-08-01T00:00:00Z"}]}
    found, _ = si.parse_bundle(bundle)
    assert "entity_refs" not in found[0]


def test_extracted_entities_carry_the_source_that_asserted_them():
    bundle = {"type": "bundle", "objects": [
        {"type": "malware", "id": "malware--m", "name": "Remcos"}]}
    assert si.entities(bundle, source="taxii")[0]["source"] == "taxii"


def test_the_round_trip_answers_the_question_across_two_bundles():
    """The end-to-end property: entities arrive in one poll, an indicator
    referencing them in another, and the question is still answerable."""
    first = {"type": "bundle", "objects": [
        {"type": "threat-actor", "id": "threat-actor--t1", "name": "Fancy"}]}
    second = {"type": "bundle", "objects": [
        {"type": "indicator", "id": "indicator--i1",
         "pattern": "[domain-name:value = 'c2.example']",
         "created": "2026-08-01T00:00:00Z"},
        {"type": "threat-actor", "id": "threat-actor--t1", "name": "Fancy"},
        {"type": "relationship", "id": "relationship--r",
         "source_ref": "indicator--i1", "target_ref": "threat-actor--t1",
         "relationship_type": "indicates"}]}

    corpus = ent.merge_corpus(None, si.entities(first, source="taxii"))
    found, _ = si.parse_bundle(second, source="taxii")
    # The indicator's bundle is discarded; only the ids persist.
    resolved = ent.EntityStore(corpus).for_indicator(found[0]["entity_refs"])
    assert [e.name for e in resolved] == ["Fancy"]


# ── corpus merging is about records, never about identities ─────────────────
def test_the_same_source_republishing_an_id_updates_its_own_record():
    first = ent.merge_corpus(None, [entity(id="a", name="Old", source="circl")])
    second = ent.merge_corpus(first, [entity(id="a", name="New", source="circl")])
    assert second["_meta"]["entities"] == 1
    assert second["entities"][0]["name"] == "New"


def test_two_sources_publishing_one_id_keep_two_records():
    corpus = ent.merge_corpus(None, [entity(id="a", source="circl", name="A"),
                                     entity(id="a", source="partner", name="B")])
    assert corpus["_meta"]["entities"] == 2


def test_an_entity_without_a_name_or_id_is_dropped():
    corpus = ent.merge_corpus(None, [entity(name=""), entity(id="")])
    assert corpus["_meta"]["entities"] == 0


def test_the_corpus_states_that_it_never_merges():
    corpus = ent.merge_corpus(None, [entity()])
    assert "never merged" in corpus["_meta"]["never_merged"].lower()


def test_a_missing_corpus_raises_rather_than_answering_nothing():
    """"This indicator is part of nothing" and "there is no corpus" are
    different answers, and only one of them is true."""
    with pytest.raises(ent.EntitiesUnavailable):
        ent.EntityStore.load(ent.ROOT / "data" / "does-not-exist.json")


def test_coverage_reports_the_open_questions():
    s = store(entity(id="a", name="X", source="circl", aliases=["Shared"]),
              entity(id="b", name="Shared", source="partner"))
    report = s.coverage()
    assert report["alias_questions"] == 1
    assert report["by_source"] == {"circl": 1, "partner": 1}
    assert "never matched against an estate" in report["never_correlated"]
