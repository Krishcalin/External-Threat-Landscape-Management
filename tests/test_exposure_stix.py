"""The exposure export — the half of SKOPOS that is not a CVE finding.

The property that matters throughout: every non-CVE observation carries the
stated limits of the rule that produced it. `core/rules.py` makes that field
mandatory, so a note here cannot be written without its caveat — the caveat is
enforced upstream rather than remembered downstream.
"""
from __future__ import annotations

import json

import pytest

from core import rules, stix

ROW = {
    "asset": "legacy.example.com",
    "addresses": ["198.51.100.9"],
    "asn": {"number": 64500, "name": "EXAMPLE-AS"},
    "certificates": [{"serial": "0A1B2C", "issuer": "Let's Encrypt",
                      "not_before": "2025-01-01", "not_after": "2026-01-01",
                      "rules": ["cert.expired"]}],
    "takeover": {"verdict": "registrable_domain_unregistered",
                 "target": "gone.example.net",
                 "reasons": ["RDAP reports the registrable domain unregistered"]},
    "abuse": [{"feed": "urlhaus", "publisher": "abuse.ch", "sense": "ABUSE",
               "data_age_days": 0}],
    "leak_listings": [{"group": "kazu", "published": "2026-08-20",
                       "confidence": "domain"}],
    "ownership_verified_on": "2026-06-01",
}


def kinds(bundle):
    out = {}
    for obj in bundle["objects"]:
        out[obj["type"]] = out.get(obj["type"], 0) + 1
    return out


# ── the two observables R1 built and never called ───────────────────────────
def test_the_certificate_observable_is_actually_emitted():
    """`x509_certificate` shipped in R1 with no caller — an orphan, and this
    codebase has a phase document about that failure mode."""
    bundle = stix.exposure_bundle([ROW], org="acme")
    assert kinds(bundle).get("x509-certificate") == 1


def test_the_autonomous_system_observable_is_actually_emitted():
    bundle = stix.exposure_bundle([ROW], org="acme")
    assert kinds(bundle).get("autonomous-system") == 1


def test_every_observable_builder_has_a_caller_now():
    """The audit that would have caught this before it shipped."""
    import inspect
    source = inspect.getsource(stix)
    body = source.split("def exposure_bundle", 1)[1]
    for builder in ("x509_certificate(", "autonomous_system(", "domain_name(",
                    "ip_address(", "composed_of(", "resolves_to("):
        assert builder in body, builder


# ── resolves-to, the edge OpenCTI drops ─────────────────────────────────────
def test_a_name_resolving_to_an_address_emits_resolves_to():
    """OpenCTI's own STIX importer is documented as failing to import
    domain-to-IPv4 `resolves_to_refs` — issue #6928, open two years. Emitting
    the edge explicitly is a join a consumer cannot make for itself."""
    bundle = stix.exposure_bundle([ROW], org="acme")
    edges = [o for o in bundle["objects"]
             if o.get("relationship_type") == "resolves-to"]
    assert edges


def test_an_address_asset_does_not_resolve_to_itself():
    """An asset that IS an address has nothing to resolve."""
    row = {"asset": "198.51.100.9", "addresses": ["198.51.100.9"]}
    bundle = stix.exposure_bundle([row], org="acme")
    assert not [o for o in bundle["objects"]
                if o.get("relationship_type") == "resolves-to"]


def test_a_dangling_delegation_records_where_it_points():
    """Where it points is a FACT, emitted separately from any verdict about
    whether anybody could claim it."""
    bundle = stix.exposure_bundle([ROW], org="acme")
    targets = [o for o in bundle["objects"]
               if o["type"] == "domain-name" and o["value"] == "gone.example.net"]
    assert targets


# ── every note carries its rule's limits ────────────────────────────────────
def test_every_observation_note_states_what_it_does_not_mean():
    """The property this export exists to have."""
    bundle = stix.exposure_bundle([ROW], org="acme")
    notes = [o for o in bundle["objects"]
             if o["type"] == "note" and o.get("labels")]
    assert len(notes) >= 4
    for note in notes:
        assert "THIS DOES NOT MEAN:" in note["content"]
        assert "OBSERVED:" in note["content"]


def test_a_note_is_labelled_with_its_rule_and_severity():
    """So a consumer can filter without parsing prose."""
    bundle = stix.exposure_bundle([ROW], org="acme")
    note = next(o for o in bundle["objects"]
                if o["type"] == "note" and o.get("labels"))
    assert any(l.startswith("skopos-rule:") for l in note["labels"])
    assert any(l.startswith("skopos-severity:") for l in note["labels"])


def test_a_note_points_at_the_catalogue():
    bundle = stix.exposure_bundle([ROW], org="acme")
    note = next(o for o in bundle["objects"]
                if o["type"] == "note" and o.get("labels"))
    assert "/api/v1/rules" in note["content"]


def test_every_rule_id_used_here_exists_in_the_catalogue():
    bundle = stix.exposure_bundle([ROW], org="acme")
    for note in bundle["objects"]:
        for label in note.get("labels", []):
            if label.startswith("skopos-rule:"):
                assert rules.get(label.split(":", 1)[1]) is not None, label


def test_an_unknown_rule_is_counted_rather_than_silently_skipped():
    """A rule id the catalogue does not know means the code and core/rules.py
    have drifted — the one failure a catalogue actually has."""
    row = dict(ROW, takeover={"verdict": "invented_verdict", "target": "x.example",
                              "reasons": ["because"]})
    bundle = stix.exposure_bundle([row], org="acme")
    assert bundle.get("x_skopos_unknown_rules", 0) >= 1


def test_a_note_is_not_an_indicator_or_a_sighting():
    """An indicator is a detection pattern and these are not patterns. A
    sighting asserts an indicator was seen, importing a claim about malice most
    of these rules explicitly refuse."""
    bundle = stix.exposure_bundle([ROW], org="acme")
    assert "indicator" not in kinds(bundle)
    assert "sighting" not in kinds(bundle)


# ── the neutral case ────────────────────────────────────────────────────────
def test_a_tor_exit_uses_the_neutral_rule():
    """Running an exit relay is legal and often admirable. Scoring it as abuse
    would be a political claim this product has no basis for."""
    row = {"asset": "relay.example.com",
           "abuse": [{"feed": "tor_exit", "publisher": "The Tor Project",
                      "sense": "NEUTRAL", "data_age_days": 0}]}
    bundle = stix.exposure_bundle([row], org="acme")
    note = next(o for o in bundle["objects"]
                if o["type"] == "note" and o.get("labels"))
    assert "skopos-rule:abuse.tor_exit" in note["labels"]
    assert "NOT abuse" in note["content"]


# ── the ordinary properties ─────────────────────────────────────────────────
def test_an_asset_with_nothing_but_a_name_still_exports():
    """A name is a fact worth exporting on its own."""
    bundle = stix.exposure_bundle([{"asset": "bare.example.com"}], org="acme")
    assert kinds(bundle).get("domain-name") == 1
    assert kinds(bundle).get("infrastructure") == 1


def test_a_row_with_no_asset_is_skipped():
    assert stix.exposure_bundle([{"addresses": ["1.2.3.4"]}], org="a")["objects"] == []


def test_an_empty_estate_produces_an_empty_bundle():
    bundle = stix.exposure_bundle([], org="acme")
    assert bundle["objects"] == []
    assert bundle["type"] == "bundle"


def test_the_ownership_edge_appears_here_too():
    bundle = stix.exposure_bundle([ROW], org="acme")
    assert any(o.get("relationship_type") == "belongs-to"
               for o in bundle["objects"])


def test_re_exporting_is_deterministic():
    stamp = "2026-01-01T00:00:00.000Z"
    first = stix.exposure_bundle([ROW], created=stamp, org="acme")
    again = stix.exposure_bundle([ROW], created=stamp, org="acme")
    assert json.dumps(first) == json.dumps(again)


def test_the_refusals_travel_with_an_exposure_bundle():
    """A consumer given assets with no statement of what this product declines
    would read the absences as oversights."""
    bundle = stix.exposure_bundle([ROW], org="acme")
    content = " ".join(o.get("content", "") for o in bundle["objects"])
    assert "STATED REFUSALS" in content
    assert "ACCURACY" in content


def test_two_tenants_do_not_collide_here_either():
    a = stix.exposure_bundle([ROW], org="acme")["objects"][0]["id"]
    b = stix.exposure_bundle([ROW], org="other")["objects"][0]["id"]
    assert a != b


# ── the route ───────────────────────────────────────────────────────────────
def test_the_export_route_is_registered():
    from api import app as api_app
    assert "/api/v1/export/stix/exposure" in {r.path for r in api_app.app.routes}


def test_the_route_states_what_it_could_not_include():
    """Certificate posture, abuse membership and leak listings are computed per
    lookup and not persisted per asset. A thin bundle with no explanation reads
    as an estate with none of those problems."""
    # Asserted against the RETURNED PAYLOAD, not the source text. Two earlier
    # versions of this test grepped the source and failed on string
    # concatenation across lines rather than on the sentence being absent —
    # which is a test measuring formatting, not behaviour.
    from api import app as api_app
    payload = api_app.export_exposure_stix(limit=1)
    assert "not_included" in payload
    assert "not a statement that the estate is free of them" in (
        payload["not_included"])


def test_the_route_reports_which_sources_were_present():
    """So a caller can tell an empty estate from an unreachable store."""
    from api import app as api_app
    payload = api_app.export_exposure_stix(limit=1)
    assert set(payload["sources_present"]) == {"dns", "takeover"}
    assert payload["objects"] == len(payload["bundle"]["objects"])


# ── referential integrity ───────────────────────────────────────────────────
@pytest.mark.parametrize("org", ["", "acme"])
def test_every_reference_resolves_inside_the_exposure_bundle(org):
    """The companion to the same check on `bundle()`, which did NOT hold.

    This path escaped that bug by capturing `emit(infrastructure(...))`'s
    return value instead of recomputing the id from a second copy of the
    formula. The check is here so that stays an invariant rather than a
    happy accident — a live OpenCTI rejects a dangling reference outright
    with MISSING_REFERENCE_ERROR, and drops the edge silently otherwise.
    """
    payload = stix.exposure_bundle([ROW], org=org)
    present = {o["id"] for o in payload["objects"]}
    dangling = []
    for obj in payload["objects"]:
        if obj["type"] == "relationship":
            for field in ("source_ref", "target_ref"):
                if obj[field] not in present:
                    dangling.append((obj["relationship_type"], field, obj[field]))
        for ref in obj.get("object_refs") or []:
            if ref not in present:
                dangling.append((obj["type"], "object_refs", ref))
    assert dangling == [], f"references to objects not in the bundle: {dangling}"
