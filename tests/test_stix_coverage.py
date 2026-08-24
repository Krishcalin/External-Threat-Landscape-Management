"""W6 STIX export and W7 coverage feeds.

Both workstreams risk the same failure in different ways: STIX by exporting a
worklist entry as an assertion, coverage by blending advisories into the
exploited list. The tests are mostly about those two things not happening.
"""
from __future__ import annotations

import json

import pytest

from core import coverage, stix
from core.coverage import (Advisory, AdvisorySource, Catalogue,
                           CoordinatesMissing, CoverageResult, PackageRef,
                           package_ref, partition)
from core.models import Asset


def finding(basis="product_match", evidence=None, **extra):
    row = {"asset": "vpn.example.com", "product": "Connect Secure",
           "cve": "CVE-2024-21887", "band": "critical", "teps": 88,
           "basis": basis, "evidence": evidence or ["product names correspond"]}
    row.update(extra)
    return row


# ── W6: STIX must not overstate ─────────────────────────────────────────────
def test_a_determination_exports_as_has_with_high_confidence():
    rel = stix.relationship(finding(basis="version_range"))
    assert rel["relationship_type"] == "has"
    assert rel["confidence"] == stix.CONFIDENCE_DETERMINATION


def test_a_worklist_entry_does_not_export_as_has():
    """The whole risk of a STIX export: handing a SIEM assertions this product
    spent its design refusing to make."""
    rel = stix.relationship(finding(basis="product_match"))
    assert rel["relationship_type"] == "related-to"
    assert rel["confidence"] == stix.CONFIDENCE_WORKLIST
    assert "NOT an assertion that the asset is vulnerable" in rel["description"]


def test_a_siem_rule_keyed_on_has_fires_only_on_determinations():
    rows = [finding(basis="product_match", cve="CVE-1"),
            finding(basis="version_range", cve="CVE-2")]
    bundle = stix.bundle(rows)
    has = [o for o in bundle["objects"]
           if o["type"] == "relationship" and o["relationship_type"] == "has"]
    assert [o["target_ref"] for o in has] == [stix._id("vulnerability", "CVE-2")]


def test_a_retired_finding_is_exported_so_it_can_be_withdrawn():
    """Omitting it leaves the downstream system believing something this
    product has since decided is false."""
    rel = stix.relationship(finding(
        basis="version_range",
        evidence=["RETIRED: version 9.9 falls outside every published range"]))
    assert rel["confidence"] == 5
    assert rel["description"].startswith("RETIRED")


def test_the_bundle_carries_the_caveat():
    bundle = stix.bundle([finding()])
    notes = [o for o in bundle["objects"] if o["type"] == "note"]
    assert notes
    assert "WORKLIST ENTRIES" in notes[0]["content"]


def test_ids_are_deterministic_so_a_consumer_can_deduplicate():
    """Random ids would make every re-export a set of new objects, and every
    consumer would accumulate duplicates forever."""
    first = stix.bundle([finding()], created="2026-01-01T00:00:00.000Z")
    second = stix.bundle([finding()], created="2026-06-01T00:00:00.000Z")
    ids = lambda b: sorted(o["id"] for o in b["objects"])
    assert ids(first) == ids(second)


def test_a_row_missing_half_the_pairing_is_skipped():
    """Inventing an anonymous endpoint would put an object in the graph that
    corresponds to nothing."""
    bundle = stix.bundle([{"asset": "", "cve": "CVE-1"},
                          {"asset": "a.example.com", "cve": ""}])
    assert bundle["objects"] == []


def test_repeated_assets_and_cves_appear_once_each():
    bundle = stix.bundle([finding(cve="CVE-1"), finding(cve="CVE-2")])
    infra = [o for o in bundle["objects"] if o["type"] == "infrastructure"]
    vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
    assert len(infra) == 1 and len(vulns) == 2


def test_the_bundle_is_valid_json_and_declares_its_spec_version():
    parsed = json.loads(stix.to_json([finding()]))
    assert parsed["type"] == "bundle"
    assert all(o.get("spec_version") == "2.1" for o in parsed["objects"])


def test_non_standard_properties_are_prefixed():
    rel = stix.relationship(finding())
    extra = [k for k in rel if k.startswith("x_")]
    assert "x_skopos_basis" in extra
    assert all(k.startswith("x_skopos_") for k in extra)


# ── W7: advisories must stay apart from exploited findings ──────────────────
def test_an_advisory_is_a_different_type_from_an_exposure():
    """Structural separation, not a flag. They cannot enter one list by
    accident, and engine.rank() will not take an advisory."""
    from core.models import Exposure
    advisory = Advisory(source=AdvisorySource.OSV, identifier="GHSA-x",
                        asset="a.example.com")
    assert not isinstance(advisory, Exposure)
    assert advisory.catalogue is Catalogue.ADVISORY


def test_the_advisory_catalogue_says_it_claims_nothing_about_exploitation():
    text = coverage.CATALOGUE_MEANING[Catalogue.ADVISORY.value]
    assert "NOTHING here says anyone is exploiting it" in text


def test_severity_is_never_read_as_exploitation():
    """A high CVSS is not evidence that anyone is exploiting anything."""
    advisory = Advisory(source=AdvisorySource.OSV, identifier="GHSA-x",
                        asset="a.example.com", severity=9.8)
    assert advisory.exploited_per_source is False


def test_a_product_name_is_not_treated_as_a_package_name():
    """Measured: a bare product name returns 0 from OSV. Guessing a mapping
    would be inventing a fact about the customer's estate."""
    asset = Asset(identifier="web.example.com", product="Apache HTTP Server",
                  version="2.4.54")
    assert package_ref(asset) is None


def test_operator_supplied_coordinates_are_used():
    asset = Asset(identifier="app.example.com", product="whatever",
                  version="2.14.1",
                  attributes={"package": "log4j-core", "ecosystem": "Maven"})
    ref = package_ref(asset)
    assert ref.queryable and ref.ecosystem == "Maven"


def test_coordinates_without_an_ecosystem_are_not_queryable():
    """Measured: without an ecosystem even a correct package name returns
    nothing, so such a query cannot succeed."""
    assert not PackageRef(name="log4j-core").queryable


def test_an_asset_that_cannot_be_looked_up_is_named_not_counted_as_clean():
    result = CoverageResult(without_coordinates=["a.example.com",
                                                 "b.example.com"])
    note = result.note()
    assert "COULD NOT BE LOOKED UP" in note
    assert "coverage gap and not a clean result" in note


def test_the_note_always_repeats_that_nothing_here_is_exploitation():
    result = CoverageResult(advisories=[
        Advisory(source=AdvisorySource.OSV, identifier="GHSA-x",
                 asset="a.example.com")])
    assert "NONE of these is a statement that anyone is exploiting" in result.note()


def test_an_advisory_already_in_kev_is_not_double_counted():
    """The same vulnerability arriving by a second route would inflate the
    estate's apparent problem count."""
    rows = [Advisory(AdvisorySource.OSV, "GHSA-a", "h", cve="CVE-1"),
            Advisory(AdvisorySource.OSV, "GHSA-b", "h", cve="CVE-2")]
    split = partition(rows, {"CVE-1"})
    assert len(split["already_exploited"]) == 1
    assert [a.cve for a in split["advisory_only"]] == ["CVE-2"]


def test_advisory_lookup_is_a_registered_passive_operation():
    from core import gate
    assert gate.classify("advisory_lookup") is gate.Exposure.PASSIVE


def test_the_osv_host_is_allow_listed_not_free_form():
    from collect import egress
    assert "api.osv.dev" in egress.ALLOWED_HTTP_HOSTS


def test_the_post_helper_refuses_plaintext_and_unlisted_hosts():
    from collect import egress
    from core import gate
    from core.scope import Scope, ScopeKind, ScopeRule
    scope = Scope([ScopeRule(kind=ScopeKind.WILDCARD, value="example.com")])
    permit = gate.authorise("a.example.com", "advisory_lookup", "k.de", scope,
                            kind=ScopeKind.DOMAIN)
    with pytest.raises(egress.PermitMismatch):
        egress.http_post_json(permit, "advisory_lookup",
                              "http://api.osv.dev/v1/query", {})
    with pytest.raises(egress.PermitMismatch):
        egress.http_post_json(permit, "advisory_lookup",
                              "https://attacker.example/collect", {})


# ── referential integrity ───────────────────────────────────────────────────
# Added after a live OpenCTI 7.260817.0 rejected two relationships per bundle
# with MISSING_REFERENCE_ERROR. `relationship()` recomputed the infrastructure
# id with its own formula while `infrastructure()` had gained an org component,
# so EVERY asset-to-CVE edge referenced an object absent from its own bundle.
#
# Nothing caught it because every existing test checked STIX *shape*, and a
# dangling reference is perfectly well-shaped. This checks the graph instead.

def _refs(bundle):
    for obj in bundle["objects"]:
        if obj["type"] == "relationship":
            yield obj, "source_ref", obj["source_ref"]
            yield obj, "target_ref", obj["target_ref"]
        for ref in obj.get("object_refs") or []:
            yield obj, "object_refs", ref


@pytest.mark.parametrize("org", ["", "acme", "verify-org"])
def test_every_reference_resolves_inside_the_bundle(org):
    """The bug this exists for was invisible at every org value, including the
    default — the two formulas differed in arity, not just content."""
    payload = stix.bundle([finding(basis="version_range"),
                           finding(asset="b.example", cve="CVE-2018-13379",
                                   basis="product_match")], org=org)
    present = {o["id"] for o in payload["objects"]}
    dangling = [(o["type"], field, ref)
                for o, field, ref in _refs(payload) if ref not in present]
    assert dangling == [], f"references to objects not in the bundle: {dangling}"


def test_the_asset_to_cve_edge_points_at_the_emitted_infrastructure():
    """The specific edge that was broken, named so a regression is legible
    rather than showing up as a generic integrity failure."""
    payload = stix.bundle([finding(basis="version_range")], org="acme")
    infra = [o for o in payload["objects"] if o["type"] == "infrastructure"]
    edge = next(o for o in payload["objects"]
                if o["type"] == "relationship"
                and o["relationship_type"] in ("has", "related-to"))
    assert edge["source_ref"] in {o["id"] for o in infra}


def test_a_relationship_built_for_another_org_does_not_match():
    """The converse. If org stopped affecting the id, the namespacing that
    keeps two tenants' `vpn.internal` apart would be silently gone."""
    a = stix.relationship(finding(), org="acme")["source_ref"]
    b = stix.relationship(finding(), org="other")["source_ref"]
    assert a != b


def test_every_stix_export_route_passes_an_org():
    """Parsed, not grepped — and about the omission CLASS, not two instances.

    `org` has a default, so leaving it off is silent. It costs two things:
    every infrastructure id collapses into the `default` namespace, which is
    the cross-tenant collision `infrastructure()` exists to prevent; and
    `belongs_to` is gated on a truthy org, so the ownership edge is never
    emitted. Two of the three export routes had shipped that way.
    """
    import ast
    import pathlib

    source = pathlib.Path("api/app.py").read_text(encoding="utf-8")
    missing = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func)
        if name.endswith(("stix.bundle", "stix.exposure_bundle")):
            if not any(k.arg == "org" for k in node.keywords):
                missing.append(f"{name} at line {node.lineno}")
    assert missing == [], f"STIX export without an org namespace: {missing}"
