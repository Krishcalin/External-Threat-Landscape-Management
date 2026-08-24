"""The OpenCTI connector, and the two ways it would be wrong.

It would be wrong if it transmitted an estate without consent, and it would be
wrong if the bundle it transmitted were valid STIX that no consumer could
actually merge. Most of this file is about those.
"""
from __future__ import annotations

import json
import uuid

import pytest

from collect import opencti
from core import stix

FINDING = {
    "asset": "api.example.com", "cve": "CVE-2021-44228", "product": "Log4j",
    "version": "2.14.1", "vendor": "apache", "basis": "version_range",
    "evidence": ["version 2.14.1 falls in 2.0..2.14.1"],
    "addresses": ["198.51.100.7"], "ownership_verified_on": "2026-06-01",
    "vulnerability": "Remote code execution", "required_action": "Upgrade",
}
WORKLIST = dict(FINDING, basis="product_match", evidence=["product: log4j"],
                asset="web.example.com")


# ── observable ids must be the ones everybody else computes ─────────────────
def test_observable_ids_follow_the_stix_specification():
    """The entire point. An observable's id is a UUIDv5 over its contributing
    properties in the SPEC's namespace, so two producers who never met emit the
    same id for `example.com` and a consumer merges rather than duplicates."""
    namespace = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
    canonical = json.dumps({"value": "example.com"}, sort_keys=True,
                           separators=(",", ":"))
    expected = f"domain-name--{uuid.uuid5(namespace, canonical)}"
    assert stix.domain_name("example.com")["id"] == expected


def test_the_observable_namespace_is_not_this_products_own():
    """Using SKOPOS's namespace would produce ids nobody else agrees with —
    valid STIX that silently fails to merge, which is worse than invalid."""
    assert stix.SCO_NAMESPACE != stix.NAMESPACE


@pytest.mark.parametrize("written", ["EXAMPLE.COM", "example.com.",
                                     "  Example.Com  "])
def test_domain_names_normalise_to_one_id(written):
    assert stix.domain_name(written)["id"] == stix.domain_name("example.com")["id"]


def test_a_hostname_observable_is_never_emitted():
    """OpenCTI's `Hostname` is an OpenCTI extension, not STIX 2.1. Emitting it
    would produce a bundle that round-trips through OpenCTI and nowhere else."""
    bundle = stix.bundle([FINDING], org="acme")
    assert not any(o["type"] == "hostname" for o in bundle["objects"])
    assert any(o["type"] == "domain-name" for o in bundle["objects"])


def test_ipv4_and_ipv6_get_their_correct_types():
    assert stix.ip_address("8.8.8.8")["type"] == "ipv4-addr"
    assert stix.ip_address("2606:4700::1111")["type"] == "ipv6-addr"


def test_something_that_is_not_an_address_is_none_rather_than_guessed():
    assert stix.ip_address("example.com") is None
    assert stix.ip_address("") is None


def test_software_records_the_observed_version():
    """`core/identity.py` refuses to let an observed version reach the field a
    published range is evaluated against. This is not that field — a `software`
    observable is exactly where what-it-appeared-to-be-running belongs."""
    item = stix.software("Log4j", "2.14.1", "apache")
    assert item["version"] == "2.14.1" and item["vendor"] == "apache"


def test_software_with_no_name_is_none():
    assert stix.software("") is None


def test_only_present_properties_contribute_to_an_id():
    """Per the spec. Including empty keys would produce ids that differ from
    every other producer's for the same software."""
    assert stix.software("nginx")["id"] != stix.software("nginx", "1.0")["id"]


# ── the bundle a consumer actually receives ─────────────────────────────────
def test_the_bundle_carries_observables_composed_onto_the_asset():
    bundle = stix.bundle([FINDING], org="acme")
    kinds = {o["type"] for o in bundle["objects"]}
    assert {"infrastructure", "domain-name", "ipv4-addr", "software",
            "vulnerability", "relationship"} <= kinds
    consists = [o for o in bundle["objects"]
                if o.get("relationship_type") == "consists-of"]
    assert len(consists) == 3


def test_consists_of_is_a_real_stix_relationship():
    """The System-identity alternative some connectors use cannot compose an
    asset from observables at all, and its vulnerability edge is an OpenCTI
    extension rather than genuine STIX."""
    bundle = stix.bundle([FINDING], org="acme")
    infra = next(o for o in bundle["objects"] if o["type"] == "infrastructure")
    edges = [o for o in bundle["objects"]
             if o.get("relationship_type") == "consists-of"]
    assert all(e["source_ref"] == infra["id"] for e in edges)


def test_the_ownership_edge_is_emitted_only_when_ownership_was_verified():
    """An unconditional edge would assert control this product never
    established — the one claim it exists to be careful about."""
    with_proof = stix.bundle([FINDING], org="acme")
    assert any(o.get("relationship_type") == "belongs-to"
               for o in with_proof["objects"])

    unproven = dict(FINDING)
    unproven.pop("ownership_verified_on")
    without = stix.bundle([unproven], org="acme")
    assert not any(o.get("relationship_type") == "belongs-to"
                   for o in without["objects"])
    assert not any(o["type"] == "identity" for o in without["objects"])


def test_the_ownership_edge_carries_its_verification_date():
    """Ownership records expire — core/ownership.py gives them 180 days — so an
    edge with no date would outlive the proof."""
    bundle = stix.bundle([FINDING], org="acme")
    edge = next(o for o in bundle["objects"]
                if o.get("relationship_type") == "belongs-to")
    assert "2026-06-01" in edge["description"]


def test_two_tenants_with_the_same_asset_name_do_not_collide():
    """OpenCTI computes an Infrastructure id from the lowercased NAME ALONE, so
    without namespacing one estate's finding attaches to another's asset."""
    a = stix.bundle([FINDING], org="acme")["objects"][0]["id"]
    b = stix.bundle([FINDING], org="other")["objects"][0]["id"]
    assert a != b


def test_the_worklist_distinction_survives_the_new_objects():
    """The whole reason this module was careful in the first place."""
    determined = stix.bundle([FINDING], org="acme")
    worklist = stix.bundle([WORKLIST], org="acme")
    d = next(o for o in determined["objects"]
             if o.get("relationship_type") == "has")
    w = next(o for o in worklist["objects"]
             if o.get("relationship_type") == "related-to")
    assert d["confidence"] == stix.CONFIDENCE_DETERMINATION
    assert w["confidence"] == stix.CONFIDENCE_WORKLIST


def test_re_exporting_produces_identical_ids():
    """Otherwise a consumer accumulates duplicates forever."""
    first = stix.bundle([FINDING], org="acme", created="2026-01-01T00:00:00.000Z")
    again = stix.bundle([FINDING], org="acme", created="2026-01-01T00:00:00.000Z")
    assert [o["id"] for o in first["objects"]] == [o["id"] for o in again["objects"]]


# ── consent ─────────────────────────────────────────────────────────────────
def test_pushing_is_off_unless_switched_on(monkeypatch):
    monkeypatch.delenv(opencti.ON_SCAN_ENV, raising=False)
    assert opencti.enabled() is False


@pytest.mark.parametrize("value", ["0", "false", "no", "", "maybe", "on"])
def test_an_unrecognised_switch_value_means_off(value, monkeypatch):
    """A typo must not transmit a customer's estate to a system they did not
    mean to configure."""
    monkeypatch.setenv(opencti.ON_SCAN_ENV, value)
    assert opencti.enabled() is False


def test_no_caller_can_request_a_push():
    """If a caller could ask, anyone who could reach the scan endpoint could
    choose the moment an estate is transmitted."""
    import inspect
    from api import app as api_app
    from core import scan

    source = inspect.getsource(scan.execute)
    assert "push_for_run(diff.new" in source
    for leak in ("push=", "opencti=", "transmit="):
        assert leak not in source, leak
    for name in inspect.signature(scan.execute).parameters:
        assert "push" not in name and "opencti" not in name, name
    assert "push_for_run" not in inspect.getsource(api_app.run_scan)


def test_a_plaintext_endpoint_is_refused(monkeypatch):
    """A bundle describing where an estate is weak does not travel in clear."""
    monkeypatch.setenv(opencti.TOKEN_ENV, "t")
    monkeypatch.setenv(opencti.COLLECTION_ENV, "c")
    result = opencti.push(stix.bundle([FINDING], org="a"),
                          url="http://cti.example.com")
    assert result["pushed"] is False and "not https" in result["reason"]


# ── the four states ─────────────────────────────────────────────────────────
def test_a_quiet_run_is_a_result():
    report = opencti.push_for_run([])
    assert report["pushed"] is False
    assert "quiet run is a result" in report["reason"]


def test_decided_but_not_pushed_says_why(monkeypatch):
    monkeypatch.delenv(opencti.ON_SCAN_ENV, raising=False)
    report = opencti.push_for_run([FINDING])
    assert report["decided"] == 1 and report["pushed"] is False
    assert "needs its own consent" in report["reason"]


def test_switched_on_with_no_endpoint_is_reported_not_silent(monkeypatch):
    """The state this exists for: indistinguishable from a quiet run outside."""
    monkeypatch.delenv(opencti.URL_ENV, raising=False)
    result = opencti.push(stix.bundle([FINDING], org="a"))
    assert result["pushed"] is False
    assert "nowhere to push to" in result["reason"]


def test_a_missing_collection_is_named_specifically(monkeypatch):
    monkeypatch.setenv(opencti.TOKEN_ENV, "t")
    monkeypatch.delenv(opencti.COLLECTION_ENV, raising=False)
    result = opencti.push(stix.bundle([FINDING], org="a"),
                          url="https://cti.example.com")
    assert "TAXII Push ingester" in result["reason"]


def test_a_failure_is_reported_rather_than_swallowed(monkeypatch):
    def boom(*a, **k):
        raise opencti.PushFailed("endpoint refused")
    monkeypatch.setattr(opencti, "push", boom)
    report = opencti.push_for_run([FINDING], switched_on=True)
    assert report["pushed"] is False
    assert "The findings are recorded and correct" in report["reason"]


# ── transport details that cost an afternoon otherwise ──────────────────────
def test_the_taxii_media_type_is_used_not_plain_json():
    """MEASURED against OpenCTI 7.260817.0, not read from the docs.

    Its validator accepts a type in
    `["application/taxii+json", "application/vnd.oasis.stix+json"]` AND a
    `version` parameter of exactly 2.1. Anything else is a 400 with
    `{"error_code": "UNSUPPORTED_ERROR"}` — not the 415 this docstring used to
    claim.

    The trap: `application/stix+json` is what the collection ADVERTISES in its
    own discovery document under `media_types`, and it is rejected.
    """
    assert opencti.MEDIA_TYPE == "application/taxii+json;version=2.1"
    assert ";version=2.1" in opencti.MEDIA_TYPE


def test_the_endpoint_is_built_rather_than_configured_whole():
    """So an operator cannot point this at a non-TAXII URL and get a 200 from
    something else entirely.

    The path is VERIFIED against a running platform's own route table. It was
    previously `/taxii2/{id}/objects/`, which 404s: OpenCTI mounts collections
    under a hard-coded api-root named `root`.
    """
    assert opencti._endpoint("https://cti.example.com/", "abc") == (
        "https://cti.example.com/taxii2/root/collections/abc/objects/")


def test_a_404_from_this_endpoint_probably_means_the_ingester_is_stopped():
    """Not a shape test — a note pinned where somebody debugging will find it.

    OpenCTI's POST handler answers `Collection not found` (404) when the TAXII
    Push ingester exists but has `ingestion_running != true`, while the
    discovery endpoint cheerfully lists that same collection with
    `can_write: true`. The message sends you looking for the wrong thing.
    """
    assert "Data > Ingestion" in opencti.__doc__
    assert "404" in opencti.__doc__


def test_a_large_bundle_is_split():
    """OpenCTI's ingestion ceiling is Elasticsearch write throughput with
    roughly tenfold write amplification, so one enormous bundle is the shape
    most likely to stall a consumer."""
    objects = [{"id": f"x--{i}"} for i in range(4500)]
    chunks = opencti.split(objects)
    assert len(chunks) == 3
    assert sum(len(c) for c in chunks) == 4500


def test_splitting_an_empty_bundle_yields_one_empty_chunk():
    assert opencti.split([]) == [[]]


def test_it_is_a_registered_passive_operation():
    from core import gate
    assert gate.OPERATIONS["intel_push"] is gate.Exposure.PASSIVE
    assert opencti.OPERATION == "intel_push"


def test_the_module_declares_its_network_boundary():
    import pathlib
    source = pathlib.Path(opencti.__file__).read_text(encoding="utf-8")
    assert "# NETWORK-BOUNDARY: intel_push" in source


def test_the_teps_score_travels_namespaced_or_not_at_all():
    """It is a number computed under this product's model against this corpus
    version. Under an `x_skopos_` prefix it is unmistakably somebody else's
    opinion; as a native STIX field it would read as a shared standard.

    This test originally asserted TEPS was absent entirely, which was a claim
    about a decision the codebase had not made — the export has always
    namespaced it, and namespacing is the better answer.
    """
    bundle = stix.bundle([dict(FINDING, teps=88.0)], org="acme")
    flat = json.dumps(bundle)
    assert '"x_skopos_teps": 88.0' in flat
    # And never under a name a consumer could mistake for a standard field.
    for native in ('"score"', '"confidence": 88', '"severity"', '"risk_score"'):
        assert native not in flat, native


def test_the_basis_does_not_depend_on_a_custom_property_surviving():
    """OpenCTI's preservation of `x_` properties on import is unverified. The
    worklist/determination distinction must survive their loss, so it is
    carried three more ways in standard STIX."""
    bundle = stix.bundle([WORKLIST], org="acme")
    edge = next(o for o in bundle["objects"]
                if o.get("relationship_type") == "related-to")
    assert edge["confidence"] == stix.CONFIDENCE_WORKLIST
    assert edge["relationship_type"] == "related-to"
    assert "not" in edge.get("description", "").lower()
