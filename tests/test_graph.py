"""The exposure graph.

A picture is the easiest place in a product to lie, because a reader takes it in
before they read anything. The two lies available here are drawing a traffic
graph from data that does not exist, and drawing only what was observed so an
uninstrumented estate looks clean.
"""
from __future__ import annotations

import pytest

from core import graph
from core.graph import EdgeKind, NodeKind


def finding(asset="fw-01.example", product="FortiOS", cve="CVE-2018-13379",
            band="critical", basis="product_match", evidence=None, **kw):
    row = {"asset": asset, "product": product, "cve": cve, "band": band,
           "basis": basis, "evidence": list(evidence or []), "teps": 80,
           "owner": "Network Team"}
    row.update(kw)
    return row


# ── it is not a traffic graph ───────────────────────────────────────────────
def test_the_refusal_is_in_the_payload_not_only_the_docstring():
    """Somebody will ask where the throughput numbers are. The answer travels
    with the data rather than living in a file they will not read."""
    payload = graph.build([]).to_dict()
    assert "not a traffic graph and cannot be" in payload["not_a_traffic_graph"]
    assert "never seen a packet" in payload["not_a_traffic_graph"]


def test_there_is_no_flow_or_throughput_field():
    """Checks for FIELDS, not words in prose.

    The first version banned the words and failed on `not_a_traffic_graph`,
    which says "throughput, sessions and flows would be drawn from nothing" —
    the disclaimer that exists to prevent the thing, tripping the check meant to
    enforce it. Exactly the mistake already made once in the compliance suite.
    """
    payload = graph.build([finding()]).to_dict()

    def field_names(node, found=None):
        found = found if found is not None else set()
        if isinstance(node, dict):
            for key, value in node.items():
                found.add(str(key).lower())
                field_names(value, found)
        elif isinstance(node, list):
            for item in node:
                field_names(item, found)
        return found

    names = field_names(payload)
    for invented in ("throughput", "bytes_in", "bytes_out", "sessions",
                     "bandwidth", "flows", "packets"):
        assert invented not in names, invented


# ── the join it actually draws ──────────────────────────────────────────────
def test_an_asset_runs_a_product_which_corresponds_to_a_vulnerability():
    built = graph.build([finding()])
    kinds = {n.kind for n in built.nodes}
    assert {NodeKind.ASSET, NodeKind.PRODUCT, NodeKind.VULNERABILITY} <= kinds
    edge_kinds = {e.kind for e in built.edges}
    assert EdgeKind.RUNS in edge_kinds and EdgeKind.CORRESPONDS in edge_kinds


def test_a_worklist_entry_and_a_determination_are_different_edges():
    """The product's central claim, carried into the picture. Drawing both as
    one line would erase it exactly where it is least likely to be questioned."""
    worklist = graph.build([finding(basis="product_match")])
    determined = graph.build([finding(basis="version_range")])
    assert any(e.kind is EdgeKind.CORRESPONDS for e in worklist.edges)
    assert any(e.kind is EdgeKind.DETERMINED for e in determined.edges)


def test_a_retired_finding_is_drawn_as_ruled_out_not_as_confirmed():
    built = graph.build([finding(basis="version_range",
                                 evidence=["RETIRED: 9.9 outside every range"])])
    assert any(e.kind is EdgeKind.RETIRED for e in built.edges)
    assert not any(e.kind is EdgeKind.DETERMINED for e in built.edges)


def test_every_edge_kind_explains_itself():
    for kind in EdgeKind:
        assert kind.meaning and len(kind.meaning) > 25


def test_the_corresponds_edge_says_the_version_was_not_compared():
    assert "THE VERSION WAS NOT COMPARED" in EdgeKind.CORRESPONDS.meaning
    assert "not a finding that this asset is vulnerable" in \
        EdgeKind.CORRESPONDS.meaning


def test_nodes_are_deduplicated_across_findings():
    """One asset running one product with three vulnerabilities is one asset
    node, not three."""
    built = graph.build([finding(cve=f"CVE-2020-{i}") for i in (1, 2, 3)])
    assets = [n for n in built.nodes if n.kind is NodeKind.ASSET]
    assert len(assets) == 1 and assets[0].count == 3


def test_a_finding_missing_either_half_is_skipped_not_invented():
    """An anonymous endpoint would put a node in the graph corresponding to
    nothing."""
    built = graph.build([finding(asset=""), finding(cve="")])
    assert built.nodes == [] or all(n.kind is NodeKind.GAP for n in built.nodes)


# ── sparse is not safe ──────────────────────────────────────────────────────
def test_coverage_gaps_are_drawn_as_nodes():
    """A picture of only what was observed makes an uninstrumented estate look
    clean — a sparse graph reads as a small attack surface when it may be a
    small amount of instrumentation."""
    built = graph.build([finding(evidence=["no positive reachability evidence"])])
    assert built.gaps.get("never probed") == 1
    assert any(n.kind is NodeKind.GAP for n in built.nodes)


def test_the_gap_warning_is_in_the_payload():
    payload = graph.build([finding()]).to_dict()
    assert "makes an uninstrumented estate look clean" in \
        payload["sparse_is_not_safe"]


def test_a_worklist_entry_counts_as_a_coverage_gap():
    built = graph.build([finding(basis="product_match")])
    assert built.gaps.get("version not compared") == 1


def test_the_gap_node_kind_says_why_it_is_drawn():
    assert "could NOT establish" in NodeKind.GAP.meaning
    assert "look clean" in NodeKind.GAP.meaning


# ── three states, never two ─────────────────────────────────────────────────
def test_no_cloud_model_is_undrawable_not_absent():
    """A missing input rendered as a clean result is the failure this codebase
    keeps catching in itself."""
    payload = graph.build([finding()], cloud_model=None).to_dict()
    assert payload["unexplained_state"] == "undrawable"
    assert "NO CLOUD MODEL HAS BEEN INGESTED" in payload["unexplained_note"]
    assert "not the same as finding none" in payload["unexplained_note"]


def test_a_cloud_model_that_agrees_is_absent_not_undrawable():
    payload = graph.build([finding()], cloud_model=True).to_dict()
    assert payload["unexplained_state"] == "absent"
    assert "A cloud model was ingested" in payload["unexplained_note"]


def test_a_disagreement_is_drawn_as_its_own_edge():
    built = graph.build([finding(reconciliation="unexplained_exposure")],
                        cloud_model=True)
    assert any(e.kind is EdgeKind.UNEXPLAINED for e in built.edges)
    assert built.to_dict()["unexplained_state"] == "present"


def test_the_unexplained_edge_is_drawn_last_so_it_reads_as_heaviest():
    rows = [finding(cve="CVE-2020-1"),
            finding(cve="CVE-2020-2", basis="version_range"),
            finding(cve="CVE-2020-3", reconciliation="unexplained_exposure")]
    edges = graph.build(rows, cloud_model=True).to_dict()["edges"]
    assert edges[-1]["kind"] == "unexplained_exposure"


def test_the_unexplained_edge_names_what_neither_product_finds_alone():
    assert "Neither product finds this alone" in EdgeKind.UNEXPLAINED.meaning


# ── the headline ────────────────────────────────────────────────────────────
def test_the_headline_counts_determinations_separately():
    rows = [finding(cve="CVE-1", basis="product_match"),
            finding(cve="CVE-2", basis="version_range")]
    headline = graph.build(rows).headline()
    assert "1 confirmed by a version comparison" in headline


def test_an_empty_graph_does_not_claim_a_clean_estate():
    headline = graph.build([]).headline()
    assert "0 asset(s)" in headline
    payload = graph.build([]).to_dict()
    # The gap for the missing cloud model is still drawn on an empty graph.
    assert payload["gaps"].get("no cloud model ingested") == 1


# ── advisories stay structurally apart ──────────────────────────────────────
def test_advisories_are_not_drawn_as_exposures():
    """OSV and EUVD carry hundreds of thousands of advisories with no
    exploitation filter. Blending them in would turn a short defensible worklist
    into a vulnerability scanner, quietly and in one merge."""
    import inspect

    from api import app as api_app
    source = inspect.getsource(api_app.exposure_graph)
    assert "STRUCTURALLY apart" in source
    assert "vulnerability scanner" in source
