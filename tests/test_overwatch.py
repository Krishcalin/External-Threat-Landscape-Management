"""OverWatch ingest, and the disagreement that justifies it.

The point of this integration is not an asset feed. It is that OverWatch answers
"is this reachable from the internet?" by a completely different method than
SKOPOS — a four-gate cloud model versus an actual probe — so the two can
disagree, and every disagreement is a finding neither tool produces alone.

These tests exist mostly to protect that: the reconciliation must never resolve a
disagreement by preferring one source, and must never report "no verdict" as
agreement.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.overwatch import (CloudContext, InternalReachability,     # noqa: E402
                            RECONCILIATION_MEANING, Reconciliation,
                            load, parse_graph, reconcile)


def graph(nodes, edges=()):
    return {"nodes": list(nodes), "edges": list(edges)}


def node(nid, kind, **props):
    return {"id": nid, "kind": kind, "props": props}


# ── reading reachability from the graph's shape ──────────────────────────────

def test_reachability_is_read_from_an_internet_edge_not_a_property():
    """OverWatch expresses reachability structurally. Reading a property named
    `is_public` instead would break the first time that property came to mean
    "has a public IP" rather than "is actually reachable" — which is exactly the
    distinction its four-gate oracle exists to draw."""
    g = graph(
        [node("i", "InternetSource"),
         node("ec2-a", "EC2Instance", dns_name="a.example.com"),
         node("ec2-b", "EC2Instance", dns_name="b.example.com")],
        [{"src": "i", "dst": "ec2-a", "kind": "REACHES"}],
    )
    assets, _ = parse_graph(g)
    verdicts = {a.asset.identifier: a.context.internal_reachability for a in assets}
    assert verdicts["a.example.com"] is InternalReachability.REACHABLE
    assert verdicts["b.example.com"] is InternalReachability.NOT_REACHABLE


def test_a_reachable_resource_with_no_external_identity_is_reported_not_dropped():
    """The most interesting kind of gap. A resource the cloud model believes is
    internet-reachable but which carries no DNS name, public IP or endpoint
    cannot be correlated with anything discovered from outside — and silently
    skipping it would hide a real exposure behind a schema mismatch."""
    g = graph(
        [node("i", "InternetSource"), node("ec2-x", "EC2Instance")],
        [{"src": "i", "dst": "ec2-x", "kind": "REACHES"}],
    )
    assets, unmappable = parse_graph(g)
    assert assets == []
    assert len(unmappable) == 1
    assert unmappable[0]["resource_id"] == "ec2-x"
    assert "no externally-visible identity" in unmappable[0]["reason"]


def test_an_unreachable_resource_without_identity_is_merely_skipped():
    """Not every unidentifiable node is a gap — only the ones the model says are
    exposed. Reporting the rest would bury the signal in IAM roles and images."""
    g = graph([node("i", "InternetSource"), node("ec2-y", "EC2Instance")])
    assets, unmappable = parse_graph(g)
    assert assets == [] and unmappable == []


def test_non_resource_kinds_are_not_promoted_to_external_assets():
    """A CNAPP graph carries IAM roles, policies and images. Treating everything
    as an external asset would flood the estate with things that have no external
    identity at all."""
    g = graph([node("role-1", "IAMRole", name="admin"),
               node("img-1", "ECRImage", name="app:1.2")])
    assets, _ = parse_graph(g)
    assert assets == []


# ── the context that feeds TEPS ──────────────────────────────────────────────

def test_fronting_is_carried_because_it_is_the_mitigation_term():
    """§9.1 gives "WAF/CDN in front of asset" a 0.15 discount. Taking it from
    observed graph structure makes it evidence rather than an assumption."""
    g = graph(
        [node("i", "InternetSource"),
         node("cf-1", "CloudFrontDistribution", domain="cdn.example.com"),
         node("alb-1", "LoadBalancer", dns_name="alb.example.com")],
        [{"src": "i", "dst": "alb-1", "kind": "REACHES"},
         {"src": "cf-1", "dst": "alb-1", "kind": "TARGETS"}],
    )
    assets, _ = parse_graph(g)
    alb = next(a for a in assets if a.asset.identifier == "alb.example.com")
    assert alb.context.fronted_by == ("CloudFrontDistribution",)
    assert alb.context.mitigation == 0.15
    cdn = next(a for a in assets if a.asset.identifier == "cdn.example.com")
    assert cdn.context.mitigation == 0.0


def test_ownership_comes_across_because_the_objective_requires_it():
    """"Accountable remediation" is half the product objective, and an exposure
    with no owner is a fact nobody will act on."""
    g = graph([node("i", "InternetSource"),
               node("ec2", "EC2Instance", dns_name="app.example.com",
                    account="123456789012", region="ap-south-1",
                    tags={"Owner": "Platform Team", "Environment": "production"})],
              [{"src": "i", "dst": "ec2", "kind": "REACHES"}])
    assets, _ = parse_graph(g)
    a = assets[0]
    assert a.asset.owner == "Platform Team"
    assert a.asset.environment == "production"
    assert a.context.account == "123456789012"
    assert a.context.region == "ap-south-1"


def test_boto3_style_tag_lists_are_understood():
    g = graph([node("ec2", "EC2Instance", public_ip="203.0.113.10",
                    tags=[{"Key": "Owner", "Value": "Network"}])])
    assets, _ = parse_graph(g)
    assert assets[0].asset.owner == "Network"


# ── the reconciliation, which is the reason for the integration ──────────────

@pytest.mark.parametrize("external,internal,expected", [
    (True, InternalReachability.REACHABLE, Reconciliation.CONFIRMED),
    (True, InternalReachability.NOT_REACHABLE, Reconciliation.UNEXPLAINED),
    (False, InternalReachability.REACHABLE, Reconciliation.BLIND_SPOT),
    (False, InternalReachability.NOT_REACHABLE, Reconciliation.AGREED_CLOSED),
])
def test_the_four_way_matrix(external, internal, expected):
    assert reconcile(external, internal) is expected


def test_not_probed_is_inconclusive_never_a_blind_spot():
    """Having no external verdict is not the same as having probed and found
    nothing. Conflating them would manufacture blind-spot findings for every
    asset SKOPOS has not got to yet."""
    assert reconcile(None, InternalReachability.REACHABLE) \
        is Reconciliation.INCONCLUSIVE


def test_no_internal_verdict_is_inconclusive_never_agreement():
    """UNKNOWN must never read as "OverWatch says it is closed". That is the
    same error as treating an empty catalogue as a clean estate."""
    assert reconcile(False, InternalReachability.UNKNOWN) \
        is Reconciliation.INCONCLUSIVE


def test_every_outcome_has_a_stated_meaning():
    """The API, the CLI and the console must not drift into describing the same
    state differently."""
    for outcome in Reconciliation:
        assert RECONCILIATION_MEANING[outcome].strip()


def test_the_unexplained_case_is_described_as_the_priority():
    """It is the finding neither tool can produce alone, and the wording has to
    say so or a reader will treat it as a data-quality nuisance."""
    text = RECONCILIATION_MEANING[Reconciliation.UNEXPLAINED]
    assert "neither tool can produce alone" in text


# ── loading ──────────────────────────────────────────────────────────────────

def test_load_accepts_a_wrapped_or_bare_graph(tmp_path):
    """The API may return the graph wrapped; a saved export may be bare."""
    g = graph([node("i", "InternetSource"),
               node("ec2", "EC2Instance", dns_name="x.example.com")],
              [{"src": "i", "dst": "ec2", "kind": "REACHES"}])
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(g), encoding="utf-8")
    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(json.dumps({"graph": g, "account_id": "1"}), encoding="utf-8")
    for path in (bare, wrapped):
        assets, _ = load(path)
        assert [a.asset.identifier for a in assets] == ["x.example.com"]


def test_overwatch_findings_are_not_imported():
    """SKOPOS scores with TEPS. Importing a second scoring opinion would give one
    asset two numbers with no way to reconcile them — OverWatch's OBSERVATIONS
    are welcome, its VERDICTS are its own."""
    g = graph([node("ec2", "EC2Instance", dns_name="y.example.com",
                    severity="CRITICAL", risk_score=99, finding="whatever")])
    assets, _ = parse_graph(g)
    asset = assets[0].asset
    # The raw props are retained as evidence, but nothing is promoted to a score.
    assert not hasattr(asset, "severity")
    assert "severity" in asset.attributes        # kept as observation only
