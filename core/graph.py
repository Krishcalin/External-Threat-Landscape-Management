"""The exposure graph, and the outside-in attack path.

WHAT THIS IS NOT
-----------------
It is not a traffic graph. SKOPOS has never seen a packet of the customer's
traffic — no flow logs, no agent, no tap — so a traffic view here would be drawn
from nothing. That belongs in OverWatch, which has flow logs. `docs/P7-SCOPE.md`
records the refusal rather than leaving it to be discovered when somebody asks
where the throughput numbers are.

What this draws is the join the product actually computes: an asset the internet
can see, the product it appears to run, and the exploited vulnerability that
product corresponds to. Every edge is a claim the rest of the codebase already
makes and already qualifies.

THE EDGE THAT MATTERS MOST, AND WHY IT IS USUALLY MISSING
----------------------------------------------------------
`unexplained_exposure` — SKOPOS reached an asset from the internet while
OverWatch's cloud model says it should not be reachable — is the one finding
neither product produces alone. It is also the most interesting thing on this
screen and today appears only as a counter in a banner.

It requires an OverWatch graph to have been ingested. Measured on the running
instance: every finding carries `reconciliation: null`, because none has been.
So the graph must distinguish THREE states, not two:

  drawn        the edge exists and is rendered
  absent       a cloud model was ingested and disagrees with nothing
  UNDRAWABLE   no cloud model was ingested, so this edge could not exist

Collapsing the third into the second renders a missing input as a clean result,
which is the failure this codebase keeps finding in itself.

A GRAPH OF ONLY WHAT WAS OBSERVED MAKES AN UNINSTRUMENTED ESTATE LOOK CLEAN
----------------------------------------------------------------------------
The Crosshair panel already refuses this in table form: coverage gaps sit at the
top rather than the bottom, because a finding reaches a high tier partly because
somebody supplied a version and probed the host. The same rule applies with more
force to a picture — a sparse graph reads as a small attack surface, when it may
be a small amount of instrumentation.

So gaps are nodes. `never probed`, `version not compared`, `no cloud model` are
drawn, counted and positioned where they cannot be missed.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


class NodeKind(str, enum.Enum):
    ASSET = "asset"
    PRODUCT = "product"
    VULNERABILITY = "vulnerability"
    #: A limit of this product's coverage, drawn so a sparse graph cannot be
    #: mistaken for a small attack surface.
    GAP = "gap"

    @property
    def meaning(self) -> str:
        return {
            NodeKind.ASSET: "a name or address this product could see from "
                            "outside",
            NodeKind.PRODUCT: "what the asset appears to run, from a banner or "
                              "a declared inventory — never confirmed by us",
            NodeKind.VULNERABILITY: "a vulnerability CISA records as actively "
                                    "exploited somewhere in the world",
            NodeKind.GAP: "something this product could NOT establish. Drawn "
                          "because a graph of only what was observed makes an "
                          "uninstrumented estate look clean",
        }[self]


class EdgeKind(str, enum.Enum):
    RUNS = "runs"
    #: The product corresponds to a catalogue entry. NOT a determination.
    CORRESPONDS = "corresponds"
    #: An observed version was compared against a published affected range.
    DETERMINED = "determined"
    #: Retired by that comparison — the version falls outside every range.
    RETIRED = "retired"
    #: Reachable from the internet while the cloud model says otherwise. The
    #: finding neither product makes alone.
    UNEXPLAINED = "unexplained_exposure"
    #: Points at what could not be established about the node it leaves.
    LIMITS = "limits"

    @property
    def meaning(self) -> str:
        return {
            EdgeKind.RUNS: "this asset appears to run this product. The "
                           "evidence is a banner or an inventory row, and a "
                           "banner is a claim by the party whose patch state is "
                           "the question",
            EdgeKind.CORRESPONDS: "the product corresponds to a known-exploited "
                                  "vulnerability. THE VERSION WAS NOT COMPARED "
                                  "— a worklist entry, not a finding that this "
                                  "asset is vulnerable",
            EdgeKind.DETERMINED: "an observed version was compared against a "
                                 "published affected range and falls inside it",
            EdgeKind.RETIRED: "compared and RULED OUT — the version falls "
                              "outside every published range",
            EdgeKind.UNEXPLAINED: "SKOPOS reached this from the internet while "
                                  "the cloud model says it should not be "
                                  "reachable. Neither product finds this alone",
            EdgeKind.LIMITS: "what could not be established here",
        }[self]

    @property
    def weight(self) -> int:
        """Drawing order and prominence. Higher is drawn later and heavier."""
        return {EdgeKind.RETIRED: 0, EdgeKind.RUNS: 1, EdgeKind.CORRESPONDS: 2,
                EdgeKind.LIMITS: 3, EdgeKind.DETERMINED: 4,
                EdgeKind.UNEXPLAINED: 5}[self]


@dataclass(frozen=True)
class Node:
    id: str
    kind: NodeKind
    label: str
    detail: str = ""
    #: Worst band across the findings touching this node. Presentation only —
    #: a node is not a finding and carries no score of its own.
    band: str = ""
    count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "kind": self.kind.value, "label": self.label,
                "detail": self.detail, "band": self.band, "count": self.count}


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: EdgeKind
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "target": self.target,
                "kind": self.kind.value, "detail": self.detail,
                "meaning": self.kind.meaning}


_BAND_ORDER = ("informational", "low", "medium", "high", "critical")


def _worse(a: str, b: str) -> str:
    try:
        return a if _BAND_ORDER.index(a) >= _BAND_ORDER.index(b) else b
    except ValueError:
        return a or b


def _is_determination(finding: Dict[str, Any]) -> bool:
    return (str(finding.get("basis")) == "version_range"
            and not _is_retired(finding))


def _is_retired(finding: Dict[str, Any]) -> bool:
    return any(str(e).startswith("RETIRED:")
               for e in finding.get("evidence") or [])


@dataclass
class Graph:
    nodes: List[Node] = field(default_factory=list)
    edges: List[Edge] = field(default_factory=list)
    #: Coverage limits, counted. Rendered as nodes AND summarised, because the
    #: count is what tells a reader whether the picture is thin or the estate is.
    gaps: Dict[str, int] = field(default_factory=dict)
    #: Whether a cloud model was ingested at all. None means UNDRAWABLE — see
    #: the module docstring.
    cloud_model: Optional[bool] = None

    def headline(self) -> str:
        assets = sum(1 for n in self.nodes if n.kind is NodeKind.ASSET)
        vulns = sum(1 for n in self.nodes if n.kind is NodeKind.VULNERABILITY)
        determined = sum(1 for e in self.edges if e.kind is EdgeKind.DETERMINED)
        unexplained = sum(1 for e in self.edges if e.kind is EdgeKind.UNEXPLAINED)
        line = (f"{assets} asset(s) the internet can see, {vulns} exploited "
                f"vulnerability/ies they correspond to, {determined} confirmed "
                f"by a version comparison.")
        if unexplained:
            line += (f" {unexplained} reachable while the cloud model says "
                     f"otherwise.")
        return line

    def to_dict(self) -> Dict[str, Any]:
        return {
            "headline": self.headline(),
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in sorted(
                self.edges, key=lambda e: e.kind.weight)],
            "gaps": dict(self.gaps),
            "node_meaning": {k.value: k.meaning for k in NodeKind},
            "edge_meaning": {k.value: k.meaning for k in EdgeKind},
            "cloud_model": self.cloud_model,
            # THREE states, never two. See the module docstring.
            "unexplained_state": (
                "undrawable" if self.cloud_model is None else
                "present" if any(e.kind is EdgeKind.UNEXPLAINED
                                 for e in self.edges) else "absent"),
            "unexplained_note": (
                "NO CLOUD MODEL HAS BEEN INGESTED, so the unexplained-exposure "
                "edge could not be drawn at all. That is not the same as "
                "finding none — ingest an OverWatch graph export with a scan "
                "and this edge becomes computable."
                if self.cloud_model is None else
                "A cloud model was ingested. Any asset reachable from outside "
                "while that model says otherwise is drawn in red — the finding "
                "neither product makes alone."),
            "not_a_traffic_graph": (
                "This is not a traffic graph and cannot be. SKOPOS has never "
                "seen a packet of your traffic — no flow logs, no agent, no "
                "tap — so throughput, sessions and flows would be drawn from "
                "nothing. What is drawn here is the join this product actually "
                "computes, from outside."),
            "sparse_is_not_safe": (
                "A graph of only what was observed makes an uninstrumented "
                "estate look clean. Every limit this product hit is drawn as a "
                "node, not omitted — a thin picture may mean a small attack "
                "surface or a small amount of instrumentation, and the gap "
                "nodes are how you tell which."),
        }


def build(findings: Sequence[Dict[str, Any]],
          cloud_model: Optional[bool] = None,
          limit: int = 400) -> Graph:
    """One graph from the findings of a scan.

    `cloud_model` is None when no OverWatch export was ingested, which makes the
    unexplained-exposure edge UNDRAWABLE rather than absent.
    """
    nodes: Dict[str, Node] = {}
    edges: Set[Edge] = set()
    gaps: Dict[str, int] = {}
    bands: Dict[str, str] = {}
    counts: Dict[str, int] = {}

    def bump(node_id: str, band: str) -> None:
        bands[node_id] = _worse(bands.get(node_id, ""), band)
        counts[node_id] = counts.get(node_id, 0) + 1

    for finding in list(findings)[:limit]:
        asset = str(finding.get("asset") or "").strip()
        cve = str(finding.get("cve") or "").strip().upper()
        product = str(finding.get("product") or "").strip() or "unidentified"
        band = str(finding.get("band") or "informational")
        if not asset or not cve:
            continue

        asset_id = f"asset:{asset}"
        product_id = f"product:{product.lower()}"
        cve_id = f"vuln:{cve}"

        nodes.setdefault(asset_id, Node(
            asset_id, NodeKind.ASSET, asset,
            detail=str(finding.get("owner") or "unassigned")))
        nodes.setdefault(product_id, Node(
            product_id, NodeKind.PRODUCT, product,
            detail=str(finding.get("version") or "version unknown")))
        nodes.setdefault(cve_id, Node(
            cve_id, NodeKind.VULNERABILITY, cve,
            detail=str(finding.get("vulnerability") or "")))

        for node_id in (asset_id, product_id, cve_id):
            bump(node_id, band)

        edges.add(Edge(asset_id, product_id, EdgeKind.RUNS,
                       detail=str(finding.get("version") or "")))

        if _is_retired(finding):
            kind = EdgeKind.RETIRED
        elif _is_determination(finding):
            kind = EdgeKind.DETERMINED
        else:
            kind = EdgeKind.CORRESPONDS
        edges.add(Edge(product_id, cve_id, kind,
                       detail=f"TEPS {finding.get('teps')}"))

        if str(finding.get("reconciliation")) == "unexplained_exposure":
            gap_id = "gap:unexplained"
            nodes.setdefault(gap_id, Node(
                gap_id, NodeKind.GAP, "reachable, but the cloud model disagrees",
                detail=EdgeKind.UNEXPLAINED.meaning))
            edges.add(Edge(asset_id, gap_id, EdgeKind.UNEXPLAINED))
            gaps["reachable while the cloud model says otherwise"] = \
                gaps.get("reachable while the cloud model says otherwise", 0) + 1

        # Coverage limits, drawn rather than omitted.
        if kind is EdgeKind.CORRESPONDS:
            gaps["version not compared"] = gaps.get("version not compared", 0) + 1
        if any("no positive reachability evidence" in str(e)
               for e in finding.get("evidence") or []):
            gaps["never probed"] = gaps.get("never probed", 0) + 1

    if cloud_model is None:
        gaps["no cloud model ingested"] = 1

    # Attach the accumulated band and count. Nodes are frozen, so they are
    # rebuilt rather than mutated — a node whose band changed under a caller
    # holding a reference is a bug nobody would look for.
    final = [Node(n.id, n.kind, n.label, n.detail,
                  band=bands.get(n.id, ""), count=counts.get(n.id, 0))
             for n in nodes.values()]

    for label, count in gaps.items():
        gap_id = f"gap:{label}"
        if gap_id not in nodes and not label.startswith("reachable while"):
            final.append(Node(gap_id, NodeKind.GAP, label, count=count,
                              detail=NodeKind.GAP.meaning))

    return Graph(nodes=final, edges=sorted(edges, key=lambda e: e.kind.weight),
                 gaps=gaps, cloud_model=cloud_model)


__all__ = ["NodeKind", "EdgeKind", "Node", "Edge", "Graph", "build"]
