"""Ingest OverWatch (the AWS CNAPP) — internal cloud context for an external tool.

WHY THIS ONE INTEGRATION, AND WHY IT IS NOT JUST AN ASSET FEED
--------------------------------------------------------------
SKOPOS sees the estate from outside: it probed something and got an answer.
OverWatch sees the same estate from inside: it evaluates whether a resource is
internet-reachable through **four independent gates** — a public IP, an ACTIVE
IGW default route, security-group rules opening the port to the world, and a
stateless NACL that permits both the inbound service port and the ephemeral
return. It deliberately refuses to conclude from `0.0.0.0/0` alone, which its own
docstring calls the industry's number-one false positive.

So the two systems answer the *same question by different methods*. That is worth
far more than either an asset list or an ownership lookup, because two
independent observations can DISAGREE — and every disagreement is a finding
neither tool can produce alone:

    SKOPOS says      OverWatch says     what it means
    ------------     --------------     ---------------------------------------
    reachable        reachable          confirmed exposure; two methods agree
    reachable        NOT reachable      UNEXPLAINED. Something answers from the
                                        internet that the cloud model says
                                        cannot. A path outside the model — a
                                        peering, an agent, a forgotten tunnel,
                                        or an asset that is not in this account
                                        at all.
    not reachable    reachable          BLIND SPOT. The model says it is exposed
                                        and external discovery did not find it.
                                        Either discovery missed it or something
                                        in front is absorbing the probe.
    not reachable    not reachable      agreement; no finding

The middle two rows are the reason to do this integration. They are also why
this module never overwrites one verdict with the other: a reconciliation that
silently prefers one source destroys the only signal that made it worth joining.

WHAT IS TAKEN
-------------
OverWatch's graph is `{nodes: [{id, kind, props}], edges: [{src, dst, kind}]}`.
Internet reachability is expressed structurally — an `InternetSource` node with
edges to the resources it reaches — so the verdict is read from the graph's shape
rather than from a property that might mean something else next release.

Ownership, account and tags come across because "accountable remediation" is half
the product objective and an exposure with no owner is a fact nobody will act on.
Fronting (CloudFront, ALB, WAF) comes across because it is literally the `M`
mitigation term in TEPS §9.1.

WHAT IS NOT TAKEN
-----------------
OverWatch's own findings and severities. SKOPOS scores with TEPS and importing a
second scoring opinion would produce two numbers for one asset with no way to
reconcile them. Its *observations* are welcome; its *verdicts* are its own.
"""
from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from core.models import Asset

#: Graph node kinds OverWatch uses for the thing that reaches in from outside.
INTERNET_KINDS = {"InternetSource", "Internet", "AnyPrincipal"}

#: Resource kinds worth surfacing as an external asset. Deliberately a list
#: rather than "everything not an InternetSource": a graph carries IAM roles,
#: policies and images too, and promoting those to external assets would flood
#: the estate with things that have no external identity at all.
REACHABLE_KINDS = {
    "EC2Instance", "LoadBalancer", "ApiGateway", "CloudFrontDistribution",
    "LambdaFunction", "ECSFargateTask", "KubePod", "KubeService",
    "S3Bucket", "RDSInstance", "ElasticIP", "NetworkInterface",
}

#: Property names OverWatch may use for an externally-visible identity, in
#: preference order. An asset with none of these has no external identity and is
#: reported as unmappable rather than invented.
_IDENTITY_KEYS = ("dns_name", "public_dns", "domain", "endpoint", "url",
                  "public_ip", "public_ipv4", "ip", "address", "arn", "name")

_PRODUCT_KEYS = ("product", "engine", "platform", "image", "runtime", "service")
_VERSION_KEYS = ("version", "engine_version", "runtime_version", "image_tag")
_OWNER_KEYS = ("owner", "team", "Owner", "Team", "owner_tag", "contact")
_FRONT_KINDS = {"CloudFrontDistribution", "LoadBalancer", "ApiGateway", "WAF"}


class InternalReachability(str, enum.Enum):
    """OverWatch's inside-out verdict."""

    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    #: The export did not cover this resource, so no verdict exists. Never
    #: conflated with NOT_REACHABLE — see the module docstring.
    UNKNOWN = "unknown"


class Reconciliation(str, enum.Enum):
    CONFIRMED = "confirmed"
    UNEXPLAINED = "unexplained_exposure"
    BLIND_SPOT = "discovery_blind_spot"
    AGREED_CLOSED = "agreed_not_exposed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class CloudContext:
    """What OverWatch knows that SKOPOS cannot see from outside."""

    resource_id: str
    kind: str
    account: Optional[str] = None
    region: Optional[str] = None
    internal_reachability: InternalReachability = InternalReachability.UNKNOWN
    #: Ports the cloud model believes are open to the world.
    exposed_ports: Tuple[int, ...] = ()
    #: CloudFront / ALB / WAF in front — the TEPS §9.1 `M` mitigation term.
    fronted_by: Tuple[str, ...] = ()
    tags: Dict[str, str] = field(default_factory=dict)

    @property
    def mitigation(self) -> float:
        """§9.1: "WAF/CDN in front of asset 0.15". Evidence, not an assumption."""
        return 0.15 if self.fronted_by else 0.0


@dataclass(frozen=True)
class CloudAsset:
    asset: Asset
    context: CloudContext


def _first(props: Dict[str, Any], keys: Iterable[str]) -> Optional[str]:
    for key in keys:
        value = props.get(key)
        if value not in (None, "", [], {}):
            return str(value).strip()
    return None


def _ports(props: Dict[str, Any]) -> Tuple[int, ...]:
    raw = props.get("exposed_ports") or props.get("public_ports") or props.get("ports")
    out: Set[int] = set()
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            try:
                out.add(int(str(item).split("/")[-1] if "/" in str(item) else item))
            except (TypeError, ValueError):
                continue
    return tuple(sorted(out))


def _tags(props: Dict[str, Any]) -> Dict[str, str]:
    raw = props.get("tags") or props.get("Tags") or {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        # boto3's [{"Key": ..., "Value": ...}] shape.
        out = {}
        for item in raw:
            if isinstance(item, dict) and "Key" in item:
                out[str(item["Key"])] = str(item.get("Value", ""))
        return out
    return {}


def parse_graph(graph: Dict[str, Any]) -> Tuple[List[CloudAsset], List[Dict[str, Any]]]:
    """`(assets, unmappable)` from an OverWatch graph export.

    Unmappable resources are RETURNED rather than dropped: a resource OverWatch
    considers internet-reachable that carries no externally-visible identity is
    the most interesting kind of gap, not a parsing nuisance. Silently skipping
    it would hide an exposure behind a schema mismatch.
    """
    nodes = {str(n.get("id")): n for n in (graph.get("nodes") or [])
             if isinstance(n, dict) and n.get("id")}
    edges = [e for e in (graph.get("edges") or []) if isinstance(e, dict)]

    internet_ids = {nid for nid, n in nodes.items()
                    if str(n.get("kind") or "") in INTERNET_KINDS}

    # Reachability is read from the graph's SHAPE — an edge from an internet
    # source — rather than from a property whose meaning may drift.
    reached: Set[str] = set()
    fronts: Dict[str, Set[str]] = {}
    for edge in edges:
        src, dst = str(edge.get("src") or ""), str(edge.get("dst") or "")
        if src in internet_ids and dst:
            reached.add(dst)
        src_kind = str((nodes.get(src) or {}).get("kind") or "")
        if src_kind in _FRONT_KINDS and dst:
            fronts.setdefault(dst, set()).add(src_kind)

    assets: List[CloudAsset] = []
    unmappable: List[Dict[str, Any]] = []
    for nid, node in nodes.items():
        kind = str(node.get("kind") or "")
        if kind not in REACHABLE_KINDS:
            continue
        props = node.get("props") or {}
        if not isinstance(props, dict):
            props = {}

        verdict = (InternalReachability.REACHABLE if nid in reached
                   else InternalReachability.NOT_REACHABLE)
        identity = _first(props, _IDENTITY_KEYS)
        if not identity:
            if verdict is InternalReachability.REACHABLE:
                unmappable.append({
                    "resource_id": nid, "kind": kind,
                    "reason": "OverWatch considers this internet-reachable but "
                              "it carries no externally-visible identity "
                              "(no DNS name, public IP or endpoint), so SKOPOS "
                              "cannot correlate it with anything it discovers "
                              "from outside",
                })
            continue

        tags = _tags(props)
        context = CloudContext(
            resource_id=nid, kind=kind,
            account=_first(props, ("account", "account_id", "aws_account")),
            region=_first(props, ("region", "aws_region")),
            internal_reachability=verdict,
            exposed_ports=_ports(props),
            fronted_by=tuple(sorted(fronts.get(nid, ()))),
            tags=tags,
        )
        assets.append(CloudAsset(
            asset=Asset(
                identifier=identity,
                product=_first(props, _PRODUCT_KEYS) or kind,
                vendor=_first(props, ("vendor",)) or "AWS",
                version=_first(props, _VERSION_KEYS),
                owner=_first(props, _OWNER_KEYS) or tags.get("Owner") or tags.get("owner"),
                environment=tags.get("Environment") or tags.get("env"),
                source="overwatch",
                attributes={"cloud_resource_id": nid, "cloud_kind": kind,
                            **{k: v for k, v in props.items()
                               if k not in ("tags", "Tags")}},
            ),
            context=context,
        ))
    return assets, unmappable


def load(path: Path) -> Tuple[List[CloudAsset], List[Dict[str, Any]]]:
    """Read an OverWatch graph export (`/accounts/{id}/graph` saved to disk).

    A FILE rather than a live API call, consistent with this product's offline-
    first posture: a scan must be reproducible and must run where there is no
    egress. Pulling the endpoint and saving the response is one command, and it
    keeps the network out of the scan path.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    # The API may wrap the graph; accept either shape.
    graph = payload.get("graph") if isinstance(payload.get("graph"), dict) else payload
    return parse_graph(graph)


def reconcile(external_reachable: Optional[bool],
              internal: InternalReachability) -> Reconciliation:
    """The four-way matrix. See the module docstring for why it exists.

    `external_reachable` is None when SKOPOS has not probed the asset — which is
    not the same as having probed it and got nothing, and must not be reported as
    a blind spot.
    """
    if internal is InternalReachability.UNKNOWN or external_reachable is None:
        return Reconciliation.INCONCLUSIVE
    if external_reachable and internal is InternalReachability.REACHABLE:
        return Reconciliation.CONFIRMED
    if external_reachable and internal is InternalReachability.NOT_REACHABLE:
        return Reconciliation.UNEXPLAINED
    if not external_reachable and internal is InternalReachability.REACHABLE:
        return Reconciliation.BLIND_SPOT
    return Reconciliation.AGREED_CLOSED


#: What a reader should do about each outcome. Carried here so the API, the CLI
#: and the console cannot drift into describing the same state differently.
RECONCILIATION_MEANING: Dict[Reconciliation, str] = {
    Reconciliation.CONFIRMED:
        "Two independent methods agree this is reachable from the internet: "
        "SKOPOS probed it and OverWatch's four-gate cloud model permits it.",
    Reconciliation.UNEXPLAINED:
        "SKOPOS reached this from the internet and OverWatch's cloud model says "
        "it should not be reachable. Something answers that the model does not "
        "account for — a path outside the evaluated account, a host-level "
        "tunnel, or an asset that is not the cloud resource it appears to be. "
        "This is the finding neither tool can produce alone and it should be "
        "investigated before any score is argued about.",
    Reconciliation.BLIND_SPOT:
        "OverWatch's cloud model says this is internet-reachable and external "
        "discovery did not find it. Either discovery has a gap, or something in "
        "front absorbed the probe. The exposure may be real and unmeasured.",
    Reconciliation.AGREED_CLOSED:
        "Both methods agree this is not reachable from the internet.",
    Reconciliation.INCONCLUSIVE:
        "One of the two methods has no verdict for this asset, so they cannot be "
        "compared. This is not agreement.",
}
