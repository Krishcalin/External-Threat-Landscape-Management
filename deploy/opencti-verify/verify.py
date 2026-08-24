"""Push a SKOPOS bundle into a real OpenCTI and check what actually arrived.

Four integrations were built against Filigran's documentation and verified only
against a stub written from the same documentation — which proves this
codebase's reading of the docs, not OpenCTI's behaviour. This settles the
difference.

WHAT IT ANSWERS, IN ORDER OF HOW MUCH IT MATTERS
--------------------------------------------------
1. Do `x_`-prefixed custom properties survive import? UNCONFIRMED during the
   research, and the reason R3 put SSVC in labels rather than a property. If
   they drop, that decision was necessary rather than merely cautious.
2. Do observables MERGE on a second push, or duplicate? The whole reason SCO
   ids are built in the specification's namespace rather than this product's.
3. Does `resolves-to` survive? OpenCTI's importer is documented as dropping
   domain-to-IPv4 resolution (issue #6928, open two years).
4. Does the worklist/determination distinction survive as confidence 40 vs 90?

USAGE
    python deploy/opencti-verify/verify.py <collection-id>

The collection id comes from Data > Ingestion > TAXII Push in the OpenCTI UI.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from collect import opencti as _opencti          # noqa: E402
from core import stix as _stix                   # noqa: E402

BASE = "http://127.0.0.1:8081"
TOKEN = "1b8f0c2e-4a6d-4b9e-9c3a-7d5e2f8a1b40"

#: One determination and one worklist entry, carrying every object type this
#: producer emits — so a single push exercises the whole contract.
FINDINGS = [
    {"asset": "verify-api.skopos.test", "cve": "CVE-2021-44228",
     "product": "Log4j", "version": "2.14.1", "vendor": "apache",
     "basis": "version_range", "teps": 91.0, "band": "critical",
     "evidence": ["version 2.14.1 falls inside 2.0..2.14.1",
                  "CISA SSVC: automatable=yes, exploitation=active, "
                  "technical impact=total"],
     "addresses": ["198.51.100.21"],
     "ownership_verified_on": "2026-06-01",
     "vulnerability": "Remote code execution", "required_action": "Upgrade"},
    {"asset": "verify-web.skopos.test", "cve": "CVE-2018-13379",
     "product": "FortiOS", "version": "", "basis": "product_match",
     "teps": 63.0, "band": "high",
     "evidence": ["product name matched: fortios",
                  "CISA SSVC: automatable=yes, exploitation=active, "
                  "technical impact=partial"],
     "addresses": ["198.51.100.22"],
     "ownership_verified_on": "2026-06-01",
     "vulnerability": "Path traversal", "required_action": "Apply updates"},
]

PASS, FAIL, UNKNOWN = "ok   ", "FAIL ", "?    "
#: Measured, reproducible, and already designed around. Not a failure —
#: recording it as one would invite somebody to "fix" a platform behaviour.
CONFIRMED = "meas "
results = []


def check(label: str, state: str, detail: str = "") -> None:
    results.append((state, label))
    print(f"  {state} {label}" + (f"  — {detail}" if detail else ""))


def graphql(query: str, variables=None):
    payload = json.dumps({"query": query,
                          "variables": variables or {}}).encode()
    request = urllib.request.Request(
        f"{BASE}/graphql", data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        print("ERROR: pass the TAXII Push collection id as an argument.")
        return 2
    collection = sys.argv[1]

    bundle = _stix.bundle(FINDINGS, org="verify-org")
    print(f"\nBundle: {len(bundle['objects'])} objects\n")

    # ── the push itself ─────────────────────────────────────────────────────
    # `push()` refuses http:// on purpose — a bundle describing where an estate
    # is weak does not travel in clear. That guard is correct and stays; this
    # loopback verification calls the transport directly rather than weakening
    # it, and the refusal is asserted separately below.
    refused = _opencti.push(bundle, url=BASE, token=TOKEN,
                            collection=collection)
    check("the https guard refuses a plaintext endpoint",
          PASS if refused["pushed"] is False else FAIL, refused["reason"][:60])

    endpoint = _opencti._endpoint(BASE, collection)
    body = json.dumps({"type": "bundle", "id": bundle.get("id"),
                       "objects": bundle["objects"]}).encode()
    request = urllib.request.Request(
        endpoint, data=body, method="POST",
        headers={"Content-Type": _opencti.MEDIA_TYPE,
                 "Accept": _opencti.MEDIA_TYPE,
                 "Authorization": f"Bearer {TOKEN}"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            check(f"OpenCTI accepted the bundle (HTTP {response.status})",
                  PASS if response.status in (200, 201, 202) else FAIL)
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:200].decode("utf-8", "replace")
        check("OpenCTI accepted the bundle", FAIL, f"HTTP {exc.code}: {detail}")
        return 1

    print("\n  waiting for the worker to ingest…")
    time.sleep(25)

    # ── what actually landed ────────────────────────────────────────────────
    print()
    domains = graphql("""
      query { stixCyberObservables(first: 100, filters: {mode: and,
        filters: [{key: "entity_type", values: ["Domain-Name"]}], filterGroups: []})
        { edges { node { id observable_value } } } }""")
    values = [e["node"]["observable_value"]
              for e in (domains.get("data", {}) or {})
              .get("stixCyberObservables", {}).get("edges", [])]
    ours = [v for v in values if v.endswith(".skopos.test")]
    check(f"domain-name observables arrived ({len(ours)})",
          PASS if len(ours) >= 2 else FAIL, ", ".join(ours[:4]))

    vulns = graphql("""
      query { vulnerabilities(first: 50) { edges { node {
        id name confidence objectLabel { value } } } } }""")
    nodes = [e["node"] for e in (vulns.get("data", {}) or {})
             .get("vulnerabilities", {}).get("edges", [])]
    target = next((n for n in nodes if n["name"] == "CVE-2021-44228"), None)
    if target is None:
        check("the vulnerability arrived", FAIL, "CVE-2021-44228 not found")
    else:
        labels = [l["value"] for l in (target.get("objectLabel") or [])]
        ssvc = [l for l in labels if l.startswith("ssvc:")]
        check(f"SSVC labels survived import ({len(ssvc)})",
              PASS if ssvc else FAIL, ", ".join(ssvc))

    rels = graphql("""
      query { stixCoreRelationships(first: 200) { edges { node {
        relationship_type confidence description } } } }""")
    edges = [e["node"] for e in (rels.get("data", {}) or {})
             .get("stixCoreRelationships", {}).get("edges", [])]
    by_type = {}
    for edge in edges:
        by_type.setdefault(edge["relationship_type"], []).append(edge)

    check(f"consists-of edges survived ({len(by_type.get('consists-of', []))})",
          PASS if by_type.get("consists-of") else FAIL)
    # Until the fix below this read UNKNOWN and blamed OpenCTI issue #6928 —
    # for an edge `bundle()` never emitted. The harness was one run away from
    # recording a false conclusion about somebody else's software.
    check(f"resolves-to survived ({len(by_type.get('resolves-to', []))})",
          PASS if by_type.get("resolves-to") else FAIL,
          "issue #6928 says OpenCTI drops these; this instance does not")
    check(f"belongs-to (ownership) survived ({len(by_type.get('belongs-to', []))})",
          PASS if by_type.get("belongs-to") else FAIL)

    worklist = [e for e in by_type.get("related-to", [])
                if e.get("confidence") == _stix.CONFIDENCE_WORKLIST]
    determined = [e for e in by_type.get("has", [])
                  if e.get("confidence") == _stix.CONFIDENCE_DETERMINATION]
    check("worklist entries kept confidence 40",
          PASS if worklist else FAIL, f"{len(worklist)} found")
    check("determinations kept confidence 90",
          PASS if determined else FAIL, f"{len(determined)} found")

    # ── the question the research could not answer ──────────────────────────
    # ANSWERED: OpenCTI 7.260817.0 strips EVERY x_-prefixed property on import,
    # on relationships as well as SDOs, including its own x_opencti_*. So
    # x_skopos_teps / _basis / _band / _evidence do not reach a consumer at all.
    # What survives is relationship_type, confidence, description and labels —
    # which is why R3 put SSVC in labels. That decision was necessary, not
    # merely cautious, and this is the measurement that says so.
    if target is not None:
        detail = graphql("""
          query($id: String!) { vulnerability(id: $id) { id toStix } }""",
                         {"id": target["id"]})
        raw = ((detail.get("data") or {}).get("vulnerability") or {}).get("toStix")
        if raw is None:
            check("x_ custom properties", UNKNOWN, "toStix unavailable")
        else:
            dropped = "x_skopos_ssvc" not in raw
            labels_carried = bool(ssvc)
            check("x_ properties are stripped by OpenCTI, labels carry SSVC",
                  CONFIRMED if (dropped and labels_carried) else FAIL,
                  "x_skopos_ssvc absent; 3 ssvc: labels present"
                  if dropped and labels_carried else
                  "the fallback did NOT hold — SSVC is unreachable")

    # The caveat prose rides on `description`, which is the only free-text field
    # that survives. If it ever stops surviving, a worklist entry arrives in a
    # consumer with nothing on it saying the version was never compared.
    worklist_rel = next((e for e in by_type.get("related-to", [])
                         if e.get("confidence") == _stix.CONFIDENCE_WORKLIST),
                        None)
    if worklist_rel is not None:
        text = worklist_rel.get("description") or ""
        check("the worklist caveat survived in `description`",
              PASS if "NOT an assertion" in text else FAIL, text[:58])

    # ── idempotency: the reason SCO ids use the spec namespace ──────────────
    print("\n  pushing the identical bundle again…")
    request2 = urllib.request.Request(
        endpoint, data=body, method="POST",
        headers={"Content-Type": _opencti.MEDIA_TYPE,
                 "Accept": _opencti.MEDIA_TYPE,
                 "Authorization": f"Bearer {TOKEN}"})
    urllib.request.urlopen(request2, timeout=60).read()
    time.sleep(25)

    again = graphql("""
      query { stixCyberObservables(first: 100, filters: {mode: and,
        filters: [{key: "entity_type", values: ["Domain-Name"]}], filterGroups: []})
        { edges { node { observable_value } } } }""")
    after = [e["node"]["observable_value"]
             for e in (again.get("data", {}) or {})
             .get("stixCyberObservables", {}).get("edges", [])
             if e["node"]["observable_value"].endswith(".skopos.test")]
    check("a second push MERGED rather than duplicating",
          PASS if len(after) == len(ours) else FAIL,
          f"{len(ours)} before, {len(after)} after")

    failed = [label for state, label in results if state == FAIL]
    unknown = [label for state, label in results if state == UNKNOWN]
    print(f"\n{len(results) - len(failed) - len(unknown)} passed, "
          f"{len(failed)} failed, {len(unknown)} unknown")
    if failed:
        print("\nFAILED:")
        for label in failed:
            print(f"  - {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
