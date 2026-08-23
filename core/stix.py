"""Findings as STIX 2.1, without losing the distinction the product is built on.

THE PROBLEM STIX CREATES FOR THIS PRODUCT
-----------------------------------------
STIX has a `vulnerability` object and a `has` relationship, and the obvious
export writes "this infrastructure has this vulnerability" for every finding.
That is false for every finding that is a worklist entry rather than a
determination — which is most of them, and the exact share is a property of the
corpus rather than a constant worth quoting here.

`MatchBasis.PRODUCT_MATCH` means *this asset runs a product with an exploited
vulnerability* — a worklist entry. `VERSION_RANGE` means the version was
compared against a published range. Exporting both as the same relationship
hands a downstream SIEM a set of assertions this product spent its whole design
refusing to make, and the receiving analyst has no way to tell them apart.

So the basis is carried three ways, because a consumer may read any one of them:

  * `confidence` — STIX 2.1's own 0–100 property. A determination exports at
    90; a worklist entry at 40, which is below the "probable" threshold in the
    specification's own scale.
  * `relationship_type` — `has` for a determination, `related-to` for a
    worklist entry. A SIEM rule keyed on `has` therefore fires only on the
    determinations.
  * `description` — the sentence, in words, for whoever reads it by eye.

DETERMINISTIC IDENTIFIERS
-------------------------
STIX ids are `type--uuid`. Generating them randomly would mean the same finding
exported twice carries two identities, and every consumer would accumulate
duplicates forever. They are derived with UUIDv5 from stable content, so
re-exporting the same finding produces the same object and a consumer can
deduplicate.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

SPEC_VERSION = "2.1"

#: A fixed namespace, so ids are stable across machines and runs. Published in
#: the source rather than generated, because a namespace that differs per
#: install would defeat the whole point of deterministic identifiers.
NAMESPACE = uuid.UUID("6f2a1d5c-1f2b-5a7e-9c3d-5b0e1a7c4d20")

#: STIX 2.1 §2.9 confidence scale. A determination is "very probable"; a
#: worklist entry is deliberately below "probable", because it is not one.
CONFIDENCE_DETERMINATION = 90
CONFIDENCE_WORKLIST = 40


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _id(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, '|'.join(str(p) for p in parts))}"


def vulnerability(cve: str, name: str = "", description: str = "",
                  created: Optional[str] = None) -> Dict[str, Any]:
    return {
        "type": "vulnerability",
        "spec_version": SPEC_VERSION,
        "id": _id("vulnerability", cve),
        "created": created or _now(),
        "modified": created or _now(),
        "name": cve,
        "description": description or name,
        "external_references": [
            {"source_name": "cve", "external_id": cve},
            {"source_name": "cisa-kev",
             "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
             "description": "Listed as known exploited by CISA."},
        ],
    }


def infrastructure(asset: str, product: str = "",
                   created: Optional[str] = None) -> Dict[str, Any]:
    return {
        "type": "infrastructure",
        "spec_version": SPEC_VERSION,
        "id": _id("infrastructure", asset),
        "created": created or _now(),
        "modified": created or _now(),
        "name": asset,
        # `unknown` rather than a guess. STIX's vocabulary has no value meaning
        # "an internet-facing host we found", and picking a near-miss would
        # assert something about the asset's role that this product never
        # established.
        "infrastructure_types": ["unknown"],
        "description": (f"Runs {product}." if product else
                        "Product not identified."),
    }


def relationship(finding: Dict[str, Any],
                 created: Optional[str] = None) -> Dict[str, Any]:
    """The object that must not overstate the finding. See the module docstring."""
    asset = str(finding.get("asset") or "")
    cve = str(finding.get("cve") or "")
    determined = str(finding.get("basis") or "") == "version_range"
    retired = any(str(e).startswith("RETIRED:")
                  for e in (finding.get("evidence") or []))

    if determined and not retired:
        rel_type = "has"
        confidence = CONFIDENCE_DETERMINATION
        summary = ("The asset's version was compared against a published "
                   "affected range and falls inside it. This is a "
                   "determination.")
    elif retired:
        # A retired finding is exported so a consumer that already holds the
        # earlier assertion can withdraw it. Omitting it would leave the
        # downstream system believing something this product has since decided
        # is false.
        rel_type = "related-to"
        confidence = 5
        summary = ("RETIRED. The asset's version falls outside every published "
                   "affected range, so this product no longer asserts the "
                   "pairing.")
    else:
        rel_type = "related-to"
        confidence = CONFIDENCE_WORKLIST
        summary = ("The asset runs a product with a known-exploited "
                   "vulnerability. The version was NOT compared, so this is a "
                   "worklist entry and NOT an assertion that the asset is "
                   "vulnerable.")

    return {
        "type": "relationship",
        "spec_version": SPEC_VERSION,
        "id": _id("relationship", asset, cve, rel_type),
        "created": created or _now(),
        "modified": created or _now(),
        "relationship_type": rel_type,
        "source_ref": _id("infrastructure", asset),
        "target_ref": _id("vulnerability", cve),
        "confidence": confidence,
        "description": summary,
        # Non-standard properties must be prefixed under the specification.
        "x_skopos_basis": finding.get("basis"),
        "x_skopos_teps": finding.get("teps"),
        "x_skopos_band": finding.get("band"),
        "x_skopos_evidence": list(finding.get("evidence") or []),
    }


def note(text: str, refs: Sequence[str],
         created: Optional[str] = None) -> Dict[str, Any]:
    return {
        "type": "note",
        "spec_version": SPEC_VERSION,
        "id": _id("note", text[:80], *refs[:3]),
        "created": created or _now(),
        "modified": created or _now(),
        "abstract": "SKOPOS export caveat",
        "content": text,
        "object_refs": list(refs),
    }


#: Attached to every bundle. A consumer that ingests only the relationships
#: still meets this if they read the bundle at all, and it says the one thing
#: the object graph alone cannot.
BUNDLE_CAVEAT = (
    "Relationships of type `has` are DETERMINATIONS: the asset's version was "
    "compared against a published affected range. Relationships of type "
    "`related-to` with confidence 40 are WORKLIST ENTRIES: the asset runs a "
    "product with a known-exploited vulnerability and the version was not "
    "compared. They are not the same claim. A substantial part of the "
    "exploited-vulnerability catalogue carries no comparable version data at "
    "all — heavily weighted toward older CVEs, whose publishers described "
    "affected versions in prose — so many of these can never become "
    "determinations however much data is ingested."
)


def bundle(findings: Iterable[Dict[str, Any]],
           created: Optional[str] = None) -> Dict[str, Any]:
    """A STIX 2.1 bundle. Deterministic, so re-exporting deduplicates."""
    stamp = created or _now()
    objects: List[Dict[str, Any]] = []
    seen: set = set()
    rows = list(findings)

    for finding in rows:
        asset = str(finding.get("asset") or "")
        cve = str(finding.get("cve") or "")
        if not asset or not cve:
            # A row missing either half cannot be expressed as a relationship,
            # and inventing an anonymous endpoint for it would put an object in
            # the graph that corresponds to nothing.
            continue
        if ("infra", asset) not in seen:
            objects.append(infrastructure(asset, str(finding.get("product") or ""),
                                          stamp))
            seen.add(("infra", asset))
        if ("vuln", cve) not in seen:
            objects.append(vulnerability(cve, str(finding.get("vulnerability") or ""),
                                         str(finding.get("required_action") or ""),
                                         stamp))
            seen.add(("vuln", cve))
        objects.append(relationship(finding, stamp))

    if objects:
        objects.append(note(BUNDLE_CAVEAT,
                            [o["id"] for o in objects
                             if o["type"] == "relationship"][:200], stamp))

    return {
        "type": "bundle",
        "id": _id("bundle", stamp, str(len(rows))),
        "objects": objects,
    }


def to_json(findings: Iterable[Dict[str, Any]], indent: int = 1) -> str:
    return json.dumps(bundle(findings), indent=indent, ensure_ascii=False)


__all__ = ["SPEC_VERSION", "NAMESPACE", "BUNDLE_CAVEAT", "bundle", "to_json",
           "vulnerability", "infrastructure", "relationship", "note",
           "CONFIDENCE_DETERMINATION", "CONFIDENCE_WORKLIST"]
