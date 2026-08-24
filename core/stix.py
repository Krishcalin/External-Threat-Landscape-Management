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


#: The STIX 2.1 namespace for Cyber Observable ids, from the specification
#: (§1.5.1). NOT this product's own namespace: an observable's id is defined by
#: the spec as a UUIDv5 over its ID Contributing Properties in THIS namespace,
#: so two producers who have never met emit the same id for `example.com`.
#:
#: That is the whole reason to bother. A consumer merges our observable with one
#: from a completely different source rather than accumulating near-duplicates —
#: and OpenCTI, which computes exactly this, will upsert rather than duplicate.
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _sco_id(kind: str, properties: Dict[str, Any]) -> str:
    """A spec-conformant observable id.

    The contributing properties are serialised as canonical JSON — sorted keys,
    no whitespace — because the spec requires a deterministic byte sequence and
    any deviation produces an id nobody else agrees with.
    """
    canonical = json.dumps(properties, sort_keys=True, separators=(",", ":"))
    return f"{kind}--{uuid.uuid5(SCO_NAMESPACE, canonical)}"


#: SSVC decision points, as published by CISA-ADP in the `vulnrichment` ADP
#: container. SKOPOS vendors 1,674 of them.
#:
#: WHY LABELS AND NOT A CUSTOM PROPERTY. OpenCTI has no SSVC field anywhere in
#: its schema — issue #17045 requests one, citing CISA BOD 26-04 — and whether
#: it preserves arbitrary `x_`-prefixed properties on STIX import is UNVERIFIED.
#: A custom property that silently drops would lose the one ranking input this
#: product carries that nothing else in the open-source field does. Labels are
#: a standard STIX property, survive any conformant importer, and are filterable
#: without parsing prose.
SSVC_POINTS = ("exploitation", "automatable", "technical_impact")

#: The fourth decision point, and the reason no outcome is computed here.
SSVC_MISSING_INPUT = "mission_and_wellbeing"

SSVC_NO_OUTCOME = (
    "SSVC decision POINTS are exported; the SSVC OUTCOME (Act / Attend / "
    "Track* / Track) is not, and cannot be. The decision tree takes four "
    "inputs and CISA publishes three: Exploitation, Automatable and Technical "
    "Impact. The fourth, MISSION AND WELL-BEING, is a judgement about what the "
    "affected system is worth to the organisation that runs it — which an "
    "outside-in product does not know and must not guess. Supply it yourself "
    "and the outcome follows; a producer that shipped one would be inventing "
    "the input it was missing.")


def ssvc_labels(points: Optional[Dict[str, Any]]) -> List[str]:
    """SSVC decision points as STIX labels: `ssvc:exploitation/active`.

    Namespaced under `ssvc:` so a consumer can select them without knowing
    anything about SKOPOS, and the value follows a `/` so it parses without
    ambiguity — a point's value can contain a hyphen but never a slash.
    """
    if not points:
        return []
    out = []
    for name in SSVC_POINTS:
        value = str(points.get(name) or "").strip().lower()
        if value:
            out.append(f"ssvc:{name.replace('_', '-')}/{value}")
    return sorted(out)


def ssvc_from_evidence(evidence: Sequence[str]) -> Dict[str, str]:
    """Recover decision points from the evidence line the engine already writes.

    `core/engine.py` renders them as `CISA SSVC: automatable=no, exploitation=
    active, technical impact=total` — a sentence for a human. Parsing it back is
    less pleasant than threading a dict through, and it is what keeps this
    change to the export rather than to the scoring path, which has its own
    tests and its own reasons for its shape.
    """
    for line in evidence or ():
        text = str(line)
        if not text.upper().startswith("CISA SSVC:"):
            continue
        points: Dict[str, str] = {}
        for chunk in text.split(":", 1)[1].split(","):
            if "=" not in chunk:
                continue
            key, _, value = chunk.partition("=")
            points[key.strip().replace(" ", "_")] = value.strip()
        return points
    return {}


def domain_name(value: str) -> Dict[str, Any]:
    """A hostname as `domain-name`, deliberately not `hostname`.

    OpenCTI has a `Hostname` observable and it is an OPENCTI EXTENSION, not
    STIX 2.1. Emitting it would produce a bundle that round-trips through
    OpenCTI and nowhere else, which defeats the point of exporting a standard.
    Subdomains are domain names; the spec is content with that.
    """
    name = str(value or "").strip().lower().rstrip(".")
    return {"type": "domain-name", "spec_version": SPEC_VERSION,
            "id": _sco_id("domain-name", {"value": name}), "value": name}


def ip_address(value: str) -> Optional[Dict[str, Any]]:
    """`ipv4-addr` or `ipv6-addr`, or None if it is neither."""
    import ipaddress as _ip
    try:
        parsed = _ip.ip_address(str(value or "").strip())
    except ValueError:
        return None
    kind = "ipv4-addr" if parsed.version == 4 else "ipv6-addr"
    text = str(parsed)
    return {"type": kind, "spec_version": SPEC_VERSION,
            "id": _sco_id(kind, {"value": text}), "value": text}


def autonomous_system(number: int, name: str = "") -> Optional[Dict[str, Any]]:
    try:
        asn = int(number)
    except (TypeError, ValueError):
        return None
    obj = {"type": "autonomous-system", "spec_version": SPEC_VERSION,
           "id": _sco_id("autonomous-system", {"number": asn}), "number": asn}
    if name:
        obj["name"] = str(name)
    return obj


def software(product: str, version: str = "", vendor: str = "",
             cpe: str = "") -> Optional[Dict[str, Any]]:
    """A `software` observable, and the one place a version legitimately goes.

    `core/identity.py` refuses to let an OBSERVED version reach the field a
    published affected range is evaluated against. This is not that field — it
    records what the asset appeared to be running, which is exactly what a
    `software` observable is for. The determination still lives in the
    relationship's confidence, where a consumer can see the basis.
    """
    name = str(product or "").strip()
    if not name:
        return None
    # Only the properties actually present contribute to the id, per the spec.
    contributing: Dict[str, Any] = {"name": name}
    if cpe:
        contributing["cpe"] = str(cpe)
    if vendor:
        contributing["vendor"] = str(vendor)
    if version:
        contributing["version"] = str(version)
    obj = {"type": "software", "spec_version": SPEC_VERSION,
           "id": _sco_id("software", contributing), "name": name}
    for key in ("cpe", "vendor", "version"):
        value = contributing.get(key)
        if value:
            obj[key] = value
    return obj


def x509_certificate(serial: str, issuer: str = "", not_before: str = "",
                     not_after: str = "") -> Optional[Dict[str, Any]]:
    serial_number = str(serial or "").strip()
    if not serial_number:
        return None
    obj = {"type": "x509-certificate", "spec_version": SPEC_VERSION,
           "id": _sco_id("x509-certificate", {"serial_number": serial_number}),
           "serial_number": serial_number}
    if issuer:
        obj["issuer"] = str(issuer)
    if not_before:
        obj["validity_not_before"] = f"{str(not_before)[:10]}T00:00:00.000Z"
    if not_after:
        obj["validity_not_after"] = f"{str(not_after)[:10]}T00:00:00.000Z"
    return obj


def organization(name: str, created: Optional[str] = None) -> Dict[str, Any]:
    """The identity an asset BELONGS TO — the ownership edge's far end.

    This is the object that carries the one thing no other producer in this
    ecosystem has: a record that somebody proved they control the asset. It is
    an `identity` with `identity_class: organization`, which is the ordinary
    STIX way to say so.
    """
    label = str(name or "").strip() or "unattributed"
    return {"type": "identity", "spec_version": SPEC_VERSION,
            "id": _id("identity", "organization", label.lower()),
            "created": created or _now(), "modified": created or _now(),
            "name": label, "identity_class": "organization"}


def composed_of(infrastructure_id: str, observable_id: str,
                created: Optional[str] = None) -> Dict[str, Any]:
    """`infrastructure --consists-of--> observable`.

    A built-in STIX 2.1 relationship, which matters: the `System`-identity
    alternative some connectors use has no way to compose an asset from
    observables at all, and its vulnerability edge is an OpenCTI extension
    rather than real STIX.
    """
    return {
        "type": "relationship", "spec_version": SPEC_VERSION,
        "id": _id("relationship", "consists-of", infrastructure_id, observable_id),
        "created": created or _now(), "modified": created or _now(),
        "relationship_type": "consists-of",
        "source_ref": infrastructure_id, "target_ref": observable_id,
    }


def belongs_to(infrastructure_id: str, identity_id: str,
               verified_on: str = "", created: Optional[str] = None
               ) -> Dict[str, Any]:
    """`infrastructure --belongs-to--> identity`. THE OWNERSHIP EDGE.

    Carries the verification date in its description rather than asserting
    ownership bare, because an ownership record has an expiry — `core/ownership.py`
    gives them 180 days — and an edge with no date would outlive the proof.
    """
    detail = ("Ownership of this asset was verified by the operator"
              + (f" on {verified_on[:10]}." if verified_on else ".")
              + " SKOPOS records the verification; it does not adjudicate it.")
    return {
        "type": "relationship", "spec_version": SPEC_VERSION,
        "id": _id("relationship", "belongs-to", infrastructure_id, identity_id),
        "created": created or _now(), "modified": created or _now(),
        "relationship_type": "belongs-to",
        "source_ref": infrastructure_id, "target_ref": identity_id,
        "description": detail,
    }


def resolves_to(source_id: str, target_id: str,
                created: Optional[str] = None) -> Dict[str, Any]:
    """`domain-name --resolves-to--> ipv4-addr`, or name to name.

    A built-in STIX 2.1 relationship and the single most useful edge this
    product can contribute, because it is the one OpenCTI's own STIX importer
    is documented as dropping (issue #6928, open two years). A consumer that
    holds an address from one source and a name from another can join them here.

    It is also how a dangling delegation is expressed honestly: the record
    points somewhere, and where it points is a fact, separately from any
    verdict about claimability.
    """
    return {
        "type": "relationship", "spec_version": SPEC_VERSION,
        "id": _id("relationship", "resolves-to", source_id, target_id),
        "created": created or _now(), "modified": created or _now(),
        "relationship_type": "resolves-to",
        "source_ref": source_id, "target_ref": target_id,
    }


def observation_note(rule_id: str, detail: str, object_refs: Sequence[str],
                     created: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """One catalogue rule's firing, as a STIX note carrying its own limits.

    THE RULE CATALOGUE IS WHY THIS IS HONEST. `core/rules.py` requires every
    rule to state what firing does NOT establish, so a note built from one
    cannot be written without its caveat — the caveat is a required field
    upstream rather than a courtesy here.

    A note rather than an `indicator` or a `sighting`, deliberately. An
    indicator is a detection pattern and these are not patterns. A sighting
    asserts an indicator was seen somewhere, which imports a claim about
    malice that most of these rules explicitly refuse. A note says: this was
    observed, here is what it means, here is what it does not.
    """
    from core import rules as _rules

    rule = _rules.get(rule_id)
    if rule is None or not object_refs:
        # An unknown rule id means the catalogue and the code have drifted.
        # Emitting a note with no provenance would hide that; returning None
        # lets the caller count it.
        return None
    content = (f"{rule.detects}\n\n"
               f"OBSERVED: {detail}\n\n"
               f"THIS DOES NOT MEAN: {rule.limits}\n\n"
               f"Rule {rule.id} ({rule.severity.value}) from SKOPOS's published "
               f"catalogue at /api/v1/rules. Emitted by {rule.emitted_by}.")
    return {
        "type": "note", "spec_version": SPEC_VERSION,
        "id": _id("note", rule.id, *sorted(object_refs)),
        "created": created or _now(), "modified": created or _now(),
        "abstract": f"{rule.title} ({rule.id})",
        "content": content,
        "object_refs": list(object_refs),
        # Labelled so a consumer can filter on the rule without parsing prose.
        "labels": [f"skopos-rule:{rule.id}", f"skopos-severity:{rule.severity.value}"],
    }


def vulnerability(cve: str, name: str = "", description: str = "",
                  created: Optional[str] = None,
                  ssvc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """A CVE, carrying SSVC decision points as labels where CISA published them.

    The labels are the point of this object beyond the CVE id. OpenCTI already
    has native `x_opencti_cisa_kev` and `x_opencti_epss_score` fields, so KEV
    and EPSS arrive there by other routes; SSVC has no field anywhere in its
    schema and no other open-source producer emits it.
    """
    labels = ssvc_labels(ssvc)
    obj = {
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
    if labels:
        obj["labels"] = labels
        # Carried in the custom property too, because a label is a flat string
        # and a consumer that wants the points as fields should not have to
        # parse them back. Belt and braces: if `x_` survives, both work; if it
        # does not, the labels still do.
        obj["x_skopos_ssvc"] = {k: v for k, v in (ssvc or {}).items()
                                if k in SSVC_POINTS}
        obj["x_skopos_ssvc_outcome"] = None
        obj["x_skopos_ssvc_note"] = SSVC_NO_OUTCOME
    return obj


def infrastructure(asset: str, product: str = "",
                   created: Optional[str] = None,
                   org: str = "") -> Dict[str, Any]:
    """An asset. The id is NAMESPACED BY ORGANISATION, deliberately.

    OpenCTI computes an Infrastructure's deterministic id from the lowercased
    NAME ALONE. Two tenants that both run `vpn.internal` would therefore
    collide inside a consumer that ingests from both — one estate's finding
    silently attaching to another's asset. Including the org in the id material
    costs nothing and makes that impossible.
    """
    return {
        "type": "infrastructure",
        "spec_version": SPEC_VERSION,
        "id": _id("infrastructure", org or "default", asset),
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
                 created: Optional[str] = None,
                 org: str = "") -> Dict[str, Any]:
    """The object that must not overstate the finding. See the module docstring.

    `org` MUST match the value the bundle used to build its infrastructure
    objects. It is not decoration: `infrastructure()` namespaces its id by
    organisation, so a relationship built with a different `org` points at an
    asset that does not exist. That is not a hypothetical — it shipped. See
    the note on `source_ref` below.
    """
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
        # DERIVED, never recomputed. This line used to read
        #     _id("infrastructure", asset)
        # while `infrastructure()` built `_id("infrastructure", org, asset)`.
        # The two formulas could never agree, so every asset-to-CVE edge
        # referenced an infrastructure absent from its own bundle. A live
        # OpenCTI rejected them with MISSING_REFERENCE_ERROR; the stub had only
        # ever checked STIX shape, which the broken edge satisfied perfectly.
        # Calling the constructor means there is one definition to disagree with.
        "source_ref": infrastructure(asset, org=org)["id"],
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
    "determinations however much data is ingested. "
    + SSVC_NO_OUTCOME
)


def _provenance_note() -> str:
    """The refusals and the accuracy record, as one outbound note.

    Built at call time from `core.refusals` and `core.backtest` so it cannot
    drift from what the product actually declines and actually scored.
    """
    from core import refusals as _refusals

    lines = ["THIS PRODUCER'S STATED REFUSALS. Each is a capability a "
             "competitor sells, absent here for a recorded reason — most of "
             "them a measurement this project made and had to accept:"]
    lines.extend(f"  - {line}" for line in _refusals.caveat_lines())
    lines.append("")
    lines.append(
        "ACCURACY. This producer publishes its own forecast track record "
        "(core/backtest.py): no skill score below 30 resolved forecasts, and "
        "lead time reported as structurally unmeasurable rather than "
        "estimated. Weigh this data accordingly.")
    return "\n".join(lines)


def _observables_for(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The Cyber Observables an exposure finding legitimately contains.

    Only what was actually observed. A finding with no address contributes no
    `ipv4-addr`, rather than one built from a resolution nobody performed.
    """
    out: List[Dict[str, Any]] = []
    asset = str(finding.get("asset") or "").strip()
    if asset:
        address = ip_address(asset)
        # An asset identifier is either a name or an address, never both.
        out.append(address if address is not None else domain_name(asset))
    for value in finding.get("addresses") or []:
        address = ip_address(value)
        if address is not None:
            out.append(address)
    product = str(finding.get("product") or "")
    if product:
        item = software(product, str(finding.get("version") or ""),
                        str(finding.get("vendor") or ""),
                        str(finding.get("cpe") or ""))
        if item is not None:
            out.append(item)
    return out


def exposure_bundle(assets, created=None, org=""):
    """Everything SKOPOS knows about an estate that is NOT a CVE finding.

    WHY THIS EXISTS SEPARATELY FROM `bundle`
    ------------------------------------------
    `bundle` exports vulnerability findings, which is one of nine categories in
    `core/rules.py`. The other eight — dangling delegations, abuse-feed
    membership, leak-site listings, certificate posture, DNS resolution — never
    reached STIX at all, and they are precisely the half a threat-intelligence
    platform has no equivalent for. OpenCTI has no asset entity type; this is
    the content it cannot produce for itself.

    EVERY NON-CVE OBSERVATION BECOMES A NOTE CARRYING ITS RULE'S LIMITS, via
    `observation_note`. That is not decoration. `core/rules.py` makes the
    "what this does not mean" field mandatory, so a consumer receives the
    caveat as a required property of the export rather than as prose somebody
    remembered to include.

    An asset row is shaped like the console's own view, and every key is
    optional — a row carrying nothing but a name still produces a `domain-name`
    observable, which is a fact worth exporting on its own:

        {"asset", "addresses", "certificates", "asn", "takeover",
         "abuse", "leak_listings", "ownership_verified_on"}
    """
    stamp = created or _now()
    objects = []
    seen = set()
    unknown_rules = 0

    def emit(obj):
        if obj is None:
            return None
        if obj["id"] not in seen:
            objects.append(obj)
            seen.add(obj["id"])
        return obj["id"]

    def add_note(rule_id, detail, refs):
        nonlocal unknown_rules
        note_obj = observation_note(rule_id, detail,
                                    [r for r in refs if r], stamp)
        if note_obj is None:
            # A rule id the catalogue does not know means the code and
            # core/rules.py have drifted — the one failure a catalogue has.
            # Counted rather than silently skipped.
            unknown_rules += 1
        else:
            emit(note_obj)

    for row in assets:
        name = str(row.get("asset") or "").strip()
        if not name:
            continue
        infra_id = emit(infrastructure(name, "", stamp, org=org))

        address = ip_address(name)
        primary = emit(address if address is not None else domain_name(name))
        if primary:
            objects.append(composed_of(infra_id, primary, stamp))

        for value in row.get("addresses") or []:
            resolved = emit(ip_address(value))
            if resolved:
                objects.append(composed_of(infra_id, resolved, stamp))
                # The edge OpenCTI's own STIX importer is documented as
                # dropping (issue #6928, open two years). Emitting it costs
                # nothing and is a join a consumer cannot make for itself.
                if primary and address is None:
                    objects.append(resolves_to(primary, resolved, stamp))

        # The two observable types R1 built and then never called.
        asn = row.get("asn") or {}
        if asn.get("number") is not None:
            system_id = emit(autonomous_system(asn.get("number"),
                                               str(asn.get("name") or "")))
            if system_id:
                objects.append(composed_of(infra_id, system_id, stamp))

        for certificate in row.get("certificates") or []:
            cert_id = emit(x509_certificate(
                str(certificate.get("serial") or ""),
                str(certificate.get("issuer") or ""),
                str(certificate.get("not_before") or ""),
                str(certificate.get("not_after") or "")))
            if not cert_id:
                continue
            objects.append(composed_of(infra_id, cert_id, stamp))
            issuer = certificate.get("issuer") or "an unnamed CA"
            expires = certificate.get("not_after") or "an unknown date"
            for rule_id in certificate.get("rules") or []:
                add_note(rule_id,
                         "{0}: certificate issued by {1}, valid until "
                         "{2}".format(name, issuer, expires),
                         [cert_id, infra_id])

        verified = str(row.get("ownership_verified_on") or "")
        if org and verified:
            identity_id = emit(organization(org, stamp))
            objects.append(belongs_to(infra_id, identity_id, verified, stamp))

        takeover = row.get("takeover") or {}
        verdict = str(takeover.get("verdict") or "")
        if verdict:
            target = str(takeover.get("target") or "")
            target_id = emit(domain_name(target)) if target else None
            if primary and target_id:
                # WHERE IT POINTS is a fact, emitted separately from any
                # verdict about whether anybody could claim it. The verdict
                # lives in the note, with its permanent ceiling attached.
                objects.append(resolves_to(primary, target_id, stamp))
            reasons = "; ".join(str(r) for r in (takeover.get("reasons") or []))
            add_note("takeover." + verdict,
                     "{0} delegates to {1}. {2}".format(
                         name, target or "an unresolved target", reasons[:400]),
                     [infra_id, target_id])

        for hit in row.get("abuse") or []:
            rule_id = ("abuse.tor_exit" if str(hit.get("sense")) == "NEUTRAL"
                       else "abuse.listed")
            add_note(rule_id,
                     "{0} appears on {1} ({2}), data {3} day(s) old.".format(
                         name, hit.get("feed"), hit.get("publisher"),
                         hit.get("data_age_days")),
                     [primary or infra_id])

        for listing in row.get("leak_listings") or []:
            rule_id = ("leak.domain_listed"
                       if str(listing.get("confidence")) == "domain"
                       else "leak.name_listed")
            add_note(rule_id,
                     "{0} published this name on its public victim index on "
                     "{1} (match confidence: {2}).".format(
                         listing.get("group"), listing.get("published"),
                         listing.get("confidence")),
                     [infra_id])

    if objects:
        # The producer's refusals and accuracy record travel with an exposure
        # bundle exactly as they do with a findings bundle. A consumer given
        # assets with no statement of what this product declines would read the
        # absences as oversights.
        objects.append(note(_provenance_note(),
                            [o["id"] for o in objects
                             if o["type"] == "infrastructure"][:200], stamp))

    payload = {
        "type": "bundle",
        "id": _id("bundle", "exposure", stamp, org or "default"),
        "objects": objects,
    }
    if unknown_rules:
        payload["x_skopos_unknown_rules"] = unknown_rules
    return payload


def bundle(findings: Iterable[Dict[str, Any]],
           created: Optional[str] = None,
           org: str = "") -> Dict[str, Any]:
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
            infra = infrastructure(asset, str(finding.get("product") or ""),
                                   stamp, org=org)
            objects.append(infra)
            seen.add(("infra", asset))

            # OBSERVABLES. The asset's name and address as first-class STIX
            # Cyber Observables, composed onto the infrastructure. This is what
            # makes the bundle worth ingesting rather than merely valid: a
            # consumer can pivot on `example.com` across every source it holds,
            # which an infrastructure object alone does not permit.
            for observable in _observables_for(finding):
                if ("sco", observable["id"]) not in seen:
                    objects.append(observable)
                    seen.add(("sco", observable["id"]))
                objects.append(composed_of(infra["id"], observable["id"], stamp))

            # RESOLUTION, on the same reasoning `exposure_bundle()` gives for
            # emitting it there: the join is one a consumer cannot make for
            # itself, and this path already holds both halves. It was missing
            # here purely because the two export paths were written apart —
            # composing an address onto an asset says they belong together, not
            # that the name resolves to it.
            #
            # Only where the asset is a NAME. An asset that IS an address does
            # not resolve to anything, and `resolves-to` between two addresses
            # would assert a hop nobody observed.
            if ip_address(asset) is None:
                origin = domain_name(asset)
                for value in finding.get("addresses") or []:
                    resolved = ip_address(value)
                    if origin and resolved:
                        objects.append(
                            resolves_to(origin["id"], resolved["id"], stamp))

            # THE OWNERSHIP EDGE, emitted only where ownership was actually
            # verified. An unconditional edge would assert control this product
            # never established, which is the one claim it exists to be careful
            # about.
            verified = str(finding.get("ownership_verified_on") or "")
            if org and verified:
                identity = organization(org, stamp)
                if ("org", identity["id"]) not in seen:
                    objects.append(identity)
                    seen.add(("org", identity["id"]))
                objects.append(belongs_to(infra["id"], identity["id"],
                                          verified, stamp))
        if ("vuln", cve) not in seen:
            # An explicit `ssvc` key wins; otherwise recover the points from
            # the evidence line the engine already renders for humans.
            points = (finding.get("ssvc")
                      or ssvc_from_evidence(finding.get("evidence") or ()))
            objects.append(vulnerability(cve, str(finding.get("vulnerability") or ""),
                                         str(finding.get("required_action") or ""),
                                         stamp, ssvc=points))
            seen.add(("vuln", cve))
        objects.append(relationship(finding, stamp, org=org))

    if objects:
        relationship_ids = [o["id"] for o in objects
                            if o["type"] == "relationship"][:200]
        objects.append(note(BUNDLE_CAVEAT, relationship_ids, stamp))
        # What this producer will NOT tell you, and its own track record.
        # A consumer receiving intelligence with no stated limits assumes an
        # absence is an oversight, and one with no accuracy record has no way
        # to weigh it. Both travel with the data rather than living in a
        # document nobody downloads.
        objects.append(note(_provenance_note(), relationship_ids, stamp))

    return {
        "type": "bundle",
        "id": _id("bundle", stamp, str(len(rows))),
        "objects": objects,
    }


def to_json(findings: Iterable[Dict[str, Any]], indent: int = 1) -> str:
    return json.dumps(bundle(findings), indent=indent, ensure_ascii=False)


__all__ = ["SPEC_VERSION", "NAMESPACE", "SCO_NAMESPACE", "BUNDLE_CAVEAT",
           "bundle", "exposure_bundle", "to_json",
           "domain_name", "ip_address", "software", "autonomous_system",
           "x509_certificate", "organization", "composed_of", "belongs_to",
           "resolves_to", "observation_note", "ssvc_labels",
           "ssvc_from_evidence", "SSVC_POINTS", "SSVC_NO_OUTCOME",
           "vulnerability", "infrastructure", "relationship", "note",
           "CONFIDENCE_DETERMINATION", "CONFIDENCE_WORKLIST"]
