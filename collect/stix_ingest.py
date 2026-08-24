"""Consume a STIX 2.1 bundle. The inverse of `core/stix.py`.

NO NETWORK IN THIS MODULE, matching `collect/misp.py` and
`collect/shadowserver.py`. `tools/refresh_intel.py` and `collect/taxii.py` do
the retrieval.

WHY THIS IS THE PIECE THAT MATTERS MOST
------------------------------------------
Before this, SKOPOS could PRODUCE STIX and not consume it: `collect/opencti.py`
pushes bundles and nothing pulled them. That asymmetry is what made SKOPOS
depend on OpenCTI rather than replace it — every CTI platform, every TAXII
server and every commercial feed speaks STIX, so a consumer here is worth more
than any number of per-vendor parsers.

`collect/misp.py` and `collect/abusech.py` each understand exactly one
publisher. This understands the interchange format itself.

THE HARD PART IS THE PATTERN, NOT THE BUNDLE
-----------------------------------------------
Bare Cyber Observables (`domain-name`, `ipv4-addr`) are trivial — they carry
their value in a field. But almost no real threat feed ships those. It ships
`indicator` SDOs, and a STIX indicator carries its observable inside a
**STIX Patterning expression**:

    [domain-name:value = 'evil.example.com']
    [file:hashes.'SHA-256' = 'a1b2...']
    [ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']

So consuming STIX intelligence is mostly a matter of parsing that grammar.
`extract_from_pattern` handles the comparison-expression forms that carry
indicators in practice, and **counts what it could not parse** rather than
discarding it silently — an unparsed pattern is intelligence that arrived and
was dropped, which the operator is entitled to know about.

WHAT IS DELIBERATELY NOT SUPPORTED
-------------------------------------
The full patterning grammar includes temporal qualifiers (`WITHIN`, `REPEATS`,
`START`/`STOP`), set membership (`IN`), comparison operators other than `=`
(`!=`, `>`, `LIKE`, `MATCHES`), and arbitrary nesting of observation
expressions. Those describe BEHAVIOUR — "this happened three times in five
minutes" — and behaviour is not something SKOPOS can correlate against, because
it holds an external inventory rather than telemetry.

An indicator SKOPOS cannot correlate is not an indicator SKOPOS should store.
Those patterns are counted as `unsupported_pattern` and dropped, which is a
statement about this product's inputs rather than a gap in the parser.

TLP ARRIVES AS AN OBJECT REFERENCE, NOT A TAG
------------------------------------------------
MISP writes `tlp:amber` as a string. STIX writes a `marking-definition` object
and points at it from `object_marking_refs`, so the marking must be resolved
through the bundle. A consumer that ignores those refs silently strips every
handling restriction it was given — which is the one mistake in this module
with a consequence outside the software.
"""
from __future__ import annotations

# NETWORK-BOUNDARY: cti_feed_read

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: STIX SCO type (or the object path inside a pattern) → the `kind` used by
#: `core/cti.py:HALF_LIFE_DAYS`.
SCO_KINDS: Dict[str, str] = {
    "domain-name": "domain",
    "ipv4-addr": "ipv4",
    "ipv6-addr": "ipv6",
    "url": "url",
    "email-addr": "email",
}

#: STIX hash names, as they appear inside `file:hashes.'...'`. STIX 2.1 spells
#: these with hyphens and quotes; producers vary in case and quoting, so the
#: lookup is normalised.
HASH_KINDS: Dict[str, str] = {
    "md5": "md5",
    "sha-1": "sha1", "sha1": "sha1",
    "sha-256": "sha256", "sha256": "sha256",
}

#: A single comparison inside a STIX pattern:
#:     domain-name:value = 'evil.example.com'
#:     file:hashes.'SHA-256' = 'a1b2…'
#: Captures the object type, the property path, the operator and the literal.
_COMPARISON = re.compile(
    r"(?P<type>[a-z0-9][a-z0-9-]*)"
    r":(?P<path>[A-Za-z0-9_.'\"\[\]-]+)"
    r"\s*(?P<op>=|!=|>|<|>=|<=|LIKE|MATCHES|IN)\s*"
    r"(?P<quote>['\"])(?P<value>(?:\\.|(?!\4).)*)(?P=quote)",
    re.IGNORECASE)

#: Constructs that make a pattern describe behaviour rather than an artefact.
#: Presence of any means the whole pattern is unsupported. See the docstring.
_BEHAVIOURAL = re.compile(r"\b(WITHIN|REPEATS|START|STOP)\b", re.IGNORECASE)

_TLP_NAMES = {
    "white": "WHITE", "clear": "CLEAR", "green": "GREEN",
    "amber": "AMBER", "amber+strict": "AMBER_STRICT", "red": "RED",
}

#: The six TLP marking-definition UUIDs fixed by the STIX 2.1 specification.
#: Hard-coded because they are constants of the standard: a bundle may
#: reference them without defining them, and a consumer that only resolves
#: locally-defined markings would treat those as unmarked.
_STANDARD_TLP: Dict[str, str] = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "WHITE",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "AMBER",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "RED",
    # TLP 2.0 additions.
    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": "CLEAR",
    "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37": "AMBER_STRICT",
}


class BundleMalformed(ValueError):
    """Not a STIX bundle. Raised rather than returning nothing.

    An empty result and an unparseable document look identical to a caller, and
    one of them means the corpus should keep its previous contents.
    """


@dataclass
class ParseReport:
    """What was ingested, and everything that was not. Counted, never silent."""

    kept: int = 0
    observables: int = 0
    from_patterns: int = 0
    unsupported_pattern: int = 0
    unparsed_pattern: int = 0
    unmapped_type: int = 0
    revoked: int = 0
    empty_value: int = 0
    unmapped_types_seen: Dict[str, int] = field(default_factory=dict)
    sample_unparsed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kept": self.kept,
            "from_observables": self.observables,
            "from_patterns": self.from_patterns,
            "dropped_unsupported_pattern": self.unsupported_pattern,
            "dropped_unparsed_pattern": self.unparsed_pattern,
            "dropped_unmapped_type": self.unmapped_type,
            "dropped_revoked": self.revoked,
            "dropped_empty_value": self.empty_value,
            "unmapped_types": dict(sorted(self.unmapped_types_seen.items(),
                                          key=lambda kv: -kv[1])[:20]),
            # Kept so an operator can see WHAT failed to parse rather than only
            # how much did. A count alone cannot be acted on.
            "sample_unparsed_patterns": self.sample_unparsed[:5],
        }


def _ip_kind(value: str) -> Optional[str]:
    try:
        return "ipv6" if ipaddress.ip_address(value).version == 6 else "ipv4"
    except ValueError:
        return None


def _kind_for(stix_type: str, path: str, value: str) -> Optional[str]:
    """Resolve a STIX object type + property path to a SKOPOS kind."""
    stix_type = (stix_type or "").strip().lower()
    path = (path or "").strip().lower()

    if stix_type == "file":
        # file:hashes.'SHA-256'  /  file:hashes.MD5  /  file:hashes[md5]
        for token in re.split(r"[.\[\]'\"]+", path):
            hit = HASH_KINDS.get(token.strip())
            if hit:
                return hit
        return None

    kind = SCO_KINDS.get(stix_type)
    if kind is None:
        return None
    # An `ipv4-addr` carrying an IPv6 literal is a producer error, but the
    # half-life follows the actual family rather than the declared one.
    if kind in ("ipv4", "ipv6"):
        return _ip_kind(value) or kind
    return kind


def extract_from_pattern(pattern: str) -> Tuple[List[Tuple[str, str]], str]:
    """A STIX pattern → [(kind, value)], plus a status.

    Status is one of `ok`, `unsupported` (temporal/behavioural qualifiers) or
    `unparsed` (nothing recognisable found). The caller counts each, because a
    pattern that arrived and was dropped is something the operator should be
    told about.
    """
    text = str(pattern or "").strip()
    if not text:
        return [], "unparsed"
    if _BEHAVIOURAL.search(text):
        # Describes behaviour over time. SKOPOS holds an external inventory,
        # not telemetry, so it could never evaluate this. See the docstring.
        return [], "unsupported"

    found: List[Tuple[str, str]] = []
    for match in _COMPARISON.finditer(text):
        if match.group("op").upper() != "=":
            # `!=`, `LIKE`, `MATCHES` and `IN` describe a set or a negation,
            # neither of which is a single correlatable value.
            continue
        value = match.group("value").strip()
        # STIX escapes backslashes and quotes inside literals.
        value = value.replace("\\\\", "\\").replace("\\'", "'").replace('\\"', '"')
        if not value:
            continue
        kind = _kind_for(match.group("type"), match.group("path"), value)
        if kind is None:
            continue
        found.append((kind, value))

    if not found:
        return [], "unparsed"
    return found, "ok"


def _markings(bundle_objects: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    """marking-definition id → TLP level, for the whole bundle."""
    out: Dict[str, str] = dict(_STANDARD_TLP)
    for obj in bundle_objects:
        if obj.get("type") != "marking-definition":
            continue
        ident = str(obj.get("id") or "")
        if not ident:
            continue
        definition = obj.get("definition") or {}
        level = str(definition.get("tlp") or obj.get("name") or "").strip().lower()
        level = level.replace("tlp:", "").strip()
        resolved = _TLP_NAMES.get(level)
        if resolved:
            out[ident] = resolved
    return out


def _tlp_of(obj: Dict[str, Any], markings: Dict[str, str]) -> str:
    """The most restrictive marking on an object.

    Most restrictive rather than first: an object carrying both GREEN and AMBER
    is AMBER, and taking the first would leak it.
    """
    from core import cti as _cti

    best = "WHITE"
    for ref in obj.get("object_marking_refs") or ():
        level = markings.get(str(ref))
        if not level:
            # An unresolvable marking reference is a restriction this consumer
            # was given and cannot read. Treated as RED — the direction that
            # cannot leak something.
            return "RED"
        if _cti.TLP_ORDER.index(level) > _cti.TLP_ORDER.index(best):
            best = level
    return best


def _identities(bundle_objects: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    """identity id → name, so `created_by_ref` resolves to a reporter."""
    return {str(o.get("id")): str(o.get("name") or "")
            for o in bundle_objects
            if o.get("type") == "identity" and o.get("id")}


#: STIX SDO types whose `name` is worth carrying as an indicator's context when
#: a relationship connects it to one. These are the entity kinds a CTI platform
#: exists to hold, and the ones §1 permits SKOPOS to carry because the bundle's
#: author asserted them rather than SKOPOS inferring them.
NAMED_ENTITY_TYPES = ("malware", "threat-actor", "intrusion-set", "campaign",
                      "tool", "attack-pattern")


def _entity_context(bundle_objects: Sequence[Dict[str, Any]]
                    ) -> Dict[str, str]:
    """indicator id → the named entity it was related to, via relationships.

    THIS IS THE ATTRIBUTION §1 PERMITS. SKOPOS is not inferring that an
    indicator belongs to a threat actor — the bundle's author said so, in a
    `relationship` object they signed. Carrying that with their name attached
    is the same move SSVC makes, and the opposite of computing it here.
    """
    names = {str(o.get("id")): (str(o.get("type")), str(o.get("name") or ""))
             for o in bundle_objects
             if o.get("type") in NAMED_ENTITY_TYPES and o.get("id")}
    out: Dict[str, str] = {}
    for obj in bundle_objects:
        if obj.get("type") != "relationship":
            continue
        source = str(obj.get("source_ref") or "")
        target = str(obj.get("target_ref") or "")
        for a, b in ((source, target), (target, source)):
            if a.startswith("indicator--") and b in names:
                kind, name = names[b]
                if name:
                    out.setdefault(a, f"{name} ({kind})")
    return out


def parse_bundle(raw: bytes | str | Dict[str, Any],
                 source: str = "stix",
                 publisher: str = "",
                 ) -> Tuple[List[Dict[str, Any]], ParseReport]:
    """A STIX 2.1 bundle → SKOPOS indicator dicts, plus what was dropped.

    `source` and `publisher` name where the bundle came from. They are
    parameters rather than constants because this parser is deliberately not
    tied to one producer — that is the whole point of consuming STIX.
    """
    if isinstance(raw, (bytes, str)):
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise BundleMalformed(f"bundle is not JSON: {exc}") from exc
    else:
        payload = raw
    if not isinstance(payload, dict):
        raise BundleMalformed("bundle is not a mapping")

    objects = payload.get("objects")
    if not isinstance(objects, list):
        raise BundleMalformed(
            "bundle has no `objects` list — a STIX bundle without one is not "
            "an empty bundle, it is a different document")

    markings = _markings(objects)
    identities = _identities(objects)
    entity_for = _entity_context(objects)
    report = ParseReport()
    out: List[Dict[str, Any]] = []

    def emit(value: str, kind: str, obj: Dict[str, Any],
             context: str, from_pattern: bool) -> None:
        if not value:
            report.empty_value += 1
            return
        reporter = identities.get(str(obj.get("created_by_ref") or ""), "")
        # `valid_from` is the indicator's own statement of when it began to
        # apply, and beats `created` — which is when the record was written,
        # not when the intelligence starts.
        seen = str(obj.get("valid_from") or obj.get("created") or "")[:10]
        entry: Dict[str, Any] = {
            "value": value,
            "kind": kind,
            "source": source,
            "publisher": publisher or reporter or source,
            "seen_on": seen,
            "context": context,
            "tags": [str(t) for t in (obj.get("labels") or [])],
            "tlp": _tlp_of(obj, markings),
            "reporter": reporter,
        }
        confidence = obj.get("confidence")
        if isinstance(confidence, int):
            # The BUNDLE AUTHOR's confidence, carried as theirs. `core/cti.py`
            # holds no opinion of its own about an indicator.
            entry["source_confidence"] = confidence
        valid_until = str(obj.get("valid_until") or "")[:10]
        if valid_until:
            entry["valid_until"] = valid_until
        out.append(entry)
        report.kept += 1
        if from_pattern:
            report.from_patterns += 1
        else:
            report.observables += 1

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        stix_type = str(obj.get("type") or "")

        if obj.get("revoked"):
            # The producer withdrew it. Ingesting a revoked indicator would
            # resurrect a claim its author has retracted.
            report.revoked += 1
            continue

        if stix_type == "indicator":
            values, status = extract_from_pattern(obj.get("pattern") or "")
            if status == "unsupported":
                report.unsupported_pattern += 1
                continue
            if status == "unparsed":
                report.unparsed_pattern += 1
                text = str(obj.get("pattern") or "")[:160]
                if text and len(report.sample_unparsed) < 5:
                    report.sample_unparsed.append(text)
                continue
            context = (entity_for.get(str(obj.get("id")))
                       or str(obj.get("name") or "")
                       or str(obj.get("description") or "")[:200]
                       or "STIX indicator")
            for kind, value in values:
                emit(value, kind, obj, context, from_pattern=True)
            continue

        if stix_type in SCO_KINDS:
            value = str(obj.get("value") or "")
            kind = _kind_for(stix_type, "value", value)
            if kind is None:
                report.unmapped_type += 1
                continue
            emit(value, kind, obj, "STIX observable", from_pattern=False)
            continue

        if stix_type == "file":
            hashes = obj.get("hashes") or {}
            emitted = False
            for name, digest in hashes.items():
                kind = HASH_KINDS.get(str(name).strip().lower())
                if kind and digest:
                    emit(str(digest), kind, obj, "STIX file observable",
                         from_pattern=False)
                    emitted = True
            if not emitted:
                report.unmapped_type += 1
            continue

        # Bundle furniture and entity objects. Counted so the shape of what
        # arrived is visible, not treated as an error.
        if stix_type and stix_type not in (
                "bundle", "relationship", "marking-definition", "identity",
                *NAMED_ENTITY_TYPES):
            report.unmapped_type += 1
            report.unmapped_types_seen[stix_type] = (
                report.unmapped_types_seen.get(stix_type, 0) + 1)

    return out, report


def entities(raw: bytes | str | Dict[str, Any]) -> List[Dict[str, Any]]:
    """The named entities a bundle asserts — actors, malware, campaigns.

    Separate from `parse_bundle` because these are not indicators and must not
    be correlated against an estate. They are what a CTI platform holds so a
    reader can ask "what is this indicator part of?", and they are carried only
    because the bundle's author stated them.
    """
    if isinstance(raw, (bytes, str)):
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise BundleMalformed(f"bundle is not JSON: {exc}") from exc
    else:
        payload = raw
    objects = (payload or {}).get("objects")
    if not isinstance(objects, list):
        raise BundleMalformed("bundle has no `objects` list")

    identities = _identities(objects)
    markings = _markings(objects)
    out: List[Dict[str, Any]] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") not in NAMED_ENTITY_TYPES:
            continue
        if obj.get("revoked"):
            continue
        out.append({
            "id": str(obj.get("id") or ""),
            "kind": str(obj.get("type") or ""),
            "name": str(obj.get("name") or ""),
            "aliases": [str(a) for a in (obj.get("aliases") or [])],
            "description": str(obj.get("description") or "")[:400],
            "asserted_by": identities.get(
                str(obj.get("created_by_ref") or ""), ""),
            "tlp": _tlp_of(obj, markings),
            "first_seen": str(obj.get("first_seen") or "")[:10],
            "last_seen": str(obj.get("last_seen") or "")[:10],
        })
    return out
