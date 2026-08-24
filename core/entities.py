"""Threat actors, malware and campaigns — carried, never merged.

`collect/stix_ingest.py:entities()` extracts these from a bundle; this stores
them across bundles so "what is this indicator part of?" survives past the poll
that answered it.

THE ONE DECISION THIS MODULE REFUSES TO MAKE
-----------------------------------------------
Every CTI platform merges entities. OpenCTI deduplicates threat actors on alias
overlap, so a feed calling a group `UAC-0001` and another calling it `APT28`
become one node with both names.

**SKOPOS does not**, and the reason is `docs/REFUSALS.md` §1. Deciding that two
sources are describing the same group is an attribution judgement — precisely
the inference P3 measured at a median of 57 groups per CVE and closed the line
on. Alias overlap is *evidence* somebody could act on; it is not proof, and the
merge is irreversible in a way the evidence is not.

Two feeds naming the same alias are recorded as **two entities and one
question**, exactly as `core/candidates.py` records a discovered name as a
question rather than adding it to scope. A person decides; this reports.

The failure mode being avoided is specific. A wrong merge is invisible after
the fact: the two names become one node, the disagreement between the sources
disappears, and every later reader sees a consensus that never existed.

WHAT AN ENTITY IS AND IS NOT CORRELATED AGAINST
--------------------------------------------------
An entity is **never matched against an estate**. A threat actor's name is not
something an asset can be, and correlating one would be a category error that
produced a "finding" on any company whose hostname happened to contain a group
name. `core/cti.py` correlates indicators; this answers questions about them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = ROOT / "data" / "entities.json"

#: The STIX SDO types carried. Deliberately the ones a reader asks about when
#: looking at an indicator — not every SDO in the specification.
KINDS: Tuple[str, ...] = ("threat-actor", "intrusion-set", "malware",
                          "campaign", "tool", "attack-pattern")

#: Stated on every alias question and on the coverage report.
SAME_NAME_IS_NOT_SAME_GROUP = (
    "Two sources sharing an alias are recorded as TWO entities and one "
    "question, never merged. Deciding that two feeds describe the same group "
    "is an attribution judgement — the inference docs/REFUSALS.md §1 refuses "
    "— and a wrong merge is invisible afterwards, because the disagreement "
    "between the sources disappears into a consensus that never existed."
)


class EntitiesUnavailable(RuntimeError):
    """No entity corpus. Callers report the absence rather than answering
    'this indicator is part of nothing'."""


def _norm(text: str) -> str:
    """Casefolded with every separator removed, for alias comparison only.

    SEPARATORS ARE DROPPED, NOT TURNED INTO SPACES. Feeds write `APT28`,
    `APT-28` and `APT 28` for one group, and flattening to spaces leaves the
    first two unequal — so a reader looking up one would miss a record holding
    the other, which is the failure this index exists to prevent.

    Comparison ONLY. Nothing is keyed on this value, because normalising two
    names to the same string is the first half of the merge this module
    refuses; the second half would be acting on it.

    Over-eagerness is the safe direction here precisely BECAUSE nothing acts on
    it. A collision that is not a real match produces one extra question for a
    person to dismiss; a missed match produces a lookup that silently answers
    "no such group".
    """
    return "".join(ch for ch in str(text or "").casefold() if ch.isalnum())


@dataclass(frozen=True)
class Entity:
    """One source's statement that a named thing exists."""

    id: str
    kind: str
    name: str
    #: The SOURCE that asserted this entity — never merged across sources, so
    #: this is part of what identifies the record.
    source: str = ""
    aliases: Tuple[str, ...] = ()
    description: str = ""
    #: The organisation the source itself credited, where it named one.
    asserted_by: str = ""
    tlp: str = "WHITE"
    first_seen: str = ""
    last_seen: str = ""

    @property
    def key(self) -> str:
        return f"{self.source}|{self.id}"

    @property
    def names(self) -> Tuple[str, ...]:
        """Every string this source uses for it — the name and its aliases."""
        return (self.name,) + tuple(self.aliases)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "name": self.name,
                "source": self.source, "aliases": list(self.aliases),
                "description": self.description,
                "asserted_by": self.asserted_by or None, "tlp": self.tlp,
                "first_seen": self.first_seen or None,
                "last_seen": self.last_seen or None}

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Entity":
        return cls(
            id=str(raw.get("id") or ""),
            kind=str(raw.get("kind") or ""),
            name=str(raw.get("name") or ""),
            source=str(raw.get("source") or ""),
            aliases=tuple(str(a) for a in (raw.get("aliases") or ()) if a),
            description=str(raw.get("description") or ""),
            asserted_by=str(raw.get("asserted_by") or ""),
            tlp=str(raw.get("tlp") or "WHITE"),
            first_seen=str(raw.get("first_seen") or ""),
            last_seen=str(raw.get("last_seen") or ""),
        )


@dataclass(frozen=True)
class AliasQuestion:
    """Two sources use one name. A question for a person, not a conclusion.

    Modelled on `core/candidates.py`: a discovered name is a question for the
    triage queue, never an addition to scope. This is the same shape applied to
    attribution.
    """

    alias: str
    entities: Tuple[Entity, ...]

    @property
    def sources(self) -> Tuple[str, ...]:
        return tuple(sorted({e.source for e in self.entities}))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alias": self.alias,
            "sources": list(self.sources),
            "entities": [e.to_dict() for e in self.entities],
            "question": (
                f"{len(self.entities)} entities from {len(self.sources)} "
                f"sources share the name {self.alias!r}. Are they the same "
                "group?"),
            "skopos_will_not_answer": SAME_NAME_IS_NOT_SAME_GROUP,
        }


class EntityStore:
    """The persisted entity corpus, and lookups that never merge."""

    def __init__(self, payload: Optional[Dict[str, Any]] = None) -> None:
        self._meta: Dict[str, Any] = dict((payload or {}).get("_meta") or {})
        self._by_key: Dict[str, Entity] = {}
        self._by_id: Dict[str, List[Entity]] = {}
        self._by_name: Dict[str, List[Entity]] = {}
        for raw in (payload or {}).get("entities") or ():
            entity = Entity.from_dict(raw)
            if entity.id and entity.name:
                self._index(entity)

    def _index(self, entity: Entity) -> None:
        self._by_key[entity.key] = entity
        self._by_id.setdefault(entity.id, []).append(entity)
        for name in entity.names:
            key = _norm(name)
            if key:
                self._by_name.setdefault(key, []).append(entity)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "EntityStore":
        target = Path(path) if path else DEFAULT_PATH
        if not target.exists():
            raise EntitiesUnavailable(
                f"No entity corpus at {target}. It is written by "
                f"`python tools/refresh_intel.py --only-taxii`.")
        with target.open("r", encoding="utf-8") as handle:
            return cls(json.load(handle))

    # -- lookups -------------------------------------------------------------
    def by_id(self, entity_id: str) -> List[Entity]:
        """Every source's record for this STIX id.

        A LIST, not one entity. Two sources can republish the same id with
        different content, and picking one would be the merge this refuses.
        """
        return list(self._by_id.get(str(entity_id or ""), []))

    def by_name(self, name: str) -> List[Entity]:
        """Every entity any source calls this — by name or by alias."""
        return list(self._by_name.get(_norm(name), []))

    def for_indicator(self, refs: Iterable[str]) -> List[Entity]:
        """What an indicator is part of, according to whoever published it.

        This is the question the whole module exists to answer, and it is
        answerable across bundles only because the refs were persisted.
        """
        out: List[Entity] = []
        seen = set()
        for ref in refs or ():
            for entity in self.by_id(ref):
                if entity.key not in seen:
                    seen.add(entity.key)
                    out.append(entity)
        return sorted(out, key=lambda e: (e.kind, e.name))

    # -- the question this raises rather than answers ------------------------
    def alias_questions(self) -> List[AliasQuestion]:
        """Names used by more than one source's entity.

        Reported so a person can decide. Cross-SOURCE only: one source using a
        name for two of its own entities is that source's business, and one
        entity carrying a name plus alias is not a collision at all.
        """
        out: List[AliasQuestion] = []
        for key, entities in sorted(self._by_name.items()):
            distinct = {e.key: e for e in entities}
            if len(distinct) < 2:
                continue
            if len({e.source for e in distinct.values()}) < 2:
                continue
            display = next(iter(distinct.values())).name
            for entity in distinct.values():
                for name in entity.names:
                    if _norm(name) == key:
                        display = name
                        break
            out.append(AliasQuestion(display,
                                     tuple(sorted(distinct.values(),
                                                  key=lambda e: e.key))))
        return out

    # -- provenance ----------------------------------------------------------
    @property
    def built_on(self) -> str:
        return str(self._meta.get("built_on") or "")

    @property
    def count(self) -> int:
        return len(self._by_key)

    def coverage(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        for entity in self._by_key.values():
            by_kind[entity.kind] = by_kind.get(entity.kind, 0) + 1
            by_source[entity.source] = by_source.get(entity.source, 0) + 1
        questions = self.alias_questions()
        return {
            "built_on": self.built_on,
            "entities": self.count,
            "by_kind": dict(sorted(by_kind.items())),
            "by_source": dict(sorted(by_source.items())),
            "alias_questions": len(questions),
            "never_merged": SAME_NAME_IS_NOT_SAME_GROUP,
            "never_correlated": (
                "Entities are never matched against an estate. A threat "
                "actor's name is not something an asset can be, and "
                "correlating one would raise a finding on any company whose "
                "hostname happened to contain a group name."),
        }


def merge_corpus(existing: Optional[Dict[str, Any]],
                 incoming: Sequence[Dict[str, Any]],
                 built_on: str = "") -> Dict[str, Any]:
    """Fold newly-seen entities into the stored corpus.

    "Merge" here means the CORPUS, never two entities. Records are keyed on
    (source, id) — the same source republishing an id updates its own record,
    and two sources publishing the same id keep two records.
    """
    kept: Dict[str, Dict[str, Any]] = {}
    for raw in (existing or {}).get("entities") or ():
        entity = Entity.from_dict(raw)
        if entity.id and entity.name:
            kept[entity.key] = entity.to_dict()
    for raw in incoming or ():
        entity = Entity.from_dict(raw)
        if entity.id and entity.name:
            kept[entity.key] = entity.to_dict()

    entities = sorted(kept.values(), key=lambda e: (e["source"], e["id"]))
    by_kind: Dict[str, int] = {}
    for item in entities:
        by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
    return {
        "_meta": {
            "built_on": built_on or datetime.now(timezone.utc).date().isoformat(),
            "entities": len(entities),
            "by_kind": dict(sorted(by_kind.items())),
            "never_merged": SAME_NAME_IS_NOT_SAME_GROUP,
        },
        "entities": entities,
    }
