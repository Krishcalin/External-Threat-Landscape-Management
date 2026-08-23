"""Merging what several sources say, and deciding what scope makes of it.

SCOPE BINDS DISCOVERY TWICE
---------------------------
Once at the apex, before any source is queried — otherwise `discover google.com`
works and this is an unbounded OSINT reconnaissance tool. And once per
discovered name, because a source will happily hand back names that belong to
somebody else.

The per-name check passes `kind=ScopeKind.DOMAIN` EXPLICITLY, and that is a
control rather than a detail. Measured: with `kind=None`, `ScopeRule.matches`
falls through to a plain string comparison, so a `repo_org` rule valued
`example.com` resolves INCLUDED for the DNS name `example.com` — a GitHub-org
rule authorising DNS discovery.

UNSCOPED IS KEPT; EXCLUDED IS NOT
---------------------------------
`Decision.UNSCOPED` means nobody has spoken about this name. Its own docstring
says that for reporting it may mean shadow asset, and shadow assets are the
product's whole point — so those are kept and tagged. `EXCLUDED` means somebody
said no, so those are returned in `excluded` (never silently dropped) and never
written to the inventory.

`obs_scope=unscoped` IS ADVISORY, NOT A CONTROL. Nothing reads that column —
measured, it lands in `Asset.attributes` and no code consults it. Enforcement
comes from `authorise()` re-resolving scope at the point of use. The one place
it does bite is `cmd_fingerprint`, which refuses to actively probe a row
carrying it.

DATES CARRY THEIR PROVENANCE
----------------------------
A CT `not_before` (a certificate was issued), a Wayback crawl timestamp (a page
was fetched once) and a passive-DNS `lastSeen` (a resolver saw it resolve) are
not the same kind of fact, and flattening them with min/max destroys exactly the
distinction the data classes exist to preserve.

`obs_last_seen` is populated ONLY from PASSIVE_DNS. Otherwise a host
decommissioned in 2016 with one 2016 crawl gets `last_seen=2016-03-02`, which
any future liveness filter reads as "resolved until 2016" when the truth is only
"crawled in 2016". A CT-only name has no `last_seen` at all: liveness unknown,
stated rather than implied.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from collect.registry import DataClass
from collect.report import Coverage, Outcome, SourceReport
from core.provenance import observed
from core.scope import Decision, Scope, ScopeKind


@dataclass
class NameObservation:
    """One sighting of one name by one source."""

    name: str
    source: str
    data_class: DataClass
    first_seen: Optional[date] = None
    last_seen: Optional[date] = None
    addresses: Tuple[str, ...] = ()


@dataclass
class DiscoveredName:
    """A name, everything that saw it, and when — kept apart by data class."""

    name: str
    sources: Set[str] = field(default_factory=set)
    data_classes: Set[DataClass] = field(default_factory=set)
    first_seen_by: Dict[DataClass, date] = field(default_factory=dict)
    last_seen_by: Dict[DataClass, date] = field(default_factory=dict)
    addresses: Set[str] = field(default_factory=set)
    is_wildcard: bool = False
    #: INCLUDED or UNSCOPED. EXCLUDED names never become a DiscoveredName.
    decision: Decision = Decision.UNSCOPED

    @property
    def first_seen(self) -> Optional[date]:
        """Earliest across every class: when did this name first appear."""
        return min(self.first_seen_by.values()) if self.first_seen_by else None

    @property
    def last_seen(self) -> Optional[date]:
        """Only a resolution somebody observed counts. See the module docstring."""
        return self.last_seen_by.get(DataClass.PASSIVE_DNS)

    @property
    def liveness(self) -> str:
        if DataClass.PASSIVE_DNS in self.data_classes:
            return "resolved"
        if self.data_classes == {DataClass.WEB_ARCHIVE}:
            return "archived-only"
        return "unknown"

    @property
    def provenance(self) -> str:
        """`ct:certspotter;pdns:mnemonic` — never a hardcoded prefix.

        A hardcoded `ct:` would assert certificate-transparency provenance for a
        web crawl, which is a claim about where a fact came from.
        """
        pairs = sorted(f"{dc.value}:{s}" for dc in self.data_classes
                       for s in sorted(self.sources)
                       if (dc, s) in self._pairs)
        return ";".join(pairs) if pairs else ";".join(sorted(self.sources))

    _pairs: Set[Tuple[DataClass, str]] = field(default_factory=set, repr=False)

    def absorb(self, observation: NameObservation) -> None:
        self.sources.add(observation.source)
        self.data_classes.add(observation.data_class)
        self._pairs.add((observation.data_class, observation.source))
        self.addresses.update(observation.addresses)
        if observation.first_seen:
            current = self.first_seen_by.get(observation.data_class)
            if current is None or observation.first_seen < current:
                self.first_seen_by[observation.data_class] = observation.first_seen
        if observation.last_seen:
            current = self.last_seen_by.get(observation.data_class)
            if current is None or observation.last_seen > current:
                self.last_seen_by[observation.data_class] = observation.last_seen


@dataclass
class Excluded:
    name: str
    reason: str


@dataclass
class DiscoveryResult:
    names: List[DiscoveredName] = field(default_factory=list)
    sources: List[SourceReport] = field(default_factory=list)
    #: Names an operator told us never to touch. Returned, never dropped.
    excluded: List[Excluded] = field(default_factory=list)
    #: Rows a source returned that could not be read at all.
    unreadable: List[str] = field(default_factory=list)
    apex: str = ""

    @property
    def coverage(self) -> Coverage:
        return Coverage(list(self.sources))

    @property
    def degraded(self) -> bool:
        return self.coverage.degraded

    @property
    def narrowed(self) -> bool:
        return self.coverage.narrowed

    @property
    def refused(self) -> bool:
        return self.coverage.refused

    @property
    def blackout(self) -> bool:
        return self.coverage.blackout

    @property
    def unscoped(self) -> List[DiscoveredName]:
        return [n for n in self.names if n.decision is Decision.UNSCOPED]

    def coverage_note(self, scope: Optional[Scope] = None) -> str:
        note = self.coverage.note(len(self.names), "name")
        if self.excluded:
            note += (f" {len(self.excluded)} name(s) matched an exclusion and "
                     f"were not written.")
        if self.unreadable:
            note += (f" {len(self.unreadable)} row(s) could not be read and were "
                     f"NOT scanned.")

        unscoped = self.unscoped
        if unscoped and len(unscoped) == len(self.names) and scope is not None:
            # A DOMAIN-only scope matches by exact equality, so every subdomain
            # comes back UNSCOPED. That is the shadow-asset finding working
            # correctly, but at 400 rows it reads as an alarm — so say which it
            # is, and name the rule that would settle it.
            has_wildcard = any(r.kind is ScopeKind.WILDCARD and not r.is_exclude
                               for r in scope.rules)
            if not has_wildcard and self.apex:
                note += (f" EVERY name is unscoped, which usually means scope "
                         f"holds a DOMAIN rule (exact match) rather than a "
                         f"wildcard. `etlm scope add {self.apex} --kind "
                         f"wildcard` would declare the estate.")
            else:
                note += (f" All {len(unscoped)} name(s) are unscoped — no rule "
                         f"mentions them. That is the shadow-asset case, not an "
                         f"error.")
        elif unscoped:
            note += (f" {len(unscoped)} name(s) are unscoped: nobody has "
                     f"declared them, which is what a shadow asset looks like.")
        return note


def merge(observations: Sequence[NameObservation], apex: str, scope: Scope
          ) -> Tuple[List[DiscoveredName], List[Excluded]]:
    """Fold sightings into names, applying scope to each one individually."""
    merged: Dict[str, DiscoveredName] = {}
    excluded: List[Excluded] = []
    refused: Set[str] = set()

    for observation in observations:
        name = str(observation.name).strip().lower().rstrip(".")
        if not name or name in refused:
            continue

        bare = name[2:] if name.startswith("*.") else name
        # kind=DOMAIN explicitly — see the module docstring. Without it a
        # repo_org rule would authorise DNS discovery.
        verdict = scope.resolve(bare, ScopeKind.DOMAIN)
        if verdict.decision is Decision.EXCLUDED:
            refused.add(name)
            excluded.append(Excluded(name, verdict.explain()))
            continue

        # Observed addresses are consulted too. The argument that a CDN address
        # should not become an asset justifies not EMITTING it; it does not
        # justify ignoring an operator who wrote "never touch this network".
        blocked = None
        for address in observation.addresses:
            address_verdict = scope.resolve(address, ScopeKind.CIDR)
            if address_verdict.decision is Decision.EXCLUDED:
                blocked = (f"{name} resolves to {address}, which "
                           f"{address_verdict.explain()} — matched via an "
                           f"observed address, not via the name")
                break
        if blocked:
            refused.add(name)
            excluded.append(Excluded(name, blocked))
            continue

        entry = merged.get(name)
        if entry is None:
            entry = DiscoveredName(name=name, is_wildcard=name.startswith("*."),
                                   decision=verdict.decision)
            merged[name] = entry
        entry.absorb(observation)

    # A name excluded by a later observation's address must not survive from an
    # earlier one that had no address to check.
    for name in refused:
        merged.pop(name, None)

    return sorted(merged.values(), key=lambda d: d.name), excluded


def to_inventory_rows(result: DiscoveryResult) -> List[Dict[str, Any]]:
    """Discovery output as inventory rows the scan reads.

    Wildcards are excluded: a wildcard certificate proves a certificate exists,
    never that a host does.
    """
    from core.provenance import write_rows

    rows: List[Dict[str, Any]] = []
    for name in result.names:
        if name.is_wildcard:
            continue
        row: Dict[str, Any] = {
            "identifier": name.name,
            # CT and passive DNS find NAMES, not technologies. `unknown` means
            # never fingerprinted — distinct from `unidentified`, which means
            # probed and nothing fired. Both are in match.STOPWORDS.
            "product": "unknown",
            "source": name.provenance,
        }
        row[observed("first_seen")] = str(name.first_seen or "")
        row[observed("last_seen")] = str(name.last_seen or "")
        row[observed("liveness")] = name.liveness
        row[observed("addresses")] = ",".join(sorted(name.addresses))
        row[observed("scope")] = name.decision.value
        rows.append(row)
    return write_rows(rows)


__all__ = ["NameObservation", "DiscoveredName", "Excluded", "DiscoveryResult",
           "merge", "to_inventory_rows"]
