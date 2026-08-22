"""What is in scope, and what is explicitly not.

SRS FR-M0-003. Scope is the boundary of everything this product is allowed to
look at, so its resolution has to be deterministic and arguable — a scope that
"probably" excludes something is not a control.

EXCLUDE ALWAYS WINS
-------------------
The acceptance criterion is one line — "overlapping include/exclude resolves
deterministically, exclude wins" — and it is the whole design. Not "the most
specific rule wins", not "the last rule wins": exclude wins, unconditionally,
whatever its specificity or order. Somebody writing an exclusion is saying "never
touch this", and every specificity scheme eventually produces a case where a
narrow include beats a broad exclude and the tool probes the thing it was told
not to. There is no ordering subtlety here on purpose.

INCLUSION IS NOT PERMISSION
---------------------------
Being in scope means "this belongs to the estate we are reasoning about". It does
NOT mean "this may be actively probed" — that requires verified ownership, which
is a separate record and a separate check (`core/ownership.py`), enforced in
`core/gate.py`. Conflating the two would let a customer authorise scanning by
typing a domain into a text box, which is precisely the failure mode
FR-GOV-001 exists to prevent.
"""
from __future__ import annotations

import enum
import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple


class ScopeKind(str, enum.Enum):
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    CIDR = "cidr"
    ASN = "asn"
    CLOUD_ACCOUNT = "cloud_account"
    REPO_ORG = "repo_org"
    APP_PUBLISHER = "app_publisher"


class Decision(str, enum.Enum):
    INCLUDED = "included"
    EXCLUDED = "excluded"
    #: Matched no rule at all. NOT the same as excluded — an asset nobody has
    #: spoken about is unknown, and the caller decides what unknown means. For
    #: active work it means refuse; for reporting it may mean "shadow asset".
    UNSCOPED = "unscoped"


_ASN = re.compile(r"^as(\d+)$", re.I)
_LABEL = re.compile(r"^[a-z0-9_-]+$")


def normalise_host(value: str) -> str:
    """Lower-case, strip a trailing dot, drop a leading wildcard label."""
    text = str(value or "").strip().lower().rstrip(".")
    return text[2:] if text.startswith("*.") else text


@dataclass(frozen=True)
class ScopeRule:
    kind: ScopeKind
    value: str
    is_exclude: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        if not str(self.value).strip():
            raise ValueError("a scope rule needs a value")

    @property
    def canonical(self) -> str:
        """The value in the one form matching compares against."""
        if self.kind in (ScopeKind.DOMAIN, ScopeKind.WILDCARD):
            return normalise_host(self.value)
        if self.kind is ScopeKind.CIDR:
            return str(ipaddress.ip_network(str(self.value).strip(), strict=False))
        if self.kind is ScopeKind.ASN:
            text = str(self.value).strip().lower()
            match = _ASN.match(text)
            return f"as{match.group(1)}" if match else text
        return str(self.value).strip()

    def matches(self, asset: str, kind: Optional[ScopeKind] = None) -> bool:
        """Does this rule speak about `asset`?"""
        if kind is not None and kind is not self.kind:
            # A CIDR rule never speaks about a GitHub org, even if the strings
            # happen to look alike.
            if not (kind in (ScopeKind.DOMAIN, ScopeKind.WILDCARD)
                    and self.kind in (ScopeKind.DOMAIN, ScopeKind.WILDCARD)):
                return False

        if self.kind is ScopeKind.DOMAIN:
            return normalise_host(asset) == self.canonical

        if self.kind is ScopeKind.WILDCARD:
            host, apex = normalise_host(asset), self.canonical
            # The dot is required. Without it `*.example.com` would claim
            # `notexample.com`, which is somebody else's domain.
            return host == apex or host.endswith("." + apex)

        if self.kind is ScopeKind.CIDR:
            try:
                address = ipaddress.ip_address(str(asset).strip())
            except ValueError:
                return False
            network = ipaddress.ip_network(self.canonical, strict=False)
            # Mixing families is not a match, and ip_network would raise.
            if address.version != network.version:
                return False
            return address in network

        if self.kind is ScopeKind.ASN:
            text = str(asset).strip().lower()
            match = _ASN.match(text)
            return (f"as{match.group(1)}" if match else text) == self.canonical

        return str(asset).strip().lower() == self.canonical.lower()


@dataclass(frozen=True)
class ScopeVerdict:
    decision: Decision
    #: Every rule that spoke about this asset, so the answer can be argued with
    #: rather than trusted. A verdict without its reasons is not reviewable.
    matched: Tuple[ScopeRule, ...] = ()

    @property
    def in_scope(self) -> bool:
        return self.decision is Decision.INCLUDED

    def explain(self) -> str:
        if not self.matched:
            return "no scope rule mentions this asset"
        excludes = [r for r in self.matched if r.is_exclude]
        if excludes:
            rule = excludes[0]
            return (f"excluded by {rule.kind.value} rule {rule.canonical!r}"
                    + (f" ({rule.note})" if rule.note else "")
                    + "; exclusion always wins over any include")
        rule = self.matched[0]
        return (f"included by {rule.kind.value} rule {rule.canonical!r}"
                + (f" ({rule.note})" if rule.note else ""))


class Scope:
    """A set of rules, and one deterministic answer per asset."""

    def __init__(self, rules: Iterable[ScopeRule] = ()) -> None:
        self._rules: List[ScopeRule] = list(rules)

    def add(self, rule: ScopeRule) -> None:
        if rule not in self._rules:
            self._rules.append(rule)

    @property
    def rules(self) -> Sequence[ScopeRule]:
        return tuple(self._rules)

    def resolve(self, asset: str, kind: Optional[ScopeKind] = None) -> ScopeVerdict:
        """The verdict for one asset.

        Order-independent by construction: every rule is evaluated, excludes are
        collected, and an exclude decides the outcome regardless of how many
        includes matched or which came first. Two scopes holding the same rules
        in different orders give the same answer, which is what makes this
        reviewable.
        """
        matched = tuple(r for r in self._rules if r.matches(asset, kind))
        if not matched:
            return ScopeVerdict(Decision.UNSCOPED, ())
        if any(r.is_exclude for r in matched):
            # Excludes first in the evidence, because they are the reason.
            ordered = tuple(sorted(matched, key=lambda r: not r.is_exclude))
            return ScopeVerdict(Decision.EXCLUDED, ordered)
        return ScopeVerdict(Decision.INCLUDED, matched)

    def includes(self, asset: str, kind: Optional[ScopeKind] = None) -> bool:
        return self.resolve(asset, kind).in_scope
