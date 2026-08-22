"""The one place that decides whether SKOPOS may touch something.

SRS FR-GOV-001: active collection against an asset whose ownership has not been
verified must fail closed. FR-GOV-003: no authenticating to or transacting on
access-controlled criminal forums, ever. FR-GOV-007: no offensive capability.

WHY THE CHECK IS HERE AND NOT IN THE COLLECTORS
-----------------------------------------------
A rule enforced inside each collector is a rule that holds for exactly the
collectors that remembered it. SKOPOS is meant to take third-party collector
plugins, so "every collector checks ownership first" is a convention a plugin
author can forget, misread, or ignore — and the failure is silent: the plugin
works, it just probes things it should not have.

So the collectors do not check anything. They cannot run at all without a
`Permit`, and a `Permit` can only come out of `authorise()`. A plugin that wants
to skip the gate has to fabricate one, and the constructor refuses to build a
Permit without a token this module never hands out. That turns a convention into
a structural property: the unsafe path is not discouraged, it is unavailable.

THREE ANSWERS, NOT TWO
----------------------
Passive collection — reading certificate transparency logs, fetching a public
leak-site index page — touches infrastructure that is not the customer's and
observes what is already published. Requiring proof of ownership for it would be
theatre, and worse, it would train users to click through ownership prompts.

Active collection — connecting to the asset, probing a port, requesting a page —
requires proof, because getting it wrong means scanning somebody else's estate.

Prohibited operations are refused whatever the paperwork says. Verified ownership
of a domain does not authorise logging into a criminal forum, and no customer can
consent on behalf of the third parties such an operation would affect. These are
refused before scope and ownership are consulted at all, so the refusal cannot be
argued with by adding a scope rule.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional, Sequence

from core.ownership import OwnershipNotVerified, Verification
from core.scope import Decision, Scope, ScopeKind

#: Handed to Permit's constructor and nowhere else. The point is not secrecy but
#: that constructing a Permit outside authorise() is obviously wrong to anyone
#: reading the code, and fails immediately for anyone who tries it anyway.
_ISSUER = object()


class Exposure(str, enum.Enum):
    """What an operation actually does to the outside world."""

    #: Observes third-party or public sources. Touches nothing the customer owns.
    PASSIVE = "passive"
    #: Connects to the asset itself. Needs proof of ownership.
    ACTIVE = "active"
    #: Refused unconditionally. See FR-GOV-003 and FR-GOV-007.
    PROHIBITED = "prohibited"


#: The registry lives here rather than on each collector, for the same reason the
#: check does: a collector that classifies itself can classify itself PASSIVE.
OPERATIONS: Dict[str, Exposure] = {
    "ct_log_search": Exposure.PASSIVE,
    "passive_dns": Exposure.PASSIVE,
    "whois_lookup": Exposure.PASSIVE,
    "leak_site_index_read": Exposure.PASSIVE,
    "overwatch_ingest": Exposure.PASSIVE,

    "http_probe": Exposure.ACTIVE,
    "tls_handshake": Exposure.ACTIVE,
    "port_scan": Exposure.ACTIVE,
    "dns_zone_transfer": Exposure.ACTIVE,
    "subdomain_bruteforce": Exposure.ACTIVE,

    # FR-GOV-003: reading a public index page is passive collection; presenting
    # credentials to get past a login is participation, and it is not something
    # this product does.
    "forum_authenticate": Exposure.PROHIBITED,
    "forum_transact": Exposure.PROHIBITED,
    # FR-GOV-007: deception assets are sensors. Nothing here attacks anything.
    "exploit_attempt": Exposure.PROHIBITED,
    "credential_replay": Exposure.PROHIBITED,
}


class OperationRefused(PermissionError):
    """The operation is not one this product performs, at any authorisation."""


class NotInScope(PermissionError):
    """The asset is outside the declared estate, or explicitly excluded."""


@dataclass(frozen=True)
class Permit:
    """Proof that the gate said yes. Collectors take one; they cannot make one."""

    asset: str
    operation: str
    exposure: Exposure
    actor: str
    #: Why it was granted, in words, so an audit payload is not a bare "allowed".
    rationale: str = ""
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _ISSUER:
            raise PermissionError(
                "a Permit may only be issued by core.gate.authorise(); "
                "constructing one directly bypasses FR-GOV-001")


def classify(operation: str) -> Exposure:
    """What an operation is, refusing to guess.

    An unregistered operation is PROHIBITED rather than assumed passive. A new
    collector whose author forgot to register it should fail loudly on its first
    run, not reach the internet under a permissive default.
    """
    return OPERATIONS.get(str(operation).strip().lower(), Exposure.PROHIBITED)


def authorise(asset: str,
              operation: str,
              actor: str,
              scope: Scope,
              verification: Optional[Verification] = None,
              kind: Optional[ScopeKind] = None,
              today: Optional[date] = None) -> Permit:
    """Decide, or raise. There is no return value meaning no."""
    exposure = classify(operation)

    # Prohibited first, before scope or ownership are consulted. Ordering it this
    # way means the refusal cannot be talked around by adding a scope rule or
    # completing a verification.
    if exposure is Exposure.PROHIBITED:
        registered = str(operation).strip().lower() in OPERATIONS
        raise OperationRefused(
            f"{operation!r} is refused: "
            + ("this product does not perform it, and no authorisation changes "
               "that (FR-GOV-003 / FR-GOV-007)"
               if registered else
               "it is not a registered operation. Unregistered operations are "
               "refused rather than assumed harmless — register it in "
               "core.gate.OPERATIONS with an honest exposure classification."))

    verdict = scope.resolve(asset, kind)
    if verdict.decision is not Decision.INCLUDED:
        # UNSCOPED and EXCLUDED both refuse, but they are different mistakes and
        # the message says which: one is a missing rule, the other is a rule
        # somebody wrote on purpose and should not be edited away casually.
        raise NotInScope(
            f"{asset}: {verdict.explain()}. "
            + ("Add it to scope if it belongs to the estate."
               if verdict.decision is Decision.UNSCOPED else
               "An exclusion is a deliberate instruction not to touch this."))

    if exposure is Exposure.PASSIVE:
        return Permit(asset=asset, operation=operation, exposure=exposure,
                      actor=actor,
                      rationale=f"passive collection; {verdict.explain()}",
                      _token=_ISSUER)

    # ACTIVE from here down: ownership must be proven, for this asset, and current.
    if verification is None:
        raise OwnershipNotVerified(
            f"{asset}: no ownership verification on record, so active operation "
            f"{operation!r} is refused. Being in scope means the asset belongs "
            f"to the estate under discussion; it does not establish that you "
            f"control it.")

    if verification.asset.strip().lower() != str(asset).strip().lower():
        # A verification for a different name is not evidence about this one, and
        # accepting it would let one proven domain unlock every other.
        raise OwnershipNotVerified(
            f"{asset}: the verification on record is for "
            f"{verification.asset!r}, not this asset.")

    if not verification.is_current(today):
        raise OwnershipNotVerified(
            f"{verification.explain(today)} — active operation {operation!r} "
            f"refused.")

    return Permit(asset=asset, operation=operation, exposure=exposure,
                  actor=actor,
                  rationale=f"active collection; {verification.explain(today)}",
                  _token=_ISSUER)


def is_permitted(asset: str, operation: str, actor: str, scope: Scope,
                 verification: Optional[Verification] = None,
                 kind: Optional[ScopeKind] = None,
                 today: Optional[date] = None) -> bool:
    """A boolean form, for UI affordances only.

    Never use this to decide whether to collect — call `authorise()` and hold the
    Permit. A boolean can be computed once and acted on much later, by which time
    a verification may have expired.
    """
    try:
        authorise(asset, operation, actor, scope, verification, kind, today)
        return True
    except (OperationRefused, NotInScope, OwnershipNotVerified):
        return False


def refusal_reasons(assets: Sequence[str], operation: str, actor: str,
                    scope: Scope, today: Optional[date] = None) -> List[str]:
    """Explain, for a batch, why each asset would be refused.

    Exists so an operator planning a run sees every problem at once, rather than
    fixing one asset, re-running, and hitting the next.
    """
    reasons: List[str] = []
    for asset in assets:
        try:
            authorise(asset, operation, actor, scope, None, None, today)
        except (OperationRefused, NotInScope, OwnershipNotVerified) as exc:
            reasons.append(f"{asset}: {exc}")
    return reasons
