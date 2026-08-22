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
`Permit`, and a `Permit` can only come out of `authorise()` — every field that
decides what it authorises is covered by a seal the constructor verifies.

The first version of this used a sentinel object and was WRONG, in a way worth
recording because the mistake is easy to repeat. `dataclasses.replace()` copies
a sentinel field forward, so a PASSIVE permit — obtainable for any in-scope name
with no ownership proof whatsoever — could be mutated into an ACTIVE permit for
an arbitrary host, and the check passed. The test that was supposed to catch it
only covered DIRECT construction, so it went green. Frozen does not mean
immutable when the language ships a copy-with-changes helper.

The seal is honest about its limit (see `_SECRET`): it stops mutation and
accident, not code already running in this process.

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
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from core.ownership import OwnershipNotVerified, Verification
from core.scope import Decision, Scope, ScopeKind

#: Process-lifetime key that seals permits. A sentinel object was tried first and
#: was NOT enough: `dataclasses.replace()` copies a sentinel field forward, so a
#: PASSIVE permit — which needs no ownership proof at all — could be mutated into
#: an ACTIVE one for an arbitrary host, and __post_init__ would accept it. That
#: was measured, not theorised. A seal over the fields fixes it because mutating
#: any of them invalidates the seal.
#:
#: HONEST LIMIT: this defeats mutation, not a co-resident attacker. Anything
#: running in this process can read _SECRET and mint permits. The guarantee is
#: "a collector cannot casually or accidentally escalate", which is the threat
#: FR-GOV-001 is actually about; it is not a cryptographic boundary against code
#: already inside the process.
_SECRET = secrets.token_bytes(32)


def _seal(asset: str, operation: str, exposure: "Exposure", actor: str,
          addresses: Sequence[str] = ()) -> str:
    """Bind a permit to exactly the fields that decide what it authorises.

    Length-prefixed for the same reason core/audit.py is: without it, an asset
    named `a` with operation `bc` and one named `ab` with operation `c` seal
    identically, and a permit is precisely where somebody would try that.
    """
    parts = (str(asset), str(operation), str(getattr(exposure, "value", exposure)),
             str(actor), ",".join(sorted(str(a) for a in (addresses or ()))))
    material = "|".join(f"{len(x)}:{x}" for x in parts)
    return hmac.new(_SECRET, material.encode("utf-8"), hashlib.sha256).hexdigest()


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

    # --- P1 PASSIVE ---
    "subdomain_index_read": Exposure.PASSIVE,   # read a published name index
    "web_archive_search": Exposure.PASSIVE,     # query a crawl index
    # Live resolution through a THIRD-PARTY recursive resolver. Distinct from
    # `passive_dns` above, which is pinned to its industry meaning: querying a
    # HISTORICAL passive-DNS database, zero packets toward the name. This one
    # emits packets. Both are passive; the audit log must tell them apart.
    #
    # It is PASSIVE for two reasons, the second decisive. The customer's
    # authoritative servers see a query from the RESOLVER's address, unattributed
    # and cache-damped. And `Method.DNS_TXT` ownership verification is itself a
    # DNS resolution — classifying resolution ACTIVE would make ownership
    # verification require ownership verification, and nothing could bootstrap.
    "dns_resolve_recursive": Exposure.PASSIVE,
    "rdap_lookup": Exposure.PASSIVE,            # registration status of a domain

    # --- P1 ACTIVE ---
    "dns_resolve_authoritative": Exposure.ACTIVE,  # RD=0, at the customer's NS
    # A synthesised label is a guaranteed cache miss, so 100% of these reach the
    # customer's authoritative servers — the exact opposite of the damping that
    # makes recursive resolution passive. A stream of them under one zone is the
    # textbook water-torture signature and will be read as an attack.
    "dns_wildcard_probe": Exposure.ACTIVE,
    "service_banner_read": Exposure.ACTIVE,     # read-only greeting, non-web port

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
    _token: str = field(default="", repr=False, compare=False)
    #: Addresses this permit authorises contact with. Empty means name-only, and
    #: `egress.tcp` refuses to connect on a name-only permit for ACTIVE work.
    addresses: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        expected = _seal(self.asset, self.operation, self.exposure, self.actor,
                         self.addresses)
        if not hmac.compare_digest(str(self._token or ""), expected):
            raise PermissionError(
                "a Permit may only be issued by core.gate.authorise(); "
                "constructing or MUTATING one bypasses FR-GOV-001. "
                "dataclasses.replace() on a Permit is not a way to change what "
                "it authorises — ask the gate again.")


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
                      _token=_seal(asset, operation, exposure, actor))

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
                  _token=_seal(asset, operation, exposure, actor))


#: Operations whose delivery is to an ADDRESS rather than a name, and which
#: therefore need at least one address positively in scope. An HTTP request is
#: routed by Host header and lands on a tenant; a port sweep is delivered to
#: whatever answers the address, which may be a CDN edge shared with thousands.
_ADDRESS_DELIVERED = frozenset({"port_scan", "service_banner_read"})


def authorise_target(asset: str,
                     addresses: Sequence[str],
                     operation: str,
                     actor: str,
                     scope: Scope,
                     verification: Optional[Verification] = None,
                     kind: Optional[ScopeKind] = None,
                     today: Optional[date] = None) -> Permit:
    """`authorise()` for the name, then the addresses. Strictly narrower.

    WHY THE NAME IS NOT ENOUGH — measured, and it makes D10 false as written.
    A `ScopeRule(CIDR, "104.18.0.0/16", is_exclude=True)` can never fire for a
    hostname: `scope.resolve("api.example.com", DOMAIN)` is INCLUDED while
    `scope.resolve("104.18.5.7", CIDR)` is EXCLUDED, and the name-based path
    never consults the address. So "exclude wins unconditionally" silently loses
    for exactly the operations that do the connecting.

    The tempting counter-argument — that a Host-routed HTTPS request only reaches
    the customer's tenant — is false at the transport layer. The TCP connection,
    the TLS handshake, the resource consumption and the abuse report all land on
    whoever owns the address.
    """
    permit = authorise(asset, operation, actor, scope, verification, kind, today)
    supplied = tuple(str(a).strip() for a in (addresses or ()) if str(a).strip())

    if permit.exposure is not Exposure.ACTIVE:
        # Passive work does not connect to the asset, so addresses do not
        # constrain it. Sealing them anyway would only invite a caller to pass
        # something meaningless and believe it was checked.
        return permit

    if not supplied:
        raise NotInScope(
            f"{asset}: an active operation must be authorised against the "
            f"addresses it will actually reach; none were supplied. Resolve the "
            f"name first and pass the addresses, so CIDR exclusions can apply.")

    op = str(operation).strip().lower()

    for address in supplied:
        verdict = scope.resolve(address, ScopeKind.CIDR)
        if verdict.decision is Decision.EXCLUDED:
            raise NotInScope(
                f"{asset} resolves to {address}, which {verdict.explain()}. "
                f"The request would be delivered to an address the operator "
                f"excluded, whatever the name says.")

    if op in _ADDRESS_DELIVERED:
        included = [a for a in supplied
                    if scope.resolve(a, ScopeKind.CIDR).decision is Decision.INCLUDED]
        if not included:
            # Ownership is proven over a NAME. A sweep is delivered to an
            # ADDRESS. A name pointed at a CDN or a SaaS tenant would otherwise
            # authorise sweeping a third party who consented to nothing.
            asn_rules = [r for r in scope.rules if r.kind is ScopeKind.ASN]
            hint = ""
            if asn_rules:
                # Measured: scope.resolve("203.0.113.10", ScopeKind.ASN) is
                # UNSCOPED — there is no IP-to-ASN mapping in this product, so an
                # ASN rule cannot authorise an address. Say so rather than
                # letting the operator believe their rule covers this.
                hint = (" ASN rules exist in scope but cannot be resolved against "
                        "an address in this release; add an equivalent CIDR rule.")
            raise NotInScope(
                f"{asset}: {operation!r} is delivered to an address, and none of "
                f"{', '.join(supplied)} is INCLUDED by a CIDR rule. Proving you "
                f"own the name does not establish that you own what it points "
                f"at.{hint}")

    return Permit(asset=permit.asset, operation=permit.operation,
                  exposure=permit.exposure, actor=permit.actor,
                  rationale=permit.rationale + f"; addresses {', '.join(supplied)}",
                  _token=_seal(permit.asset, permit.operation, permit.exposure,
                               permit.actor, supplied),
                  addresses=supplied)


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


def plan(assets: Sequence[str], operation: str, actor: str, scope: Scope,
         verifications: Mapping[str, Optional[Verification]],
         kind: Optional[ScopeKind] = None,
         today: Optional[date] = None) -> Tuple[List[str], List[str]]:
    """What a run WOULD touch, and what it would refuse — using real records.

    This is what a --dry-run must call. `refusal_reasons()` cannot answer the
    question: it passes verification=None, so for any ACTIVE operation it reports
    every asset as unverified by construction. An operator previewing a port
    sweep would be told nothing will be touched, then watch the real run touch
    things — which is worse than having no preview, because it is a preview that
    is confidently wrong.

    Returns `(would_run, refusals)`. Both are returned because a preview that
    shows only one of them is half an answer.
    """
    would_run: List[str] = []
    refusals: List[str] = []
    for asset in assets:
        try:
            authorise(asset, operation, actor, scope,
                      verifications.get(asset), kind, today)
            would_run.append(asset)
        except (OperationRefused, NotInScope, OwnershipNotVerified) as exc:
            refusals.append(f"{asset}: {exc}")
    return would_run, refusals


def refusal_reasons(assets: Sequence[str], operation: str, actor: str,
                    scope: Scope, today: Optional[date] = None) -> List[str]:
    """Why each asset would be refused WITH NO VERIFICATIONS AT ALL.

    Note the qualifier — it is not the question an operator previewing a run is
    asking, because every ACTIVE operation comes back refused regardless of what
    is on record. Use `plan()` for that. This remains for the case it does answer:
    which assets are refused for a reason ownership cannot fix (out of scope,
    excluded, prohibited operation).
    """
    reasons: List[str] = []
    for asset in assets:
        try:
            authorise(asset, operation, actor, scope, None, None, today)
        except (OperationRefused, NotInScope, OwnershipNotVerified) as exc:
            reasons.append(f"{asset}: {exc}")
    return reasons
