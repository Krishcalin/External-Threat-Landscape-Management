"""Dangling records, and how far this product is willing to go about them.

THERE IS NO `vulnerable` TIER, IN THIS PHASE OR ANY LATER ONE
------------------------------------------------------------
The only experiment that upgrades "this looks claimable" to "this IS claimable"
is registering the resource. That is `exploit_attempt`, which `core/gate.py`
refuses before scope or ownership are even consulted. So the ceiling is
permanent, and the reason stated to the reader is CAPABILITY, not caution: we
did not run the confirming experiment because this product refuses to run it.
Said plainly here so a future contributor reads the ceiling as a decision rather
than an unfinished feature.

WHAT P1 SHIPS, AND WHAT IT DOES NOT
-----------------------------------
`CLAIMABLE_LOOKING` is NOT reachable in this phase. Confirming a dangling
provider hostname needs an HTTP fetch of the CNAME target, which is ACTIVE work
against a THIRD PARTY's host — and the customer's ownership verification cannot
authorise that. Worse, the name that most needs probing is the one that
structurally cannot be verified: RFC 1034 forbids a CNAME coexisting with any
other record at the same name, so no DNS TXT can be placed there, and
`/.well-known` cannot be served because the name points somewhere the customer
does not control.

So P1 caps the provider case at `INCONCLUSIVE` / `PROVIDER_GUARDED` and counts
`probes_unavailable` rather than pretending the question was answered.

`REGISTRABLE_DOMAIN_UNREGISTERED` is the headline finding and is FULLY PASSIVE.
A CNAME or NS pointing at a domain whose registration has lapsed is takeable by
anyone for the price of a registration — no provider account, no probe — and
RDAP answers it outright.

`NO_CLAIM_SIGNAL_FOUND`, NOT `NOT_CLAIMABLE`
--------------------------------------------
The negative is one this product cannot establish. A dangling CNAME pointing at
a provider missing from the rule catalogue, or one whose unclaimed-page
behaviour changed since the rules were last reviewed, would be returned as
"safe" — and it would render identically to a resource an attacker has ALREADY
claimed. The verdict says what was looked for and what was not.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import date
from typing import Dict, List, Optional, Sequence, Tuple


class TakeoverVerdict(str, enum.Enum):
    #: Determinable in P1, fully passive, and the strongest thing we can say.
    REGISTRABLE_DOMAIN_UNREGISTERED = "registrable_domain_unregistered"
    #: NOT reachable in P1 — see the module docstring.
    CLAIMABLE_LOOKING = "claimable_looking"
    PROVIDER_GUARDED = "provider_guarded"
    INTERNAL_DANGLING = "internal_dangling"
    NO_CLAIM_SIGNAL_FOUND = "no_claim_signal_found"
    INCONCLUSIVE = "inconclusive"


class Corroboration(str, enum.Enum):
    #: Bound to exactly one producer: an RDAP lookup saying the registrable
    #: domain is unregistered. Anything else would be dead vocabulary
    #: advertising a tier this product refuses to reach.
    REGISTRATION_OPEN = "registration_open"
    PROVIDER_RULE = "provider_rule"
    NONE = "none"


class RegistrationStatus(str, enum.Enum):
    REGISTERED = "registered"
    UNREGISTERED = "unregistered"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TakeoverEvidence:
    """Everything a reader needs to disagree with the verdict.

    Frozen and fully required. A finding cannot be constructed without the CNAME
    target, what the resolvers said about it, and how many of them said it —
    which makes "mandatory evidence" a property of the type rather than a rule
    somebody has to remember.
    """

    name: str
    target: str
    target_rcode: str
    #: How many resolvers agreed. A single-resolver claim is one party's word.
    resolvers_agreeing: int
    resolvers_queried: int
    chain: Tuple[str, ...] = ()
    registrable_domain: Optional[str] = None
    registration_status: RegistrationStatus = RegistrationStatus.UNKNOWN
    rdap_response: str = ""
    provider: Optional[str] = None
    rule_catalogue_version: str = ""
    rule_last_reviewed: str = ""
    observed_at: Optional[date] = None

    def __post_init__(self) -> None:
        if not str(self.name).strip():
            raise ValueError("takeover evidence must name the record")
        if not str(self.target).strip():
            raise ValueError(
                "takeover evidence must record the CNAME target. A claim that a "
                "name is hijackable without saying what it points at is not "
                "reviewable, and this product does not make it.")
        if not str(self.target_rcode).strip():
            raise ValueError(
                "takeover evidence must record what the resolvers said about "
                "the target")
        if self.resolvers_queried <= 0:
            raise ValueError("takeover evidence must record how many resolvers "
                             "were asked")


@dataclass(frozen=True)
class TakeoverFinding:
    """A verdict, its corroboration, its evidence, and why. All four required."""

    verdict: TakeoverVerdict
    corroboration: Corroboration
    evidence: TakeoverEvidence
    reasons: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.reasons:
            raise ValueError("a takeover finding must say why")
        if (self.corroboration is Corroboration.REGISTRATION_OPEN
                and self.verdict is not
                TakeoverVerdict.REGISTRABLE_DOMAIN_UNREGISTERED):
            raise ValueError(
                "REGISTRATION_OPEN corroborates exactly one verdict — an "
                "unregistered registrable domain. Attaching it elsewhere would "
                "advertise a confidence tier this product refuses to reach.")
        if self.verdict is TakeoverVerdict.CLAIMABLE_LOOKING:
            raise ValueError(
                "CLAIMABLE_LOOKING is not reachable in this phase: confirming it "
                "requires an active HTTP probe of a third party's host, which "
                "the customer's ownership verification cannot authorise. See "
                "the module docstring.")
        if (self.verdict is TakeoverVerdict.REGISTRABLE_DOMAIN_UNREGISTERED
                and self.evidence.registration_status
                is not RegistrationStatus.UNREGISTERED):
            raise ValueError(
                "an unregistered-domain verdict requires an RDAP answer saying "
                "so; without it this is INCONCLUSIVE")
        if self.evidence.resolvers_agreeing < 2:
            # One resolver can be poisoned, censored, or simply wrong, and a
            # takeover finding is exactly the kind of claim somebody would try
            # to manufacture.
            raise ValueError(
                f"a takeover finding needs at least two agreeing resolvers; "
                f"this has {self.evidence.resolvers_agreeing}")

    def explain(self) -> str:
        return (f"{self.evidence.name} -> {self.evidence.target}: "
                f"{meaning(self.verdict, self.evidence)}")


def meaning(verdict: TakeoverVerdict,
            evidence: Optional[TakeoverEvidence] = None) -> str:
    """What a verdict means, including what was NOT established."""
    if verdict is TakeoverVerdict.REGISTRABLE_DOMAIN_UNREGISTERED:
        return ("the registrable domain this record points at is not registered. "
                "Anyone can register it for the price of a domain and take "
                "control of this name. No provider account is required, which is "
                "what makes this the strongest takeover finding available "
                "passively.")
    if verdict is TakeoverVerdict.PROVIDER_GUARDED:
        detail = ""
        if evidence and evidence.rule_catalogue_version:
            detail = (f" (per rule catalogue {evidence.rule_catalogue_version}, "
                      f"provider policy last reviewed "
                      f"{evidence.rule_last_reviewed or 'unrecorded'})")
        return (f"the record dangles, but the provider is known to reserve "
                f"released hostnames against re-registration{detail}. That is a "
                f"statement about the provider's policy at a point in time, not "
                f"a guarantee about today.")
    if verdict is TakeoverVerdict.INTERNAL_DANGLING:
        return ("the record points somewhere that does not resolve publicly. "
                "Not claimable from outside, but it is a broken record and may "
                "be reachable from inside the network.")
    if verdict is TakeoverVerdict.NO_CLAIM_SIGNAL_FOUND:
        return ("nothing was found that suggests this is claimable. NOT the same "
                "as safe: a provider missing from the rule catalogue, or one "
                "whose behaviour changed since the rules were reviewed, would "
                "look exactly like this — and so would a resource an attacker "
                "has already claimed.")
    if verdict is TakeoverVerdict.INCONCLUSIVE:
        return ("the record dangles and this product could not establish more. "
                "Confirming would require actively probing a third party's host, "
                "which no ownership verification of yours can authorise, so it "
                "was not attempted. This is a capability boundary, not caution.")
    return ("this verdict is not reachable in this phase; see core/takeover.py")


TAKEOVER_MEANING: Dict[str, str] = {v.value: meaning(v) for v in TakeoverVerdict}


@dataclass
class TakeoverReport:
    findings: List[TakeoverFinding]
    #: Records that dangle but could not be assessed further without an active
    #: probe. Counted, never silently absent.
    probes_unavailable: int = 0
    assessed: int = 0

    def note(self) -> str:
        parts = [f"{len(self.findings)} takeover finding(s) across "
                 f"{self.assessed} dangling record(s)"]
        if self.probes_unavailable:
            parts.append(
                f"{self.probes_unavailable} could not be taken further without "
                f"an ACTIVE probe of a third party's host. This product does "
                f"not do that, so those remain inconclusive by design rather "
                f"than by omission.")
        return ". ".join(parts) + "."


__all__ = ["TakeoverVerdict", "Corroboration", "RegistrationStatus",
           "TakeoverEvidence", "TakeoverFinding", "TakeoverReport",
           "TAKEOVER_MEANING", "meaning"]
