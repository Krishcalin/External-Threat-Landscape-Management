"""Type a domain or an address, and see what the public record says.

WHAT THIS REUSES RATHER THAN REBUILDS
--------------------------------------
`core/suppliers.assess()` already reads SPF, DMARC, MTA-STS, CAA, certificate
expiry and registrar lock from records a domain publishes. That IS the posture
half of this lookup, so it is called rather than reimplemented — a second
assessment of the same records would drift from the first and the two would
disagree on screen.

What is new here is target parsing, name discovery, and a score.

THE SCORE, AND WHY IT IS NOT A GRADE
-------------------------------------
The direction asked for "risks, rating, probability". A single composite letter
is the artefact this product refuses, for the same reason it refuses a
compliance coverage percentage: it gets screenshotted, shown to somebody
senior, and its inputs never travel with it.

So this score carries the TEPS contract, which the product already applies to
findings:

  * it is always DECOMPOSED — every factor, its value and its inputs come back
    in the same payload, never on a second request somebody has to know to make;
  * it REFUSES to render below `MIN_FACTORS` observed factors, rather than
    scoring what it happened to see and presenting it as whole;
  * a factor nobody could observe is UNOBSERVED, never zero. Scoring an
    unobserved factor as zero is how "we have no Shodan key" becomes "this host
    exposes nothing".

That last one is the whole reason the keyed sources are modelled as absent
rather than skipped. Without a Shodan key this lookup cannot see open ports, and
a clean-looking result that does not say so is a lie of omission.

WHAT A CIDR CAN HONESTLY YIELD, WHICH IS LESS THAN IT SOUNDS
-------------------------------------------------------------
For an address there is no certificate transparency, no SPF, no DMARC. What is
passively available is RDAP (who the block is allocated to) and reverse DNS. Port
and service data needs either an active probe — refused against anything
unverified — or a third party who already scanned it, which is Shodan and needs
a key. So a /24 lookup with no key returns allocation and PTR records and says
plainly that it cannot see services. That is the honest answer, and it is worth
having: it is more than most people know about a block they were handed.
"""
from __future__ import annotations

import enum
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Sequence

from core import suppliers

#: A lookup with fewer than this many OBSERVED factors gets no score. Two is not
#: a posture, it is two facts, and averaging them into a number invites somebody
#: to compare it against a target that saw four.
MIN_FACTORS = 3

#: A /24 is 256 addresses and the passive work is per-address. Larger blocks are
#: refused rather than silently truncated: a lookup that quietly examined the
#: first 256 of a /16 would report a clean result for a block it barely touched.
MAX_CIDR_HOSTS = 256

_DOMAIN = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Kind(str, enum.Enum):
    DOMAIN = "domain"
    HOST = "host"
    ADDRESS = "address"
    BLOCK = "block"


class TargetError(ValueError):
    """Something this lookup will not accept, with the reason a user sees."""


@dataclass(frozen=True)
class Target:
    raw: str
    kind: Kind
    value: str
    #: For a block, the addresses it expands to. Bounded by MAX_CIDR_HOSTS.
    addresses: Sequence[str] = ()

    @property
    def is_network(self) -> bool:
        return self.kind in (Kind.ADDRESS, Kind.BLOCK)

    def to_dict(self) -> Dict[str, Any]:
        return {"raw": self.raw, "kind": self.kind.value, "value": self.value,
                "addresses": list(self.addresses)}


def parse(raw: str) -> Target:
    """Classify what was typed, or refuse it with a reason.

    A URL is accepted and reduced to its host, because people paste URLs. An
    email address is refused HERE rather than half-handled: breach exposure for
    an address is a different question with a different source, and answering it
    from this function would mean one screen quietly doing two unrelated things.
    """
    text = str(raw or "").strip().lower()
    if not text:
        raise TargetError("nothing to look up")

    # People paste URLs. Take the host and carry on rather than making them edit.
    if "://" in text:
        text = text.split("://", 1)[1]

    # STRIP THE PATH, BUT NOT A CIDR PREFIX. Splitting on "/" unconditionally
    # turned 203.0.113.0/24 into the single address 203.0.113.0 and — worse —
    # let 10.0.0.0/8 through the size guard entirely, because by the time the
    # guard ran there was no prefix left to be too large.
    prefix_only = re.match(r"^([0-9a-f:.]+)/(\d{1,3})$", text)
    if not prefix_only:
        text = text.split("/")[0]
    text = text.split("?")[0].strip(".")

    if "@" in text and _EMAIL.match(str(raw).strip()):
        raise TargetError(
            "that is an email address. This lookup answers questions about "
            "hosts and networks; breach exposure for an address is a different "
            "question with a different source, and answering it here would mean "
            "one box quietly doing two unrelated things")
    if ":" in text and not text.count(":") > 1:
        text = text.rsplit(":", 1)[0]          # host:port

    try:
        # strict=False so 203.0.113.5/24 is accepted as the block it names —
        # people paste an address with a mask and mean the network. The
        # normalised value is returned, so what was examined is never ambiguous.
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        network = None

    if network is not None:
        if network.num_addresses == 1:
            return Target(raw=str(raw), kind=Kind.ADDRESS,
                          value=str(network.network_address),
                          addresses=(str(network.network_address),))
        if network.num_addresses > MAX_CIDR_HOSTS:
            raise TargetError(
                f"{network} holds {network.num_addresses:,} addresses. This "
                f"lookup examines at most {MAX_CIDR_HOSTS} — a larger block "
                f"would be silently truncated, and a clean result for a block "
                f"that was barely touched is worse than a refusal")
        # EVERY address, not `.hosts()`. `.hosts()` drops the network and
        # broadcast addresses, so 8.8.8.8/29 examined .9 through .14 and
        # silently skipped 8.8.8.8 — the address the user actually typed.
        #
        # Those addresses can carry PTR records like any other, and for a
        # passive lookup "usable host" is not the relevant distinction; being
        # in the block is.
        return Target(raw=str(raw), kind=Kind.BLOCK, value=str(network),
                      addresses=tuple(str(a) for a in network))

    if not _DOMAIN.match(text):
        raise TargetError(
            f"{raw!r} is not a domain, a hostname, an IP address or a CIDR "
            f"block. Those are what this lookup can ask about.")

    # A name with more labels than its registrable form is a host; the
    # distinction changes what is worth asking. There is no public-suffix list
    # vendored here, so this is a heuristic and is labelled as one — it changes
    # presentation, never whether an operation is permitted.
    labels = text.split(".")
    kind = Kind.HOST if len(labels) > 2 else Kind.DOMAIN
    return Target(raw=str(raw), kind=kind, value=text)


# ── the score ────────────────────────────────────────────────────────────────
class Factor(str, enum.Enum):
    """One dimension of the score. Each states what it can and cannot see."""

    SURFACE = "surface"
    POSTURE = "posture"
    REGISTRATION = "registration"
    REPUTATION = "reputation"

    @property
    def measures(self) -> str:
        return {
            Factor.SURFACE: "how much of this target is publicly visible — "
                            "names in certificate transparency, addresses that "
                            "resolve",
            Factor.POSTURE: "how far the owner took the controls they publish: "
                            "DMARC enforcement, MTA-STS, CAA",
            Factor.REGISTRATION: "registration hygiene — transfer lock, and how "
                                 "close the certificate is to expiry",
            Factor.REPUTATION: "what third-party scanners and abuse feeds say "
                               "about it",
        }[self]

    @property
    def cannot_see(self) -> str:
        return {
            Factor.SURFACE: "a name that has never had a certificate and has "
                            "never resolved publicly is invisible here, and "
                            "that is not the same as it not existing",
            Factor.POSTURE: "presence of SPF and DMARC is near-universal and "
                            "measures nothing; only enforcement discriminates. "
                            "None of it says their mail is actually secure",
            Factor.REGISTRATION: "nothing about the registrar account itself, "
                                 "which is what a transfer lock does not protect",
            Factor.REPUTATION: "OPEN PORTS AND RUNNING SERVICES. That needs an "
                               "active probe, which is refused against anything "
                               "whose ownership is unproven, or a third party "
                               "who already scanned it — which needs a key",
        }[self]


@dataclass
class Score:
    """A number that arrives with its own decomposition, or does not arrive."""

    factors: Dict[str, Optional[float]] = field(default_factory=dict)
    inputs: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def observed(self) -> List[str]:
        return [name for name, value in self.factors.items() if value is not None]

    @property
    def unobserved(self) -> List[str]:
        return [name for name, value in self.factors.items() if value is None]

    @property
    def publishable(self) -> bool:
        return len(self.observed) >= MIN_FACTORS

    @property
    def value(self) -> Optional[int]:
        """0-100, or None. None is a real answer and is rendered as one."""
        if not self.publishable:
            return None
        seen = [self.factors[name] for name in self.observed]
        return int(round(100 * sum(seen) / len(seen)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "publishable": self.publishable,
            "minimum_factors": MIN_FACTORS,
            # ALWAYS present, never behind a second request. A score whose
            # decomposition is one click away arrives alone in a screenshot.
            "factors": {
                name: {
                    "value": value,
                    "observed": value is not None,
                    "inputs": self.inputs.get(name, []),
                    "measures": Factor(name).measures,
                    "cannot_see": Factor(name).cannot_see,
                }
                for name, value in self.factors.items()
            },
            "refusal": None if self.publishable else (
                f"Only {len(self.observed)} of {len(self.factors)} factors could "
                f"be observed, and {MIN_FACTORS} are needed. No score is shown: "
                f"averaging what happened to be visible produces a number that "
                f"looks comparable to one drawn from four factors and is not. "
                f"The factors themselves are below, with what each could not see."),
            "not_a_grade": (
                "This is not a letter grade and does not compare organisations. "
                "It summarises what is PUBLICLY OBSERVABLE about one target, "
                "from sources that are named beside every factor. An unobserved "
                "factor is never scored as zero — see `unobserved`."),
            "unobserved": self.unobserved,
        }


@dataclass
class Lookup:
    target: Target
    posture: Optional[suppliers.Posture] = None
    names: List[str] = field(default_factory=list)
    registration: Dict[str, Any] = field(default_factory=dict)
    reverse_dns: Dict[str, str] = field(default_factory=dict)
    #: Sources that were not consulted, and why. NEVER silently dropped: a
    #: result that omits Shodan without saying so reads as "no open ports".
    unavailable: List[Dict[str, str]] = field(default_factory=list)
    reports: List[Any] = field(default_factory=list)
    #: Vendored abuse-feed membership, from `core/blocklists.py`. Empty is not
    #: "clean" — `abuse_coverage` carries the sentence that says so, and the
    #: two travel together for exactly that reason.
    abuse: List[Dict[str, Any]] = field(default_factory=list)
    abuse_coverage: Dict[str, Any] = field(default_factory=dict)
    #: Ransomware leak-site listings matching this target, from
    #: `collect/leaksites.py`. A CLAIM BY A GROUP, never a confirmed breach.
    leak_listings: List[Dict[str, Any]] = field(default_factory=list)
    leak_coverage: Dict[str, Any] = field(default_factory=dict)
    #: Certificate posture from the SAME CT read discovery already performs —
    #: the fields `from_certspotter` discards. See collect/ct.py.
    certificates: List[Dict[str, Any]] = field(default_factory=list)
    certificate_lineage: Dict[str, Any] = field(default_factory=dict)
    certificate_coverage: Dict[str, Any] = field(default_factory=dict)
    #: Organisation names a CA validated on certificates for this target.
    #: QUESTIONS for the triage queue, never additions to scope.
    subsidiary_candidates: List[Dict[str, Any]] = field(default_factory=list)

    def score(self) -> Score:
        result = Score()
        result.factors = {f.value: None for f in Factor}

        # SURFACE — how much is visible. More visible is not automatically
        # worse, so this measures whether we saw ENOUGH to say anything.
        if self.names or self.reverse_dns:
            count = len(self.names) + len(self.reverse_dns)
            result.factors[Factor.SURFACE.value] = min(1.0, count / 25.0)
            result.inputs[Factor.SURFACE.value] = [
                f"{len(self.names)} name(s) in certificate transparency",
                f"{len(self.reverse_dns)} address(es) with a PTR record",
            ]

        # POSTURE — only the DISCRIMINATING signals. Measured across 8 real
        # domains: SPF 8/8 and DMARC 8/8, so presence separates nobody.
        if self.posture is not None and self.posture.observed:
            wanted = [s for s in suppliers.DISCRIMINATING
                      if s in self.posture.present or s in self.posture.absent]
            if wanted:
                present = [s for s in wanted if s in self.posture.present]
                result.factors[Factor.POSTURE.value] = len(present) / len(wanted)
                result.inputs[Factor.POSTURE.value] = [
                    f"{s.value}: {'present' if s in self.posture.present else 'absent'}"
                    for s in wanted]

        # `locked` is None when nobody read the field, and None is NOT False.
        # The first version used bool(), so an unread transfer-lock scored 0.0 —
        # this module's own docstring says an unobserved factor must never be
        # scored as zero, and it was doing exactly that within twenty lines of
        # saying so. A factor is observed only when a real boolean arrived.
        locked = self.registration.get("locked")
        # `observed` False means the lookup failed or was redirected somewhere
        # unallowlisted — not that the domain has no lock.
        if self.registration.get("observed") and isinstance(locked, bool):
            result.factors[Factor.REGISTRATION.value] = 1.0 if locked else 0.0
            result.inputs[Factor.REGISTRATION.value] = [
                f"{key}: {value}" for key, value in self.registration.items()
                if key != "raw"]

        # REPUTATION — what third-party feeds say. The socket was declared in
        # P7 and stood empty until the vendored abuse corpus arrived.
        #
        # SCORED ONLY WHEN THE CORPUS WAS ACTUALLY CONSULTED. `abuse_coverage`
        # is populated whether or not anything matched, so its presence is the
        # signal that a check happened; scoring 0.0 on an absent corpus would
        # turn "we never looked" into "nothing was found", which is the one
        # translation this whole module exists to prevent.
        if self.abuse_coverage:
            # NEUTRAL listings do not count. A Tor exit relay is context about
            # where traffic came from, and scoring it as reputation would make
            # running one look like misconduct.
            adverse = [h for h in self.abuse if h.get("sense") == "ABUSE"]
            if adverse:
                # Deliberately not a count-based ramp. Appearing on one abuse
                # feed and appearing on four are not four times as meaningful —
                # the feeds overlap heavily and share upstream reporters.
                result.factors[Factor.REPUTATION.value] = 0.0
                result.inputs[Factor.REPUTATION.value] = [
                    f"{h['feed']} ({h['publisher']}), data {h['data_age_days']}"
                    f" day(s) old: {h['means']}" for h in adverse[:6]]
            else:
                result.factors[Factor.REPUTATION.value] = 1.0
                result.inputs[Factor.REPUTATION.value] = [
                    self.abuse_coverage.get("absence_means", "")]

        # REPUTATION stays None whenever no source could answer, which is the
        # normal case without a key and without a vendored corpus. It is never
        # scored as zero for want of looking.
        return result

    def headline(self) -> str:
        parts = [f"{self.target.kind.value} {self.target.value}"]
        if self.names:
            parts.append(f"{len(self.names)} name(s) seen publicly")
        if self.reverse_dns:
            parts.append(f"{len(self.reverse_dns)} address(es) with a PTR")
        adverse = [h for h in self.abuse if h.get("sense") == "ABUSE"]
        if adverse:
            parts.append(f"on {len(adverse)} abuse feed(s)")
        if self.leak_listings:
            # Named in the headline because it is the highest-signal thing this
            # product can observe, and burying it below a port list would be a
            # ranking decision nobody made deliberately.
            parts.append(f"{len(self.leak_listings)} ransomware leak-site "
                         f"listing(s)")
        if self.unavailable:
            parts.append(f"{len(self.unavailable)} source(s) unavailable")
        return "; ".join(parts) + "."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "headline": self.headline(),
            "score": self.score().to_dict(),
            "names": list(self.names),
            "reverse_dns": dict(self.reverse_dns),
            "registration": dict(self.registration),
            "posture": self.posture.to_dict() if self.posture else None,
            # Rendered, not logged. Every one of these is something the result
            # does not know, and a reader who cannot see the list will read the
            # result as complete.
            "unavailable_sources": list(self.unavailable),
            # Vendored corpora. Both carry their coverage alongside their hits,
            # because in both cases an empty list is the overwhelmingly common
            # result and means almost nothing on its own.
            "abuse": list(self.abuse),
            "abuse_coverage": dict(self.abuse_coverage),
            "leak_listings": list(self.leak_listings),
            "leak_coverage": dict(self.leak_coverage),
            "certificates": list(self.certificates),
            "certificate_lineage": dict(self.certificate_lineage),
            "certificate_coverage": dict(self.certificate_coverage),
            "subsidiary_candidates": list(self.subsidiary_candidates),
            "passive_only": PASSIVE_ONLY,
        }


#: Stated on every lookup. The constraint is architectural, not a setting.
PASSIVE_ONLY = (
    "This lookup is PASSIVE and cannot be anything else. Ownership of a target "
    "you typed into a box cannot be proven, and every active operation — port "
    "scan, TLS handshake, HTTP probe, banner read — fails closed against an "
    "unverified asset before scope is even consulted. Nothing here sends a "
    "packet to the target: it reads public records and asks third-party "
    "resolvers. So this reports what the target PUBLISHES, and cannot report "
    "what it runs.")


__all__ = ["Kind", "Target", "TargetError", "parse", "Factor", "Score",
           "Lookup", "MIN_FACTORS", "MAX_CIDR_HOSTS", "PASSIVE_ONLY"]
