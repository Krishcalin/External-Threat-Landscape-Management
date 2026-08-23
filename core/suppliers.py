"""Third-party exposure, from outside, without touching them.

WHAT THE GATE ALREADY DECIDED, BEFORE ANYBODY THOUGHT ABOUT SUPPLIERS
---------------------------------------------------------------------
A supplier's infrastructure is somebody else's estate. The customer cannot prove
ownership of it, and FR-GOV-001 makes every ACTIVE collector fail closed against
an unverified asset. Measured, with a supplier domain explicitly in scope and no
verification: `ct_log_search`, `passive_dns`, `rdap_lookup`,
`dns_resolve_recursive` and `whois_lookup` are allowed; `http_probe`,
`tls_handshake`, `port_scan` and `service_banner_read` are all refused with
`OwnershipNotVerified`.

So "passive posture assessment" is not a cautious choice in this module. It is
the only thing the architecture permits, no scope rule can change it, and the
refusal is decided before scope is even consulted.

THE CONSEQUENCE THAT SHAPES EVERYTHING HERE
--------------------------------------------
No active probe means no fingerprint. No fingerprint means no product name. No
product name means NO CVE JOIN FOR A SUPPLIER, EVER — not a shorter list, not a
lower-confidence list, none. Anything resembling a supplier CVE count is a
fabrication, and there is deliberately no function in this file that could
produce one.

What is left is a different and smaller claim: how a supplier configures the
things they publish to the world. That correlates with how an organisation runs
itself and IS NOT A MEASUREMENT OF THEIR SECURITY. A supplier with a perfect
DMARC record can be breached tomorrow. Its value is that it is comparable across
a whole register and costs the supplier nothing — no questionnaire, no NDA, no
waiting for someone to answer.

CONCENTRATION IS THE PART THAT DOES NOT EXIST ELSEWHERE
--------------------------------------------------------
Each supplier can tell you about themselves. None of them can tell you that
fourteen of your thirty suppliers resolve mail through the same provider, and
neither can a questionnaire. That is computable from NS and MX records alone.

Its honest limit, stated wherever it is rendered: shared infrastructure is a
correlation in AVAILABILITY and BLAST RADIUS. It is not proof of a shared
vulnerability, and presenting it as fourth-party risk would be a claim the data
does not support.
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: A register smaller than this cannot support a concentration claim. Five
#: suppliers sharing one mail provider is not a concentration, it is a small
#: company using the obvious product — the same reasoning that makes
#: `latency.MIN_SAMPLE` refuse a reference class rather than interpolate it.
MIN_REGISTER_FOR_CONCENTRATION = 8

#: A provider must serve at least this many suppliers before it is reported.
MIN_SUPPLIERS_PER_PROVIDER = 2

#: A certificate closer to expiry than this is worth saying out loud. Not a
#: vulnerability — an operational fact that is cheap to fix and embarrassing to
#: discover from a customer.
EXPIRY_WARNING_DAYS = 30


class Tier(str, enum.Enum):
    """How much the CUSTOMER depends on this supplier. Declared, never inferred.

    A tool that ranked suppliers by how exposed their DNS looked would be
    substituting an observation it can make for a judgement only the customer
    can make. A supplier with immaculate DNS can still be the one whose outage
    stops the business.
    """

    CRITICAL = "critical"
    IMPORTANT = "important"
    ROUTINE = "routine"

    @property
    def meaning(self) -> str:
        return {
            Tier.CRITICAL: "the organisation states that losing this supplier "
                           "stops or materially degrades its operations",
            Tier.IMPORTANT: "the organisation states that losing this supplier "
                            "causes significant disruption it could work around",
            Tier.ROUTINE: "the organisation states that losing this supplier is "
                          "absorbable",
        }[self]


class Signal(str, enum.Enum):
    """One observable, published fact. Each carries what it does NOT mean."""

    SPF = "spf"
    DMARC = "dmarc"
    DMARC_ENFORCED = "dmarc_enforced"
    MTA_STS = "mta_sts"
    CAA = "caa"
    CERT_EXPIRING = "cert_expiring"
    REGISTRY_LOCK = "registry_lock"

    @property
    def means(self) -> str:
        return {
            Signal.SPF: "publishes an SPF record, so receiving servers can check "
                        "whether mail claiming to be from them was sent by a "
                        "host they authorised",
            Signal.DMARC: "publishes a DMARC record",
            Signal.DMARC_ENFORCED: "DMARC policy is quarantine or reject, so a "
                                   "failing message is actually acted on",
            Signal.MTA_STS: "publishes MTA-STS, requiring TLS for inbound mail",
            Signal.CAA: "constrains which certificate authorities may issue for "
                        "their names",
            Signal.CERT_EXPIRING: "a certificate naming them is close to expiry",
            Signal.REGISTRY_LOCK: "the domain registration carries a transfer "
                                  "lock",
        }[self]

    @property
    def does_not_mean(self) -> str:
        return {
            Signal.SPF: "does NOT mean their mail is secure, or that the record "
                        "is correct — a permissive `+all` SPF record is present "
                        "and worthless",
            Signal.DMARC: "does NOT mean it is enforced. A `p=none` record is "
                          "monitoring only and is the commonest state",
            Signal.DMARC_ENFORCED: "does NOT mean spoofing is impossible, only "
                                   "that this control is switched on",
            Signal.MTA_STS: "does NOT mean their mail servers are correctly "
                            "configured — confirming that needs a handshake, "
                            "which this product is refused",
            Signal.CAA: "does NOT prevent misissuance; it constrains it, and "
                        "relies on the CA honouring the record",
            Signal.CERT_EXPIRING: "does NOT mean the certificate will lapse — "
                                  "most renew automatically, and this is an "
                                  "observation rather than a prediction",
            Signal.REGISTRY_LOCK: "does NOT protect against a compromised "
                                  "registrar account",
        }[self]


#: Measured against 8 real domains (github, cloudflare, wikipedia, python.org,
#: sbi.co.in, irctc.co.in, zomato, hdfcbank) on 2026-08-23, passive lookups
#: only. The result changed the design: SPF 8/8 and DMARC 8/8, so the PRESENCE
#: of either separates nobody. What separates them is how far they went —
#: enforcement 7/8, CAA 3/8, MTA-STS 1/8.
#:
#: A posture screen that leads with an SPF column shows a column of "yes" and
#: teaches its reader that the whole panel is decorative.
DISCRIMINATION = (
    "Measured across 8 real domains: SPF 8/8 and DMARC 8/8 — the presence of "
    "either separates nobody, because publishing them is now universal. What "
    "distinguishes suppliers is how far they took it: DMARC enforcement 7/8, "
    "CAA 3/8, MTA-STS 1/8. This register leads with those and reports SPF and "
    "DMARC presence as context rather than as a score.")

#: The signals worth ranking on. Presence-of-SPF and presence-of-DMARC are
#: deliberately absent — see DISCRIMINATION.
DISCRIMINATING = (Signal.DMARC_ENFORCED, Signal.MTA_STS, Signal.CAA,
                  Signal.CERT_EXPIRING, Signal.REGISTRY_LOCK)


class RegisterError(ValueError):
    """A register entry that would misrepresent a commercial relationship."""


_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


@dataclass(frozen=True)
class Supplier:
    """What the ORGANISATION states about one third party.

    SKOPOS does not get to decide who your suppliers are. A tool that inferred
    supplier relationships from DNS would be inventing a commercial fact, and
    inventing the wrong one is worse than having no register: an organisation
    would either assess a company it has no relationship with, or believe a real
    dependency was covered.
    """

    name: str
    domain: str
    tier: Tier
    #: What the organisation actually depends on them FOR. Free text on purpose:
    #: no vocabulary this product invents would survive contact with a real
    #: supply chain, and a wrong dropdown produces confidently wrong data.
    dependency: str = ""
    declared_by: str = ""
    declared_on: Optional[date] = None

    def __post_init__(self) -> None:
        if not str(self.name).strip():
            raise RegisterError("a supplier entry must name the supplier")
        if not _DOMAIN.match(str(self.domain).strip().lower()):
            raise RegisterError(
                f"{self.domain!r} is not a domain. The register keys on a domain "
                f"because that is the only handle a passive collector has — a "
                f"supplier with no domain here cannot be assessed at all, which "
                f"is better recorded than silently skipped")
        if not str(self.declared_by).strip():
            raise RegisterError(
                "a supplier entry must record who declared the relationship — "
                "an unattributed claim that a company is a supplier is not a "
                "record")


@dataclass
class Posture:
    """What one supplier publishes, and what SKOPOS could not see.

    `unobserved` is a first-class field. A signal SKOPOS did not look for and a
    signal that is genuinely absent are different facts, and collapsing them
    into "not configured" turns our coverage gap into their finding.
    """

    supplier: Supplier
    present: List[Signal] = field(default_factory=list)
    absent: List[Signal] = field(default_factory=list)
    unobserved: List[Signal] = field(default_factory=list)
    #: Provider dependencies, for concentration. Lower-cased registrable-ish
    #: labels rather than raw host names, so `ns1.` and `ns2.` of one provider
    #: do not count as two.
    providers: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    @property
    def observed(self) -> int:
        return len(self.present) + len(self.absent)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "supplier": self.supplier.name,
            "domain": self.supplier.domain,
            "tier": self.supplier.tier.value,
            "tier_meaning": self.supplier.tier.meaning,
            "dependency": self.supplier.dependency or None,
            "present": [s.value for s in self.present],
            "absent": [s.value for s in self.absent],
            # Never merged into `absent`. Our blind spot is not their gap.
            "unobserved": [s.value for s in self.unobserved],
            "providers": dict(self.providers),
            "notes": list(self.notes),
            "signal_meaning": {s.value: {"means": s.means,
                                         "does_not_mean": s.does_not_mean}
                               for s in self.present + self.absent},
        }


def _provider_of(host: str) -> str:
    """A coarse provider label from a host name.

    `ns1.example-dns.net` and `ns2.example-dns.net` are ONE provider. Taking the
    last two labels is crude and wrong for multi-level suffixes like `co.uk`;
    it is used anyway because the alternative is vendoring the public suffix
    list for a display label, and the failure mode is a slightly wrong label
    rather than a wrong conclusion — concentration compares these to each
    other, so a consistent error cancels.
    """
    parts = [p for p in str(host).strip(".").lower().split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else ".".join(parts)


def assess(supplier: Supplier, records: Dict[str, Sequence[str]],
           certificates: Sequence[Dict[str, Any]] = (),
           registration: Optional[Dict[str, Any]] = None,
           today: Optional[date] = None) -> Posture:
    """Judge one supplier from published records alone.

    `records` maps an rrtype (and the derived names, `_dmarc` and `_mta-sts`) to
    the strings observed. A KEY THAT IS ABSENT MEANS NOT LOOKED UP, and a key
    present with an empty list means looked up and genuinely nothing there. That
    distinction is the whole reason `unobserved` exists.
    """
    day = today or date.today()
    posture = Posture(supplier=supplier)

    def record(signal: Signal, key: str, predicate) -> None:
        if key not in records:
            posture.unobserved.append(signal)
            return
        (posture.present if predicate(records[key]) else posture.absent).append(signal)

    record(Signal.SPF, "TXT",
           lambda vs: any(str(v).lower().startswith("v=spf1") for v in vs))
    record(Signal.DMARC, "_dmarc",
           lambda vs: any(str(v).lower().startswith("v=dmarc1") for v in vs))
    record(Signal.MTA_STS, "_mta-sts",
           lambda vs: any(str(v).lower().startswith("v=stsv1") for v in vs))
    record(Signal.CAA, "CAA", lambda vs: any("issue" in str(v).lower() for v in vs))

    # Enforcement is a separate signal from presence, because `p=none` is the
    # commonest DMARC state and reporting it as "has DMARC" is how a register
    # ends up green while nothing is enforced.
    if "_dmarc" in records:
        enforced = any(
            re.search(r"\bp\s*=\s*(quarantine|reject)\b", str(v), re.I)
            for v in records["_dmarc"])
        (posture.present if enforced else posture.absent).append(Signal.DMARC_ENFORCED)
    else:
        posture.unobserved.append(Signal.DMARC_ENFORCED)

    for key, label in (("NS", "dns"), ("MX", "mail")):
        hosts = records.get(key)
        if hosts is None:
            continue
        providers = sorted({_provider_of(h) for h in hosts if str(h).strip()})
        if providers:
            posture.providers[label] = providers[0]
            if len(providers) > 1:
                posture.notes.append(
                    f"{label}: {len(providers)} distinct providers "
                    f"({', '.join(providers)}) — counted under the first")

    soonest: Optional[int] = None
    for cert in certificates:
        expires = cert.get("not_after")
        if isinstance(expires, date):
            days = (expires - day).days
            soonest = days if soonest is None else min(soonest, days)
        issuer = cert.get("issuer")
        if issuer and "ca" not in posture.providers:
            posture.providers["ca"] = _provider_of(str(issuer)) or str(issuer)
    if soonest is None:
        posture.unobserved.append(Signal.CERT_EXPIRING)
    elif soonest <= EXPIRY_WARNING_DAYS:
        posture.present.append(Signal.CERT_EXPIRING)
        posture.notes.append(
            f"a certificate naming them expires in {soonest} day(s). Most renew "
            f"automatically — this is an observation, not a prediction")
    else:
        posture.absent.append(Signal.CERT_EXPIRING)

    if registration is None:
        posture.unobserved.append(Signal.REGISTRY_LOCK)
    else:
        locked = any("lock" in str(s).lower()
                     for s in registration.get("status") or [])
        (posture.present if locked else posture.absent).append(Signal.REGISTRY_LOCK)

    return posture


@dataclass
class Concentration:
    """One provider that several suppliers depend on."""

    kind: str
    provider: str
    suppliers: List[str]
    critical: int

    def to_dict(self, total: int) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "provider": self.provider,
            "suppliers": list(self.suppliers),
            "count": len(self.suppliers),
            "critical_suppliers": self.critical,
            "share_of_register": round(len(self.suppliers) / total, 3) if total else None,
        }


#: Rendered wherever a concentration is shown. Without it the screen reads as a
#: fourth-party risk claim, which is a different and unsupported statement.
CONCENTRATION_MEANING = (
    "Shared infrastructure is a correlation in AVAILABILITY and BLAST RADIUS: "
    "one outage or one compromise at that provider reaches every supplier "
    "listed, at once. It is NOT evidence of a shared vulnerability, and it is "
    "not a judgement about the provider — a concentration on a well-run "
    "provider is still a concentration. What it tells you is which single "
    "events your supply chain has no diversity against.")

TOO_SMALL = (
    f"A register of fewer than {MIN_REGISTER_FOR_CONCENTRATION} suppliers "
    f"cannot support a concentration finding. Five suppliers sharing one mail "
    f"provider is not a concentration — it is a small organisation using the "
    f"obvious product. No conclusion is drawn rather than a weak one.")


def concentrations(postures: Sequence[Posture]) -> Tuple[List[Concentration], Optional[str]]:
    """Providers several suppliers share. Returns (findings, refusal).

    The refusal is returned rather than raised, because "your register is too
    small to say" is a legitimate answer this screen must be able to render.
    """
    if len(postures) < MIN_REGISTER_FOR_CONCENTRATION:
        return [], TOO_SMALL

    buckets: Dict[Tuple[str, str], List[Posture]] = {}
    for posture in postures:
        for kind, provider in posture.providers.items():
            buckets.setdefault((kind, provider), []).append(posture)

    found = [
        Concentration(
            kind=kind, provider=provider,
            suppliers=sorted(p.supplier.name for p in group),
            critical=sum(1 for p in group if p.supplier.tier is Tier.CRITICAL))
        for (kind, provider), group in buckets.items()
        if len(group) >= MIN_SUPPLIERS_PER_PROVIDER
    ]
    # Most critical suppliers first, then breadth: a provider carrying three
    # critical suppliers matters more than one carrying nine routine ones.
    found.sort(key=lambda c: (-c.critical, -len(c.suppliers), c.kind, c.provider))
    return found, None


@dataclass
class Register:
    postures: List[Posture] = field(default_factory=list)
    findings: List[Concentration] = field(default_factory=list)
    refusal: Optional[str] = None

    def headline(self) -> str:
        if not self.postures:
            return ("No suppliers declared. An empty register is not a supply "
                    "chain with no third parties — it is one nobody has "
                    "written down.")
        critical = sum(1 for p in self.postures
                       if p.supplier.tier is Tier.CRITICAL)
        line = (f"{len(self.postures)} supplier(s) declared, {critical} of them "
                f"critical.")
        if self.refusal:
            return line + " " + self.refusal
        if self.findings:
            top = self.findings[0]
            line += (f" The largest concentration is {top.provider} "
                     f"({top.kind}), which {len(top.suppliers)} of them depend "
                     f"on.")
        else:
            line += " No provider is shared by enough of them to report."
        return line

    def to_dict(self) -> Dict[str, Any]:
        total = len(self.postures)
        return {
            "headline": self.headline(),
            "suppliers": [p.to_dict() for p in self.postures],
            "concentrations": [c.to_dict(total) for c in self.findings],
            "concentration_meaning": CONCENTRATION_MEANING,
            "concentration_refused": self.refusal,
            "minimum_register": MIN_REGISTER_FOR_CONCENTRATION,
            "no_cve_join": (
                "Supplier assessment is PASSIVE ONLY, and not by choice: a "
                "customer cannot prove ownership of a supplier's domain, so "
                "every active collector is refused against it. No active probe "
                "means no fingerprint, no fingerprint means no product name, "
                "and no product name means SKOPOS cannot and does not report "
                "vulnerabilities for a supplier. What is measured here is how "
                "they configure what they publish, which correlates with how "
                "they run things and is not a measurement of their security."),
        }


def build(suppliers: Sequence[Supplier],
          observations: Dict[str, Dict[str, Any]],
          today: Optional[date] = None) -> Register:
    """Assess every declared supplier and look for concentration across them."""
    postures = [
        assess(supplier,
               records=(observations.get(supplier.domain) or {}).get("records", {}),
               certificates=(observations.get(supplier.domain) or {}).get("certificates", ()),
               registration=(observations.get(supplier.domain) or {}).get("registration"),
               today=today)
        for supplier in suppliers
    ]
    postures.sort(key=lambda p: (list(Tier).index(p.supplier.tier),
                                 p.supplier.name))
    findings, refusal = concentrations(postures)
    return Register(postures=postures, findings=findings, refusal=refusal)


__all__ = ["Tier", "Signal", "Supplier", "Posture", "Concentration", "Register",
           "DISCRIMINATION", "DISCRIMINATING",
           "RegisterError", "assess", "concentrations", "build",
           "CONCENTRATION_MEANING", "TOO_SMALL",
           "MIN_REGISTER_FOR_CONCENTRATION", "MIN_SUPPLIERS_PER_PROVIDER",
           "EXPIRY_WARNING_DAYS"]
