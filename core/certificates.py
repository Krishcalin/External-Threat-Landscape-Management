"""Certificate posture and lineage from data already being collected.

WHAT THIS IS BUYING FOR NOTHING
---------------------------------
Recorded Future's Attack Surface Intelligence advertises "10+ years of current
and historical DNS, WHOIS and SSL/TLS certificate data" as a paid differentiator.

The certificate half of that is free and public. Certificate Transparency logs
are append-only by design and SKOPOS has been reading them since P1 — for names
only. `collect/ct.py` extracts the SANs, discards issuer, validity window and
organisation, and moves on. This module is what those discarded fields are worth.

THREE THINGS THE DISCARDED FIELDS GIVE
----------------------------------------
1. **Expiry.** Mundane and the most operationally useful thing here.
2. **Lineage.** Every certificate ever issued for a host. "Four issuers in six
   months" is visible in a CT log and invisible in a live TLS handshake, which
   only ever shows the certificate presented today.
3. **Organisation.** OV and EV certificates carry a subject organisation, which
   is a passive pivot toward subsidiaries — surfaced as CANDIDATES for the
   triage queue, never auto-added, because nothing here may decide what SKOPOS
   is allowed to scan.

WHY A CT RECORD IS NOT A LIVE OBSERVATION
-------------------------------------------
A certificate in a CT log was ISSUED. It may never have been deployed, may have
been replaced the same day, and says nothing about what a host is serving now.
This is the same distinction `core/provenance.py` draws everywhere else, and the
`observed` field carries it: `issued` for a log entry, `presented` for something
a handshake actually returned.

A host whose newest certificate expired last year is therefore a QUESTION, not a
finding. It may be decommissioned, it may be behind something that terminates
TLS elsewhere, or it may be genuinely broken — and the difference is not
knowable from a log.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: Renewal is routine and usually automated, so this is a working window rather
#: than an alarm. Thirty days is the shortest interval in which a human process
#: — a purchase order, a change window, a CA validation — reliably completes.
EXPIRING_SOON_DAYS = 30

#: Hash functions nobody should still be signing certificates with.
#:
#: Matched as a PREFIX of the normalised algorithm name rather than by exact
#: membership, because CAs spell the same thing a dozen ways —
#: `md5WithRSAEncryption`, `md5WithRSA`, `MD5-RSA`, `md5`. An enumeration of
#: spellings misses the one that matters and looks like a clean result; an
#: enumeration of the two broken HASHES does not.
#:
#: Deliberately short: things that are broken, not things that are merely
#: dated. A rule firing on every SHA-1 anywhere in a chain would fire constantly
#: and be switched off, which is worse than not having it.
WEAK_HASHES = ("md5", "sha1")

#: Kept as a name because it reads better at the call site, and because the
#: previous exact-set version is the kind of thing somebody reintroduces.
WEAK_SIGNATURES = WEAK_HASHES


def _is_weak_signature(algorithm: str) -> bool:
    """Whether this signature algorithm uses a broken hash.

    `sha1WithRSAEncryption` -> True. `sha256WithRSAEncryption` -> False, and
    note that a naive `"sha1" in name` test would also be False here only by
    luck — `ecdsa-with-SHA1` would pass it and `sha512` would not. Normalising
    and matching the LEADING hash is what makes this reliable.
    """
    name = str(algorithm or "").lower()
    for junk in ("-", " ", "_"):
        name = name.replace(junk, "")
    if not name:
        return False
    # Strip a leading curve/keytype prefix so `ecdsawithsha1` is caught too.
    for prefix in ("ecdsawith", "rsawith", "dsawith", "rsassapss"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    for weak in WEAK_HASHES:
        if name.startswith(weak):
            # `sha1...` matches; `sha256...` must not, and it does not because
            # "sha256" does not start with "sha1" — but "sha1" IS a prefix of
            # nothing else in current use, which is why this is safe.
            return True
    return False

#: A SAN set larger than this is worth asking about. Not wrong — a CDN or a
#: shared platform legitimately issues these — but a certificate covering 200
#: names has a blast radius, and its private key is a single point of failure
#: for every one of them.
BROAD_SAN_COUNT = 100


class Observed(str, enum.Enum):
    """How this certificate came to be known. The distinction P1 built
    `core/provenance.py` to keep."""

    #: Seen in a Certificate Transparency log. It was ISSUED. Whether it was
    #: ever deployed is unknown and unknowable from a log.
    ISSUED = "issued"
    #: Returned by a live TLS handshake. This one is actually in service.
    PRESENTED = "presented"


@dataclass(frozen=True)
class Certificate:
    host: str
    issuer: str
    not_before: str
    not_after: str
    observed: Observed = Observed.ISSUED
    serial: str = ""
    signature_algorithm: str = ""
    #: The subject organisation, where the CA validated one. Empty for DV
    #: certificates, which is most of them.
    organisation: str = ""
    sans: Tuple[str, ...] = ()

    def days_until_expiry(self, today: Optional[date] = None) -> Optional[int]:
        try:
            expires = date.fromisoformat(str(self.not_after)[:10])
        except (TypeError, ValueError):
            return None
        return (expires - (today or _today())).days

    def to_dict(self, today: Optional[date] = None) -> Dict[str, Any]:
        return {
            "host": self.host, "issuer": self.issuer,
            "not_before": self.not_before, "not_after": self.not_after,
            "observed": self.observed.value,
            "serial": self.serial,
            "signature_algorithm": self.signature_algorithm,
            "organisation": self.organisation,
            "san_count": len(self.sans),
            "days_until_expiry": self.days_until_expiry(today),
            "observed_means": OBSERVED_MEANING[self.observed],
        }


OBSERVED_MEANING = {
    Observed.ISSUED: (
        "seen in a Certificate Transparency log, which records that a "
        "certificate was ISSUED. It may never have been deployed and says "
        "nothing about what this host is serving now."),
    Observed.PRESENTED: (
        "returned by a live TLS handshake, so this certificate is actually in "
        "service on this host."),
}


def _today() -> date:
    return datetime.now(timezone.utc).date()


def assess(certificates: Sequence[Certificate],
           today: Optional[date] = None) -> List[Dict[str, Any]]:
    """Rule firings for one host's certificates.

    Returns rule ids from `core/rules.py` rather than free text, so these land
    in the catalogue like every other check. The whole reason W1 was built
    first.
    """
    when = today or _today()
    findings: List[Dict[str, Any]] = []
    if not certificates:
        return findings

    # Expiry is judged on the NEWEST certificate only. A host accumulates
    # expired certificates as a matter of course — that is what renewal looks
    # like in a log — and firing on each one would produce a rule that is
    # permanently true everywhere and therefore useless.
    newest = max(certificates,
                 key=lambda c: str(c.not_after) or "")
    remaining = newest.days_until_expiry(when)
    if remaining is not None:
        if remaining < 0:
            findings.append({
                "rule": "cert.expired",
                "host": newest.host, "issuer": newest.issuer,
                "not_after": newest.not_after, "days_ago": -remaining,
                "observed": newest.observed.value,
            })
        elif remaining <= EXPIRING_SOON_DAYS:
            findings.append({
                "rule": "cert.expiring",
                "host": newest.host, "issuer": newest.issuer,
                "not_after": newest.not_after, "days_left": remaining,
                "observed": newest.observed.value,
            })

    for certificate in certificates:
        if _is_weak_signature(certificate.signature_algorithm):
            findings.append({
                "rule": "cert.weak_signature",
                "host": certificate.host,
                "signature_algorithm": certificate.signature_algorithm,
                "not_after": certificate.not_after,
            })
        if len(certificate.sans) > BROAD_SAN_COUNT:
            findings.append({
                "rule": "cert.broad_san",
                "host": certificate.host,
                "san_count": len(certificate.sans),
                "issuer": certificate.issuer,
            })
    return findings


def lineage(certificates: Sequence[Certificate],
            today: Optional[date] = None) -> Dict[str, Any]:
    """Every certificate ever seen for a host, and what the sequence shows.

    THE THING A HANDSHAKE CANNOT TELL YOU. A live probe returns the certificate
    presented today. A CT log returns all of them, so an issuer that changed
    three times in a quarter is visible here and nowhere else.

    It is reported as an observation, not a finding: changing CA is a normal
    procurement decision, and a migration in progress looks identical to
    something worse.
    """
    rows = sorted(certificates, key=lambda c: str(c.not_before) or "")
    issuers: List[str] = []
    for certificate in rows:
        name = str(certificate.issuer or "unknown")
        if not issuers or issuers[-1] != name:
            issuers.append(name)
    distinct = sorted({str(c.issuer or "unknown") for c in rows})
    return {
        "certificates": len(rows),
        "issuer_sequence": issuers,
        "distinct_issuers": distinct,
        "issuer_changes": max(0, len(issuers) - 1),
        "first_seen": rows[0].not_before if rows else None,
        "newest_expiry": max((c.not_after for c in rows), default=None),
        "means": (
            "Certificate Transparency records every certificate ISSUED for a "
            "name, so this is history a live handshake cannot show — a "
            "handshake only ever returns today's certificate. Changing CA is a "
            "normal procurement decision and a migration in progress looks "
            "identical to something worse, so this is reported and not scored."),
    }


def candidate_organisations(certificates: Sequence[Certificate],
                            known: Sequence[str] = ()) -> List[Dict[str, Any]]:
    """Subject organisations that are not already known.

    A PASSIVE PIVOT TOWARD SUBSIDIARIES, and the reason Recorded Future's ASI
    can propose them: an OV or EV certificate carries a validated organisation
    name, so a company's certificates name the company.

    Returned as candidates for the triage queue, never added to anything.
    Nothing in this product may decide what it is allowed to scan.
    """
    seen = {str(k).strip().lower() for k in known if str(k).strip()}
    proposals: Dict[str, Dict[str, Any]] = {}
    for certificate in certificates:
        org = str(certificate.organisation or "").strip()
        if not org or org.lower() in seen:
            continue
        entry = proposals.setdefault(org, {
            "organisation": org, "hosts": [], "issuers": set(),
            "basis": ("a CA validated this organisation name when issuing a "
                      "certificate for a host already in scope. That makes it "
                      "worth ASKING about — it is not evidence the "
                      "organisation is a subsidiary, and nothing is added to "
                      "scope on the strength of it."),
        })
        if certificate.host not in entry["hosts"]:
            entry["hosts"].append(certificate.host)
        entry["issuers"].add(certificate.issuer)
    out = []
    for entry in proposals.values():
        entry["issuers"] = sorted(entry["issuers"])
        out.append(entry)
    return sorted(out, key=lambda e: (-len(e["hosts"]), e["organisation"]))


def coverage(certificates: Sequence[Certificate]) -> Dict[str, Any]:
    """What this data can and cannot support."""
    issued = sum(1 for c in certificates if c.observed is Observed.ISSUED)
    presented = len(certificates) - issued
    with_org = sum(1 for c in certificates if c.organisation)
    return {
        "certificates": len(certificates),
        "from_ct_logs": issued,
        "from_live_handshake": presented,
        "with_validated_organisation": with_org,
        "limits": (
            "A Certificate Transparency entry records ISSUANCE, not "
            "deployment. A host whose newest certificate expired last year may "
            "be decommissioned, may terminate TLS somewhere else entirely, or "
            "may be genuinely broken — and a log cannot tell those apart. "
            "Only entries marked `presented` were confirmed in service."),
    }


__all__ = ["Certificate", "Observed", "OBSERVED_MEANING", "assess", "lineage",
           "candidate_organisations", "coverage", "EXPIRING_SOON_DAYS",
           "WEAK_SIGNATURES", "BROAD_SAN_COUNT"]
