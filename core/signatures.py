"""Observed banner -> the catalogue's spelling of a product.

Fingerprinting only pays off if what it writes actually joins. The contract is
exact: `tokens(asset.product)` must be a NON-EMPTY SUBSET of
`tokens(entry.product) | tokens(entry.vendor_project)`. Every extra token is a
veto, which makes the obvious implementation — write the banner — useless.
Measured against the real 1,674-entry corpus:

    unknown                              {unknown}                 0 exposures
    Apache/2.4.54 (Ubuntu)               {apache, ubuntu}          0  <- distro vetoes
    cpe:2.3:a:apache:http_server:2.4.54  {apache, cpe, http}       0  <- 'cpe' vetoes
    Windows Server 2019                  {2019, windows}           0  <- the year vetoes
    Apache HTTP Server  + Apache                                   4, all STRONG
    Zimbra              + Zimbra                                  19, all PARTIAL
    Zimbra              + Synacor                                 19, all STRONG

The last pair is the whole argument for a reviewed table. CISA files Zimbra
under Synacor, so writing the vendor everybody says out loud costs you every
STRONG match. `vendor` is the only lever that reaches STRONG, because
`_corresponds` compares it against `vendor_project` alone.

THE BREADTH CAP IS VENDOR SPAN, NOT HIT COUNT
---------------------------------------------
A hit-count cap was tried and is the wrong metric — measured, it inverts the
populations it is meant to separate:

    Cisco            + Cisco         96 hits   1 vendor    precise
    Chromium         + Google        63 hits   1 vendor    precise
    Apache                           40 hits   1 vendor    precise
    Security Gateway + Check Point   28 hits   8 vendors   imprecise
    Routers          + D-Link        27 hits   9 vendors   imprecise
    Windows          + Microsoft    177 hits   3 vendors   imprecise

Hit count measures how often a product has been exploited, not how vague the
signature is. A cap on it also means a corpus refresh that takes Confluence from
9 entries to 26 turns a working signature into a CI failure — so the more a
product is exploited, the sooner this product stops identifying it. Exactly
backwards.

Vendor span measures the thing we actually care about: does this signature name
one vendor's product, or does it drag in other people's?
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from core.identity import Attestation, IdentitySignal
from core.match import tokens

#: Tokens that identify an OS family rather than a product. Measured: `IOS XE`
#: tokenises to {ios} — `xe` is below MIN_TOKEN — and pulls 33 Apple iOS entries
#: onto a Cisco router, 79 hits spanning two vendors. An OS-family
#: identification is recorded in obs_* attributes and never written to `product`.
FORBIDDEN_PRODUCT_TOKENS: Set[str] = {
    "windows", "ios", "microsoft", "cisco", "apple", "multiple", "kernel",
    "linux", "android", "router", "routers",
}


class SignatureRejected(ValueError):
    """A signature that would write something the join cannot use, or that
    spans vendors it did not declare."""


@dataclass(frozen=True)
class Signature:
    """One rule: a pattern over an observed signal, and what to write."""

    #: Where to look: "http.server", "http.powered_by", "tls.subject",
    #: "tls.issuer", "body".
    source: str
    pattern: str
    #: The CATALOGUE'S spelling, not the vendor's marketing name.
    product: str
    vendor: Optional[str] = None
    attestation: Attestation = Attestation.SELF_REPORTED
    #: Vendors this signature is KNOWN to span, declared deliberately. Measured
    #: legitimate spans: Connect Secure -> Ivanti + Pulse Secure (a rename);
    #: VMware -> VMware + Broadcom (an acquisition).
    expect_vendors: Tuple[str, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        written = tokens(self.product)
        if not written:
            raise SignatureRejected(
                f"{self.product!r} tokenises to nothing, so it can never join. "
                f"Every token is either below MIN_TOKEN or a stopword.")
        forbidden = written & FORBIDDEN_PRODUCT_TOKENS
        if forbidden:
            raise SignatureRejected(
                f"{self.product!r} contains OS-family token(s) {sorted(forbidden)}. "
                f"Measured: 'IOS XE' tokenises to {{ios}} and pulls Apple's iOS "
                f"entries onto a Cisco router. Record the family in an obs_* "
                f"attribute instead of writing it to `product`.")
        if re.search(r"\d+\.\d+", self.product):
            raise SignatureRejected(
                f"{self.product!r} carries a version. Any component of three or "
                f"more characters becomes a token and vetoes every match.")

    @property
    def regex(self):
        return re.compile(self.pattern, re.I)

    def matches(self, signal: IdentitySignal) -> bool:
        return (signal.source == self.source
                and bool(self.regex.search(str(signal.value or ""))))


def catalogue_profile(product: str, vendor: Optional[str],
                      catalogue: Sequence) -> Tuple[int, Set[str]]:
    """What this signature would actually pull: `(hits, vendor_project set)`."""
    from core.match import match_asset
    from core.models import Asset

    hits = match_asset(Asset(identifier="probe", product=product, vendor=vendor),
                       catalogue)
    return len(hits), {h.exploited.vendor_project for h in hits}


def audit(signature: Signature, catalogue: Sequence) -> Tuple[bool, str]:
    """Would this signature drag in vendors it never declared?

    Returns `(ok, explanation)` rather than raising, so a corpus refresh can
    report drift without deleting signatures. Hit-count change is reported and
    is deliberately NOT a failure — see the module docstring.
    """
    hits, vendors = catalogue_profile(signature.product, signature.vendor,
                                      catalogue)
    if not hits:
        return False, (f"{signature.product!r} matches nothing in the catalogue. "
                       f"That may be correct — nginx and OpenSSH have zero KEV "
                       f"entries — but if it is a spelling mistake the signature "
                       f"is inert and nobody will notice.")
    declared = set(signature.expect_vendors) | ({signature.vendor}
                                                if signature.vendor else set())
    undeclared = vendors - declared
    if len(vendors) > 1 and undeclared:
        return False, (
            f"{signature.product!r} spans {len(vendors)} vendors "
            f"{sorted(vendors)}; {sorted(undeclared)} undeclared. A signature "
            f"that names one vendor's product must not drag in another's. "
            f"Declare the span in expect_vendors if it is a rename or an "
            f"acquisition, or narrow the signature.")
    return True, f"{hits} hit(s), {len(vendors)} vendor(s): {sorted(vendors)}"


#: The reviewed table. Every entry uses the CATALOGUE'S spelling and carries no
#: version. Deliberately small: a wrong signature is worse than a missing one,
#: because a missing one produces `unidentified` (which an operator can see and
#: act on) while a wrong one produces a confident worklist about software that
#: is not there.
SIGNATURES: Tuple[Signature, ...] = (
    # 'HTTP Server' is the catalogue's own spelling but tokenises to {http} —
    # 'server' is a stopword — and measured, that pulls in Rejetto's HTTP File
    # Server, IETF HTTP/2 and Microsoft HTTP.sys: 9 hits across 4 vendors.
    # Writing MORE narrows it, which is counterintuitive and is exactly why the
    # table is audited against the real corpus rather than eyeballed.
    Signature("http.server", r"^Apache(?:/|$|\s)", "Apache HTTP Server", "Apache",
              note="bare 'Apache' spans 21 products; bare 'HTTP Server' spans 4 "
                   "vendors; the pair is precise at 4 hits, 1 vendor"),
    Signature("http.server", r"^Apache-Coyote|^Tomcat", "Tomcat", "Apache"),
    Signature("http.server", r"^Microsoft-IIS", "Internet Information Services",
              "Microsoft"),
    Signature("http.powered_by", r"Zimbra", "Zimbra", "Synacor",
              note="CISA files Zimbra under Synacor; writing 'Zimbra' as the "
                   "vendor costs every STRONG match"),
    Signature("tls.subject", r"Connect Secure|Pulse Secure", "Connect Secure",
              "Ivanti", attestation=Attestation.INFERRED,
              expect_vendors=("Ivanti", "Pulse Secure"),
              note="renamed; the catalogue carries both spellings"),
    Signature("http.server", r"Confluence", "Confluence Server and Data Center",
              "Atlassian"),
    Signature("http.server", r"^GitLab", "GitLab", "GitLab"),
    # WebPros' catalogue entry is literally "cPanel & WHM and WP2 (WordPress
    # Squared)", so the word appears under a second vendor. It cannot be
    # narrowed away without losing WordPress Core, so the span is declared and
    # the reason recorded rather than left to surprise somebody.
    Signature("http.powered_by", r"WordPress", "WordPress", "WordPress",
              expect_vendors=("WordPress", "WebPros"),
              note="WebPros names WordPress inside a cPanel product string; a "
                   "catalogue quirk, not a second identification"),
    Signature("tls.subject", r"FortiGate|FortiOS", "FortiOS", "Fortinet",
              attestation=Attestation.INFERRED),
    Signature("http.server", r"^Jenkins", "Jenkins", "Jenkins"),
)


def identify(signals: Sequence[IdentitySignal],
             table: Sequence[Signature] = SIGNATURES
             ) -> Tuple[Optional[Signature], List[IdentitySignal]]:
    """The first signature that fires, and the signals that supported it.

    INFERRED beats SELF_REPORTED when both fire. A certificate subject is a side
    effect of running the software; a `Server:` header is a string anyone with
    access can rewrite, so when they disagree the one that is harder to forge
    should win.
    """
    hits: List[Tuple[Signature, IdentitySignal]] = []
    for signature in table:
        for signal in signals:
            if signature.matches(signal):
                hits.append((signature, signal))
                break
    if not hits:
        return None, []
    hits.sort(key=lambda pair: 0 if pair[0].attestation is Attestation.INFERRED
              else 1)
    chosen = hits[0][0]
    return chosen, [signal for sig, signal in hits if sig is chosen]


__all__ = ["Signature", "SignatureRejected", "SIGNATURES",
           "FORBIDDEN_PRODUCT_TOKENS", "catalogue_profile", "audit", "identify"]
