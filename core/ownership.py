"""Proof that an asset is yours, before anything touches it.

SRS FR-M0-004. Three methods — a DNS TXT record, a file at a well-known path, or
a manual attestation with a named approver — and every verification expires after
180 days.

WHY EXPIRY IS NOT BUREAUCRACY
-----------------------------
Domains change hands, subdomains get delegated to a SaaS vendor, cloud accounts
are sold with the business unit. A verification proves control at the moment it
was checked and says nothing about today. An unbounded verification would let a
tool keep probing an asset for years after it stopped being the customer's, which
is the exact harm the gate exists to prevent — so verification is a perishable
fact by construction.

WHAT A TOKEN PROVES
-------------------
That whoever placed it can write to the zone or the web root. That is control,
which is the right question — legal ownership is not something a scanner can
establish, and pretending otherwise would be worse than the honest, narrower
claim.

The token is bound to the asset, so a token published once cannot be replayed to
claim a second name. It is also high-entropy: a guessable token would let an
attacker verify somebody else's domain and point this tool at it.
"""
from __future__ import annotations

import enum
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Optional

#: FR-M0-004. Long enough not to be a nuisance, short enough that a transferred
#: domain stops being probed within a couple of quarters.
VALIDITY_DAYS = 180

#: Where the file method looks. Fixed, because a configurable path is one a
#: customer can point at a directory somebody else can write to.
WELL_KNOWN_PATH = "/.well-known/skopos-verification.txt"

TOKEN_PREFIX = "skopos-verification"


class Method(str, enum.Enum):
    DNS_TXT = "dns_txt"
    WELL_KNOWN = "well_known"
    #: A human asserting ownership. Weakest by far, so it records who said so.
    MANUAL = "manual"


class OwnershipNotVerified(PermissionError):
    """Raised when active work is attempted against an unproven asset.

    A PermissionError rather than a ValueError on purpose: this is a refusal,
    not a malformed input, and callers that catch broad ValueErrors around
    parsing should not accidentally swallow it.
    """


def issue_token(asset: str, secret: str) -> str:
    """A token bound to one asset.

    Derived from a server secret rather than stored, so the token can be
    recomputed for checking without keeping a table of live secrets. Binding to
    the asset is what stops one published token verifying every name a customer
    types in.
    """
    if not str(asset).strip():
        raise ValueError("a token must be bound to an asset")
    if not secret or len(str(secret)) < 32:
        # A short secret makes tokens guessable, and a guessable token lets an
        # attacker verify a domain they do not control.
        raise ValueError("the signing secret must be at least 32 characters")
    digest = hmac.new(str(secret).encode("utf-8"),
                      str(asset).strip().lower().encode("utf-8"),
                      hashlib.sha256).hexdigest()[:40]
    return f"{TOKEN_PREFIX}={digest}"


def token_matches(asset: str, secret: str, presented: str) -> bool:
    """Constant-time comparison, because this is an authentication check."""
    expected = issue_token(asset, secret)
    return hmac.compare_digest(expected, str(presented or "").strip())


@dataclass(frozen=True)
class Verification:
    asset: str
    method: Method
    verified_at: Optional[date] = None
    expires_at: Optional[date] = None
    #: Required for MANUAL. A human attestation with nobody's name on it is not
    #: an attestation.
    approved_by: Optional[str] = None
    evidence: str = ""

    def __post_init__(self) -> None:
        if not str(self.asset).strip():
            raise ValueError("a verification must name an asset")
        if self.method is Method.MANUAL and not (self.approved_by or "").strip():
            raise ValueError(
                "a manual attestation must record who approved it — an "
                "unattributed assertion of ownership is not evidence")

    @staticmethod
    def granted(asset: str, method: Method, approved_by: Optional[str] = None,
                evidence: str = "", on: Optional[date] = None) -> "Verification":
        day = on or datetime.now(timezone.utc).date()
        return Verification(asset=str(asset).strip().lower(), method=method,
                            verified_at=day,
                            expires_at=day + timedelta(days=VALIDITY_DAYS),
                            approved_by=approved_by, evidence=evidence)

    def is_current(self, today: Optional[date] = None) -> bool:
        """Verified, and not yet expired."""
        if self.verified_at is None or self.expires_at is None:
            return False
        now = today or datetime.now(timezone.utc).date()
        return now <= self.expires_at

    def days_remaining(self, today: Optional[date] = None) -> Optional[int]:
        if self.expires_at is None:
            return None
        return (self.expires_at - (today or datetime.now(timezone.utc).date())).days

    def explain(self, today: Optional[date] = None) -> str:
        if self.verified_at is None:
            return f"{self.asset}: never verified"
        left = self.days_remaining(today)
        if left is not None and left < 0:
            return (f"{self.asset}: verification by {self.method.value} EXPIRED "
                    f"{-left} day(s) ago ({self.expires_at}); ownership must be "
                    f"re-proven before any active collection")
        return (f"{self.asset}: verified by {self.method.value} on "
                f"{self.verified_at}, {left} day(s) remaining"
                + (f", approved by {self.approved_by}" if self.approved_by else ""))


def generate_secret() -> str:
    """A signing secret for token derivation."""
    return secrets.token_urlsafe(48)
