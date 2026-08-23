"""Authentication core — pure, stdlib-only, no database and no framework.

Ported from OverWatch's `aws_authn.py`; the reasoning is kept because the
reasoning is the load-bearing part, and the one addition — org binding — is what
makes this module matter to SKOPOS specifically.

WHAT THIS FIXES THAT IS NOT ABOUT LOGGING IN
---------------------------------------------
P5 built tenancy and left a gap that was recorded rather than hidden: row-level
security is enforced perfectly at the database, the application connects as an
unprivileged role that cannot bypass it, and **nothing resolves an organisation
per request**. `tenancy.using()` exists and nothing calls it, so every request
falls back to `SKOPOS_ORG_ID` — one organisation per deployment.

A session carries a user, and a user belongs to an organisation. That is the
missing link, and it is why authentication was built before anything in P7 that
exposes more data. The enforcement floor came first on purpose; this sits on it.

THREE DECISIONS THAT ARE EASY TO GET WRONG
-------------------------------------------
1. **PBKDF2-HMAC-SHA256, not a bare hash and not bcrypt/argon2.** `hashlib` is
   stdlib and has no build step; a native password-hashing extension would add a
   compiled dependency to a product whose collectors are deliberately
   dependency-light. The iteration count is stored IN the hash string, so raising
   it later re-hashes on next login instead of invalidating every password.

2. **The session table stores a FINGERPRINT, never the token.** The token is
   shown to the browser once and only its SHA-256 is persisted. A dump of the
   session table — a backup, a support export, a read-only SQL grant — therefore
   yields nothing anybody can present as a live session. It is the reasoning
   behind password hashes, applied to the credential that is actually sent on
   every request.

3. **Constant-time comparison everywhere**, including the fingerprint lookup. `==`
   on a secret leaks its prefix through timing, and a session token is guessable
   one byte at a time if the comparison short-circuits.

WHAT THIS MODULE IS NOT
------------------------
It is not authorisation. `core/gate.py` decides what may be done to an asset and
knows nothing about users; this decides who is asking. Those stay separate — a
logged-in user gains no permission the gate would otherwise refuse, and the
authorisation model is unchanged by the existence of a login page.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Optional, Tuple

#: Cost. Raise freely — `verify_password` reads the count from the stored
#: string, so old hashes keep verifying and `needs_rehash` reports which ones to
#: upgrade on next login.
PBKDF2_ITERATIONS = 600_000
_ALGO = "pbkdf2_sha256"
_SALT_BYTES = 16
_TOKEN_BYTES = 32                    # 256 bits of urandom; not a UUID (v4 has 122)

#: Deliberately modest and stated in one place. A length floor is the only
#: password rule with good evidence behind it; composition rules push people
#: toward `Password1!` and are not imposed here.
MIN_PASSWORD_LENGTH = 12

#: How long a session survives without being re-issued. Twelve hours is a working
#: day: long enough not to interrupt an investigation, short enough that a
#: forgotten browser on a shared machine is not a standing grant.
SESSION_TTL_SECONDS = 12 * 3600

#: Sessions extend on use but never past this from first issue, so a
#: continuously-active session still forces a fresh authentication eventually.
SESSION_ABSOLUTE_MAX_SECONDS = 7 * 24 * 3600

#: The cookie the console presents. `Secure` is set by the API when the request
#: arrived over TLS; `HttpOnly` always, so a cross-site script cannot read it.
SESSION_COOKIE = "skopos_session"


class WeakPassword(ValueError):
    """Raised on a password the policy refuses. Carries a readable reason."""


class AuthError(Exception):
    """Authentication failed. Deliberately carries no detail about WHICH half
    failed — see `core/auth_store.py`."""


def check_password_policy(password: str) -> None:
    """Raise `WeakPassword` if unacceptable. Silence means fine."""
    if password is None or not isinstance(password, str):
        raise WeakPassword("a password is required")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPassword(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if password.strip() == "":
        raise WeakPassword("a password cannot be only whitespace")


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    """`pbkdf2_sha256$<iterations>$<salt-hex>$<derived-hex>`.

    Self-describing on purpose: the algorithm and cost travel WITH the hash, so
    the verifier never has to guess how an old row was produced, and raising the
    cost is not a migration.
    """
    check_password_policy(password)
    salt = os.urandom(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                  iterations)
    return f"{_ALGO}${iterations}${salt.hex()}${derived.hex()}"


def parse_hash(stored: str) -> Optional[Tuple[str, int]]:
    """`(algorithm, iterations)` for a stored hash, or None if unreadable."""
    parts = (stored or "").split("$")
    if len(parts) != 4 or parts[0] != _ALGO:
        return None
    try:
        return parts[0], int(parts[1])
    except ValueError:
        return None


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification against a self-describing hash.

    Returns False rather than raising on a malformed stored value: a corrupt row
    must fail closed, not crash the login route and reveal that the row exists.
    """
    parts = (stored or "").split("$")
    if len(parts) != 4 or parts[0] != _ALGO:
        return False
    try:
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
    except ValueError:
        return False
    want_hex = parts[3]
    derived = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"),
                                  salt, iterations)
    return hmac.compare_digest(derived.hex(), want_hex)


def needs_rehash(stored: str, *, iterations: int = PBKDF2_ITERATIONS) -> bool:
    """Whether this hash was produced below the current cost.

    Checked on successful login, which is the only moment the plaintext exists
    and an upgrade is possible without asking anybody to change anything.
    """
    parsed = parse_hash(stored)
    return parsed is None or parsed[1] < iterations


# ── sessions ─────────────────────────────────────────────────────────────────
def new_session_token() -> str:
    """A fresh opaque bearer token. `token_urlsafe` draws from `os.urandom`."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def token_fingerprint(token: str) -> str:
    """What the database stores.

    SHA-256 rather than a stretching KDF: this is 256 bits of uniform randomness
    with no structure to guess at, so stretching buys nothing and would put a
    deliberate delay on every authenticated request. What it buys is that a
    leaked session table yields no usable sessions.
    """
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def tokens_match(token: str, stored_fingerprint: str) -> bool:
    return hmac.compare_digest(token_fingerprint(token),
                               str(stored_fingerprint or ""))


def split_cookie(header_value: str, name: str = SESSION_COOKIE) -> Optional[str]:
    """Pull one cookie out of a `Cookie:` header.

    Hand-parsed because the value is opaque and the header may carry several
    cookies set by anything else on the same host.
    """
    for chunk in (header_value or "").split(";"):
        key, _, value = chunk.strip().partition("=")
        if key == name and value:
            return value
    return None


__all__ = ["PBKDF2_ITERATIONS", "MIN_PASSWORD_LENGTH", "SESSION_TTL_SECONDS",
           "SESSION_ABSOLUTE_MAX_SECONDS", "SESSION_COOKIE", "WeakPassword",
           "AuthError", "check_password_policy", "hash_password", "parse_hash",
           "verify_password", "needs_rehash", "new_session_token",
           "token_fingerprint", "tokens_match", "split_cookie"]
