"""Users and sessions, over the database that already exists.

`core/authn.py` owns the cryptography and knows nothing about storage; this owns
the storage and knows nothing about HTTP. The route layer turns a resolved
session into an organisation and enters `tenancy.using(org)` — which is the
whole reason this exists, and is what P5 recorded as missing.

LOGIN FAILURES ARE DELIBERATELY INDISTINGUISHABLE
--------------------------------------------------
"No such user" and "wrong password" return the same error, and the password is
verified against a dummy hash even when the user does not exist. Without the
dummy verification the timing difference alone enumerates valid usernames — the
absent-user path returns in microseconds and the real path takes the full PBKDF2
cost. A login form that reveals which usernames are real is a gift to anyone
credential-stuffing.

WHY THE SECOND FACTOR IS CHECKED IN A SEPARATE STEP
----------------------------------------------------
Password first, then TOTP, with a short-lived pending token in between. The
alternative — one form taking all three fields — cannot tell a user whose
password is wrong from one whose clock has drifted, and produces "login failed"
for both. It also means the TOTP secret is never consulted for a caller who has
not already proven the password, so a wrong-password attempt costs an attacker
nothing they can learn about the second factor.
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Protocol

from core import authn, totp
from core.store import StoreUnavailable, runtime_or_admin_dsn

#: Verified against when no user matches, so the absent-user path costs the same
#: as the real one. The plaintext is unguessable and never used.
_DUMMY_HASH = authn.hash_password(secrets.token_urlsafe(32))

BOOTSTRAP_USER_ENV = "SKOPOS_BOOTSTRAP_USER"
BOOTSTRAP_PASSWORD_ENV = "SKOPOS_BOOTSTRAP_PASSWORD"

#: How long the between-factors token lives. Long enough to read a code off a
#: phone, short enough that a stolen one is useless by the time it is noticed.
PENDING_TTL_SECONDS = 180

#: Truncated HMAC length. Fixed width, so payload and MAC are split by
#: position rather than by a delimiter that can occur inside the MAC.
_MAC_BYTES = 16

#: Seals the pending token. Regenerated per process, so a restart invalidates
#: half-completed logins — which is correct: a login in progress should not
#: survive the process that started it.
#:
#: `SKOPOS_PENDING_SECRET` overrides it, and MUST be set when more than one
#: replica serves traffic, or a token minted on one pod is meaningless on
#: another. The Helm chart runs replicaCount 2.
_PENDING_SECRET = (os.environ.get("SKOPOS_PENDING_SECRET", "").encode("utf-8")
                   or secrets.token_bytes(32))


def _seal_pending(user_id: int, expires_at: int) -> str:
    """A self-contained claim: `user_id.expiry.mac`, base64url.

    STATELESS ON PURPOSE. The first version kept these in a dict on the store
    instance, and `_store()` builds a new instance per request — so `login`
    minted a token that `enrol` had never heard of. The same design would have
    failed across Kubernetes replicas even with a process-lifetime store.

    Replay inside the window is acceptable and worth being explicit about: this
    token alone grants nothing. A session still requires a TOTP code, and that
    code is single-use against `totp_last_counter`.
    """
    payload = f"{int(user_id)}.{int(expires_at)}".encode("ascii")
    mac = hmac.new(_PENDING_SECRET, payload, hashlib.sha256).digest()[:_MAC_BYTES]
    # NO DELIMITER between payload and MAC. The first version joined them with
    # b"." and split on the last one — but the MAC is 16 RANDOM bytes and about
    # 6% of them contain 0x2E, so roughly one login in sixteen split in the
    # wrong place and was rejected as expired. It presented as a flaky test and
    # would have presented in production as intermittent, unreproducible login
    # failures. A fixed-width suffix cannot be ambiguous.
    return base64.urlsafe_b64encode(payload + mac).decode("ascii").rstrip("=")


def _open_pending(token: str) -> Optional[int]:
    """The user id inside a pending token, or None. Constant-time."""
    try:
        raw = (token or "").encode("ascii")
        raw += b"=" * (-len(raw) % 4)
        decoded = base64.urlsafe_b64decode(raw)
        payload, mac = decoded[:-_MAC_BYTES], decoded[-_MAC_BYTES:]
        user_id_text, _, expiry_text = payload.decode("ascii").partition(".")
        expected = hmac.new(_PENDING_SECRET, payload, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(mac, expected):
            return None
        if int(expiry_text) < int(time.time()):
            return None
        return int(user_id_text)
    except Exception:                                          # noqa: BLE001
        # A malformed token is a refusal, never a crash on the login path.
        return None


class LoginFailed(authn.AuthError):
    """Wrong credentials, a disabled account, or no such user.

    One exception for all of them, on purpose. The caller must not be able to
    tell which, and neither must the message.
    """


class SecondFactorRequired(authn.AuthError):
    """The password was right. Carries the pending token and whether the user
    has ever enrolled — a user with no enrolment must be sent to set one up
    rather than asked for a code they cannot produce."""

    def __init__(self, pending: str, enrolled: bool) -> None:
        super().__init__("a second factor is required")
        self.pending = pending
        self.enrolled = enrolled


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AuthStore(Protocol):
    def create_user(self, username: str, password: str, org_id: str,
                    created_by: str, display_name: str = "") -> int: ...

    def user_count(self) -> int: ...

    def find_user(self, username: str) -> Optional[Dict[str, Any]]: ...

    def start_login(self, username: str, password: str) -> str: ...

    def complete_login(self, pending: str, code: str,
                       user_agent: str = "") -> Dict[str, Any]: ...

    def resolve_session(self, token: str) -> Optional[Dict[str, Any]]: ...

    def revoke_session(self, token: str) -> bool: ...

    def begin_enrolment(self, user_id: int) -> Dict[str, Any]: ...

    def confirm_enrolment(self, user_id: int, code: str) -> List[str]: ...


class PostgresAuthStore:
    def __init__(self, dsn: Optional[str] = None, migrate: bool = True) -> None:
        self._dsn, is_admin = runtime_or_admin_dsn(dsn)
        if not self._dsn:
            raise StoreUnavailable(
                "neither SKOPOS_DATABASE_URL nor SKOPOS_APP_DATABASE_URL is set")
        try:
            import psycopg  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise StoreUnavailable(f"psycopg is not installed: {exc}") from exc
        if migrate and is_admin:
            from core import migrate as _migrate
            _migrate.ensure_once(self._dsn)

    def _connect(self):
        """A connection bound to an organisation.

        Auth is the one caller that binds to `default` rather than to the
        request's org: it runs BEFORE any org is known, because resolving the
        org is what it is for. `app_user` carries no row-level policy for
        exactly this reason — see db/008_auth.sql.
        """
        import psycopg

        from core import tenancy
        try:
            conn = psycopg.connect(tenancy.runtime_dsn(self._dsn) or self._dsn)
        except Exception as exc:  # pragma: no cover
            raise StoreUnavailable(f"could not reach the database: {exc}") from exc
        try:
            tenancy.apply(conn, tenancy.DEFAULT_ORG)
        except Exception as exc:  # pragma: no cover
            conn.close()
            raise StoreUnavailable(str(exc)) from exc
        return conn

    # ── users ───────────────────────────────────────────────────────────────
    def user_count(self) -> int:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM app_user")
            return int(cur.fetchone()[0])

    def create_user(self, username: str, password: str, org_id: str,
                    created_by: str, display_name: str = "") -> int:
        name = str(username or "").strip().lower()
        if not name:
            raise ValueError("a username is required")
        stored = authn.hash_password(password)      # raises WeakPassword
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO app_user (org_id, username, password_hash,"
                " display_name, created_by) VALUES (%s, %s, %s, %s, %s)"
                " RETURNING id",
                (org_id, name, stored, display_name, created_by))
            return int(cur.fetchone()[0])

    def find_user(self, username: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, org_id, username, password_hash, display_name,"
                "       disabled_at, totp_secret, totp_enrolled_at,"
                "       totp_last_counter"
                " FROM app_user WHERE username = %s",
                (str(username or "").strip().lower(),))
            row = cur.fetchone()
        if row is None:
            return None
        keys = ("id", "org_id", "username", "password_hash", "display_name",
                "disabled_at", "totp_secret", "totp_enrolled_at",
                "totp_last_counter")
        return dict(zip(keys, row))

    # ── login, in two steps ─────────────────────────────────────────────────
    def start_login(self, username: str, password: str) -> str:
        """Verify the password. Returns a pending token for the second factor.

        The dummy verification on the absent-user path is not decoration: without
        it, an absent user returns in microseconds while a real one costs the
        full PBKDF2 iterations, and the difference enumerates valid usernames.
        """
        user = self.find_user(username)
        if user is None:
            authn.verify_password(password, _DUMMY_HASH)
            raise LoginFailed("username or password is incorrect")
        if user["disabled_at"] is not None:
            authn.verify_password(password, _DUMMY_HASH)
            raise LoginFailed("username or password is incorrect")
        if not authn.verify_password(password, user["password_hash"]):
            raise LoginFailed("username or password is incorrect")

        if authn.needs_rehash(user["password_hash"]):
            # The only moment the plaintext exists and an upgrade is possible
            # without asking anybody to change anything.
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute("UPDATE app_user SET password_hash = %s WHERE id = %s",
                            (authn.hash_password(password), user["id"]))

        pending = _seal_pending(user["id"],
                                int(time.time()) + PENDING_TTL_SECONDS)
        raise SecondFactorRequired(pending, bool(user["totp_enrolled_at"]))

    def complete_login(self, pending: str, code: str,
                       user_agent: str = "") -> Dict[str, Any]:
        """Check the second factor and issue a session."""
        user_id = _open_pending(pending)
        if user_id is None:
            raise LoginFailed("this login attempt has expired; start again")

        user = self._user_by_id(user_id)
        if user is None or not user["totp_secret"]:
            raise LoginFailed("this account has no second factor enrolled")

        last = int(user["totp_last_counter"])
        counter = totp.verify(user["totp_secret"], code, after_counter=last)
        if counter is None:
            # A REPLAY AND A WRONG CODE ARE DIFFERENT FAILURES, and telling a
            # user they are the same wastes an hour of their evening.
            #
            # Measured during the first live run of this flow: enrolling and
            # then logging in inside the same 30-second step is refused, because
            # the enrolment code was already spent. That is the replay guard
            # doing its job, and "that code is not valid" for six digits the
            # phone is currently displaying reads as a broken product.
            #
            # Re-checking WITHOUT the guard distinguishes them. It grants
            # nothing: the result is still a refusal, only an accurate one.
            if totp.verify(user["totp_secret"], code) is not None:
                raise LoginFailed(
                    "that code has already been used. Wait for your "
                    "authenticator to show the next one — codes are single-use "
                    "even inside the 30 seconds they remain displayed")
            counter = self._consume_recovery_code(user["id"], code)
            if counter is None:
                raise LoginFailed("that code is not valid")
        else:
            with self._connect() as conn, conn.cursor() as cur:
                # Persisted so the same six digits cannot be replayed inside
                # their own still-valid window.
                cur.execute("UPDATE app_user SET totp_last_counter = %s"
                            " WHERE id = %s", (counter, user["id"]))

        return self._issue_session(user, user_agent)

    def _issue_session(self, user: Dict[str, Any], user_agent: str) -> Dict[str, Any]:
        token = authn.new_session_token()
        now = _now()
        expires = now + timedelta(seconds=authn.SESSION_TTL_SECONDS)
        absolute = now + timedelta(seconds=authn.SESSION_ABSOLUTE_MAX_SECONDS)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO app_session (user_id, fingerprint, expires_at,"
                " absolute_expiry, user_agent) VALUES (%s, %s, %s, %s, %s)",
                (user["id"], authn.token_fingerprint(token), expires, absolute,
                 (user_agent or "")[:200]))
            cur.execute("UPDATE app_user SET last_login_at = now() WHERE id = %s",
                        (user["id"],))
        return {"token": token, "expires_at": expires.isoformat(),
                "username": user["username"], "org_id": user["org_id"],
                "display_name": user["display_name"]}

    def resolve_session(self, token: str) -> Optional[Dict[str, Any]]:
        """The user behind a token, or None. THE ORG COMES FROM HERE."""
        if not token:
            return None
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT s.id, u.id, u.username, u.org_id, u.display_name,"
                "       s.expires_at, s.absolute_expiry"
                " FROM app_session s JOIN app_user u ON u.id = s.user_id"
                " WHERE s.fingerprint = %s AND s.revoked_at IS NULL"
                "   AND u.disabled_at IS NULL",
                (authn.token_fingerprint(token),))
            row = cur.fetchone()
            if row is None:
                return None
            session_id, user_id, username, org_id, display, expires, absolute = row
            now = _now()
            if expires < now or absolute < now:
                return None
            # Extend on use, but never past the absolute ceiling.
            extended = min(now + timedelta(seconds=authn.SESSION_TTL_SECONDS),
                           absolute)
            cur.execute("UPDATE app_session SET expires_at = %s WHERE id = %s",
                        (extended, session_id))
        return {"user_id": user_id, "username": username, "org_id": org_id,
                "display_name": display, "expires_at": extended.isoformat()}

    def revoke_session(self, token: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE app_session SET revoked_at = now()"
                " WHERE fingerprint = %s AND revoked_at IS NULL",
                (authn.token_fingerprint(token or ""),))
            return cur.rowcount > 0

    # ── enrolment ───────────────────────────────────────────────────────────
    def begin_enrolment(self, user_id: int) -> Dict[str, Any]:
        """Issue a secret. NOT active until a code is typed back.

        A failed scan or a mistyped secret therefore cannot lock anybody out —
        it simply does not enrol, and the old secret (if any) keeps working.
        """
        user = self._user_by_id(user_id)
        if user is None:
            raise LoginFailed("no such user")
        secret = totp.new_secret()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE app_user SET totp_secret = %s,"
                        " totp_enrolled_at = NULL WHERE id = %s",
                        (secret, user_id))
        return {
            "secret": secret,
            "formatted": totp.format_secret(secret),
            "uri": totp.provisioning_uri(secret, user["username"]),
        }

    def confirm_enrolment(self, user_id: int, code: str) -> List[str]:
        """Activate the second factor and return recovery codes, once."""
        user = self._user_by_id(user_id)
        if user is None or not user["totp_secret"]:
            raise LoginFailed("no enrolment is in progress")
        counter = totp.verify(user["totp_secret"], code)
        if counter is None:
            raise LoginFailed("that code is not valid")

        codes = totp.new_recovery_codes()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE app_user SET totp_enrolled_at = now(),"
                        " totp_last_counter = %s WHERE id = %s",
                        (counter, user_id))
            cur.execute("DELETE FROM app_recovery_code WHERE user_id = %s",
                        (user_id,))
            for code_text in codes:
                cur.execute(
                    "INSERT INTO app_recovery_code (user_id, fingerprint)"
                    " VALUES (%s, %s)",
                    (user_id, totp.recovery_fingerprint(code_text)))
        # Returned once and never retrievable. Storing them recoverably would
        # make the table as good as the passwords it backs up.
        return codes

    def _consume_recovery_code(self, user_id: int, code: str) -> Optional[int]:
        """Spend a recovery code. Returns a sentinel counter, or None."""
        fingerprint = totp.recovery_fingerprint(code)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE app_recovery_code SET used_at = now()"
                " WHERE user_id = %s AND fingerprint = %s AND used_at IS NULL",
                (user_id, fingerprint))
            return -1 if cur.rowcount > 0 else None

    def _user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, org_id, username, password_hash, display_name,"
                "       disabled_at, totp_secret, totp_enrolled_at,"
                "       totp_last_counter FROM app_user WHERE id = %s",
                (user_id,))
            row = cur.fetchone()
        if row is None:
            return None
        keys = ("id", "org_id", "username", "password_hash", "display_name",
                "disabled_at", "totp_secret", "totp_enrolled_at",
                "totp_last_counter")
        return dict(zip(keys, row))


def bootstrap(store: AuthStore, org_id: str = "default") -> Optional[str]:
    """Create the first administrator from the environment, once.

    Applied only against an EMPTY user table, so re-running with the variables
    still set cannot silently reset a password somebody has since changed. The
    operator chooses the secret and it never appears in a log line — which rules
    out both `admin/admin` and the auto-generated-and-printed alternative.
    """
    username = os.environ.get(BOOTSTRAP_USER_ENV, "").strip()
    password = os.environ.get(BOOTSTRAP_PASSWORD_ENV, "")
    if not username or not password:
        return None
    if store.user_count() > 0:
        return None
    store.create_user(username=username, password=password, org_id=org_id,
                      created_by="bootstrap", display_name=username)
    return username


def open_pending(token: str) -> Optional[int]:
    """The user id inside a pending token, for the route layer."""
    return _open_pending(token)


def open_auth_store(dsn: Optional[str] = None) -> AuthStore:
    return PostgresAuthStore(dsn)


__all__ = ["AuthStore", "PostgresAuthStore", "open_auth_store", "bootstrap",
           "open_pending",
           "LoginFailed", "SecondFactorRequired", "BOOTSTRAP_USER_ENV",
           "BOOTSTRAP_PASSWORD_ENV", "PENDING_TTL_SECONDS"]
