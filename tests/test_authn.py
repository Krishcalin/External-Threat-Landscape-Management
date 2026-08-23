"""Password hashing, session tokens, and the login flow against a real database.

The offline half needs no database. The live half creates its own throwaway one
and its own throwaway role — a PostgreSQL role is cluster-wide, and a test that
touched `skopos_app` would break the running application, which has happened
once already in this repository's history.
"""
from __future__ import annotations

import os
import uuid

import pytest

from core import authn, totp
from core.authn import WeakPassword


# ── password hashing ────────────────────────────────────────────────────────
def test_a_hash_is_self_describing():
    """The algorithm and cost travel WITH the hash, so raising the cost later is
    a re-hash on next login rather than a migration."""
    stored = authn.hash_password("a-long-enough-passphrase")
    algorithm, iterations = authn.parse_hash(stored)
    assert algorithm == "pbkdf2_sha256"
    assert iterations == authn.PBKDF2_ITERATIONS
    assert stored.count("$") == 3


def test_the_same_password_hashes_differently_every_time():
    """A shared salt would make one rainbow table cover every user."""
    a = authn.hash_password("a-long-enough-passphrase")
    b = authn.hash_password("a-long-enough-passphrase")
    assert a != b
    assert authn.verify_password("a-long-enough-passphrase", a)
    assert authn.verify_password("a-long-enough-passphrase", b)


def test_a_wrong_password_does_not_verify():
    stored = authn.hash_password("a-long-enough-passphrase")
    assert not authn.verify_password("a-long-enough-passphras", stored)
    assert not authn.verify_password("", stored)


@pytest.mark.parametrize("corrupt", ["", "nonsense", "pbkdf2_sha256$x$y$z",
                                     "pbkdf2_sha256$1$notahex$deadbeef",
                                     "argon2$1$aa$bb", "a$b$c$d$e"])
def test_a_corrupt_stored_hash_fails_closed_rather_than_raising(corrupt):
    """A crash on the login route reveals that the row exists."""
    assert authn.verify_password("anything", corrupt) is False


def test_an_old_hash_is_flagged_for_upgrade_but_still_verifies():
    stored = authn.hash_password("a-long-enough-passphrase", iterations=1000)
    assert authn.verify_password("a-long-enough-passphrase", stored)
    assert authn.needs_rehash(stored) is True
    assert authn.needs_rehash(authn.hash_password("a-long-enough-passphrase")) is False


def test_an_unreadable_hash_is_treated_as_needing_a_rehash():
    assert authn.needs_rehash("nonsense") is True


# ── password policy ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", ["", "   ", "short", "elevenchar", None, 12345])
def test_the_policy_refuses_what_it_should(bad):
    with pytest.raises(WeakPassword):
        authn.check_password_policy(bad)


def test_the_only_rule_is_length():
    """Composition rules push people toward `Password1!`, so none are imposed."""
    authn.check_password_policy("aaaaaaaaaaaa")
    assert authn.MIN_PASSWORD_LENGTH == 12


def test_a_weak_password_cannot_be_hashed_at_all():
    """Enforced at the hash, not only at the route, so a second caller cannot
    bypass the policy by not knowing about it."""
    with pytest.raises(WeakPassword):
        authn.hash_password("short")


# ── session tokens ──────────────────────────────────────────────────────────
def test_a_token_is_256_bits_of_urandom():
    token = authn.new_session_token()
    assert len(token) >= 43        # 32 bytes, url-safe base64, unpadded
    assert len({authn.new_session_token() for _ in range(200)}) == 200


def test_only_a_fingerprint_is_ever_stored():
    """A dump of the session table — a backup, a support export, a read-only
    grant — must yield nothing anybody can present as a live session."""
    token = authn.new_session_token()
    fingerprint = authn.token_fingerprint(token)
    assert len(fingerprint) == 64
    assert token not in fingerprint
    assert authn.tokens_match(token, fingerprint)
    assert not authn.tokens_match(authn.new_session_token(), fingerprint)


def test_a_missing_token_matches_nothing():
    assert not authn.tokens_match("", authn.token_fingerprint("x"))
    assert not authn.tokens_match("x", "")


def test_the_cookie_is_found_among_others():
    header = "other=1; skopos_session=abc123; another=2"
    assert authn.split_cookie(header) == "abc123"
    assert authn.split_cookie("nothing=here") is None
    assert authn.split_cookie("") is None


def test_sessions_expire_and_have_an_absolute_ceiling():
    """A continuously-active session must still force a fresh authentication."""
    assert authn.SESSION_TTL_SECONDS < authn.SESSION_ABSOLUTE_MAX_SECONDS


# ── the live flow ───────────────────────────────────────────────────────────
ADMIN_DSN = os.environ.get("SKOPOS_TEST_ADMIN_DSN", "")


def _reachable(dsn):
    if not dsn:
        return False
    try:
        import psycopg
        with psycopg.connect(dsn, connect_timeout=3):
            return True
    except Exception:
        return False


live = pytest.mark.skipif(not _reachable(ADMIN_DSN),
                          reason="set SKOPOS_TEST_ADMIN_DSN to a live database")


@pytest.fixture(scope="module")
def store():
    """A throwaway database AND a throwaway role.

    A PostgreSQL role is cluster-wide: a test that reset `skopos_app`'s password
    would break the running application, which is exactly what happened once in
    this repository and is why `ensure_app_role` takes a role name.
    """
    import psycopg

    from core import migrate
    from core.auth_store import PostgresAuthStore

    name = f"skopos_auth_{uuid.uuid4().hex[:12]}"
    role = f"skopos_a_{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
        admin.execute(f'CREATE ROLE "{role}" NOSUPERUSER NOBYPASSRLS')
    dsn = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    try:
        migrate.ensure_current(dsn)
        migrate.ensure_app_role(dsn, password, role=role)
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(f'GRANT "skopos_app" TO "{role}"')
            conn.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
        head, tail = dsn.split("://", 1)
        _, rest = tail.split("@", 1)
        yield PostgresAuthStore(f"{head}://{role}:{password}@{rest}", migrate=False)
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            admin.execute(f'DROP ROLE IF EXISTS "{role}"')


@pytest.fixture
def enrolled(store):
    """A user with a working second factor."""
    from core.auth_store import SecondFactorRequired
    username = f"u{uuid.uuid4().hex[:8]}"
    user_id = store.create_user(username, "a-long-enough-passphrase", "default",
                                created_by="test")
    enrolment = store.begin_enrolment(user_id)
    store.confirm_enrolment(user_id, totp.code_now(enrolment["secret"]))
    return {"username": username, "id": user_id,
            "secret": enrolment["secret"],
            "password": "a-long-enough-passphrase"}


def _with_margin(seconds: float = 5.0) -> None:
    """Wait until the current TOTP step has room left in it.

    Without this, a test that logs in twice can straddle a 30-second boundary:
    the code it is replaying ages out of the ±1 drift window entirely, verify
    finds no match at all, and the replay assertion fails against "that code is
    not valid" instead of "already been used". That is a flake in the test, not
    a defect in the guard — but a suite that fails once a fortnight at 00:29:58
    is a suite people stop believing.
    """
    import time
    remaining = totp.PERIOD - (time.time() % totp.PERIOD)
    if remaining < seconds:
        time.sleep(remaining + 0.2)


def _next_code(secret):
    """The code for the FOLLOWING step, which is what a real user reads.

    The enrolment code is spent the moment it activates the second factor, so a
    user who enrols and immediately logs in inside the same 30-second window is
    correctly refused — the product tells them to wait for the next code. This
    helper does what the product instructs. It is still inside the drift window,
    so it goes through the real verify path rather than around it.
    """
    return totp.code_at(secret, totp.counter_at() + 1)


def _login(store, user, code=None):
    from core.auth_store import SecondFactorRequired
    try:
        store.start_login(user["username"], user["password"])
    except SecondFactorRequired as exc:
        return store.complete_login(
            exc.pending, code or _next_code(user["secret"]))
    raise AssertionError("a second factor was not demanded")


@live
def test_a_password_alone_never_produces_a_session(store, enrolled):
    """The whole point of the second factor."""
    from core.auth_store import SecondFactorRequired
    with pytest.raises(SecondFactorRequired):
        store.start_login(enrolled["username"], enrolled["password"])


@live
def test_a_wrong_password_and_an_absent_user_are_indistinguishable(store, enrolled):
    """A login form that reveals which usernames are real is a gift to anyone
    credential-stuffing."""
    from core.auth_store import LoginFailed
    with pytest.raises(LoginFailed) as wrong:
        store.start_login(enrolled["username"], "wrong-but-long-enough")
    with pytest.raises(LoginFailed) as absent:
        store.start_login("nobody-at-all", "wrong-but-long-enough")
    assert str(wrong.value) == str(absent.value)


@live
def test_a_session_carries_the_organisation(store, enrolled):
    """THE POINT OF THIS MIGRATION. P5 left tenancy enforced at the database
    with nothing resolving an org per request; a session closes that."""
    session = _login(store, enrolled)
    assert session["org_id"] == "default"
    resolved = store.resolve_session(session["token"])
    assert resolved["org_id"] == "default"
    assert resolved["username"] == enrolled["username"]


@live
def test_a_replayed_code_is_refused_and_says_so(store, enrolled):
    """Measured on the first live run: enrolling and logging in inside the same
    30-second step is refused, and 'that code is not valid' for six digits the
    phone is displaying reads as a broken product."""
    from core.auth_store import LoginFailed
    _with_margin()
    code = _next_code(enrolled["secret"])
    _login(store, enrolled, code)
    with pytest.raises(LoginFailed) as exc:
        _login(store, enrolled, code)
    assert "already been used" in str(exc.value)
    assert "next one" in str(exc.value)


@live
def test_a_wrong_code_reads_differently_from_a_replay(store, enrolled):
    from core.auth_store import LoginFailed
    with pytest.raises(LoginFailed) as exc:
        _login(store, enrolled, "000000")
    assert "not valid" in str(exc.value)
    assert "already been used" not in str(exc.value)


@live
def test_a_revoked_session_resolves_to_nothing(store, enrolled):
    session = _login(store, enrolled)
    assert store.revoke_session(session["token"]) is True
    assert store.resolve_session(session["token"]) is None


@live
def test_an_unknown_token_resolves_to_nothing(store):
    assert store.resolve_session(authn.new_session_token()) is None
    assert store.resolve_session("") is None


@live
def test_enrolment_is_not_active_until_a_code_is_typed_back(store):
    """A failed scan or a mistyped secret must never lock anybody out."""
    from core.auth_store import LoginFailed, SecondFactorRequired
    username = f"u{uuid.uuid4().hex[:8]}"
    user_id = store.create_user(username, "a-long-enough-passphrase", "default",
                                created_by="test")
    store.begin_enrolment(user_id)
    with pytest.raises(SecondFactorRequired) as exc:
        store.start_login(username, "a-long-enough-passphrase")
    assert exc.value.enrolled is False, "not enrolled until confirmed"


@live
def test_a_recovery_code_works_once(store, enrolled):
    """A wiped phone must not be a permanently locked account — and for the
    first administrator there is nobody left to ask."""
    from core.auth_store import LoginFailed
    codes = store.confirm_enrolment(enrolled["id"],
                                    _next_code(enrolled["secret"]))
    session = _login(store, enrolled, codes[0])
    assert session["org_id"] == "default"
    with pytest.raises(LoginFailed):
        _login(store, enrolled, codes[0])


@live
def test_bootstrap_applies_once_and_never_resets_a_password(store):
    """Re-running with the variables still set must not silently reset a
    password somebody has since changed."""
    from core import auth_store as module
    os.environ[module.BOOTSTRAP_USER_ENV] = f"boot{uuid.uuid4().hex[:6]}"
    os.environ[module.BOOTSTRAP_PASSWORD_ENV] = "a-long-enough-passphrase"
    try:
        before = store.user_count()
        if before == 0:
            assert module.bootstrap(store) is not None
        assert module.bootstrap(store) is None, "second call must be a no-op"
    finally:
        os.environ.pop(module.BOOTSTRAP_USER_ENV, None)
        os.environ.pop(module.BOOTSTRAP_PASSWORD_ENV, None)


@live
def test_there_is_no_default_credential(store):
    """Not admin/admin, and not an auto-generated one printed to stdout —
    container logs are aggregated, shipped and retained."""
    from core import auth_store as module
    os.environ.pop(module.BOOTSTRAP_USER_ENV, None)
    os.environ.pop(module.BOOTSTRAP_PASSWORD_ENV, None)
    assert module.bootstrap(store) is None
    for guess in ("admin", "root", "skopos", "administrator"):
        assert store.find_user(guess) is None, guess


# ── the sealed pending token ────────────────────────────────────────────────
def test_a_sealed_pending_token_always_round_trips():
    """Twenty thousand tokens, because the bug this guards was PROBABILISTIC.

    The first version joined payload and MAC with b"." and split on the last
    one. The MAC is 16 random bytes and ~6% of them contain 0x2E, so roughly one
    login in sixteen split in the wrong place and was rejected as expired. It
    surfaced as a flaky test; in production it would have been intermittent,
    unreproducible login failures with nothing in the logs.

    A single round-trip assertion would have passed 94% of the time and taught
    nobody anything.
    """
    import time

    from core.auth_store import _open_pending, _seal_pending
    expiry = int(time.time()) + 180
    for user_id in range(1, 20001):
        assert _open_pending(_seal_pending(user_id, expiry)) == user_id


def test_a_tampered_pending_token_is_refused():
    import time

    from core.auth_store import _open_pending, _seal_pending
    token = _seal_pending(7, int(time.time()) + 180)
    assert _open_pending(token) == 7
    flipped = ("A" if token[0] != "A" else "B") + token[1:]
    assert _open_pending(flipped) is None


def test_an_expired_pending_token_is_refused():
    import time

    from core.auth_store import _open_pending, _seal_pending
    assert _open_pending(_seal_pending(7, int(time.time()) - 1)) is None


@pytest.mark.parametrize("junk", ["", "!!!!", "a", "x" * 200, "....."])
def test_a_malformed_pending_token_is_a_refusal_not_a_crash(junk):
    """The login path must not raise on input an attacker controls."""
    from core.auth_store import _open_pending
    assert _open_pending(junk) is None
