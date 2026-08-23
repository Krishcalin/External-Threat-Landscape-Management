"""Account administration, and the four ways it becomes an escalation path.

Most of this file is about things an administrator must NOT be able to do:
disable the last administrator, reach into another tenant, take over an account
by holding a stolen cookie, or read a secret out of a user listing.

The rule tests need no database — that is the point of `core/accounts.py` being
a module rather than five route bodies — so they run everywhere. The store tests
need one and skip without `SKOPOS_TEST_ADMIN_DSN`.
"""
from __future__ import annotations

import os
import uuid

import pytest

from core import accounts, authn, totp

ADMIN = {"user_id": 1, "username": "admin", "org_id": "default",
         "is_admin": True}
PLAIN = {"user_id": 2, "username": "analyst", "org_id": "default",
         "is_admin": False}
OTHER = {"id": 2, "username": "analyst", "org_id": "default",
         "is_admin": False, "disabled_at": None}


# ── who may administer ──────────────────────────────────────────────────────
def test_a_plain_user_may_not_administer():
    with pytest.raises(accounts.NotPermitted):
        accounts.require_admin(PLAIN)


def test_no_session_may_not_administer():
    with pytest.raises(accounts.NotPermitted):
        accounts.require_admin(None)


def test_the_refusal_does_not_say_which_reason_applies():
    """'You are not an administrator' confirms administrators exist here."""
    messages = set()
    for session in (None, PLAIN, {}):
        try:
            accounts.require_admin(session)
        except accounts.NotPermitted as exc:
            messages.add(str(exc))
    assert len(messages) == 1, messages


def test_administering_is_not_authority_over_an_estate():
    """The property that keeps this feature from becoming a scanning bypass.

    `core/gate.py` decides what may be done to an asset. If it ever consults
    `is_admin`, then 'can create accounts' has quietly become 'can probe
    anything', which is a far larger power and not the one being granted.
    """
    import inspect

    from core import gate
    source = inspect.getsource(gate)
    assert "is_admin" not in source
    assert "accounts" not in source


# ── creating ────────────────────────────────────────────────────────────────
def test_the_org_comes_from_the_session_not_the_caller():
    """A caller-supplied org would let one tenant's administrator plant an
    account inside another — the boundary migration 006 exists to hold,
    defeated through the front door."""
    import inspect
    signature = inspect.signature(accounts.plan_creation)
    assert "org" not in signature.parameters
    assert accounts.plan_creation(ADMIN, "newbie")["org_id"] == "default"


def test_creation_records_who_did_it():
    assert accounts.plan_creation(ADMIN, "newbie")["created_by"] == "admin"


def test_a_username_is_normalised():
    plan = accounts.plan_creation(ADMIN, "  MixedCase  ")
    assert plan["username"] == "mixedcase"


def test_a_username_with_a_space_inside_is_refused():
    """`strip()` does not catch this one, and two accounts differing only by an
    inner space is an invitation to authorise the wrong person."""
    with pytest.raises(accounts.AccountRefused):
        accounts.plan_creation(ADMIN, "two words")


def test_an_empty_username_is_refused():
    with pytest.raises(accounts.AccountRefused):
        accounts.plan_creation(ADMIN, "   ")


def test_a_plain_user_cannot_create_an_account():
    with pytest.raises(accounts.NotPermitted):
        accounts.plan_creation(PLAIN, "newbie")


def test_the_display_name_defaults_to_the_username():
    assert accounts.plan_creation(ADMIN, "newbie")["display_name"] == "newbie"


# ── the generated password ──────────────────────────────────────────────────
def test_an_issued_password_clears_the_policy():
    for _ in range(200):
        authn.check_password_policy(accounts.issue_initial_password())


def test_issued_passwords_are_not_repeated():
    seen = {accounts.issue_initial_password() for _ in range(500)}
    assert len(seen) == 500


def test_an_issued_password_avoids_ambiguous_characters():
    """It gets read down a phone line. `O` and `0` is how it gets mistyped and
    then replaced with something weak the user can actually type."""
    joined = "".join(accounts.issue_initial_password() for _ in range(200))
    for ambiguous in "O0Il1":
        assert ambiguous not in joined, ambiguous


# ── changing a password ─────────────────────────────────────────────────────
def test_a_change_requires_the_current_password():
    with pytest.raises(accounts.AccountRefused):
        accounts.check_change(PLAIN, "", "a-long-enough-passphrase")


def test_a_change_to_the_same_password_is_refused():
    with pytest.raises(accounts.AccountRefused):
        accounts.check_change(PLAIN, "same-long-passphrase",
                              "same-long-passphrase")


def test_a_weak_new_password_is_refused_by_the_existing_policy():
    with pytest.raises(authn.WeakPassword):
        accounts.check_change(PLAIN, "current-long-passphrase", "short")


def test_a_plain_user_may_change_their_own_password():
    """The one account action that is not administrative."""
    accounts.check_change(PLAIN, "current-long-passphrase",
                          "a-different-long-passphrase")


# ── disabling ───────────────────────────────────────────────────────────────
def test_you_cannot_disable_yourself():
    me = dict(OTHER, id=1, username="admin", is_admin=True)
    with pytest.raises(accounts.AccountRefused, match="your own account"):
        accounts.check_disable(ADMIN, me, admin_count=2)


def test_the_last_administrator_cannot_be_disabled():
    """There is no password reset and no recovery for an instance with no
    administrator; db/008_auth.sql records why."""
    only = dict(OTHER, id=9, username="other-admin", is_admin=True)
    with pytest.raises(accounts.AccountRefused, match="no recovery path"):
        accounts.check_disable(ADMIN, only, admin_count=1)


def test_an_administrator_can_be_disabled_when_another_exists():
    accounts.check_disable(ADMIN, dict(OTHER, id=9, is_admin=True),
                           admin_count=2)


def test_disabling_across_organisations_is_refused():
    with pytest.raises(accounts.NotPermitted):
        accounts.check_disable(ADMIN, dict(OTHER, org_id="acme"),
                               admin_count=2)


def test_a_plain_user_cannot_disable_anybody():
    with pytest.raises(accounts.NotPermitted):
        accounts.check_disable(PLAIN, OTHER, admin_count=2)


# ── promoting and demoting ──────────────────────────────────────────────────
def test_the_last_administrator_cannot_be_demoted():
    only = dict(OTHER, id=1, username="admin", is_admin=True)
    with pytest.raises(accounts.AccountRefused):
        accounts.check_role_change(ADMIN, only, make_admin=False,
                                   admin_count=1)


def test_promotion_is_allowed():
    accounts.check_role_change(ADMIN, OTHER, make_admin=True, admin_count=1)


def test_role_changes_across_organisations_are_refused():
    with pytest.raises(accounts.NotPermitted):
        accounts.check_role_change(ADMIN, dict(OTHER, org_id="acme"),
                                   make_admin=True, admin_count=2)


# ── password reset ──────────────────────────────────────────────────────────
def test_a_plain_user_cannot_reset_anybodys_password():
    with pytest.raises(accounts.NotPermitted):
        accounts.check_reset_password(PLAIN, OTHER)


def test_resetting_your_own_password_points_at_the_change_form():
    """Not dangerous — wrong tool. A reset would sign you out and hand you a
    password you then have to change."""
    me = dict(OTHER, id=1, username="admin", is_admin=True)
    with pytest.raises(accounts.AccountRefused, match="change-password form"):
        accounts.check_reset_password(ADMIN, me)


def test_a_password_reset_across_organisations_is_refused():
    with pytest.raises(accounts.NotPermitted):
        accounts.check_reset_password(ADMIN, dict(OTHER, org_id="acme"))


def test_only_one_password_generator_exists():
    """Two generators drift, and the weaker one is the one nobody re-reads. The
    store takes a password rather than making its own for this reason."""
    import inspect
    from core import auth_store
    assert "password" in inspect.signature(
        auth_store.PostgresAuthStore.reset_password).parameters
    assert "secrets" not in inspect.getsource(auth_store.PostgresAuthStore)


def test_the_takeover_path_is_stated_rather_than_denied():
    """An administrator who resets a password AND a second factor can sign in
    as that user. The module must not claim otherwise — it did once."""
    import inspect
    # Whitespace-normalised: the sentences being looked for are wrapped across
    # lines in the source, and a raw substring check fails on the line break
    # rather than on the claim being absent.
    source = " ".join(inspect.getsource(accounts).split())
    assert "can sign in as that user" in source
    assert "does not pretend otherwise" in source


# ── second-factor reset ─────────────────────────────────────────────────────
def test_a_plain_user_cannot_reset_anybodys_second_factor():
    with pytest.raises(accounts.NotPermitted):
        accounts.check_reset_second_factor(PLAIN, OTHER)


def test_a_second_factor_reset_across_organisations_is_refused():
    with pytest.raises(accounts.NotPermitted):
        accounts.check_reset_second_factor(ADMIN, dict(OTHER, org_id="acme"))


# ── what a listing may contain ──────────────────────────────────────────────
def test_a_described_user_carries_no_secret_material():
    """Built up field by field rather than filtered down, so a column added to
    the query tomorrow cannot leak by default."""
    described = accounts.describe({
        "id": 2, "username": "analyst", "display_name": "Analyst",
        "org_id": "default", "is_admin": False, "disabled_at": None,
        "totp_secret": "JBSWY3DPEHPK3PXP", "totp_enrolled_at": None,
        "password_hash": "pbkdf2_sha256$600000$salt$derived",
        "must_change_password": True, "created_at": None,
        "created_by": "admin", "last_login_at": None,
    }, self_id=2)
    flat = repr(described)
    assert "JBSWY3DPEHPK3PXP" not in flat
    assert "pbkdf2" not in flat
    assert "totp_secret" not in described and "password_hash" not in described
    assert described["second_factor"] == "not enrolled"
    assert described["is_you"] is True


def test_the_summary_counts_the_accounts_nobody_watches():
    """A created-and-never-used account is either a colleague who never got
    their credential or an account nobody needed. Neither shows in a total."""
    users = [
        {"is_admin": True, "disabled": False, "second_factor": "enrolled",
         "last_login_at": "2026-08-01T00:00:00+00:00"},
        {"is_admin": False, "disabled": False, "second_factor": "not enrolled",
         "last_login_at": None},
        {"is_admin": False, "disabled": True, "second_factor": "not enrolled",
         "last_login_at": None},
    ]
    summary = accounts.summarise(users)
    assert summary == {"total": 3, "administrators": 1, "disabled": 1,
                       "awaiting_second_factor": 1, "never_signed_in": 1}


# ── the middleware lock ─────────────────────────────────────────────────────
def test_a_locked_session_can_reach_only_four_paths():
    from api import auth_routes
    assert set(auth_routes.LOCKED_ALLOWED) == {
        "/api/v1/auth/session", "/api/v1/auth/logout",
        "/api/v1/account/password", "/api/v1/health"}


def test_the_lock_is_in_the_middleware_not_a_dependency():
    """A dependency binds only for routes that declare it, so a route added by
    somebody who has not heard of this would serve a locked session."""
    import inspect
    from api import auth_routes
    source = inspect.getsource(auth_routes.register)
    assert "must_change_password" in source
    assert "LOCKED_ALLOWED" in source


def test_every_mutating_account_route_writes_an_audit_record():
    """These powers are not all preventable, so they have to be
    reconstructable. A route that mutates and does not audit is a power with no
    record."""
    import inspect
    import re
    from api import account_routes

    source = inspect.getsource(account_routes.register)
    # Split into route bodies at each decorator.
    bodies = re.split(r"\n    @app\.post\(", source)[1:]
    # Without this, a decorator whose formatting changed would make the split
    # find nothing and the loop below pass over an empty list — a green test
    # asserting nothing at all.
    assert len(bodies) >= 6, f"expected the POST routes, found {len(bodies)}"
    for body in bodies:
        name = body.split("def ", 1)[1].split("(", 1)[0]
        assert "_audit(" in body, f"{name} mutates without an audit record"


def test_an_audit_payload_never_carries_a_password():
    """An audit log that records credentials is a credential store with worse
    access control.

    Parsed rather than grepped. A line-based version of this test fired on
    `must_change_password=True` in an unrelated `create_user` call — the same
    mistake as a banned-word check that trips on the disclaimer preventing the
    thing, and one this repository has now made three times.
    """
    import ast
    import inspect
    from api import account_routes

    tree = ast.parse(inspect.getsource(account_routes).lstrip())
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "_audit"]
    assert calls, "no audit calls found; the parse is wrong, not the code"
    for call in calls:
        for keyword in call.keywords:
            assert keyword.arg not in ("password", "initial_password",
                                       "issued", "new_password"), keyword.arg
            # And no argument may be the issued credential by another name.
            rendered = ast.unparse(keyword.value)
            assert "issued" not in rendered, rendered
            assert "plan[\"password\"]" not in rendered, rendered


def test_the_password_route_is_on_the_allowed_list():
    """Otherwise the only account that must change its password is the one
    account that cannot."""
    from api import account_routes, auth_routes
    from fastapi import FastAPI
    app = FastAPI()
    account_routes.register(app)
    paths = {r.path for r in app.routes}
    for allowed in auth_routes.LOCKED_ALLOWED:
        if allowed.startswith("/api/v1/account/"):
            assert allowed in paths, allowed


# ── the live store ──────────────────────────────────────────────────────────
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
    """A throwaway database AND a throwaway role — a PostgreSQL role is
    cluster-wide, and a fixture that resets `skopos_app` breaks the running
    application. That happened once here; see tests/test_authn.py."""
    import psycopg

    from core import migrate
    from core.auth_store import PostgresAuthStore

    name = f"skopos_acct_{uuid.uuid4().hex[:12]}"
    role = f"skopos_r_{uuid.uuid4().hex[:10]}"
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
        yield PostgresAuthStore(f"{head}://{role}:{password}@{rest}",
                                migrate=False)
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            admin.execute(f'DROP ROLE IF EXISTS "{role}"')


def _signed_in(store, *, is_admin=False, must_change=False):
    """A user with a live session token."""
    username = f"u{uuid.uuid4().hex[:8]}"
    user_id = store.create_user(username, "a-long-enough-passphrase", "default",
                                created_by="test", is_admin=is_admin,
                                must_change_password=must_change)
    enrolment = store.begin_enrolment(user_id)
    store.confirm_enrolment(user_id, totp.code_now(enrolment["secret"]))
    return {"id": user_id, "username": username,
            "password": "a-long-enough-passphrase",
            "secret": enrolment["secret"]}


@live
def test_the_bootstrap_user_is_an_administrator(store):
    """Nothing else can grant the flag, so a first user without it would be an
    instance where no account can ever be created."""
    from core.auth_store import bootstrap
    name = f"boot{uuid.uuid4().hex[:8]}"
    os.environ["SKOPOS_BOOTSTRAP_USER"] = name
    os.environ["SKOPOS_BOOTSTRAP_PASSWORD"] = "a-long-enough-passphrase"
    try:
        created = bootstrap(store)
    finally:
        os.environ.pop("SKOPOS_BOOTSTRAP_USER", None)
        os.environ.pop("SKOPOS_BOOTSTRAP_PASSWORD", None)
    if created is None:
        pytest.skip("a user already existed in this fixture database")
    assert store.find_user(created)["is_admin"] is True


@live
def test_a_created_account_must_change_its_password(store):
    user = _signed_in(store, must_change=True)
    assert store.find_user(user["username"])["must_change_password"] is True


@live
def test_changing_a_password_clears_the_must_change_flag(store):
    user = _signed_in(store, must_change=True)
    store.change_password(user["id"], user["password"], "a-brand-new-passphrase")
    assert store.find_user(user["username"])["must_change_password"] is False


@live
def test_a_wrong_current_password_is_refused(store):
    """Without this, a stolen cookie becomes a permanent takeover: the thief
    sets a new password and the owner is locked out of their own account."""
    from core.auth_store import LoginFailed
    user = _signed_in(store)
    with pytest.raises(LoginFailed):
        store.change_password(user["id"], "not-the-password",
                              "a-brand-new-passphrase")
    # And the old password still works.
    assert authn.verify_password(
        user["password"], store.find_user(user["username"])["password_hash"])


@live
def test_a_password_change_revokes_other_sessions_and_keeps_yours(store):
    user = _signed_in(store)
    tokens = [_full_login(store, user) for _ in range(3)]
    keep = tokens[-1]

    revoked = store.change_password(user["id"], user["password"],
                                    "a-brand-new-passphrase", keep_token=keep)
    assert revoked == 2, "the other two sessions should be gone"
    assert store.resolve_session(keep) is not None, "yours must survive"
    for gone in tokens[:-1]:
        assert store.resolve_session(gone) is None


@live
def test_disabling_an_account_cuts_its_sessions_immediately(store):
    """Otherwise the account being disabled BECAUSE it is compromised keeps
    working for whoever holds the cookie, for hours."""
    user = _signed_in(store)
    token = _full_login(store, user)
    assert store.resolve_session(token) is not None
    store.set_disabled(user["id"], True)
    assert store.resolve_session(token) is None


@live
def test_restoring_an_account_lets_it_sign_in_again(store):
    user = _signed_in(store)
    store.set_disabled(user["id"], True)
    store.set_disabled(user["id"], False)
    assert store.find_user(user["username"])["disabled_at"] is None
    assert _full_login(store, user)


@live
def test_resetting_a_second_factor_clears_the_old_secret(store):
    """A recovered phone — or one in somebody else's hands — must not keep
    producing accepted codes after the reset performed because of it."""
    user = _signed_in(store)
    old_secret = user["secret"]
    store.reset_second_factor(user["id"])
    row = store.find_user(user["username"])
    assert row["totp_secret"] is None, "the old secret must not survive"
    assert row["totp_enrolled_at"] is None
    # The old authenticator still produces codes; there is now nothing stored
    # for them to be checked against, which is the whole point.
    assert totp.code_now(old_secret) and row["totp_secret"] != old_secret
    # -1 rather than NULL or 0. The column is NOT NULL, so this crashed the
    # first time it ran; -1 is its sentinel for 'nothing accepted yet'.
    assert row["totp_last_counter"] == -1


@live
def test_resetting_a_second_factor_revokes_sessions(store):
    user = _signed_in(store)
    token = _full_login(store, user)
    store.reset_second_factor(user["id"])
    assert store.resolve_session(token) is None


@live
def test_a_listing_is_scoped_to_one_organisation(store):
    """The org is a required argument, not an optional filter — an optional
    filter defaults to unfiltered, and one omission hands a tenant's
    administrator every account on the instance."""
    import inspect
    mine = _signed_in(store)
    listed = store.list_users("default")
    assert mine["username"] in {u["username"] for u in listed}
    assert all(u["org_id"] == "default" for u in listed)
    org = inspect.signature(store.list_users).parameters["org_id"]
    assert org.default is inspect.Parameter.empty, "org must not be optional"


@live
def test_admin_count_ignores_disabled_administrators(store):
    """A disabled administrator cannot create accounts, so counting one as the
    safety net that permits demoting the last active one leaves nobody."""
    before = store.admin_count("default")
    extra = _signed_in(store, is_admin=True)
    assert store.admin_count("default") == before + 1
    store.set_disabled(extra["id"], True)
    assert store.admin_count("default") == before


@live
def test_a_reset_password_locks_the_account_to_the_change_form(store):
    """Otherwise a reset would hand somebody a working account on a credential
    the administrator has seen, with nothing forcing it to be replaced."""
    user = _signed_in(store)
    issued = accounts.issue_initial_password()
    store.reset_password(user["id"], issued)
    row = store.find_user(user["username"])
    assert row["must_change_password"] is True
    assert authn.verify_password(issued, row["password_hash"])
    assert not authn.verify_password(user["password"], row["password_hash"])


@live
def test_a_reset_password_revokes_every_session(store):
    user = _signed_in(store)
    token = _full_login(store, user)
    store.reset_password(user["id"], accounts.issue_initial_password())
    assert store.resolve_session(token) is None


@live
def test_a_reset_leaves_the_second_factor_alone(store):
    """They forgot a password, not their phone. Clearing the enrolment as well
    would turn one recovery into two, and weaken the account for no reason."""
    user = _signed_in(store)
    store.reset_password(user["id"], accounts.issue_initial_password())
    assert store.find_user(user["username"])["totp_secret"] == user["secret"]


@live
def test_a_session_carries_the_admin_flag(store):
    """Read on every request rather than stamped at login, so a demotion takes
    effect on the next request rather than whenever the session expires."""
    user = _signed_in(store, is_admin=False)
    token = _full_login(store, user)
    assert store.resolve_session(token)["is_admin"] is False
    store.set_admin(user["id"], True)
    assert store.resolve_session(token)["is_admin"] is True


# ── helpers for the live flow ───────────────────────────────────────────────
def _full_login(store, user) -> str:
    """Password then code, returning the session token.

    Waits for the next TOTP step first. The replay guard refuses a counter it
    has already accepted — which is the point of it — so two logins inside one
    30-second step cannot both succeed, and a test that logs in three times
    would otherwise fail on the guard working correctly.
    """
    import time

    from core.auth_store import SecondFactorRequired
    time.sleep(totp.PERIOD - (time.time() % totp.PERIOD) + 0.3)
    try:
        store.start_login(user["username"], user["password"])
    except SecondFactorRequired as required:
        session = store.complete_login(required.pending,
                                       totp.code_now(user["secret"]))
        return session["token"]
    raise AssertionError("login did not demand a second factor")
