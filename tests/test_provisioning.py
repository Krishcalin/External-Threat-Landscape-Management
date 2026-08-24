"""Creating an organisation: the validation, and the transaction.

The property most of these defend is that a tenant is created WHOLE or not at
all. An org with no users is unreachable — nobody can log in to it, so nobody
can create the account that would make it usable — and it is invisible, because
every listing is scoped to a session that cannot exist for it.
"""
from __future__ import annotations

import ast
import inspect
import os
import uuid

import pytest

from core import provisioning as prov

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


# ── validation ──────────────────────────────────────────────────────────────
def test_a_valid_request_produces_a_plan():
    plan = prov.plan("acme", "Acme Ltd", "jane")
    assert plan.org_id == "acme" and plan.admin_username == "jane"


def test_the_default_org_is_reserved():
    """It holds every row that predates tenancy, so handing it to a new
    customer would give them the instance's own history."""
    with pytest.raises(prov.ProvisioningRefused) as exc:
        prov.plan("default", "Someone Else", "jane")
    assert "reserved" in str(exc.value)


@pytest.mark.parametrize("org_id", ["Bad Id", "", "-leading", "x" * 64, "UPPER"])
def test_an_invalid_org_id_is_refused(org_id):
    """The same rule the org table's CHECK constraint enforces — refused here
    so the operator gets a sentence rather than a constraint violation."""
    with pytest.raises(prov.ProvisioningRefused):
        prov.plan(org_id, "Name", "jane")


def test_an_organisation_needs_a_name():
    """An id alone tells the next operator nothing about whose tenant it is."""
    with pytest.raises(prov.ProvisioningRefused):
        prov.plan("acme", "   ", "jane")


@pytest.mark.parametrize("username", ["", "has space", "x" * 129])
def test_an_invalid_admin_username_is_refused(username):
    with pytest.raises(prov.ProvisioningRefused):
        prov.plan("acme", "Acme", username)


def test_the_username_rules_match_the_ones_accounts_applies():
    """A first administrator created by a different rule from every later
    account is a difference nobody would think to look for."""
    from core import accounts
    session = {"is_admin": True, "org_id": "acme", "username": "root"}
    assert (accounts.plan_creation(session, "  JANE ")["username"]
            == prov.plan("acme", "Acme", "  JANE ").admin_username)


# ── properties of the plan, not choices ─────────────────────────────────────
def test_the_first_account_is_always_an_administrator():
    """An org whose only user cannot create users is unreachable by a
    different route. Not a parameter, so a caller cannot get it wrong."""
    plan = prov.plan("acme", "Acme", "jane")
    assert plan.is_admin is True
    assert "is_admin" not in inspect.signature(prov.plan).parameters


def test_the_first_account_must_change_its_password():
    """It is a credential the operator has seen, so it is not the user's own
    account until they have changed it."""
    assert prov.plan("acme", "Acme", "jane").must_change_password is True


def test_the_credential_never_appears_in_the_serialisable_form():
    """`to_dict` is what gets logged and audited."""
    plan = prov.plan("acme", "Acme", "jane")
    payload = plan.to_dict()
    assert plan.password not in str(payload)
    assert "password" not in payload and "password_hash" not in payload


def test_the_password_is_generated_rather_than_chosen():
    """An administrator choosing passwords picks a house pattern, and a house
    pattern means every account on the instance shares a guessable prefix."""
    first = prov.plan("a1", "A", "jane").password
    second = prov.plan("a2", "A", "jane").password
    assert first != second and len(first) > 12


def test_the_stored_form_is_a_hash_not_the_password():
    plan = prov.plan("acme", "Acme", "jane")
    assert plan.password_hash.startswith("pbkdf2_sha256$")
    assert plan.password not in plan.password_hash


def test_an_explicit_empty_password_is_refused():
    with pytest.raises(prov.ProvisioningRefused):
        prov.plan("acme", "Acme", "jane", password="   ")


# ── planning touches no database ────────────────────────────────────────────
def test_planning_performs_no_database_access():
    """Whether the org exists is a question for the transaction, where the
    primary key answers it atomically. Checking here would be a race, and a
    race that reports "created" while doing nothing is worse than a
    constraint violation."""
    tree = ast.parse(inspect.getsource(prov))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    for banned in ("psycopg", "psycopg2", "sqlite3", "core.store"):
        assert banned not in imported


# ── failures are told apart by constraint name ──────────────────────────────
def test_a_username_clash_is_not_reported_as_an_org_clash():
    """Both violations say "duplicate key". Matching on that phrase reported a
    taken username as "that organisation already exists", which sent the
    operator looking for a tenant that was not there. Found by provisioning
    against a real database — a dry run could not have shown it."""
    username_error = ('duplicate key value violates unique constraint '
                      '"app_user_username_key"')
    org_error = ('duplicate key value violates unique constraint "org_pkey"')
    assert prov.classify_failure(username_error) == "username_taken"
    assert prov.classify_failure(org_error) == "org_exists"


def test_an_unrelated_error_is_not_classified():
    """So it is reported verbatim rather than as a wrong guess."""
    assert prov.classify_failure("connection refused") == ""


def test_the_username_message_says_usernames_are_instance_wide():
    """`app_user.username` is UNIQUE across the whole instance, not per
    tenant — surprising enough to be worth saying outright."""
    text = prov.describe_username_taken(prov.plan("acme", "Acme", "jane"))
    assert "unique across the whole instance" in text
    assert "rolled back" in text


def test_the_refusal_to_be_an_endpoint_is_stated_on_the_plan():
    """The reasoning travels with the thing rather than living only in a
    docstring."""
    assert "not an API endpoint" in prov.plan("a", "A", "j").to_dict()["why_not_an_api"]


# ── the transaction ─────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def dsn():
    """A throwaway database, migrated. Never the running one.

    `tests/test_accounts.py` records why the role is throwaway too: a
    PostgreSQL role is cluster-wide, and a fixture that resets `skopos_app`
    breaks the running application. That happened once.
    """
    import psycopg

    from core import migrate

    name = f"skopos_prov_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    target = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    try:
        migrate.ensure_current(target)
        yield target
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def _count(dsn_, sql, *args):
    import psycopg
    with psycopg.connect(dsn_) as conn, conn.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchone()[0]


@live
def test_provisioning_creates_the_org_and_its_administrator(dsn):
    from tools import provision_org

    plan = prov.plan("acme-live", "Acme Live", "acmeadmin",
                     note="created by tests")
    provision_org.provision(plan, dsn)

    assert _count(dsn, "SELECT count(*) FROM org WHERE id=%s", "acme-live") == 1
    assert _count(dsn, "SELECT count(*) FROM app_user WHERE org_id=%s AND "
                       "is_admin AND must_change_password", "acme-live") == 1


@live
def test_a_failed_second_statement_leaves_no_org_behind(dsn):
    """THE PROPERTY THIS EXISTS FOR. A half-provisioned tenant is not a
    partial success — it is an unreachable row somebody has to find and delete
    by hand later."""
    from tools import provision_org

    first = prov.plan("rollback-a", "First", "clasher")
    provision_org.provision(first, dsn)

    # Same username, different org. The org insert succeeds, the user insert
    # violates the instance-wide unique constraint, and both must vanish.
    second = prov.plan("rollback-b", "Second", "clasher")
    with pytest.raises(Exception) as exc:
        provision_org.provision(second, dsn)
    assert prov.classify_failure(str(exc.value)) == "username_taken"
    assert _count(dsn, "SELECT count(*) FROM org WHERE id=%s", "rollback-b") == 0


@live
def test_an_existing_organisation_is_refused_by_the_primary_key(dsn):
    """Adopting one would add an administrator nobody already in that tenant
    authorised."""
    from tools import provision_org

    plan = prov.plan("twice", "Twice", "twiceadmin")
    provision_org.provision(plan, dsn)
    again = prov.plan("twice", "Twice Again", "differentadmin")
    with pytest.raises(Exception) as exc:
        provision_org.provision(again, dsn)
    assert prov.classify_failure(str(exc.value)) == "org_exists"
    assert _count(dsn, "SELECT count(*) FROM app_user WHERE org_id=%s",
                  "twice") == 1


@live
def test_the_new_tenant_is_isolated_from_the_default_one(dsn):
    """The whole point of creating one. Row-level security keys on org_id, so
    a tenant that shared rows with `default` would be a tenant in name only."""
    from tools import provision_org

    plan = prov.plan("isolated", "Isolated", "isoadmin")
    provision_org.provision(plan, dsn)
    assert _count(dsn, "SELECT count(*) FROM app_user WHERE org_id=%s "
                       "AND username=%s", "default", "isoadmin") == 0
