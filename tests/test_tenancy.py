"""Tenancy, and the measurement that decided how it was built.

The finding that shaped migration 006: the application connected as `skopos`,
which is `rolsuper = true`, `rolbypassrls = true`, and the OWNER of every table.
Row-level security does not apply to such a role at all. Adding policies while
the app connected that way would have produced a schema that reviews as
multi-tenant and enforces nothing — worse than no tenancy, because it would be
believed.

So the live tests here connect as the unprivileged role and check that RLS
actually blocks, and one of them connects as the superuser to demonstrate the
bypass that made the role change necessary.
"""
from __future__ import annotations

import os
import threading
import uuid

import pytest

from core import tenancy
from core.tenancy import TenancyError


# ── the context ─────────────────────────────────────────────────────────────
def test_the_default_is_a_tenant_not_none():
    """A caller that got None would have to decide what to do about it, and
    every wrong answer to that question is a cross-tenant read."""
    assert tenancy.current_org() == tenancy.DEFAULT_ORG


def test_using_scopes_and_restores():
    with tenancy.using("acme"):
        assert tenancy.current_org() == "acme"
    assert tenancy.current_org() == tenancy.DEFAULT_ORG


def test_nesting_restores_the_outer_org_not_the_default():
    """A plain reassignment on exit would restore the wrong value — the bug a
    ContextVar token is here to prevent."""
    with tenancy.using("outer"):
        with tenancy.using("inner"):
            assert tenancy.current_org() == "inner"
        assert tenancy.current_org() == "outer"


def test_one_thread_cannot_see_another_thread_org():
    """ASGI serves concurrent requests in one process. A module global would be
    a race in which tenant A overwrites tenant B between connect and execute."""
    seen = {}

    def worker(org):
        with tenancy.using(org):
            seen[org] = tenancy.current_org()

    threads = [threading.Thread(target=worker, args=(o,))
               for o in ("alpha", "beta", "gamma")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert seen == {"alpha": "alpha", "beta": "beta", "gamma": "gamma"}


@pytest.mark.parametrize("bad", [
    "", "  ", "Acme", "-leading", "a" * 64, "acme;DROP TABLE org",
    "acme'--", "../etc", "acme org",
])
def test_a_malformed_org_never_reaches_a_connection(bad):
    with pytest.raises(TenancyError):
        tenancy.validate(bad)


def test_the_env_var_sets_a_single_tenant_deployment(monkeypatch):
    monkeypatch.setenv(tenancy.ORG_ENV, "acme")
    assert tenancy.current_org() == "acme"


def test_a_malformed_env_var_raises_rather_than_defaulting(monkeypatch):
    """Falling back to the default tenant on a bad value would write one
    customer's rows into another's."""
    monkeypatch.setenv(tenancy.ORG_ENV, "NOT VALID")
    with pytest.raises(TenancyError):
        tenancy.current_org()


# ── what the claim is allowed to say ────────────────────────────────────────
def test_the_isolation_claim_states_its_own_limit():
    text = tenancy.ISOLATION_MEANING
    assert "THROUGH A BUG" in text
    assert "not isolation against a compromised application" in text
    assert "separate databases" in text


def test_no_function_claims_isolation():
    for banned in ("isolate", "isolation_guaranteed", "secure_tenant"):
        assert not hasattr(tenancy, banned), banned


# ── against a real database ─────────────────────────────────────────────────
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
def tenanted():
    """A throwaway database with two tenants and a row in each."""
    import psycopg

    from core import migrate

    name = f"skopos_tenant_{uuid.uuid4().hex[:12]}"
    password = uuid.uuid4().hex
    # A THROWAWAY ROLE, not skopos_app. PostgreSQL roles are cluster-wide, so
    # calling ensure_app_role on this throwaway DATABASE would still rewrite the
    # real role's password for every database in the cluster — which is exactly
    # what happened once, and the running application started failing
    # authentication the moment the suite passed.
    role = f"skopos_t_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
        admin.execute(f'CREATE ROLE "{role}" NOSUPERUSER NOBYPASSRLS')
    dsn = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    try:
        migrate.ensure_current(dsn)
        migrate.ensure_app_role(dsn, password, role=role)
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(f'GRANT "skopos_app" TO "{role}"')
            admin.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
        head, tail = dsn.split("://", 1)
        _, rest = tail.split("@", 1)
        app_dsn = f"{head}://{role}:{password}@{rest}"

        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute("INSERT INTO org (id, name) VALUES ('acme','Acme')")
            for org, value in (("default", "d.example"), ("acme", "a.example")):
                admin.execute("SELECT set_config('skopos.org_id',%s,false)", (org,))
                admin.execute(
                    "INSERT INTO scope_rule (kind,value,is_exclude,note,created_by)"
                    " VALUES ('domain',%s,false,'','t@example.com')", (value,))
        yield dsn, app_dsn
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            admin.execute(f'DROP ROLE IF EXISTS "{role}"')


def _values(dsn, org):
    import psycopg
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        if org is not None:
            cur.execute("SELECT set_config('skopos.org_id',%s,false)", (org,))
        cur.execute("SELECT value FROM scope_rule ORDER BY value")
        return [r[0] for r in cur.fetchall()]


@live
def test_the_app_role_cannot_bypass_rls(tenanted):
    """The property everything else rests on."""
    import psycopg
    _, app_dsn = tenanted
    with psycopg.connect(app_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT rolsuper, rolbypassrls FROM pg_roles "
                    "WHERE rolname = current_user")
        superuser, bypass = cur.fetchone()
    assert not superuser and not bypass


@live
def test_a_tenant_sees_only_its_own_rows(tenanted):
    _, app_dsn = tenanted
    assert _values(app_dsn, "default") == ["d.example"]
    assert _values(app_dsn, "acme") == ["a.example"]


@live
def test_an_unset_org_sees_nothing_rather_than_everything(tenanted):
    """The failure direction. An empty result is noticed in minutes; the
    opposite default is noticed by a customer."""
    _, app_dsn = tenanted
    assert _values(app_dsn, None) == []


@live
def test_the_superuser_bypasses_rls_which_is_why_the_role_changed(tenanted):
    """Not a bug — this is the measurement that made migration 006 necessary.
    Serving requests as this role would mean no tenancy at all, while the
    schema still reviewed as multi-tenant."""
    admin_dsn, _ = tenanted
    assert _values(admin_dsn, "acme") == ["a.example", "d.example"]


@live
def test_a_write_lands_in_the_callers_own_tenant(tenanted):
    """No INSERT statement in the stores names org_id. The column default is
    the session GUC, which is what makes tenancy work without editing them."""
    import psycopg
    _, app_dsn = tenanted
    with psycopg.connect(app_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('skopos.org_id','acme',false)")
        cur.execute("INSERT INTO scope_rule (kind,value,is_exclude,note,created_by)"
                    " VALUES ('domain','written.example',false,'','t@example.com')"
                    " RETURNING org_id")
        assert cur.fetchone()[0] == "acme"


@live
def test_writing_into_another_tenant_is_refused(tenanted):
    import psycopg
    _, app_dsn = tenanted
    with pytest.raises(psycopg.errors.Error):
        with psycopg.connect(app_dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT set_config('skopos.org_id','default',false)")
            cur.execute(
                "INSERT INTO scope_rule (org_id,kind,value,is_exclude,note,created_by)"
                " VALUES ('acme','domain','planted.example',false,'','t@example.com')")


@live
def test_two_tenants_may_hold_the_same_scope_rule(tenanted):
    """Without per-tenant uniqueness, one tenant scoping example.com would
    silently prevent every other tenant from doing so — and the second rule
    would vanish into ON CONFLICT DO NOTHING with no error."""
    import psycopg
    _, app_dsn = tenanted
    for org in ("default", "acme"):
        with psycopg.connect(app_dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT set_config('skopos.org_id',%s,false)", (org,))
            cur.execute("INSERT INTO scope_rule (kind,value,is_exclude,note,created_by)"
                        " VALUES ('domain','shared.example',false,'','t@example.com')"
                        " ON CONFLICT (org_id,kind,value,is_exclude) DO NOTHING")
            cur.execute("SELECT count(*) FROM scope_rule WHERE value='shared.example'")
            assert cur.fetchone()[0] == 1, org


@live
def test_enforcement_reports_which_identity_is_serving(tenanted):
    import psycopg
    admin_dsn, app_dsn = tenanted
    with psycopg.connect(app_dsn) as conn:
        assert "enforced" in tenancy.enforcement(conn)
    with psycopg.connect(admin_dsn) as conn:
        assert "NOT ENFORCED" in tenancy.enforcement(conn)


@live
def test_the_app_role_password_step_refuses_a_privileged_role(tenanted):
    """`ensure_app_role` checks rather than assumes, because a runtime role
    that could bypass RLS would make every policy inert.

    On a throwaway role: ALTER ROLE is cluster-wide, so doing this to skopos_app
    would break every other database on the same server, including the one the
    application is using while the suite runs.
    """
    import psycopg

    from core import migrate
    admin_dsn, app_dsn = tenanted
    role = app_dsn.split("://", 1)[1].split(":", 1)[0]
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(f'ALTER ROLE "{role}" WITH BYPASSRLS')
    try:
        with pytest.raises(migrate.MigrationError) as exc:
            migrate.ensure_app_role(admin_dsn, "irrelevant", role=role)
        assert "BYPASSRLS" in str(exc.value)
    finally:
        with psycopg.connect(admin_dsn, autocommit=True) as conn:
            conn.execute(f'ALTER ROLE "{role}" WITH NOBYPASSRLS')


@live
def test_every_tenanted_table_has_a_policy(tenanted):
    """A table that gained org_id but no policy is a table where tenancy looks
    present and does nothing."""
    import psycopg
    admin_dsn, _ = tenanted
    with psycopg.connect(admin_dsn) as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT c.relname FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r'
              AND EXISTS (SELECT 1 FROM pg_attribute a
                          WHERE a.attrelid = c.oid AND a.attname = 'org_id')
              AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
        """)
        unprotected = {r[0] for r in cur.fetchall()}
    # epss_history is deliberately global: an EPSS score is a public fact about
    # a CVE, identical for every tenant, and per-tenant copies would leave a
    # tenant whose snapshot job never ran with no velocity data at all.
    assert unprotected == {"epss_history"}, unprotected


@live
def test_every_tenanted_table_forces_rls(tenanted):
    """Redundant while the app is not the table owner, and the thing that saves
    this if somebody later points the app back at the superuser."""
    import psycopg
    admin_dsn, _ = tenanted
    with psycopg.connect(admin_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT relname FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname='public' AND c.relrowsecurity "
                    "AND NOT c.relforcerowsecurity")
        assert [r[0] for r in cur.fetchall()] == []
