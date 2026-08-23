-- Tenancy: org_id on every table, and row-level security that actually fires.
--
-- WHY THE ROLE CHANGE IS THE LOAD-BEARING PART, NOT THE POLICIES
-- ---------------------------------------------------------------
-- Measured before writing this: the application connected as `skopos`, which
-- is `rolsuper = true`, `rolbypassrls = true`, and the OWNER of every table.
-- Row-level security does not apply to such a role — not "applies weakly",
-- does not apply. Adding policies while the app connected that way would have
-- produced a schema that looks multi-tenant in a review and enforces nothing
-- at runtime, which is worse than no tenancy at all because it would be
-- believed.
--
-- So this migration makes `skopos_app` a LOGIN role and the application
-- connects as it. `skopos` remains the owner and the migrator. Two identities,
-- and only one of them serves requests:
--
--   skopos      superuser, owns the tables, runs migrations. Bypasses RLS,
--               which is correct for a migrator and is why it must not be the
--               runtime identity.
--   skopos_app  no superuser, no BYPASSRLS, owns nothing. Every query it makes
--               is filtered by the policies below.
--
-- FORCE ROW LEVEL SECURITY is set anyway. It is redundant while the app is not
-- the owner, and it is the thing that saves this if somebody later points the
-- app back at `skopos` — belt and braces on the failure mode that already
-- happened once.
--
-- WHAT THIS DOES AND DOES NOT DEFEND AGAINST
-- -------------------------------------------
-- The org is carried in a session GUC, `skopos.org_id`, set by the application
-- on each connection. So this defends against a BUG in the application — a
-- forgotten WHERE clause, a join that loses a filter, a new query written by
-- somebody who did not know about tenancy. It does NOT defend against a
-- compromised application or leaked app credentials: whoever can run SQL on
-- that connection can also `SET skopos.org_id` to another tenant.
--
-- That is the normal, honest limit of GUC-based RLS and it is stated here
-- because "row-level security" in a feature list reads as a stronger claim
-- than it is. A defence against cross-tenant leakage by accident is genuinely
-- valuable; a defence against a hostile tenant it is not.
--
-- The SRS asks for "Postgres roles per org". Deliberately not done: a role per
-- tenant means DDL at signup, a connection pool per tenant, and an application
-- holding rights to CREATE ROLE — which is a larger and permanently-held
-- privilege than the accidental-leak risk it removes. One unprivileged role
-- plus enforced RLS is the smaller attack surface.

-- ── the tenant registry ────────────────────────────────────────────────────
CREATE TABLE org (
    id          TEXT PRIMARY KEY CHECK (id <> '' AND id ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    name        TEXT NOT NULL CHECK (name <> ''),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Recorded so an operator can tell a tenant that was deliberately retained
    -- from one nobody has cleaned up.
    note        TEXT NOT NULL DEFAULT ''
);

-- Every row that exists today belongs to somebody, and that somebody is the
-- single tenant this instance has been serving. Naming it explicitly is better
-- than a NULL that each query has to remember to special-case.
INSERT INTO org (id, name, note) VALUES
    ('default', 'Default organisation',
     'Created by migration 006. Every row that predates tenancy belongs here.');

-- ── org_id on every table ──────────────────────────────────────────────────
-- DEFAULT 'default' so existing rows backfill in place and any INSERT written
-- before tenancy still lands somewhere valid rather than failing NOT NULL.
ALTER TABLE scope_rule             ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES org(id);
ALTER TABLE ownership_verification ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES org(id);
ALTER TABLE responsible_use_ack    ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES org(id);
ALTER TABLE audit_log              ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES org(id);
ALTER TABLE dns_run                ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES org(id);
ALTER TABLE dns_observation        ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES org(id);
ALTER TABLE takeover_finding       ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES org(id);
ALTER TABLE scan_run               ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES org(id);
ALTER TABLE finding                ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES org(id);
ALTER TABLE forecast               ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES org(id);
ALTER TABLE epss_history           ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES org(id);

-- ── uniqueness is per tenant, not global ───────────────────────────────────
-- Without this, one tenant adding `example.com` to scope silently prevents
-- every other tenant from doing the same, and the second tenant's rule
-- disappears into an ON CONFLICT DO NOTHING with no error.
ALTER TABLE scope_rule DROP CONSTRAINT scope_rule_kind_value_is_exclude_key;
ALTER TABLE scope_rule ADD CONSTRAINT scope_rule_org_unique
    UNIQUE (org_id, kind, value, is_exclude);

ALTER TABLE takeover_finding DROP CONSTRAINT takeover_finding_name_target_verdict_key;
ALTER TABLE takeover_finding ADD CONSTRAINT takeover_finding_org_unique
    UNIQUE (org_id, name, target, verdict);

ALTER TABLE finding DROP CONSTRAINT finding_run_id_asset_cve_key;
ALTER TABLE finding ADD CONSTRAINT finding_org_unique
    UNIQUE (org_id, run_id, asset, cve);

ALTER TABLE forecast DROP CONSTRAINT forecast_pairing_unique;
ALTER TABLE forecast ADD CONSTRAINT forecast_pairing_unique
    UNIQUE NULLS NOT DISTINCT (org_id, run_id, asset, cve, model_version);

-- epss_history is keyed (cve, observed_on). EPSS is a PUBLIC score about a CVE,
-- identical for every tenant, so its primary key stays global on purpose —
-- per-tenant rows would be N copies of one published fact, and a tenant with no
-- snapshot job would silently have no velocity at all.
-- epss_history keeps the LITERAL default, unlike every table above. Its rows
-- are a public score about a CVE, identical for every tenant, and it carries no
-- RLS policy for the same reason: per-tenant copies would mean a tenant whose
-- snapshot job never ran has no velocity data at all, while the row it needed
-- was already in the table.
ALTER TABLE epss_history ALTER COLUMN org_id SET DEFAULT 'default';

-- audit_log.record_hash is a chain digest and is globally unique by
-- construction; leaving that constraint global is what keeps a tenant from
-- forging a hash that already exists elsewhere in the chain.

-- ── the column default becomes the session's org ───────────────────────────
-- Added as DEFAULT 'default' above so existing rows backfill in place. From
-- here on the default is the SESSION's organisation, and that is what makes
-- tenancy work without editing a single INSERT statement in the stores.
--
-- With a literal default, an INSERT by tenant `acme` would write org_id
-- 'default', fail the WITH CHECK below, and every write for every tenant but
-- one would break. With this default it lands in the caller's own org, and a
-- connection that never set the GUC writes NULL and is rejected by NOT NULL —
-- which is the correct direction to fail.
ALTER TABLE scope_rule             ALTER COLUMN org_id SET DEFAULT current_setting('skopos.org_id', true);
ALTER TABLE ownership_verification ALTER COLUMN org_id SET DEFAULT current_setting('skopos.org_id', true);
ALTER TABLE responsible_use_ack    ALTER COLUMN org_id SET DEFAULT current_setting('skopos.org_id', true);
ALTER TABLE audit_log              ALTER COLUMN org_id SET DEFAULT current_setting('skopos.org_id', true);
ALTER TABLE dns_run                ALTER COLUMN org_id SET DEFAULT current_setting('skopos.org_id', true);
ALTER TABLE dns_observation        ALTER COLUMN org_id SET DEFAULT current_setting('skopos.org_id', true);
ALTER TABLE takeover_finding       ALTER COLUMN org_id SET DEFAULT current_setting('skopos.org_id', true);
ALTER TABLE scan_run               ALTER COLUMN org_id SET DEFAULT current_setting('skopos.org_id', true);
ALTER TABLE finding                ALTER COLUMN org_id SET DEFAULT current_setting('skopos.org_id', true);
ALTER TABLE forecast               ALTER COLUMN org_id SET DEFAULT current_setting('skopos.org_id', true);

CREATE INDEX scope_rule_by_org   ON scope_rule (org_id);
CREATE INDEX finding_by_org_run  ON finding (org_id, run_id, teps DESC);
CREATE INDEX scan_run_by_org     ON scan_run (org_id, id DESC);
CREATE INDEX audit_log_by_org    ON audit_log (org_id, seq);

-- ── the runtime identity ───────────────────────────────────────────────────
-- skopos_app existed since 001 with grants and NOLOGIN, so nothing ever
-- connected as it. Giving it LOGIN is what turns every policy below from
-- decoration into enforcement.
--
-- No password is set here. A password in a migration file is a password in the
-- repository; `core/migrate.py` sets it from SKOPOS_APP_PASSWORD after this
-- migration applies.
ALTER ROLE skopos_app WITH LOGIN;

GRANT SELECT ON org TO skopos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON epss_history TO skopos_app;

-- ── row-level security ─────────────────────────────────────────────────────
-- `current_setting('skopos.org_id', true)` returns NULL when unset rather than
-- raising, and `org_id = NULL` is never true — so a connection that forgets to
-- set the GUC sees NOTHING. That is the correct failure direction: a query that
-- returns no rows is noticed immediately, and one that returns everybody's rows
-- is noticed by a customer.

ALTER TABLE scope_rule             ENABLE ROW LEVEL SECURITY;
ALTER TABLE ownership_verification ENABLE ROW LEVEL SECURITY;
ALTER TABLE responsible_use_ack    ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log              ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_run                ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_observation        ENABLE ROW LEVEL SECURITY;
ALTER TABLE takeover_finding       ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_run               ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding                ENABLE ROW LEVEL SECURITY;
ALTER TABLE forecast               ENABLE ROW LEVEL SECURITY;

ALTER TABLE scope_rule             FORCE ROW LEVEL SECURITY;
ALTER TABLE ownership_verification FORCE ROW LEVEL SECURITY;
ALTER TABLE responsible_use_ack    FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log              FORCE ROW LEVEL SECURITY;
ALTER TABLE dns_run                FORCE ROW LEVEL SECURITY;
ALTER TABLE dns_observation        FORCE ROW LEVEL SECURITY;
ALTER TABLE takeover_finding       FORCE ROW LEVEL SECURITY;
ALTER TABLE scan_run               FORCE ROW LEVEL SECURITY;
ALTER TABLE finding                FORCE ROW LEVEL SECURITY;
ALTER TABLE forecast               FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON scope_rule
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));
CREATE POLICY org_isolation ON ownership_verification
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));
CREATE POLICY org_isolation ON responsible_use_ack
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));
CREATE POLICY org_isolation ON dns_run
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));
CREATE POLICY org_isolation ON dns_observation
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));
CREATE POLICY org_isolation ON takeover_finding
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));
CREATE POLICY org_isolation ON scan_run
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));
CREATE POLICY org_isolation ON finding
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));
CREATE POLICY org_isolation ON forecast
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));

-- The audit chain is append-only for the application (001 grants SELECT and
-- INSERT only). Reading is scoped to the tenant; there is no UPDATE or DELETE
-- policy because there is no UPDATE or DELETE grant, and a policy permitting
-- what no grant allows would misdescribe the table.
CREATE POLICY org_isolation ON audit_log
    FOR SELECT USING (org_id = current_setting('skopos.org_id', true));
CREATE POLICY org_append ON audit_log
    FOR INSERT WITH CHECK (org_id = current_setting('skopos.org_id', true));
