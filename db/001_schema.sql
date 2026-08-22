-- SKOPOS P0 schema: scope, proven ownership, and an audit log that cannot be
-- rewritten by the application that writes to it.
--
-- SRS CON-02 asks for PostgreSQL 16+. Tenancy (FR-M0-001) is deferred by the
-- sponsor's decision, so there is no org_id and no row-level security yet.
-- Every table below gains an org_id column when it arrives; nothing here is
-- shaped in a way that makes that a rewrite.

CREATE TABLE scope_rule (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN (
                    'domain','wildcard','cidr','asn',
                    'cloud_account','repo_org','app_publisher')),
    value       TEXT NOT NULL,
    is_exclude  BOOLEAN NOT NULL DEFAULT FALSE,
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL,
    -- The same value may appear once as an include and once as an exclude;
    -- core/scope.py resolves that deterministically (exclude wins). What must
    -- not happen is the same rule twice, which would make the evidence list in
    -- a ScopeVerdict misleading about how many rules actually spoke.
    UNIQUE (kind, value, is_exclude)
);

CREATE TABLE ownership_verification (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset        TEXT NOT NULL,
    method       TEXT NOT NULL CHECK (method IN ('dns_txt','well_known','manual')),
    verified_at  DATE NOT NULL,
    expires_at   DATE NOT NULL,
    approved_by  TEXT,
    evidence     TEXT NOT NULL DEFAULT '',
    revoked_at   TIMESTAMPTZ,
    -- A manual attestation with nobody's name on it is not an attestation.
    -- Enforced here as well as in core/ownership.py: a check that lives only in
    -- the application is a check that the next writer of a migration script
    -- gets to skip.
    CONSTRAINT manual_needs_an_approver
        CHECK (method <> 'manual' OR (approved_by IS NOT NULL AND approved_by <> '')),
    CONSTRAINT expiry_after_verification CHECK (expires_at > verified_at)
);

-- The gate asks one question — "is there a live verification for this asset?" —
-- on every active operation, so it gets an index rather than a sequential scan.
CREATE INDEX ownership_live ON ownership_verification (asset, expires_at DESC)
    WHERE revoked_at IS NULL;

CREATE TABLE responsible_use_ack (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor        TEXT NOT NULL,
    version      TEXT NOT NULL,
    accepted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    seq          BIGINT PRIMARY KEY,
    at           TEXT NOT NULL,
    actor        TEXT NOT NULL CHECK (actor <> ''),
    action       TEXT NOT NULL CHECK (action <> ''),
    payload      JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash    CHAR(64) NOT NULL,
    record_hash  CHAR(64) NOT NULL UNIQUE
);

-- APPEND-ONLY, ENFORCED BY THE DATABASE.
--
-- The hash chain in core/audit.py detects tampering after the fact. This stops
-- it: the application role can INSERT and SELECT and nothing else, so a bug or
-- an injected statement in SKOPOS cannot quietly rewrite history and re-chain
-- it. A superuser can still drop the rules — that is inherent, and the answer
-- to it is that the app does not connect as one.
CREATE RULE audit_log_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE audit_log_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;

-- The application connects as this role, not as the owner.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'skopos_app') THEN
        CREATE ROLE skopos_app;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO skopos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scope_rule, ownership_verification,
      responsible_use_ack TO skopos_app;
-- Note the asymmetry, and that it is the point.
GRANT SELECT, INSERT ON audit_log TO skopos_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO skopos_app;

GRANT skopos_app TO skopos;
