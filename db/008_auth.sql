-- Users, sessions and second factors.
--
-- WHY THIS TABLE FINISHES TENANCY. Migration 006 enforced row-level security
-- against a session GUC and left the gap recorded in P5: nothing resolved an
-- organisation PER REQUEST, so every request fell back to SKOPOS_ORG_ID and the
-- deployment was single-tenant with multi-tenant enforcement underneath. A user
-- belongs to an org; a session belongs to a user; so a request carrying a
-- session carries an org. That is the missing link.
--
-- WHY app_user IS NOT ITSELF ORG-SCOPED THE WAY EVERYTHING ELSE IS.
-- Every other table gets `org_id DEFAULT current_setting('skopos.org_id')` and a
-- policy comparing against it. This one cannot: the login route runs BEFORE any
-- org is known — resolving the org is what it is for — so a policy keyed on the
-- session GUC would hide the very row the lookup needs.
--
-- So `app_user.org_id` is a plain foreign key with NO row-level policy, and the
-- protection is different in kind: the table holds no findings, no assets and no
-- customer data, only credentials that are already hashed, and the lookup is by
-- username alone. What it must never gain is a column carrying tenant data,
-- because that column would sit outside RLS.
--
-- NO DEFAULT CREDENTIAL. Not admin/admin, which is a published credential on
-- every install that forgets to change it, and not an auto-generated one printed
-- to stdout, because container logs are aggregated, shipped and retained. The
-- first administrator comes from SKOPOS_BOOTSTRAP_USER / SKOPOS_BOOTSTRAP_PASSWORD,
-- applied ONCE against an empty table and ignored thereafter — so re-running with
-- the variables still set cannot silently reset a password somebody has since
-- changed.

CREATE TABLE app_user (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The organisation this user acts for. THE POINT OF THIS MIGRATION.
    org_id         TEXT NOT NULL REFERENCES org(id),
    username       TEXT NOT NULL CHECK (username <> ''),
    -- pbkdf2_sha256$<iterations>$<salt>$<derived>. Self-describing, so raising
    -- the cost is a re-hash on next login rather than a migration.
    password_hash  TEXT NOT NULL CHECK (password_hash <> ''),
    display_name   TEXT NOT NULL DEFAULT '',
    -- Recorded, never inferred. An account nobody created is not an account.
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by     TEXT NOT NULL DEFAULT 'bootstrap',
    disabled_at    TIMESTAMPTZ,
    last_login_at  TIMESTAMPTZ,

    -- ── second factor ──────────────────────────────────────────────────────
    -- The base32 TOTP secret. NULL until enrolment starts.
    totp_secret    TEXT,
    -- Enrolment is not active until the user has typed back a working code, so
    -- a failed scan or a mistyped secret can never lock anybody out.
    totp_enrolled_at TIMESTAMPTZ,
    -- The last counter accepted. A TOTP code stays valid for its whole 30-second
    -- step and replays happily unless this is persisted — core/totp.py refuses
    -- to hold this state and says so, because it is state and belongs here.
    totp_last_counter BIGINT NOT NULL DEFAULT -1,

    UNIQUE (username)
);

-- Single-use fallbacks, stored only as SHA-256. Without these a wiped phone is a
-- permanently locked account, and for the FIRST administrator there is no
-- administrator left to ask.
CREATE TABLE app_recovery_code (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL,
    used_at      TIMESTAMPTZ,
    UNIQUE (user_id, fingerprint)
);

CREATE TABLE app_session (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    -- THE FINGERPRINT, NEVER THE TOKEN. The token is shown to the browser once.
    -- A dump of this table — a backup, a support export, a read-only grant —
    -- yields nothing anybody can present as a live session.
    fingerprint  TEXT NOT NULL UNIQUE,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    -- Sessions extend on use but never past this, so a continuously-active
    -- session still forces a fresh authentication eventually.
    absolute_expiry TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    -- Recorded for the audit trail, never used to decide anything: an IP is
    -- trivially spoofed and binding a session to one breaks every mobile user
    -- who changes network mid-investigation.
    user_agent   TEXT NOT NULL DEFAULT '',
    CHECK (expires_at <= absolute_expiry)
);

CREATE INDEX app_user_by_org ON app_user (org_id, username);
CREATE INDEX app_session_live ON app_session (fingerprint) WHERE revoked_at IS NULL;
CREATE INDEX app_session_by_user ON app_session (user_id, issued_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE
    ON app_user, app_session, app_recovery_code TO skopos_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO skopos_app;
