-- P1: DNS observations, change tracking, and takeover findings.
--
-- Applied by core/migrate.py, NOT by Postgres's initdb hook — that hook runs
-- only on an empty data directory, so this file would never have executed on an
-- existing skopos-db-1 volume while running fine in the tests' throwaway
-- databases. Green tests, missing constraints in the deployment.

CREATE TABLE dns_run (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor        TEXT NOT NULL CHECK (actor <> ''),
    resolvers    TEXT[] NOT NULL,
    attempted    INTEGER NOT NULL DEFAULT 0,
    observed     INTEGER NOT NULL DEFAULT 0,
    quorum_failed INTEGER NOT NULL DEFAULT 0,
    unobserved   INTEGER NOT NULL DEFAULT 0,
    refused      INTEGER NOT NULL DEFAULT 0,
    -- Counted so a partial run cannot be read as a whole one after the fact.
    degraded     BOOLEAN NOT NULL DEFAULT FALSE
);

-- Only CONCLUSIVE observations are stored. A SERVFAIL never lands here, because
-- a resolver outage must not be able to supersede what we last actually saw —
-- otherwise a bad night reads as the customer's DNS being deleted.
CREATE TABLE dns_observation (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id       BIGINT NOT NULL REFERENCES dns_run(id),
    name         TEXT NOT NULL CHECK (name <> ''),
    rrtype       TEXT NOT NULL CHECK (rrtype <> ''),
    rcode        TEXT NOT NULL CHECK (rcode IN ('NOERROR', 'NXDOMAIN')),
    digest       CHAR(64) NOT NULL,
    values       TEXT[] NOT NULL DEFAULT '{}',
    observed_at  DATE NOT NULL,
    resolvers_agreeing INTEGER NOT NULL CHECK (resolvers_agreeing >= 2)
);

-- The lookup change tracking makes on every run: the newest conclusive
-- observation per (name, rrtype).
CREATE INDEX dns_observation_latest
    ON dns_observation (name, rrtype, observed_at DESC);

CREATE TABLE takeover_finding (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id        BIGINT NOT NULL REFERENCES dns_run(id),
    name          TEXT NOT NULL CHECK (name <> ''),
    verdict       TEXT NOT NULL CHECK (verdict IN (
                      'registrable_domain_unregistered',
                      'provider_guarded', 'internal_dangling',
                      'no_claim_signal_found', 'inconclusive')),
    corroboration TEXT NOT NULL CHECK (corroboration IN (
                      'registration_open', 'provider_rule', 'none')),
    -- Evidence is NOT NULL and non-empty at the database level as well as in
    -- core/takeover.py. A takeover claim with no target recorded is not
    -- reviewable, and a constraint that lives only in Python is one the next
    -- migration script gets to skip.
    target        TEXT NOT NULL CHECK (target <> ''),
    target_rcode  TEXT NOT NULL CHECK (target_rcode <> ''),
    resolvers_agreeing INTEGER NOT NULL CHECK (resolvers_agreeing >= 2),
    reasons       TEXT[] NOT NULL CHECK (array_length(reasons, 1) >= 1),
    evidence      JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen    DATE NOT NULL,
    last_seen     DATE NOT NULL,
    -- claimable_looking is deliberately absent from the CHECK above. It is not
    -- reachable in this phase, and a value the schema accepts is one somebody
    -- will eventually write.
    UNIQUE (name, target, verdict)
);

GRANT SELECT, INSERT, UPDATE, DELETE
    ON dns_run, dns_observation, takeover_finding TO skopos_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO skopos_app;
