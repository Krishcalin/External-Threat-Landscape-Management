-- Discovered assets awaiting a decision.
--
-- WHAT WAS MISSING
-- ----------------
-- SKOPOS had a scope register and an ownership register and NOTHING BETWEEN
-- THEM. Discovery produced names; scope held names somebody had decided about;
-- and the transition from the first to the second was an operator re-typing a
-- CLI command per name. Recorded Future's ASI workflow is discover -> confirm ->
-- monitor, and the confirm step is where an attack-surface product is actually
-- used day to day.
--
-- THE COLUMN THAT MATTERS IS `decided_at`, BECAUSE IT IS USUALLY NULL
-- --------------------------------------------------------------------
-- An undecided candidate is not an administrative backlog. "Nobody has decided
-- whether this is ours" is a real exposure — it is precisely the state that
-- shadow IT and forgotten subsidiaries live in — and it is currently invisible
-- in every product this one has been compared to. Ageing the queue turns it
-- into a finding.
--
-- WHAT THIS TABLE DELIBERATELY CANNOT DO
-- ----------------------------------------
-- It cannot put anything in scope. `core/scope.py` remains the only writer of
-- scope rules and a claim here records a HUMAN DECISION that a person then
-- carries out; nothing auto-promotes. An attack-surface tool that quietly moved
-- names into scope would be deciding what it is allowed to scan, which is the
-- one thing `core/gate.py` exists to stop it doing.

CREATE TABLE asset_candidate (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES org(id)
                 DEFAULT current_setting('skopos.org_id', true),

    name         TEXT NOT NULL CHECK (name <> ''),
    -- Which collector proposed it, and when it was first seen. Provenance is
    -- not decoration here: "certificate transparency saw it" and "somebody's
    -- CSV mentioned it" justify very different amounts of attention.
    source       TEXT NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- NULL until somebody decides. This is the point of the table.
    decided_at   TIMESTAMPTZ,
    decision     TEXT CHECK (decision IN ('claimed', 'disowned', 'deferred')),
    decided_by   TEXT,
    -- Required for `disowned`, enforced below. "Not ours" with no reason is
    -- indistinguishable six months later from "nobody looked".
    reason       TEXT,

    -- A disowned candidate that discovery keeps re-proposing is itself worth
    -- knowing about: either the exclusion is wrong or something changed.
    times_seen   INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT disown_needs_a_reason CHECK (
        decision IS DISTINCT FROM 'disowned'
        OR (reason IS NOT NULL AND reason <> '')),
    CONSTRAINT decision_needs_a_decider CHECK (
        decision IS NULL OR (decided_by IS NOT NULL AND decided_by <> '')),
    -- Per tenant, like everything migration 006 touched. One organisation
    -- deciding about `example.com` must not silently answer for another.
    UNIQUE (org_id, name)
);

CREATE INDEX asset_candidate_undecided
    ON asset_candidate (org_id, first_seen)
    WHERE decided_at IS NULL;

CREATE INDEX asset_candidate_org ON asset_candidate (org_id);

ALTER TABLE asset_candidate ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_candidate FORCE ROW LEVEL SECURITY;

CREATE POLICY asset_candidate_tenant ON asset_candidate
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));

GRANT SELECT, INSERT, UPDATE ON asset_candidate TO skopos_app;
