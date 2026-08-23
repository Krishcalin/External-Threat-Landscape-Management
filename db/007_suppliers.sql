-- The supplier register, and the observations made about it.
--
-- DECLARED, NEVER INFERRED. Same discipline as the CII register: this product
-- does not get to decide who your suppliers are. A tool that guessed supplier
-- relationships from DNS would be inventing a commercial fact, and inventing
-- the wrong one is worse than an empty register — the organisation would either
-- assess a company it has no relationship with, or believe a real dependency
-- was covered.
--
-- WHY THERE IS NO VULNERABILITY COLUMN HERE, AND CANNOT BE. A supplier's estate
-- is somebody else's, the customer cannot prove ownership of it, and the gate
-- refuses every ACTIVE operation against an unverified asset. No active probe
-- means no fingerprint; no fingerprint means no product name; no product name
-- means no CVE join. A `supplier_finding` table would be a place to put numbers
-- this product is structurally unable to produce, so it does not exist.

CREATE TABLE supplier (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id       TEXT NOT NULL DEFAULT current_setting('skopos.org_id', true)
                 REFERENCES org(id),
    name         TEXT NOT NULL CHECK (name <> ''),
    -- The register keys on a domain because that is the only handle a passive
    -- collector has. A supplier with no domain cannot be assessed at all, and
    -- recording that is better than silently skipping them.
    domain       TEXT NOT NULL CHECK (domain <> ''),
    -- The customer's judgement, not an observation. A supplier with immaculate
    -- DNS can still be the one whose outage stops the business.
    tier         TEXT NOT NULL CHECK (tier IN ('critical', 'important', 'routine')),
    -- What they are depended on FOR. Free text on purpose: no vocabulary this
    -- product invents would survive contact with a real supply chain, and a
    -- wrong dropdown produces confidently wrong data.
    dependency   TEXT NOT NULL DEFAULT '',
    -- An unattributed claim that a company is a supplier is not a record.
    declared_by  TEXT NOT NULL CHECK (declared_by <> ''),
    declared_on  DATE NOT NULL DEFAULT CURRENT_DATE,
    note         TEXT NOT NULL DEFAULT '',
    UNIQUE (org_id, domain)
);

-- One row per (supplier, observation run). Posture is a point-in-time reading
-- of published records, and keeping the history is what makes "they turned
-- DMARC enforcement off in March" answerable at all.
CREATE TABLE supplier_observation (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id       TEXT NOT NULL DEFAULT current_setting('skopos.org_id', true)
                 REFERENCES org(id),
    supplier_id  BIGINT NOT NULL REFERENCES supplier(id) ON DELETE CASCADE,
    observed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The three states are kept APART on purpose. Merging `unobserved` into
    -- `absent` would turn this product's coverage gap into the supplier's
    -- finding, which is the commonest lie in third-party risk tooling.
    present      JSONB NOT NULL DEFAULT '[]'::jsonb,
    absent       JSONB NOT NULL DEFAULT '[]'::jsonb,
    unobserved   JSONB NOT NULL DEFAULT '[]'::jsonb,
    providers    JSONB NOT NULL DEFAULT '{}'::jsonb,
    notes        JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX supplier_by_org ON supplier (org_id, tier, name);
CREATE INDEX supplier_observation_latest
    ON supplier_observation (org_id, supplier_id, observed_at DESC);

ALTER TABLE supplier             ENABLE ROW LEVEL SECURITY;
ALTER TABLE supplier_observation ENABLE ROW LEVEL SECURITY;
ALTER TABLE supplier             FORCE ROW LEVEL SECURITY;
ALTER TABLE supplier_observation FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON supplier
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));
CREATE POLICY org_isolation ON supplier_observation
    USING (org_id = current_setting('skopos.org_id', true))
    WITH CHECK (org_id = current_setting('skopos.org_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON supplier, supplier_observation TO skopos_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO skopos_app;
