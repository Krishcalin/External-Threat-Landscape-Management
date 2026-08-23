-- Scan results, persisted.
--
-- They were held in a module-level dict in api/app.py, carrying a comment
-- saying persistence was a later phase. Measured: a POST /api/v1/scan produced
-- 64 findings across 7 assets, `docker compose restart app` followed, and
-- GET /api/v1/summary answered "no scan has been run". The product's actual
-- OUTPUT was the one thing that did not survive, while scope, ownership, the
-- audit chain and every DNS observation did.
--
-- Two consequences beyond the obvious one. A second app replica would have had
-- its own findings and disagreed with the first. And run-over-run diff — "what
-- is NEW since last time", which is most of what makes a monitoring product
-- worth running continuously — was impossible to build at all.

CREATE TABLE scan_run (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scanned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor          TEXT NOT NULL CHECK (actor <> ''),
    inventory      TEXT NOT NULL,
    -- The catalogue version that answered. A result computed against a stale
    -- corpus is a different claim from the same result computed today, and
    -- nothing in the numbers says which — so it is stored beside them.
    catalog_version TEXT NOT NULL,
    catalog_age_days INTEGER,
    assets_read    INTEGER NOT NULL DEFAULT 0,
    rows_rejected  INTEGER NOT NULL DEFAULT 0,
    -- The honest counterpart to the finding count. Kept on the run rather than
    -- recomputed, because a later corpus refresh would change the answer and
    -- the stored run must keep saying what it said at the time.
    assets_unmatched INTEGER NOT NULL DEFAULT 0,
    summary        JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE finding (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id         BIGINT NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    asset          TEXT NOT NULL CHECK (asset <> ''),
    product        TEXT NOT NULL,
    cve            TEXT NOT NULL CHECK (cve <> ''),
    teps           NUMERIC(5,2) NOT NULL,
    band           TEXT NOT NULL,
    -- PRODUCT_MATCH is a worklist entry; VERSION_RANGE is a determination. The
    -- distinction is the product's central claim, so the database refuses
    -- anything else rather than accepting a third value somebody invents.
    basis          TEXT NOT NULL CHECK (basis IN ('product_match', 'version_range')),
    name_confidence TEXT NOT NULL CHECK (name_confidence IN ('strong', 'partial')),
    known_ransomware BOOLEAN NOT NULL DEFAULT FALSE,
    reconciliation TEXT,
    payload        JSONB NOT NULL,
    UNIQUE (run_id, asset, cve)
);

-- The two questions asked of this table: "the current worklist, ranked" and
-- "what is new since the previous run".
CREATE INDEX finding_by_run ON finding (run_id, teps DESC);
CREATE INDEX finding_identity ON finding (asset, cve);

GRANT SELECT, INSERT, UPDATE, DELETE ON scan_run, finding TO skopos_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO skopos_app;
