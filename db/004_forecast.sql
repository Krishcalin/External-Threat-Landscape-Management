-- W2: the forecast record.
--
-- THE ONE WORKSTREAM WITH A DEADLINE. Every other capability costs the same
-- whenever it is built. This one gets strictly more expensive every week it is
-- not, because a Brier score needs RESOLVED forecasts, resolution takes calendar
-- time, and history cannot be backfilled. A record started late cannot produce a
-- measured accuracy claim until long after.
--
-- What is stored is the INPUT VECTOR, not the score. A score is a conclusion;
-- the inputs are what makes it checkable, and they are what a later model
-- version has to be re-run against to show it improved on anything.

CREATE TABLE forecast (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    run_id       BIGINT REFERENCES scan_run(id) ON DELETE SET NULL,
    asset        TEXT NOT NULL CHECK (asset <> ''),
    cve          TEXT NOT NULL CHECK (cve <> ''),

    -- Pinned so a model change cannot corrupt the history it is measured
    -- against. Scoring a v1 forecast with a v2 model and calling the result a
    -- v2 accuracy figure is the most obvious way to fake an improvement.
    model_version TEXT NOT NULL CHECK (model_version <> ''),

    -- Every factor that produced the score, at the moment it was produced.
    inputs       JSONB NOT NULL,
    teps         NUMERIC(5,2) NOT NULL,
    band         TEXT NOT NULL,

    -- Filled in later, by tools/resolve_forecasts.py.
    resolved_at  TIMESTAMPTZ,
    outcome      TEXT CHECK (outcome IN ('kev_added', 'epss_crossed',
                                         'no_event', 'unresolved')),
    resolution_source TEXT,

    -- One forecast per (asset, cve, model) per run. Re-scoring the same pairing
    -- in one run would double-count it in every accuracy figure computed later.
    UNIQUE (run_id, asset, cve, model_version)
);

-- The two questions asked of this table: "what is still unresolved" and
-- "score everything from model version X".
CREATE INDEX forecast_unresolved ON forecast (issued_at)
    WHERE resolved_at IS NULL;
CREATE INDEX forecast_by_model ON forecast (model_version, outcome);

-- W4: EPSS retained daily, which is one of the two resolution signals and is
-- also what makes velocity computable in P3.
CREATE TABLE epss_history (
    cve          TEXT NOT NULL CHECK (cve <> ''),
    observed_on  DATE NOT NULL,
    epss         NUMERIC(7,6) NOT NULL CHECK (epss >= 0 AND epss <= 1),
    percentile   NUMERIC(7,6) CHECK (percentile >= 0 AND percentile <= 1),
    model        TEXT NOT NULL DEFAULT '',
    -- One reading per CVE per day. EPSS publishes daily; a second row for the
    -- same day would silently weight that day twice in any velocity figure.
    PRIMARY KEY (cve, observed_on)
);

CREATE INDEX epss_history_series ON epss_history (cve, observed_on DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON forecast, epss_history TO skopos_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO skopos_app;
