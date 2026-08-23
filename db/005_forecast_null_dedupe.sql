-- Fix: a forecast recorded outside a run could be written twice.
--
-- db/004 declared UNIQUE (run_id, asset, cve, model_version). In SQL two NULLs
-- are not equal, so that constraint never collides when run_id IS NULL — and
-- `ON CONFLICT ... DO NOTHING` therefore did nothing to prevent a duplicate.
-- Caught by a test that recorded the same pairing twice and got two rows.
--
-- It matters because a duplicated pairing is counted twice in every accuracy
-- figure computed later: the Brier score, the resolved count, the lead-time
-- distribution. A record that silently over-weights some predictions is worse
-- than a smaller honest one.
--
-- PostgreSQL 15+ can say what was meant. SKOPOS requires 16 (SRS CON-02).

ALTER TABLE forecast DROP CONSTRAINT IF EXISTS forecast_run_id_asset_cve_model_version_key;

ALTER TABLE forecast
    ADD CONSTRAINT forecast_pairing_unique
    UNIQUE NULLS NOT DISTINCT (run_id, asset, cve, model_version);
