"""One scan, called by the route and by the scheduler.

WHY THIS IS NOT IN api/app.py ANY MORE
---------------------------------------
It was, as 178 lines inside the route handler — and those 178 lines contain the
alerting decision, the ticketing decision and the forecast record. A scheduled
scan that reimplemented them would agree with the route on the day it was
written and drift afterwards, silently, in exactly the way four stale
`ON CONFLICT` targets and one unapplied migration already drifted in this
repository.

So there is one implementation. The route parses parameters and turns a bad
input into a 400; the scheduler catches the same errors and logs them. Neither
holds any scanning logic of its own.

WHAT IS DELIBERATELY STILL DECIDED INSIDE HERE
-----------------------------------------------
Alert delivery and ticket filing. Both are gated on environment variables and
neither takes a parameter, so a caller — HTTP or cron — cannot ask for delivery.
If the caller could, anyone who can reach the API could choose the moment the
estate is described to a third party. Moving the gate out to the callers would
have quietly handed that choice to whoever adds the next one.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional

from core import engine, intel, inventory, match, scoring
from core.overwatch import load as load_overwatch
from core.store import StoreUnavailable


class ScanError(RuntimeError):
    """A scan could not be completed."""


class ScanInputError(ScanError):
    """Something the caller supplied cannot be read. A 400, not a 500."""


class ScanUnavailable(ScanError):
    """A dependency this scan needs is not reachable. A 503."""


def _load_corpus():
    try:
        return intel.load()
    except intel.IntelUnavailable as exc:
        raise ScanUnavailable(str(exc)) from exc


def _open_store():
    from core.findings_store import open_findings_store
    try:
        return open_findings_store()
    except StoreUnavailable as exc:
        raise ScanUnavailable(str(exc)) from exc


def _intel_status() -> Dict[str, Any]:
    """The catalogue that answered THIS run, recorded beside the result.

    A figure computed against a stale corpus is a different claim from the same
    figure computed today, and nothing in the numbers says which.
    """
    corpus = _load_corpus()
    return {
        "catalog_version": corpus.catalog_version,
        "released": str(corpus.released) if corpus.released else None,
        "retrieved": str(corpus.retrieved) if corpus.retrieved else None,
        "age_days": corpus.age_days(),
        "entries": len(corpus),
        "epss_scope": corpus.epss_scope,
    }


def execute(inventory_path: str,
            overwatch_graph: Optional[str] = None,
            asset_tier: int = 3,
            days_exposed: int = 0,
            sector_match: float = 0.0,
            geo_match: float = 0.0,
            tech_match: float = 0.0,
            actor: str = "api") -> Dict[str, Any]:
    """Join an inventory against the exploited catalogue and score the result."""
    corpus = _load_corpus()
    try:
        assets, rejected = inventory.load(Path(inventory_path))
    except FileNotFoundError as exc:
        raise ScanInputError(str(exc)) from exc

    cloud_by_id: Dict[str, Any] = {}
    unmappable: List[Dict[str, Any]] = []
    if overwatch_graph:
        try:
            cloud, unmappable = load_overwatch(Path(overwatch_graph))
        except (OSError, ValueError) as exc:
            raise ScanInputError(
                f"could not read OverWatch graph: {exc}") from exc
        cloud_by_id = {c.asset.identifier: c for c in cloud}
        # Cloud resources OverWatch knows about are part of the estate even if
        # the declared inventory never mentioned them — that IS the shadow-asset
        # case (FR-M1-011), not a reason to ignore them.
        known = {a.identifier for a in assets}
        for c in cloud:
            if c.asset.identifier not in known:
                assets.append(c.asset)

    declared = {a.identifier for a in assets if a.source != "overwatch"}
    # Pass None unless the OPERATOR actually supplied triad values, so the
    # engine falls back to what the catalogue can support. An all-zero
    # AdversaryInterest is still a truthy object, so constructing one
    # unconditionally silently defeated that fallback and left 25% of every
    # score multiplied by zero — measured: 64 of 64 findings at adversary 0.0.
    supplied_triad = any((sector_match, geo_match, tech_match))
    adversary = (scoring.AdversaryInterest(sector_match=sector_match,
                                           geo_match=geo_match,
                                           tech_match=tech_match,
                                           supplied=True)
                 if supplied_triad else None)
    catalogue = corpus.entries()
    from core import reach

    findings = []
    for asset in assets:
        cloud = cloud_by_id.get(asset.identifier)
        # Outside-in reachability, where a fingerprint run supplied it. None
        # means never probed, which is not the same as probed-and-closed and
        # must not reconcile as one.
        reachable, _ports = reach.from_row(asset.attributes)
        for correspondence in match.match_asset(asset, catalogue):
            findings.append(engine.score_exposure(
                correspondence,
                cloud=cloud,
                external_reachable=reachable,
                # THE DETERMINATION TIER. Passing this is what turns a
                # PRODUCT_MATCH worklist entry into a VERSION_RANGE verdict —
                # and, when a version falls outside every published range, what
                # retires the finding entirely. It has been inert since the
                # evaluator was written because nothing supplied ranges.
                affected_versions=corpus.version_ranges_for(
                    correspondence.exploited.cve),
                ssvc=corpus.ssvc_for(correspondence.exploited.cve),
                adversary=adversary,
                asset_tier=asset_tier,
                days_exposed=days_exposed,
                shadow=asset.identifier not in declared,
            ))

    ranked = engine.rank(
        findings,
        automatable={e.cve: corpus.automatable(e.cve)
                     for e in catalogue})
    unmatched = len(match.unmatched_assets(assets, [f for f in findings]))
    summary_payload = engine.summarise(ranked, unmatched=unmatched,
                                       unmappable=len(unmappable))
    catalogue_status = _intel_status()

    store = _open_store()
    run_id = store.record_run(
        actor=actor, inventory=inventory_path, catalogue=catalogue_status,
        assets_read=len(assets), rows_rejected=len(rejected),
        assets_unmatched=unmatched, summary=summary_payload,
        findings=[f.to_dict() for f in ranked])

    # THE FORECAST RECORD. Every finding is a prediction, and this is the only
    # moment its inputs exist — the corpus moves, EPSS moves, the model version
    # changes. Writing it later is not an option: a Brier score needs RESOLVED
    # forecasts, resolution takes calendar time, and history cannot be
    # backfilled.
    #
    # This module and its schema were built and left unwired, and five scans
    # completed before anybody noticed. Those five runs are evidence that can
    # never be recovered, which is exactly the failure the workstream was
    # sequenced first to avoid.
    forecasts_written = 0
    try:
        from core import forecast as _forecast
        from core.forecast_store import open_forecast_store
        forecasts_written = open_forecast_store().record(
            [_forecast.from_finding(f) for f in ranked], run_id=run_id)
    except StoreUnavailable as exc:
        # Reported, never silent. A scan that completes while the record is not
        # accumulating looks identical to one that is, and the difference is
        # only visible months later when there is nothing to score.
        forecasts_written = -1
        _log_forecast_failure = str(exc)

    diff = store.diff_against_previous(run_id)

    # ALERT DELIVERY. Gated on SKOPOS_ALERT_ON_SCAN, never on a request
    # parameter: if the caller could ask for delivery, anyone who can reach
    # this endpoint could choose the moment the estate is described to a third
    # party. The switch lives in the environment, where it is set once by
    # whoever runs the service.
    #
    # A delivery failure does not fail the scan. The findings are already
    # persisted and correct; what failed is telling somebody about them, and
    # discarding a valid run over that would be the worse trade.
    from core import alerting as _alerting
    try:
        alerting_report = _alerting.deliver_for_run(diff)
    except Exception as exc:                                   # noqa: BLE001
        alerting_report = {"decided": None, "delivered": False, "channels": {},
                           "reason": f"alerting failed: {type(exc).__name__}: {exc}"}

    # ITSM. Filed from diff.new ONLY, which is where the deduplication comes
    # from: a finding carried over from the previous run was already ticketed on
    # the run it first appeared, and identity is (asset, cve) - the same key the
    # diff uses. That needs no ticket-tracking table and cannot drift out of
    # step with the diff, because it IS the diff.
    from core import itsm as _itsm
    try:
        itsm_report = _itsm.file_for_run(diff.new)
    except Exception as exc:                                   # noqa: BLE001
        itsm_report = {"decided": None, "filed": False,
                       "reason": f"ticketing failed: {type(exc).__name__}: {exc}"}
    # The bodies are not echoed into the scan response: they are long, and a
    # scan result is not where somebody reads a ticket.
    itsm_report.pop("tickets", None)

    return {
        "run": run_id,
        "scanned_at": date.today().isoformat(),
        "catalogue": catalogue_status,
        "assets_read": len(assets),
        "rows_rejected": len(rejected),
        "summary": summary_payload,
        "unmappable_cloud_resources": unmappable,
        # Surfaced on every scan. If this is ever 0 or -1 the accuracy record is
        # not accumulating, and that must be visible now rather than discovered
        # when somebody asks for a Brier score.
        "forecasts_recorded": forecasts_written,
        # What is NEW since last time is most of why a monitoring product is
        # worth running continuously rather than once. It was not merely
        # unbuilt before persistence — it was impossible.
        # Always present, always says which of the four states this run was in
        # — including "delivery is on and no channel is configured", which from
        # the outside is indistinguishable from a quiet run.
        "alerting": alerting_report,
        "ticketing": itsm_report,
        "since_last_run": {
            "previous_run": diff.previous_run,
            "headline": diff.headline(),
            "new": len(diff.new),
            "resolved": len(diff.resolved),
            "changed_band": len(diff.reband),
            "carried": diff.carried,
        },
    }


__all__ = ["execute", "ScanError", "ScanInputError",
           "ScanUnavailable"]
