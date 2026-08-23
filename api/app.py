"""SKOPOS API — FastAPI, OpenAPI 3.1 at /api/docs.

SCOPE, HONESTLY. This serves the analysis that exists today: the exposure ×
actively-exploited join, TEPS scoring, and the OverWatch reconciliation. It is not
the full §8.2 endpoint inventory and does not pretend to be — the endpoints that
have no engine behind them are absent rather than stubbed, because a route that
returns an empty list reads to a caller exactly like a landscape with nothing
wrong in it.

SINGLE-ORG, per the sponsor's decision. There is no `org_id` in the path and no
tenant claim in the token. Routes are shaped so that adding one later is a prefix
change rather than a redesign — `/api/v1/...` becomes `/api/v1/orgs/{id}/...` —
but nothing here implements FR-M0-001 and nothing should pretend it does.
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import os                                                  # noqa: E402

from fastapi import FastAPI, HTTPException, Query          # noqa: E402
from fastapi.middleware.cors import CORSMiddleware         # noqa: E402
from fastapi.responses import FileResponse                 # noqa: E402
from fastapi.staticfiles import StaticFiles                # noqa: E402

from core import engine, intel, inventory, match, scoring  # noqa: E402
from core.overwatch import (RECONCILIATION_MEANING, load as load_overwatch,
                            parse_graph)                   # noqa: E402
from core.store import StoreUnavailable                    # noqa: E402

app = FastAPI(
    title="SKOPOS",
    version="0.2.0",
    description="Preemptive External Threat Landscape Management — "
                "what you expose, joined to what adversaries are exploiting.",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

# CORS is a BROWSER-side cross-origin control, and the Dockerfile serves the SPA
# from the SAME origin as this API, where CORS never applies at all. This block
# exists only so `npm run dev` on :5173 can reach the API on :8000.
#
# It is NOT what makes this API read-only. The API is read-only because no write
# route exists — and POST /api/v1/scan already exists and is callable with curl.
# A future contributor who reads `allow_methods=["GET"]` as "GET-only by
# construction" and adds a POST would believe something false about the product.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

def _findings_store():
    """Scan results live in Postgres, not in this process.

    They used to live in a module-level dict here. Measured: a scan produced 64
    findings across 7 assets, the container restarted, and GET /summary answered
    "no scan has been run" — while scope, ownership, the audit chain and every
    DNS observation survived. The product's OUTPUT was the only thing that did
    not, a second replica would have disagreed with the first, and run-over-run
    diff was impossible rather than merely unbuilt.
    """
    from core.findings_store import open_findings_store
    from core.store import StoreUnavailable
    try:
        return open_findings_store()
    except StoreUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))


def _corpus():
    try:
        return intel.load()
    except intel.IntelUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/api/v1/health", tags=["ops"])
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "version": app.version,
        # Stated rather than left to be discovered by a 404. An operator who
        # cannot find the takeover route needs to know it is unconfigured, not
        # broken.
        "takeover_route": ("registered" if TAKEOVER_ROUTE_REGISTERED
                           else "not registered — set SKOPOS_API_TOKEN"),
    }


@app.get("/api/v1/intel", tags=["intelligence"])
def intel_status() -> Dict[str, Any]:
    """The corpus, and how old it is.

    Age is returned on every call rather than buried in a footnote: a result
    computed against a stale corpus is a different claim from the same result
    computed today, and nothing in the numbers says which you are holding.
    """
    corpus = _corpus()
    return {
        "catalog_version": corpus.catalog_version,
        "released": str(corpus.released) if corpus.released else None,
        "retrieved": str(corpus.retrieved) if corpus.retrieved else None,
        "age_days": corpus.age_days(),
        "entries": len(corpus),
        "epss_scope": corpus.epss_scope,
        "ransomware_linked": sum(1 for e in corpus.entries() if e.known_ransomware),
        # Whether determinations are possible at all, and for how much of the
        # catalogue. Without this a reader cannot tell a cautious product from
        # one that simply has no range data vendored.
        "affected_ranges": corpus.has_affected,
        "determinable_share": corpus.determinable_share,
    }


@app.post("/api/v1/scan", tags=["scan"])
def run_scan(inventory_path: str = Query(..., description="CSV or JSON asset inventory"),
             overwatch_graph: Optional[str] = Query(
                 None, description="OverWatch graph export, for internal cloud context"),
             asset_tier: int = Query(3, ge=1, le=5),
             days_exposed: int = Query(0, ge=0),
             sector_match: float = Query(0.0, ge=0.0, le=1.0),
             geo_match: float = Query(0.0, ge=0.0, le=1.0),
             tech_match: float = Query(0.0, ge=0.0, le=1.0),
             actor: str = Query("api", description=
                 "who ran this; asserted, not authenticated")) -> Dict[str, Any]:
    """Join an inventory against the exploited catalogue and score the result."""
    corpus = _corpus()
    try:
        assets, rejected = inventory.load(Path(inventory_path))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    cloud_by_id: Dict[str, Any] = {}
    unmappable: List[Dict[str, Any]] = []
    if overwatch_graph:
        try:
            cloud, unmappable = load_overwatch(Path(overwatch_graph))
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=400,
                                detail=f"could not read OverWatch graph: {exc}")
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
                adversary=adversary,
                asset_tier=asset_tier,
                days_exposed=days_exposed,
                shadow=asset.identifier not in declared,
            ))

    ranked = engine.rank(findings)
    unmatched = len(match.unmatched_assets(assets, [f for f in findings]))
    summary_payload = engine.summarise(ranked, unmatched=unmatched,
                                       unmappable=len(unmappable))
    catalogue_status = intel_status()

    store = _findings_store()
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
        "since_last_run": {
            "previous_run": diff.previous_run,
            "headline": diff.headline(),
            "new": len(diff.new),
            "resolved": len(diff.resolved),
            "changed_band": len(diff.reband),
            "carried": diff.carried,
        },
    }


@app.get("/api/v1/summary", tags=["findings"])
def summary() -> Dict[str, Any]:
    run = _findings_store().latest_run()
    if run is None:
        raise HTTPException(status_code=404, detail="no scan has been run")
    return {"run": run["id"], "scanned_at": run["scanned_at"],
            **(run["summary"] or {}),
            # The catalogue THAT ANSWERED this run, not whatever is vendored
            # now. A refresh between the scan and this request would otherwise
            # silently re-attribute the result to a corpus that never saw it.
            "catalogue_at_scan": {"version": run["catalog_version"],
                                  "age_days": run["catalog_age_days"]},
            "catalogue": intel_status()}


@app.get("/api/v1/runs", tags=["findings"])
def runs(limit: int = Query(20, ge=1, le=200)) -> Dict[str, Any]:
    rows = _findings_store().runs(limit)
    return {"total": len(rows), "runs": rows}


@app.get("/api/v1/changes", tags=["findings"])
def changes(run: Optional[int] = None) -> Dict[str, Any]:
    """What is new since the previous scan.

    A finding's identity is (asset, cve) — never its TEPS or its band, both of
    which move when EPSS moves. Keying on either would report a score change as
    a new finding and flood this list with things already seen, which is the
    fastest way to make a feed unreadable.
    """
    diff = _findings_store().diff_against_previous(run)
    return {
        "previous_run": diff.previous_run,
        "is_baseline": diff.is_baseline,
        "headline": diff.headline(),
        "new": diff.new,
        "resolved": diff.resolved,
        "changed_band": diff.reband,
        "carried": diff.carried,
    }


@app.get("/api/v1/findings", tags=["findings"])
def findings(limit: int = Query(100, ge=1, le=500),
             band: Optional[str] = None,
             reconciliation: Optional[str] = None) -> Dict[str, Any]:
    """Ranked findings. The total is always stated, so a capped list never
    reads as a complete one."""
    store = _findings_store()
    rows = store.findings(limit=limit, band=band, reconciliation=reconciliation)
    run = store.latest_run()
    return {
        "run": run["id"] if run else None,
        "total": len(rows),
        "returned": len(rows),
        "findings": rows,
    }


@app.get("/api/v1/reconciliation", tags=["findings"])
def reconciliation_guide() -> Dict[str, str]:
    """What each outside-in/inside-out outcome means.

    Served rather than hard-coded in the console so the API, the CLI and the UI
    cannot drift into describing the same state differently.
    """
    return {k.value: v for k, v in RECONCILIATION_MEANING.items()}


# ---------------------------------------------------------------------------
# P1 surfaces: discovery coverage, DNS, takeover.
#
# Meaning strings are SERVED rather than hard-coded in the console, on the
# RECONCILIATION_MEANING precedent — so the API, the CLI and the UI cannot drift
# into describing the same state differently.
# ---------------------------------------------------------------------------
def _dns_store():
    from core.dns_store import open_dns_store
    from core.store import StoreUnavailable
    try:
        return open_dns_store()
    except StoreUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/api/v1/dns/runs", tags=["dns"])
def dns_runs(limit: int = Query(20, ge=1, le=200)) -> Dict[str, Any]:
    """Past sweeps and their coverage.

    Every run carries what it could NOT see. A sweep that observed 66 of 70
    pairs is a different claim from one that observed 70, and a reader deciding
    whether "0 changes" means a quiet night needs both numbers.
    """
    rows = _dns_store().runs(limit)
    return {"total": len(rows), "runs": rows}


@app.get("/api/v1/dns/change-meaning", tags=["dns"])
def dns_change_meaning() -> Dict[str, str]:
    from core.dns_state import CHANGE_MEANING
    return CHANGE_MEANING


@app.get("/api/v1/takeover/meaning", tags=["takeover"])
def takeover_meaning() -> Dict[str, str]:
    from core.takeover import TAKEOVER_MEANING
    return TAKEOVER_MEANING


@app.get("/api/v1/attestation-meaning", tags=["findings"])
def attestation_meaning() -> Dict[str, str]:
    from core.identity import ATTESTATION_MEANING
    return ATTESTATION_MEANING


#: A ranked list of dangling subdomains with evidence attached is finished
#: reconnaissance against the customer. It is the first content in this product
#: where the absence of authentication genuinely matters, so the route is not
#: registered at all unless a token is configured — an unset token must not
#: leave it open, and a 401 that can be probed is still an admission the data
#: exists.
TAKEOVER_TOKEN = os.environ.get("SKOPOS_API_TOKEN", "")


def _register_takeover(application: FastAPI) -> bool:
    if not TAKEOVER_TOKEN:
        return False

    from fastapi import Header

    @application.get("/api/v1/takeover", tags=["takeover"])
    def takeover(limit: int = Query(50, ge=1, le=500),
                 authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        import hmac as _hmac

        presented = (authorization or "").removeprefix("Bearer ").strip()
        if not _hmac.compare_digest(presented, TAKEOVER_TOKEN):
            raise HTTPException(status_code=401, detail="a bearer token is required")
        from core.takeover import TAKEOVER_MEANING
        rows = _dns_store().findings(limit)
        return {"total": len(rows), "findings": rows,
                "meaning": TAKEOVER_MEANING,
                "ceiling": "There is no 'vulnerable' verdict in this product. "
                           "The only experiment that would establish one is "
                           "registering the resource, which is refused before "
                           "scope or ownership are consulted."}

    return True


TAKEOVER_ROUTE_REGISTERED = _register_takeover(app)


# ---------------------------------------------------------------------------
# The console.
#
# Mounted LAST, deliberately. A catch-all that serves index.html must not shadow
# /api/* — if it did, a typo in an API path would return the SPA with status 200
# and the client would try to parse HTML as JSON, which surfaces as a baffling
# console error instead of the 404 it actually is.
# ---------------------------------------------------------------------------
CONSOLE_DIR = Path(os.environ.get("SKOPOS_CONSOLE_DIR", ROOT / "frontend" / "dist"))


def mount_console(application: FastAPI, directory: Path) -> bool:
    """Serve the built SPA, if one has been built.

    Returns whether it mounted, rather than raising. Running the API without a
    console is a legitimate configuration — the CLI and the OpenAPI docs are
    still useful — and a missing bundle should not take the service down.
    """
    index = directory / "index.html"
    if not index.is_file():
        return False

    assets = directory / "assets"
    if assets.is_dir():
        application.mount("/assets", StaticFiles(directory=assets), name="assets")

    @application.get("/", include_in_schema=False)
    def _root() -> FileResponse:
        return FileResponse(index)

    @application.get("/{path:path}", include_in_schema=False)
    def _spa(path: str) -> FileResponse:
        # Client-side routes have no file behind them, so unknown paths return
        # the shell. API paths are excluded above by mount order; anything under
        # /api reaching here is a genuine 404 and is reported as one.
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail=f"no such endpoint: /{path}")
        candidate = directory / path
        if candidate.is_file() and directory.resolve() in candidate.resolve().parents:
            return FileResponse(candidate)
        return FileResponse(index)

    return True


CONSOLE_MOUNTED = mount_console(app, CONSOLE_DIR)
