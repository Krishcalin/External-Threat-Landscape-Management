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

from fastapi import FastAPI, HTTPException, Query          # noqa: E402
from fastapi.middleware.cors import CORSMiddleware         # noqa: E402

from core import engine, intel, inventory, match, scoring  # noqa: E402
from core.overwatch import (RECONCILIATION_MEANING, load as load_overwatch,
                            parse_graph)                   # noqa: E402

app = FastAPI(
    title="SKOPOS",
    version="0.2.0",
    description="Preemptive External Threat Landscape Management — "
                "what you expose, joined to what adversaries are exploiting.",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

# The console is served from a different origin in development only. In a
# deployment the SPA is served by this app, so no origin is granted by default.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

#: In-memory for now. Persistence is a later phase; keeping it explicit here
#: stops the API pretending to a durability it does not have.
STATE: Dict[str, Any] = {"findings": [], "summary": None, "scanned_at": None}


def _corpus():
    try:
        return intel.load()
    except intel.IntelUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/api/v1/health", tags=["ops"])
def health() -> Dict[str, Any]:
    return {"status": "ok", "version": app.version}


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
    }


@app.post("/api/v1/scan", tags=["scan"])
def run_scan(inventory_path: str = Query(..., description="CSV or JSON asset inventory"),
             overwatch_graph: Optional[str] = Query(
                 None, description="OverWatch graph export, for internal cloud context"),
             asset_tier: int = Query(3, ge=1, le=5),
             days_exposed: int = Query(0, ge=0),
             sector_match: float = Query(0.0, ge=0.0, le=1.0),
             geo_match: float = Query(0.0, ge=0.0, le=1.0),
             tech_match: float = Query(0.0, ge=0.0, le=1.0)) -> Dict[str, Any]:
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
    adversary = scoring.AdversaryInterest(sector_match=sector_match,
                                          geo_match=geo_match,
                                          tech_match=tech_match)
    catalogue = corpus.entries()
    findings = []
    for asset in assets:
        cloud = cloud_by_id.get(asset.identifier)
        for correspondence in match.match_asset(asset, catalogue):
            findings.append(engine.score_exposure(
                correspondence,
                cloud=cloud,
                # SKOPOS has not probed anything yet — active discovery is a
                # later phase — so external reachability is UNKNOWN rather than
                # assumed. That keeps the reconciliation honest.
                external_reachable=None,
                adversary=adversary,
                asset_tier=asset_tier,
                days_exposed=days_exposed,
                shadow=asset.identifier not in declared,
            ))

    ranked = engine.rank(findings)
    unmatched = len(match.unmatched_assets(assets, [f for f in findings]))
    STATE["findings"] = ranked
    STATE["summary"] = engine.summarise(ranked, unmatched=unmatched,
                                        unmappable=len(unmappable))
    STATE["scanned_at"] = date.today().isoformat()
    return {
        "scanned_at": STATE["scanned_at"],
        "catalogue": intel_status(),
        "assets_read": len(assets),
        "rows_rejected": len(rejected),
        "summary": STATE["summary"],
        "unmappable_cloud_resources": unmappable,
    }


@app.get("/api/v1/summary", tags=["findings"])
def summary() -> Dict[str, Any]:
    if STATE["summary"] is None:
        raise HTTPException(status_code=404, detail="no scan has been run")
    return {"scanned_at": STATE["scanned_at"], **STATE["summary"],
            "catalogue": intel_status()}


@app.get("/api/v1/findings", tags=["findings"])
def findings(limit: int = Query(100, ge=1, le=500),
             band: Optional[str] = None,
             reconciliation: Optional[str] = None) -> Dict[str, Any]:
    """Ranked findings. The total is always stated, so a capped list never
    reads as a complete one."""
    rows = STATE["findings"]
    if band:
        rows = [f for f in rows if f.score.band == band]
    if reconciliation:
        rows = [f for f in rows
                if f.reconciliation and f.reconciliation.value == reconciliation]
    return {
        "total": len(rows),
        "returned": min(limit, len(rows)),
        "findings": [f.to_dict() for f in rows[:limit]],
    }


@app.get("/api/v1/reconciliation", tags=["findings"])
def reconciliation_guide() -> Dict[str, str]:
    """What each outside-in/inside-out outcome means.

    Served rather than hard-coded in the console so the API, the CLI and the UI
    cannot drift into describing the same state differently.
    """
    return {k.value: v for k, v in RECONCILIATION_MEANING.items()}
