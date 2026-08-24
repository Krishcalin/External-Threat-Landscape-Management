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
from datetime import date, datetime
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
from pydantic import BaseModel                      # noqa: E402

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
        "taxii": ("registered at /taxii2/" if TAXII_REGISTERED
                  else "not registered — set SKOPOS_API_TOKEN"),
        # Reported, never inferred: an unauthenticated console must say so.
        "auth": _auth_routes.auth_status(),
    }


@app.get("/api/v1/refusals", tags=["intelligence"])
def refusal_register() -> Dict[str, Any]:
    """What this product will not tell you, and the measurement behind each.

    PUBLIC, for the same reason the rule catalogue is: the first question
    anybody comparing SKOPOS to a commercial platform asks is why it does not
    do X, and the answer should be one request away rather than archaeology
    through seven phase documents. It describes the software and names no
    asset.
    """
    from core import refusals
    return refusals.payload()


@app.get("/api/v1/rules", tags=["intelligence"])
def rule_catalogue() -> Dict[str, Any]:
    """Every check this product performs, named and listable.

    PUBLIC on purpose — see `api/auth_routes.PUBLIC_EXACT`. Somebody deciding
    whether to install SKOPOS should be able to read what it checks first, and
    a catalogue behind a login is a catalogue nobody reads. It contains no
    finding, no asset and nothing about any estate: it is a description of the
    software, which is already open source.
    """
    from core import rules
    return rules.catalogue()


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
    """Join an inventory against the exploited catalogue and score the result.

    A THIN WRAPPER ON PURPOSE. The scan itself lives in `core/scan.py` because
    the scheduler runs the same thing, and 178 lines of alerting, ticketing and
    forecast logic duplicated in two places is how they stop agreeing — the
    failure this repository already hit with four stale ON CONFLICT targets and
    an unapplied migration.

    Note what this route does NOT expose: no parameter asks for alert delivery
    or ticket filing. Both are decided inside `core/scan.py` from the
    environment, so a caller cannot choose the moment the estate is described to
    a third party.
    """
    from core import scan as _scan
    try:
        return _scan.execute(
            inventory_path=inventory_path, overwatch_graph=overwatch_graph,
            asset_tier=asset_tier, days_exposed=days_exposed,
            sector_match=sector_match, geo_match=geo_match,
            tech_match=tech_match, actor=actor)
    except _scan.ScanInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except _scan.ScanUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))


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
# TAXII 2.1. Registered only when a token is configured, for the same reason
# the takeover route is: a feed of somebody's exposed assets joined to exploited
# vulnerabilities is finished reconnaissance against them, and an unset token
# must not leave it open.


def _taxii_objects(store) -> tuple:
    """The current bundle, plus the run timestamp every object is stamped with.

    Returns (objects, stamp, counts). The stamp is the SCAN RUN's `scanned_at`,
    never `now()` — see `core/taxii.py`: a `date_added` that moves per request
    silently breaks every consumer's incremental poll while the server keeps
    answering 200.
    """
    from core import stix as _stix
    from core import taxii as _taxii

    runs = store.runs(limit=1)
    if not runs:
        return [], "", {}
    stamp = str(runs[0].get("scanned_at") or "")
    # STIX timestamps are RFC 3339 with a literal Z. Postgres hands back
    # "+00:00", which is the same instant and a different string, and TAXII
    # clients compare `added_after` as text.
    stamp = stamp.replace(" ", "T").replace("+00:00", "Z")
    if stamp and not stamp.endswith("Z"):
        stamp = stamp + "Z"

    rows = store.findings(limit=_taxii.MAX_PAGE)
    bundle = _stix.bundle(rows, created=stamp)
    objects = bundle.get("objects", [])
    determinations = sum(1 for r in rows if str(r.get("basis")) == "version_range")
    return objects, stamp, {"determinations": determinations,
                            "worklist": len(rows) - determinations}


def _register_taxii(application: FastAPI) -> bool:
    if not TAKEOVER_TOKEN:
        return False

    import hmac as _hmac

    from fastapi import Header
    from fastapi.responses import JSONResponse

    from core import taxii as _taxii

    def _taxii_json(payload: Dict[str, Any], status: int = 200) -> JSONResponse:
        # The version parameter is part of the media type. A conforming client
        # content-negotiates on the exact string and treats bare
        # application/json as a different type.
        return JSONResponse(content=payload, status_code=status,
                            media_type=_taxii.MEDIA_TYPE)

    def _authorise(authorization: Optional[str]) -> None:
        presented = (authorization or "").removeprefix("Bearer ").strip()
        if not _hmac.compare_digest(presented, TAKEOVER_TOKEN):
            raise HTTPException(
                status_code=401,
                detail=_taxii.TaxiiError(
                    "Unauthorized",
                    "a bearer token is required; this collection is finished "
                    "reconnaissance against the estate it describes",
                    401).to_dict())

    def _check_root(api_root: str) -> None:
        if api_root != _taxii.API_ROOT:
            raise HTTPException(
                status_code=404,
                detail=_taxii.TaxiiError(
                    "Not Found", f"no API root named {api_root!r}", 404).to_dict())

    def _check_collection(collection_id: str) -> None:
        if collection_id != _taxii.FINDINGS_COLLECTION:
            raise HTTPException(
                status_code=404,
                detail=_taxii.TaxiiError(
                    "Not Found",
                    f"no collection {collection_id!r}. This server serves one "
                    f"collection, {_taxii.FINDINGS_COLLECTION}", 404).to_dict())

    @application.get("/taxii2/", tags=["taxii"])
    def taxii_discovery(authorization: Optional[str] = Header(None)):
        """TAXII 2.1 §4.1 discovery."""
        _authorise(authorization)
        return _taxii_json(_taxii.discovery())

    @application.get("/taxii2/{api_root}/", tags=["taxii"])
    def taxii_api_root(api_root: str,
                       authorization: Optional[str] = Header(None)):
        _authorise(authorization)
        _check_root(api_root)
        return _taxii_json(_taxii.api_root())

    @application.get("/taxii2/{api_root}/collections/", tags=["taxii"])
    def taxii_collections(api_root: str,
                          authorization: Optional[str] = Header(None)):
        _authorise(authorization)
        _check_root(api_root)
        _, _, counts = _taxii_objects(_findings_store())
        return _taxii_json(_taxii.collections(_corpus().catalog_version, counts))

    @application.get("/taxii2/{api_root}/collections/{collection_id}/",
                     tags=["taxii"])
    def taxii_collection(api_root: str, collection_id: str,
                         authorization: Optional[str] = Header(None)):
        _authorise(authorization)
        _check_root(api_root)
        _check_collection(collection_id)
        _, _, counts = _taxii_objects(_findings_store())
        return _taxii_json(_taxii.collection(_corpus().catalog_version, counts))

    def _page(collection_id: str, api_root: str, limit: int, next_token: str,
              match_type: Optional[str], match_id: Optional[str],
              match_version: Optional[str], match_spec_version: Optional[str],
              added_after: Optional[str]):
        _check_root(api_root)
        _check_collection(collection_id)
        objects, stamp, _ = _taxii_objects(_findings_store())
        index = _taxii.date_added_index(objects, stamp)
        try:
            selected = _taxii.filter_objects(
                objects, index, match_type=match_type, match_id=match_id,
                match_version=match_version,
                match_spec_version=match_spec_version, added_after=added_after)
            offset = int(next_token) if next_token else 0
            page, more, token = _taxii.paginate(selected, limit, offset)
        except _taxii.TaxiiError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.to_dict())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=_taxii.TaxiiError(
                    "Invalid next",
                    "next must be the token returned by a previous page",
                    400).to_dict())
        return page, more, token, index

    @application.get(
        "/taxii2/{api_root}/collections/{collection_id}/objects/", tags=["taxii"])
    def taxii_objects(api_root: str, collection_id: str,
                      limit: int = Query(_taxii.DEFAULT_PAGE, ge=1,
                                         le=_taxii.MAX_PAGE),
                      next: str = Query(""),
                      added_after: Optional[str] = Query(None),
                      match_type: Optional[str] = Query(None, alias="match[type]"),
                      match_id: Optional[str] = Query(None, alias="match[id]"),
                      match_version: Optional[str] = Query(None,
                                                           alias="match[version]"),
                      match_spec_version: Optional[str] = Query(
                          None, alias="match[spec_version]"),
                      authorization: Optional[str] = Header(None)):
        """TAXII 2.1 §5.4. The objects themselves, as a STIX envelope."""
        _authorise(authorization)
        page, more, token, _ = _page(collection_id, api_root, limit, next,
                                     match_type, match_id, match_version,
                                     match_spec_version, added_after)
        return _taxii_json(_taxii.envelope(page, more, token))

    @application.get(
        "/taxii2/{api_root}/collections/{collection_id}/manifest/", tags=["taxii"])
    def taxii_manifest(api_root: str, collection_id: str,
                       limit: int = Query(_taxii.DEFAULT_PAGE, ge=1,
                                          le=_taxii.MAX_PAGE),
                       next: str = Query(""),
                       added_after: Optional[str] = Query(None),
                       match_type: Optional[str] = Query(None, alias="match[type]"),
                       match_id: Optional[str] = Query(None, alias="match[id]"),
                       match_version: Optional[str] = Query(None,
                                                            alias="match[version]"),
                       match_spec_version: Optional[str] = Query(
                           None, alias="match[spec_version]"),
                       authorization: Optional[str] = Header(None)):
        """TAXII 2.1 §5.3. What is in the collection, without transferring it."""
        _authorise(authorization)
        page, more, token, index = _page(collection_id, api_root, limit, next,
                                         match_type, match_id, match_version,
                                         match_spec_version, added_after)
        return _taxii_json(_taxii.manifest(page, index, more, token))

    return True


TAXII_REGISTERED = _register_taxii(app)

# ---------------------------------------------------------------------------
# Authentication. The middleware registered here binds tenancy.using(org) around
# EVERY request, including routes written by somebody who has never heard of
# tenancy — which is the failure mode P5 recorded and this closes.
from api import account_routes as _account_routes       # noqa: E402
from api import auth_routes as _auth_routes             # noqa: E402

AUTH_REGISTERED = _auth_routes.register(app)
BOOTSTRAPPED = _auth_routes.bootstrap_from_env()

# Account administration. Registered unconditionally, unlike the auth routes:
# every route inside re-checks `is_admin` on the session, so on an instance with
# no users the middleware's own 401 covers them, and on one with users the
# routes cover themselves. Registering conditionally would mean the endpoints a
# user is told about in an error message might not exist.
_account_routes.register(app)



@app.get("/api/v1/accuracy", tags=["accuracy"])
def accuracy(model_version: str = Query("teps-1.0.0")) -> Dict[str, Any]:
    """This product's own track record, published as-is.

    THE POINT OF THE PRODUCT, not a diagnostic. A predictive tool that never
    measures its predictions is marketing, and the competitor's evidence page
    has been frozen since 2021. So this route exists from the first release, it
    is served whether the numbers flatter the product or not, and it refuses to
    show a figure it cannot support.

    It publishes NOTHING until 30 forecasts have resolved. A Brier score over a
    handful of outcomes is noise wearing the costume of a measurement, and
    spending credibility on an early number would defeat the whole exercise.
    """
    from core import backtest
    from core.forecast_store import open_forecast_store
    from core.store import StoreUnavailable
    try:
        store = open_forecast_store()
    except StoreUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return backtest.score(store.all_forecasts(), model_version).to_dict()


@app.get("/api/v1/accuracy/method", tags=["accuracy"])
def accuracy_method() -> Dict[str, Any]:
    """How the score is computed, and what it cannot measure.

    Served rather than written into the console, so the method and the figure
    cannot drift apart — and so a reader can check the arithmetic against the
    numbers on the same screen.
    """
    from core import backtest
    from core.forecast import BAND_PROBABILITY, OBSERVATION_WINDOW_DAYS
    return {
        "band_probabilities": BAND_PROBABILITY,
        "observation_window_days": OBSERVATION_WINDOW_DAYS,
        "minimum_resolved_to_publish": backtest.MIN_RESOLVED_TO_PUBLISH,
        "uninformative_brier": backtest.UNINFORMATIVE_BRIER,
        "lead_time": backtest.LEAD_TIME_UNMEASURABLE,
        "notes": [
            "A Brier score alone means nothing. Always predicting the base rate "
            "scores well on a rare event without containing any information, so "
            "every figure ships with a climatology reference and a skill score.",
            "Skill is measured against climatology. Positive means the model "
            "knows something the base rate does not; zero or negative means it "
            "does not, and that is published rather than buried.",
            "Band probabilities are crude and expert-set on purpose. The point "
            "of the record is that they become measurable and therefore "
            "improvable — a model nobody wrote down cannot be shown wrong.",
            "An EPSS crossing resolves a forecast only if the score was BELOW "
            "the threshold when the forecast was issued. Measured: 80 of 128 "
            "forecasts already sat above it, and resolving on the level would "
            "have validated the model against its own input.",
        ],
    }


@app.get("/api/v1/crosshair", tags=["findings"])
def crosshair(limit: int = Query(200, ge=1, le=500)) -> Dict[str, Any]:
    """Convergence: what is being fired at the internet that you stand in front of.

    NOT a claim about who is targeting you. SKOPOS cannot attribute a CVE to a
    threat actor and has the measurement to prove it — the one open mapping
    implicates a median of 57 groups per CVE, 139 at the extreme out of 191. A
    screen naming your attackers would be the least honest thing this product
    could ship, and the response says so in `not_targeting`.
    """
    from core import crosshair as _crosshair
    from core import intel as _intel
    from core import velocity as _velocity

    store = _findings_store()
    rows = store.findings(limit=limit)
    try:
        corpus = _intel.load()
        decisions = {f["cve"]: corpus.automatable(f["cve"]) for f in rows}
    except _intel.IntelUnavailable:
        decisions = {}

    # EPSS velocity, where enough history exists to compute one. On a young
    # record this is empty, and an empty accelerating set means "we have not
    # been watching long enough", never "nothing is moving".
    moving = []
    try:
        from core.forecast_store import open_forecast_store
        forecasts = open_forecast_store()
        # ONE query for every series, not one per finding. Measured: the
        # per-finding loop that used to be here put this route at 575ms against
        # 64 findings while every other route answered in under 30ms, because
        # each call opened its own connection.
        series_by_cve = forecasts.epss_series_many(
            [row["cve"] for row in rows], days=30)
        for row in rows:
            reading = _velocity.compute(row["cve"],
                                        series_by_cve.get(row["cve"], []))
            if reading and reading.accelerating:
                moving.append(row["cve"])
    except StoreUnavailable:
        pass

    board = _crosshair.build(rows, automatable=decisions, accelerating=moving)
    payload = board.to_dict()
    payload["velocity_available"] = bool(moving) or None
    return payload


# ---------------------------------------------------------------------------
# Weaponisation latency. A base rate over what happened to others, and mostly
# a refusal: three of the four reference classes cannot support a statement.


@app.get("/api/v1/latency", tags=["latency"])
def latency_classes() -> Dict[str, Any]:
    """Every reference class, including the ones that cannot answer.

    All four are returned on purpose. Serving only the usable class would leave
    a caller believing the product has a general answer to "how long do I have",
    when the honest headline is that it has one answer out of four and the other
    three span years.
    """
    from core import latency as _latency
    try:
        corpus = intel.load()
    except intel.IntelUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if not corpus.has_artefacts:
        raise HTTPException(status_code=503, detail={
            "error": "no artefact index is vendored",
            "fix": "python tools/refresh_intel.py --only-artefacts",
            "why": ("weaponisation latency is measured from published exploit "
                    "code to catalogue addition. With no artefact index there "
                    "is no measurement, and a base rate is not guessed.")})
    payload = _latency.report(corpus)
    payload["artefact_coverage"] = corpus.artefact_coverage
    payload["coverage_meaning"] = (
        f"{corpus.artefact_coverage:.1%} of the catalogue has published code we "
        f"index. The rest is not evidence that no exploit exists — private and "
        f"unindexed code is the normal case."
        if corpus.artefact_coverage else None)
    return payload


@app.get("/api/v1/latency/{cve}", tags=["latency"])
def latency_for(cve: str) -> Dict[str, Any]:
    """The reference class this CVE falls into, and what it does or cannot say.

    The class is chosen from facts about the CVE — ransomware linkage from the
    catalogue, weaponisation from whether a packaged module exists — never from
    anything observed on the customer's asset. The same CVE gets the same answer
    for everybody, which is what makes it a base rate rather than a score.
    """
    from core import latency as _latency
    try:
        corpus = intel.load()
    except intel.IntelUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    wanted = str(cve).strip().upper()
    entry = next((e for e in corpus.entries() if e.cve.upper() == wanted), None)
    if entry is None:
        raise HTTPException(status_code=404, detail={
            "error": f"{wanted} is not in the vendored catalogue",
            "why": ("this base rate is measured over known-exploited "
                    "vulnerabilities. A CVE outside that set has no comparable "
                    "population here, and one would not be invented for it.")})

    records = corpus.artefacts_for(wanted)
    from core.artefacts import Artefact, ArtefactKind, ArtefactSet
    artefacts = []
    for record in records:
        try:
            kind = ArtefactKind(str(record.get("kind")))
        except ValueError:
            continue
        artefacts.append(Artefact(kind=kind, cve=wanted,
                                  published=_latency._as_date(record.get("published")),
                                  reference=str(record.get("reference") or "")))
    artefact_set = ArtefactSet(cve=wanted, artefacts=artefacts)

    observations, _ = _latency.observations_from(corpus)
    classes = _latency.build(observations)
    answer = _latency.lookup(classes, entry.known_ransomware,
                             artefact_set.weaponised)
    return {
        "cve": wanted,
        "known_ransomware": entry.known_ransomware,
        "weaponised": artefact_set.weaponised,
        "artefacts": artefact_set.evidence(),
        "reference_class": answer.to_dict(),
        "answer": answer.explain(),
        "not_a_forecast": _latency.NOT_A_FORECAST,
    }


# ---------------------------------------------------------------------------
# STIX 2.1 export.


def _exposure_rows(limit: int = 500):
    """The estate, assembled from what is actually PERSISTED.

    Two sources, and the honesty is in what is missing rather than what is
    here. DNS observations and dangling-record findings are stored, so they
    describe the whole estate. Certificate posture, abuse-feed membership and
    leak-site listings are computed per lookup and are NOT persisted per asset,
    so they are absent from an estate-wide export until something stores them.

    That gap is reported in the payload rather than left for a consumer to
    infer from a thin bundle.
    """
    from collections import defaultdict

    from core import dns_store as _dns

    try:
        store = _dns.open_dns_store()
    except Exception:                                           # noqa: BLE001
        return [], {"dns": False, "takeover": False}

    addresses = defaultdict(set)
    try:
        for (name, rrtype), observation in store.latest_observations().items():
            if str(rrtype).upper() in {"A", "AAAA"}:
                for value in getattr(observation, "values", ()) or ():
                    addresses[str(name)].add(str(value))
    except Exception:                                           # noqa: BLE001
        pass

    takeovers = {}
    try:
        for finding in store.findings(limit=limit):
            name = str(finding.get("name") or "")
            if name:
                takeovers[name] = {
                    "verdict": str(finding.get("verdict") or ""),
                    "target": str(finding.get("target") or ""),
                    "reasons": list(finding.get("reasons") or []),
                }
    except Exception:                                           # noqa: BLE001
        pass

    names = sorted(set(addresses) | set(takeovers))[:limit]
    rows = []
    for name in names:
        row = {"asset": name}
        if addresses.get(name):
            row["addresses"] = sorted(addresses[name])
        if name in takeovers:
            row["takeover"] = takeovers[name]
        rows.append(row)
    return rows, {"dns": bool(addresses), "takeover": bool(takeovers)}


@app.get("/api/v1/export/validation-targets", tags=["export"])
def export_validation_targets(limit: int = Query(200, ge=1, le=1000),
                              run: Optional[int] = None) -> Dict[str, Any]:
    """What to point an adversarial-exposure-validation platform at.

    SKOPOS refuses the CTEM validation stage outright — `exploit_attempt` is
    PROHIBITED in core/gate.py under FR-GOV-007 — so this is the handoff to a
    platform that does cover it: OpenAEV, which is open source and Apache 2.0,
    or a commercial equivalent.

    It carries NO ATT&CK TECHNIQUES, because SKOPOS holds none. What it carries
    is the thing a validation platform cannot know for itself: which of your
    assets are externally reachable, what they appear to run, and which findings
    are unresolved worklist entries where a simulation resolves the question
    faster than a human reading a banner.
    """
    from core import findings_store as _fs
    from core import validation as _validation

    try:
        store = _fs.open_findings_store()
        rows = store.findings(run_id=run, limit=2000)
    except Exception as exc:                                    # noqa: BLE001
        raise HTTPException(status_code=503, detail={
            "error": f"{type(exc).__name__}: {exc}",
            "why": "no findings store is reachable, so there is no target list "
                   "to produce. That is not an empty estate."})

    payload = _validation.targets(rows, limit=limit)
    payload["coverage_gaps"] = _validation.coverage_gaps(rows)
    payload["gaps_are_not_omissions"] = (
        "Coverage gaps are listed rather than dropped. A target list that "
        "silently omitted what it could not assess would read as an estate "
        "with nothing else in it — the same reason OpenCTI generates "
        "placeholder injects for coverage it cannot test.")
    return payload


@app.get("/api/v1/export/stix/exposure", tags=["export"])
def export_exposure_stix(limit: int = Query(500, ge=1, le=2000)
                         ) -> Dict[str, Any]:
    """The estate as STIX 2.1 — everything that is NOT a CVE finding.

    `/export/stix` carries vulnerability findings, which is one of the nine
    categories in the rule catalogue. This carries the rest: the asset itself
    as an `infrastructure` composed of its observables, the addresses it
    resolves to, and any dangling delegation — each non-CVE observation as a
    `note` that carries its rule's stated limits, because `core/rules.py`
    makes that field mandatory.

    This is the half a threat-intelligence platform has no equivalent for.
    OpenCTI has no asset entity type at all.
    """
    from core import stix as _stix
    from core import tenancy as _tenancy

    rows, sources = _exposure_rows(limit)
    bundle = _stix.exposure_bundle(rows, org=_tenancy.current_org())
    return {
        "bundle": bundle,
        "assets": len(rows),
        "objects": len(bundle.get("objects") or []),
        "sources_present": sources,
        # Stated rather than left to be inferred from a thin bundle.
        "not_included": (
            "Certificate posture, abuse-feed membership and leak-site listings "
            "are computed per lookup and are not persisted per asset, so they "
            "are absent from an estate-wide export. They appear on an "
            "individual /lookup. This is a gap in what SKOPOS stores, not a "
            "statement that the estate is free of them."),
    }


@app.get("/api/v1/export/stix", tags=["export"])
def export_stix(limit: int = Query(500, ge=1, le=2000),
                run: Optional[int] = None) -> Dict[str, Any]:
    """Findings as a STIX 2.1 bundle, with the worklist distinction preserved.

    STIX has no vocabulary for "this product matches but the version was never
    compared", and the obvious encoding — a `Relationship` of type `has` — reads
    downstream as a determination. So confidence is set explicitly (worklist 40,
    determination 90) and a `note` object carrying the caveat travels inside the
    bundle. A caveat that stays behind in the console is not a caveat.
    """
    from core import stix as _stix
    rows = _findings_store().findings(run_id=run, limit=limit)
    bundle = _stix.bundle(rows)
    return {
        "bundle": bundle,
        "objects": len(bundle.get("objects", [])),
        "findings_exported": len(rows),
        "limit": limit,
        "truncated": len(rows) >= limit,
        "caveat": _stix.BUNDLE_CAVEAT,
    }


# ---------------------------------------------------------------------------
# Alerting. This route DECIDES; it does not deliver.


@app.get("/api/v1/alerts", tags=["alerts"])
def alerts(run: Optional[int] = None,
           minimum_band: Optional[str] = None) -> Dict[str, Any]:
    """What would be worth interrupting somebody for, computed and not sent.

    Deliberately read-only. `core/alerting.py` can dispatch to a webhook or an
    SMTP server, and that path stays configuration-driven rather than reachable
    from HTTP: a GET that caused the server to POST your findings outward would
    let anyone who can reach this API choose the moment your estate is
    described to a third party. Delivery is an operator decision, made once, in
    the environment — not a query parameter.

    The suppressed counts are returned with the alerts, because an operator who
    sees five needs to know whether five was everything or a cap.
    """
    from core import alerting as _alerting
    diff = _findings_store().diff_against_previous(run)
    policy = (_alerting.Policy(minimum_band=minimum_band)
              if minimum_band else _alerting.Policy())
    decided = _alerting.build(diff, policy=policy)
    return {
        "previous_run": diff.previous_run,
        "is_baseline": diff.is_baseline,
        "alerts": [a.as_dict() for a in decided["alerts"]],
        "suppressed_below_band": decided["suppressed_below_band"],
        "suppressed_by_cap": decided["suppressed_by_cap"],
        "minimum_band": decided["minimum_band"],
        "note": decided["note"],
        "delivered": False,
        "delivery": (
            "This endpoint computed the decision and sent nothing. Configure "
            "SKOPOS_ALERT_WEBHOOK or SKOPOS_ALERT_EMAIL to have a scan deliver "
            "them; until then alerts are computed and not delivered, which is "
            "reported rather than left to be discovered."),
        "triggers_off_by_default": [
            t.value for t in _alerting.Trigger
            if t not in _alerting.DEFAULT_TRIGGERS],
    }


@app.get("/api/v1/tenancy", tags=["tenancy"])
def tenancy_status() -> Dict[str, Any]:
    """Which organisation this instance serves, and whether RLS actually applies.

    The second half is the point. A deployment can have a perfectly correct
    multi-tenant schema and no tenancy whatsoever — that is exactly the state
    this codebase was in before migration 006, because the application
    connected as a superuser and row-level security does not apply to such a
    role. Nothing in the query results says which one you have, so it is
    reported here.
    """
    from core import tenancy as _tenancy

    payload: Dict[str, Any] = {
        "org": _tenancy.current_org(),
        "isolation_meaning": _tenancy.ISOLATION_MEANING,
    }
    try:
        store = _findings_store()
        connect = getattr(store, "_connect", None)
        if connect is None:
            payload["enforcement"] = ("in-memory store: there is no database "
                                      "and therefore no row-level security")
            payload["bound_org"] = None
            return payload
        with connect() as conn:
            payload["enforcement"] = _tenancy.enforcement(conn)
            payload["bound_org"] = _tenancy.bound_org(conn)
    except StoreUnavailable as exc:
        payload["enforcement"] = f"unknown: {exc}"
        payload["bound_org"] = None
    return payload


# ---------------------------------------------------------------------------
# Suppliers. Declared by the customer, assessed passively, and never joined to
# a CVE — see core/suppliers.py for why that last one is structural.


def _supplier_store():
    from core.supplier_store import open_supplier_store
    return open_supplier_store()


class _SupplierBody(BaseModel):
    name: str
    domain: str
    tier: str
    dependency: str = ""
    declared_by: str


@app.get("/api/v1/suppliers", tags=["suppliers"])
def supplier_register() -> Dict[str, Any]:
    """The register, with the most recent passive observation of each.

    Never triggers collection. A GET that went and queried thirty suppliers'
    DNS would make the cost of loading a page depend on how many third parties
    somebody declared, and would put outbound lookups behind a page refresh.
    Assessment is a POST somebody makes on purpose.
    """
    from core import suppliers as _suppliers

    store = _supplier_store()
    declared = store.suppliers()
    observations = store.latest_observations()

    postures = []
    for supplier in declared:
        seen = observations.get(supplier.domain)
        posture = _suppliers.Posture(supplier=supplier)
        if seen:
            def _signals(key):
                out = []
                for value in seen.get(key) or []:
                    try:
                        out.append(_suppliers.Signal(value))
                    except ValueError:
                        continue        # a signal this build no longer models
                return out
            posture.present = _signals("present")
            posture.absent = _signals("absent")
            posture.unobserved = _signals("unobserved")
            posture.providers = dict(seen.get("providers") or {})
            posture.notes = list(seen.get("notes") or [])
        else:
            # Declared but never assessed. Every signal is UNOBSERVED, which is
            # the truth — reporting them as absent would be this product's
            # inaction rendered as the supplier's neglect.
            posture.unobserved = list(_suppliers.Signal)
        postures.append(posture)

    findings, refusal = _suppliers.concentrations(postures)
    register = _suppliers.Register(postures=postures, findings=findings,
                                   refusal=refusal)
    payload = register.to_dict()
    payload["assessed"] = sum(1 for p in postures if p.observed)
    payload["never_assessed"] = sum(1 for p in postures if not p.observed)
    payload["discrimination"] = _suppliers.DISCRIMINATING and _suppliers.DISCRIMINATION
    payload["ranking_signals"] = [s.value for s in _suppliers.DISCRIMINATING]
    return payload


@app.post("/api/v1/suppliers", tags=["suppliers"])
def declare_supplier(body: _SupplierBody) -> Dict[str, Any]:
    """Record a supplier relationship. Declared, never inferred.

    There is deliberately no discovery endpoint that proposes suppliers from
    DNS. Inventing a commercial relationship is worse than an empty register:
    the organisation would either assess a company it has no dealings with, or
    believe a real dependency was covered.
    """
    from core import suppliers as _suppliers
    try:
        supplier = _suppliers.Supplier(
            name=body.name, domain=body.domain.strip().lower(),
            tier=_suppliers.Tier(body.tier), dependency=body.dependency,
            declared_by=body.declared_by)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={
            "error": str(exc),
            "tiers": [t.value for t in _suppliers.Tier]})
    identifier = _supplier_store().declare(supplier)
    return {"id": identifier, "domain": supplier.domain,
            "tier": supplier.tier.value,
            "tier_meaning": supplier.tier.meaning,
            "assessed": False,
            "note": ("Declared. Nothing has been looked up yet — POST "
                     "/api/v1/suppliers/assess to observe what they publish.")}


@app.delete("/api/v1/suppliers/{domain}", tags=["suppliers"])
def forget_supplier(domain: str) -> Dict[str, Any]:
    removed = _supplier_store().forget(domain)
    if not removed:
        raise HTTPException(status_code=404,
                            detail=f"{domain!r} is not in the register")
    return {"domain": domain, "removed": True,
            "note": "Observations for this supplier were removed with it."}


@app.post("/api/v1/suppliers/assess", tags=["suppliers"])
def assess_suppliers(actor: str = Query(..., min_length=3)) -> Dict[str, Any]:
    """Observe what every declared supplier publishes. PASSIVE ONLY.

    A POST because it performs outbound lookups, and an actor is required
    because every permit names one — an unattributed lookup against a third
    party is not something this product will do.

    Nothing here can reach the supplier's own infrastructure: every operation
    available is passive and travels to a public recursive resolver. The four
    active operations are refused against an unverified asset by the gate, and
    a supplier's domain can never be verified by the customer.
    """
    from collect import supplier_scan
    from core import suppliers as _suppliers

    store = _supplier_store()
    declared = store.suppliers()
    if not declared:
        return {"assessed": 0, "note": (
            "The register is empty. An empty register is not a supply chain "
            "with no third parties — it is one nobody has written down.")}

    try:
        result = supplier_scan.observe(declared, actor=actor)
    except Exception as exc:                                    # noqa: BLE001
        raise HTTPException(status_code=502, detail={
            "error": f"{type(exc).__name__}: {exc}",
            "why": "the lookups failed; no observation was recorded rather "
                   "than a partial one being written as fact"})

    postures = [_suppliers.assess(
        supplier,
        records=(result["observations"].get(supplier.domain) or {}).get("records", {}))
        for supplier in declared]
    written = store.record_observations(postures)

    return {
        "assessed": written,
        "attempted_lookups": result["attempted"],
        "observed_lookups": result["observed"],
        "refused": result["refused"],
        # Stated rather than implied: an assessment built on a sweep that half
        # failed is a different claim from one built on a clean sweep.
        "coverage_note": result["note"],
    }


# ---------------------------------------------------------------------------
# Ask anything. Passive, and structurally so.


class _LookupBody(BaseModel):
    target: str
    actor: str


def _attach_abuse(found, target) -> None:
    """Vendored abuse-feed membership for a lookup target.

    Addresses are checked against the address and netblock feeds; a name is
    checked against the URL feeds, which are matched on host. Both, for a
    target that has both.
    """
    from core import blocklists as _bl
    try:
        corpus = _bl.Blocklists.load()
    except _bl.CorpusUnavailable as exc:
        found.unavailable.append({
            "source": "abuse feeds",
            "why": str(exc)[:160],
            "cost": "membership of published abuse feeds was not checked; this "
                    "is NOT a statement that the target is absent from them",
            "terms": "open"})
        return

    hits = []
    for address in list(target.addresses)[:16]:
        hits.extend(h.to_dict() for h in corpus.check_address(address))
    if not target.is_network:
        hits.extend(h.to_dict() for h in corpus.check_host(target.value))

    # One feed can list both an address and its name. Deduplicated on
    # (feed, matched) so a target does not appear to be on more lists than it is.
    seen = set()
    for hit in hits:
        key = (hit["feed"], hit["matched"])
        if key in seen:
            continue
        seen.add(key)
        found.abuse.append(hit)
    found.abuse_coverage = corpus.coverage()


def _attach_leak_listings(found, target) -> None:
    """Ransomware leak-site listings naming this target.

    Names only — a network has no company name, so a CIDR lookup skips this
    rather than matching every listing whose domain happens to resolve nearby.
    """
    from collect import leaksites as _leaks
    if target.is_network:
        return
    try:
        corpus = _leaks.LeakSites.load()
    except _leaks.CorpusUnavailable as exc:
        found.unavailable.append({
            "source": "ransomware leak sites",
            "why": str(exc)[:160],
            "cost": "public extortion-site victim indexes were not checked",
            "terms": "open"})
        return
    found.leak_listings = [m.to_dict() for m in corpus.check([target.value])]
    found.leak_coverage = corpus.coverage()


@app.post("/api/v1/lookup", tags=["lookup"])
def lookup_target(body: _LookupBody) -> Dict[str, Any]:
    """What the public record says about a domain, a host, an address or a /24.

    A POST because it performs outbound lookups and an actor is required — every
    permit names one, and an unattributed query against somebody else's estate
    is not something this product will do.

    PASSIVE AND UNABLE TO BE OTHERWISE. Ownership of a target somebody typed
    into a box cannot be proven, and the gate refuses every active operation
    against an unverified asset before scope is consulted. So this reports what
    the target PUBLISHES and cannot report what it runs — which is stated in the
    response rather than left for somebody to infer from a thin result.
    """
    from collect import ct as _ct
    from collect import lookup_scan
    from collect import takeover_scan
    from core import certificates as _certs
    from core import gate as _gate
    from core import lookup as _lookup
    from core import suppliers as _suppliers
    from core.scope import Scope, ScopeKind, ScopeRule

    try:
        target = _lookup.parse(body.target)
    except _lookup.TargetError as exc:
        raise HTTPException(status_code=422, detail={
            "error": str(exc),
            "accepts": ["a domain (example.com)", "a hostname (www.example.com)",
                        "an address (203.0.113.4)",
                        f"a block up to /{32 - (_lookup.MAX_CIDR_HOSTS.bit_length() - 1)}"
                        " (203.0.113.0/24)"]})

    try:
        observed = lookup_scan.observe(target, actor=body.actor)
    except Exception as exc:                                    # noqa: BLE001
        raise HTTPException(status_code=502, detail={
            "error": f"{type(exc).__name__}: {exc}",
            "why": "the lookups failed; no partial result is returned as fact"})

    found = _lookup.Lookup(
        target=target,
        reverse_dns=observed["reverse_dns"],
        reports=observed["reports"],
        unavailable=lookup_scan.unavailable_sources(target))

    if not target.is_network:
        found.posture = _suppliers.assess(
            _suppliers.Supplier(name=target.value, domain=target.value,
                                tier=_suppliers.Tier.ROUTINE,
                                declared_by=body.actor),
            records=observed["records"])

        # Certificate transparency: the SURFACE factor, and the one source that
        # finds names nobody told us about. A per-name scope, as everywhere else
        # a third party is read passively.
        scope = Scope([ScopeRule(kind=ScopeKind.DOMAIN, value=target.value)])
        try:
            permit = _gate.authorise(target.value, _ct.OPERATION, body.actor,
                                     scope, kind=ScopeKind.DOMAIN)
            names, report = _ct.from_certspotter(target.value, permit=permit)
            # (name, first_seen) tuples, not objects.
            found.names = sorted({n for n, _ in names})
            found.reports.append(report)

            # The SAME log, read for the fields discovery discards. Issuer,
            # validity window and lineage are what Recorded Future sells as
            # historical TLS data; CT gives them away and SKOPOS was already
            # making the call.
            certificates, cert_report = _ct.certificates_from_certspotter(
                target.value, permit=permit)
            found.reports.append(cert_report)
            if certificates:
                found.certificates = _certs.assess(certificates)
                found.certificate_lineage = _certs.lineage(certificates)
                found.certificate_coverage = _certs.coverage(certificates)
                found.subsidiary_candidates = _certs.candidate_organisations(
                    certificates, known=[target.value])
        except Exception as exc:                                # noqa: BLE001
            # A CT failure leaves SURFACE unobserved rather than zero. Reporting
            # "0 names" for a source that errored is our outage rendered as
            # their absence.
            found.unavailable.append({
                "source": "certspotter",
                "why": f"{type(exc).__name__}: {str(exc)[:80]}",
                "cost": "names visible only in certificate transparency were "
                        "not enumerated",
                "terms": "open"})

        try:
            permit = _gate.authorise(target.value, takeover_scan.RDAP_OPERATION,
                                     body.actor, scope, kind=ScopeKind.DOMAIN)
            found.registration = takeover_scan.rdap_registration(permit,
                                                                 target.value)
        except Exception as exc:                                # noqa: BLE001
            # Unobserved, never "unlocked". A failed lookup that scored as an
            # absent transfer lock would be our outage rendered as their
            # negligence.
            found.registration = {"observed": False,
                                  "detail": f"{type(exc).__name__}"}

    # ── the vendored corpora ────────────────────────────────────────────────
    # No network call: both were fetched by `tools/refresh_intel.py` and are
    # queried in process. A missing corpus is reported as UNAVAILABLE, never as
    # an empty result — "we never built the index" and "nothing matched" are
    # different sentences and only one of them is reassuring.
    _attach_abuse(found, target)
    _attach_leak_listings(found, target)

    # The licensed sources. Each is inert without its key and reports itself as
    # unavailable rather than absent — "we have no key" must never render as
    # "there is nothing there".
    from collect import keyed_sources as _keyed
    answers = []
    try:
        def permit_for(operation: str):
            return _gate.authorise(target.value, operation, body.actor,
                                   Scope([ScopeRule(kind=ScopeKind.DOMAIN,
                                                    value=target.value)]),
                                   kind=ScopeKind.DOMAIN)
        answers = _keyed.consult_for_target(permit_for, target)
    except Exception as exc:                                    # noqa: BLE001
        found.unavailable.append({
            "source": "keyed", "why": f"{type(exc).__name__}: {str(exc)[:60]}",
            "cost": "no third-party service or reputation data", "terms": "n/a"})

    payload = found.to_dict()
    payload["keyed_sources"] = [a.to_dict() for a in answers]
    payload["coverage"] = {
        "attempted": observed["attempted"],
        "observed": observed["observed"],
        "refused": observed["refused"],
    }
    return payload


@app.get("/api/v1/lookup/sources", tags=["lookup"])
def lookup_sources() -> Dict[str, Any]:
    """Every source a lookup can consult, and which are configured.

    Public knowledge about the instance, not about anybody's estate: it says
    which questions this deployment is able to answer at all. A user reading a
    thin result needs to be able to tell "nothing there" from "no key".
    """
    from collect import registry
    return {
        "sources": [
            {"name": source.name, "operation": source.operation,
             "terms": source.terms.value, "configured": source.configured,
             "default_on": source.default_on,
             "credential_env": source.credential_env, "note": source.note}
            for source in registry.REGISTRY
        ],
        "terms_reviewed_on": registry.TERMS_REVIEWED_ON,
        "note": ("A CREDENTIALED source is off until its key is set, and a "
                 "lookup running without one reports it as unavailable rather "
                 "than returning a clean result. Terms are the operator's to "
                 "accept, not this product's."),
    }


# ---------------------------------------------------------------------------
# Brand and identity exposure. Both passive; neither renders a verdict.


class _BrandBody(BaseModel):
    terms: List[str]
    owned: List[str] = []
    declared_by: str


@app.post("/api/v1/brand/lookalikes", tags=["brand"])
def brand_lookalikes(body: _BrandBody) -> Dict[str, Any]:
    """Names in certificate transparency that borrow a declared term.

    A password-harvesting site needs HTTPS to look legitimate, which needs a
    certificate, which lands in a public log. So this finds imitation with no
    cooperation from the impersonator and no packet sent to them.

    IT ESTABLISHES NOTHING. A name that borrows your term and sits outside the
    domains you declared owning may be a phishing site, a partner, a reseller or
    an unrelated company. Deciding which is a judgement about your commercial
    relationships, and a takedown filed against a legitimate reseller is worse
    than a missed phishing domain — it is an action you took on our say-so.
    """
    from collect import lookalike_scan
    from core import gate as _gate
    from core import lookalike as _lookalike
    from core.scope import Scope, ScopeKind, ScopeRule

    try:
        brand = _lookalike.Brand(terms=tuple(body.terms),
                                 owned=tuple(body.owned),
                                 declared_by=body.declared_by)
    except _lookalike.BrandError as exc:
        raise HTTPException(status_code=422, detail={"error": str(exc)})

    anchor = brand.owned[0] if brand.owned else brand.terms[0] + ".invalid"

    def permit_for(operation: str):
        scope = Scope([ScopeRule(kind=ScopeKind.DOMAIN, value=anchor)])
        return _gate.authorise(anchor, operation, brand.declared_by, scope,
                               kind=ScopeKind.DOMAIN)

    try:
        observed = lookalike_scan.observe(list(brand.terms), permit_for)
    except Exception as exc:                                    # noqa: BLE001
        raise HTTPException(status_code=502, detail={
            "error": f"{type(exc).__name__}: {exc}",
            "why": "no partial result is returned as fact"})

    report = _lookalike.build(brand, observed["names"],
                              searched=observed["searched"],
                              unavailable=observed["unavailable"])
    payload = report.to_dict()
    payload["terms"] = list(brand.terms)
    payload["owned"] = list(brand.owned)
    return payload


class _AccountBody(BaseModel):
    address: str
    actor: str


@app.post("/api/v1/identity/breaches", tags=["brand"])
def account_breaches(body: _AccountBody) -> Dict[str, Any]:
    """Whether an email address appears in a published breach corpus.

    THIS IS THE ONE PLACE AN EMAIL ADDRESS IS AN INPUT. `/api/v1/lookup`
    refuses one on purpose — breach exposure is a different question with a
    different source, and answering it from the same box would mean one screen
    quietly doing two unrelated things.

    What it says: this address appeared in a corpus published on a date. What it
    does NOT say: that the account is compromised now, that the password is
    still in use, or that anything should be revoked. That remedy is somebody's
    judgement and it is not this product's to assert.
    """
    from collect import keyed_sources
    from core import gate as _gate
    from core.scope import Scope, ScopeKind, ScopeRule

    address = str(body.address or "").strip().lower()
    if "@" not in address or "." not in address.split("@")[-1]:
        raise HTTPException(status_code=422, detail={
            "error": f"{body.address!r} is not an email address",
            "note": "for a domain or an address, use /api/v1/lookup"})

    # The permit names the DOMAIN half. HIBP is a third-party index and the
    # lookup never reaches the address owner's infrastructure, but the operation
    # is still authorised and audited like every other outbound read.
    domain = address.split("@")[-1]
    scope = Scope([ScopeRule(kind=ScopeKind.DOMAIN, value=domain)])
    try:
        permit = _gate.authorise(domain, keyed_sources.OPERATION, body.actor,
                                 scope, kind=ScopeKind.DOMAIN)
        answer = keyed_sources.hibp_account(permit, address)
    except Exception as exc:                                    # noqa: BLE001
        raise HTTPException(status_code=502,
                            detail={"error": f"{type(exc).__name__}: {exc}"})

    payload = answer.to_dict()
    payload["address"] = address
    payload["what_this_does_not_say"] = (
        "That the account is compromised now, that the password is still in "
        "use, or that anything should be revoked. It says the address appeared "
        "in a corpus that was published on a date.")
    return payload


@app.get("/api/v1/identity/secrets-scanning", tags=["brand"])
def secrets_scanning() -> Dict[str, Any]:
    """Where exposed keys and tokens are handled, which is NOT here.

    A route that returns a deliberate refusal, because the alternative is
    somebody discovering the gap by looking for a screen that does not exist.

    This portfolio already has a Secrets Scanner with its own detector corpus,
    its own validation and its own false-positive discipline. Growing a second
    regex corpus here would produce two products that disagree about whether a
    string is a live credential, and the one a customer happened to open would
    decide what they believed.
    """
    return {
        "supported": False,
        "reason": (
            "Exposed keys and tokens are the Secrets Scanner's job. It already "
            "has a detector corpus, validation and a false-positive discipline; "
            "a second corpus here would drift from it, and two products "
            "disagreeing about whether a string is a live credential is worse "
            "than one product answering."),
        "integration": (
            "The intended shape is INGEST, not reimplementation: SKOPOS "
            "correlates a secret the Secrets Scanner already found against the "
            "externally-visible asset it was found on. That needs an export "
            "contract from that tool, which does not exist yet."),
        "what_skopos_does_contribute": (
            "The external half. A leaked key matters more when it is on an "
            "asset this product can see from the internet, and that "
            "reachability is something only SKOPOS knows."),
    }


@app.get("/api/v1/graph", tags=["graph"])
def exposure_graph(limit: int = Query(300, ge=1, le=500),
                   run: Optional[int] = None) -> Dict[str, Any]:
    """The exposure graph: asset -> product -> exploited vulnerability.

    NOT A TRAFFIC GRAPH, and it says so in the payload. This product has never
    seen a packet of the customer's traffic, so throughput and flows would be
    drawn from nothing.

    THE UNEXPLAINED-EXPOSURE EDGE HAS THREE STATES, not two. Drawn; absent
    because a cloud model was ingested and disagrees with nothing; or UNDRAWABLE
    because no cloud model was ingested at all. The third is the common case and
    collapsing it into the second would render a missing input as a clean
    result.
    """
    from core import graph as _graph

    store = _findings_store()
    rows = store.findings(run_id=run, limit=limit)

    # Whether a cloud model was ingested is read from the FINDINGS, not from a
    # flag somebody could set independently: a reconciliation value exists only
    # when an OverWatch export was actually joined against this run.
    reconciled = [r for r in rows if r.get("reconciliation")]
    cloud_model = True if reconciled else None

    built = _graph.build(rows, cloud_model=cloud_model, limit=limit)
    payload = built.to_dict()
    payload["findings_drawn"] = len(rows)
    payload["truncated"] = len(rows) >= limit
    # Advisories beyond the exploited catalogue, kept STRUCTURALLY apart. They
    # are a different type, not a flag on a finding — see core/coverage.py. The
    # graph reports the count and refuses to draw them as exposures.
    payload["beyond_catalogue"] = {
        "advisories": None,
        "route": "/api/v1/advisories",
        "note": (
            "Vulnerabilities beyond the exploited catalogue are held in a "
            "different type on purpose (core/coverage.py): OSV and EUVD carry "
            "hundreds of thousands of advisories with no exploitation filter, "
            "and blending them into this graph would turn a short defensible "
            "worklist into a vulnerability scanner, quietly and in one merge. "
            "They are served from /api/v1/advisories, which needs an "
            "inventory carrying package coordinates."),
    }
    return payload


@app.get("/api/v1/advisories", tags=["graph"])
def advisories(inventory_path: str = Query(..., description=
                   "the inventory to look up; the same CSV a scan reads"),
               actor: str = Query("api")) -> Dict[str, Any]:
    """Vulnerabilities BEYOND the exploited catalogue, served separately.

    A different route because they are a different type. OSV and EUVD carry
    hundreds of thousands of advisories with no exploitation filter, and putting
    them in the same list as the exploited worklist would turn this product into
    the thing it was written not to be — quietly, and in a single merge.
    `core/coverage.py` makes that impossible rather than merely unwise:
    `engine.rank()` will not accept an advisory.

    WHY THIS USUALLY RETURNS NOTHING, AND WHY THAT IS THE POINT. OSV joins on an
    ECOSYSTEM AND AN EXACT PACKAGE NAME, which come from an SBOM or a dependency
    manifest. A discovered, fingerprinted host carries neither — measured on the
    sample inventory: 0 of 9 rows have package coordinates. So the normal answer
    is "nothing could be looked up", and the response says which assets and why
    rather than returning an empty list that reads as a clean estate.
    """
    from collect import advisories as _advisories
    from core import coverage as _coverage
    from core import inventory as _inventory

    try:
        assets, rejected = inventory.load(Path(inventory_path))
    except Exception as exc:                                    # noqa: BLE001
        raise HTTPException(status_code=422, detail={
            "error": f"{type(exc).__name__}: {exc}",
            "note": "this route reads the same inventory a scan does"})

    # The stored scope, exactly as a discovery run uses it. An advisory lookup
    # reaches a public vulnerability database and never the customer's estate,
    # but it still takes a permit per asset like everything else.
    from core.store import PostgresStore
    try:
        scope = PostgresStore().load_scope()
    except StoreUnavailable:
        # No database, no scope rules — so every asset is UNSCOPED and the
        # collector refuses each one by name. That is a real answer and reads
        # correctly in `failures`; an empty Scope() silently permitting nothing
        # would look the same but mean something else.
        scope = Scope([])
    try:
        # Returns (CoverageResult, Coverage) — the second is the
        # per-source degradation report every collector produces.
        result, coverage = _advisories.run(assets, actor=actor,
                                           scope=scope)
    except Exception as exc:                                    # noqa: BLE001
        raise HTTPException(status_code=502, detail={
            "error": f"{type(exc).__name__}: {exc}",
            "why": "no partial advisory set is returned as fact"})

    return {
        "note": result.note(total_assets=len(assets)),
        "advisories": [a.to_dict() if hasattr(a, "to_dict") else {
            "asset": a.asset, "identifier": a.identifier,
            "source": getattr(a.source, "value", str(a.source)),
            "summary": a.summary, "published": str(a.published or ""),
        } for a in result.advisories],
        "assets_read": len(assets),
        "assets_covered": result.assets_covered,
        # NAMED, not counted. This is the majority case for a discovered estate
        # and a reader needs to know it is a coverage gap, not a clean result.
        "without_coordinates": list(result.without_coordinates),
        "failures": [{"asset": a, "why": w} for a, w in result.failures],
        "rows_rejected": len(rejected),
        # Whether the SOURCE answered, separate from whether anything was
        # found. A failed OSV lookup and an empty one are different results.
        "source_coverage": coverage.note(len(result.advisories), "advisory")
        if hasattr(coverage, "note") else None,
        "kept_separate": (
            "These are NOT exposures and are not scored, ranked or merged into "
            "the worklist. None of them is a statement that anyone is "
            "exploiting anything — that is what the exploited catalogue is for, "
            "and it is a separate list on purpose."),
        "how_to_get_coverage": (
            "OSV needs an ecosystem and an exact package name. Add `package` "
            "and `ecosystem` columns to the inventory, from an SBOM or a "
            "dependency manifest. A product name is deliberately NOT used as a "
            "package name: measured, it returns nothing, and guessing a mapping "
            "from \"Apache HTTP Server\" to a package would be inventing a "
            "fact about your estate."),
    }


@app.get("/api/v1/compliance/controls", tags=["compliance"])
def compliance_controls(framework: Optional[str] = None) -> Dict[str, Any]:
    """Which controls this product helps evidence, and what it does not do.

    There is deliberately no coverage figure. A percentage would be summed,
    shown to a board, and the board would be receiving a number no tool has the
    basis to produce.
    """
    from core import controls as _controls
    payload = _controls.mapping()
    if framework:
        payload["controls"] = [c.to_dict()
                               for c in _controls.by_framework(framework)]
    return payload


@app.get("/api/v1/compliance/cert-in", tags=["compliance"])
def compliance_cert_in() -> Dict[str, Any]:
    """What SKOPOS can and cannot observe against CERT-In's reportable list.

    The honest answer is: almost none of it. Seven of the eight Annexure I
    categories describe something an adversary DID, and this product looks at
    your estate from outside rather than monitoring your systems. The six-hour
    clock is not started from a finding and there is no endpoint that does so —
    see `why_not_automatic`.
    """
    from core import cert_in as _cert_in
    return _cert_in.observability_note()


@app.get("/api/v1/compliance/cii", tags=["compliance"])
def compliance_cii() -> Dict[str, Any]:
    """The CII exposure register, over assets the ORGANISATION has declared.

    SKOPOS does not designate anything. Under Section 70 of the IT Act, 2000,
    the appropriate Government declares a computer resource a protected system
    by notification in the Official Gazette. This route reads declarations the
    organisation recorded and adds what SKOPOS observed from outside.

    Designations live in the scope store as CII-kind rules in a later slice; for
    now the register is served empty with its authority and caveats intact, so a
    consumer can integrate against the shape before the write path exists.
    """
    from core import cii as _cii
    store = _findings_store()
    rows = store.findings(limit=500)
    register = _cii.build(designations=(), findings=rows)
    payload = register.to_dict()
    payload["note"] = (
        "No designations are recorded yet, so every externally visible asset "
        "appears in `undeclared_assets` as a question. That is the correct "
        "empty state: an empty register is not an estate with no critical "
        "infrastructure, it is an estate nobody has declared.")
    return payload


class _RelatedFinding(BaseModel):
    """A finding the declarer considers related, named by asset and CVE.

    Only the coordinates are accepted. The finding's BASIS is read back from the
    store rather than taken from the request, so a caller cannot post
    `basis: version_range` and receive a regulator-facing document describing a
    worklist entry as a confirmed vulnerable version.
    """

    asset: str
    cve: str


class _DeclarationBody(BaseModel):
    category: str
    #: When the organisation BECAME AWARE. Must carry a timezone — a six-hour
    #: deadline computed from an ambiguous time is worse than no deadline.
    became_aware_at: datetime
    declared_by: str
    summary: str
    organisation: str = ""
    related: List[_RelatedFinding] = []


@app.post("/api/v1/compliance/cert-in/draft", tags=["compliance"])
def compliance_cert_in_draft(body: _DeclarationBody) -> Dict[str, Any]:
    """Pre-fill a CERT-In notification from a human's incident declaration.

    POST, not GET, because the input is a statement somebody makes rather than a
    resource that exists. A Declaration is required, so there is no path from a
    finding to this document — the determination that an incident occurred is
    the reporter's, and this route will not make it for them.

    Nothing is persisted and nothing is transmitted. The response is text for a
    human to complete and file themselves; the judgement fields come back marked
    rather than guessed.
    """
    from core import cert_in as _cert_in
    try:
        category = _cert_in.Category(body.category)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"error": f"unknown category {body.category!r}",
                    "categories": [c.value for c in _cert_in.Category],
                    "note": _cert_in.observability_note()["summary"]})

    related: List[Dict[str, Any]] = []
    if body.related:
        wanted = {(r.asset, r.cve.upper()) for r in body.related}
        rows = _findings_store().findings(limit=2000)
        found = {(str(r.get("asset")), str(r.get("cve", "")).upper()): r
                 for r in rows}
        missing = sorted(f"{a}/{c}" for a, c in wanted if (a, c) not in found)
        if missing:
            raise HTTPException(
                status_code=422,
                detail={"error": "no such finding", "unresolved": missing,
                        "why": "a notification must not cite a finding this "
                               "product cannot produce evidence for"})
        related = [found[k] for k in sorted(wanted)]

    try:
        declaration = _cert_in.Declaration(
            category=category, became_aware_at=body.became_aware_at,
            declared_by=body.declared_by, summary=body.summary,
            related_findings=related)
    except _cert_in.DeclarationInvalid as exc:
        raise HTTPException(status_code=422, detail={"error": str(exc)})

    clock = _cert_in.Clock(declaration)
    return {
        "draft": _cert_in.notification_draft(declaration, clock=clock,
                                             organisation=body.organisation),
        "filed": False,
        "transmitted_to": None,
        "deadline": clock.deadline.isoformat(),
        "directive": _cert_in.DIRECTIVE,
        "note": ("This endpoint produced text and stored nothing. SKOPOS does "
                 "not file with CERT-In, and cannot: filing is an act by your "
                 "organisation, through CERT-In's own channel."),
    }


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
        if path == "taxii2" or path.startswith("taxii2/"):
            # Reached only when TAXII is unregistered, i.e. no SKOPOS_API_TOKEN.
            # Returning the console shell here would hand a TAXII client HTML
            # from a discovery endpoint, which it cannot distinguish from this
            # not being a TAXII server at all.
            raise HTTPException(
                status_code=404,
                detail="TAXII is not enabled on this instance; set SKOPOS_API_TOKEN")
        candidate = directory / path
        if candidate.is_file() and directory.resolve() in candidate.resolve().parents:
            return FileResponse(candidate)
        return FileResponse(index)

    return True


CONSOLE_MOUNTED = mount_console(app, CONSOLE_DIR)
