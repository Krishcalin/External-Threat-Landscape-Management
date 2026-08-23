"""Persistence for the forecast record and the EPSS series.

Both tables exist for the same reason: they accumulate evidence that cannot be
reconstructed later. A missing week of EPSS is a permanent hole in every
velocity figure computed afterwards, and a forecast never written is a forecast
that can never be scored.

So writes here are append-only in spirit and idempotent in practice —
re-running a scan must not double-count a pairing in any accuracy figure, and
re-running the EPSS snapshot on the same day must not weight that day twice.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

from core.forecast import (OBSERVATION_WINDOW_DAYS, Forecast, Outcome,
                           score_record)
from core.store import StoreUnavailable


class ForecastStore(Protocol):
    def record(self, forecasts: Sequence[Forecast],
               run_id: Optional[int] = None) -> int: ...

    def unresolved(self, older_than_days: int = 0) -> List[Forecast]: ...

    def resolve(self, asset: str, cve: str, model_version: str,
                outcome: Outcome, source: str,
                when: Optional[datetime] = None) -> bool: ...

    def all_forecasts(self, model_version: Optional[str] = None) -> List[Forecast]: ...

    def record_epss(self, day: date, scores: Dict[str, Dict[str, float]],
                    model: str = "") -> int: ...

    def epss_series(self, cve: str, days: int = 30) -> List[Tuple[date, float]]: ...


class MemoryForecastStore:
    def __init__(self) -> None:
        self._rows: List[Forecast] = []
        self._epss: Dict[Tuple[str, date], Tuple[float, Optional[float], str]] = {}

    def record(self, forecasts, run_id=None) -> int:
        seen = {(f.asset, f.cve, f.model_version) for f in self._rows}
        written = 0
        for forecast in forecasts:
            key = (forecast.asset, forecast.cve, forecast.model_version)
            if key in seen:
                continue
            forecast.issued_at = forecast.issued_at or datetime.now(timezone.utc)
            self._rows.append(forecast)
            seen.add(key)
            written += 1
        return written

    def unresolved(self, older_than_days=0):
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        return [f for f in self._rows
                if not f.resolved and (f.issued_at or cutoff) <= cutoff]

    def resolve(self, asset, cve, model_version, outcome, source, when=None):
        for forecast in self._rows:
            if (forecast.asset == asset and forecast.cve == cve
                    and forecast.model_version == model_version
                    and not forecast.resolved):
                forecast.outcome = outcome
                forecast.resolved_at = when or datetime.now(timezone.utc)
                forecast.resolution_source = source
                return True
        return False

    def all_forecasts(self, model_version=None):
        if model_version is None:
            return list(self._rows)
        return [f for f in self._rows if f.model_version == model_version]

    def record_epss(self, day, scores, model=""):
        written = 0
        for cve, values in scores.items():
            key = (str(cve).upper(), day)
            if key in self._epss:
                continue
            self._epss[key] = (float(values.get("epss", 0.0)),
                               values.get("percentile"), model)
            written += 1
        return written

    def epss_series(self, cve, days=30):
        wanted = str(cve).upper()
        rows = [(d, v[0]) for (c, d), v in self._epss.items() if c == wanted]
        return sorted(rows)[-days:]


class PostgresForecastStore:
    def __init__(self, dsn: Optional[str] = None, migrate: bool = True) -> None:
        self._dsn = dsn or os.environ.get("SKOPOS_DATABASE_URL")
        if not self._dsn:
            raise StoreUnavailable("SKOPOS_DATABASE_URL is not set")
        if migrate:
            # Every store migrates, not just core/store.py. See
            # migrate.ensure_once for the deployment this was measured breaking.
            from core import migrate as _migrate
            try:
                _migrate.ensure_once(self._dsn)
            except _migrate.MigrationError as exc:
                raise StoreUnavailable(str(exc)) from exc

    def _connect(self):
        import psycopg
        try:
            return psycopg.connect(self._dsn)
        except Exception as exc:                   # pragma: no cover
            raise StoreUnavailable(f"could not reach the database: {exc}") from exc

    def record(self, forecasts, run_id=None) -> int:
        import psycopg
        written = 0
        with self._connect() as conn, conn.cursor() as cur:
            for forecast in forecasts:
                cur.execute(
                    "INSERT INTO forecast (run_id, asset, cve, model_version,"
                    " inputs, teps, band) VALUES (%s,%s,%s,%s,%s,%s,%s)"
                    " ON CONFLICT (run_id, asset, cve, model_version)"
                    " DO NOTHING",
                    (run_id, forecast.asset, forecast.cve,
                     forecast.model_version,
                     psycopg.types.json.Jsonb(forecast.inputs),
                     forecast.teps, forecast.band))
                written += cur.rowcount or 0
        return written

    def _rows_to_forecasts(self, rows) -> List[Forecast]:
        out = []
        for r in rows:
            out.append(Forecast(
                asset=r[0], cve=r[1], model_version=r[2], inputs=r[3] or {},
                teps=float(r[4]), band=r[5], issued_at=r[6], resolved_at=r[7],
                outcome=Outcome(r[8]) if r[8] else None,
                resolution_source=r[9] or ""))
        return out

    _SELECT = ("SELECT asset, cve, model_version, inputs, teps, band,"
               " issued_at, resolved_at, outcome, resolution_source FROM forecast")

    def unresolved(self, older_than_days=0):
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(self._SELECT +
                        " WHERE resolved_at IS NULL AND issued_at <= now() -"
                        " make_interval(days => %s) ORDER BY issued_at",
                        (older_than_days,))
            return self._rows_to_forecasts(cur.fetchall())

    def resolve(self, asset, cve, model_version, outcome, source, when=None):
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE forecast SET resolved_at = %s, outcome = %s,"
                " resolution_source = %s"
                " WHERE asset = %s AND cve = %s AND model_version = %s"
                "   AND resolved_at IS NULL",
                (when or datetime.now(timezone.utc), outcome.value, source,
                 asset, cve, model_version))
            return (cur.rowcount or 0) > 0

    def all_forecasts(self, model_version=None):
        clause = " WHERE model_version = %s" if model_version else ""
        params = (model_version,) if model_version else ()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(self._SELECT + clause + " ORDER BY issued_at", params)
            return self._rows_to_forecasts(cur.fetchall())

    def record_epss(self, day, scores, model=""):
        written = 0
        with self._connect() as conn, conn.cursor() as cur:
            for cve, values in scores.items():
                cur.execute(
                    "INSERT INTO epss_history (cve, observed_on, epss,"
                    " percentile, model) VALUES (%s,%s,%s,%s,%s)"
                    " ON CONFLICT (cve, observed_on) DO NOTHING",
                    (str(cve).upper(), day, values.get("epss", 0.0),
                     values.get("percentile"), model))
                written += cur.rowcount or 0
        return written

    def epss_series(self, cve, days=30):
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT observed_on, epss FROM epss_history WHERE cve = %s"
                " ORDER BY observed_on DESC LIMIT %s", (str(cve).upper(), days))
            return [(r[0], float(r[1])) for r in reversed(cur.fetchall())]


def open_forecast_store(dsn: Optional[str] = None) -> ForecastStore:
    return PostgresForecastStore(dsn)


def accuracy(store: ForecastStore, model_version: str):
    return score_record(store.all_forecasts(model_version), model_version)


__all__ = ["ForecastStore", "MemoryForecastStore", "PostgresForecastStore",
           "open_forecast_store", "accuracy"]
