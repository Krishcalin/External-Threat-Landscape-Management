"""Scan results, and what is new since the last one.

WHY THIS EXISTS
---------------
Findings were held in a module-level dict in `api/app.py`. Measured: a scan
produced 64 findings across 7 assets, the container restarted, and
`GET /api/v1/summary` answered "no scan has been run" — while scope, ownership,
the audit chain and every DNS observation survived intact. The product's actual
output was the only thing that did not.

WHAT PERSISTENCE UNLOCKS BEYOND SURVIVING A RESTART
---------------------------------------------------
Run-over-run diff. "What is NEW since last time" is most of what makes a
monitoring product worth running continuously rather than once, and it was not
merely unbuilt — it was impossible, because nothing remembered the previous run.

A FINDING'S IDENTITY IS (asset, cve)
------------------------------------
Not the TEPS, which moves when EPSS moves; not the band, which moves when the
TEPS crosses a threshold. Keying on either would report a score change as a new
finding and flood the "new since last scan" list with things the operator has
already seen — the single fastest way to make a feed unreadable.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

from core.store import StoreUnavailable


@dataclass
class RunDiff:
    """What changed between two scans, in the terms an operator acts on."""

    previous_run: Optional[int]
    new: List[Dict[str, Any]] = field(default_factory=list)
    resolved: List[Dict[str, Any]] = field(default_factory=list)
    carried: int = 0
    #: Findings present in both runs whose band moved. Not "new", but the reason
    #: somebody may need to look again.
    reband: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def is_baseline(self) -> bool:
        return self.previous_run is None

    def headline(self) -> str:
        if self.is_baseline:
            return (f"First scan on record: {len(self.new)} finding(s). "
                    f"Nothing is 'new' on a baseline — there is nothing to be "
                    f"new against.")
        parts = [f"{len(self.new)} new since run {self.previous_run}"]
        if self.resolved:
            parts.append(f"{len(self.resolved)} no longer present")
        if self.reband:
            parts.append(f"{len(self.reband)} changed band")
        parts.append(f"{self.carried} carried over unchanged")
        return ", ".join(parts) + "."


class FindingsStore(Protocol):
    def record_run(self, actor: str, inventory: str, catalogue: Dict[str, Any],
                   assets_read: int, rows_rejected: int, assets_unmatched: int,
                   summary: Dict[str, Any],
                   findings: Sequence[Dict[str, Any]]) -> int: ...

    def latest_run(self) -> Optional[Dict[str, Any]]: ...

    def findings(self, run_id: Optional[int] = None, limit: int = 200,
                 band: Optional[str] = None,
                 reconciliation: Optional[str] = None) -> List[Dict[str, Any]]: ...

    def diff_against_previous(self, run_id: Optional[int] = None) -> RunDiff: ...

    def runs(self, limit: int = 20) -> List[Dict[str, Any]]: ...


def _row(finding: Dict[str, Any]) -> Tuple:
    return (
        str(finding.get("asset") or ""),
        str(finding.get("product") or ""),
        str(finding.get("cve") or ""),
        float(finding.get("teps") or 0.0),
        str(finding.get("band") or "informational"),
        str(finding.get("basis") or "product_match"),
        str(finding.get("name_confidence") or "partial"),
        bool(finding.get("known_ransomware")),
        finding.get("reconciliation"),
    )


class MemoryFindingsStore:
    """In process, for tests. Not a fallback — see `open_findings_store`."""

    def __init__(self) -> None:
        self._runs: List[Dict[str, Any]] = []
        self._findings: Dict[int, List[Dict[str, Any]]] = {}

    def record_run(self, actor, inventory, catalogue, assets_read,
                   rows_rejected, assets_unmatched, summary, findings) -> int:
        run_id = len(self._runs) + 1
        self._runs.append({
            "id": run_id, "actor": actor, "inventory": inventory,
            "catalog_version": catalogue.get("catalog_version"),
            "catalog_age_days": catalogue.get("age_days"),
            "assets_read": assets_read, "rows_rejected": rows_rejected,
            "assets_unmatched": assets_unmatched, "summary": summary,
            "scanned_at": catalogue.get("scanned_at", ""),
        })
        self._findings[run_id] = [dict(f) for f in findings]
        return run_id

    def latest_run(self):
        return self._runs[-1] if self._runs else None

    def findings(self, run_id=None, limit=200, band=None, reconciliation=None):
        if run_id is None:
            latest = self.latest_run()
            if latest is None:
                return []
            run_id = latest["id"]
        rows = self._findings.get(run_id, [])
        if band:
            rows = [r for r in rows if r.get("band") == band]
        if reconciliation:
            rows = [r for r in rows if r.get("reconciliation") == reconciliation]
        return sorted(rows, key=lambda r: -float(r.get("teps") or 0))[:limit]

    def runs(self, limit=20):
        return list(reversed(self._runs))[:limit]

    def diff_against_previous(self, run_id=None) -> RunDiff:
        if not self._runs:
            return RunDiff(previous_run=None)
        current = run_id or self._runs[-1]["id"]
        earlier = [r["id"] for r in self._runs if r["id"] < current]
        if not earlier:
            return RunDiff(previous_run=None,
                           new=list(self._findings.get(current, [])))
        previous = max(earlier)
        return _diff(self._findings.get(previous, []),
                     self._findings.get(current, []), previous)


def _diff(before: Sequence[Dict[str, Any]], after: Sequence[Dict[str, Any]],
          previous_run: int) -> RunDiff:
    """Keyed on (asset, cve). See the module docstring for why not on score."""
    before_by = {(f["asset"], f["cve"]): f for f in before}
    after_by = {(f["asset"], f["cve"]): f for f in after}

    new = [f for key, f in after_by.items() if key not in before_by]
    resolved = [f for key, f in before_by.items() if key not in after_by]
    reband, carried = [], 0
    for key, current in after_by.items():
        prior = before_by.get(key)
        if prior is None:
            continue
        if prior.get("band") != current.get("band"):
            reband.append({**current, "previous_band": prior.get("band")})
        else:
            carried += 1
    return RunDiff(previous_run=previous_run, new=new, resolved=resolved,
                   carried=carried, reband=reband)


class PostgresFindingsStore:
    def __init__(self, dsn: Optional[str] = None) -> None:
        self._dsn = dsn or os.environ.get("SKOPOS_DATABASE_URL")
        if not self._dsn:
            raise StoreUnavailable("SKOPOS_DATABASE_URL is not set")

    def _connect(self):
        import psycopg
        try:
            return psycopg.connect(self._dsn)
        except Exception as exc:                   # pragma: no cover
            raise StoreUnavailable(f"could not reach the database: {exc}") from exc

    def record_run(self, actor, inventory, catalogue, assets_read,
                   rows_rejected, assets_unmatched, summary, findings) -> int:
        import psycopg

        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scan_run (actor, inventory, catalog_version,"
                " catalog_age_days, assets_read, rows_rejected,"
                " assets_unmatched, summary)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (actor, inventory, str(catalogue.get("catalog_version") or ""),
                 catalogue.get("age_days"), assets_read, rows_rejected,
                 assets_unmatched, psycopg.types.json.Jsonb(summary)))
            run_id = cur.fetchone()[0]
            for finding in findings:
                asset, product, cve, teps, band, basis, confidence, ransom, recon \
                    = _row(finding)
                if not asset or not cve:
                    continue
                cur.execute(
                    "INSERT INTO finding (run_id, asset, product, cve, teps,"
                    " band, basis, name_confidence, known_ransomware,"
                    " reconciliation, payload)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                    " ON CONFLICT (run_id, asset, cve) DO NOTHING",
                    (run_id, asset, product, cve, teps, band, basis, confidence,
                     ransom, recon, psycopg.types.json.Jsonb(finding)))
        return run_id

    def latest_run(self):
        rows = self.runs(1)
        return rows[0] if rows else None

    def runs(self, limit=20):
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, scanned_at, actor, inventory, catalog_version,"
                " catalog_age_days, assets_read, rows_rejected,"
                " assets_unmatched, summary FROM scan_run"
                " ORDER BY id DESC LIMIT %s", (limit,))
            return [{"id": r[0], "scanned_at": str(r[1]), "actor": r[2],
                     "inventory": r[3], "catalog_version": r[4],
                     "catalog_age_days": r[5], "assets_read": r[6],
                     "rows_rejected": r[7], "assets_unmatched": r[8],
                     "summary": r[9]} for r in cur.fetchall()]

    def findings(self, run_id=None, limit=200, band=None, reconciliation=None):
        clauses, params = [], []
        if run_id is None:
            clauses.append("run_id = (SELECT max(id) FROM scan_run)")
        else:
            clauses.append("run_id = %s")
            params.append(run_id)
        if band:
            clauses.append("band = %s")
            params.append(band)
        if reconciliation:
            clauses.append("reconciliation = %s")
            params.append(reconciliation)
        params.append(limit)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT payload FROM finding WHERE "
                        + " AND ".join(clauses)
                        + " ORDER BY teps DESC LIMIT %s", tuple(params))
            return [r[0] for r in cur.fetchall()]

    def diff_against_previous(self, run_id=None) -> RunDiff:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT max(id) FROM scan_run")
            latest = cur.fetchone()[0]
            if latest is None:
                return RunDiff(previous_run=None)
            current = run_id or latest
            cur.execute("SELECT max(id) FROM scan_run WHERE id < %s", (current,))
            previous = cur.fetchone()[0]

            cur.execute("SELECT payload FROM finding WHERE run_id = %s", (current,))
            after = [r[0] for r in cur.fetchall()]
            if previous is None:
                return RunDiff(previous_run=None, new=after)
            cur.execute("SELECT payload FROM finding WHERE run_id = %s", (previous,))
            before = [r[0] for r in cur.fetchall()]
        return _diff(before, after, previous)


def open_findings_store(dsn: Optional[str] = None) -> FindingsStore:
    """The deployment store, or refuse.

    No silent fallback to memory, for the same reason `core/store.py` refuses
    one: a service that quietly runs in-process while the database is
    unreachable keeps answering, and loses everything at the next restart —
    which is the bug this module exists to fix.
    """
    return PostgresFindingsStore(dsn)


__all__ = ["RunDiff", "FindingsStore", "MemoryFindingsStore",
           "PostgresFindingsStore", "open_findings_store"]
