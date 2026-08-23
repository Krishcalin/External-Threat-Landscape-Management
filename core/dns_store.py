"""Persistence for DNS observations and takeover findings.

Same shape as `core/store.py`: a protocol, an in-memory implementation so the
diff logic stays cheap to test, and a Postgres one for the deployment.

ONLY CONCLUSIVE OBSERVATIONS ARE WRITTEN. That rule lives here as well as in the
schema's CHECK constraint, because it is the one that decides whether a resolver
outage reads as the customer's DNS being deleted overnight.
"""
from __future__ import annotations

import json
import os
from datetime import date
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

from core.dns_state import Observation
from core.store import StoreUnavailable


class DnsStore(Protocol):
    def start_run(self, actor: str, resolvers: Sequence[str]) -> int: ...

    def finish_run(self, run_id: int, sweep) -> None: ...

    def latest_observations(self) -> Dict[Tuple[str, str], Observation]: ...

    def record_observations(self, run_id: int,
                            observations: Sequence[Observation],
                            agreeing: int = 2) -> None: ...

    def record_findings(self, run_id: int, findings: Sequence) -> None: ...

    def findings(self, limit: int = 100) -> List[Dict[str, Any]]: ...

    def runs(self, limit: int = 20) -> List[Dict[str, Any]]: ...


class MemoryDnsStore:
    def __init__(self) -> None:
        self._runs: List[Dict[str, Any]] = []
        self._observations: Dict[Tuple[str, str], Observation] = {}
        self._findings: List[Dict[str, Any]] = []

    def start_run(self, actor: str, resolvers: Sequence[str]) -> int:
        self._runs.append({"id": len(self._runs) + 1, "actor": actor,
                           "resolvers": list(resolvers)})
        return len(self._runs)

    def finish_run(self, run_id: int, sweep) -> None:
        self._runs[run_id - 1].update({
            "attempted": sweep.attempted, "observed": sweep.observed,
            "quorum_failed": sweep.quorum_failed,
            "unobserved": sweep.unobserved,
            "refused": len(sweep.refusals), "degraded": sweep.degraded})

    def latest_observations(self) -> Dict[Tuple[str, str], Observation]:
        return dict(self._observations)

    def record_observations(self, run_id: int,
                            observations: Sequence[Observation],
                            agreeing: int = 2) -> None:
        for observation in observations:
            self._observations[(observation.name, observation.rrtype)] = observation

    def record_findings(self, run_id: int, findings: Sequence) -> None:
        for finding in findings:
            self._findings.append(_finding_row(run_id, finding))

    def findings(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._findings[:limit]

    def runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(self._runs))[:limit]


def _finding_row(run_id: int, finding) -> Dict[str, Any]:
    evidence = finding.evidence
    return {
        "run_id": run_id,
        "name": evidence.name,
        "verdict": finding.verdict.value,
        "corroboration": finding.corroboration.value,
        "target": evidence.target,
        "target_rcode": evidence.target_rcode,
        "resolvers_agreeing": evidence.resolvers_agreeing,
        "reasons": list(finding.reasons),
        "evidence": {
            "resolvers_queried": evidence.resolvers_queried,
            "provider": evidence.provider,
            "registrable_domain": evidence.registrable_domain,
            "registration_status": evidence.registration_status.value,
            "rdap_response": evidence.rdap_response,
            "rule_catalogue_version": evidence.rule_catalogue_version,
            "rule_last_reviewed": evidence.rule_last_reviewed,
        },
        "observed_at": str(evidence.observed_at or date.today()),
    }


class PostgresDnsStore:
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

    def start_run(self, actor: str, resolvers: Sequence[str]) -> int:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO dns_run (actor, resolvers) VALUES (%s, %s) "
                        "RETURNING id", (actor, list(resolvers)))
            return cur.fetchone()[0]

    def finish_run(self, run_id: int, sweep) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE dns_run SET attempted=%s, observed=%s, quorum_failed=%s,"
                " unobserved=%s, refused=%s, degraded=%s WHERE id=%s",
                (sweep.attempted, sweep.observed, sweep.quorum_failed,
                 sweep.unobserved, len(sweep.refusals), sweep.degraded, run_id))

    def latest_observations(self) -> Dict[Tuple[str, str], Observation]:
        """The newest conclusive observation per (name, rrtype).

        DISTINCT ON, not a self-join on max(observed_at): two runs on the same
        day would otherwise both qualify and the result would be arbitrary.
        """
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT ON (name, rrtype) name, rrtype, rcode, digest,"
                " values, observed_at FROM dns_observation"
                " ORDER BY name, rrtype, observed_at DESC, id DESC")
            return {(r[0], r[1]): Observation(name=r[0], rrtype=r[1], rcode=r[2],
                                              digest=r[3], values=tuple(r[4] or ()),
                                              observed_at=r[5])
                    for r in cur.fetchall()}

    def record_observations(self, run_id: int,
                            observations: Sequence[Observation],
                            agreeing: int = 2) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            for observation in observations:
                if observation.rcode not in ("NOERROR", "NXDOMAIN"):
                    # Belt and braces with the schema's CHECK. A non-conclusive
                    # observation reaching storage is the bug that makes an
                    # outage look like a deletion.
                    continue
                cur.execute(
                    "INSERT INTO dns_observation (run_id, name, rrtype, rcode,"
                    " digest, values, observed_at, resolvers_agreeing)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                    (run_id, observation.name, observation.rrtype,
                     observation.rcode, observation.digest,
                     list(observation.values),
                     observation.observed_at or date.today(), agreeing))

    def record_findings(self, run_id: int, findings: Sequence) -> None:
        import psycopg
        with self._connect() as conn, conn.cursor() as cur:
            for finding in findings:
                row = _finding_row(run_id, finding)
                cur.execute(
                    "INSERT INTO takeover_finding (run_id, name, verdict,"
                    " corroboration, target, target_rcode, resolvers_agreeing,"
                    " reasons, evidence, first_seen, last_seen)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                    " ON CONFLICT (name, target, verdict) DO UPDATE"
                    " SET last_seen = EXCLUDED.last_seen,"
                    "     evidence  = EXCLUDED.evidence",
                    (run_id, row["name"], row["verdict"], row["corroboration"],
                     row["target"], row["target_rcode"],
                     row["resolvers_agreeing"], row["reasons"],
                     psycopg.types.json.Jsonb(row["evidence"]),
                     row["observed_at"], row["observed_at"]))

    def findings(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT name, verdict, corroboration, target, target_rcode,"
                " resolvers_agreeing, reasons, evidence, first_seen, last_seen"
                " FROM takeover_finding ORDER BY"
                # The headline verdict first: an unregistered registrable domain
                # is takeable by anyone for the price of a registration.
                "   CASE verdict WHEN 'registrable_domain_unregistered' THEN 0"
                "                WHEN 'inconclusive' THEN 1 ELSE 2 END,"
                "   last_seen DESC LIMIT %s", (limit,))
            return [{"name": r[0], "verdict": r[1], "corroboration": r[2],
                     "target": r[3], "target_rcode": r[4],
                     "resolvers_agreeing": r[5], "reasons": list(r[6] or ()),
                     "evidence": r[7], "first_seen": str(r[8]),
                     "last_seen": str(r[9])} for r in cur.fetchall()]

    def runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, started_at, actor, resolvers, attempted, observed,"
                " quorum_failed, unobserved, refused, degraded FROM dns_run"
                " ORDER BY id DESC LIMIT %s", (limit,))
            return [{"id": r[0], "started_at": str(r[1]), "actor": r[2],
                     "resolvers": list(r[3] or ()), "attempted": r[4],
                     "observed": r[5], "quorum_failed": r[6],
                     "unobserved": r[7], "refused": r[8], "degraded": r[9]}
                    for r in cur.fetchall()]


def open_dns_store(dsn: Optional[str] = None) -> DnsStore:
    return PostgresDnsStore(dsn)


__all__ = ["DnsStore", "MemoryDnsStore", "PostgresDnsStore", "open_dns_store"]
