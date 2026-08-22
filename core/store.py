"""Persistence for scope, ownership and the audit log.

Two implementations behind one protocol:

  * `PostgresStore` — what the deployment runs, against `skopos-db-1`.
  * `MemoryStore`   — what the tests run, so the rules in `core/gate.py`,
    `core/scope.py` and `core/audit.py` can be exercised without a database.

The second one exists to keep the tests honest, not to keep them convenient.
Domain rules that can only be tested with a live Postgres get tested rarely; the
tests that matter most here are about refusal, and refusal has to be cheap to
assert or it will not be asserted enough. The database-side controls
(append-only rules, CHECK constraints) are covered separately by a live
integration test, because those are precisely the things a fake cannot prove.

WHAT THE STORE DELIBERATELY DOES NOT DO
---------------------------------------
It does not decide anything. `record_verification` will happily store a
verification the gate would reject, and `append_audit` will store a record of a
refusal as readily as one of a success. Putting policy in the store would give
the product two places where authorisation is decided, and the second one always
drifts.
"""
from __future__ import annotations

import os
from datetime import date
from typing import Any, Dict, List, Optional, Protocol, Sequence

from core.audit import GENESIS, AuditChain, AuditRecord
from core.ownership import Method, Verification
from core.scope import Scope, ScopeKind, ScopeRule


class StoreUnavailable(RuntimeError):
    """The datastore could not be reached or is not initialised."""


class Store(Protocol):
    """What the service layer needs. Nothing more, so both backends stay small."""

    def load_scope(self) -> Scope: ...

    def add_scope_rule(self, rule: ScopeRule, actor: str) -> None: ...

    def live_verification(self, asset: str,
                          today: Optional[date] = None) -> Optional[Verification]: ...

    def record_verification(self, verification: Verification) -> None: ...

    def append_audit(self, actor: str, action: str,
                     payload: Optional[Dict[str, Any]] = None) -> AuditRecord: ...

    def audit_records(self) -> Sequence[AuditRecord]: ...

    def verify_audit(self, expected_seq: Optional[int] = None): ...


# ---------------------------------------------------------------------------
# In-memory
# ---------------------------------------------------------------------------
class MemoryStore:
    """Everything the protocol asks for, held in process."""

    def __init__(self) -> None:
        self._rules: List[ScopeRule] = []
        self._verifications: List[Verification] = []
        self._chain = AuditChain()

    def load_scope(self) -> Scope:
        return Scope(self._rules)

    def add_scope_rule(self, rule: ScopeRule, actor: str) -> None:
        if rule not in self._rules:
            self._rules.append(rule)

    def record_verification(self, verification: Verification) -> None:
        self._verifications.append(verification)

    def live_verification(self, asset: str,
                          today: Optional[date] = None) -> Optional[Verification]:
        """The newest verification for this asset that has not expired.

        Newest rather than any: re-proving ownership should extend the window,
        and returning an older row would let a stale record shorten it.
        """
        wanted = str(asset).strip().lower()
        live = [v for v in self._verifications
                if v.asset.strip().lower() == wanted and v.is_current(today)]
        if not live:
            return None
        return max(live, key=lambda v: (v.expires_at or date.min))

    def append_audit(self, actor: str, action: str,
                     payload: Optional[Dict[str, Any]] = None) -> AuditRecord:
        return self._chain.append(actor, action, payload)

    def audit_records(self) -> Sequence[AuditRecord]:
        return self._chain.records

    def verify_audit(self, expected_seq: Optional[int] = None):
        return self._chain.verify(expected_seq)


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------
class PostgresStore:
    """The deployment backend. Requires `psycopg` and a reachable database."""

    def __init__(self, dsn: Optional[str] = None, migrate: bool = True) -> None:
        self._dsn = dsn or os.environ.get("SKOPOS_DATABASE_URL")
        if not self._dsn:
            raise StoreUnavailable(
                "SKOPOS_DATABASE_URL is not set. The compose stack sets it for "
                "skopos-app-1; for a local process, point it at "
                "postgresql://skopos:<password>@127.0.0.1:55443/skopos")
        try:
            import psycopg  # noqa: F401
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise StoreUnavailable(f"psycopg is not installed: {exc}") from exc

        if migrate:
            # Refuse to serve against a schema behind the code. A missing CHECK
            # constraint does not announce itself — it simply stops rejecting
            # the rows it exists to reject, and the first sign is a bad finding.
            from core import migrate as _migrate
            try:
                _migrate.ensure_current(self._dsn)
            except _migrate.MigrationError as exc:
                raise StoreUnavailable(str(exc)) from exc

    def _connect(self):
        import psycopg
        try:
            return psycopg.connect(self._dsn)
        except Exception as exc:  # pragma: no cover - environment-dependent
            raise StoreUnavailable(f"could not reach the database: {exc}") from exc

    # -- scope --------------------------------------------------------------
    def load_scope(self) -> Scope:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT kind, value, is_exclude, note FROM scope_rule")
            return Scope([
                ScopeRule(kind=ScopeKind(kind), value=value,
                          is_exclude=is_exclude, note=note or "")
                for kind, value, is_exclude, note in cur.fetchall()
            ])

    def add_scope_rule(self, rule: ScopeRule, actor: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scope_rule (kind, value, is_exclude, note, created_by) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (kind, value, is_exclude) DO NOTHING",
                (rule.kind.value, rule.canonical, rule.is_exclude,
                 rule.note, actor))

    # -- ownership ----------------------------------------------------------
    def record_verification(self, verification: Verification) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO ownership_verification "
                "(asset, method, verified_at, expires_at, approved_by, evidence) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (verification.asset, verification.method.value,
                 verification.verified_at, verification.expires_at,
                 verification.approved_by, verification.evidence))

    def live_verification(self, asset: str,
                          today: Optional[date] = None) -> Optional[Verification]:
        day = today or date.today()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT asset, method, verified_at, expires_at, approved_by, evidence "
                "FROM ownership_verification "
                "WHERE lower(asset) = lower(%s) AND revoked_at IS NULL "
                "  AND expires_at >= %s "
                "ORDER BY expires_at DESC LIMIT 1",
                (str(asset).strip(), day))
            row = cur.fetchone()
        if row is None:
            return None
        return Verification(asset=row[0], method=Method(row[1]),
                            verified_at=row[2], expires_at=row[3],
                            approved_by=row[4], evidence=row[5] or "")

    # -- audit --------------------------------------------------------------
    def append_audit(self, actor: str, action: str,
                     payload: Optional[Dict[str, Any]] = None) -> AuditRecord:
        """Append one record, chained to whatever is currently the head.

        The read of the head and the insert share a transaction and take an
        explicit lock. Without it, two concurrent appends both read the same
        head, both compute seq N+1, and one loses on the primary key — or worse,
        with a different key, both land and the chain forks. A forked audit log
        is not an audit log.
        """
        import psycopg
        chain = AuditChain()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("LOCK TABLE audit_log IN EXCLUSIVE MODE")
                cur.execute("SELECT seq, at, actor, action, payload, prev_hash, "
                            "record_hash FROM audit_log "
                            "ORDER BY seq DESC LIMIT 1")
                head = cur.fetchone()
                if head is not None:
                    chain = AuditChain([AuditRecord(
                        seq=head[0], at=head[1], actor=head[2], action=head[3],
                        payload=head[4] or {}, prev_hash=head[5],
                        record_hash=head[6])])
                record = chain.append(actor, action, payload)
                cur.execute(
                    "INSERT INTO audit_log (seq, at, actor, action, payload, "
                    "prev_hash, record_hash) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (record.seq, record.at, record.actor, record.action,
                     psycopg.types.json.Jsonb(record.payload),
                     record.prev_hash, record.record_hash))
        return record

    def audit_records(self) -> Sequence[AuditRecord]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT seq, at, actor, action, payload, prev_hash, "
                        "record_hash FROM audit_log ORDER BY seq")
            return tuple(AuditRecord(seq=r[0], at=r[1], actor=r[2], action=r[3],
                                     payload=r[4] or {}, prev_hash=r[5],
                                     record_hash=r[6])
                         for r in cur.fetchall())

    def verify_audit(self, expected_seq: Optional[int] = None):
        return AuditChain(self.audit_records()).verify(expected_seq)


def open_store(dsn: Optional[str] = None) -> Store:
    """The deployment store if a DSN is configured, else refuse.

    Deliberately does NOT silently fall back to MemoryStore. A service that
    quietly runs on an in-process store when the database is unreachable keeps
    answering requests while writing the audit log to somewhere that disappears
    at the next restart — which is the one failure an audit log must not have.
    """
    return PostgresStore(dsn)


__all__ = ["Store", "MemoryStore", "PostgresStore", "StoreUnavailable",
           "open_store", "GENESIS"]
