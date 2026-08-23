"""Persistence for the declared supplier register.

Follows the same protocol-plus-two-implementations shape as the other stores, so
the API can run against memory in a test and PostgreSQL in a deployment without
either knowing which it has.

WHAT IS NOT STORED, AND WHY IT MATTERS THAT THERE IS NOWHERE TO PUT IT. There is
no supplier finding, no supplier CVE, no supplier score. The gate refuses every
active operation against a third party, so this product cannot produce any of
them; a column would be an invitation to fill it with a number nothing here can
compute.
"""
from __future__ import annotations

import json
import os
from datetime import date
from typing import Any, Dict, List, Optional, Protocol, Sequence

from core.store import StoreUnavailable, runtime_or_admin_dsn
from core.suppliers import Posture, Supplier, Tier


class SupplierStore(Protocol):
    def declare(self, supplier: Supplier) -> int: ...

    def suppliers(self) -> List[Supplier]: ...

    def forget(self, domain: str) -> bool: ...

    def record_observations(self, postures: Sequence[Posture]) -> int: ...

    def latest_observations(self) -> Dict[str, Dict[str, Any]]: ...


def _to_supplier(row: Dict[str, Any]) -> Supplier:
    return Supplier(name=row["name"], domain=row["domain"],
                    tier=Tier(row["tier"]), dependency=row.get("dependency") or "",
                    declared_by=row["declared_by"],
                    declared_on=row.get("declared_on"))


class MemorySupplierStore:
    """For tests and for a process with no database."""

    def __init__(self) -> None:
        self._rows: Dict[str, Supplier] = {}
        self._observations: Dict[str, Dict[str, Any]] = {}

    def declare(self, supplier: Supplier) -> int:
        self._rows[supplier.domain] = supplier
        return len(self._rows)

    def suppliers(self) -> List[Supplier]:
        return sorted(self._rows.values(),
                      key=lambda s: (list(Tier).index(s.tier), s.name))

    def forget(self, domain: str) -> bool:
        return self._rows.pop(str(domain).lower(), None) is not None

    def record_observations(self, postures: Sequence[Posture]) -> int:
        for posture in postures:
            self._observations[posture.supplier.domain] = {
                "present": [s.value for s in posture.present],
                "absent": [s.value for s in posture.absent],
                "unobserved": [s.value for s in posture.unobserved],
                "providers": dict(posture.providers),
                "notes": list(posture.notes),
            }
        return len(postures)

    def latest_observations(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._observations)


class PostgresSupplierStore:
    def __init__(self, dsn: Optional[str] = None, migrate: bool = True) -> None:
        self._dsn, is_admin = runtime_or_admin_dsn(dsn)
        if not self._dsn:
            raise StoreUnavailable(
                "neither SKOPOS_DATABASE_URL nor SKOPOS_APP_DATABASE_URL is set")
        try:
            import psycopg  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise StoreUnavailable(f"psycopg is not installed: {exc}") from exc
        # Only the admin identity may migrate. A pod holding just the runtime
        # DSN is a correctly-secured deployment, not a broken one.
        if migrate and is_admin:
            from core import migrate as _migrate
            _migrate.ensure_once(self._dsn)

    def _connect(self):
        """A connection already bound to this request's organisation.

        Binding here rather than in each query is the point: a new method
        written by somebody who has never heard of tenancy is still filtered,
        because the filter lives in the connection.
        """
        import psycopg

        from core import tenancy
        try:
            conn = psycopg.connect(tenancy.runtime_dsn(self._dsn) or self._dsn)
        except Exception as exc:  # pragma: no cover
            raise StoreUnavailable(f"could not reach the database: {exc}") from exc
        try:
            tenancy.apply(conn)
        except Exception as exc:  # pragma: no cover
            conn.close()
            raise StoreUnavailable(
                f"could not bind the connection to an organisation: {exc}") from exc
        return conn

    def declare(self, supplier: Supplier) -> int:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO supplier (name, domain, tier, dependency,"
                " declared_by, declared_on) VALUES (%s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (org_id, domain) DO UPDATE SET"
                "   name = EXCLUDED.name, tier = EXCLUDED.tier,"
                "   dependency = EXCLUDED.dependency,"
                "   declared_by = EXCLUDED.declared_by"
                " RETURNING id",
                (supplier.name, supplier.domain.lower(), supplier.tier.value,
                 supplier.dependency, supplier.declared_by,
                 supplier.declared_on or date.today()))
            return cur.fetchone()[0]

    def suppliers(self) -> List[Supplier]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT name, domain, tier, dependency, declared_by, declared_on"
                " FROM supplier ORDER BY"
                # Critical first, by the tier's own ordering rather than
                # alphabetically — 'critical' < 'important' < 'routine' happens
                # to sort correctly, and relying on that would break the day a
                # tier is renamed.
                "   CASE tier WHEN 'critical' THEN 0 WHEN 'important' THEN 1"
                "             ELSE 2 END, name")
            return [_to_supplier(dict(zip(
                ("name", "domain", "tier", "dependency", "declared_by",
                 "declared_on"), row))) for row in cur.fetchall()]

    def forget(self, domain: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM supplier WHERE domain = %s",
                        (str(domain).lower(),))
            return cur.rowcount > 0

    def record_observations(self, postures: Sequence[Posture]) -> int:
        written = 0
        with self._connect() as conn, conn.cursor() as cur:
            for posture in postures:
                cur.execute("SELECT id FROM supplier WHERE domain = %s",
                            (posture.supplier.domain.lower(),))
                row = cur.fetchone()
                if row is None:
                    # A posture for a supplier nobody declared. Skipped rather
                    # than inserted: the register is the declaration, and
                    # writing an observation would create a supplier by side
                    # effect.
                    continue
                cur.execute(
                    "INSERT INTO supplier_observation"
                    " (supplier_id, present, absent, unobserved, providers, notes)"
                    " VALUES (%s, %s, %s, %s, %s, %s)",
                    (row[0],
                     json.dumps([s.value for s in posture.present]),
                     json.dumps([s.value for s in posture.absent]),
                     json.dumps([s.value for s in posture.unobserved]),
                     json.dumps(dict(posture.providers)),
                     json.dumps(list(posture.notes))))
                written += 1
        return written

    def latest_observations(self) -> Dict[str, Dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT ON (s.domain) s.domain, o.present, o.absent,"
                "       o.unobserved, o.providers, o.notes, o.observed_at"
                " FROM supplier s JOIN supplier_observation o"
                "   ON o.supplier_id = s.id"
                " ORDER BY s.domain, o.observed_at DESC")
            return {
                row[0]: {"present": row[1], "absent": row[2],
                         "unobserved": row[3], "providers": row[4],
                         "notes": row[5], "observed_at": str(row[6])}
                for row in cur.fetchall()
            }


def open_supplier_store(dsn: Optional[str] = None) -> SupplierStore:
    """The deployment store, or memory when there is no database configured."""
    try:
        return PostgresSupplierStore(dsn)
    except StoreUnavailable:
        return MemorySupplierStore()


__all__ = ["SupplierStore", "MemorySupplierStore", "PostgresSupplierStore",
           "open_supplier_store"]
