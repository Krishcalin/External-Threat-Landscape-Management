"""Reading an asset inventory, from whatever the customer already has.

NO CANONICAL SCHEMA, ON PURPOSE
-------------------------------
Every organisation already has an inventory — a CMDB export, a spreadsheet, a
Nessus or Qualys asset list, the output of another scanner. None of them agree on
column names, and a product that demands its own schema first makes the customer
do a data-migration project before they can see a single result. So the column
names are ALIASED rather than mandated, and anything unrecognised is kept in
`attributes` instead of discarded — an unread column is still evidence, and the
CVE matcher reads across all of them.

Two fields are genuinely required and the reason is the same for both: an asset
with no identifier cannot be assigned to anybody, and an asset with no product
cannot be joined to a vulnerability catalogue. A row missing either is reported
rather than silently dropped, because a scan that quietly reads 380 of 400 rows
produces a clean-looking result for the twenty it never saw.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

from core.models import Asset

#: Accepted spellings, in preference order. Lower-cased and stripped of
#: separators before lookup, so `Host Name`, `host_name` and `hostname` are one.
ALIASES: Dict[str, Sequence[str]] = {
    "identifier": ("identifier", "id", "assetid", "host", "hostname", "fqdn",
                   "name", "asset", "ip", "ipaddress", "address", "url"),
    "product": ("product", "software", "application", "app", "service",
                "technology", "component", "productname", "banner"),
    "vendor": ("vendor", "manufacturer", "publisher", "vendorproject",
               "supplier", "maker"),
    "version": ("version", "productversion", "release", "softwareversion",
                "build"),
    "owner": ("owner", "assetowner", "team", "responsible", "custodian",
              "businessowner", "contact"),
    "environment": ("environment", "env", "tier", "stage", "criticality",
                    "classification"),
}

_KEY = str.maketrans("", "", " _-.")


def _normalise(name: str) -> str:
    return str(name or "").strip().lower().translate(_KEY)


def _pick(row: Dict[str, Any], field: str) -> Any:
    lookup = {_normalise(k): v for k, v in row.items()}
    for alias in ALIASES[field]:
        value = lookup.get(_normalise(alias))
        if value not in (None, ""):
            return value
    return None


def from_rows(rows: Sequence[Dict[str, Any]], source: str = "inventory"
              ) -> Tuple[List[Asset], List[Dict[str, Any]]]:
    """`(assets, rejected)`.

    Rejected rows are RETURNED, not logged and forgotten. The caller reports the
    count, because "we read 380 of your 400 rows" is a materially different
    statement from "we read your inventory".
    """
    assets: List[Asset] = []
    rejected: List[Dict[str, Any]] = []
    for row in rows:
        identifier = _pick(row, "identifier")
        product = _pick(row, "product")
        if not identifier or not product:
            rejected.append({
                "row": row,
                "reason": ("no identifier column recognised" if not identifier
                           else "no product column recognised"),
            })
            continue
        consumed = set()
        for field, names in ALIASES.items():
            for key in row:
                if _normalise(key) in {_normalise(n) for n in names}:
                    consumed.add(key)
        assets.append(Asset(
            identifier=str(identifier).strip(),
            product=str(product).strip(),
            vendor=(str(_pick(row, "vendor")).strip()
                    if _pick(row, "vendor") else None),
            version=(str(_pick(row, "version")).strip()
                     if _pick(row, "version") else None),
            owner=(str(_pick(row, "owner")).strip()
                   if _pick(row, "owner") else None),
            environment=(str(_pick(row, "environment")).strip()
                         if _pick(row, "environment") else None),
            source=source,
            # Everything the aliases did not claim. The CVE matcher reads these,
            # so a column nobody thought to map can still carry the answer.
            attributes={k: v for k, v in row.items() if k not in consumed},
        ))
    return assets, rejected


def load(path: Path) -> Tuple[List[Asset], List[Dict[str, Any]]]:
    """Read a `.csv` or `.json` inventory."""
    if not path.exists():
        raise FileNotFoundError(f"no inventory at {path}")
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload if isinstance(payload, list) else payload.get("assets", [])
    else:
        with open(path, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
    return from_rows(rows, source=path.name)
