"""Is THIS version affected? The step that turns a worklist into a verdict.

WHAT THIS CLOSES
----------------
Phase 1 could only ever say "your asset runs a product that appears in the
exploited catalogue" — a worklist — because CISA KEV carries no version data at
all. NVD's CPE would have supplied it, except that CPE is absent from the
majority of 2026 CVEs (measured: 92% of an August window, and `Deferred` records
never receive it).

CNA records in `cvelistV5` carry `affected[].versions[]` regardless of NVD's
state, and they carry EXACT versions rather than a match expression. That is the
input this module evaluates, and a positive result is a `VERSION_RANGE`
determination: two facts published outside this product, compared arithmetically.

THE SHAPES REAL CNAs PUBLISH
----------------------------
Measured over a sample of KEV CVEs, 427 version objects:

    72%   {"version": "2.7.0", "status": "affected"}                 exact
    23%   {"version": "5.3",  "lessThan": "5.3.9", ...}              half-open [a, b)
     5%   {"version": "1.0",  "lessThanOrEqual": "1.5", ...}         closed     [a, b]

with `0` and `*` used as "from the beginning" sentinels, and `versionType`
frequently `custom` rather than `semver` — so a semver parser alone is not
enough and comparison must work on ordinary dotted versions.

FAILING CLOSED IS THE WHOLE POINT
---------------------------------
A version this module cannot parse yields `UNKNOWN`, never `NOT_AFFECTED`. And
if ANY range for a product is unparseable, the verdict for that product is
`UNKNOWN` even when another range matched nothing — because "none of the ranges
I could read matched" is not "not affected".

Saying "affected" wrongly costs somebody an afternoon. Saying "not affected"
wrongly costs them the breach. The two errors are not symmetrical and the code
must not treat them as though they were.
"""
from __future__ import annotations

import enum
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: Values a CNA uses to mean "from the very beginning".
_LOWER_SENTINELS = {"0", "*", "", "-", "unspecified", "all"}

#: A version we can order: dotted numbers, optionally with a trailing numeric
#: build. Anything carrying letters, dates or qualifiers is refused rather than
#: coerced — `1.0.0-beta` versus `1.0.0` is a judgement, not an arithmetic.
_NUMERIC_VERSION = re.compile(r"^\d+(?:\.\d+)*$")


class Verdict(str, enum.Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    #: Could not be established. NEVER conflated with NOT_AFFECTED.
    UNKNOWN = "unknown"


def parse_version(text: Any) -> Optional[Tuple[int, ...]]:
    """`"5.3.9"` -> `(5, 3, 9)`, or None when it cannot be ordered."""
    if text is None:
        return None
    value = str(text).strip().lower().lstrip("v")
    if not value or not _NUMERIC_VERSION.match(value):
        return None
    return tuple(int(part) for part in value.split("."))


def _pad(a: Tuple[int, ...], b: Tuple[int, ...]) -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    """`(2,7)` against `(2,7,0)` must compare equal, not less.

    Zero-padding the shorter side is what makes `2.7` and `2.7.0` the same
    version, which is what every vendor means by them.
    """
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def _lt(a: Tuple[int, ...], b: Tuple[int, ...]) -> bool:
    x, y = _pad(a, b)
    return x < y


def _le(a: Tuple[int, ...], b: Tuple[int, ...]) -> bool:
    x, y = _pad(a, b)
    return x <= y


def _eq(a: Tuple[int, ...], b: Tuple[int, ...]) -> bool:
    x, y = _pad(a, b)
    return x == y


def evaluate_range(asset_version: Tuple[int, ...],
                   entry: Dict[str, Any]) -> Verdict:
    """One `versions[]` object against a parsed asset version."""
    status = str(entry.get("status") or "").strip().lower()
    if status and status != "affected":
        # `unaffected` and `unknown` entries carve exceptions out of a range.
        # They are not evidence of exposure and are not treated as such here.
        return Verdict.NOT_AFFECTED

    raw = str(entry.get("version") or "").strip().lower()
    upper_exclusive = entry.get("lessThan")
    upper_inclusive = entry.get("lessThanOrEqual")

    # ── a bounded range ────────────────────────────────────────────────────
    if upper_exclusive is not None or upper_inclusive is not None:
        lower = None if raw in _LOWER_SENTINELS else parse_version(raw)
        if lower is None and raw not in _LOWER_SENTINELS:
            return Verdict.UNKNOWN
        bound_text = upper_exclusive if upper_exclusive is not None else upper_inclusive
        bound = parse_version(bound_text)
        if bound is None:
            return Verdict.UNKNOWN
        if lower is not None and _lt(asset_version, lower):
            return Verdict.NOT_AFFECTED
        inside = (_lt(asset_version, bound) if upper_exclusive is not None
                  else _le(asset_version, bound))
        return Verdict.AFFECTED if inside else Verdict.NOT_AFFECTED

    # ── an exact version ───────────────────────────────────────────────────
    exact = parse_version(raw)
    if exact is None:
        return Verdict.UNKNOWN
    return Verdict.AFFECTED if _eq(asset_version, exact) else Verdict.NOT_AFFECTED


def evaluate(asset_version: Optional[str],
             versions: Sequence[Dict[str, Any]]) -> Verdict:
    """Every published range for one product, against one asset version.

    An unparseable range anywhere poisons the whole verdict to UNKNOWN, even if
    the ranges that DID parse all missed. "None of the ranges I could read
    matched" is not "not affected", and reporting it as such is the error that
    costs a breach rather than an afternoon.
    """
    parsed = parse_version(asset_version)
    if parsed is None or not versions:
        return Verdict.UNKNOWN

    verdicts = [evaluate_range(parsed, v) for v in versions]
    if Verdict.AFFECTED in verdicts:
        return Verdict.AFFECTED
    if Verdict.UNKNOWN in verdicts:
        return Verdict.UNKNOWN
    return Verdict.NOT_AFFECTED


def affected_products(cna_record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """`[{vendor, product, versions}]` from a cvelistV5 CNA container.

    Only the CNA container is read. ADP containers carry enrichment (SSVC, CWE)
    and are authoritative for that, but the affected-product statement belongs to
    the party that published the vulnerability.
    """
    cna = (cna_record.get("containers") or {}).get("cna") or {}
    out: List[Dict[str, Any]] = []
    for affected in cna.get("affected") or []:
        versions = [v for v in (affected.get("versions") or [])
                    if isinstance(v, dict)]
        if not versions:
            continue
        out.append({
            "vendor": str(affected.get("vendor") or "").strip(),
            "product": str(affected.get("product") or "").strip(),
            # `defaultStatus` decides what an unlisted version means. Carried so
            # the evaluator is not guessing at the CNA's intent.
            "default_status": str(affected.get("defaultStatus") or "").strip(),
            "versions": versions,
        })
    return out
