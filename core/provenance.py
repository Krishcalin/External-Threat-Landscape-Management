"""Who wrote this string — the customer, or something we read off the internet.

The distinction has teeth because `core/match.py:declared_cves()` treats a CVE
named on an asset row as the CUSTOMER'S OWN STATEMENT and promotes it above name
matching, with `Confidence.STRONG` and the evidence line "the inventory names
CVE-… on this asset".

That is correct for a CMDB column. It is dangerous for a string a collector
copied out of somebody else's HTTP response. Measured, before this module
existed:

    Asset(identifier="h", product="unknown",
          attributes={"fp_evidence": "Server: EvilWAF blocks cve-2021-44228"})

produced exactly one exposure, at STRONG confidence, claiming the inventory
named Log4Shell on that host. Nobody's inventory said any such thing — a target
did, in a header it controls entirely. P1 multiplies the third-party text
reaching that bucket by roughly eight sources, which is what turns a latent
defect into a live one.

TWO LAYERS, BECAUSE ONE IS NOT ENOUGH
-------------------------------------
1. PROVENANCE (structural). Every column any collector writes is prefixed, and
   `declared_cves()` skips prefixed keys. This does not depend on recognising
   anything — a CVE we never thought to pattern-match still cannot be promoted,
   because the promotion is keyed on who wrote the column, not on what it says.

2. REDACTION (defence in depth). Before rows are written, cells are checked for
   CVE identifiers. This catches the case where a collector writes into an
   UNPREFIXED column by mistake — a bug layer 1 cannot see.

The redactor imports the pattern from `core.match` rather than restating it. A
private copy is how the original bug survived review: the matcher's pattern is
case-insensitive, so a redactor written with a case-sensitive one passes its own
tests and misses `cve-2021-44228` in the wild.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, Mapping

from core.match import CVE_PATTERN

#: Prefix for every column a SKOPOS collector authors. Short, greppable, and
#: unlikely to collide with a real CMDB column name.
TOOL_PREFIX = "obs_"

#: Columns `core/inventory.py` understands. A collector legitimately writes these
#: — they are the asset's identity, not commentary about it — so they are not
#: prefixed and are not treated as customer assertions either way.
INVENTORY_FIELDS = frozenset({
    "identifier", "product", "vendor", "version", "owner", "environment",
})


class ProvenanceViolation(ValueError):
    """A cell that would have been attributed to the customer wrongly."""


def tool_authored(key: str) -> bool:
    """Did SKOPOS write this column, rather than the customer?"""
    return str(key or "").strip().lower().startswith(TOOL_PREFIX)


def observed(name: str) -> str:
    """The column name a collector must use. Idempotent."""
    clean = str(name or "").strip().lower()
    if not clean:
        raise ValueError("an observation column needs a name")
    return clean if clean.startswith(TOOL_PREFIX) else f"{TOOL_PREFIX}{clean}"


def redact(text: Any) -> str:
    """Neutralise CVE identifiers in third-party text.

    Replaced with a marker rather than deleted. An operator reading the evidence
    should be able to see that the target said something about a CVE — that is
    genuinely informative — without the product treating it as the customer's
    own assertion. Deleting it silently would lose a real signal; promoting it
    would be the bug.
    """
    return CVE_PATTERN.sub("[cve-reference-from-third-party]", str(text or ""))


def check_row(row: Mapping[str, Any]) -> None:
    """Raise if a cell would be misattributed. Called before any row is written.

    Deliberately raises rather than silently redacting. A collector writing
    target-controlled text into an unprefixed column is a BUG in that collector,
    and quietly cleaning up after it means the bug ships and the next one is
    written the same way.
    """
    for key, value in row.items():
        if tool_authored(key):
            continue
        if str(key).strip().lower() in INVENTORY_FIELDS:
            # Identity fields still must not smuggle a CVE reference: a SaaS
            # tenant can register cve-2021-44228.example.com, and it would land
            # in `identifier` legitimately.
            if CVE_PATTERN.search(str(value or "")):
                raise ProvenanceViolation(
                    f"column {key!r} contains a CVE identifier "
                    f"({str(value)[:60]!r}). An identity field carrying a CVE "
                    f"reference would be read as the customer asserting it.")
            continue
        if CVE_PATTERN.search(str(value or "")):
            raise ProvenanceViolation(
                f"column {key!r} is not prefixed {TOOL_PREFIX!r} and contains a "
                f"CVE identifier. Anything a collector writes must use "
                f"provenance.observed({key!r}), or it will be promoted to a "
                f"customer assertion at STRONG confidence.")


def write_rows(rows: Iterable[Mapping[str, Any]]) -> list:
    """Validate a batch and return it, so there is one place rows pass through."""
    checked = []
    for row in rows:
        check_row(row)
        checked.append(dict(row))
    return checked


def observation(**fields: Any) -> Dict[str, Any]:
    """Build a correctly-prefixed, redacted observation payload."""
    return {observed(k): redact(v) for k, v in fields.items()}


__all__ = ["TOOL_PREFIX", "INVENTORY_FIELDS", "ProvenanceViolation",
           "tool_authored", "observed", "redact", "check_row", "write_rows",
           "observation"]
