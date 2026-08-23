"""OSV and EUVD lookups, through the one door that performs I/O.

# NETWORK-BOUNDARY: advisory_lookup

Both are PASSIVE: they query a public vulnerability database and emit nothing
toward the customer's estate. Neither is a discovery source — see
`core/coverage.py` for the measurements that decided that.
"""
from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Sequence

from collect import egress
from collect.report import Outcome, SourceReport
from core import gate
from core.coverage import (Advisory, AdvisorySource, CoordinatesMissing,
                           CoverageResult, PackageRef, package_ref)

OPERATION = "advisory_lookup"

OSV_QUERY = "https://api.osv.dev/v1/query"
EUVD_BY_CVE = "https://euvdservices.enisa.europa.eu/api/enisaid?id={cve}"


def _day(value) -> Optional[date]:
    text = str(value or "").strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text[:19] if "T" in text else text,
                                     fmt).date()
        except ValueError:
            continue
    return None


def osv_for_package(permit, asset: str, ref: PackageRef,
                    budget=None, limiter=None) -> List[Advisory]:
    """Advisories for one package. Raises if the coordinates cannot be queried.

    Raising rather than returning [] is the point. Measured: a bare product
    name returns zero from OSV, so a caller that silently accepted an empty
    result would report a clean estate for every asset it could not actually
    ask about.
    """
    if not ref.queryable:
        raise CoordinatesMissing(
            f"{asset}: OSV needs an ecosystem and an exact package name. "
            f"Got name={ref.name!r} ecosystem={ref.ecosystem!r}. A product name "
            f"is not a package name — measured, it returns nothing — so this "
            f"asset was NOT looked up rather than reported as clean.")

    payload = {"package": {"name": ref.name, "ecosystem": ref.ecosystem}}
    if ref.version:
        payload["version"] = ref.version

    response = egress.http_post_json(permit, OPERATION, OSV_QUERY, payload,
                                     budget=budget, limiter=limiter)
    if response.status != 200:
        raise RuntimeError(f"OSV returned HTTP {response.status}")
    body = json.loads(response.text or "{}")

    out: List[Advisory] = []
    for vuln in body.get("vulns") or []:
        aliases = [a for a in (vuln.get("aliases") or [])
                   if str(a).upper().startswith("CVE-")]
        out.append(Advisory(
            source=AdvisorySource.OSV,
            identifier=str(vuln.get("id") or ""),
            asset=asset,
            summary=str(vuln.get("summary") or "")[:300],
            cve=aliases[0] if aliases else None,
            published=_day(vuln.get("published")),
            # OSV makes no exploitation claim, and none is inferred. A high
            # severity is not evidence that anyone is exploiting anything.
            exploited_per_source=False,
            reference=f"https://osv.dev/vulnerability/{vuln.get('id')}"))
    return out


def euvd_for_cve(permit, cve: str, budget=None, limiter=None
                 ) -> Optional[Dict[str, Any]]:
    """The European catalogue's view of a CVE we already hold.

    ENRICHMENT ONLY. EUVD's text search returns 471 results for "Connect
    Secure" and 517 for "Apache HTTP Server" — full-text matches across
    descriptions — so it is not used to find vulnerabilities, only to add a
    second authority's assessment to one already in hand.
    """
    response = egress.http_get(permit, OPERATION,
                               EUVD_BY_CVE.format(cve=cve),
                               budget=budget, limiter=limiter)
    if response.status != 200:
        return None
    try:
        record = json.loads(response.text or "{}")
    except ValueError:
        return None
    if not record.get("id"):
        return None
    return {
        "euvd_id": record.get("id"),
        "base_score": record.get("baseScore"),
        "base_score_version": record.get("baseScoreVersion"),
        "published": str(_day(record.get("datePublished")) or ""),
        "source": "ENISA EUVD",
    }


def run(assets: Sequence[Any], actor: str, scope,
        budget=None, limiter=None) -> tuple:
    """OSV lookups across an inventory. Returns `(CoverageResult, Coverage)`."""
    from collect.report import Coverage
    from core.scope import ScopeKind

    result = CoverageResult()
    coverage = Coverage()
    looked_up = 0

    for asset in assets:
        identifier = getattr(asset, "identifier", str(asset))
        ref = package_ref(asset)
        if ref is None or not ref.queryable:
            result.without_coordinates.append(identifier)
            continue
        try:
            permit = gate.authorise(identifier, OPERATION, actor, scope,
                                    kind=ScopeKind.DOMAIN)
        except (gate.NotInScope, gate.OperationRefused) as exc:
            result.failures.append((identifier, f"refused: {exc}"))
            continue
        try:
            result.advisories.extend(
                osv_for_package(permit, identifier, ref, budget, limiter))
            looked_up += 1
        except CoordinatesMissing as exc:
            result.without_coordinates.append(identifier)
        except Exception as exc:                   # noqa: BLE001
            result.failures.append((identifier,
                                    (str(exc) or type(exc).__name__)[:80]))

    coverage.add(SourceReport(
        "osv",
        Outcome.OK if looked_up and not result.failures
        else (Outcome.PARTIAL if looked_up else Outcome.DISABLED),
        len(result.advisories), looked_up,
        (f"{len(result.without_coordinates)} asset(s) carry no package "
         f"coordinates and were not looked up")
        if result.without_coordinates else ""))
    return result, coverage


__all__ = ["OPERATION", "osv_for_package", "euvd_for_cve", "run"]
