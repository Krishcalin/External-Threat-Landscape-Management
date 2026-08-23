"""Every forecast, with the inputs that produced it, so it can be scored later.

WHY THIS SHIPS BEFORE THE FEATURES
----------------------------------
A Brier score needs RESOLVED forecasts. Resolution takes calendar time — a CVE
is added to KEV, an EPSS score crosses a threshold, an incident is published —
and **history cannot be backfilled**. Every other capability in this phase costs
the same whenever it is built. This one gets strictly more expensive every week
it is not, and a record started late cannot produce a measured accuracy claim
until long after.

So it ships first, despite producing nothing a user can see.

THE INPUT VECTOR, NOT THE SCORE
-------------------------------
A score is a conclusion. The inputs are what makes it checkable, and they are
what a later model version must be re-run against to demonstrate it improved on
anything. Storing only `teps=78` would leave a future model with nothing to
compare itself to except its own output.

`model_version` is pinned on every row for the same reason. Scoring a v1
forecast with a v2 model and publishing the result as v2's accuracy is the most
obvious way to manufacture an improvement, and a schema that allows it invites
it.

WRITE EVEN WHEN THE MODEL IS CRUDE
----------------------------------
A record of a bad model is evidence. No record is nothing. The first published
Brier score will be poor — publishing a poor number is the entire wedge, because
the alternative on offer in this market is an evidence page that has not been
updated since 2021.
"""
from __future__ import annotations

import enum
import os
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

from core.store import StoreUnavailable


class Outcome(str, enum.Enum):
    #: The CVE was subsequently added to CISA KEV. The SRS target is stated
    #: against this: a median of seven days' lead time or better.
    KEV_ADDED = "kev_added"
    #: EPSS crossed the threshold this forecast implied.
    EPSS_CROSSED = "epss_crossed"
    #: The observation window closed with neither. A correct low forecast
    #: resolves here, so this is a SUCCESS for a low-band prediction and a miss
    #: for a high one — which is exactly what a Brier score is for.
    NO_EVENT = "no_event"
    #: Still inside the window. Never scored; counted separately so a small
    #: resolved set cannot masquerade as a complete one.
    UNRESOLVED = "unresolved"


#: How long a forecast waits before `NO_EVENT` is a fair verdict. Ninety days is
#: chosen to exceed the observed KEV-addition lag for most entries; it is stated
#: here rather than buried so a future change to it is visible as a change to
#: what the accuracy figure means.
OBSERVATION_WINDOW_DAYS = 90


def input_vector(finding) -> Dict[str, Any]:
    """Everything that produced this score, at the moment it was produced.

    Deliberately flat and JSON-native: a future scorer reads this without
    importing anything from this codebase, which is what makes an independent
    check possible.
    """
    score = finding.score
    entry = finding.exploited
    return {
        "exposure": round(score.exposure, 6),
        "exploitability": round(score.exploitability, 6),
        "adversary_interest": round(score.adversary, 6),
        "business_criticality": round(score.business, 6),
        "mitigation": round(score.mitigation, 6),
        "flags": list(score.flags),
        # The catalogue-side facts, so a re-run does not have to reconstruct
        # what the corpus said on the day.
        "epss": entry.epss,
        "epss_percentile": entry.epss_percentile,
        "known_ransomware": bool(entry.known_ransomware),
        "due_date": str(entry.due_date) if entry.due_date else None,
        "basis": finding.basis.value,
        "name_confidence": finding.confidence.value,
        "match_confidence": finding.match_confidence,
        "reconciliation": (finding.reconciliation.value
                           if finding.reconciliation else None),
    }


@dataclass
class Forecast:
    asset: str
    cve: str
    model_version: str
    inputs: Dict[str, Any]
    teps: float
    band: str
    issued_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    outcome: Optional[Outcome] = None
    resolution_source: str = ""

    @property
    def resolved(self) -> bool:
        return self.outcome is not None and self.outcome is not Outcome.UNRESOLVED


def from_finding(finding, model_version: Optional[str] = None) -> Forecast:
    return Forecast(
        asset=finding.asset.identifier,
        cve=finding.exploited.cve,
        model_version=model_version or finding.score.model_version,
        inputs=input_vector(finding),
        teps=float(finding.score.teps),
        band=finding.score.band,
    )


# ---------------------------------------------------------------------------
# Scoring the record
# ---------------------------------------------------------------------------
#: What each band asserts as a probability of exploitation inside the window.
#: Crude, expert-set, and DELIBERATELY SO — the point of the record is that this
#: mapping becomes measurable and therefore improvable. A model that was never
#: written down cannot be shown to be wrong.
BAND_PROBABILITY: Dict[str, float] = {
    "critical": 0.80,
    "high": 0.60,
    "medium": 0.35,
    "low": 0.15,
    "informational": 0.05,
}


def brier_score(forecasts: Sequence[Forecast]) -> Optional[float]:
    """Mean squared error between predicted probability and observed outcome.

    Lower is better; 0.25 is what you get by always saying 50%. Returns None
    rather than 0.0 for an empty set — a perfect score on no data is the most
    misleading number this module could produce.
    """
    resolved = [f for f in forecasts if f.resolved]
    if not resolved:
        return None
    total = 0.0
    for forecast in resolved:
        predicted = BAND_PROBABILITY.get(forecast.band, 0.5)
        observed = 0.0 if forecast.outcome is Outcome.NO_EVENT else 1.0
        total += (predicted - observed) ** 2
    return round(total / len(resolved), 4)


def lead_times(forecasts: Sequence[Forecast]) -> List[int]:
    """Days between issuing a forecast and the event that resolved it.

    The SRS target: for CVEs later added to KEV, the corresponding finding
    should have been raised at High or above a median of at least seven days
    before the KEV addition date.
    """
    out: List[int] = []
    for forecast in forecasts:
        if (forecast.outcome is Outcome.KEV_ADDED
                and forecast.issued_at and forecast.resolved_at):
            out.append((forecast.resolved_at.date() - forecast.issued_at.date()).days)
    return sorted(out)


def median(values: Sequence[int]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2


@dataclass
class Accuracy:
    """What the record says about this product, published as-is."""

    model_version: str
    issued: int
    resolved: int
    brier: Optional[float]
    median_lead_days: Optional[float]
    lead_distribution: List[int] = field(default_factory=list)
    outcomes: Dict[str, int] = field(default_factory=dict)

    def headline(self) -> str:
        if not self.resolved:
            return (f"{self.issued} forecast(s) on record for "
                    f"{self.model_version}, none resolved yet. No accuracy can "
                    f"be claimed until they are — and none is.")
        line = (f"{self.model_version}: {self.resolved} of {self.issued} "
                f"forecast(s) resolved. Brier {self.brier}")
        if self.median_lead_days is not None:
            line += (f", median lead {self.median_lead_days:.0f} day(s) "
                     f"before KEV addition")
            if self.median_lead_days < 7:
                # The SRS target, and it is reported as missed rather than
                # quietly omitted. A predictive product that never measures its
                # predictions is marketing.
                line += " — BELOW the 7-day target"
        return line + "."


def score_record(forecasts: Sequence[Forecast],
                 model_version: str) -> Accuracy:
    subset = [f for f in forecasts if f.model_version == model_version]
    resolved = [f for f in subset if f.resolved]
    leads = lead_times(subset)
    outcomes: Dict[str, int] = {}
    for forecast in subset:
        key = forecast.outcome.value if forecast.outcome else "unresolved"
        outcomes[key] = outcomes.get(key, 0) + 1
    return Accuracy(model_version=model_version, issued=len(subset),
                    resolved=len(resolved), brier=brier_score(subset),
                    median_lead_days=median(leads), lead_distribution=leads,
                    outcomes=outcomes)


__all__ = ["Outcome", "OBSERVATION_WINDOW_DAYS", "Forecast", "Accuracy",
           "input_vector", "from_finding", "brier_score", "lead_times",
           "median", "score_record", "BAND_PROBABILITY"]
