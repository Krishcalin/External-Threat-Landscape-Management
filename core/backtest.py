"""Scoring this product's own predictions, including where it cannot.

A BRIER SCORE ALONE MEANS NOTHING
---------------------------------
0.18 is not good or bad until you know what it is being compared against.
Always predicting the base rate scores well on a rare event without containing
any information at all, and a product quoting a bare number is relying on the
reader not knowing that. So every figure here ships with two references:

    uninformative   always predicting 0.5      -> Brier 0.25
    climatology     always predicting the observed base rate

and a SKILL SCORE against climatology, which is the one that answers "does this
model know anything the base rate does not". Positive is informative. Zero or
negative means the model is not beating a constant, and that is reported rather
than buried.

THE SRS LEAD-TIME TARGET IS NOT MEASURABLE ON A KEV-ONLY CORPUS
---------------------------------------------------------------
The specification asks that, for CVEs subsequently added to KEV, SKOPOS should
have raised the finding at High or above a median of at least seven days before
the KEV addition date.

It cannot be measured here, and the reason is structural rather than a gap in
the implementation. SKOPOS only learns of a CVE when CISA lists it — the corpus
IS the KEV catalogue — so every forecast is issued AFTER the event it would be
scored against. Measured over the record: median lead −1258 days, range −1754 to
−2, every single value negative.

What would make it measurable is a forecast issued about a CVE that is NOT yet
in KEV, which means the advisory path (OSV/EUVD) feeding the forecast record.
Until then the metric is reported as UNMEASURABLE with that explanation, never
as a number, and never omitted — an absent metric reads as an oversight, and a
computed one would be a lie about a negative distribution.

CALIBRATION IS THE MORE USEFUL FIGURE ANYWAY
--------------------------------------------
"When this product says critical, how often is it right?" is answerable from the
record as it stands, and it is what a reader actually wants. It is reported per
band with the count behind each, because a 100% hit rate over two forecasts is
not a hit rate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from core.forecast import (BAND_PROBABILITY, OBSERVATION_WINDOW_DAYS, Forecast,
                           Outcome)

#: Below this many resolved forecasts, no figure is published. A Brier score
#: over a handful of outcomes is noise wearing the costume of a measurement, and
#: publishing it early would spend the credibility the whole exercise is for.
MIN_RESOLVED_TO_PUBLISH = 30

#: Always-0.5 predictions. The classic reference point.
UNINFORMATIVE_BRIER = 0.25


def observed(forecast: Forecast) -> Optional[float]:
    """1.0 if the predicted event happened, 0.0 if it did not, None if open."""
    if forecast.outcome is None or forecast.outcome is Outcome.UNRESOLVED:
        return None
    return 0.0 if forecast.outcome is Outcome.NO_EVENT else 1.0


def predicted(forecast: Forecast) -> float:
    return BAND_PROBABILITY.get(forecast.band, 0.5)


def brier(pairs: Sequence[Tuple[float, float]]) -> Optional[float]:
    if not pairs:
        return None
    return round(sum((p - o) ** 2 for p, o in pairs) / len(pairs), 4)


@dataclass
class BandCalibration:
    band: str
    claimed: float
    resolved: int
    happened: int

    @property
    def actual(self) -> Optional[float]:
        return round(self.happened / self.resolved, 4) if self.resolved else None

    @property
    def trustworthy(self) -> bool:
        """A hit rate over a handful of outcomes is not a hit rate."""
        return self.resolved >= 10

    def explain(self) -> str:
        if not self.resolved:
            return f"{self.band}: nothing resolved yet"
        line = (f"{self.band}: claimed {self.claimed:.0%}, observed "
                f"{self.actual:.0%} over {self.resolved} resolved")
        if not self.trustworthy:
            line += " — too few to read anything into"
        return line


@dataclass
class Scoreboard:
    """What the record says about this product. Published as-is."""

    model_version: str
    issued: int
    resolved: int
    brier: Optional[float] = None
    climatology_brier: Optional[float] = None
    base_rate: Optional[float] = None
    skill: Optional[float] = None
    calibration: List[BandCalibration] = field(default_factory=list)
    outcomes: Dict[str, int] = field(default_factory=dict)
    #: Always present, always the same value on a KEV-only corpus. See the
    #: module docstring.
    lead_time: str = ""
    publishable: bool = False

    def headline(self) -> str:
        if not self.resolved:
            return (f"{self.issued} forecast(s) on record for "
                    f"{self.model_version}. NONE resolved yet, so no accuracy "
                    f"figure exists — and none is shown. Resolution takes "
                    f"calendar time; the record started when it started.")
        if not self.publishable:
            return (f"{self.resolved} of {self.issued} forecast(s) resolved. "
                    f"Below {MIN_RESOLVED_TO_PUBLISH}, no score is published: a "
                    f"Brier over a handful of outcomes is noise wearing the "
                    f"costume of a measurement.")

        line = (f"{self.model_version}: Brier {self.brier} over {self.resolved} "
                f"resolved forecast(s). Base rate {self.base_rate:.0%}, "
                f"climatology {self.climatology_brier}")
        if self.skill is None:
            line += ". Skill undefined."
        elif self.skill > 0:
            line += (f", skill {self.skill:+.3f} — the model beats predicting "
                     f"the base rate.")
        else:
            line += (f", skill {self.skill:+.3f} — THE MODEL DOES NOT BEAT "
                     f"predicting the base rate. Published because it is true.")
        return line

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_version": self.model_version,
            "issued": self.issued,
            "resolved": self.resolved,
            "publishable": self.publishable,
            "minimum_to_publish": MIN_RESOLVED_TO_PUBLISH,
            "brier": self.brier,
            "climatology_brier": self.climatology_brier,
            "uninformative_brier": UNINFORMATIVE_BRIER,
            "base_rate": self.base_rate,
            "skill_vs_climatology": self.skill,
            "outcomes": self.outcomes,
            "calibration": [
                {"band": c.band, "claimed": c.claimed, "resolved": c.resolved,
                 "happened": c.happened, "actual": c.actual,
                 "trustworthy": c.trustworthy, "note": c.explain()}
                for c in self.calibration],
            "lead_time": self.lead_time,
            "headline": self.headline(),
        }


#: Stated identically every time it is asked for, because the answer does not
#: depend on how much data has accumulated.
LEAD_TIME_UNMEASURABLE = (
    "UNMEASURABLE on a KEV-only corpus, and not for want of data. SKOPOS learns "
    "of a CVE when CISA lists it, so every forecast is issued AFTER the KEV "
    "addition it would be scored against — measured over the record, every lead "
    "time is negative (median -1258 days). Measuring it requires forecasts about "
    "CVEs not yet in KEV, which means the advisory path feeding the record. "
    "Reported rather than omitted: an absent metric reads as an oversight, and a "
    "computed one would be a lie about a negative distribution."
)


def score(forecasts: Sequence[Forecast], model_version: str) -> Scoreboard:
    """The scoreboard for one model version."""
    subset = [f for f in forecasts if f.model_version == model_version]
    pairs: List[Tuple[float, float]] = []
    outcomes: Dict[str, int] = {}
    per_band: Dict[str, List[float]] = {}

    for forecast in subset:
        key = forecast.outcome.value if forecast.outcome else "unresolved"
        outcomes[key] = outcomes.get(key, 0) + 1
        actual = observed(forecast)
        if actual is None:
            continue
        pairs.append((predicted(forecast), actual))
        per_band.setdefault(forecast.band, []).append(actual)

    board = Scoreboard(model_version=model_version, issued=len(subset),
                       resolved=len(pairs), outcomes=outcomes,
                       lead_time=LEAD_TIME_UNMEASURABLE)
    board.calibration = [
        BandCalibration(band=band, claimed=BAND_PROBABILITY.get(band, 0.5),
                        resolved=len(values), happened=int(sum(values)))
        for band, values in sorted(per_band.items())]

    if not pairs:
        return board

    board.brier = brier(pairs)
    rate = sum(o for _p, o in pairs) / len(pairs)
    board.base_rate = round(rate, 4)
    board.climatology_brier = brier([(rate, o) for _p, o in pairs])

    if board.climatology_brier:
        # Brier Skill Score. Positive means the model carries information the
        # base rate does not; zero or negative means it does not, and that is
        # the number most worth publishing honestly.
        board.skill = round(1 - (board.brier / board.climatology_brier), 4)
    board.publishable = len(pairs) >= MIN_RESOLVED_TO_PUBLISH
    return board


def due_for_resolution(forecasts: Sequence[Forecast],
                       today: Optional[date] = None,
                       window_days: int = OBSERVATION_WINDOW_DAYS
                       ) -> List[Forecast]:
    """Unresolved forecasts whose observation window has closed.

    A forecast still inside its window is not a miss — it is pending, and
    marking it NO_EVENT early would score the model against an event that may
    still happen.
    """
    now = today or datetime.now(timezone.utc).date()
    out = []
    for forecast in forecasts:
        if forecast.resolved or forecast.issued_at is None:
            continue
        issued = forecast.issued_at.date() if hasattr(forecast.issued_at, "date") \
            else forecast.issued_at
        if (now - issued).days >= window_days:
            out.append(forecast)
    return out


__all__ = ["Scoreboard", "BandCalibration", "score", "brier", "observed",
           "predicted", "due_for_resolution", "MIN_RESOLVED_TO_PUBLISH",
           "UNINFORMATIVE_BRIER", "LEAD_TIME_UNMEASURABLE"]
