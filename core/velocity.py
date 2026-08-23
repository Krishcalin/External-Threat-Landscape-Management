"""EPSS over time, and what a moving score means that a single reading does not.

WHY A SERIES AND NOT A NUMBER
-----------------------------
A single EPSS reading says how likely exploitation is judged to be today. A
series says which direction that judgement is travelling and how fast, and the
two support different actions. A score sitting at 0.31 for six months is a known
quantity; a score that reached 0.31 from 0.02 in four days is a vulnerability the
world has just changed its mind about, and it is the second that warrants
interrupting somebody.

FIRST's model is retrained periodically, so a series can also step for reasons
that have nothing to do with the vulnerability. `model` is stored per reading so
a jump across a retrain boundary can be identified rather than reported as a
real movement.

THIS IS WHY W4 EXISTS AND WHY IT CANNOT WAIT
--------------------------------------------
EPSS publishes today's scores. It does not publish yesterday's. A day not
recorded is a permanent hole in every velocity figure computed afterwards, and
no amount of later effort fills it — the same argument that puts the forecast
record first, applied to a second dataset.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Dict, List, Optional, Sequence, Tuple

#: Below this, a movement is noise rather than a judgement change. EPSS scores
#: jitter by small amounts daily and a threshold of zero would make every CVE
#: "accelerating" every day, which is a signal nobody would read twice.
MIN_MEANINGFUL_DELTA = 0.05

#: The window a velocity is computed over. Short enough that a real shift shows
#: up while it still matters, long enough not to fire on a single day's jitter.
DEFAULT_WINDOW_DAYS = 14


@dataclass(frozen=True)
class Velocity:
    cve: str
    first: float
    latest: float
    days: int
    readings: int
    #: True when the series does not span the requested window. A rise measured
    #: over three days of a fourteen-day window is a different claim, and
    #: presenting it as the same one is how a young dataset flatters itself.
    partial: bool = False

    @property
    def delta(self) -> float:
        return round(self.latest - self.first, 6)

    @property
    def per_day(self) -> float:
        return round(self.delta / self.days, 6) if self.days else 0.0

    @property
    def accelerating(self) -> bool:
        return self.delta >= MIN_MEANINGFUL_DELTA

    @property
    def decelerating(self) -> bool:
        return self.delta <= -MIN_MEANINGFUL_DELTA

    def explain(self) -> str:
        if self.readings < 2:
            return (f"{self.cve}: only {self.readings} reading on record — no "
                    f"velocity can be computed, which is not the same as a flat "
                    f"score")
        direction = ("rose" if self.delta > 0 else
                     "fell" if self.delta < 0 else "did not move")
        line = (f"{self.cve}: EPSS {direction} from {self.first:.3f} to "
                f"{self.latest:.3f} over {self.days} day(s)")
        if self.partial:
            line += (" — the series is shorter than the requested window, so "
                     "this covers less time than it appears to")
        if self.accelerating:
            line += ". The world's judgement of this vulnerability changed."
        return line


def compute(cve: str, series: Sequence[Tuple[date, float]],
            window_days: int = DEFAULT_WINDOW_DAYS,
            today: Optional[date] = None) -> Optional[Velocity]:
    """Velocity over the trailing window, or None if it cannot be computed.

    None rather than a zero, deliberately. "The score did not move" and "we have
    one reading" are different facts, and a zero would let a CVE we started
    watching yesterday sit alongside one we have watched for months looking
    equally quiet.
    """
    if not series:
        return None
    ordered = sorted(series)
    cutoff = (today or ordered[-1][0]) - timedelta(days=window_days)
    inside = [(d, v) for d, v in ordered if d >= cutoff]
    if len(inside) < 2:
        # Keep the CVE, report the shortfall. A caller that filters these out
        # silently would show a shrinking watchlist as a calming one.
        return Velocity(cve=cve, first=ordered[-1][1], latest=ordered[-1][1],
                        days=0, readings=len(inside), partial=True)
    span = (inside[-1][0] - inside[0][0]).days or 1
    return Velocity(cve=cve, first=inside[0][1], latest=inside[-1][1],
                    days=span, readings=len(inside),
                    partial=span < window_days)


def accelerating(velocities: Sequence[Velocity],
                 minimum: float = MIN_MEANINGFUL_DELTA) -> List[Velocity]:
    """Those whose score moved up by more than noise, steepest first."""
    return sorted((v for v in velocities if v.readings >= 2
                   and v.delta >= minimum),
                  key=lambda v: -v.delta)


def coverage(velocities: Sequence[Velocity]) -> Dict[str, int]:
    """How much of the watchlist can actually be given a velocity.

    Reported beside any velocity list, because a young EPSS history makes the
    accelerating set look small for a reason that has nothing to do with the
    estate.
    """
    return {
        "computable": sum(1 for v in velocities if v.readings >= 2),
        "insufficient_history": sum(1 for v in velocities if v.readings < 2),
        "partial_window": sum(1 for v in velocities if v.partial and v.readings >= 2),
    }


__all__ = ["Velocity", "compute", "accelerating", "coverage",
           "MIN_MEANINGFUL_DELTA", "DEFAULT_WINDOW_DAYS"]
