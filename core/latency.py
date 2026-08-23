"""How long exploitation took for vulnerabilities like this one, and when we
will not say.

WHY THIS IS NOT THE FORECASTER THE PLAN ASKED FOR
-------------------------------------------------
P3 names a "time-to-attack forecaster". A forecaster returns a time. This
returns a distribution and frequently returns nothing, because the data does not
support a time — measured, not assumed.

Weaponisation latency (public exploit artefact -> CISA listing the CVE as
exploited) over the 228 usable pairs in the 2023+ window, split by the two
attributes that actually stratify it:

    ransomware  weaponised    n   p25  median   p75   spread
    -----------------------------------------------------------
    no          yes         129    10     120  1713   useless
    YES         YES          58     1       8   124   usable
    no          no           31  -145     -14  1380   useless
    yes         no           10   -45     -30  2360   useless

One cell out of four says anything. Ransomware crews move in days; everybody
else's distribution spans years. Reporting a median of 120 days when the
interquartile range runs from 10 to 1,713 would be a number with no information
in it, dressed as a prediction.

WHAT IT DOES INSTEAD
--------------------
It answers "what happened to vulnerabilities like this one" — a base rate over a
named reference class, always with its spread and its sample size, and only
where both are defensible. A base rate is a genuinely useful thing to tell
somebody triaging: "vulnerabilities of this shape were exploited a median of
eight days after public code, and a quarter took more than four months" supports
a decision. "Expect attack in 8 days" does not, because it is false.

NEGATIVE LATENCY IS REAL AND IS KEPT
------------------------------------
A negative value means CISA listed the CVE before public exploit code appeared —
exploitation was observed first. That is not an error and not noise: it is the
signature of targeted use, and clamping it to zero would erase the distinction
between "code first, then attacks" and "attacks first, code later". Two of the
four cells above have negative medians, which is itself the finding.

THE WINDOW MATTERS AND IS NOT NEGOTIABLE
----------------------------------------
Computed over all of KEV the median is 777 days, and that number describes
CISA's launch backfill rather than any warning period — see
`core/artefacts.py:DEFAULT_LATENCY_SINCE`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from statistics import median as _median
from typing import Dict, List, Optional, Sequence, Tuple

#: Below this, a distribution is a handful of anecdotes. The smallest cell in
#: the measurement above has n=10 and a spread of 2,405 days, which is exactly
#: what a sample this size looks like when it means nothing.
MIN_SAMPLE = 20

#: Interquartile spread beyond which no summary is offered. A range of a year or
#: more does not support any statement a reader would act on differently from
#: having no statement at all.
MAX_USEFUL_SPREAD_DAYS = 400


@dataclass(frozen=True)
class ReferenceClass:
    """The attributes that were measured to actually stratify latency.

    Deliberately only two. Artefact type was tried and produced medians from -32
    to 3,639 days across six combinations — a split that fine slices the sample
    into noise while looking more sophisticated.
    """

    ransomware: bool
    weaponised: bool

    @property
    def label(self) -> str:
        return (f"{'ransomware-linked' if self.ransomware else 'not ransomware-linked'}, "
                f"{'packaged exploit module' if self.weaponised else 'no packaged module'}")


@dataclass
class Latency:
    """What happened to a reference class, or why nothing is said about it."""

    reference: ReferenceClass
    samples: int
    p25: Optional[int] = None
    median: Optional[int] = None
    p75: Optional[int] = None

    @property
    def spread(self) -> Optional[int]:
        if self.p25 is None or self.p75 is None:
            return None
        return self.p75 - self.p25

    @property
    def usable(self) -> bool:
        """Would a reader act differently on this than on nothing?"""
        return (self.samples >= MIN_SAMPLE and self.spread is not None
                and self.spread <= MAX_USEFUL_SPREAD_DAYS)

    def explain(self) -> str:
        if self.samples < MIN_SAMPLE:
            return (f"{self.reference.label}: only {self.samples} comparable "
                    f"vulnerability/ies on record — too few to say anything, so "
                    f"nothing is said")
        if not self.usable:
            return (f"{self.reference.label}: {self.samples} comparable "
                    f"vulnerabilities, but the middle half of them span "
                    f"{self.spread} days ({self.p25} to {self.p75}). NO "
                    f"estimate is offered — a median drawn from that range "
                    f"would carry no information a reader could act on")
        early = ("exploitation was observed BEFORE public code existed"
                 if self.median is not None and self.median < 0
                 else f"exploitation followed public code by a median of "
                      f"{self.median} day(s)")
        return (f"{self.reference.label}: across {self.samples} comparable "
                f"vulnerabilities, {early}; the middle half fell between "
                f"{self.p25} and {self.p75} days. This is what happened to "
                f"OTHERS, not a prediction about yours")

    def to_dict(self) -> Dict[str, object]:
        return {"reference_class": self.reference.label,
                "ransomware": self.reference.ransomware,
                "weaponised": self.reference.weaponised,
                "samples": self.samples, "usable": self.usable,
                "p25": self.p25, "median": self.median, "p75": self.p75,
                "spread_days": self.spread, "note": self.explain()}


def _quantiles(values: Sequence[int]) -> Tuple[int, int, int]:
    ordered = sorted(values)
    return (ordered[len(ordered) // 4], int(_median(ordered)),
            ordered[(3 * len(ordered)) // 4])


def build(observations: Sequence[Tuple[bool, bool, int]]) -> Dict[str, Latency]:
    """`(ransomware, weaponised, latency_days)` -> one Latency per class."""
    buckets: Dict[Tuple[bool, bool], List[int]] = {}
    for ransomware, weaponised, days in observations:
        buckets.setdefault((bool(ransomware), bool(weaponised)), []).append(int(days))

    out: Dict[str, Latency] = {}
    for (ransomware, weaponised), values in buckets.items():
        reference = ReferenceClass(ransomware, weaponised)
        if len(values) < 4:
            out[reference.label] = Latency(reference, len(values))
            continue
        p25, med, p75 = _quantiles(values)
        out[reference.label] = Latency(reference, len(values), p25, med, p75)
    return out


def lookup(classes: Dict[str, Latency], ransomware: bool,
           weaponised: bool) -> Latency:
    reference = ReferenceClass(bool(ransomware), bool(weaponised))
    return classes.get(reference.label, Latency(reference, 0))


#: Shipped with every answer, because the name of this module invites the wrong
#: reading and a caveat nobody sees is not a caveat.
NOT_A_FORECAST = (
    "This is a BASE RATE over comparable past vulnerabilities, not a prediction "
    "about yours. Measured across four reference classes, only one has a spread "
    "narrow enough to support any statement at all — the others range over "
    "years, and a median drawn from them would be a number with no information "
    "in it. Where the data cannot support a statement, none is made."
)

__all__ = ["ReferenceClass", "Latency", "build", "lookup", "MIN_SAMPLE",
           "MAX_USEFUL_SPREAD_DAYS", "NOT_A_FORECAST"]
