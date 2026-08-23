"""What is being fired at the internet that you happen to be standing in front of.

WHAT THIS IS NOT
----------------
The competitor's screen of this name answers "who is targeting you". SKOPOS
cannot answer that and has the measurements to prove it: ATT&CK carries no
usable CVE-to-actor linkage, and the one open mapping that exists implicates a
median of 57 threat groups per CVE — 139 at the extreme, out of 191. A screen
claiming to name your attackers would be the single least honest thing this
product could ship, so it does not exist.

WHAT THIS IS
------------
The convergence. Everything here is already known: KEV says what is being
exploited, SSVC says what can be sprayed at scale, EPSS velocity says what the
world just changed its mind about, and the fingerprint and reachability data say
what you actually expose. The Management view lists all of it, ranked. This
view answers a narrower question that a ranked list buries:

    of everything being actively fired at the internet right now,
    what are you standing in front of, and how sure are we?

The distinction that makes it honest is AIMED versus SPRAYED. SSVC
`automatable` is CISA's decision that exploitation can be mass-produced without
human effort. A vulnerability with that property is not aimed at anybody — it is
sprayed at everything, which means being found is a matter of when a scanner
reaches your address, not whether somebody chose you. That is a genuinely
different operational posture from a vulnerability requiring hands on keyboard,
and it is the one thing in this data that speaks to how the attack arrives.

CONVERGENCE IS COUNTED, NOT SCORED
----------------------------------
Each finding accumulates independent signals and lands in a tier by how many
converge. Deliberately not a weighted score: a single number would need weights,
the weights would be tuned until the top of the screen looked right, and the
tuning would quietly become the product's real opinion — the same argument that
keeps `match.rank` an ordered tuple.

EVERY TIER STATES WHAT IT DOES NOT KNOW
---------------------------------------
A finding reaches the top tier partly because somebody supplied a version and
fingerprinted the host. An identical finding on an unfingerprinted host sits
lower for a reason that is about OUR coverage, not about the customer's risk. A
convergence view that hid that would rank the well-instrumented parts of an
estate as the dangerous ones.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence


class Signal(str, enum.Enum):
    """One independent reason this finding is in the crosshair."""

    #: CISA observed exploitation. True of everything in this corpus, so it is
    #: the floor rather than a discriminator — stated for completeness.
    EXPLOITED = "exploited"
    #: SSVC automatable: mass exploitation is feasible without human effort.
    SPRAYED = "sprayed"
    #: Used in a ransomware campaign. Changes what a breach costs.
    RANSOMWARE = "ransomware"
    #: The version was compared against a published range and falls inside it.
    CONFIRMED = "confirmed"
    #: A port answered. We connected; there is no ambiguity.
    REACHABLE = "reachable"
    #: EPSS moved sharply. The world changed its mind recently.
    ACCELERATING = "accelerating"
    #: A CISA remediation deadline has passed.
    OVERDUE = "overdue"

    @property
    def meaning(self) -> str:
        return {
            Signal.EXPLOITED:
                "CISA has observed this being exploited in the wild",
            Signal.SPRAYED:
                "CISA judged exploitation automatable — this is sprayed at "
                "everything, not aimed at you, so being found is a matter of "
                "when a scanner reaches your address",
            Signal.RANSOMWARE:
                "used in a ransomware campaign, which changes what a breach "
                "costs rather than how likely it is",
            Signal.CONFIRMED:
                "the version was compared against a published affected range "
                "and falls inside it — a determination, not a worklist entry",
            Signal.REACHABLE:
                "a port answered when we probed. We connected; this is not an "
                "inference",
            Signal.ACCELERATING:
                "the EPSS score moved sharply — the world's judgement of this "
                "vulnerability changed recently",
            Signal.OVERDUE:
                "a CISA remediation deadline has already passed",
        }[self]


class Tier(str, enum.Enum):
    CONVERGED = "converged"      # four or more signals
    ELEVATED = "elevated"        # two or three
    PRESENT = "present"          # one — which every KEV finding has by definition

    @property
    def meaning(self) -> str:
        return {
            Tier.CONVERGED:
                "several independent signals agree. This is where to start",
            Tier.ELEVATED:
                "more than exploitation alone, but not a convergence",
            Tier.PRESENT:
                "exploited somewhere in the world, and nothing further is known "
                "about it here. NOT the same as safe",
        }[self]


#: Deliberately blunt thresholds over a count. See the module docstring.
CONVERGED_AT = 4
ELEVATED_AT = 2


@dataclass
class Aimed:
    """One finding, and why it is in the crosshair."""

    asset: str
    cve: str
    product: str
    signals: List[Signal] = field(default_factory=list)
    #: What we could NOT establish, named per finding. A missing signal is
    #: sometimes a fact about the estate and sometimes a fact about our
    #: coverage, and only the second is our problem to fix.
    unknown: List[str] = field(default_factory=list)
    teps: int = 0
    owner: Optional[str] = None

    @property
    def tier(self) -> Tier:
        count = len(self.signals)
        if count >= CONVERGED_AT:
            return Tier.CONVERGED
        return Tier.ELEVATED if count >= ELEVATED_AT else Tier.PRESENT

    def explain(self) -> str:
        return (f"{self.cve} on {self.asset}: "
                + "; ".join(s.meaning for s in self.signals))

    def to_dict(self) -> Dict[str, Any]:
        return {"asset": self.asset, "cve": self.cve, "product": self.product,
                "owner": self.owner, "teps": self.teps,
                "tier": self.tier.value,
                "signals": [s.value for s in self.signals],
                "unknown": list(self.unknown)}


def read(finding: Dict[str, Any],
         automatable: Optional[bool] = None,
         accelerating: bool = False,
         today=None) -> Aimed:
    """Turn one finding into its crosshair entry."""
    from datetime import date as _date

    now = today or _date.today()
    signals: List[Signal] = [Signal.EXPLOITED]
    unknown: List[str] = []

    if automatable is True:
        signals.append(Signal.SPRAYED)
    elif automatable is None:
        unknown.append("CISA has not decided whether this is automatable, so "
                       "we cannot say whether it is sprayed or aimed")

    if finding.get("known_ransomware"):
        signals.append(Signal.RANSOMWARE)

    if str(finding.get("basis")) == "version_range" and not any(
            str(e).startswith("RETIRED:") for e in finding.get("evidence") or []):
        signals.append(Signal.CONFIRMED)
    elif not finding.get("version"):
        # OUR coverage gap, not their risk. Said so explicitly.
        unknown.append("no version on record, so this cannot be confirmed — "
                       "that is a gap in what we know, not evidence of safety")

    reachable = _reachable(finding)
    if reachable is True:
        signals.append(Signal.REACHABLE)
    elif reachable is None:
        unknown.append("never probed, so outside-in reachability is unknown — "
                       "which is not the same as unreachable")

    if accelerating:
        signals.append(Signal.ACCELERATING)

    due = finding.get("due_date")
    if due:
        try:
            if _date.fromisoformat(str(due)) < now:
                signals.append(Signal.OVERDUE)
        except ValueError:
            pass

    return Aimed(asset=str(finding.get("asset") or ""),
                 cve=str(finding.get("cve") or ""),
                 product=str(finding.get("product") or ""),
                 owner=finding.get("owner"),
                 teps=int(finding.get("teps") or 0),
                 signals=signals, unknown=unknown)


def _reachable(finding: Dict[str, Any]) -> Optional[bool]:
    values = finding.get("factor_values") or {}
    if "external_reachable" in finding:
        return finding["external_reachable"]
    # The evidence line is where reachability is recorded today.
    for line in finding.get("evidence") or []:
        text = str(line).lower()
        if "answered on" in text:
            return True
        if "nothing answered" in text:
            return False
        if "no positive reachability" in text or "not probed" in text:
            return None
    return None


@dataclass
class Crosshair:
    entries: List[Aimed] = field(default_factory=list)
    total_findings: int = 0

    def of_tier(self, tier: Tier) -> List[Aimed]:
        return [e for e in self.entries if e.tier is tier]

    @property
    def coverage_gaps(self) -> Dict[str, int]:
        """How often each unknown appeared. This is the fix-list for US."""
        counts: Dict[str, int] = {}
        for entry in self.entries:
            for gap in entry.unknown:
                key = gap.split(",")[0].split(" — ")[0]
                counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def headline(self) -> str:
        converged = len(self.of_tier(Tier.CONVERGED))
        elevated = len(self.of_tier(Tier.ELEVATED))
        line = (f"{converged} converged, {elevated} elevated, "
                f"{len(self.of_tier(Tier.PRESENT))} present, "
                f"across {self.total_findings} finding(s).")
        if not converged and self.coverage_gaps:
            # The honest reading of an empty top tier on an uninstrumented
            # estate. Without this it reads as good news.
            line += (" Nothing has converged — but signals are missing across "
                     "this estate, so that is partly a statement about our "
                     "coverage rather than about your risk.")
        return line

    def to_dict(self) -> Dict[str, Any]:
        return {
            "headline": self.headline(),
            "total_findings": self.total_findings,
            "tiers": {t.value: [e.to_dict() for e in self.of_tier(t)]
                      for t in Tier},
            "coverage_gaps": self.coverage_gaps,
            "signal_meaning": {s.value: s.meaning for s in Signal},
            "tier_meaning": {t.value: t.meaning for t in Tier},
            "not_targeting": (
                "This view does NOT claim anyone is targeting you. SKOPOS "
                "cannot attribute a CVE to a threat actor — the one open "
                "mapping implicates a median of 57 groups per CVE — and a "
                "screen naming your attackers would be the least honest thing "
                "this product could ship. What it shows is convergence: what is "
                "being fired at the internet that you are standing in front of."),
        }


def build(findings: Sequence[Dict[str, Any]],
          automatable: Optional[Dict[str, Optional[bool]]] = None,
          accelerating: Optional[Sequence[str]] = None,
          today=None) -> Crosshair:
    decisions = automatable or {}
    moving = set(accelerating or ())
    entries = [read(f, automatable=decisions.get(f.get("cve")),
                    accelerating=f.get("cve") in moving, today=today)
               for f in findings]
    entries.sort(key=lambda e: (-len(e.signals), -e.teps, e.cve))
    return Crosshair(entries=entries, total_findings=len(findings))


__all__ = ["Signal", "Tier", "Aimed", "Crosshair", "build", "read",
           "CONVERGED_AT", "ELEVATED_AT"]
