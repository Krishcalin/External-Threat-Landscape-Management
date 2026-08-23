"""CERT-In notification support, built around the thing it must not do.

THE CENTRAL CONSTRAINT: AN EXPOSURE IS NOT AN INCIDENT
------------------------------------------------------
Direction No. 20(3)/2022-CERT-In (issued 28 April 2022, effective 28 June 2022)
requires service providers, intermediaries, data centres, body corporates and
government organisations in India to report cyber incidents to CERT-In within
SIX HOURS of becoming aware of them.

The clock starts on awareness of an INCIDENT. Annexure I's reportable categories
are things like targeted scanning or probing of critical networks, unauthorised
access to IT systems or data, data breach, data leak, website defacement and
compromise of critical systems. Every one of them describes something an
adversary DID.

SKOPOS produces exposures: this asset runs a product with a known-exploited
vulnerability. That is a statement about the estate, not about an adversary's
activity. It is not, on its own, any of the categories above.

So this module WILL NOT start a clock on a finding. A tool that opened a
six-hour countdown every time it saw an unpatched perimeter service would push
its users toward over-reporting to a national CERT — wasting the regulator's
capacity, and training the customer to ignore the alarm that matters. The clock
starts when a HUMAN declares that they have become aware of an incident, and
records who declared it and when.

WHAT SKOPOS LEGITIMATELY CONTRIBUTES
------------------------------------
Once a human has made that determination, the hard part of a six-hour deadline
is assembling technical facts under time pressure. That is exactly what this
product already holds: which asset, which vulnerability, since when it was
externally visible, what the evidence was, who owns it. So it pre-fills a DRAFT
with facts it can substantiate and leaves every judgement blank.

NOTHING HERE IS FILED, AND NOTHING HERE IS ADVICE
-------------------------------------------------
The output is a draft for a human to review, complete and submit through the
official channel. This module does not transmit anything, does not assert that a
report is required, and does not tell anybody they are compliant. Whether an
event is reportable is a legal determination about a specific organisation, and
the directive's own text is the authority — not this file, which is a
convenience over data the customer already owns.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence

#: Direction No. 20(3)/2022-CERT-In. Six hours from becoming aware.
REPORTING_WINDOW = timedelta(hours=6)

DIRECTIVE = "No. 20(3)/2022-CERT-In, dated 28 April 2022 (effective 28 June 2022)"

#: When the categories below were last checked against the directive. A
#: regulatory list with no review date silently ages into a false claim, exactly
#: as a terms field does in collect/registry.py.
REVIEWED_ON = "2026-08-23"


class Category(str, enum.Enum):
    """Annexure I categories, as published.

    Note what they have in common: each describes something an adversary DID.
    None of them is "we found an unpatched service", which is why a SKOPOS
    finding does not map onto this list by itself.
    """

    TARGETED_SCANNING = "targeted_scanning_probing_critical_systems"
    UNAUTHORISED_ACCESS = "unauthorised_access_to_it_systems_or_data"
    DATA_BREACH = "data_breach"
    DATA_LEAK = "data_leak"
    WEBSITE_DEFACEMENT = "website_defacement_or_intrusion"
    MALICIOUS_CODE = "malicious_code_attack"
    CRITICAL_SYSTEM_COMPROMISE = "compromise_of_critical_systems_or_information"
    IDENTITY_THEFT = "identity_theft_spoofing_phishing"

    @property
    def label(self) -> str:
        return self.value.replace("_", " ")


class Detectability(str, enum.Enum):
    """Can SKOPOS observe this category at all? Almost always: no."""

    #: SKOPOS cannot see it. It looks at the estate from outside; it does not
    #: monitor the estate's own logs, traffic or data.
    NOT_OBSERVABLE = "not_observable"
    #: A human must decide, and SKOPOS can supply supporting facts.
    HUMAN_DETERMINATION = "human_determination"


#: Every category, and what this product can honestly say about it. The value of
#: this table is that it is almost entirely NOT_OBSERVABLE — a compliance
#: feature whose main output is "we cannot tell you this" is unusual, and it is
#: the correct answer.
OBSERVABILITY: Dict[Category, Detectability] = {
    Category.TARGETED_SCANNING: Detectability.NOT_OBSERVABLE,
    Category.UNAUTHORISED_ACCESS: Detectability.NOT_OBSERVABLE,
    Category.DATA_BREACH: Detectability.NOT_OBSERVABLE,
    Category.DATA_LEAK: Detectability.NOT_OBSERVABLE,
    Category.WEBSITE_DEFACEMENT: Detectability.NOT_OBSERVABLE,
    Category.MALICIOUS_CODE: Detectability.NOT_OBSERVABLE,
    Category.CRITICAL_SYSTEM_COMPROMISE: Detectability.HUMAN_DETERMINATION,
    Category.IDENTITY_THEFT: Detectability.NOT_OBSERVABLE,
}

WHY_NOT_AUTOMATIC = (
    "SKOPOS does not open this clock automatically and will not. The six-hour "
    "window runs from a human becoming aware of a cyber INCIDENT — something an "
    "adversary did. A SKOPOS finding says an asset runs a product with a "
    "known-exploited vulnerability, which is a statement about your estate, not "
    "about an adversary's activity. Starting a regulatory countdown on every "
    "unpatched perimeter service would push you toward over-reporting to a "
    "national CERT and would train your team to ignore the alarm that matters."
)


class DeclarationInvalid(ValueError):
    """A declaration missing something that makes it meaningful."""


@dataclass(frozen=True)
class Declaration:
    """A human's statement that they became aware of an incident.

    Frozen, and it requires a person and a time. An incident record with nobody's
    name on it is not a record — the same reasoning that makes a manual ownership
    attestation require an approver.
    """

    category: Category
    #: When the organisation BECAME AWARE. Not when SKOPOS produced a finding,
    #: not when the declaration was typed. The directive's clock runs from
    #: awareness, and only a human knows when that was.
    became_aware_at: datetime
    declared_by: str
    summary: str
    #: Findings the declarer considers related. Supporting facts, never the
    #: basis of the determination.
    related_findings: Sequence[Dict[str, Any]] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not str(self.declared_by).strip():
            raise DeclarationInvalid(
                "a declaration must record who made it — an unattributed "
                "assertion that an incident occurred is not a record")
        if not str(self.summary).strip():
            raise DeclarationInvalid(
                "a declaration must say what happened, in the declarer's own "
                "words. This product cannot write that sentence for you")
        if self.became_aware_at.tzinfo is None:
            raise DeclarationInvalid(
                "became_aware_at must carry a timezone; a six-hour deadline "
                "computed from an ambiguous timestamp is worse than none")


@dataclass
class Clock:
    """The six-hour window, from a declared awareness time."""

    declaration: Declaration

    @property
    def deadline(self) -> datetime:
        return self.declaration.became_aware_at + REPORTING_WINDOW

    def remaining(self, now: Optional[datetime] = None) -> timedelta:
        return self.deadline - (now or datetime.now(timezone.utc))

    def elapsed(self, now: Optional[datetime] = None) -> timedelta:
        return (now or datetime.now(timezone.utc)) - self.declaration.became_aware_at

    def overdue(self, now: Optional[datetime] = None) -> bool:
        return self.remaining(now).total_seconds() < 0

    def explain(self, now: Optional[datetime] = None) -> str:
        left = self.remaining(now)
        aware = self.declaration.became_aware_at.isoformat(timespec="minutes")
        if self.overdue(now):
            # Stated plainly. A tool that softened this would be helping
            # somebody misunderstand their own position.
            over = -left
            return (f"The six-hour window under {DIRECTIVE} closed "
                    f"{_humanise(over)} ago. Awareness was declared at {aware}; "
                    f"the deadline was {self.deadline.isoformat(timespec='minutes')}. "
                    f"This is a statement of elapsed time, not legal advice.")
        return (f"{_humanise(left)} remaining of the six-hour window under "
                f"{DIRECTIVE}. Awareness declared at {aware} by "
                f"{self.declaration.declared_by}; deadline "
                f"{self.deadline.isoformat(timespec='minutes')}.")


def _humanise(delta: timedelta) -> str:
    minutes = int(abs(delta).total_seconds()) // 60
    hours, minutes = divmod(minutes, 60)
    if hours and minutes:
        return f"{hours}h {minutes}m"
    return f"{hours}h" if hours else f"{minutes}m"


def observability_note() -> Dict[str, Any]:
    """What this product can and cannot see, per reportable category."""
    return {
        "directive": DIRECTIVE,
        "reviewed_on": REVIEWED_ON,
        "window_hours": REPORTING_WINDOW.total_seconds() / 3600,
        "why_not_automatic": WHY_NOT_AUTOMATIC,
        "categories": [
            {"category": c.value, "label": c.label,
             "skopos_can_observe": OBSERVABILITY[c] is not Detectability.NOT_OBSERVABLE,
             "note": ("SKOPOS looks at your estate from outside. It does not "
                      "monitor your logs, traffic or data, so it cannot observe "
                      "this."
                      if OBSERVABILITY[c] is Detectability.NOT_OBSERVABLE else
                      "A human must determine this. SKOPOS can supply "
                      "supporting technical facts about the exposed asset.")}
            for c in Category],
        "summary": (
            "Seven of the eight reportable categories are things SKOPOS cannot "
            "observe at all. That is not a gap to be closed — it is what an "
            "outside-in product is. Anyone selling you automatic CERT-In "
            "incident detection from external scanning is describing something "
            "the data does not support."),
    }


__all__ = ["REPORTING_WINDOW", "DIRECTIVE", "REVIEWED_ON", "Category",
           "Detectability", "OBSERVABILITY", "WHY_NOT_AUTOMATIC",
           "Declaration", "DeclarationInvalid", "Clock", "observability_note"]
