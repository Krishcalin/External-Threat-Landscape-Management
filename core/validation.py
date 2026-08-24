"""What to point a validation platform at — and nothing about how to test it.

THE DIVISION OF LABOUR, WHICH IS NOT ARBITRARY
------------------------------------------------
Gartner's CTEM programme has five stages: Scoping, Discovery, Prioritisation,
Validation, Mobilisation. SKOPOS covers two of them properly and refuses the
fourth outright — `core/gate.py` classifies `exploit_attempt` and
`credential_replay` as PROHIBITED under FR-GOV-007, before scope or ownership
are even consulted.

Adversarial Exposure Validation platforms cover that stage. OpenAEV is open
source and Apache 2.0; Pentera, Cymulate and Picus are the commercial ones. What
they lack is not technique knowledge — they have MITRE's entire Enterprise
matrix and, in OpenAEV's case, roughly 1,819 Atomic Red Team tests. What they
lack is **knowing which of your assets are exposed and worth the time.**

That is the handoff this module builds: *here is what to test*, never *here is
how*.

WHY THERE ARE NO ATT&CK TECHNIQUES IN HERE
--------------------------------------------
Because SKOPOS holds none. P3 built the CVE → technique → group chain far enough
to measure it, found that resolving technique to group implicates a median of 57
groups per CVE, and closed the whole line. There is no vendored ATT&CK mapping
in `data/` and nothing in this codebase can tell a validation platform which
techniques apply to a finding.

A target list that invented techniques would be worse than useless: it would
send somebody's simulation programme after the wrong thing, with SKOPOS's name
on the recommendation.

WHAT MAKES A GOOD TARGET, AND WHY THE ORDER MATTERS
-----------------------------------------------------
Simulation time is finite and every inject costs a maintenance window. The
ordering here is not TEPS — TEPS ranks what to FIX, and what is worth fixing is
not the same question as what is worth TESTING.

A determination needs no validation to be believed; the version was compared.
A worklist entry on a reachable asset is the interesting case: somebody has to
check it anyway, and a simulation answers the question faster than a human
reading a version banner. So reachable worklist entries lead.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

#: Above this, a target list stops being a plan and becomes a backlog. Not a
#: silent truncation — `summarise` reports what was cut, for the same reason
#: `core/itsm.py` announces its cap.
MAX_TARGETS = 200

#: What SKOPOS will not supply, stated on every payload rather than in a
#: footnote, because a validation platform receiving a target list with no
#: techniques will otherwise assume the field was omitted by accident.
NO_TECHNIQUES = (
    "This list carries NO ATT&CK techniques and no payload suggestions. SKOPOS "
    "holds no technique mapping at all — P3 measured CVE-to-technique-to-group "
    "at a median of 57 groups per CVE and closed the line — so nothing here can "
    "tell a validation platform WHICH technique applies to a finding. Your "
    "validation platform already knows that from MITRE's own data. What it "
    "cannot know, and this supplies, is which of your assets are externally "
    "reachable and what they appear to run.")

NOT_VALIDATION = (
    "SKOPOS does not validate and will not. `exploit_attempt` and "
    "`credential_replay` are PROHIBITED in core/gate.py under FR-GOV-007, "
    "refused before scope or ownership are consulted. This is a scoping input "
    "for a platform that does validate — OpenAEV, Pentera, Cymulate, Picus. A "
    "target appearing here is a suggestion about where to spend simulation "
    "time, never a claim that an attack would succeed.")


@dataclass(frozen=True)
class Target:
    asset: str
    cve: str
    product: str
    version: str
    #: `product_match` or `version_range`. Decides why this is worth testing.
    basis: str
    #: True only where a port actually answered. None means nobody looked.
    reachable: Optional[bool]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"asset": self.asset, "cve": self.cve, "product": self.product,
                "version": self.version or None, "basis": self.basis,
                "reachable": self.reachable, "why_test_this": self.reason}


def _reachable(finding: Dict[str, Any]) -> Optional[bool]:
    """Whether a port answered. THREE-VALUED, and the third value matters.

    `core/reach.py` returns True / False / None, and None means nobody probed —
    which on an unverified asset is the normal case, because the gate refused.
    Collapsing None to False would tell a validation platform an asset is
    unreachable when the truth is that SKOPOS was not allowed to look.
    """
    value = finding.get("reachable")
    if value is None:
        return None
    return bool(value)


def _reason(finding: Dict[str, Any], reachable: Optional[bool]) -> str:
    determined = str(finding.get("basis") or "") == "version_range"
    if determined:
        base = ("The version was compared against a published affected range "
                "and falls inside it. Validation here answers a different "
                "question from the finding: whether your controls would stop "
                "exploitation, not whether the asset is affected.")
    else:
        base = ("A worklist entry: this asset runs a product with a "
                "known-exploited vulnerability and NOBODY HAS COMPARED THE "
                "VERSION. Somebody has to check it either way, and a "
                "simulation answers it faster than reading a banner.")
    if reachable is True:
        return base + " A port answered, so it is reachable from outside."
    if reachable is False:
        return base + " No port answered when SKOPOS probed."
    return (base + " Reachability is UNKNOWN — SKOPOS did not probe, which on "
            "an asset without proven ownership is the gate working correctly.")


def _rank(target: Target) -> tuple:
    """Reachable worklist entries first. Deliberately NOT TEPS order.

    TEPS ranks what to FIX. This ranks what to TEST, and the two differ: a
    determination is already believed, so validating it confirms a control
    rather than resolving a doubt. An unresolved worklist entry on something
    that answers from outside is where a simulation earns its time.
    """
    reachable_first = 0 if target.reachable is True else (
        1 if target.reachable is None else 2)
    worklist_first = 0 if target.basis != "version_range" else 1
    return (reachable_first, worklist_first, target.asset, target.cve)


def targets(findings: Sequence[Dict[str, Any]],
            limit: int = MAX_TARGETS) -> Dict[str, Any]:
    """A validation-scoping list, ordered by what is worth testing.

    Returns the payload rather than a bare list, because the two statements
    that must travel with it — no techniques, not validation — are not
    optional and a caller should not be able to drop them by taking `[0]`.
    """
    rows: List[Target] = []
    for finding in findings:
        asset = str(finding.get("asset") or "").strip()
        cve = str(finding.get("cve") or "").strip()
        if not asset or not cve:
            continue
        reachable = _reachable(finding)
        rows.append(Target(
            asset=asset, cve=cve,
            product=str(finding.get("product") or ""),
            version=str(finding.get("version") or ""),
            basis=str(finding.get("basis") or "product_match"),
            reachable=reachable,
            reason=_reason(finding, reachable)))

    rows.sort(key=_rank)
    selected = rows[:limit]
    dropped = len(rows) - len(selected)

    return {
        "targets": [t.to_dict() for t in selected],
        "count": len(selected),
        "considered": len(rows),
        # Announced rather than applied silently, like every other cap here.
        "dropped_by_cap": dropped,
        "cap": limit,
        "ordering": (
            "Reachable first, then worklist entries before determinations. "
            "This is NOT TEPS order: TEPS ranks what to fix, and what is worth "
            "fixing is a different question from what is worth testing."),
        "no_techniques": NO_TECHNIQUES,
        "not_validation": NOT_VALIDATION,
        "unknown_reachability": sum(1 for t in selected if t.reachable is None),
        "reachability_note": (
            "`reachable: null` means SKOPOS did not probe — on an asset whose "
            "ownership is unproven that is the gate working, not a finding "
            "that the asset is unreachable. Treat null as 'find out', never as "
            "'no'."),
    }


def coverage_gaps(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """What a validation platform should be told it CANNOT learn from here.

    Borrowed directly from OpenCTI's handoff to OpenAEV, which generates
    PLACEHOLDER INJECTS for coverage it cannot test so that gaps become visible
    artifacts rather than silent omissions. That instinct is the same one behind
    this product's coverage counters, and it is worth copying explicitly: a
    target list that simply omits what it could not assess reads as an estate
    with nothing else in it.
    """
    unknown = [f for f in findings if _reachable(f) is None]
    unversioned = [f for f in findings if not str(f.get("version") or "")]
    gaps = []
    if unknown:
        gaps.append({
            "gap": "reachability_unknown",
            "count": len(unknown),
            "means": ("SKOPOS did not probe these, so it cannot say whether "
                      "they answer from outside. Prove ownership and rescan, "
                      "or treat them as in scope for validation regardless."),
        })
    if unversioned:
        gaps.append({
            "gap": "no_version_observed",
            "count": len(unversioned),
            "means": ("No version was observed, so no determination was "
                      "possible regardless of what the catalogue holds. These "
                      "are the entries a simulation resolves fastest."),
        })
    return gaps


__all__ = ["Target", "targets", "coverage_gaps", "MAX_TARGETS",
           "NO_TECHNIQUES", "NOT_VALIDATION"]
