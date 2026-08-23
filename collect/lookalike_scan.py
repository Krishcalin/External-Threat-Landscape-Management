"""Find names that borrow a brand, in certificate transparency.

TWO SOURCES THAT ANSWER DIFFERENT QUESTIONS
---------------------------------------------
crt.sh takes a SUBSTRING — "every name anywhere containing this term" — which is
the only way to find an impersonation nobody predicted. It is one query and it
is the whole feature.

certspotter takes a DOMAIN. It cannot answer "names containing tata"; it can
only confirm whether a name somebody already guessed has a certificate. So it is
a fallback that finds what you thought of, never what you did not.

Measured while building this: crt.sh returned 502 on every request including its
own homepage, while certspotter answered normally. That is not a hypothetical
outage — it is the state the source was in on the day this was written.

WHICH MAKES ONE PROPERTY MORE IMPORTANT THAN THE FEATURE
---------------------------------------------------------
A brand-protection screen reporting "no lookalike domains found" during a source
outage is the worst failure available here, because zero is exactly what the
customer hopes to see and they will believe it.

So `searched` is returned separately from results. Zero candidates from a
successful search and zero candidates because nothing could be asked are
different answers, and `core/lookalike.Report` renders them differently. Nothing
in this module returns an empty list that reads as reassurance.
"""
from __future__ import annotations

import json
import urllib.parse
from datetime import date
from typing import Any, Dict, List, Optional, Sequence, Tuple

from collect import ct, egress
from collect.report import Outcome, SourceReport

#: The same PASSIVE operation asset discovery uses. Reading a public log is
#: reading a public log, whoever the name belongs to.
OPERATION = "ct_log_search"

#: crt.sh substring queries are expensive for them and slow for us. Capped so a
#: three-term brand cannot become a nine-minute request.
MAX_ROWS = 4000


def _parse_day(value: Any) -> Optional[date]:
    text = str(value or "")[:10]
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def from_crtsh(permit, term: str, budget=None, limiter=None
               ) -> Tuple[List[Tuple[str, Optional[date]]], SourceReport]:
    """Every name containing `term`, from crt.sh.

    THE ONLY SOURCE THAT FINDS WHAT NOBODY PREDICTED. A failure here is a
    coverage gap, never an empty result — see the module docstring.
    """
    url = ("https://crt.sh/?q=" + urllib.parse.quote(f"%{term}%")
           + "&output=json&exclude=expired")
    try:
        response = egress.http_get(permit, OPERATION, url, budget=budget,
                                   limiter=limiter)
    except egress.PermitMismatch:
        raise
    except Exception as exc:                                    # noqa: BLE001
        return [], SourceReport("crt.sh", Outcome.FAILED, 0, 0,
                                f"{type(exc).__name__}: {str(exc)[:70]}")

    if response.status != 200:
        return [], SourceReport("crt.sh", Outcome.FAILED, 0, 0,
                                f"HTTP {response.status}")
    try:
        rows = json.loads(response.text)
    except ValueError:
        return [], SourceReport("crt.sh", Outcome.FAILED, 0, 0,
                                "HTTP 200 with an unparseable body")

    out: Dict[str, Optional[date]] = {}
    for row in rows[:MAX_ROWS]:
        seen = _parse_day(row.get("not_before"))
        for raw in str(row.get("name_value") or "").split("\n"):
            name = raw.strip().lower().lstrip("*.")
            if not name:
                continue
            # Earliest issuance wins: "when did this name first appear" is the
            # question, and a renewal is not a new appearance.
            if name not in out or (seen and out[name] and seen < out[name]):
                out[name] = seen
    truncated = len(rows) > MAX_ROWS
    return (
        sorted(out.items()),
        SourceReport("crt.sh", Outcome.PARTIAL if truncated else Outcome.OK,
                     len(out), len(rows),
                     f"capped at {MAX_ROWS} rows; more exist" if truncated
                     else "complete"),
    )


def from_certspotter(permit, candidate: str, budget=None, limiter=None
                     ) -> Tuple[List[Tuple[str, Optional[date]]], SourceReport]:
    """Does a name somebody GUESSED have a certificate?

    Cannot find an imitation nobody thought of. Used when crt.sh is unavailable,
    and the report says which of the two answered so a thin result is
    attributable.
    """
    names, report = ct.from_certspotter(candidate, permit=permit, budget=budget,
                                        limiter=limiter)
    return [(n, d) for n, d in names], report


def observe(terms: Sequence[str], permit_for, budget=None, limiter=None
            ) -> Dict[str, Any]:
    """Search every declared term. Returns names, coverage and availability.

    `permit_for` is a callable taking an operation and returning a permit, so
    this module never touches the gate and cannot mint its own authority.
    """
    names: Dict[str, Optional[date]] = {}
    reports: List[SourceReport] = []
    unavailable: List[Dict[str, str]] = []
    searched = False

    for term in terms:
        try:
            found, report = from_crtsh(permit_for(OPERATION), term, budget,
                                       limiter)
        except egress.PermitMismatch:
            raise
        except Exception as exc:                                # noqa: BLE001
            found, report = [], SourceReport(
                "crt.sh", Outcome.FAILED, 0, 0, f"{type(exc).__name__}")
        reports.append(report)

        if report.outcome is Outcome.FAILED:
            unavailable.append({
                "source": "crt.sh",
                "term": term,
                "why": report.detail,
                # The sentence that stops a reader taking silence for safety.
                "cost": ("substring search is the ONLY way to find a name "
                         "nobody predicted. Without it this cannot tell you "
                         "whether anybody is imitating you — a quiet result "
                         "here means nothing was asked, not that nothing "
                         "exists"),
            })
            continue

        searched = True
        for name, seen in found:
            if name not in names or (seen and names[name] and seen < names[name]):
                names[name] = seen

    return {
        "names": sorted(names.items()),
        # False when NO term could be searched. The single most important field
        # in this payload.
        "searched": searched,
        "unavailable": unavailable,
        "reports": reports,
    }


__all__ = ["OPERATION", "MAX_ROWS", "from_crtsh", "from_certspotter", "observe"]
