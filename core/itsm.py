"""A finding becomes a ticket in somebody else's system.

THE SAME DISCIPLINE AS ALERT DELIVERY, FOR THE SAME REASON
-----------------------------------------------------------
Creating a ticket describes the estate to a third party. So it is switched on in
the ENVIRONMENT by whoever runs the service, never by a request parameter and
never by a console button — if the caller could ask for it, anyone who can reach
the API could choose the moment your unpatched systems are written into another
company's database.

THE TWO THINGS THAT DECIDE WHETHER THIS STAYS SWITCHED ON
-----------------------------------------------------------
1. IT MUST NOT CREATE A TICKET PER FINDING PER RUN. A scan runs daily; 64
   findings would be 64 tickets on Monday and 64 more on Tuesday. Identity is
   `(asset, cve)` — the same key the run-over-run diff uses, and for the same
   reason: a TEPS moving is not a new problem. A finding already ticketed is
   skipped, and the caller supplies what it already knows about.

2. THE TICKET BODY MUST CARRY THE WORKLIST DISTINCTION. A ticket that says
   "CVE-2018-13379 on fw-01" reads as a determination to whoever picks it up,
   and they will either patch something that was never affected or lose trust in
   the queue. Where the version was never compared, the ticket says so in its
   first line and in its title.

WHY A GENERIC WEBHOOK RATHER THAN A SERVICENOW SDK
---------------------------------------------------
`docs/P6-SCOPE.md` said in advance: if the ITSM systems in reach need per-tenant
OAuth apps, the honest move is a documented generic payload rather than a
half-finished vendor integration. That is what this is. A ServiceNow, Jira or
Zendesk instance is reached through the customer's own automation — every one of
them can receive an HTTP POST — and this product holds no vendor credentials, no
per-vendor SDK, and no per-vendor bug surface.

The cost is stated rather than hidden: the customer writes a small mapping on
their side. The alternative was three vendor integrations, each with an auth
flow this product would have to store secrets for.
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# NETWORK-BOUNDARY: ticket_create

#: Off unless set. A scan describes your estate to yourself; a ticket describes
#: it to another company's database, and consent to the first is not consent to
#: the second.
ON_SCAN_ENV = "SKOPOS_ITSM_ON_SCAN"
ENDPOINT_ENV = "SKOPOS_ITSM_WEBHOOK"
TOKEN_ENV = "SKOPOS_ITSM_TOKEN"

#: A first scan of a large estate legitimately produces hundreds of findings.
#: Filing all of them is how an integration is switched off in week two.
MAX_TICKETS_PER_RUN = 20

#: Only findings at or above this band are filed. Everything else is on the
#: worklist, which is where work that is not urgent belongs.
MINIMUM_BAND = "high"

_BANDS = ("informational", "low", "medium", "high", "critical")
_TRUE = {"1", "true", "yes", "on"}


class TicketingFailed(RuntimeError):
    """A ticket could not be filed. Never swallowed — a finding somebody
    believes was ticketed and was not is worse than one nobody filed."""


def enabled(value: Optional[str] = None) -> bool:
    raw = value if value is not None else os.environ.get(ON_SCAN_ENV, "")
    return str(raw).strip().lower() in _TRUE


def identity(finding: Dict[str, Any]) -> Tuple[str, str]:
    """`(asset, cve)`. The same key the diff uses, and never the score."""
    return (str(finding.get("asset") or "").lower(),
            str(finding.get("cve") or "").upper())


@dataclass
class Ticket:
    """One ticket, in a shape any ITSM system can be mapped onto."""

    asset: str
    cve: str
    title: str
    body: str
    severity: str
    #: `(asset, cve)`, so the customer's automation can deduplicate on its side
    #: too rather than trusting ours.
    external_key: str
    finding: Dict[str, Any] = field(default_factory=dict)
    raised_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "external_key": self.external_key,
            "title": self.title,
            "body": self.body,
            "severity": self.severity,
            "asset": self.asset,
            "cve": self.cve,
            "finding": self.finding,
            "raised_at": self.raised_at or datetime.now(
                timezone.utc).isoformat(timespec="seconds"),
        }


def _is_determination(finding: Dict[str, Any]) -> bool:
    return (str(finding.get("basis")) == "version_range"
            and not any(str(e).startswith("RETIRED:")
                        for e in finding.get("evidence") or []))


def build_ticket(finding: Dict[str, Any]) -> Ticket:
    """One finding, expressed so the person who picks it up is not misled."""
    asset, cve = identity(finding)
    determined = _is_determination(finding)
    product = str(finding.get("product") or "an unidentified product")

    # The distinction is in the TITLE, not only the body. A queue is read as a
    # list of titles, and the body is opened after the decision to act.
    title = (f"{cve} on {asset} — affected version confirmed" if determined
             else f"{cve} on {asset} — CHECK VERSION before acting")

    lead = ("An observed version was compared against the published affected "
            "range and falls inside it. This is a determination."
            if determined else
            "The product name corresponds to a known-exploited vulnerability. "
            "THE VERSION WAS NOT COMPARED — this is a worklist entry, not a "
            "confirmation that this asset is vulnerable. Somebody has to check "
            "the version before patching or escalating.")

    evidence = "\n".join(f"  - {e}" for e in (finding.get("evidence") or [])) \
        or "  - none recorded"

    body = (
        f"{lead}\n\n"
        f"Asset       : {asset}\n"
        f"Product     : {product}\n"
        f"Vulnerability: {finding.get('vulnerability') or cve}\n"
        f"Band        : {finding.get('band') or 'unknown'} "
        f"(TEPS {finding.get('teps')})\n"
        f"Owner       : {finding.get('owner') or 'unassigned'}\n"
        f"Due         : {finding.get('due_date') or 'none published'} "
        f"(CISA's deadline for US federal agencies; not necessarily yours)\n"
        f"Action      : {finding.get('required_action') or 'see vendor guidance'}\n\n"
        f"Evidence:\n{evidence}\n\n"
        f"Raised by SKOPOS. Identity is (asset, cve) — this ticket will not be "
        f"raised again for the same pair, and a score changing does not make it "
        f"a new problem."
    )

    return Ticket(asset=asset, cve=cve, title=title, body=body,
                  severity=str(finding.get("band") or "unknown"),
                  external_key=f"{asset}|{cve}", finding=dict(finding))


def select(findings: Sequence[Dict[str, Any]],
           already: Iterable[Tuple[str, str]] = (),
           minimum_band: str = MINIMUM_BAND,
           cap: int = MAX_TICKETS_PER_RUN) -> Dict[str, Any]:
    """What to file, what was skipped, and why. The counts are not optional.

    An operator who receives eight tickets needs to know whether eight was
    everything or a cap, or the cap becomes a silent filter on their view of
    their own estate.
    """
    seen: Set[Tuple[str, str]] = {(str(a).lower(), str(c).upper())
                                  for a, c in already}
    floor = _BANDS.index(minimum_band) if minimum_band in _BANDS else 0

    tickets: List[Ticket] = []
    below = 0
    duplicate = 0
    for finding in findings:
        band = str(finding.get("band") or "")
        # An unknown band is filed rather than dropped: a band this build does
        # not recognise is a reason to look, not a reason to stay silent.
        if band in _BANDS and _BANDS.index(band) < floor:
            below += 1
            continue
        if identity(finding) in seen:
            duplicate += 1
            continue
        seen.add(identity(finding))
        tickets.append(build_ticket(finding))

    capped = max(0, len(tickets) - cap)
    return {
        "tickets": tickets[:cap],
        "skipped_below_band": below,
        "skipped_already_ticketed": duplicate,
        "skipped_by_cap": capped,
        "minimum_band": minimum_band,
        "note": _note(len(tickets), below, duplicate, capped, cap),
    }


def _note(total: int, below: int, duplicate: int, capped: int, cap: int) -> str:
    if not total and not below and not duplicate:
        return "Nothing met the ticketing policy this run."
    parts = [f"{min(total, cap)} ticket(s)"]
    if duplicate:
        parts.append(f"{duplicate} already ticketed and NOT raised again — "
                     f"identity is (asset, cve), so a score moving does not "
                     f"open a second ticket")
    if below:
        parts.append(f"{below} below the {MINIMUM_BAND} threshold and left on "
                     f"the worklist")
    if capped:
        parts.append(f"{capped} held back by the per-run cap of {cap}, which is "
                     f"announced rather than applied silently")
    return "; ".join(parts) + "."


# NETWORK-BOUNDARY: ticket_create
def post_tickets(endpoint: str, tickets: Sequence[Ticket],
                 token: str = "", timeout: float = 15.0) -> int:
    """POST the batch as one JSON document.

    One request, not one per ticket: a partial failure halfway through twenty
    requests leaves a state nobody can reason about, and the customer's
    automation can iterate the array itself.
    """
    if not endpoint.startswith("https://"):
        raise TicketingFailed(
            f"{endpoint!r} is not https. Tickets name your unpatched systems; "
            f"they do not go over plaintext.")
    if not tickets:
        return 0

    payload = json.dumps({
        "source": "SKOPOS",
        "tickets": [t.to_dict() for t in tickets],
        "deduplicate_on": "external_key",
        "note": ("Tickets whose title says CHECK VERSION are WORKLIST ENTRIES: "
                 "the product matched but no version was compared. Do not treat "
                 "them as confirmed vulnerabilities."),
    }).encode("utf-8")

    headers = {"Content-Type": "application/json", "User-Agent": "SKOPOS/0.6"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(endpoint, data=payload, method="POST",
                                     headers=headers)
    try:
        with urllib.request.urlopen(
                request, timeout=timeout,
                context=ssl.create_default_context()) as response:
            if response.status >= 300:
                raise TicketingFailed(f"endpoint returned HTTP {response.status}")
    except urllib.error.URLError as exc:
        raise TicketingFailed(f"ticket delivery failed: {exc}") from exc
    return len(tickets)


def file_for_run(findings: Sequence[Dict[str, Any]],
                 already: Iterable[Tuple[str, str]] = (),
                 switched_on: Optional[bool] = None,
                 endpoint: Optional[str] = None,
                 token: Optional[str] = None) -> Dict[str, Any]:
    """Decide, then file only if filing is switched on. Always report both.

    Four states, three of which are "nothing was filed", and the third is the
    one this exists for: switched on with no endpoint configured looks exactly
    like a quiet run from the outside.
    """
    decided = select(findings, already=already)
    tickets: List[Ticket] = decided["tickets"]
    report: Dict[str, Any] = {
        "decided": len(tickets),
        "skipped_below_band": decided["skipped_below_band"],
        "skipped_already_ticketed": decided["skipped_already_ticketed"],
        "skipped_by_cap": decided["skipped_by_cap"],
        "note": decided["note"],
        "filed": False,
        "tickets": [t.to_dict() for t in tickets],
    }

    if not tickets:
        report["reason"] = ("nothing met the ticketing policy, so nothing was "
                            "filed. A quiet run is a result, not a failure")
        return report

    if switched_on is None:
        switched_on = enabled()
    if not switched_on:
        report["reason"] = (
            f"{len(tickets)} ticket(s) were decided and NOT filed: "
            f"{ON_SCAN_ENV} is not set. Raising a ticket writes your unpatched "
            f"systems into another company's database, and that needs its own "
            f"consent")
        return report

    target = endpoint if endpoint is not None else os.environ.get(ENDPOINT_ENV, "")
    if not target:
        report["reason"] = (
            f"{ON_SCAN_ENV} is on and {ENDPOINT_ENV} is not set, so nothing was "
            f"filed. From the outside this is indistinguishable from a quiet "
            f"run, which is why it is reported here")
        return report

    try:
        sent = post_tickets(target, tickets,
                            token if token is not None
                            else os.environ.get(TOKEN_ENV, ""))
    except TicketingFailed as exc:
        report["reason"] = (
            f"filing failed: {exc}. The findings are recorded and correct; what "
            f"failed is telling your ITSM about them")
        return report

    report["filed"] = True
    report["reason"] = f"filed {sent} ticket(s) to the configured endpoint"
    return report


__all__ = ["ON_SCAN_ENV", "ENDPOINT_ENV", "TOKEN_ENV", "MAX_TICKETS_PER_RUN",
           "MINIMUM_BAND", "TicketingFailed", "Ticket", "enabled", "identity",
           "build_ticket", "select", "post_tickets", "file_for_run"]
