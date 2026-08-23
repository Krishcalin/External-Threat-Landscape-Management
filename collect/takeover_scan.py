"""Turn a DNS sweep into takeover findings, passively.

TAKEOVER IS A STATE JUDGEMENT, NOT A CHANGE
-------------------------------------------
It runs fully on the first sweep. A dangling CNAME is dangerous the first time
you look at it, and waiting for a second run to "confirm" would mean the most
urgent finding in the product is the one it deliberately withholds. That is why
this is a separate module from `core/dns_state.py`.

WHAT IT WILL NOT DO
-------------------
It never fetches the CNAME target. That would be an active probe of a third
party's host, which the customer's ownership verification cannot authorise — see
`core/takeover.py`. Records it cannot take further are counted in
`probes_unavailable`, so the gap is a number on the report rather than an
absence.
"""
from __future__ import annotations

import json
from datetime import date
from typing import Any, Dict, List, Optional, Sequence, Tuple

from collect import egress
from collect.dns_wire import RRType, Rcode
from core import gate, takeover_rules
from core.takeover import (Corroboration, RegistrationStatus, TakeoverEvidence,
                           TakeoverFinding, TakeoverReport, TakeoverVerdict)

RDAP_OPERATION = "rdap_lookup"


def rdap_lookup(permit, domain: str, budget=None, limiter=None
                ) -> Tuple[RegistrationStatus, str]:
    """Is this registrable domain registered? PASSIVE — RDAP is a public registry.

    Returns UNKNOWN rather than guessing on any failure. A network error must
    never become "unregistered", because that is the input to this product's
    strongest takeover claim.
    """
    url = f"https://rdap.org/domain/{domain}"
    try:
        response = egress.http_get(permit, RDAP_OPERATION, url, budget=budget,
                                   limiter=limiter,
                                   headers={"Accept": "application/rdap+json"})
    except egress.PermitMismatch:
        raise
    except Exception as exc:                       # noqa: BLE001
        return RegistrationStatus.UNKNOWN, f"lookup failed: {exc}"[:120]

    if response.status == 404:
        return RegistrationStatus.UNREGISTERED, "RDAP 404: no registration record"
    if response.status == 200:
        try:
            payload = json.loads(response.text)
        except ValueError:
            return RegistrationStatus.UNKNOWN, "RDAP 200 with unparseable body"
        handle = payload.get("handle") or payload.get("ldhName")
        return RegistrationStatus.REGISTERED, f"RDAP 200: {handle or 'registered'}"
    return RegistrationStatus.UNKNOWN, f"RDAP HTTP {response.status}"


def _dangling(agreement) -> Optional[str]:
    """The CNAME target, if this pair is a CNAME that points somewhere."""
    if agreement.rrtype is not RRType.CNAME or not agreement.agreed:
        return None
    winning = agreement.winning
    if winning.rcode is not Rcode.NOERROR or not winning.values:
        return None
    return winning.values[0]


def assess(sweep, actor: str, scope, resolve_target,
           permit_for_rdap=None, budget=None, limiter=None,
           today: Optional[date] = None) -> TakeoverReport:
    """Assess every CNAME in a sweep.

    `resolve_target(name)` returns an `Agreement` for the target's A record —
    injected so this module never resolves anything itself, and so the tests can
    run without a network.
    """
    now = today or date.today()
    findings: List[TakeoverFinding] = []
    probes_unavailable = 0
    assessed = 0

    for agreement in sweep.agreements:
        target = _dangling(agreement)
        if target is None:
            continue

        target_agreement = resolve_target(target)
        if target_agreement is None or not target_agreement.agreed:
            # We could not establish what the target does. Saying nothing would
            # be indistinguishable from saying it is fine.
            probes_unavailable += 1
            continue

        target_response = target_agreement.winning
        resolves = (target_response.rcode is Rcode.NOERROR
                    and bool(target_response.values))
        if resolves:
            continue          # the target is live; this record is not dangling

        assessed += 1
        agreeing = len(target_agreement.by_state.get(target_response.state, []))
        rule = takeover_rules.match(target)
        base = dict(name=agreement.name, target=target,
                    target_rcode=target_response.rcode.name,
                    resolvers_agreeing=agreeing,
                    resolvers_queried=len(target_agreement.responses),
                    provider=rule.provider if rule else None,
                    rule_catalogue_version=takeover_rules.CATALOGUE_VERSION,
                    rule_last_reviewed=rule.last_reviewed if rule else "",
                    observed_at=now)

        if agreeing < 2:
            probes_unavailable += 1
            continue

        # ---- the headline finding: an expired registrable domain -----------
        registrable = takeover_rules.registrable_domain(target)
        if (rule is None and registrable
                and takeover_rules.registrable_domain_is_reliable(target)
                and permit_for_rdap is not None):
            status, detail = rdap_lookup(permit_for_rdap, registrable,
                                         budget, limiter)
            if status is RegistrationStatus.UNREGISTERED:
                findings.append(TakeoverFinding(
                    TakeoverVerdict.REGISTRABLE_DOMAIN_UNREGISTERED,
                    Corroboration.REGISTRATION_OPEN,
                    TakeoverEvidence(registrable_domain=registrable,
                                     registration_status=status,
                                     rdap_response=detail, **base),
                    (f"the CNAME target {target} does not resolve "
                     f"({target_response.rcode.name})",
                     f"RDAP reports {registrable} unregistered: {detail}")))
                continue

        evidence = TakeoverEvidence(registrable_domain=registrable, **base)

        if rule is not None and rule.guarded:
            findings.append(TakeoverFinding(
                TakeoverVerdict.PROVIDER_GUARDED, Corroboration.PROVIDER_RULE,
                evidence,
                (f"target does not resolve ({target_response.rcode.name})",
                 f"{rule.provider} reserves released hostnames: {rule.note}"
                 if rule.note else f"{rule.provider} reserves released names")))
        elif rule is not None:
            # A known provider that does NOT reserve names. This is the case
            # that would be CLAIMABLE_LOOKING if the ACTIVE tier existed; it
            # stops at INCONCLUSIVE, and the reason says why.
            probes_unavailable += 1
            findings.append(TakeoverFinding(
                TakeoverVerdict.INCONCLUSIVE, Corroboration.PROVIDER_RULE,
                evidence,
                (f"target does not resolve ({target_response.rcode.name})",
                 f"{rule.provider} does not reserve released hostnames, so this "
                 f"MAY be claimable",
                 "confirming would require fetching the target, which is an "
                 "active probe of a third party and is not something this "
                 "product does")))
        else:
            findings.append(TakeoverFinding(
                TakeoverVerdict.NO_CLAIM_SIGNAL_FOUND, Corroboration.NONE,
                evidence,
                (f"target does not resolve ({target_response.rcode.name})",
                 "the target matches no provider in the rule catalogue, and no "
                 "registration signal was obtained")))

    return TakeoverReport(findings=findings,
                          probes_unavailable=probes_unavailable,
                          assessed=assessed)


def rdap_registration(permit, domain: str, budget=None, limiter=None
                      ) -> Dict[str, Any]:
    """Registration detail, including the transfer lock. PASSIVE.

    Separate from `rdap_lookup`, which answers one question — does a
    registration exist — and feeds the takeover verdict. Widening that function
    would put a takeover-critical path at the mercy of extra parsing.

    ONE REDIRECT, FOLLOWED BY HAND. rdap.org is a bootstrap service and answers
    .com with a 302 to the registry's own server, so the registration factor was
    permanently unobservable through it. `egress.http_get` deliberately does not
    follow redirects — urllib's handler would send the request to whatever host
    the response named, with no allowlist check.

    So the target is taken from `redirect_to`, ITS HOST IS CHECKED AGAINST THE
    ALLOWLIST HERE, and a second explicit request is made. Every destination is
    still validated; nothing is followed blindly.
    """
    from urllib.parse import urlparse

    url = f"https://rdap.org/domain/{domain}"
    for _ in range(2):
        try:
            response = egress.http_get(permit, RDAP_OPERATION, url,
                                       budget=budget, limiter=limiter,
                                       headers={"Accept": "application/rdap+json"})
        except egress.PermitMismatch:
            raise
        except Exception as exc:                                # noqa: BLE001
            return {"observed": False,
                    "detail": f"lookup failed: {type(exc).__name__}"}

        if response.redirect_to:
            host = (urlparse(response.redirect_to).hostname or "").lower()
            if host not in egress.ALLOWED_HTTP_HOSTS:
                return {"observed": False,
                        "detail": f"redirected to {host!r}, which is not a "
                                  f"registered source host; not followed"}
            url = response.redirect_to
            continue

        if response.status != 200:
            return {"observed": False, "detail": f"RDAP HTTP {response.status}"}
        try:
            payload = json.loads(response.text)
        except ValueError:
            return {"observed": False, "detail": "RDAP 200, unparseable body"}

        statuses = [str(v).lower() for v in (payload.get("status") or [])]
        # EPP status codes. A client-side transfer lock is the one an owner
        # sets; a server-side one is the registry's. Either means transfer is
        # refused, which is what the factor measures.
        locked = any("transfer prohibited" in v for v in statuses)
        events = {str(e.get("eventAction") or "").lower(): e.get("eventDate")
                  for e in (payload.get("events") or [])}
        return {
            "observed": True,
            "locked": locked,
            "statuses": statuses,
            "registered_on": str(events.get("registration") or "")[:10] or None,
            "expires_on": str(events.get("expiration") or "")[:10] or None,
            "detail": ("transfer is locked" if locked else
                       "NO transfer lock is set on this registration"),
        }
    return {"observed": False, "detail": "too many redirects"}


__all__ = ["rdap_lookup", "rdap_registration", "assess", "RDAP_OPERATION"]
