"""What is worth interrupting somebody for, and what is merely true.

THE HARD PART IS NOT DELIVERY
-----------------------------
P1 already computes run-over-run diff, keyed on `(asset, cve)`. Turning that
into notifications is plumbing. The part that decides whether anybody keeps the
integration switched on is the rule about what NOT to send.

An alert feed that fires on everything that changed is one nobody reads, and an
unread feed is worse than no feed because it is mistaken for coverage. So the
default set is deliberately narrow — three triggers, each of which represents
something an operator would want to be woken for:

  * a NEW finding at or above a threshold band
  * a NEW takeover finding
  * a DNS record that DISAPPEARED conclusively

Everything else is available and off. In particular a band change is NOT a
trigger by default: EPSS moves daily, TEPS moves with it, and a feed that fires
whenever a score crosses a boundary trains the reader to ignore it — which is
the same reasoning that made `(asset, cve)` the diff key rather than the score.

WHAT AN ALERT MUST CARRY
------------------------
Enough to act without opening the console, and enough to argue with. A
notification saying "3 new critical findings" is a prompt to go and look, which
is what the console is for; it is not an alert. Every alert carries the asset,
the CVE, the score with its basis, and the evidence.
"""
from __future__ import annotations

import enum
import json
import os
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Callable, Dict, List, Optional, Sequence

# NETWORK-BOUNDARY: alert_dispatch

BANDS = ("informational", "low", "medium", "high", "critical")


class Trigger(str, enum.Enum):
    NEW_FINDING = "new_finding"
    NEW_TAKEOVER = "new_takeover"
    DNS_DISAPPEARED = "dns_disappeared"
    #: Off by default. See the module docstring — EPSS moves daily and a feed
    #: that fires on score drift is one nobody reads.
    BAND_CHANGED = "band_changed"
    #: Off by default. A resolved finding is good news, and good news does not
    #: need to interrupt anybody.
    FINDING_RESOLVED = "finding_resolved"


DEFAULT_TRIGGERS = (Trigger.NEW_FINDING, Trigger.NEW_TAKEOVER,
                    Trigger.DNS_DISAPPEARED)


@dataclass(frozen=True)
class Alert:
    trigger: Trigger
    subject: str
    body: str
    #: The structured payload, for a webhook consumer that wants to route on it
    #: rather than parse prose.
    detail: Dict[str, Any] = field(default_factory=dict)
    at: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"trigger": self.trigger.value, "subject": self.subject,
                "body": self.body, "detail": self.detail,
                "at": self.at or datetime.now(timezone.utc).isoformat(timespec="seconds")}


@dataclass(frozen=True)
class Policy:
    """What this installation considers worth sending."""

    triggers: Sequence[Trigger] = DEFAULT_TRIGGERS
    #: Findings below this band are not alerted on, however new they are.
    minimum_band: str = "high"
    #: A hard ceiling per run. A first scan of a large estate legitimately
    #: produces hundreds of new findings, and mailing all of them is how an
    #: integration gets switched off on day one.
    max_alerts: int = 25

    def band_at_least(self, band: str) -> bool:
        try:
            return BANDS.index(band) >= BANDS.index(self.minimum_band)
        except ValueError:
            # An unrecognised band is alerted on rather than dropped. A band we
            # do not know about is more likely a new severity than a mistake,
            # and silently swallowing it is the wrong direction of error.
            return True


def build(diff, takeover_new: Sequence[Dict[str, Any]] = (),
          dns_changes: Sequence[Any] = (),
          policy: Optional[Policy] = None) -> Dict[str, Any]:
    """Alerts for one run, plus what was suppressed and why.

    Returns the suppressed count deliberately. An operator who receives 25
    alerts needs to know whether that was everything or a cap, or the cap
    becomes a silent filter on their view of their own estate.
    """
    policy = policy or Policy()
    alerts: List[Alert] = []
    below_band = 0

    if Trigger.NEW_FINDING in policy.triggers:
        for finding in getattr(diff, "new", []) or []:
            band = str(finding.get("band") or "")
            if not policy.band_at_least(band):
                below_band += 1
                continue
            alerts.append(_finding_alert(finding))

    if Trigger.BAND_CHANGED in policy.triggers:
        for finding in getattr(diff, "reband", []) or []:
            if policy.band_at_least(str(finding.get("band") or "")):
                alerts.append(_reband_alert(finding))

    if Trigger.NEW_TAKEOVER in policy.triggers:
        for finding in takeover_new:
            alerts.append(_takeover_alert(finding))

    if Trigger.DNS_DISAPPEARED in policy.triggers:
        for change in dns_changes:
            alerts.append(_dns_alert(change))

    capped = max(0, len(alerts) - policy.max_alerts)
    return {
        "alerts": alerts[:policy.max_alerts],
        "suppressed_below_band": below_band,
        "suppressed_by_cap": capped,
        "minimum_band": policy.minimum_band,
        "note": _note(len(alerts), below_band, capped, policy),
    }


def _note(total: int, below_band: int, capped: int, policy: Policy) -> str:
    if not total and not below_band:
        return "Nothing met the alert policy this run."
    parts = [f"{min(total, policy.max_alerts)} alert(s)"]
    if below_band:
        parts.append(f"{below_band} new finding(s) below {policy.minimum_band} "
                     f"were not sent — they are in the console, not lost")
    if capped:
        parts.append(f"{capped} more were CAPPED at {policy.max_alerts}. That is "
                     f"a limit on the notification, not on the findings")
    return ". ".join(parts) + "."


def _finding_alert(finding: Dict[str, Any]) -> Alert:
    asset = finding.get("asset", "?")
    cve = finding.get("cve", "?")
    band = finding.get("band", "?")
    basis = finding.get("basis", "product_match")
    # The basis belongs in the subject line. "Confirmed vulnerable" and "runs a
    # product with an exploited vulnerability" warrant different urgency, and an
    # alert that hides the difference makes every entry read like the first.
    kind = ("CONFIRMED by version" if basis == "version_range"
            else "worklist — version unverified")
    return Alert(
        trigger=Trigger.NEW_FINDING,
        subject=f"[{band.upper()}] {cve} on {asset} ({kind})",
        body="\n".join([
            f"Asset      {asset}",
            f"Product    {finding.get('product', '?')}",
            f"CVE        {cve}  ({finding.get('vulnerability', '')})",
            f"TEPS       {finding.get('teps', '?')} ({band})",
            f"Basis      {basis} — {kind}",
            f"Ransomware {'yes' if finding.get('known_ransomware') else 'no'}",
            f"Due        {finding.get('due_date') or 'no CISA due date'}",
            "",
            "Evidence:",
            *[f"  - {e}" for e in (finding.get("evidence") or [])],
        ]),
        detail=dict(finding))


def _reband_alert(finding: Dict[str, Any]) -> Alert:
    return Alert(
        trigger=Trigger.BAND_CHANGED,
        subject=(f"[{finding.get('band','?').upper()}] {finding.get('cve','?')} on "
                 f"{finding.get('asset','?')} moved from "
                 f"{finding.get('previous_band','?')}"),
        body=(f"The score changed; the finding is not new. "
              f"{finding.get('previous_band','?')} -> {finding.get('band','?')}, "
              f"TEPS {finding.get('teps','?')}."),
        detail=dict(finding))


def _takeover_alert(finding: Dict[str, Any]) -> Alert:
    verdict = str(finding.get("verdict", "?"))
    return Alert(
        trigger=Trigger.NEW_TAKEOVER,
        subject=f"[TAKEOVER] {finding.get('name','?')} -> {finding.get('target','?')}",
        body="\n".join([
            f"Verdict    {verdict}",
            f"Target     {finding.get('target','?')} "
            f"({finding.get('target_rcode','?')})",
            f"Resolvers  {finding.get('resolvers_agreeing','?')} agreeing",
            "",
            "Why:",
            *[f"  - {r}" for r in (finding.get("reasons") or [])],
            "",
            "This product never reports a subdomain as 'vulnerable'. The only "
            "experiment that would establish it is registering the resource, "
            "which it refuses to perform.",
        ]),
        detail=dict(finding))


def _dns_alert(change) -> Alert:
    name = getattr(change, "name", "?")
    rrtype = getattr(change, "rrtype", "?")
    return Alert(
        trigger=Trigger.DNS_DISAPPEARED,
        subject=f"[DNS] {name} {rrtype} no longer resolves",
        body=(getattr(change, "explain", lambda: "")()
              or f"{name} {rrtype} disappeared.")
        + "\n\nThis is a CONCLUSIVE disappearance — a resolver answered and "
          "answered that it no longer exists. A resolver outage is reported "
          "separately and never as this.",
        detail={"name": name, "rrtype": rrtype})


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------
class DeliveryFailed(RuntimeError):
    """A channel could not deliver. Never swallowed — an alert nobody received
    and nobody knows was not received is the worst state available."""


def send_webhook(url: str, alerts: Sequence[Alert],
                 timeout: float = 10.0) -> int:
    """POST the batch as JSON. One request, not one per alert.

    A webhook covers Slack, Teams, PagerDuty and anything else an operator
    already runs, which is why there are no per-vendor SDKs here — each would be
    a dependency and a credential for a capability this already has.
    """
    if not url.startswith("https://"):
        raise DeliveryFailed(
            f"{url!r} is not https. Findings name your unpatched systems; they "
            f"do not go over plaintext.")
    payload = json.dumps({"alerts": [a.as_dict() for a in alerts]}).encode("utf-8")
    request = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "SKOPOS/0.5"})
    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=ssl.create_default_context()) as response:
            if response.status >= 300:
                raise DeliveryFailed(f"webhook returned HTTP {response.status}")
    except urllib.error.URLError as exc:
        raise DeliveryFailed(f"webhook delivery failed: {exc}") from exc
    return len(alerts)


def send_email(alerts: Sequence[Alert], to: str, sender: str,
               host: str, port: int = 587,
               username: Optional[str] = None,
               password: Optional[str] = None,
               timeout: float = 20.0) -> int:
    """One message carrying the batch.

    One message rather than one per alert: twenty-five separate emails about the
    same scan is how a mailbox rule gets written, and a rule that files SKOPOS
    into a folder is indistinguishable from the integration being off.
    """
    if not alerts:
        return 0
    message = EmailMessage()
    message["Subject"] = (f"SKOPOS: {len(alerts)} alert(s) — "
                          f"{alerts[0].subject[:60]}"
                          + (" and others" if len(alerts) > 1 else ""))
    message["From"] = sender
    message["To"] = to
    message.set_content("\n\n".join(
        f"{'=' * 70}\n{a.subject}\n{'=' * 70}\n{a.body}" for a in alerts))
    try:
        with smtplib.SMTP(host, port, timeout=timeout) as server:
            server.starttls(context=ssl.create_default_context())
            if username:
                server.login(username, password or "")
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise DeliveryFailed(f"email delivery failed: {exc}") from exc
    return len(alerts)


def dispatch(alerts: Sequence[Alert],
             webhook_url: Optional[str] = None,
             email_to: Optional[str] = None) -> Dict[str, Any]:
    """Send through every configured channel, reporting each independently.

    A channel that fails does not stop the others, and every outcome is
    returned. Silently dropping a channel would mean an operator believing they
    are covered by a route that has been broken for weeks.
    """
    results: Dict[str, Any] = {}
    if not alerts:
        return {"sent": 0, "channels": {}, "note": "nothing to send"}

    webhook_url = webhook_url or os.environ.get("SKOPOS_ALERT_WEBHOOK")
    if webhook_url:
        try:
            results["webhook"] = {"ok": True,
                                  "sent": send_webhook(webhook_url, alerts)}
        except DeliveryFailed as exc:
            results["webhook"] = {"ok": False, "error": str(exc)}

    email_to = email_to or os.environ.get("SKOPOS_ALERT_EMAIL")
    if email_to:
        host = os.environ.get("SKOPOS_SMTP_HOST")
        if not host:
            results["email"] = {"ok": False,
                                "error": "SKOPOS_SMTP_HOST is not set"}
        else:
            try:
                results["email"] = {"ok": True, "sent": send_email(
                    alerts, email_to,
                    os.environ.get("SKOPOS_SMTP_FROM", "skopos@localhost"),
                    host, int(os.environ.get("SKOPOS_SMTP_PORT", "587")),
                    os.environ.get("SKOPOS_SMTP_USER"),
                    os.environ.get("SKOPOS_SMTP_PASSWORD"))}
            except DeliveryFailed as exc:
                results["email"] = {"ok": False, "error": str(exc)}

    if not results:
        return {"sent": 0, "channels": {},
                "note": ("no alert channel is configured. Set "
                         "SKOPOS_ALERT_WEBHOOK or SKOPOS_ALERT_EMAIL — until "
                         "then alerts are computed and not delivered, which is "
                         "reported here rather than silently.")}
    return {"sent": sum(c.get("sent", 0) for c in results.values()),
            "channels": results,
            "note": ("one or more channels failed; see channels"
                     if any(not c.get("ok") for c in results.values())
                     else "delivered")}


#: Delivery from a scan run is OFF unless this is set to a true-ish value.
#:
#: A scan is already an action somebody took, so it is tempting to treat
#: delivery as part of it. It is not the same act: running a scan describes
#: your estate to YOURSELF, and delivering alerts describes it to a webhook
#: endpoint or a mail server, which is a third party even when you own it.
#: Consent to the first is not consent to the second.
ON_SCAN_ENV = "SKOPOS_ALERT_ON_SCAN"

_TRUE = {"1", "true", "yes", "on"}


def delivery_enabled(value: Optional[str] = None) -> bool:
    raw = value if value is not None else os.environ.get(ON_SCAN_ENV, "")
    return str(raw).strip().lower() in _TRUE


def deliver_for_run(diff, takeover_new: Sequence[Dict[str, Any]] = (),
                    dns_changes: Sequence[Any] = (),
                    policy: Optional[Policy] = None,
                    enabled: Optional[bool] = None,
                    webhook_url: Optional[str] = None,
                    email_to: Optional[str] = None) -> Dict[str, Any]:
    """Decide, then deliver only if delivery is switched on. Always report both.

    The single entry point for both the API scan route and the CLI, so the two
    cannot drift into different rules about when a customer's findings leave the
    building.

    THE RETURN VALUE ALWAYS SAYS WHICH STATE IT WAS IN. There are four, and
    three of them are "nothing was sent":

      * nothing met the policy — a quiet run, which is a result
      * delivery is off — decided and deliberately not sent
      * delivery is on, no channel configured — a misconfiguration that would
        otherwise look exactly like a quiet run
      * delivered, per channel, including partial failure

    The third is the one this exists for. An operator who switched delivery on
    and set no webhook has a silent integration, and a silent alerting
    integration is worse than none because it is mistaken for coverage.
    """
    decided = build(diff, takeover_new=takeover_new, dns_changes=dns_changes,
                    policy=policy)
    alerts: List[Alert] = decided["alerts"]
    report: Dict[str, Any] = {
        "decided": len(alerts),
        "suppressed_below_band": decided["suppressed_below_band"],
        "suppressed_by_cap": decided["suppressed_by_cap"],
        "minimum_band": decided["minimum_band"],
        "note": decided["note"],
        "delivered": False,
        "channels": {},
    }

    if not alerts:
        report["reason"] = ("nothing met the alert policy, so there was nothing "
                            "to deliver. A quiet run is a result, not a failure")
        return report

    if enabled is None:
        enabled = delivery_enabled()
    if not enabled:
        report["reason"] = (
            f"{len(alerts)} alert(s) were decided and NOT delivered: "
            f"{ON_SCAN_ENV} is not set. Running a scan describes your estate "
            f"to yourself; delivering alerts describes it to a third party, "
            f"and consent to the first is not consent to the second")
        return report

    sent = dispatch(alerts, webhook_url=webhook_url, email_to=email_to)
    report["channels"] = sent.get("channels", {})
    report["delivered"] = bool(sent.get("sent"))
    if not report["channels"]:
        report["reason"] = (
            f"{ON_SCAN_ENV} is on and NO CHANNEL IS CONFIGURED, so nothing was "
            f"sent. This looks identical to a quiet run from the outside, which "
            f"is why it is reported here: set SKOPOS_ALERT_WEBHOOK or "
            f"SKOPOS_ALERT_EMAIL")
    else:
        failed = sorted(name for name, c in report["channels"].items()
                        if not c.get("ok"))
        report["reason"] = (
            f"delivered {sent.get('sent', 0)} alert(s)" if not failed
            else f"channel(s) failed: {', '.join(failed)}. An alert nobody "
                 f"received and nobody knows was not received is the worst "
                 f"state available, so the failure is returned rather than "
                 f"logged and forgotten")
    return report


__all__ = ["Trigger", "DEFAULT_TRIGGERS", "Alert", "Policy", "build",
           "deliver_for_run", "delivery_enabled", "ON_SCAN_ENV",
           "dispatch", "send_webhook", "send_email", "DeliveryFailed", "BANDS"]
