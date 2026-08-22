"""Ask a service what it is, over HTTP and TLS. Active work, gated.

One module, two callers: fingerprinting uses it now, and takeover corroboration
would use it if the ACTIVE tier is ever approved. Two designs proposed
`http_fingerprint.py` and `http_fp.py` separately; one probe with one permit
check is the point.

WHY ONLY WEB PORTS BY DEFAULT
-----------------------------
`WEB_PORTS` are the ports on which a `Host:`/SNI request is virtual-host routed
to the tenant — which is exactly the reach of a name-based ownership proof. On
any other port the connection is answered by whatever process is listening,
which may belong to somebody else entirely on shared infrastructure. No
top-1000, no full range: the abuse-report and consent surface scales with the
port count while the identity yield does not.

EVERYTHING HERE IS A CLAIM, NOT A FACT
--------------------------------------
A `Server:` header is a string the operator of that box can set to anything. It
is recorded as `SELF_REPORTED` and never as ground truth. A certificate subject
is `INFERRED` — still not a fact, but a side effect of running the software
rather than a statement about it, so it is harder to forge casually.
"""
from __future__ import annotations

import socket
import ssl
from typing import List, Optional, Sequence, Tuple

from collect import egress
from collect.report import Outcome, SourceReport
from core import gate
from core.identity import Attestation, IdentitySignal

#: The only ports where a name-based ownership proof actually covers what answers.
WEB_PORTS: Tuple[int, ...] = (443, 80, 8443, 8080)

OPERATION = "http_probe"
TLS_OPERATION = "tls_handshake"


def _header_signals(response, port: int) -> List[IdentitySignal]:
    signals: List[IdentitySignal] = []
    for header, source in (("server", "http.server"),
                           ("x-powered-by", "http.powered_by"),
                           ("x-generator", "http.powered_by")):
        value = (response.headers or {}).get(header)
        if value:
            signals.append(IdentitySignal(source, str(value)[:200],
                                          Attestation.SELF_REPORTED, port))
    return signals


def probe_http(permit, host: str, address: str, port: int,
               budget=None, limiter=None
               ) -> Tuple[List[IdentitySignal], SourceReport]:
    """Fetch `/` and read what the service says about itself."""
    scheme = "https" if port in (443, 8443) else "http"
    if scheme == "http":
        # egress refuses plaintext, deliberately and for good reasons. Rather
        # than carving an exception into the choke point, port 80 is reported as
        # not attempted — visibly, so the coverage gap is a stated one.
        return [], SourceReport(f"http:{port}", Outcome.DISABLED, 0, 0,
                                "plaintext HTTP is not fetched; see "
                                "collect/egress.py")
    url = f"https://{host}:{port}/"
    try:
        response = egress.http_get(permit, OPERATION, url, budget=budget,
                                   limiter=limiter, address=address,
                                   host_header=host)
    except egress.PermitMismatch:
        raise
    except egress.BudgetExhausted:
        raise
    except Exception as exc:                     # noqa: BLE001
        return [], SourceReport(f"http:{port}", Outcome.FAILED, 0, 0,
                                (str(exc) or type(exc).__name__)[:80])

    signals = _header_signals(response, port)
    if response.redirect_to:
        # Recorded, never followed. Following would carry an active probe to a
        # host no permit covers.
        signals.append(IdentitySignal("http.redirect",
                                      str(response.redirect_to)[:200],
                                      Attestation.INFERRED, port))
    return signals, SourceReport(f"http:{port}", Outcome.OK, len(signals),
                                 len(signals), f"HTTP {response.status}")


def probe_tls(permit, host: str, address: str, port: int,
              budget=None, limiter=None
              ) -> Tuple[List[IdentitySignal], SourceReport]:
    """Read the certificate. INFERRED, because it is a side effect of serving.

    # NETWORK-BOUNDARY: tls_handshake
    """
    budget = budget or egress.Budget()
    limiter = limiter or egress.Limiter(budget)
    egress.require(permit, TLS_OPERATION, exposure=gate.Exposure.ACTIVE,
                   address=address, port=port)
    limiter.acquire(address)

    context = ssl.create_default_context()
    # The certificate is being READ, not trusted — a self-signed or expired
    # certificate is exactly the case worth identifying, and refusing to look at
    # it would blind the probe to the hosts that matter most.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    signals: List[IdentitySignal] = []
    try:
        with socket.create_connection((address, port),
                                      timeout=budget.connect_timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                if not cert:
                    der = tls.getpeercert(binary_form=True)
                    if der:
                        signals.append(IdentitySignal(
                            "tls.present", "certificate presented, unparsed",
                            Attestation.INFERRED, port))
                else:
                    for field, source in (("subject", "tls.subject"),
                                          ("issuer", "tls.issuer")):
                        parts = cert.get(field) or ()
                        rendered = ", ".join(
                            f"{k}={v}" for rdn in parts for k, v in rdn)
                        if rendered:
                            signals.append(IdentitySignal(
                                source, rendered[:200], Attestation.INFERRED, port))
    except egress.PermitMismatch:
        raise
    except Exception as exc:                     # noqa: BLE001
        return [], SourceReport(f"tls:{port}", Outcome.FAILED, 0, 0,
                                (str(exc) or type(exc).__name__)[:80])
    return signals, SourceReport(f"tls:{port}", Outcome.OK, len(signals),
                                 len(signals))


def probe(permit, host: str, address: str,
          ports: Sequence[int] = WEB_PORTS,
          budget=None, limiter=None
          ) -> Tuple[List[IdentitySignal], List[SourceReport], List[int]]:
    """Every signal this host will give up, with per-port reports.

    Returns `(signals, reports, open_ports)`. `open_ports` is what answered —
    the reachability half of the outside-in/inside-out reconciliation, which
    until now has been `external_reachable=None` on every finding.
    """
    signals: List[IdentitySignal] = []
    reports: List[SourceReport] = []
    open_ports: List[int] = []

    for port in ports:
        tls_signals, tls_report = ([], None)
        if port in (443, 8443):
            tls_signals, tls_report = probe_tls(permit, host, address, port,
                                                budget, limiter)
            reports.append(tls_report)
            signals.extend(tls_signals)

        http_signals, http_report = probe_http(permit, host, address, port,
                                               budget, limiter)
        reports.append(http_report)
        signals.extend(http_signals)

        if http_report.answered or (tls_report is not None and tls_report.answered):
            open_ports.append(port)

    return signals, reports, open_ports
