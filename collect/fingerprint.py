"""Run the probe over an inventory, under permits, and write what joins.

This is the step that connects discovery to scoring. Everything upstream of it
produces names; `core/match.py` joins on products; and the gap between the two
is why a 400-host discovery currently yields zero findings.

THE GATE IS ASKED PER HOST, AND THE ANSWER IS NOT ASSUMED
---------------------------------------------------------
Every host needs its own permit, because ownership is proven per name and
expires per name. A host whose verification lapsed is refused mid-run and the
refusal is REPORTED — not skipped, not counted as "nothing found". A partial run
and a clean estate must never render the same way.

Resolution happens here rather than inside egress so the addresses can be sealed
onto the permit before anything connects. `gate.authorise_target()` then applies
CIDR exclusions, which is the only way an exclusion can reach an operation that
was authorised by name.
"""
from __future__ import annotations

import socket
from typing import Dict, List, Optional, Sequence, Tuple

from collect import egress, http_probe
from collect.report import Coverage, Outcome, SourceReport
from core import gate, signatures
from core.identity import Attestation, Fingerprint, FingerprintRun, IdentitySignal
from core.models import Asset
from core.ownership import OwnershipNotVerified


def resolve(host: str) -> List[str]:
    """Addresses for a name, so they can be sealed onto the permit.

    # NETWORK-BOUNDARY: dns_resolve_recursive
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    # Ordered and de-duplicated: a set would make the sealed permit's address
    # tuple vary between runs, and a permit that differs run to run is one
    # nobody can reproduce from an audit record.
    seen: List[str] = []
    for info in infos:
        address = info[4][0]
        if address not in seen:
            seen.append(address)
    return seen


def fingerprint_host(host: str, actor: str, scope, verification,
                     ports: Sequence[int] = http_probe.WEB_PORTS,
                     budget=None, limiter=None,
                     table: Sequence = signatures.SIGNATURES,
                     ) -> Tuple[Optional[Fingerprint], List[SourceReport], str]:
    """One host. Returns `(fingerprint, reports, refusal)`.

    `refusal` is a non-empty sentence when the gate said no, and the caller
    records it rather than dropping the host.
    """
    addresses = resolve(host)
    if not addresses:
        return None, [SourceReport(host, Outcome.FAILED, 0, 0,
                                   "name did not resolve")], ""

    try:
        permit = gate.authorise_target(host, addresses, http_probe.OPERATION,
                                       actor, scope, verification)
    except (gate.NotInScope, OwnershipNotVerified, gate.OperationRefused) as exc:
        return None, [], str(exc)

    signals, reports, open_ports = http_probe.probe(
        permit, host, addresses[0], ports, budget, limiter)

    signature, supporting = signatures.identify(signals, table)
    fingerprint = Fingerprint(
        host=host,
        product=signature.product if signature else "unidentified",
        vendor=signature.vendor if signature else None,
        observed_version=_version_from(signals),
        attestation=(signature.attestation if signature else None),
        signals=signals,
        open_ports=tuple(open_ports),
        probed_ports=tuple(ports),
    )
    return fingerprint, reports, ""


_VERSION_SOURCES = ("http.server", "http.powered_by")


def _version_from(signals: Sequence[IdentitySignal]) -> Optional[str]:
    """Pull a version out of a banner, for the record only.

    This NEVER reaches `Asset.version`. It is written to `obs_version`, which is
    not in `inventory.ALIASES["version"]`, so `affected.evaluate()` cannot see
    it. See core/identity.py for why that matters: `engine.score_exposure` marks
    NOT_AFFECTED as a VERSION_RANGE determination and RETIRES the finding, so a
    spoofed high version would delete entries from the customer's worklist.
    """
    import re
    for signal in signals:
        if signal.source in _VERSION_SOURCES:
            found = re.search(r"(\d+\.[\d.]+)", str(signal.value or ""))
            if found:
                return found.group(1)
    return None


def run(hosts: Sequence[str], actor: str, scope, verifications: Dict,
        ports: Sequence[int] = http_probe.WEB_PORTS,
        budget=None, limiter=None,
        table: Sequence = signatures.SIGNATURES) -> Tuple[FingerprintRun, Coverage]:
    """Fingerprint an inventory. Refusals and unattempted hosts are reported."""
    outcome = FingerprintRun()
    coverage = Coverage()
    limiter = limiter or egress.Limiter(budget or egress.Budget())

    for index, host in enumerate(hosts):
        try:
            fingerprint, reports, refusal = fingerprint_host(
                host, actor, scope, verifications.get(host), ports,
                budget, limiter, table)
        except egress.BudgetExhausted as exc:
            # Everything from here on is NOT ATTEMPTED, and is named. A run cut
            # short and an estate with nothing exposed otherwise produce
            # identical output.
            outcome.unattempted.extend(hosts[index:])
            coverage.add(SourceReport("budget", Outcome.PARTIAL,
                                      len(outcome.fingerprints), len(hosts),
                                      str(exc)[:120]))
            break

        for report in reports:
            coverage.add(report)
        if refusal:
            outcome.refused.append((host, refusal))
            coverage.add(SourceReport(host, Outcome.REFUSED, 0, 0, refusal[:120]))
        elif fingerprint is not None:
            outcome.fingerprints.append(fingerprint)

    return outcome, coverage


def to_inventory_rows(outcome: FingerprintRun,
                      base: Optional[Sequence[Dict]] = None) -> List[Dict]:
    """Merge fingerprints onto an existing inventory, preserving its columns.

    Union-preserving: an operator inventory carrying `owner`, `environment` or a
    `cve` column keeps them. A closed column list through csv.DictWriter either
    raises on those or, with extrasaction='ignore', silently blanks them —
    destroying `owner`, which core/models.py calls the whole objective.
    """
    from core.provenance import write_rows

    additions = {f.host: f.inventory_row() for f in outcome.fingerprints}
    merged: List[Dict] = []
    seen = set()

    for row in (base or []):
        host = str(row.get("identifier") or row.get("hostname") or "").strip()
        combined = dict(row)
        if host in additions:
            combined.update(additions[host])
            seen.add(host)
        merged.append(combined)

    for host, row in additions.items():
        if host not in seen:
            merged.append(row)

    return write_rows(merged)
