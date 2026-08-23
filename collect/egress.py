"""The only module in SKOPOS that touches the network.

# NETWORK-BOUNDARY: ct_log_search
# NETWORK-BOUNDARY: subdomain_index_read
# NETWORK-BOUNDARY: web_archive_search
# NETWORK-BOUNDARY: passive_dns
# NETWORK-BOUNDARY: rdap_lookup
# NETWORK-BOUNDARY: advisory_lookup
# NETWORK-BOUNDARY: dns_resolve_recursive
# NETWORK-BOUNDARY: dns_resolve_authoritative
# NETWORK-BOUNDARY: dns_wildcard_probe
# NETWORK-BOUNDARY: http_probe
# NETWORK-BOUNDARY: tls_handshake
# NETWORK-BOUNDARY: port_scan
# NETWORK-BOUNDARY: service_banner_read

Three subsystems each designed their own egress layer. Collapsing them into one
is not tidiness — it is the only way the permit check can be asserted ONCE. The
alternative, which all three designs independently arrived at, puts the check
inside each of eight source modules, which is precisely the "every collector
remembers" pattern `core/gate.py` exists to reject.

WHAT IS ENFORCED HERE, NOT BY CALLERS
-------------------------------------
* the permit authorises this exact operation and asset
* the port is one the operation is allowed to reach
* the address is one the permit sealed, and is connected to WITHOUT re-resolving
* HTTPS only; no redirects by default
* three rate buckets — address, /24, and run-wide
* a budget, whose exhaustion is loud and names what was not attempted

RATE LIMITING NEEDS ALL THREE BUCKETS
-------------------------------------
Per-address alone is not enough: 400 hosts on 400 distinct addresses inside one
/22 behind a single firewall is ~400 new flows per second with every per-address
budget respected, and that fills a state table. Per-hostname is wrong in the
other direction: certificate transparency routinely yields hundreds of names
behind one CDN address, so hostname keying would deliver a several-hundred-fold
amplification to one server.

A RESET IS AN ANSWER
--------------------
Never retry on RST. The port is closed; retrying produces traffic that looks
like a scan and adds nothing.
"""
from __future__ import annotations

import http.client
import json
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, Iterator, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core import gate


class PermitMismatch(PermissionError):
    """The permit does not authorise the work being attempted."""


class BudgetExhausted(RuntimeError):
    """The run hit its own ceiling. What was not attempted must be reported."""


class RateLimited(RuntimeError):
    """A source told us to back off for longer than we are willing to wait."""


#: Ports each operation may reach. Without this, an `http_probe` permit reads
#: the MySQL greeting on 3306 through the approved helper and every check passes.
PORTS_BY_OPERATION: Dict[str, frozenset] = {
    "http_probe": frozenset({80, 443, 8080, 8443}),
    "tls_handshake": frozenset({443, 8443, 993, 995, 465}),
    "dns_resolve_recursive": frozenset({53}),
    "dns_resolve_authoritative": frozenset({53}),
    "dns_wildcard_probe": frozenset({53}),
    # Set by the caller's declared probe set, intersected with this ceiling.
    "port_scan": frozenset({21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993,
                            995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
                            27017}),
    "service_banner_read": frozenset({21, 22, 25, 110, 143, 587, 3306, 5432,
                                      6379, 9200, 27017}),
}

#: Hosts the HTTP helper may contact. A destination is never a free-form caller
#: argument: `--resolvers 10.0.0.53` would otherwise aim every query at customer
#: infrastructure under a PASSIVE permit that required no ownership proof.
ALLOWED_HTTP_HOSTS: frozenset = frozenset({
    "crt.sh", "api.certspotter.com",
    "jldc.me", "api.hackertarget.com",
    "web.archive.org",
    "api.mnemonic.no", "otx.alienvault.com",
    "rdap.org", "rdap.verisign.com", "www.rdap.net",
    "api.osv.dev", "euvdservices.enisa.europa.eu",
})

#: Third-party recursive resolvers. Not the customer's.
DEFAULT_RESOLVERS: Tuple[str, ...] = ("1.1.1.1", "8.8.8.8", "9.9.9.9")

#: Above this, do not sleep. An uncapped honour of `Retry-After: 86400` hangs a
#: synchronous CLI for a day.
MAX_RETRY_AFTER = 30.0

MAX_CONCURRENCY = 32


@dataclass(frozen=True)
class Budget:
    connect_timeout: float = 5.0
    read_timeout: float = 5.0
    per_address_interval: float = 0.5
    per_address_burst: int = 2
    per_network_interval: float = 0.1     # keyed on the containing /24
    global_interval: float = 0.05         # 20 connections/sec, run-wide
    concurrency: int = 8
    max_body_bytes: int = 65536
    max_redirects: int = 0
    run_seconds: Optional[float] = 900.0
    max_queries: Optional[int] = 50_000


@dataclass
class HttpResponse:
    status: int
    body: bytes
    headers: Dict[str, str] = field(default_factory=dict)
    truncated: bool = False
    #: A cross-host redirect is recorded rather than followed — following would
    #: carry an ACTIVE probe to a host no permit covers.
    redirect_to: Optional[str] = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


class Limiter:
    """Address, network and run-wide buckets, all traversed on every acquire."""

    def __init__(self, budget: Optional[Budget] = None,
                 clock=time.monotonic, sleep=time.sleep) -> None:
        self.budget = budget or Budget()
        self._clock, self._sleep = clock, sleep
        self._lock = threading.Lock()
        self._address_last: Dict[str, float] = {}
        self._network_last: Dict[str, float] = {}
        self._global_last = 0.0
        self._started = clock()
        self._queries = 0

    @staticmethod
    def _network(address: str) -> str:
        parts = str(address).split(".")
        return ".".join(parts[:3]) if len(parts) == 4 else str(address)

    def remaining_seconds(self) -> Optional[float]:
        if self.budget.run_seconds is None:
            return None
        return self.budget.run_seconds - (self._clock() - self._started)

    def acquire(self, address: str) -> None:
        """Wait out all three buckets, or raise if the run's budget is spent."""
        with self._lock:
            if self.budget.max_queries is not None and \
                    self._queries >= self.budget.max_queries:
                raise BudgetExhausted(
                    f"the run's query budget of {self.budget.max_queries} is "
                    f"spent; everything not attempted is reported unattempted")
            left = self.remaining_seconds()
            if left is not None and left <= 0:
                raise BudgetExhausted(
                    f"the run's time budget of {self.budget.run_seconds:.0f}s is "
                    f"spent; everything not attempted is reported unattempted")

            now = self._clock()
            waits = [
                self._address_last.get(address, 0.0)
                + self.budget.per_address_interval - now,
                self._network_last.get(self._network(address), 0.0)
                + self.budget.per_network_interval - now,
                self._global_last + self.budget.global_interval - now,
            ]
            delay = max([w for w in waits] + [0.0])
            if delay > 0:
                self._sleep(delay)
                now = self._clock()
            self._address_last[address] = now
            self._network_last[self._network(address)] = now
            self._global_last = now
            self._queries += 1


def require(permit, operation: str, *, exposure: "gate.Exposure",
            asset: Optional[str] = None, address: Optional[str] = None,
            port: Optional[int] = None) -> None:
    """Raise unless the permit authorises exactly this work.

    Explicit `raise`, never `assert`. `python -O` deletes asserts, and a security
    check that a compiler flag removes is not a security check.
    """
    if permit is None:
        raise PermitMismatch(
            f"{operation!r} requires a Permit from core.gate.authorise(); "
            f"none was supplied. Collectors do not decide what they may touch.")

    # authorise() stores the RAW operation and asset while classify() normalises,
    # so 'CT_Log_Search' yields a permit a naive == would reject.
    want = str(operation).strip().lower()
    held = str(permit.operation).strip().lower()
    if held != want:
        raise PermitMismatch(
            f"permit authorises {permit.operation!r}, not {operation!r}")

    if permit.exposure is not exposure:
        raise PermitMismatch(
            f"permit is {permit.exposure.value}, but {operation!r} is "
            f"{exposure.value}")

    if asset is not None and \
            str(permit.asset).strip().lower() != str(asset).strip().lower():
        raise PermitMismatch(
            f"permit is for {permit.asset!r}, not {asset!r}")

    if port is not None:
        allowed = PORTS_BY_OPERATION.get(want)
        if allowed is not None and int(port) not in allowed:
            raise PermitMismatch(
                f"{operation!r} may not reach port {port}. Allowed: "
                f"{sorted(allowed)}. A permit for one kind of service is not a "
                f"permit to read whatever else answers.")

    if address is not None and exposure is gate.Exposure.ACTIVE:
        if not permit.addresses:
            raise PermitMismatch(
                f"an active operation must be authorised against addresses; "
                f"this permit is name-only. Use gate.authorise_target().")
        if str(address) not in permit.addresses:
            raise PermitMismatch(
                f"permit does not cover address {address!r} "
                f"(sealed: {', '.join(permit.addresses)}). Connecting to a "
                f"freshly resolved address would defeat the check.")


@contextmanager
def tcp(permit, operation: str, address: str, port: int,
        budget: Optional[Budget] = None,
        limiter: Optional[Limiter] = None) -> Iterator[socket.socket]:
    """A TCP connection to a sealed address. Never re-resolves."""
    budget = budget or Budget()
    limiter = limiter or Limiter(budget)
    exposure = gate.classify(operation)
    require(permit, operation, exposure=exposure, address=address, port=port)
    limiter.acquire(address)

    sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET,
                         socket.SOCK_STREAM)
    sock.settimeout(budget.connect_timeout)
    try:
        sock.connect((address, int(port)))
        sock.settimeout(budget.read_timeout)
        yield sock
    finally:
        try:
            sock.close()
        except OSError:
            pass


def udp(permit, operation: str, address: str, port: int, payload: bytes,
        budget: Optional[Budget] = None,
        limiter: Optional[Limiter] = None,
        allowed: Optional[Sequence[str]] = None) -> bytes:
    """One UDP exchange with a sealed or allow-listed address."""
    budget = budget or Budget()
    limiter = limiter or Limiter(budget)
    exposure = gate.classify(operation)
    permitted_addresses = tuple(allowed) if allowed is not None else DEFAULT_RESOLVERS

    if exposure is gate.Exposure.PASSIVE and str(address) not in permitted_addresses:
        # A passive permit required no ownership proof, so the destination must
        # not be a free-form argument. A caller may subset the allowlist, never
        # extend it.
        raise PermitMismatch(
            f"{operation!r} is passive and may only query the declared "
            f"third-party resolvers {list(permitted_addresses)}; {address!r} is "
            f"not one. Aiming this at customer infrastructure would be active "
            f"work under a permit that proved nothing.")

    require(permit, operation, exposure=exposure, address=address, port=port)
    limiter.acquire(address)

    sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET,
                         socket.SOCK_DGRAM)
    sock.settimeout(budget.read_timeout)
    try:
        sock.sendto(payload, (address, int(port)))
        data, _ = sock.recvfrom(4096)
        return data
    finally:
        try:
            sock.close()
        except OSError:
            pass


def http_get(permit, operation: str, url: str, *,
             budget: Optional[Budget] = None,
             limiter: Optional[Limiter] = None,
             headers: Optional[Dict[str, str]] = None,
             host_header: Optional[str] = None,
             address: Optional[str] = None,
             max_redirects: int = 0) -> HttpResponse:
    """An HTTPS GET, with no redirects and a capped body."""
    budget = budget or Budget()
    limiter = limiter or Limiter(budget)
    exposure = gate.classify(operation)

    parts = urlsplit(url)
    if parts.scheme != "https":
        # An on-path attacker who can silently DELETE hostnames from a plaintext
        # response shrinks the reported estate, and no source reports FAILED —
        # the exact "thin result looks like a small estate" failure, arriving
        # through the one source that did not use TLS.
        raise PermitMismatch(
            f"{url!r} is not https. This product does not fetch collection "
            f"input over plaintext.")

    host = parts.hostname or ""
    port = parts.port or 443

    if exposure is gate.Exposure.PASSIVE:
        if host not in ALLOWED_HTTP_HOSTS:
            raise PermitMismatch(
                f"{host!r} is not a registered source host. Passive collection "
                f"reaches a declared list, not an arbitrary destination.")
        require(permit, operation, exposure=exposure)
        target = host
    else:
        require(permit, operation, exposure=exposure, address=address, port=port)
        target = address or host

    limiter.acquire(target)

    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(target, port, timeout=budget.connect_timeout,
                                       context=context)
    try:
        request_headers = dict(headers or {})
        request_headers.setdefault("User-Agent", "SKOPOS/0.3 (+external-attack-surface)")
        request_headers.setdefault("Accept", "*/*")
        if host_header or address:
            request_headers["Host"] = host_header or host
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        conn.request("GET", path, headers=request_headers)
        response = conn.getresponse()

        if response.status in (429, 503):
            advertised = response.getheader("Retry-After") or ""
            raise RateLimited(
                f"{host} returned {response.status}"
                + (f" with Retry-After: {advertised}" if advertised else "")
                + f"; not waiting (cap {MAX_RETRY_AFTER:.0f}s)")

        body = response.read(budget.max_body_bytes + 1)
        truncated = len(body) > budget.max_body_bytes
        if truncated:
            body = body[:budget.max_body_bytes]

        redirect_to = None
        if 300 <= response.status < 400:
            location = response.getheader("Location")
            if location and max_redirects <= 0:
                # Recorded as a signal, not followed. urllib's redirect handler
                # would carry an ACTIVE probe to a host no permit covers.
                redirect_to = location
        return HttpResponse(status=response.status, body=body,
                            headers={k.lower(): v for k, v in response.getheaders()},
                            truncated=truncated, redirect_to=redirect_to)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def http_post_json(permit, operation: str, url: str, payload,
                   *, budget: Optional[Budget] = None,
                   limiter: Optional[Limiter] = None,
                   headers: Optional[Dict[str, str]] = None) -> HttpResponse:
    """A JSON POST, under the same rules as `http_get`.

    OSV's query endpoint takes a POST body, which is the only reason a write
    verb exists here. It carries no customer data outward — a package name and
    a version — and is subject to the identical permit, host-allowlist, HTTPS
    and rate-bucket checks, because an exception carved for one caller is how a
    choke point stops being one.
    """
    budget = budget or Budget()
    limiter = limiter or Limiter(budget)
    exposure = gate.classify(operation)

    parts = urlsplit(url)
    if parts.scheme != "https":
        raise PermitMismatch(f"{url!r} is not https.")
    host = parts.hostname or ""
    if host not in ALLOWED_HTTP_HOSTS:
        raise PermitMismatch(
            f"{host!r} is not a registered source host. Passive collection "
            f"reaches a declared list, not an arbitrary destination.")
    require(permit, operation, exposure=exposure)
    limiter.acquire(host)

    body = json.dumps(payload).encode("utf-8")
    conn = http.client.HTTPSConnection(host, parts.port or 443,
                                       timeout=budget.connect_timeout,
                                       context=ssl.create_default_context())
    try:
        request_headers = dict(headers or {})
        request_headers.setdefault("User-Agent",
                                   "SKOPOS/0.5 (+external-attack-surface)")
        request_headers["Content-Type"] = "application/json"
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        conn.request("POST", path, body=body, headers=request_headers)
        response = conn.getresponse()
        if response.status in (429, 503):
            raise RateLimited(f"{host} returned {response.status}")
        data = response.read(budget.max_body_bytes + 1)
        truncated = len(data) > budget.max_body_bytes
        return HttpResponse(status=response.status,
                            body=data[:budget.max_body_bytes],
                            headers={k.lower(): v for k, v in response.getheaders()},
                            truncated=truncated)
    finally:
        try:
            conn.close()
        except OSError:
            pass


__all__ = ["Budget", "Limiter", "HttpResponse", "PermitMismatch",
           "BudgetExhausted", "RateLimited", "require", "tcp", "udp",
           "http_get", "http_post_json", "PORTS_BY_OPERATION", "ALLOWED_HTTP_HOSTS",
           "DEFAULT_RESOLVERS", "MAX_RETRY_AFTER", "MAX_CONCURRENCY"]
