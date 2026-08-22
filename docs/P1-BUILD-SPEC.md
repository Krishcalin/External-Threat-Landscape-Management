All critique claims are now verified against the real code. Key measurements:

- **Permit forgery is real** — `dataclasses.replace()` on a PASSIVE permit yields a valid ACTIVE permit for an arbitrary host.
- **CVE injection is real** — lowercase `cve-2021-44228` in any attribute yields `Confidence.STRONG`.
- **The breadth cap dispute resolves against the designer** — `Cisco` 96 hits/1 vendor, `Chromium` 63/1, `Fortinet` 29/1 are precise; `Security Gateway` 28/8 vendors and `Routers` 27/9 are not. Hit count does not separate the populations; vendor span does.
- **`faß.example.com`.encode('idna')` → `fass.example.com`** — name corruption, not just a merge miss.
- **Nothing calls `gate.authorise()` outside tests, and nothing can create a scope rule.**

---

# SKOPOS P1 — Build Specification

**Status:** supersedes the three subsystem designs. Where a design and a critique conflict, the resolution below is authoritative and the reasoning is stated. Every critical and major problem from both critics on all three subsystems is dispositioned in §12.

**Governing rule for this spec:** P1 is the first phase in which anything in the product calls `core.gate.authorise()`. Three subsystems were designed independently and each invented its own egress module, its own source-report vocabulary, and its own permit-binding convention. That triplication is the single largest source of the critiques. **P1 collapses them into one of each**, and the collapse is specified before any subsystem.

---

## 1. What P1 delivers

| Capability | Tier | Ships in P1 |
|---|---|---|
| Passive name discovery from multiple sources | PASSIVE | Yes |
| DNS record collection + run-over-run change tracking | PASSIVE | Yes |
| Dangling-CNAME detection, capped at `INCONCLUSIVE`/`PROVIDER_GUARDED` | PASSIVE | Yes |
| Expired-registrable-domain takeover, **determinable** via RDAP | PASSIVE | Yes |
| HTTP/TLS fingerprinting that makes `core/match.py` fire | ACTIVE | Yes |
| TCP reachability sweep supplying `external_reachable` | ACTIVE | Yes |
| Takeover HTTP corroboration (`CLAIMABLE_LOOKING`) | ACTIVE | **No — §11** |

The load-bearing feature is fingerprinting: CT discovery writes `product="unknown"`, which measured against the vendored 1,674-entry corpus matches **0 entries**, so today a 400-host discovery yields zero findings and one number in a warning banner.

---

## 2. P0 corrections that must land first

These are defects in shipped P0 code that P1 makes exploitable. They block every subsystem.

### 2.1 `Permit` is forgeable — CRITICAL, measured

```python
p = authorise('api.example.com', 'ct_log_search', 'k.de', scope)   # PASSIVE, no ownership needed
dataclasses.replace(p, asset='victim.net', operation='port_scan', exposure=Exposure.ACTIVE)
# -> valid ACTIVE Permit. Verified live.
```

`_token` is a normal `init=True` field, so `replace()` copies `_ISSUER` forward and `__post_init__` passes. Every enforcement claim in all three designs is downstream of this object.

**Fix — `core/gate.py`:**

```python
_SECRET = secrets.token_bytes(32)          # process-lifetime, module-private

def _seal(asset, operation, exposure, actor, addresses) -> str:
    material = "|".join(f"{len(p)}:{p}" for p in (
        str(asset), str(operation), str(exposure.value), str(actor),
        ",".join(sorted(addresses or ()))))
    return hmac.new(_SECRET, material.encode("utf-8"), hashlib.sha256).hexdigest()
```

`Permit.__post_init__` does `hmac.compare_digest(self._token or "", _seal(...))`. Mutating any sealed field invalidates the seal. Keep the docstring's honesty: this is a structural guarantee against careless mutation, not a cryptographic one against a co-resident attacker who can read `_SECRET`.

**Tests (`tests/test_gate.py`, EDIT):** `test_a_permit_cannot_be_forged_by_mutation` — parametrised over every sealed field, asserting `dataclasses.replace` raises.

### 2.2 Target-controlled text reaches the highest-confidence match path — CRITICAL, measured

```python
Asset(identifier='h', product='unknown',
      attributes={'fp_evidence': 'Server: EvilWAF blocks cve-2021-44228'})
# -> declared_cves() == {'CVE-2021-44228'}, one exposure, Confidence.STRONG,
#    evidence "the inventory names CVE-2021-44228 on this asset"
```

`_CVE` is compiled `re.I`, so a case-sensitive redactor in a collector misses it. `declared_cves()` scans *every* attribute value, and `inventory.from_rows` puts every unaliased column there. P1 multiplies the volume of third-party text flowing into that bucket by roughly eight sources.

**Fix — two independent layers, both required, both tested.**

*Layer 1 — provenance, structural.* New `core/provenance.py`:

```python
TOOL_PREFIX = "obs_"     # every column any SKOPOS collector writes that is not
                         # one of the six inventory.ALIASES fields
def tool_authored(key: str) -> bool: ...
```

`core/match.py` EDIT — `declared_cves()` skips tool-authored keys:

> An explicit CVE on an asset row outranks name matching because it is *the customer's* statement. A string this product wrote from a third party's response is not the customer's statement, and treating it as one lets anyone who controls a response header write into the top of the worklist.

*Layer 2 — redaction, defence in depth.* `core/provenance.redact()` imports `core.match._CVE` (promoted to public `match.CVE_PATTERN`) rather than restating the pattern — a private copy drifts, and the measured lowercase miss is exactly that drift. The single row-writer choke point (§5.4) asserts no emitted cell matches `CVE_PATTERN` and raises before the file is written.

**Rejected:** redacting only one dataclass field. Measured: `Refusal.reason` embeds the asset name verbatim, and `cve-2021-44228.example.com` is a legal DNS name a SaaS tenant can register.

### 2.3 Matcher hygiene — `core/match.py` EDIT

- `STOPWORDS` gains `unknown`, `unidentified`, `none`. Today CT hosts fail to match by *coincidence* — `{unknown}` happens to appear in 0 of 1,674 entries. One KEV entry carrying the word joins every unfingerprinted host in the estate at once. The addition routes it through the empty-set short-circuit in `_corresponds`, making the safety structural.
- `unmatched_assets()` dedupes on `(identifier, product)`, not `identifier`. Measured: with fingerprinting, one host serving two products under-reports its own misses — the exact statistic the function exists to protect.

### 2.4 `core/models.py` EDIT

`Asset(product=None)` passes `__post_init__` because `str(None).strip()` is `"None"`. Reject `None` explicitly.

### 2.5 There is no migration runner — MAJOR

`docker-compose.yml` mounts `./db:/docker-entrypoint-initdb.d:ro`, which Postgres runs **only on an empty data directory**; the compose file says so. There is no `schema_version` table and no applier. `db/002_p1.sql` would never execute on `skopos-db-1`, and the CHECK constraints P1 relies on would silently not exist while the same inserts are refused in tests.

**Fix — `core/migrate.py` NEW:**

```python
def ensure_current(dsn: Optional[str] = None) -> List[str]:
    """Apply every migration not yet recorded, in filename order. Returns applied ids."""
class SchemaBehind(RuntimeError): ...
```

- Creates `schema_migration(version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())` if absent.
- Back-fills `'001'` as applied when `scope_rule` already exists (the existing-volume case).
- Applies each `db/NNN_*.sql` inside one transaction per file.
- `PostgresStore.__init__` and the FastAPI startup hook call it and **refuse to serve** when behind — the same posture as `open_store()` refusing to fall back to memory.

**Test (`tests/test_store_postgres.py`, EDIT):** assert every named constraint and rule from 002 exists by querying `pg_constraint` and `pg_rules`, so a missing constraint fails a test rather than being discovered by a bad finding.

### 2.6 `gate.refusal_reasons()` answers the wrong question — MAJOR

It hardcodes `verification=None`, so for any ACTIVE operation it reports *every* asset as unverified by construction. Both the active layer's `--dry-run` and the DNS sweep's `--plan` were designed on top of it, meaning the one control an operator uses to preview a run systematically under-reports what will be touched.

**Fix — `core/gate.py`:** add

```python
def plan(assets, operation, actor, scope,
         verifications: Mapping[str, Optional[Verification]],
         kind=None, today=None) -> Tuple[List[str], List[str]]:
    """(would_run, refusals) using the verifications actually on record."""
```

Every `--dry-run`/`--plan` path uses `plan()`. `refusal_reasons()` keeps its signature and gains a docstring line stating it answers "what would be refused with no verifications at all", which is not the question an operator is asking.

---

## 3. Shared abstractions — specified once

### 3.1 Naming: contradictions resolved

The three designs collide. These are the binding names.

| Concept | Design names in conflict | **P1 name** |
|---|---|---|
| Per-source outcome record | `SourceReport` (passive) / `ResolverReport` (dns) / `Refusal` (active) | `collect.report.SourceReport` |
| A discovered DNS name | `DiscoveredName` | `DiscoveredName` |
| One third-party sighting | `Observation` (passive) | `NameObservation` |
| One identity signal from a service | `Observation` (active) | `IdentitySignal` |
| Port sweep result | `SweepResult` (active) | `PortSweep` |
| DNS sweep result | `SweepResult` (dns) | `DnsSweep` |
| HTTP probe module | `http_fingerprint.py` (dns) / `http_fp.py` (active) | `collect/http_probe.py` — **one module, both callers** |
| Egress | `collect/http.py` / `collect/net.py` / `collect/dns_wire.py` | `collect/egress.py` + `collect/dns_wire.py` (parser only) |

**Pre-existing collision, do not worsen:** `core.gate.Exposure` (the enum), `core.models.Exposure` (asset × exploited), and `core.scoring.Exposure` (TEPS factors) are three different types. Always import qualified: `from core import gate` then `gate.Exposure`.

### 3.2 `collect/report.py` — NEW. The one degradation vocabulary.

Used by passive discovery, the DNS sweep, **and** the fingerprint run. A boolean cannot distinguish "answered, genuinely nothing" from "capped at 50 rows" or "the gate refused it", and today every one of those reads as a small estate.

```python
class Outcome(str, enum.Enum):
    OK           = "ok"            # answered in full
    PARTIAL      = "partial"       # answered, and said it was cut off
    FAILED       = "failed"        # tried, could not
    UNCONFIGURED = "unconfigured"  # needs a credential nobody supplied
    DISABLED     = "disabled"      # left out by configuration or terms
    REFUSED      = "refused"       # the gate said no — scope or exclusion

@dataclass
class SourceReport:
    name: str
    outcome: Outcome
    contributed: int = 0     # names/rows that survived containment — the P0 meaning
    returned: int = 0        # rows the source handed back, before filtering
    detail: str = ""
    def __post_init__(self):  # bool coercion shim: True->OK, False->FAILED.
        ...                   # REMOVE BY 2026-12-31 — an undated shim is a permanent one.
    @property
    def ok(self) -> bool: ...        # outcome is OK — preserves P0 semantics
    @property
    def answered(self) -> bool: ...  # OK or PARTIAL
```

**Three flags, not one** (critics split `REFUSED` out of `narrowed`, correctly):

```python
degraded  -> any FAILED or PARTIAL      # something broke; re-running may help
narrowed  -> any UNCONFIGURED/DISABLED  # nothing broke; coverage is smaller by choice
refused   -> any REFUSED                # the gate said no; a governance event
```

If `UNCONFIGURED` folded into `degraded`, every install without an optional API key would be permanently degraded, and a flag that is always on is a flag nobody reads.

**`contributed` vs `returned`** resolves the critique that moving apex containment into the shared merge silently changes what the count means: a source that returns a 500-SAN shared-CDN certificate of which 3 names are in-apex reports `returned=500, contributed=3`. Never sum `contributed` across sources — `coverage_note()` reports the union and the answered-source count, and `overlap()` gives the per-source unique count computed *after* the merge so it is order-independent.

### 3.3 `collect/egress.py` — NEW. The only module that performs I/O.

This resolves the three competing egress designs, the missing `operation` parameter, the absent global rate ceiling, the plaintext-HTTP Wayback URL, the uncapped `Retry-After`, and the grep test that failed on day one.

```python
class PermitMismatch(PermissionError): ...
class BudgetExhausted(RuntimeError): ...
class RateLimited(RuntimeError): ...

def require(permit, operation: str, *, exposure: gate.Exposure,
            asset: Optional[str] = None, address: Optional[str] = None) -> None:
    """Raise PermitMismatch unless the permit authorises exactly this work."""
```

`require()` uses **explicit `raise`, never `assert`** — `python -O` deletes asserts, and there is not one `assert` anywhere in `core/`, `collect/`, `api/` or `tools/` today. Comparison is on normalised strings: `authorise()` stores the raw operation and asset (`gate.py:163`, `:188`) while `classify()` normalises, so `'CT_Log_Search'` yields a permit a naive `==` rejects.

**Entry points — every one takes `permit` and `operation`:**

```python
@contextmanager
def tcp(permit, operation, address, port, budget, limiter) -> Iterator[socket.socket]
def udp(permit, operation, address, port, payload, budget, limiter) -> bytes
def http_get(permit, operation, url, *, budget, limiter,
             headers=None, host_header=None, max_redirects=0) -> HttpResponse
```

Enforced inside, not by the caller:

- **`PORTS_BY_OPERATION`** — `http_probe`/`tls_handshake` → `{80, 443, 8080, 8443}`; `port_scan`/`service_banner_read` → the declared probe set; `dns_resolve_*` → `{53}`. A port outside the permit's operation raises. This closes "an `http_probe` permit reads the MySQL greeting through the approved helper".
- **`permit.addresses`** — `tcp`/`udp` refuse any address not on the permit, and connect to the address they were handed rather than re-resolving. Pins the permit check and the connection together against DNS rebinding.
- **HTTPS only.** `http_get` raises on any scheme but `https`. Wayback's CDX endpoint is `https://web.archive.org/...`; an on-path attacker who can silently *delete* hostnames from a plaintext response shrinks the reported estate with no source reporting FAILED — the exact "thin result looks like a small estate" failure, through the one source that did not use TLS.
- **No redirects by default.** Uses `http.client`, not `urllib.request`, whose `HTTPRedirectHandler` would carry an ACTIVE probe to a host no permit covers. A cross-host redirect is recorded as a signal and the chain stops.
- **`Retry-After` capped at 30 s.** Above the cap, do not sleep: `PARTIAL` if rows were already collected, `FAILED` otherwise, `detail` naming the advertised window. An uncapped honour lets a 503 with `Retry-After: 86400` hang a synchronous CLI for a day.
- **Uses only `DEFAULT_RESOLVERS` / registered source hosts.** Destination is not a free-form caller argument; a caller may subset the allowlist, never extend it. Otherwise `--resolvers 10.0.0.53` aims every query at customer infrastructure under a PASSIVE permit that required no ownership proof.

**`Budget` / `Limiter`:**

```python
@dataclass(frozen=True)
class Budget:
    connect_timeout: float = 5.0;  read_timeout: float = 5.0
    per_address_interval: float = 0.5;  per_address_burst: int = 2
    per_network_interval: float = 0.1      # keyed on the containing /24
    global_interval: float = 0.05          # 20 connections/sec, run-wide
    concurrency: int = 8                   # hard cap MAX_CONCURRENCY = 32
    max_body_bytes: int = 65536;  max_redirects: int = 0
    run_seconds: Optional[float] = 900.0
    max_queries: Optional[int] = 50_000
```

Three buckets, all traversed on every acquisition: **address → /24 → global**. Per-address alone is not enough — 400 hosts on 400 distinct IPs in one /22 behind one firewall is ~400 new flows/sec with every per-address budget respected, which fills a state table. Per-hostname alone is wrong the other way: CT routinely yields hundreds of names behind one CDN address, and hostname keying would deliver a 500-fold amplification to one server.

Never retry on RST — a reset is an answer, and retrying it is noise that looks like a scan.

**Budget exhaustion is loud.** `BudgetExhausted` sets `degraded`, and everything not attempted is **returned and named**. A run cut short and an estate with nothing exposed produce identical empty output otherwise.

**The CI test — `tests/test_egress_boundary.py` NEW.** The naive grep fails on day one: `collect/ct.py` uses `urllib.request` at lines 38–41 and 98–101, legitimately. A filename allowlist is the convention `gate.py`'s docstring rejects, and a third-party author adds themselves to it.

Resolution: **a module may perform I/O only if it carries `# NETWORK-BOUNDARY: <operation>` markers**, and the test asserts every marker names a key in `gate.OPERATIONS`. `collect/egress.py` declares the markers for the operations it services; `collect/ct.py` is ported onto `egress.http_get` and declares none. The scan covers `collect/`, `core/`, `api/` **and** `main.py`, and matches `socket.`, `ssl.wrap`, `http.client`, `urllib.request`, `asyncio.open_connection`, `httpx`, `requests`, `ftplib`, `smtplib`, `telnetlib`, and `subprocess` invocations of `curl`/`nc`/`nmap`.

### 3.4 Permit binding is asserted **once**, in shared code

The designs put the binding check in each of eight source modules — the pattern `gate.py`'s docstring condemns, applied to the more security-critical half while correctly centralising the less critical one. A P2 contributor who copies a source's shape and omits the three boilerplate lines gets a working, silent bypass.

**Rule:** `collect/egress.require()` is the guarantee. Per-source asserts are permitted as defence in depth but nothing may depend on them. Test: `test_egress_rejects_a_mismatched_permit_for_a_source_that_does_not_check`.

### 3.5 Name normalisation — no `idna`

Measured: `'faß.example.com'.encode('idna')` → `b'fass.example.com'`, a **different registrable domain** that may belong to someone else; `('a'*64 + '.example.com').encode('idna')` raises. IDNA2003 nameprep maps ß→ss and ς→σ. Emitting a hostname no source reported is not a documentation gap.

**`collect/discovery.normalise_name()`** lower-cases, strips a trailing dot, rejects empty/space-containing values and empty labels, and **keys on the literal name**. Unicode and A-label spellings of one name remain two rows. That is honest and is stated in `coverage_note()`. Adding `idna>=3` is a justified future dependency; P1 does not corrupt names to avoid it.

**Test:** `test_a_unicode_name_is_emitted_as_observed` — the `faß` case, asserting the emitted name is one a source actually returned.

---

## 4. `gate.OPERATIONS` — the complete additions

All keys lowercase and edge-trimmed (`classify()` looks up `str().strip().lower()`, so an uppercase key is permanently unreachable). All values real `Exposure` members, asserted by the existing `test_every_registered_operation_has_an_explicit_classification`.

```python
    # --- P1 PASSIVE ---
    "subdomain_index_read":     Exposure.PASSIVE,  # read a published name index
    "web_archive_search":       Exposure.PASSIVE,  # query a crawl index
    "dns_resolve_recursive":    Exposure.PASSIVE,  # live resolution via a THIRD-PARTY recursive resolver
    "rdap_lookup":              Exposure.PASSIVE,  # registration status of a registrable domain

    # --- P1 ACTIVE ---
    "dns_resolve_authoritative": Exposure.ACTIVE,  # RD=0, straight at the customer's nameservers
    "dns_wildcard_probe":        Exposure.ACTIVE,  # a synthesised label; cache-miss by construction
    "service_banner_read":       Exposure.ACTIVE,  # read-only greeting on a non-web port
```

`http_probe`, `tls_handshake`, `port_scan` already exist as ACTIVE and are **not** re-registered — registering near-synonyms for work already named is the drift the registry exists to prevent.

**A comment pins the existing `passive_dns` key** to its industry meaning — querying a *historical* passive-DNS database (mnemonic, CIRCL, OTX), zero packets toward the name. `dns_resolve_recursive` emits packets. Both are PASSIVE; they are different operations and the audit log must tell them apart.

**Why `dns_resolve_recursive` is PASSIVE.** Packets go to a third-party recursive resolver; the customer's authoritative servers see a query from the *resolver's* address, unattributed, cache-damped. Decisively: `Method.DNS_TXT` ownership verification is itself a DNS resolution, so classifying recursive resolution ACTIVE would make ownership verification require ownership verification and the product could not bootstrap.

**Why `dns_wildcard_probe` is ACTIVE and opt-in.** A random label is a guaranteed cache miss, so 100% of these forward to the customer's authoritative nameservers on every run — the exact opposite of the cache-damping argument that makes recursive resolution passive. A stream of random labels under one zone is the textbook DNS water-torture signature and will be read as an attack in the customer's telemetry. It uses a **fixed self-identifying label** `skopos-wildcard-probe.<zone>`, not a random one, so it is recognisable as this tool; one probe per zone per run, never per name; `wildcard_probe` defaults to **False**.

**Not added:** `subfinder_aggregate`. See §11.

---

## 5. Shared data contracts

### 5.1 Address-aware authorisation — `core/gate.py` EDIT (MERGE POINT)

Both critics independently found that a `ScopeRule(CIDR, ..., is_exclude=True)` can never fire for a hostname — measured: `scope.resolve('api.example.com', DOMAIN)` is `INCLUDED` while `scope.resolve('104.18.5.7', CIDR)` is `EXCLUDED`, and `ScopeRule.matches` returns False for a non-IP asset. D10 says exclude wins unconditionally; here it loses silently, for the operations that do almost all of the connecting.

The "a `Host:`-routed request reaches only the tenant" argument is false at the transport layer: the TCP connection, the TLS handshake, the resource consumption and the abuse report all land on the address owner.

```python
@dataclass(frozen=True)
class Permit:
    ...
    addresses: Tuple[str, ...] = ()   # declared AFTER _token; () means name-only

def authorise_target(asset, addresses, operation, actor, scope,
                     verification=None, kind=None, today=None) -> Permit:
    """authorise() for the name, then the address rules. Strictly narrower."""
```

1. `authorise(...)` for the name — PROHIBITED → scope → ownership ordering unchanged, so `test_prohibited_is_decided_before_scope` continues to hold.
2. **Every** address must not resolve `EXCLUDED` under `ScopeKind.CIDR`, for every ACTIVE operation including `http_probe`. Raise `NotInScope` naming both the name and the address.
3. For `port_scan` / `service_banner_read` **additionally**: at least one address must resolve `INCLUDED` via a CIDR rule. Ownership is proven over a *name*; a sweep is delivered to an *address*, and a name pointed at a CDN or SaaS tenant would otherwise authorise sweeping a third party who consented to nothing.
4. The addresses are sealed onto the permit; `egress.tcp` refuses any other.

**ASN is dropped.** Measured: `scope.resolve('203.0.113.10', ScopeKind.ASN)` is `UNSCOPED` and there is no IP→ASN mapping in the product. The refusal message must name the situation — if any ASN rule exists in scope, say that ASN rules cannot be resolved against an address in this release and an equivalent CIDR rule is required. Test: `test_an_asn_rule_does_not_authorise_an_address`.

For a **shared address**, resolve every EXCLUDED in-scope name once per run and refuse a sweep of any address one of them resolves to, reported as a `SourceReport(REFUSED)` row rather than skipped.

### 5.2 The refusal taxonomy and exit codes — resolves a self-contradiction in two designs

Both passive-discovery critics found the same thing: `run.py` catches `OperationRefused`/`NotInScope` and files them as a per-source status line, so the `PermissionError → 3` clause in `main()` is dead, an unscoped apex exits 2 with "no source answered", and the operator is handed the wrong remedy. Separately, a developer who forgets `gate.OPERATIONS` gets a nightly one-line footnote next to "you didn't set an API key" — inverting `classify()`'s documented promise to "fail loudly on its first run".

**Binding rule — three cases, three behaviours:**

| Cause | Behaviour | Exit |
|---|---|---|
| `OperationRefused` (unregistered or PROHIBITED) | **propagates uncaught** — a build error, never a coverage gap | 3 |
| `NotInScope` **on the apex / target asset** | propagates, audited as `*.refused` | 3 |
| `NotInScope` on a *non-apex* asset (one name of many, one hop) | degrades that item to `Outcome.REFUSED`, sets `result.refused` | 0 |
| No permit found for a source's operation (caller bug) | raises `PermitMismatch` | 3 |

`main()` EDIT gains `except PermissionError → 3` (catches all three gate exceptions), `except DiscoveryUnavailable → 2`, `except StoreUnavailable → 2`, `except migrate.SchemaBehind → 2`, `except RulesUnavailable → 2`.

**Tests:** `test_an_unscoped_apex_exits_3_with_the_gates_own_sentence`; `test_an_unregistered_source_operation_fails_the_run` asserting a non-zero exit, not a report row.

### 5.3 Total blackout raises

A run in which no source answered raises `DiscoveryUnavailable` (mirroring `IntelUnavailable`); `sources=[]` raises too. Today `cmd_discover` prints "Nothing to write" and returns 0 — a clean-looking zero with a success exit code, on the command whose characteristic failure is an estate that looks small. If even one source answered this does **not** raise; that is degradation, and degradation is reported, never fatal.

`run_sources()` **always returns** the `DnsSweep`/`DiscoveryResult`; the caller audits and *then* raises. Otherwise the one run where "which sources were contacted, and what did they say" is the whole question is the one run with no per-source audit records.

### 5.4 The inventory row writer — one function, one place

Both the discovery writer and the fingerprint writer emit inventory rows. Specified once in `core/provenance.py`:

```python
def write_rows(base: Optional[Sequence[Dict[str, Any]]],
               additions: Mapping[str, Dict[str, Any]],
               keyed_on: str = "hostname") -> List[Dict[str, Any]]
```

Rules, all tested:

1. **Union-preserving.** Fieldnames = every key present in `base` ∪ every key in `additions`. Measured: a closed `COLUMNS` tuple through `csv.DictWriter` raises `ValueError` on an operator inventory carrying `owner`/`version`/`cve`, and with `extrasaction='ignore'` silently blanks them — destroying `owner` (which `models.Asset` calls the whole objective), the OPERATOR-attested `version`, and the cheapest STRONG match path.
2. **Never overwrite a non-empty operator value.** Observed `product`/`vendor` fill only where the base value is absent or the literal `unknown`. A self-reported banner must not outrank the customer's own record.
3. **Every tool-authored column carries `obs_`** (§2.2). Measured-safe names: `obs_addresses`, `obs_first_seen`, `obs_last_seen`, `obs_record_type`, `obs_scope`, `obs_source`, `obs_version`, `obs_attestation`, `obs_signature`, `obs_evidence`, `obs_port`, `obs_open_ports`, `obs_scheme`, `obs_reachable`, `obs_resolved_address`, `obs_probed_at`, `obs_liveness`.
   **Never emit `address`, `banner`, `service`, `version`, `name`, `url`, `ip`** — measured, all are in `inventory.ALIASES`; `address` is consumed by `identifier` and then *loses* to `hostname` in preference order, so the IP is silently deleted end to end.
4. **Asserts `not CVE_PATTERN.search(value)` over every cell** and raises before writing.

**Test:** `test_no_emitted_column_collides_with_an_inventory_alias` runs over `inventory.ALIASES` so it fails if either side changes.

### 5.5 The coverage sidecar — honesty survives the file boundary

Every design keeps the house principle "discovery writes a file, the scan reads it", and every design then leaves `coverage_note()`, `degraded`, `not_attempted` and `budget_exhausted` on an object discarded at the file boundary. Run 1: 5 sources OK, 400 rows. Run 2: 4 fail, CSV silently overwritten with 12 rows. `etlm scan` prints "12 asset(s) read" and "No asset corresponds to anything in the catalogue" — a report identical to a small clean estate.

**Every command that writes an inventory CSV writes `<name>.coverage.json` beside it:**

```json
{"tool":"discover|fingerprint","at":"…","actor":"…",
 "attempted":412,"contributed":400,"identified":0,
 "refused":[…],"not_attempted":[…],"unreadable":[…],
 "degraded":true,"narrowed":false,"refused_any":false,
 "budget_exhausted":false,"sources":[{…SourceReport…}],
 "coverage_note":"…"}
```

`cmd_scan` EDIT reads it, reprints the note beside `WORKLIST_NOTICE`, and **refuses to run silently** when the CSV is present and the sidecar is missing.

Additionally: on a degraded run, refuse to overwrite a larger existing CSV without `--overwrite`; on a zero-name run write an empty-with-header file rather than leaving a stale one in place.

### 5.6 Rejected and unreadable rows are returned

CLAUDE.md's first convention, applied to the merge. Names dropped by `normalise_name()` or by apex containment are currently discarded inside `merge()` while `contributed` was computed by the source beforehand, so the report says `hackertarget OK 50` while 44 names exist.

```python
DiscoveryResult.unreadable: List[Tuple[str, str, str]]   # (source, raw value, reason)
```

Populated by `merge()`, printed by the CLI, in the sidecar, and in the `discovery.completed` audit payload. Mirrors `inventory.load()`'s two-return-value shape.

### 5.7 Audit — brackets the contact, and grades by exposure

`authorise()` writes nothing to the audit log; the caller discharges FR-M0-007.

| Event | Granularity | Rule |
|---|---|---|
| `*.source.attempt` | per source, **before** `fetch` | so an unmatched attempt is visibly an incomplete run |
| `*.source.result` | per source, after | outcome, contributed/returned, detail |
| `*.refused` | per refusal | `str(exc)` |
| `*.completed` | per run | counts, degraded/narrowed/refused, coverage note |
| **every ACTIVE operation** | **per operation** | actor, asset, destination address, port, `permit.rationale`, outcome |
| PASSIVE per-name DNS lookups | per run rollup | not per name |

The volume argument (400 names × 6 rrtypes daily ≈ 146k rows/yr into a table taking an EXCLUSIVE lock per insert) applies to PASSIVE bulk lookups only. ACTIVE probes are rare by construction, and economising on the highest-exposure events is exactly backwards: a `--probe` run of 40 candidates yielding 3 findings must produce **40** ACTIVE audit records, not 4.

**Audit-failure policy, stated:** if `append_audit` raises mid-run, **abort the run**. The alternative is collecting without a record.

---

## 6. Schema — `db/002_p1.sql` (NEW) and `core/migrate.py` (NEW)

One migration file for all of P1. Shaped to take `org_id` when tenancy arrives.

**Tables:** `dns_run`, `dns_observation`, `dns_wildcard_probe`, `http_observation`, `takeover_finding`, `discovery_run`, `discovery_source_report`.

Corrections against the design, all measured:

- **`rcode` is stored as its NAME, never the integer.** Measured: `json.dumps({'rcode': Rcode.NXDOMAIN})` → `{"rcode": 3}` and `default=str` does not help because it *is* an int. The proposed `CHECK (... ->>'rcode' IN ('NOERROR','NXDOMAIN'))` therefore **rejects every legitimate claim**, while `rcode: null` from a timeout passes (`NULL IN (...)` is NULL, and CHECK only rejects on FALSE). `to_dict()` emits `rcode.name`.
- **Constraints are NULL-safe:**
  ```sql
  CONSTRAINT a_claim_is_not_built_on_a_failure CHECK (
      verdict <> 'claimable_looking' OR (
          COALESCE(evidence->'target_resolution'->>'rcode','') IN ('NOERROR','NXDOMAIN')
      AND COALESCE(evidence->'target_resolution'->>'transport_error','') = ''))
  CONSTRAINT a_claim_names_its_rule CHECK (
      verdict <> 'claimable_looking'
      OR (evidence ? 'rule' AND evidence->'rule' <> 'null'::jsonb))
  CONSTRAINT a_claim_has_resolver_quorum CHECK (
      verdict <> 'claimable_looking'
      OR jsonb_array_length(evidence->'target_resolutions') >= 2)
  CONSTRAINT a_claim_is_not_built_on_a_capped_chain CHECK (
      verdict <> 'claimable_looking'
      OR COALESCE((evidence->'chain'->>'truncated')::bool, TRUE) IS FALSE)
  CONSTRAINT reasons_are_not_empty CHECK (jsonb_array_length(reasons) > 0)
  CONSTRAINT retirement_states_a_reason CHECK (retired_at IS NULL OR retire_reason IS NOT NULL)
  ```
- **The conclusive index tracks conclusiveness, not record-presence.** The design's `WHERE rrset_digest IS NOT NULL` excludes conclusive *negatives*, so a deletion is re-reported as DISAPPEARED forever and the restoration is never reported. A conclusive negative stores the digest of the empty set, and:
  ```sql
  CREATE INDEX dns_last_conclusive ON dns_observation (name, rrtype, observed_at DESC)
      WHERE rcode IN (0,3) AND transport_error = '';
  ```
- **Finding dedup is a UNIQUE index, not an index.** Otherwise 12 dangling names swept daily produce 360 open rows in a month and the API reports `total: 360` — a 30× overstatement.
  ```sql
  CREATE UNIQUE INDEX takeover_open ON takeover_finding
      (name, rule_provider, (evidence->>'target')) WHERE retired_at IS NULL;
  ```
  `raise_finding` is an upsert bumping `last_run_id`.
- `permit_rationale TEXT NOT NULL` on `http_observation` — an ACTIVE probe cannot be recorded without the words the gate granted it under.
- DO-INSTEAD-NOTHING on UPDATE/DELETE for `dns_observation`, `http_observation`, `discovery_source_report`. Grants: `SELECT, INSERT` on the evidence tables, `SELECT, INSERT, UPDATE` on `dns_run`/`takeover_finding`/`discovery_run`. **No DELETE anywhere.**

**Stated, not solved:** the append-only grants leave no prune path for `dns_observation`. Partition-by-month and DROP PARTITION is the likely answer and is **not** designed here (§11).

---

## 7. Subsystem A — passive discovery

`collect/discovery.py`, `collect/registry.py`, `collect/passive_dns.py`, `collect/names.py`, `collect/run.py` (all NEW), `collect/ct.py` (EDIT).

### 7.1 Sources

| Source | Operation | Data class | Terms | Default |
|---|---|---|---|---|
| certspotter | `ct_log_search` | CT | open | **on** |
| crt.sh | `ct_log_search` | CT | open | **on** |
| mnemonic pDNS | `passive_dns` | PASSIVE_DNS | open (100/min, 1000/day anon) | **on** |
| Anubis/jldc | `subdomain_index_read` | NAME_INDEX | open | **on** |
| Wayback CDX | `web_archive_search` | WEB_ARCHIVE | open | **off** |
| AlienVault OTX | `passive_dns` | PASSIVE_DNS | credentialed | off |
| HackerTarget | `subdomain_index_read` | NAME_INDEX | noncommercial | off |

**Wayback is out of `DEFAULT_ENABLED`** — the design's own risk register says the staleness question must be settled before it ships on by default, and its open questions leave it unsettled. A design cannot ship a source on by default while recording that doing so is blocked. It stays registered, enabled by `--source wayback`, and it never populates `obs_last_seen` (see 7.3).

**HackerTarget** is `Terms.NONCOMMERCIAL` (free tier ~20–50 queries/day, 50-result cap, memberships sold for volume — which reads as excluding commercial use). SKOPOS may be run commercially and must not make that choice for the operator: off unless `--allow-noncommercial`.

**OTX** is `Terms.CREDENTIALED`: `UNCONFIGURED` without a key, `PARTIAL` if queried anonymously, never `OK` — its docs say unauthenticated requests return public data only, and a silent subset is the worst failure mode available.

`registry.enabled()` returns `(sources, prereports)` and **`run_sources(apex, sources, permits, scope, prereports=())` takes the second value and prepends it to `result.sources`.** Without the parameter the reports are dropped on the floor, `narrowed` is structurally dead for the two states it was invented for, and an install querying 5 of 7 registered sources reports as fully covered.

**Truncation detection, per source, reported as `PARTIAL`:** Wayback `showResumeKey=true` (a resume key means results were cut off); HackerTarget exactly-50 rows; mnemonic returned count == requested limit; OTX anonymous by construction; a capped `Retry-After` mid-pagination.

**Text/CSV endpoints parse positively.** A row counts only if it splits into exactly `host,ip` with a valid host and a parseable IP. If zero rows parse and the body is non-empty → `FAILED` with the first 80 characters as `detail`, **never `OK`**. Special-casing one error string ("API count exceeded") leaves every other 200-with-error-body reporting `OK` with 0 names — a failure wearing a success. The rule lives once in `egress`.

### 7.2 Scope binds discovery twice

Measured mechanism: in `authorise()`, `scope.resolve(asset, kind)` runs at lines 151–160, **before** the PASSIVE short-circuit at 162. Passive skips only the ownership block. So `verification=None` is correct rather than a shortcut, and passive operations are scope-checked identically to active ones.

1. **The apex must resolve `INCLUDED` before any source is queried.** Today `ct.discover(args.domain)` runs with no authorisation at all, so `etlm discover google.com` works and the product is an unbounded OSINT recon tool.
2. **Every discovered name is resolved individually**, with `kind=ScopeKind.DOMAIN` passed explicitly. Measured: with `kind=None`, `ScopeRule.matches` falls through to `str(asset).lower() == self.canonical.lower()`, so a `repo_org` rule valued `example.com` returns `INCLUDED` — a GitHub-org rule authorising DNS discovery. Test `test_a_repo_org_rule_does_not_authorise_dns_discovery` pins it as a control rather than a detail.
   - `EXCLUDED` → `result.excluded` with the verdict's `explain()`, never written to the CSV. Returned, not dropped.
   - `UNSCOPED` → **kept and written**, tagged `obs_scope=unscoped`. `Decision.UNSCOPED`'s own docstring says "for reporting it may mean shadow asset", and that is the product's whole point.
3. **Observed addresses are resolved under `ScopeKind.CIDR`.** If any address for a name resolves `EXCLUDED`, the name goes to `result.excluded` with a verdict stating the exclusion was matched via an observed address, not via the name. The CDN argument justifies not *emitting* addresses as assets; it does not justify not *consulting* them when an operator has written "never touch this".

**`obs_scope=unscoped` is advisory provenance for a human reader, not a control.** Nothing reads that column — measured, it lands in `Asset.attributes` and no code consults it. Enforcement comes from `authorise()` re-resolving scope. The design's claim that it stops later active steps is corrected in the docstring, and real enforcement is added where enforcement lives: `cmd_fingerprint` refuses to probe a row carrying `obs_scope=unscoped`, with a test.

**A DOMAIN-only scope produces a 100%-unscoped CSV**, because a DOMAIN rule matches by exact equality. That is correct and is the shadow-asset finding working, but at 400 rows it reads as an alarm. `coverage_note()` must say which it is and name the wildcard rule that would declare the estate.

### 7.3 Dates carry their provenance

`min(first_seen)` / `max(last_seen)` flattened across data classes destroys the exact distinction the `DataClass` split was created to preserve. A CT `not_before` (a certificate was issued), a Wayback crawl timestamp (a page was fetched) and a pDNS `lastSeen` (a resolver saw it resolve) are not the same kind of fact.

```python
DiscoveredName.first_seen_by: Dict[DataClass, date]
DiscoveredName.last_seen_by:  Dict[DataClass, date]
```

- `obs_first_seen` = min across all classes (the P0 rule: when did this name first appear).
- **`obs_last_seen` is populated only from `PASSIVE_DNS`** — "a resolution somebody observed". A web-archive crawl timestamp goes to `obs_liveness=archived-only`, never to `last_seen`. Otherwise `old.example.com`, decommissioned in 2016 with one 2016 crawl, gets `last_seen=2016-03-02`, which any future liveness filter reads as "resolved until 2016" when it was only "crawled in 2016".
- A CT-only name has no `last_seen`. Liveness unknown, stated rather than implied.

### 7.4 Provenance in the `source` column

`source = ";".join(f"{dc.value}:{name}")`, e.g. `ct:certspotter;pdns:mnemonic`. The hardcoded `"ct:"` prefix would assert certificate-transparency provenance for a web crawl. Round-trip asserted like `obs_addresses`.

### 7.5 CLI arithmetic

`wildcards = sum(1 for n in result.names if n.is_wildcard)` and `len(result.excluded)` reported separately, with a test asserting the two sum to `len(result.names) - len(rows)`. The existing `len(result.names) - len(rows)` attributes every absent name to wildcards, so a run with 1 wildcard and 2 exclusions prints a confidently-worded claim about three wildcards when it is true of one.

---

## 8. Subsystem B — DNS records, change tracking, takeover

`collect/dns_wire.py`, `collect/dns_records.py`, `collect/dns_authoritative.py`, `core/dns_state.py`, `core/takeover.py`, `core/takeover_rules.py`, `core/dns_store.py` (all NEW).

### 8.1 The wire resolver

Stdlib `socket` + `struct`, justified: measured, `socket.getaddrinfo` raises an identical `gaierror(11001)` for NXDOMAIN, SERVFAIL, timeout and a filtering resolver, and the RCODE is the evidence the entire takeover claim rests on. `dnspython` is the alternative and is deliberately deferred — the needed subset is six RR types with no DNSSEC validation, and the `WireResolver` interface is injectable so swapping it later is a constructor change.

Hardened: bounded compression-pointer jumps (raises past 10), size cap, transaction-id **and** question-section echo verified, TCP retry on TC. All sends go through `egress.udp`/`egress.tcp` with a permit.

Only `NOERROR` and `NXDOMAIN` are `conclusive`. NODATA (NOERROR, zero answers of the asked type) is a distinct third state. A SERVFAIL persisting across three independent resolvers is reported as a **DNS-health finding** (broken DNSSEC or lame delegation) in its own right, but can never support a takeover claim — persistence measures the durability of the failure, not its cause.

### 8.2 The CNAME target is read from the chained answer — no separate query

Both critics found the same critical defect from opposite directions: `TakeoverEvidence.__post_init__` requires `target_resolution.question == target`, and the target is always a third party's name (`customer-bucket.s3.amazonaws.com`), which is always UNSCOPED. Measured: `authorise('customer.github.io', ...)` → `NotInScope`. So the mandatory-evidence invariant *forces* the collector either to send unauthorised packets or to have the operator add `*.s3.amazonaws.com` to their scope — declaring Amazon's namespace part of the customer's estate and whitelisting it for every other operation.

**Fix:** a recursive resolver returns the whole CNAME chain and the terminal RCODE **in one message**. The target's resolution is derived from the in-scope name's answer. The invariant relaxes to `target_resolution.question in (name, target)` with the derivation recorded on the evidence.

Every hop is still scope-resolved for *reporting*, and `Chain` gains `refused_hops`, `truncated`, `loop` — all carried into the evidence, with `truncated`/`loop` barring any claim (a 12-hop chain capped at `MAX_CHAIN=10` otherwise yields a "target" that is an intermediate hop, with nothing saying the chain was capped).

### 8.3 Change tracking

**The comparand is `(rcode, digest)`, not `digest`.** NXDOMAIN and NODATA both produce an empty record set and therefore the same sha256, so the two most meaningful DNS transitions — a zone being deleted (NODATA→NXDOMAIN) and a name being created (NXDOMAIN→NODATA) — are invisible. `rrset_digest` sorts values, lower-cases, dot-normalises, and **excludes TTL** (including it makes every record set "change" every run as the counter ticks down).

**Diff against the last *conclusive* prior observation**, not the previous run. A run may be partial, and run-to-run comparison silently breaks the first time one is — and the breakage looks like change. Last-conclusive also yields a better sentence: "changed since 2026-08-14, the last time we could see it". `previous_observed_at` and `gap_days` on every `NameChange`.

**`Agreement` is per-`(name, rrtype)`, not per-name.** Measured across the default resolvers: `www.microsoft.com` returns three disjoint addresses from 1.1.1.1 / 8.8.8.8 / 9.9.9.9; `outlook.office365.com` three disjoint 8-address sets. A name-level rollup means a routine CDN A-record disagreement suppresses a perfectly solid CNAME-based finding on evidence from a record type the claim does not use.

**Quorum failure is never silence.** When no digest reaches quorum, emit `ChangeKind.INDETERMINATE` with the per-resolver digests as detail, and count `quorum_failed` alongside attempted/observed/unobserved. Otherwise geo-balanced names are silently excluded from the change list while still counted as observed, and "observed 400/400, 0 changes" reads as a quiet night.

**Counters are per `(name, rrtype)` pair**, stated explicitly — per-name counting lets a name with 5 of 6 rrtypes failed report as fully observed.

**Change vocabulary:**

| Kind | Means |
|---|---|
| `FIRST_OBSERVED` | our coverage grew — permanent, not just run one |
| `APPEARED` | a name we were already watching now resolves |
| `DISAPPEARED` | conclusively gone |
| `MODIFIED` | the record set changed |
| `INDETERMINATE` | resolvers disagreed; no quorum |
| `UNOBSERVED` | **we could not look** — our outage |
| `NOT_LOOKED_AT` | **the gate refused it** — a deliberate instruction |

`UNOBSERVED` and `NOT_LOOKED_AT` are distinct: one is our failure, the other is the operator adding an exclusion. Without the second, adding `ScopeRule(WILDCARD, '*.legacy.example.com', is_exclude=True)` on Monday makes Tuesday's sweep report 40 DISAPPEARED — "your DNS records were deleted" — on a day when nothing changed. Refusals produce first-class rows the diff can see (`Refusal` carrying name + exception type + message, not a bare `List[str]`), and `degraded` is true when refusals is non-empty.

**Only a conclusive observation may supersede a stored record set.** A resolver outage otherwise reads as the customer's entire DNS being deleted overnight.

**The first run reports a named BASELINE:** `comparison=BASELINE`, empty change list, non-zero `established`. Both obvious answers misrepresent what happened — reporting everything as new makes run one the noisiest report the customer ever gets on a day when none of it is actionable, training them to dismiss the feed before the first true change arrives; reporting nothing is indistinguishable from a failed run.

**`headline()` is built from `established`, not `attempted`.** A degraded baseline gets its own sentence: *"First observation of 32 of 412 name(s); 380 could not be resolved (2 of 3 resolvers failed) and are not baselined — they will baseline on the first run that can see them."* The design's specified sentence asserts 412 first observations against 32 actual ones.

**Takeover assessment is a STATE judgement and runs fully on the first sweep** — a dangling CNAME is dangerous the first time you look at it. Separating state from change is why they are separate modules.

### 8.4 Takeover — the confidence vocabulary

**There is no `vulnerable` and no determination tier, ever.** The only experiment that would upgrade "this looks claimable" to "this is claimable" is registering the resource, which is `exploit_attempt` — PROHIBITED before scope or ownership are consulted. The reason stated to the reader is capability, not caution: we did not run the confirming experiment because this product refuses to run it. The module docstring must say so explicitly, or a future contributor reads the ceiling as an unfinished feature.

```python
class TakeoverVerdict(str, enum.Enum):
    REGISTRABLE_DOMAIN_UNREGISTERED = "registrable_domain_unregistered"  # determinable in P1
    CLAIMABLE_LOOKING               = "claimable_looking"                # NOT reachable in P1 — §11
    PROVIDER_GUARDED                = "provider_guarded"
    INTERNAL_DANGLING               = "internal_dangling"
    NO_CLAIM_SIGNAL_FOUND           = "no_claim_signal_found"
    INCONCLUSIVE                    = "inconclusive"
```

`NOT_CLAIMABLE` is renamed **`NO_CLAIM_SIGNAL_FOUND`**. The original asserts a negative the product cannot establish: a dangling CNAME pointing at a provider absent from the catalogue, or one whose unclaimed page changed since `last_reviewed`, would be returned as "safe" — and it renders identically to a resource an attacker has *already* claimed. `TAKEOVER_MEANING` states what was looked for and what was not.

`PROVIDER_GUARDED`'s meaning string **interpolates the rule's `last_reviewed` and the catalogue version**: "guarded per rule catalogue v7, provider policy last reviewed 2026-02-11" is defensible; "guarded" is not.

**`REGISTRABLE_DOMAIN_UNREGISTERED` is P1's headline takeover finding** and is fully PASSIVE. A CNAME or NS pointing at an expired registrable domain is takeable by anyone for the price of a registration — no provider account needed — and the designs demoted it to a bare string in `dangling_unrecognised_provider`, never stored, never ranked, never retired, while a guarded Azure hostname nobody can take produced a tracked finding. It is corroborated by `rdap_lookup` (PASSIVE, newly registered), and `registrable_domain_status` is a typed enum with the RDAP response recorded as evidence. `Corroboration.REGISTRATION_OPEN` is bound to exactly this producer and applies only to the domain-registration variant — otherwise it is dead vocabulary advertising a tier the product refuses to reach.

### 8.5 Mandatory evidence, enforced structurally

`TakeoverFinding(verdict, corroboration, evidence, reasons)` — all four required, no defaults. `TakeoverEvidence` is frozen with required `name`, `chain`, `target`, `target_resolutions` (**plural — a tuple**), `resolvers_consulted`, `rule_catalogue_version`, `observed_at`, `wildcard_in_parent`.

`__post_init__` makes the classic false positives **unrepresentable**:

| Invariant | Prevents |
|---|---|
| `target == chain[-1]`, `chain` not truncated, no loop | a claim on an intermediate hop of a capped chain |
| `target_resolution.question in (name, target)` | pasting in a resolution of a different name |
| every resolution `conclusive` (`NOERROR`/`NXDOMAIN`, no transport error) | the SERVFAIL-as-NXDOMAIN false positive |
| `len(target_resolutions) >= 2` from **distinct operators**, agreeing on rcode | one filtering or poisoned resolver manufacturing a claim |
| `agreement is Agreement.AGREED` for the chain's rrtypes | a disagreeing estate producing a claim |
| `rule is not None` | a claim with no named provider rule |
| `not rule.claim_requires_domain_verification` | the measured Azure case |
| `wildcard_in_parent is False` | see below |

**`wildcard_in_parent` is required and tri-state**, with `None` ("not checked") **barring** any claim and rendering as "wildcard status not checked" rather than being absent. A customer with `*.example.com CNAME assets.s3.amazonaws.com` and a deleted bucket otherwise gets one finding per discovered name — 400 claimed hijackable subdomains where there is one deletable wildcard record. When the parent zone synthesises a matching target, collapse to **one finding keyed on `(zone, target)`** with the affected-label count as detail. The field names the customer's zone, which is the one that synthesises.

`_ISSUER`-style tokens are deliberately **not** used here. That pattern exists in `gate.py` because the adversary is a plugin author routing around a governance boundary. Here the adversary is a careless internal caller building a truth claim, and an invariant that raises with a sentence explaining *why* the evidence is insufficient teaches something a token cannot.

### 8.6 Provider rules

`data/takeover_rules.json`, vendored and versioned like `data/kev.json`, refreshed by `tools/refresh_takeover_rules.py`. An empty or missing catalogue **raises `RulesUnavailable`** — zero takeover findings is indistinguishable from a clean estate.

Every rule requires `source_url` and `last_reviewed` (a fingerprint with no provenance is an assertion), plus two fields most tooling omits and measurement proves load-bearing:

- `nxdomain_is_signal` — measured live: S3 → NOERROR/10, S3-website → NOERROR/9, github.io → NOERROR/4, herokuapp → NOERROR/5, cloudfront → NODATA, azurewebsites → NXDOMAIN, blob.core.windows.net → NXDOMAIN. **Five of seven give an unclaimed resource a DNS answer indistinguishable from a claimed one**; an NXDOMAIN-based detector has ~70% false negatives on this sample.
- `claim_requires_domain_verification` — the two that *do* NXDOMAIN are both Azure, which requires domain-ownership proof before binding a hostname. On this sample the NXDOMAIN signal is **anti-correlated** with claimability: it fires exactly where it is least actionable.

**Consequence for P1:** the five NOERROR providers structurally cannot reach `CLAIMABLE_LOOKING` without an HTTP probe, and P1 does not ship the probe. They report `INCONCLUSIVE` with `probes_unavailable` stated. This is honest and is §11's central deferral.

`tools/refresh_takeover_rules.py` refuses a partial catalogue, refuses any rule missing `source_url`/`last_reviewed`, **returns** rejects rather than dropping them, and warns on rules older than a threshold.

### 8.7 Retirement

`RetireReason` is `RECORD_REMOVED`, `TARGET_CLAIMED`, `RULE_WITHDRAWN`. **`UNOBSERVED` is removed.** D11 says telling a customer their finding was fixed when the resolver was merely down is a worse lie than the finding was — and then retires on exactly that. A three-day resolver outage would silently close every open finding. Instead `StoredFinding` gains `last_confirmed_at` and `runs_unobserved`, surfaced as a staleness badge. Retirement requires a conclusive observation.

---

## 9. Subsystem C — active fingerprinting

`core/identity.py`, `core/signatures.py`, `collect/ports.py`, `collect/http_probe.py` (all NEW).

### 9.1 What fingerprinting writes — the join contract

**The contract, exactly:** `tokens(asset.product)` must be a **non-empty subset** of `tokens(entry.product) | tokens(entry.vendor_project)`. Measured against the real corpus:

| written | tokens | exposures |
|---|---|---|
| `unknown` | `{unknown}` | 0 |
| `Apache/2.4.54 (Ubuntu)` | `{apache, ubuntu}` | **0** — the distro token vetoes |
| `cpe:2.3:a:apache:http_server:2.4.54` | `{apache, cpe, http}` | **0** — the `cpe` literal vetoes |
| `Windows Server 2019` | `{2019, windows}` | **0** — the year is a token |
| `Apache HTTP Server` + vendor `Apache` | | 4 STRONG |
| `Zimbra` + vendor `Zimbra` | | 19 **PARTIAL** |
| `Zimbra` + vendor `Synacor` | | 19 **STRONG** — CISA files it under Synacor |
| `Connect Secure` + vendor `Ivanti` | | 14 (13 STRONG) |

Rules that fall out and are enforced by `core/signatures.py`:

1. Write a **canonical product name from a reviewed table**, never the observed banner. Every extra token is a veto.
2. **Never leave the version in `product`.** Any component ≥3 characters becomes a token and vetoes.
3. **Write `vendor` as a separate field** — `_corresponds(asset_vendor, tokens(entry.vendor_project))` compares against `vendor_project` *alone*, so it is the only lever that reaches STRONG, and `Confidence` is the 4th key in `match.rank()`.
4. **The catalogue's spelling, not the vendor's.**

### 9.2 The signature breadth cap — **vendor span, not hit count**

The design proposed `MAX_CATALOGUE_BREADTH = 25`. Measured, that is the wrong metric and it inverts the populations:

| signature | hits | vendors | design's cap | correct |
|---|---:|---:|---|---|
| `Cisco` + Cisco | 96 | **1** | refused | admit |
| `Chromium` + Google | 63 | **1** | refused | admit |
| `Oracle` + Oracle | 45 | **1** | refused | admit |
| `Apache` | 40 | **1** | refused | admit |
| `Fortinet` + Fortinet | 29 | **1** | refused | admit |
| `Security Gateway` + Check Point | 28 | **8** | refused (barely) | refuse |
| `Routers` + D-Link | 27 | **9** | refused (barely) | refuse |
| `Windows` + Microsoft | 177 | **3** | refused | refuse |
| `IOS XE` + Cisco | 79 | **2 (Apple + Cisco)** | refused | refuse |

Hit count measures how often a product has been exploited, not how imprecise the signature is; in the 25–40 band it does not separate the two populations. It also makes a `refresh_intel.py` bump that takes Confluence from 9 to 26 turn a working signature into a CI failure — *the more a product is exploited, the more likely SKOPOS stops identifying it* — and it makes a `Precision.FAMILY` signature illegal for every KEV-heavy appliance vendor, so a FortiGate portal identified by TLS cert `O=Fortinet` could not be written at all.

**Binding rule:** refuse any signature whose measured `catalogue_profile` spans **more than one `vendor_project`** unless the span is explicitly declared in `expect_vendors`. Declarable spans measured and legitimate: `Connect Secure` → Ivanti + Pulse Secure (rename); `VMware` → VMware + VMware Tanzu + Broadcom (acquisition); `D-Link` → D-Link + "D-Link and TRENDnet" (a catalogue vendor-string quirk).

`FORBIDDEN_PRODUCT_TOKENS` is retained for the OS-family case (`windows`, `ios`, `microsoft`, `cisco`, `apple`, `multiple`, `kernel`) — measured, `IOS XE` tokenises to `{ios}` (`xe` is below `MIN_TOKEN`) and pulls 33 Apple iOS entries onto a Cisco router. An OS-family identification is recorded in `obs_*` attributes and never written to `product`.

**Golden test — `tests/test_signatures.py`:** assert `vendors == expect_vendors`; report hit-count drift **non-blocking** so a corpus refresh surfaces change without forcing signature deletion. `tools/refresh_intel.py` invokes it, or the guard is decorative.

### 9.3 The unidentified host

Unspecified in the design, and both available values misreport. Measured: an empty `product` makes `inventory.from_rows` reject the row with `reason: "no product column recognised"` — a false reason, and the host vanishes from `assets_read`, misdirecting the operator to fix their CSV headers. Carrying `unknown` through folds it into `assets_matched_nothing`, indistinguishable from a host that *was* fingerprinted and genuinely runs nothing in KEV.

**Rule:** write `product='unidentified'` (distinct from discovery's `unknown`), empty `obs_attestation`, and count `identified` vs `probed_unidentified` in the sidecar. Then `unknown` means "never probed" and `unidentified` means "probed, no signature fired". Both are in `STOPWORDS` (§2.3), so the zero-match safety is structural.

### 9.4 Version — `PRODUCT_MATCH` only, refused structurally

A fingerprint justifies `PRODUCT_MATCH` and **can never justify `VERSION_RANGE`**. A banner version is not an outside fact about the build; it is the assertion of the party whose patch state is the question, and it fails both ways — distribution backporting makes it a false positive, header suppression a false negative.

The danger is live in shipped code: `engine.score_exposure` sets `basis = MatchBasis.VERSION_RANGE` for **both** `AFFECTED` and `NOT_AFFECTED` (lines 188–193), so a spoofed high version would produce a determination that **retires** the finding — a target-controlled string deleting entries from the customer's worklist. Because `affected_versions` is never passed today, writing a banner version into `Asset.version` would be inert *now* and become determination-grade the day CNA ranges are wired, with no code change and no review.

**The refusal is a column name:** the writer emits `obs_version`, which normalises to `obsversion` and is absent from `inventory.ALIASES['version']` (measured), so it lands in `attributes` where `affected.evaluate()` — which reads `asset.version` only — cannot reach it. `Attestation.can_determine_version` is True for `OPERATOR` alone.

**Attestation vocabulary — three values, no score.** `SELF_REPORTED` (the asset said so: `Server`, `X-Powered-By`), `INFERRED` (concluded from behaviour the asset did not intend as a claim: certificate issuer/subject, a default error page's byte pattern), `OPERATOR` (the customer's own record). They fail differently: the first is switched off by one line of config and edited freely by anyone who owns the box; the second is a side effect of running the software. A numeric confidence would invite a threshold, the threshold gets tuned until the list looks right, and the tuning becomes the product's real opinion where nobody can see it — the argument `Confidence`'s docstring already makes.

### 9.5 Ports

`WEB_PORTS = (443, 80, 8443, 8080)` — the default, and the only ports on which a `Host:`/SNI request is virtual-host routed to the tenant, which is exactly the reach of a name-based ownership proof. No top-1000, no full range: the abuse-report and consent surface scales with the port count while the identity yield does not.

**`PROBE_PORTS = engine.SENSITIVE_PORTS - ICS_PORTS`, with `ICS_PORTS = frozenset({102, 502, 20000, 44818, 47808})`.** Measured — `engine.SENSITIVE_PORTS` contains Modbus, S7comm, DNP3, EtherNet/IP and BACnet. Reusing it wholesale conflates "dangerous to expose" (a scoring judgement, safe) with "safe to touch" (a collection judgement, not safe). A bare TCP connect is a documented cause of PLC faults; "never sends a byte first" does not help, because on these devices the handshake is the hazard. 47808 is UDP BACnet, so a TCP connect there has zero yield and pure downside. The scorer's list is unchanged so TEPS still treats an exposed Modbus port as dangerous. Test: `test_no_ics_port_is_ever_probed`. OT visibility, if ever wanted, needs its own operation, its own consent conversation and a maintenance window — not a `--ports` value.

`banner()` is **read-only** — connect, read ≤512 bytes, close, never send first. MySQL greets on connect and is identified; Redis does not and yields nothing rather than being talked to. Nothing ever presents credentials (`credential_replay` is PROHIBITED).

### 9.6 Reachability is tri-state everywhere

`ServiceObservation.reachable: Optional[bool]` and `PortSweep.external_reachable() -> Optional[bool]`. The design typed the *default* path — HTTP, which is the path that runs without CIDR rules — as a bare `bool`, in the one type that cannot express "unknown".

- `True` on a completed handshake.
- `False` **only** on an explicit RST from every probed port.
- `None` for timeout, DNS failure, limiter halt, budget skip, or TLS abort, with the reason in `detail`.

Measured consequence of getting it wrong: a host behind a DROP firewall times out on four ports → `False` → `reconcile(False, NOT_REACHABLE)` → `AGREED_CLOSED`, served as *"Both methods agree this is not reachable from the internet."* SKOPOS never reached it and does not know. The mirror case manufactures a `BLIND_SPOT` from its own timeout.

**With the four-web-port default, emit `True` or `None` and never `False`** — four ports cannot establish unreachability, and a bastion with only SSH open would otherwise be reported as agreed-closed. `obs_reachable` is accompanied by `obs_reachable_on_ports`. `AGREED_CLOSED` is documented as unreachable until a wider sweep exists.

### 9.7 Freshness

`_observed_reachability(asset)` reads `obs_probed_at` and returns `None` past a 30-day horizon, surfacing the age in the finding's evidence — *"external reachability observed 2026-03-14, 161 days ago"* — the way corpus age already travels with every result. A March `fingerprinted.csv` scanned in September otherwise produces `CONFIRMED` — "two independent methods agree" — for a host decommissioned in April. Normalise the truthiness check (`str(v).strip().lower()`): csv round-trips Python `True` as `"True"`.

### 9.8 Observed ports reach the scorer — `core/engine.py` EDIT

`build_exposure_factors` derives `service_sensitivity` exclusively from `cloud.context.exposed_ports`; there is no path for a sweep result. Measured: a host swept with 3389/RDP open, no OverWatch graph, scores `service_sensitivity = 0.4` with the evidence line *"no port data; assumed a public web surface"* — a false statement about a host the tool just measured.

Add `observed_ports: Sequence[int] = ()` to `build_exposure_factors` and `score_exposure`, unioned with the cloud model's ports before the `SENSITIVE_PORTS` lookup, with **separate evidence lines** so a reader can tell which method saw which port.

### 9.9 Exposure age is a lower bound, never a manufactured zero

`days_exposed: Optional[int]`, contributing 0 when `None` **and appending the flag** "first seen unknown; exposure age not scored". The precedent is one function away: `business_criticality(None)` takes the midpoint and flags it. Prefer the estate-side date (`obs_first_seen`, the earliest certificate `not_before`) over the date SKOPOS first looked — feeding first-observation into `days_exposed` scores when *we* arrived, which is the same "our coverage grew ≠ their estate changed" error `FIRST_OBSERVED` exists to prevent, fed straight into a scored output. Normalise the join key and report how many assets the lookup could not resolve.

### 9.10 Failure containment

A target-controlled string that trips the redaction guard must not abort the run. `main()` catches only `IntelUnavailable` and `FileNotFoundError`, so a `ValueError` from an observation constructor exits with a traceback after N hosts having written no file — letting an unauthenticated remote party abort the run and double the traffic the politeness budget bounds. Catch at the construction site, record `IdentitySignal(kind='rejected', detail='discarded: contained CVE-shaped text')`, count it in the sidecar, and wrap the per-host loop so one host never ends the run.

---

## 10. CLI and API surface

### 10.1 CLI — `main.py` EDIT (**MERGE POINT — all three subsystems**)

| Command | Args | New/Edit |
|---|---|---|
| `etlm scope add <value>` | `--kind {domain,wildcard,cidr,asn,cloud_account,repo_org,app_publisher}` `--exclude` `--note` `--actor` | **NEW — unblocks everything** |
| `etlm scope list` | | NEW |
| `etlm verify <asset>` | `--method {dns_txt,well_known,manual}` `--approved-by` `--actor` | NEW |
| `etlm discover <domain>` | `-o` `--actor` `--source` (repeatable) `--allow-noncommercial` `--list-sources` `--dry-run` | EDIT |
| `etlm dns-sweep <names.csv \| --from-discovered>` | `--resolvers` `--wildcard-probe` `--plan` `--actor` | NEW |
| `etlm dns-changes` | `--run` `--since` `--limit` | NEW |
| `etlm takeover` | `--limit` `--json` | NEW |
| `etlm dns-runs` | `--limit` | NEW |
| `etlm fingerprint <inventory.csv>` | `-o` `--actor` `--ports web\|sensitive\|<list>` `--concurrency` `--budget` `--deep` `--dry-run` | NEW |
| `etlm scan <inventory>` | + reads the coverage sidecar; **now scores and reconciles** | EDIT |

**`etlm scope add` must ship in P1 or nothing runs.** Measured: `open_store()` is `PostgresStore` and raises without `SKOPOS_DATABASE_URL`; `db/001_schema.sql` seeds no rows; `add_scope_rule` is called from two test files and nowhere else; `api/app.py` has no scope route. On a fresh clone, `docker compose up -d` then `etlm discover example.com` would refuse every operation, raise `DiscoveryUnavailable`, and exit 2 with **no supported command that fixes it** — the operator would have to hand-write `INSERT INTO scope_rule`. The `NotInScope` message names the command.

**`--actor` is required with no default** — never `getpass.getuser()`. The CLI help and docs state that the actor string is **asserted, not authenticated**, so the audit chain attributes a claim rather than an identity.

**Active collection refuses without a store.** `cmd_fingerprint`, `cmd_dns_sweep` and `cmd_takeover --probe` exit 2 when `open_store()` raises, with a message stating that active collection requires an audit destination surviving a restart. There is no `--assume-verified` and no file-based scope fallback: running without a store means running without the scope and ownership data the gate needs, and a YAML the operator wrote thirty seconds earlier makes FR-GOV-001 a formality. Test: `test_fingerprint_refuses_without_a_store`. *(Stated cost: `discover` and `fingerprint` now hard-require Postgres, which cuts against NFR-USE-003. `scan` and `intel` remain fully offline.)*

**`--deep` path probing is its own ACTIVE operation** — a dozen appliance-specific requests is not the `http_probe` a customer consented to, and the audit must name what was actually done. *(Deferred to P2 with the operation left unregistered; `--deep` is not implemented in P1.)*

### 10.2 API — `api/app.py` EDIT (**MERGE POINT**)

| Route | Notes |
|---|---|
| `GET /api/v1/dns/runs` | resolvers, attempted/observed/unobserved, degraded, age of newest run |
| `GET /api/v1/dns/changes` | comparison, counts, changes, quorum_failed, wildcard_zones |
| `GET /api/v1/discovery` | per-source outcomes, degraded/narrowed/refused, coverage note |
| `GET /api/v1/takeover` | **token-gated — see below** |
| `GET /api/v1/takeover/meaning` | `TAKEOVER_MEANING` |
| `GET /api/v1/dns/change-meaning` | `CHANGE_MEANING` |
| `POST /api/v1/scan` | EDIT — `external_reachable` and `observed_ports` read per asset |

Meaning strings are **served**, not hard-coded in TSX, on the `RECONCILIATION_MEANING` precedent — so the API, the CLI and the UI cannot drift into describing the same state differently.

**`/api/v1/takeover` requires a bearer token.** A ranked list of claimable-looking subdomains with evidence attached is finished reconnaissance, and this is the first content in the product where the absence of auth genuinely matters. If `SKOPOS_API_TOKEN` is unset the route is **not registered at all** and `/api/v1/health` says so. Test: `test_the_takeover_route_is_absent_without_a_token`.

**Correct the reasoning, in the design and in `api/app.py`'s docstring:** the API is read-only because no write route exists — *not* because of `allow_methods=["GET"]`. Measured: `POST /api/v1/scan` already exists and is callable with curl; CORS is a browser-side cross-origin control, and the Dockerfile serves the SPA from the **same origin**, where CORS never applies. A future contributor who reads "GET-only by construction" and adds a POST believes something false.

**No POST trigger for collection.** A route that triggers active collection from a browser collects without an operator present to have read the refusals.

---

## 11. What P1 deliberately does NOT do

| Deferred | Why |
|---|---|
| **Takeover `CLAIMABLE_LOOKING`** (the ACTIVE corroboration probe) | Blocked on a genuine circularity both critics found independently. Confirming needs an ACTIVE probe → needs a current `Verification` for that exact name → **RFC 1034 forbids a CNAME coexisting with any other record at the same name**, so no DNS TXT is placeable, and `/.well-known` cannot be served because the name points somewhere the customer does not control. The proposed fix (`Method.PARENT_ZONE`, valid only where the zone-cut check proves the child is served from the parent's zone) is sound — a CNAME at the leaf is a record authored in the parent's zone file, and NS and CNAME cannot coexist, so whoever controls the parent wrote it and can delete it; the case where it is false is a delegated subzone, which is precisely the NS-takeover variant the check detects and refuses to cover. **But it edits the product's most load-bearing check and is a sponsor decision.** P1 ships the passive tier, capped, with `probes_unavailable` counted and stated. *If PARENT_ZONE is approved, the zone-cut evidence must be gathered PASSIVELY (an NS/SOA walk up the label chain via third-party recursive resolvers), or the check that justifies the relaxation itself requires the relaxation.* |
| **The subfinder adapter** | Its `-silent -json` output is a stream of names it *found*; a source that returned nothing, was rate-limited, or lacked a key is simply absent, with no machine-readable per-source status. Shelling out makes "was that 12 names, or 12 because four sources were down" unanswerable — the exact confusion this subsystem exists to prevent. Its default keyless set includes RapidDNS (HTML scraping under terms that do not contemplate automation) and ThreatCrowd (long dead, its silence indistinguishable from an empty answer). It also delegates the exposure classification of ~60 third parties outside `gate.OPERATIONS`, changing with the binary's version. `available()` reaching the binary would additionally break `--dry-run`'s "zero network contact" promise via ProjectDiscovery's startup update check. |
| **`Method.PARENT_ZONE`** | See row 1. Specified, not built. |
| **NS-delegation takeover** | Shares the evidence model and zone-cut machinery; broadens the slice. The zone-cut code exists for the RDAP path. |
| **Wayback in `DEFAULT_ENABLED`** | Registered, `--source wayback`. The archive-staleness question (does an old `last_seen` exclude a name or annotate it?) is unsettled, and a design cannot ship a source on by default while recording that doing so is blocked. |
| **OTX / HackerTarget by default** | Terms (§7.1). |
| **`--deep` path probing** | Needs its own registered operation so it can be refused separately; `http_probe` consent does not cover a twelve-path 404-hunt. |
| **ICS/OT port probing** | §9.5. Not a `--ports` value; needs its own operation and consent conversation. |
| **`VERSION_RANGE` determinations** | Needs CNA `affected[].versions[]`, not a banner. §9.4. |
| **Full-range / top-1000 port scans** | §9.5. |
| **`idna` normalisation** | Measured name corruption (§3.5). Two rows for one name is honest; a name nobody observed is not. |
| **Retention / partitioning for `dns_observation`** | The append-only grants leave no prune path. Partition-and-drop is the likely answer and needs a decision about compatibility with the evidence stance. Stated, not solved. |
| **Cross-run rate budgets** | A nightly run over 30 apexes is inside mnemonic's 1000/day but exhausts HackerTarget's free tier before the estate is covered, so later apexes report PARTIAL. Correct per-run; derivable later from the per-source audit records without a schema change. |
| **API authentication generally** | Only `/api/v1/takeover` is gated in P1. The rest is unchanged and unauthenticated, and that is a known gap, not a decision. |
| **Tenancy (FR-M0-001)** | Sponsor decision. `db/002_p1.sql` takes `org_id` without a rewrite. |
| **Brand / lookalike-domain monitoring** | Structurally incompatible with the apex-must-be-INCLUDED rule — `evil-examp1e.com` will never be in the customer's scope. Needs its own operation or a `ScopeKind.BRAND` whose rules describe what you are *protecting* rather than what you *own*. Decide before building, because the answer changes what `authorise()` is asked. |

---

## 12. Critique disposition

Every critical and major problem. **F** = fixed here, **R** = rejected with reason, **D** = deferred with the feature.

### Passive discovery

| # | Problem | | Where |
|---|---|---|---|
| A1 | Third-party text → `declared_cves` injection | F | §2.2 |
| A2 | Gate refusal downgraded to `narrowed`, exit 0 | F | §5.2 |
| A3 | CIDR exclusions cannot fire for discovered names | F | §7.2(3) |
| A4 | `plan()` reaches the subfinder binary | F | §11 (dropped) |
| A5 | Permit binding decentralised into 8 modules | F | §3.4 |
| A6 | `ct.discover` shim makes `scope` optional | F | required positionally; ~10 lines of test migration accepted |
| A7 | Wayback over plaintext HTTP | F | §3.3 (HTTPS enforced) |
| A8 | No rate limiting; uncapped `Retry-After` | F | §3.3 |
| B1 | No scope writer → unrunnable on every install | F | §10.1 |
| B2 | Refusal reported as outage; exit-code contradiction | F | §5.2 |
| B3 | Honesty artefacts never reach the CSV | F | §5.5 |
| B4 | `names_found` silently changes meaning | F | §3.2 (`contributed`/`returned`) |
| B5 | `enabled()` prereports have no path into the result | F | §7.1 (`prereports=`) |
| B6 | min/max dates flattened across data classes | F | §7.3 |
| B7 | Wayback default contradicts its own risk register | F | §7.1 / §11 |
| B8 | `idna` corrupts `faß` → `fass` | F | §3.5 |
| B9 | Unregistered operation fails softly | F | §5.2 |
| B10 | CIDR exclusion silently ineffective | F | §7.2(3) |
| B11 | `ct.discover` scope-optional | F | as A6 |

Minors also fixed: dropped names returned (§5.6); `http.py`'s false structural claim (§3.3, permit required); audit brackets the contact (§5.7); wildcard arithmetic (§7.5); positive-parse rule for text endpoints (§7.1); `ct:` prefix (§7.4); blackout audits (§5.3); `obs_scope` reworded + real enforcement (§7.2); `Retry-After` cap (§3.3); `unknown` in STOPWORDS (§2.3).

### DNS + takeover

| # | Problem | | Where |
|---|---|---|---|
| A1 | CNAME hops resolved with no permit; excluded names reached | F | §8.2 |
| A2 | `wildcard_present` permit-free; is `subdomain_bruteforce` | F | §4 (own ACTIVE op, opt-in, fixed label) |
| A3 | Packet destination caller-controlled, unauthorised | F | §3.3 (allowlist) |
| A4 | ACTIVE ops unaudited unless a finding results | F | §5.7 |
| A5 | `db/002` never executes on an existing deployment | F | §2.5 |
| A6 | `CLAIMABLE_LOOKING` from a single resolver | F | §8.5 (quorum invariant + SQL) |
| A7 | Provider body is attacker-controlled; no `peer_ip` | D | ACTIVE tier deferred; `peer_ip` + provider-range check specified for when built |
| A8 | PARENT_ZONE evidence is circular | F+D | §11 (zone-cut made PASSIVE; tier deferred) |
| A9 | No query budget; self-DoS profile | F | §3.3 |
| B1 | `CLAIMABLE_LOOKING` unreachable over HTTPS (cert mismatch) | D | ACTIVE tier deferred; port-80 + `transport` field specified for when built |
| B2 | Target resolution is always out of scope | F | §8.2 |
| B3 | SQL constraint inverted by IntEnum serialisation | F | §6 |
| B4 | Resolver disagreement undefined in `diff()` | F | §8.3 (`INDETERMINATE`, `quorum_failed`) |
| B5 | `Agreement` per-name, not per-rrtype | F | §8.3 |
| B6 | Partial index excludes conclusive negatives | F | §6 |
| B7 | Digest collides NXDOMAIN with NODATA | F | §8.3 (`(rcode, digest)`) |
| B8 | A refused name reads as DISAPPEARED | F | §8.3 (`NOT_LOOKED_AT`) |
| B9 | `wildcard_in_parent` unenforced; `None` ≡ `False` | F | §8.5 |
| B10 | Single-resolver target manufactures a claim | F | §8.5 |
| B11 | `NOT_CLAIMABLE` / `PROVIDER_GUARDED` overclaim | F | §8.4 |
| B12 | Expired registrable domain cannot be a finding | F | §8.4 — becomes P1's headline takeover verdict |
| B13 | Wildcard probe permit-free and cache-defeating | F | §4 |
| B14 | `raise_finding` has no dedup | F | §6 (UNIQUE + upsert) |
| B15 | Retiring as `UNOBSERVED` lies to the customer | F | §8.7 |

Minors: `assert` under `-O` → explicit `raise` (§3.3); `first_seen` ≠ exposure age (§9.9); takeover endpoint auth + corrected CORS reasoning (§10.2); `Chain.truncated`/`loop` in evidence (§8.2, §8.5); BASELINE headline counter (§8.3); `REGISTRATION_OPEN` bound to RDAP (§8.4).

### Active layer

| # | Problem | | Where |
|---|---|---|---|
| A1 | **Permit forgeable via `dataclasses.replace`** | F | §2.1 — measured |
| A2 | CIDR excludes never consulted on the HTTP path | F | §5.1 |
| A3 | `open_tcp` has no `operation`; any port reachable | F | §3.3 (`PORTS_BY_OPERATION`) |
| A4 | `--ports sensitive` probes ICS/OT | F | §9.5 |
| A5 | No global rate ceiling | F | §3.3 (three buckets) |
| A6 | `ServiceObservation.reachable` is `bool` | F | §9.6 |
| A7 | Redaction narrower than its sink (case + fields) | F | §2.2 |
| A8 | `_preflight` built on `refusal_reasons(verification=None)` | F | §2.6 (`gate.plan`) |
| B1 | Redaction covers one field only | F | §2.2, §5.4 |
| B2 | Case-sensitive pattern misses `re.I` sink | F | §2.2 |
| B3 | Unqualified `reachable` → false `AGREED_CLOSED` | F | §9.6 |
| B4 | Closed `COLUMNS` destroys operator columns | F | §5.4 |
| B5 | `MAX_CATALOGUE_BREADTH` is the wrong metric | F | §9.2 — measured, cap changed to vendor span |
| B6 | `coverage_note()` lost at the file boundary | F | §5.5 |
| B7 | Unidentified-host `product` unspecified | F | §9.3 |
| B8 | Grep test fails on day one / scope too narrow | F | §3.3 (`NETWORK-BOUNDARY` markers) |
| B9 | ASN fallback impossible | F | §5.1 (dropped, message names it) |
| B10 | Observed ports never reach the scorer | F | §9.8 |
| B11 | `reachable` bool on the default path | F | §9.6 |

Minors: `probed_at` staleness (§9.7); observation `raise` aborting the run (§9.10); the `external_reachable` benefit only reachable via POST (§10.1 — `cmd_scan` now scores); offline store + unauthenticated actor (§10.1).

---

## 13. Build order

Numbered. **MERGE POINT** marks a file more than one subsystem edits — land it once, early, and rebase.

### P1a — governance corrections (blocks everything)

| # | File | | Notes |
|---|---|---|---|
| 1 | `core/gate.py` | **EDIT — MERGE POINT** | HMAC seal; `Permit.addresses`; `authorise_target()`; `plan()`; `OPERATIONS` +7 |
| 2 | `tests/test_gate.py` | **EDIT — MERGE POINT** | forgery-by-mutation; address exclusion; ASN; ordering preserved |
| 3 | `core/provenance.py` | NEW | `TOOL_PREFIX`, `redact()`, `write_rows()` |
| 4 | `core/match.py` | **EDIT — MERGE POINT** | `CVE_PATTERN` public; `declared_cves` skips `obs_`; STOPWORDS +3; `unmatched_assets` dedupe |
| 5 | `core/models.py` | EDIT | reject `product=None` |
| 6 | `core/migrate.py` | NEW | `ensure_current()`, `SchemaBehind` |
| 7 | `db/002_p1.sql` | NEW | §6 |
| 8 | `core/store.py` | EDIT | call `ensure_current()`; `verifications()` listing |
| 9 | `tests/test_provenance.py` | NEW | injection round-trip; alias-collision guard |
| 10 | `tests/test_store_postgres.py` | EDIT | assert constraints exist via `pg_constraint`/`pg_rules` |

### P1b — shared egress and vocabulary

| # | File | | Notes |
|---|---|---|---|
| 11 | `collect/report.py` | NEW | `Outcome`, `SourceReport`, flags |
| 12 | `collect/egress.py` | NEW | `require`, `Budget`, `Limiter`, `tcp`/`udp`/`http_get` |
| 13 | `collect/ct.py` | **EDIT — MERGE POINT** | port onto `egress` + `report`; permit param; `NameObservation` |
| 14 | `tests/test_ct_discovery.py` | **EDIT — MERGE POINT** | permit/scope fixtures (~10 lines) |
| 15 | `tests/test_egress_boundary.py` | NEW | `NETWORK-BOUNDARY` marker scan |

### P1c — the CLI that unblocks the operator

| # | File | | Notes |
|---|---|---|---|
| 16 | `main.py` | **EDIT — MERGE POINT (all three subsystems)** | `scope add/list`, `verify`; exception clauses; `--actor` required |
| 17 | `tests/test_cli_scope.py` | NEW | round-trip + audit record |

### P1d — passive discovery

| # | File | | |
|---|---|---|---|
| 18 | `collect/discovery.py` | NEW | merge, containment, scope, `unreadable` |
| 19 | `collect/registry.py` | NEW | source table, `Terms`, `TERMS_REVIEWED_ON` |
| 20 | `collect/passive_dns.py` | NEW | mnemonic, OTX |
| 21 | `collect/names.py` | NEW | Anubis, HackerTarget, Wayback |
| 22 | `collect/run.py` | NEW | the only caller of `authorise()` for discovery |
| 23 | `main.py` | EDIT (merge point) | `cmd_discover` rewrite |
| 24 | `tests/test_discovery_sources.py`, `tests/test_discovery_gate.py` | NEW | |

### P1e — DNS, change tracking, takeover

| # | File | | |
|---|---|---|---|
| 25 | `collect/dns_wire.py` | NEW | parser + `WireResolver` over `egress` |
| 26 | `collect/dns_records.py` | NEW | `DnsSweep`, chain, per-rrtype agreement |
| 27 | `collect/dns_authoritative.py` | NEW | RD=0 + zone cut (ACTIVE) |
| 28 | `core/dns_state.py` | NEW | `(rcode,digest)` diff, BASELINE |
| 29 | `core/takeover_rules.py` + `data/takeover_rules.json` + `tools/refresh_takeover_rules.py` | NEW | |
| 30 | `collect/rdap.py` | NEW | `rdap_lookup`, PASSIVE |
| 31 | `core/takeover.py` | NEW | verdicts, invariants, `TAKEOVER_MEANING` |
| 32 | `core/dns_store.py` | NEW | `DnsStore` protocol, Memory + Postgres |
| 33 | `main.py` | EDIT (merge point) | `dns-sweep`, `dns-changes`, `takeover`, `dns-runs` |
| 34 | `tests/test_dns_wire.py`, `test_dns_records.py`, `test_dns_state.py`, `test_takeover.py`, `test_takeover_rules.py` | NEW | captured real bytes from the seven measured providers |

### P1f — active fingerprinting

| # | File | | |
|---|---|---|---|
| 35 | `core/identity.py` | NEW | `Attestation`, `IdentitySignal`, `Fingerprint`, `FingerprintRun` |
| 36 | `core/signatures.py` | NEW | table, vendor-span cap, `catalogue_profile` |
| 37 | `collect/ports.py` | NEW | `PortSweep`, `PROBE_PORTS`, banner |
| 38 | `collect/http_probe.py` | NEW | **one module**; serves fingerprinting now, takeover corroboration later |
| 39 | `main.py` | EDIT (merge point) | `cmd_fingerprint` |
| 40 | `tests/test_active_gating.py`, `tests/test_signatures.py` | NEW | |

### P1g — consumption

| # | File | | |
|---|---|---|---|
| 41 | `core/engine.py` | **EDIT — MERGE POINT** | `observed_ports`; `days_exposed: Optional[int]` + flag |
| 42 | `api/app.py` | **EDIT — MERGE POINT** | `_observed_reachability`, ports, new routes, takeover token, docstring correction |
| 43 | `main.py` | EDIT (merge point) | `cmd_scan` reads the sidecar and scores |
| 44 | `frontend/src/api/types.ts`, `App.tsx` | EDIT | coverage panel; render `name_confidence` (declared today, never rendered) |
| 45 | `CLAUDE.md` | EDIT | D12–D15: egress choke point, provenance boundary, vendor-span cap, takeover ceiling |

**Baseline: 150 tests collected.** Every numbered item above lands with its tests in the same commit.