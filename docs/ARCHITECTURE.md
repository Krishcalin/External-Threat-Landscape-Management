<p align="center">
  <img src="skopos-logo.png" alt="SKOPOS" width="420">
</p>

# SKOPOS — Architecture

How the product is put together, and why each boundary is where it is. Written
for somebody about to change the code.

The reasoning behind individual decisions lives in `CLAUDE.md` (D1–D19); this
document is the shape.

---

## Contents

1. [The shape in one diagram](#1-the-shape-in-one-diagram)
2. [The gate — the one authorisation decision](#2-the-gate--the-one-authorisation-decision)
3. [The egress boundary — the one place I/O happens](#3-the-egress-boundary--the-one-place-io-happens)
4. [The pipeline](#4-the-pipeline)
5. [The join, and the two tiers of claim](#5-the-join-and-the-two-tiers-of-claim)
6. [Storage](#6-storage)
7. [The honesty machinery](#7-the-honesty-machinery)
8. [Module map](#8-module-map)
9. [Invariants a change must not break](#9-invariants-a-change-must-not-break)
10. [Adding a collector](#10-adding-a-collector)
11. [What is deliberately absent](#11-what-is-deliberately-absent)

---

## 1. The shape in one diagram

```
                        ┌──────────────────────────────┐
   operator ──CLI──────▶│         main.py              │
                        │  scope · verify · discover   │
   browser ──HTTP──────▶│  dns-sweep · fingerprint     │
                        │  takeover · scan · intel     │
                        └──────────────┬───────────────┘
                                       │
                        ┌──────────────▼───────────────┐
                        │        core/gate.py          │   ← every decision
                        │  authorise() authorise_target│     about touching
                        │        issues a Permit       │     anything
                        └──────────────┬───────────────┘
                                       │ Permit (HMAC-sealed)
                        ┌──────────────▼───────────────┐
                        │      collect/egress.py       │   ← every packet
                        │   tcp() · udp() · http_get() │
                        └──────────────┬───────────────┘
                                       │
        ┌──────────────┬───────────────┼──────────────┬───────────────┐
        ▼              ▼               ▼              ▼               ▼
   ct.py         names.py       dns_records.py   http_probe.py   takeover_scan.py
   (CT logs)     (pDNS,         (multi-resolver  (identity       (dangling +
                  indexes,       sweep)           signals)        RDAP)
                  archive)
        └──────────────┴───────────────┼──────────────┴───────────────┘
                                       ▼
                        ┌──────────────────────────────┐
                        │   core/  reasoning layer     │
                        │  match · affected · scoring  │
                        │  dns_state · takeover        │
                        │  identity · reach · overwatch│
                        └──────────────┬───────────────┘
                                       ▼
                        ┌──────────────────────────────┐
                        │   PostgreSQL  (skopos-db-1)  │
                        │  scope · ownership · audit   │
                        │  dns · takeover · findings   │
                        └──────────────────────────────┘
```

Two choke points, and they are the architecture: **nothing decides whether it may
act except the gate, and nothing reaches the network except egress.**

---

## 2. The gate — the one authorisation decision

`core/gate.py`. Everything else in this document is downstream of it.

### Why it is not in the collectors

A rule enforced inside each collector holds for exactly the collectors that
remembered it. SKOPOS is meant to accept third-party collector plugins, so
"every collector checks ownership first" is a convention a plugin author can
forget — and the failure is silent: the plugin works, it just touches things it
should not have.

So collectors check nothing. **They cannot run without a `Permit`, and a `Permit`
can only come out of `authorise()`.**

### How the Permit resists forgery

```python
_SECRET = secrets.token_bytes(32)          # process lifetime, module private

def _seal(asset, operation, exposure, actor, addresses) -> str:
    # length-prefixed, so ('a','bc') and ('ab','c') cannot seal identically
```

`Permit.__post_init__` recomputes the seal and compares it in constant time.

The first version used a sentinel object and **was wrong**, which is worth
recording because the mistake is easy to repeat: `dataclasses.replace()` copies a
sentinel field forward, so a PASSIVE permit — obtainable for any in-scope name
with no ownership proof at all — could be mutated into an ACTIVE permit for an
arbitrary host, and the check passed. Frozen does not mean immutable when the
language ships a copy-with-changes helper.

**Honest limit:** this defeats mutation and accident, not code already running in
the process, which can read `_SECRET`. The threat FR-GOV-001 is actually about is
a collector escalating carelessly, and that is closed.

### Three exposure classes

| Class | Needs | Registered operations |
|---|---|---|
| **PASSIVE** (9) | scope only | `ct_log_search`, `passive_dns`, `dns_resolve_recursive`, `subdomain_index_read`, `web_archive_search`, `rdap_lookup`, `whois_lookup`, `leak_site_index_read`, `overwatch_ingest` |
| **ACTIVE** (8) | scope **+ current ownership + address check** | `http_probe`, `tls_handshake`, `port_scan`, `service_banner_read`, `dns_resolve_authoritative`, `dns_wildcard_probe`, `dns_zone_transfer`, `subdomain_bruteforce` |
| **PROHIBITED** (4) | nothing lifts these | `exploit_attempt`, `credential_replay`, `forum_authenticate`, `forum_transact` |

**Order matters and is load-bearing.** PROHIBITED is decided *before* scope and
ownership are consulted, so the refusal cannot be argued around by adding a scope
rule. There is a test that would fail if the ordering were reversed.

**An unregistered operation is PROHIBITED**, never assumed passive. A collector
whose author forgot to register it fails loudly on its first run rather than
reaching the internet under a permissive default.

**`dns_resolve_recursive` is PASSIVE, decisively** because `Method.DNS_TXT`
ownership verification is itself a DNS resolution — classifying resolution ACTIVE
would make ownership verification require ownership verification, and nothing
could bootstrap.

### Names are not addresses

`authorise()` covers a name. `authorise_target()` additionally covers the
addresses it resolves to, and seals them onto the permit.

This exists because a `ScopeRule(CIDR, …, is_exclude=True)` could never fire for
a hostname: `resolve('api.example.com', DOMAIN)` is INCLUDED while
`resolve('104.18.5.7', CIDR)` is EXCLUDED, and the name path never consulted the
address. "Exclude wins unconditionally" was silently false for exactly the
operations that connect.

The tempting counter-argument — that a `Host:`-routed HTTPS request only reaches
the customer's tenant — is false at the transport layer. The TCP connection, the
TLS handshake, the resource consumption and the abuse report all land on whoever
owns the address.

A **sweep** (`port_scan`, `service_banner_read`) additionally needs at least one
address positively INCLUDED by a CIDR rule: ownership is proven over a *name*, a
sweep is delivered to an *address*, and a name pointed at a SaaS tenant would
otherwise authorise sweeping a third party who consented to nothing.

### Previewing a run

`gate.plan(assets, operation, actor, scope, verifications)` returns
`(would_run, refusals)` using the verifications actually on record.

`refusal_reasons()` still exists but answers a different question — it hardcodes
`verification=None`, so every ACTIVE operation comes back refused by
construction. Every `--dry-run` / `--plan` path uses `plan()`, because a preview
that confidently reports "nothing will be touched" and is then contradicted by
the real run is worse than no preview.

---

## 3. The egress boundary — the one place I/O happens

`collect/egress.py`. Three entry points: `tcp()`, `udp()`, `http_get()`.

Enforced there so no collector has to remember any of it:

- the permit authorises **this** operation and **this** asset, compared on
  normalised strings (`authorise()` stores the raw operation, `classify()`
  normalises, so a naive `==` rejects a permit the gate legitimately issued)
- **`PORTS_BY_OPERATION`** — an `http_probe` permit cannot read the MySQL
  greeting on 3306 through the approved helper
- the address is one the permit **sealed**, connected to *without re-resolving*,
  which pins the check and the connection together against DNS rebinding
- **HTTPS only.** An on-path attacker who can silently *delete* hostnames from a
  plaintext response shrinks the reported estate with no source reporting FAILED
- **no redirects** (`http.client`, not `urllib`, whose redirect handler would
  carry an active probe to a host no permit covers). A cross-host redirect is
  recorded as a signal and the chain stops
- **`Retry-After` capped at 30 s** — an uncapped honour of `Retry-After: 86400`
  hangs a synchronous CLI for a day
- passive fetches reach only `ALLOWED_HTTP_HOSTS`; passive DNS reaches only
  `DEFAULT_RESOLVERS`. A caller may *subset* an allowlist, never extend it —
  otherwise `--resolvers 10.0.0.53` aims every query at customer infrastructure
  under a permit that proved nothing

### Rate limiting needs three buckets

`Limiter` traverses **address → /24 → global** on every acquisition.

Per-address alone is not enough: 400 hosts on 400 distinct addresses inside one
/22 behind a single firewall is ~400 new flows per second with every per-address
budget respected, and that fills a state table. Per-hostname is wrong the other
way: certificate transparency routinely yields hundreds of names behind one CDN
address, so hostname keying delivers a several-hundred-fold amplification to one
server.

`BudgetExhausted` is loud, and everything not attempted is **returned and named**
— a run cut short and an estate with nothing exposed otherwise produce identical
empty output.

### How the boundary is enforced

`tests/test_egress_boundary.py` scans `collect/`, `core/`, `api/` and `main.py`
for socket, `http.client`, `urllib`, `requests`, `httpx`, legacy protocol
clients, and `subprocess` invocations of network tools.

A module may perform I/O **only if it carries `# NETWORK-BOUNDARY: <operation>`
markers**, and every marker must name a real key in `gate.OPERATIONS`.

A filename allowlist was rejected deliberately: it is the same convention the
gate exists to reject, because a third-party author simply adds themselves to it.
Tying the declaration to the operation registry means a module cannot claim a
boundary for work the product does not recognise.

---

## 4. The pipeline

Each stage writes a file or a table; the next stage reads it. **Discovery writes
and scanning reads** — keeping the network off the scan path is what makes a scan
reproducible and runnable offline, and it means a discovery run can be reviewed
before anything is scored against it.

```
scope add ──▶ scope_rule table
                   │
                   ▼
discover  ──▶ collect/run.py ─▶ registry.enabled() ─▶ per-source fetchers
                   │                                  (ct, names)
                   ▼
              discovery.merge()   scope applied PER NAME, kind=DOMAIN explicit
                   │              addresses checked under CIDR
                   ▼
              discovered.csv      product=unknown  ← joins nothing, by design
                   │
     ┌─────────────┼─────────────────────┐
     ▼             ▼                     ▼
 dns-sweep     verify              fingerprint  (ACTIVE, needs verify)
     │             │                     │
     ▼             ▼                     ▼
 dns_observation  ownership_        assets.csv  product = catalogue spelling
 takeover_finding verification                  obs_* = everything observed
     │                                   │
     └───────────────┬───────────────────┘
                     ▼
                   scan ──▶ match ─▶ scoring ─▶ engine.rank
                     │                              │
                     ▼                              ▼
              scan_run + finding tables      run-over-run diff
```

### Why fingerprinting is the load-bearing stage

CT and passive DNS find **names**, not technologies. Discovery writes
`product=unknown`, which matches **0** of the catalogue's 1,674 entries — not by
luck, but because `unknown` is in `match.STOPWORDS` and tokenises to the empty
set, which the matcher short-circuits.

So a 400-host discovery produces zero findings until something fills `product`.

---

## 5. The join, and the two tiers of claim

`core/match.py`. The contract is exact:

> `tokens(asset.product)` must be a **non-empty subset** of
> `tokens(entry.product) | tokens(entry.vendor_project)`

One-directional containment. Both alternatives were tried against the real
catalogue and both failed, in opposite directions — shorter-side containment made
`Apache Tomcat` match bare `Apache`; requiring full equality made
`Ivanti Connect Secure` match nothing at all.

**Every extra token is a veto**, which makes the obvious implementation useless:

| written | tokens | exposures |
|---|---|---:|
| `unknown` | `{}` | 0 |
| `Apache/2.4.54 (Ubuntu)` | `{apache, ubuntu}` | 0 |
| `cpe:2.3:a:apache:http_server:2.4.54` | `{apache, cpe, http}` | 0 |
| `Apache HTTP Server` + vendor `Apache` | `{apache, http}` | 4 |

So `core/signatures.py` writes a **canonical name from a reviewed table**, never
the observed banner, and never a version. `vendor` is written separately because
it is the only lever that reaches `STRONG` — and it must be the *catalogue's*
spelling: `Zimbra`+`Zimbra` is 19 PARTIAL, `Zimbra`+`Synacor` is 19 STRONG,
because CISA files Zimbra under Synacor.

### The breadth cap is vendor span, not hit count

| signature | hits | vendors | verdict |
|---|---:|---:|---|
| `Cisco` + Cisco | 96 | 1 | precise — admit |
| `Chromium` + Google | 63 | 1 | precise — admit |
| `Security Gateway` + Check Point | 28 | 8 | vague — refuse |
| `Routers` + D-Link | 27 | 9 | vague — refuse |

Hit count measures how often a product has been exploited, not how vague the
signature is. Capping it also means a corpus refresh taking Confluence from 9
entries to 26 turns a working signature into a CI failure — the more a product is
exploited, the sooner SKOPOS stops identifying it. Exactly backwards.

### PRODUCT_MATCH vs VERSION_RANGE

| | means |
|---|---|
| `PRODUCT_MATCH` | the asset runs a product with an exploited vulnerability. **A worklist.** |
| `VERSION_RANGE` | the version was compared against a published affected range. **A determination.** |

A fingerprint justifies the first and **can never justify the second**. A banner
version is the assertion of the party whose patch state is the question, and it
fails both ways — distribution backporting makes it a false positive, header
suppression a false negative.

**The refusal is structural, not a rule to remember.** `engine.score_exposure`
marks `NOT_AFFECTED` as a `VERSION_RANGE` determination, and `NOT_AFFECTED`
*retires* the finding — so a spoofed high version would **delete** entries from
the customer's worklist. The writer emits `obs_version`, which normalises to
`obsversion` and is absent from `inventory.ALIASES["version"]`, so it lands in
`attributes` where `affected.evaluate()` cannot reach it.

---

## 6. Storage

PostgreSQL 16. Five migrations, applied by `core/migrate.py`.

| Migration | Tables |
|---|---|
| `001_schema.sql` | `scope_rule`, `ownership_verification`, `responsible_use_ack`, `audit_log` |
| `002_p1.sql` | `dns_run`, `dns_observation`, `takeover_finding` |
| `003_findings.sql` | `scan_run`, `finding` |
| `004_forecast.sql` | `forecast` — every finding's full input vector at the moment it was issued |
| `005_forecast_null_dedupe.sql` | `UNIQUE NULLS NOT DISTINCT` on the forecast key |

`005` exists because of a defect worth recording: the original constraint was
`UNIQUE (run_id, ...)` with a nullable `run_id`, and in SQL `NULL != NULL`, so
`ON CONFLICT DO NOTHING` silently matched nothing and every offline scan wrote a
duplicate. `004` itself went unapplied through five scans because migrations ran
only in `PostgresStore`; `ensure_once()` now runs in all four stores.

### Why a migration runner exists

`docker-compose.yml` mounts `db/` at `/docker-entrypoint-initdb.d`, which
Postgres executes **only on an empty data directory**. The moment a second
migration existed, `002` would never have run on the deployment's volume while
running fine in the tests' throwaway databases — green tests, missing constraints
in production, invisible until a bad finding reached a customer.

`ensure_current()` back-fills `001` when the tables already exist (the
initdb-created volume) rather than re-running it, and `require_current()` refuses
to serve when behind. That is the same posture as `open_store()` refusing to fall
back to memory: this product would rather not run than run while quietly missing
a control it claims to have.

### Controls the database enforces, not the code

- `audit_log` carries `DO INSTEAD NOTHING` rules on UPDATE and DELETE, and the
  app role holds only SELECT and INSERT. The hash chain *detects* tampering;
  this *prevents* it. Verified: an UPDATE and a DELETE against a live row both
  reported 0 rows and the row survived — for the table owner, not just the app
  role
- a manual ownership attestation with no named approver is refused by a CHECK
  constraint, so the rule survives someone writing a migration that bypasses
  `core/ownership.py`
- `dns_observation.rcode` is constrained to `NOERROR` or `NXDOMAIN`, so a
  non-conclusive observation cannot be stored and a resolver outage cannot
  supersede what was last actually seen
- `finding.basis` is constrained to `product_match` or `version_range` — the
  product's central claim, so a third invented value is not storable
- `takeover_finding` has no `claimable_looking` value, because a value the schema
  accepts is one somebody eventually writes

### Repository boundary

Every store has a `Memory*` implementation and a `Postgres*` one. The in-memory
versions exist so the **refusal** tests stay cheap to write — most of what
matters here is refusal, and it has to be cheap to assert or it will not be
asserted enough. They are **not fallbacks**: `open_store()` and
`open_findings_store()` raise rather than degrade, because a service that
silently runs in-process while the database is unreachable keeps answering and
loses everything at the next restart.

---

## 7. The honesty machinery

Four mechanisms, each fixing a way this product could quietly mislead.

### Provenance — whose statement is this?

`core/provenance.py`. `match.declared_cves()` promotes a CVE named on an asset
row to STRONG confidence with the evidence line *"the inventory names CVE-… on
this asset"*. Correct for a CMDB column; dangerous for a string copied out of
somebody else's HTTP response. Measured:

```python
attributes={"fp_evidence": "Server: EvilWAF blocks cve-2021-44228"}
# → one exposure, STRONG, "the inventory names CVE-2021-44228 on this asset"
```

Every column a collector writes is prefixed **`obs_`**, and `declared_cves()`
skips prefixed keys. The promotion keys on **who wrote the column**, not on what
it says — so a CVE reference nobody thought to pattern-match still cannot be
promoted. A second layer redacts, importing `match.CVE_PATTERN` rather than
restating it, because a private copy is how a case-sensitive redactor passes its
own tests while missing `cve-2021-44228` in the wild.

### The degradation vocabulary

`collect/report.py`. `ok: bool` cannot distinguish six states that all render as
a small estate:

`OK` · `PARTIAL` (answered, said it was cut off) · `FAILED` · `UNCONFIGURED` (no
key) · `DISABLED` (terms) · `REFUSED` (the gate)

Three flags, not one: **`degraded`** (something broke), **`narrowed`** (smaller
by choice), **`refused`** (a governance event). Folding `UNCONFIGURED` into
`degraded` would leave every keyless install permanently degraded, and a flag
that is always on is a flag nobody reads.

`contributed` vs `returned` keeps a 500-SAN shared-CDN certificate honest: 3
in-apex names out of 500 is not a source that did badly.

### Change tracking

`core/dns_state.py`. The comparand is **`(rcode, digest)`**, not the digest.
NXDOMAIN and NODATA both produce an empty answer set and therefore the identical
sha256 — measured live — so a digest alone makes a zone deletion and a name
creation invisible. TTL is excluded, or every record set "changes" every run.

Seven change kinds, and two of them exist to separate our failure from the
operator's instruction: **`UNOBSERVED`** (we could not look — our outage, and it
never supersedes stored state) versus **`NOT_LOOKED_AT`** (the gate refused it).
Without the second, adding an exclusion on Monday makes Tuesday's sweep report
forty records DISAPPEARED — "your DNS was deleted" — on a day nothing changed.

The first run is a named **BASELINE**. Reporting everything as new makes run one
the noisiest report the customer ever receives on a day when none of it is
actionable; reporting nothing is indistinguishable from a failed run.

### Ceilings that are types, not discipline

`core/takeover.py`. `TakeoverEvidence` cannot be constructed without the target,
what the resolvers said about it, and how many said it. `TakeoverFinding` rejects
fewer than two agreeing resolvers, rejects `CLAIMABLE_LOOKING` outright, and
rejects `REGISTRATION_OPEN` corroborating anything but an unregistered domain.

`NOT_CLAIMABLE` is named **`NO_CLAIM_SIGNAL_FOUND`**, because the original
asserts a negative the product cannot establish and would render identically to a
resource an attacker has *already* claimed.

---

## 8. Module map

### `core/` — reasoning, no I/O

| Module | Responsibility |
|---|---|
| `gate.py` | **the** authorisation decision; `Permit`, `authorise`, `authorise_target`, `plan`, `OPERATIONS` |
| `scope.py` | include/exclude; exclude wins unconditionally, order-independent |
| `ownership.py` | verification records, 180-day expiry, HMAC-bound tokens |
| `audit.py` | hash-chained log, and what a chain cannot prove |
| `provenance.py` | the `obs_` boundary and CVE redaction |
| `migrate.py` | schema versioning; refuses to serve when behind |
| `store.py` / `dns_store.py` / `findings_store.py` | persistence behind protocols |
| `models.py` | `Asset`, `Exploited`, `Exposure`, `MatchBasis`, `Confidence` |
| `intel.py` | vendored corpus + staleness; raises rather than returning empty |
| `inventory.py` | aliased ingest; rejected rows are **returned** |
| `match.py` | the join, and what it refuses to claim |
| `affected.py` | CNA range evaluation — one unreadable range poisons to UNKNOWN |
| `scoring.py` | TEPS, SRS §9.1 |
| `engine.py` | composition, ranking, summarising |
| `overwatch.py` | cloud ingest + four-way reconciliation |
| `identity.py` | `Attestation`, `Fingerprint`; the version refusal |
| `signatures.py` | banner → catalogue spelling; vendor-span cap |
| `reach.py` | outside-in reachability: `True` / `False` / `None` |
| `dns_state.py` | change tracking |
| `takeover.py` / `takeover_rules.py` | verdicts, mandatory evidence, provider catalogue |
| `criticality.py` | per-asset tier from the declared environment; a controlled vocabulary |
| `artefacts.py` | published exploit code and when — windowed from 2023-01-01, and why |
| `ssvc.py` | CISA-ADP decisions: a stated judgement with a named author |
| `crosshair.py` | seven signals, a count, three tiers — convergence, never attribution |
| `latency.py` | reference classes for time-to-exploitation; refuses three of its four cells |
| `forecast.py` / `forecast_store.py` | the input vector written at issue time, so accuracy is measurable later |
| `backtest.py` | Brier, climatology, skill — and what it declines to publish |
| `velocity.py` | EPSS as a series, not a reading |
| `coverage.py` | vulnerabilities beyond the exploited catalogue, kept structurally apart |
| `alerting.py` | what is worth interrupting somebody for, versus what is merely true |
| `stix.py` | STIX 2.1 export that carries the worklist/determination distinction outward |
| `cert_in.py` | the six-hour clock that will not start itself; the notification draft |
| `controls.py` | ISO 27001:2022 + NIST CSF 2.0 — contributes / does not / evidence, no percentage |
| `cii.py` | the CII exposure register; records declarations, designates nothing |

### `collect/` — I/O, all through one door

| Module | Responsibility |
|---|---|
| `egress.py` | **the only** module that performs network I/O |
| `report.py` | one degradation vocabulary for every subsystem |
| `registry.py` | sources, terms, review dates, defaults |
| `run.py` | the only caller of `authorise()` for discovery |
| `discovery.py` | merge, per-name scope binding, date provenance |
| `ct.py` · `names.py` | certificate transparency; pDNS, indexes, archive |
| `dns_wire.py` | DNS packet build/parse — returns rcode, not `gaierror` |
| `dns_records.py` | multi-resolver sweep, per-rrtype agreement, quorum |
| `takeover_scan.py` | dangling assessment + RDAP |
| `http_probe.py` | HTTP/TLS identity signals (active) |
| `fingerprint.py` | the run, under permits, writing what joins |

### Naming collision to know about

`gate.Exposure` (the enum), `models.Exposure` (asset × exploited) and
`scoring.Exposure` (TEPS factors) are three different types. **Always import
qualified**: `from core import gate` then `gate.Exposure`.

---

## 9. Invariants a change must not break

Each of these has a test that fails if it is violated.

1. A collector cannot reach the network without a `Permit` from `authorise()`.
2. A `Permit` cannot be constructed or mutated outside the gate.
3. `PROHIBITED` is decided before scope and ownership.
4. An unregistered operation is refused, never assumed passive.
5. An exclusion beats every include, whatever its specificity or order.
6. `UNSCOPED` is not `EXCLUDED`; `False` reachability is not `None`.
7. Only `Attestation.OPERATOR` may determine a version.
8. A CVE in a tool-authored column is never a customer assertion.
9. Only a conclusive DNS observation may supersede a stored one.
10. Every marker in a `# NETWORK-BOUNDARY:` comment names a real operation.
11. Every registered discovery source names a real operation.
12. A takeover finding cannot exist without its evidence, or on one resolver.
13. Truncation, refusal and degradation are always reported, never inferred.
14. A `PRODUCT_MATCH` is never rendered as a determination — on a dashboard, in
    a STIX bundle, or in a document addressed to a regulator.
15. A reference class below `MIN_SAMPLE`, or wider than `MAX_USEFUL_SPREAD_DAYS`,
    cannot be rendered as a forecast.
16. No skill score is published below `MIN_RESOLVED_TO_PUBLISH` resolved
    forecasts, and lead time is reported as unmeasurable, not as a number.
17. No control mapping produces a coverage figure, in any field or any sentence.
18. The CERT-In six-hour clock cannot be opened from a finding — only from a
    `Declaration` carrying a named person, their own summary, and a tz-aware time.
19. CII status is never inferred; a gazette claim without its notification
    reference is refused at construction.

---

## 10. Adding a collector

1. **Register the operation** in `gate.OPERATIONS` with an honest exposure class.
   Skipping this does not fail open — `classify()` returns `PROHIBITED` and the
   first run refuses loudly.
2. **Register the source** in `collect/registry.py` with its data class, its
   terms, and today's date in `TERMS_REVIEWED_ON` if you changed the table.
   Anything whose terms read as excluding commercial use is `default_on=False`.
3. **Write the fetcher** taking `(apex, permit, budget, limiter)`. Call
   `egress.http_get` / `tcp` / `udp` — never a socket directly, or
   `test_egress_boundary` will fail.
4. **Return `(observations, SourceReport)`.** Let `PermitMismatch` propagate: a
   permit problem is a build error, not a coverage gap, and filing it as one
   hands the operator the wrong remedy.
5. **Parse positively.** A row counts only if it parses. If nothing parses and
   the body is non-empty, report `FAILED` with the first 80 characters —
   special-casing one known error string leaves every other 200-with-error-body
   reporting OK with zero results.
6. **Detect truncation** and report `PARTIAL` with the tell you used.
7. **Prefix anything you write** with `provenance.observed()`.

---

## 11. What is deliberately absent

| | Why |
|---|---|
| Closed-forum / marketplace collection | FR-GOV-003. Not lawfully or ethically reproducible. |
| Active takeover corroboration | Needs an HTTP fetch of a third party's host. RFC 1034 forbids a CNAME coexisting with a TXT record, so the name that most needs probing is the one that structurally cannot be verified. `Method.PARENT_ZONE` is specified in `P1-BUILD-SPEC.md` §11 and deferred by sponsor decision. |
| Version determinations from banners | §5. Needs CNA `affected[].versions[]`. |
| The `subfinder` adapter | Its output cannot distinguish "12 names" from "12 because four sources were down", and it delegates the exposure classification of ~60 third parties outside `gate.OPERATIONS`. |
| Multi-tenancy | Sponsor decision. Every table takes `org_id` without a rewrite. |
| Any unmeasured prediction claim | If the backtesting harness cannot support it, it does not ship. |

---

*Companion documents: `CLAUDE.md` for decisions D1–D19 and their reasoning;
`docs/P1-BUILD-SPEC.md` for the adversarial design pass and the 86 problems it
raised.*
