# CLAUDE.md — External Threat Landscape Management (ETLM)

## What this is

An open-source ETLM platform. The objective, from the README and unchanged:

> Continuously connect **what the organisation exposes** with **what adversaries
> are exploiting**, and drive accountable remediation.

**Python 3.10+ · FastAPI · TypeScript · PostgreSQL · MIT**

The differentiator is the **join**. An attack-surface tool does the first half, a
threat-intelligence feed does the second, and neither does the join — which is
where the only actionable question lives: *of the things we run, which are being
attacked right now, and who fixes them?*

---

## The SRS, and where measurement corrected it

`SKOPOS-SRS-v1.0` is the governing specification. Two decisions in it were
overruled by the sponsor and one research finding in it was wrong; all three are
recorded here rather than silently applied.

### Overruled by the sponsor, 2026-08-22

| SRS says | Decision | Consequence, accepted |
|---|---|---|
| New repo `skopos-etlm`, Apache-2.0 | **Keep this repo, MIT** | No explicit patent grant. Consistent with the rest of the portfolio. |
| Build multi-tenancy in P0 (~3 weeks) | **Single-org first** | The SRS estimates the retrofit at ~3 months. Mitigated only by avoiding designs that *preclude* tenancy — no global-unique keys where per-org would be needed. FR-M0-001 and RLS are **not** implemented. |

### WS-3 was aimed at the wrong field — measured, 2026-08-22

The SRS calls the 2026 NVD degradation a first-class architectural finding, and
it is right that it matters. It is wrong about which field fails. Measured
against the live NVD API across three 2026 windows, 600 CVEs sampled:

| published | no CPE | no CVSS | `Deferred` share of processed |
|---|---:|---:|---:|
| March 2026 | 6% | 0% | 6% |
| May 2026 | 14% | 0% | 14% |
| August 2026 | 92% | 1% | 75% |

The correlation with `vulnStatus` is deterministic: `Analyzed` and `Modified`
**always** carry CPE; `Deferred` and `Received` **never** do.

Three corrections:

1. **The status string is `Deferred`.** FR-M2-003 names `Not Scheduled`, which no
   current record uses — handling written against it would never fire.
2. **CVSS is not the missing field** (present ~99.5%). §9.1's mandatory
   missing-data rule is implemented as written and will almost never trigger.
3. **The degradation lands on MATCHING, not scoring.** CPE is the join key for
   FR-M2-010. This compounds with the KEV finding below: both halves of the join
   were degraded and the SRS hardened neither.

**The fix, verified.** `CVE-2026-7518` is `Deferred` with zero CPE, yet its CNA
record in `cvelistV5` carries **8 explicit affected versions**. CNA
`affected[].versions[]` survives regardless of NVD state and is *better* than CPE
— exact versions rather than a match expression. FR-M2-001 already makes
`cvelistV5` the source of truth; it simply does not connect that choice to this
problem.

Restated: **do not depend on NVD for CPE. Derive product identity and version
ranges from CNA records; treat NVD as supplementary enrichment only.**

`core/scoring.py` therefore adds `match_confidence` as a first-class input and
flags `identity unresolved` — the caveat the SRS does not have and the data says
is the one that matters.

## Decisions already made

### D1 — Hybrid data posture: vendored corpus, opt-in collectors

The intelligence is **vendored into `data/`** and regenerated deliberately by
`tools/refresh_intel.py`, not fetched at scan time.

**Why.** A scan has to be reproducible and has to run where there is no internet.
Fetching at scan time makes every result depend on a network round trip, a rate
limit and whatever upstream published in that second — two people scanning the
same estate an hour apart get different answers and neither can say why.
Vendoring makes the intelligence a *versioned input*.

**The cost is staleness, and it is handled by stating it.** Every result carries
the catalogue version and its age. A reader who ignores a stated age has made a
decision; one who was never told has been misled.

Live collectors (CT logs, DNS, Shodan) will exist and will be **opt-in and
documented as partial** — the same shape as MonitorRisk's `collect/` module.

### D6 — OverWatch is the only sibling tool SKOPOS ingests (sponsor, 2026-08-22)

§18 question 4 asked whether SKOPOS should consume findings from the other
Phalanx tools. Decision: **OverWatch only**, to bring internal cloud context into
an external platform.

**And the value is not the asset feed.** OverWatch answers *"is this reachable
from the internet?"* by a completely different method than SKOPOS — a four-gate
cloud model (public IP, ACTIVE IGW default route, security-group world-open
ports, and a stateless NACL permitting both the inbound port and the ephemeral
return) versus an actual probe from outside. `aws_exposure.py` explicitly refuses
to conclude from `0.0.0.0/0` alone, calling it the industry's number-one false
positive.

Two independent methods answering one question can **disagree**, and each
disagreement is a finding neither tool produces alone:

| SKOPOS | OverWatch | outcome |
|---|---|---|
| reachable | reachable | `confirmed` — two methods agree |
| reachable | not reachable | **`unexplained_exposure`** — something answers that the cloud model does not account for |
| not reachable | reachable | **`discovery_blind_spot`** — the model says exposed, discovery missed it |
| not reachable | not reachable | `agreed_not_exposed` |

The middle two rows are the whole reason for the integration, so `reconcile()`
never resolves a disagreement by preferring a source, and "no verdict" is
`inconclusive` — never agreement.

**Reachability is read from the graph's SHAPE** (an edge from an `InternetSource`
node) rather than from a property like `is_public`, which would break the first
time that property came to mean "has a public IP" instead of "is actually
reachable" — the exact distinction OverWatch's oracle exists to draw.

**Taken:** external identity, ownership/account/region/tags (accountable
remediation is half the objective), exposed ports, and fronting — CloudFront/ALB
is literally the `M` mitigation term in §9.1, so it becomes evidence rather than
an assumption.

**Not taken:** OverWatch's findings and severities. SKOPOS scores with TEPS, and
importing a second scoring opinion gives one asset two numbers with no way to
reconcile them. Its observations are welcome; its verdicts are its own.

### D2 — First slice: exposure × actively-exploited

Not attack-surface discovery, not brand protection, not credential leakage.
Those are Phase 2+. The first slice is the join itself, because it is the
objective sentence and because it reuses the strongest reasoning in the portfolio.

### D3 — A worklist is not a verdict, and the difference is stated on every run

**This is the most important decision in the product.**

The CISA KEV catalogue carries **no structured affected-version data** — 1,674
entries, zero version ranges (55 mention a bound in unparseable prose). So a
product-name match establishes *"this asset runs a product with an exploited
vulnerability"* and can never establish *"this asset is vulnerable"*.

`MatchBasis` encodes this:

| | means | is |
|---|---|---|
| `PRODUCT_MATCH` | the product corresponds | a **worklist** — somebody must check the version |
| `VERSION_RANGE` | the version falls in a published affected range | a **determination** — arithmetic on two external facts |

**Phase 1 produces only the first**, and `WORKLIST_NOTICE` says so on every run.
Reaching `VERSION_RANGE` needs affected-range data (NVD CPE) the corpus does not
carry — a stated gap, not a silent one.

The industry norm is to present the first as the second. The resulting list is
mostly wrong, gets worked once, and is then ignored *along with the true entries
inside it*. That failure is the reason this distinction exists.

### D4 — The matcher fails closed, and says where it failed

Correspondence is **one-directional token containment**: everything the *asset*
claims to be must be accounted for by the catalogue entry. Both alternatives were
tried against the real catalogue and both failed:

- **Shorter-side containment → false positive.** `Apache Tomcat` matched bare-
  `Apache` entries, reporting httpd bugs against a Tomcat host. The extra token
  *is* the identity.
- **Asset-product-only → false negative, and worse.** `Ivanti Connect Secure`
  matched **nothing**: the catalogue splits the identity across `vendorProject`
  (`Ivanti`) and `product` (`Connect Secure and Policy Secure`), so neither set
  contained the other. Dozens of entries, among the most exploited products in
  the catalogue, silently missed.

Fixed by comparing against vendor **and** product together, in one direction.
Failing closed means a differently-spelled product is missed — so
`unmatched_assets()` reports every asset that matched nothing. *"0 exposures, 400
unmatched"* is a naming problem; *"0 exposures, 0 unmatched"* is a clean estate,
and they must never look alike.

### D5 — Ranking is an ordered tuple, not a score

Ransomware use → CISA due date → EPSS → match confidence. Deliberately **not** a
composite score: a single number needs weights, weights get tuned until the top
of the list looks right, and the tuning becomes the product's real opinion where
nobody can inspect it.

**EPSS is a forecast; KEV membership is an observation.** EPSS orders the list
and never establishes exploitation.

---

## Layout

```
skopos/
├── main.py                   CLI: scope, verify, discover, dns-sweep,
│                             takeover, fingerprint, scan, intel
├── core/
│   ├── gate.py               THE authorisation decision. Permit, authorise,
│   │                         authorise_target, plan, OPERATIONS
│   ├── scope.py              include/exclude; exclude wins unconditionally
│   ├── ownership.py          verification records, 180-day expiry
│   ├── audit.py              hash-chained log + what a chain cannot prove
│   ├── provenance.py         whose statement a string is (obs_ prefix)
│   ├── migrate.py            schema versioning; refuses to serve when behind
│   ├── store.py              scope / ownership / audit  (Memory + Postgres)
│   ├── dns_store.py          observations, sweeps, takeover findings
│   ├── findings_store.py     scan runs, findings, run-over-run diff
│   ├── models.py             Asset, Exploited, Exposure, MatchBasis, Confidence
│   ├── intel.py              vendored corpus + staleness reporting
│   ├── inventory.py          aliased CSV/JSON ingest; rejects are RETURNED
│   ├── match.py              the join, and what it refuses to claim
│   ├── affected.py           CNA range evaluation (the determination tier)
│   ├── scoring.py            TEPS, SRS §9.1
│   ├── engine.py             composition, ranking, summarising
│   ├── overwatch.py          cloud ingest + four-way reconciliation
│   ├── identity.py           Attestation, Fingerprint; the version refusal
│   ├── signatures.py         banner -> catalogue spelling; vendor-span cap
│   ├── reach.py              outside-in reachability: True / False / None
│   ├── dns_state.py          change tracking; (rcode, digest) comparand
│   ├── takeover.py           verdicts, mandatory evidence, the ceiling
│   └── takeover_rules.py     provider catalogue + review dates
├── collect/
│   ├── egress.py             the door discovery and probing go through
│   ├── report.py             one degradation vocabulary for every subsystem
│   ├── registry.py           sources, their terms, their defaults
│   ├── discovery.py          merge, scope binding, date provenance
│   ├── ct.py                 certificate transparency
│   ├── names.py              passive DNS, name indexes, web archive
│   ├── run.py                the only caller of authorise() for discovery
│   ├── dns_wire.py           DNS packet build/parse (rcode, not gaierror)
│   ├── dns_records.py        multi-resolver sweep + per-rrtype agreement
│   ├── takeover_scan.py      dangling assessment + RDAP
│   ├── http_probe.py         HTTP/TLS identity signals (active)
│   └── fingerprint.py        the run, under permits, writing what joins
├── api/app.py                FastAPI; serves the console same-origin
├── frontend/                 React + TypeScript console
├── db/                       001 schema · 002 DNS · 003 findings
├── data/                     kev.json, epss.json — VERSIONED INPUTS
├── docs/P1-BUILD-SPEC.md     the adversarial design pass, and its 86 problems
└── tests/                    767 tests
```

---

## Conventions

- **No canonical inventory schema.** Column names are aliased; unrecognised
  columns are kept in `attributes` and the CVE matcher reads across them. A
  product that demands its own schema makes the customer do a migration before
  seeing one result.
- **Rejected rows are returned, never dropped.** "We read 380 of your 400 rows"
  is a materially different statement from "we read your inventory".
- **An empty corpus raises.** `IntelUnavailable`, never a clean-looking zero — an
  empty catalogue produces a report identical to a secure estate. Discovery
  follows the same rule: a total source blackout raises rather than returning 0.
- **Truncation says so.** A capped list that does not announce the cap reads as a
  complete one.
- **Anything a collector writes is prefixed `obs_`.** That prefix is what stops
  a third party's text being read as the customer's own assertion. See D13.
- **Every network call goes through `collect/egress.py`.** Enforced by a test
  over `# NETWORK-BOUNDARY:` markers, not by a filename allowlist.
- **Meaning strings are served by the API**, never hard-coded in the console, so
  the API, the CLI and the UI cannot drift into describing one state differently.

---

## Status

**P0 through P5 complete. 767 tests** (704 offline + 63 against a live
PostgreSQL).

**TEPS golden-tested against SRS §9.1** — the published worked example reproduces
exactly at 78, every intermediate factor matching (E=0.817, X=1.000, A=0.850,
B=1.000).

**Verified against reality, not fixtures.** Live CT and passive DNS discovery;
live multi-resolver DNS sweeps (66 of 70 pairs observed, 4 genuine no-quorum
disagreements); a real dangling record found on a real domain and correctly
capped; findings surviving a container restart; migrations applied to the running
volume. Several defects in this codebase were found only by running it against
real services — they are named in the commit messages rather than quietly fixed.

### What each phase measured before it built

Every one of these was a planned feature that measurement changed or killed. The
number is in the product, not just in this file.

| Phase | Measured | Consequence |
|---|---|---|
| P2 | 47.5% of KEV carries comparable version data (668 structured + 128 exact, 878 uncomparable) | `VERSION_RANGE` determinations ship; the coverage figure is stated on every run and in the STIX bundle caveat |
| P3 | 0 CVE refs in ATT&CK `external_references`; a technique implicates a median of 57 groups (max 139 of 191) | The triad was closed. SSVC shipped instead |
| P3 | 1 of 4 latency reference classes has enough resolved samples (ransomware+weaponised: n=58, median 8d, IQR 1–124); the others span 1,380–2,360 days | The forecaster refuses three of its four cells rather than interpolating |
| P3 | Lead time on a KEV-only corpus is structurally negative (median −1258 days) | The SRS lead-time target is recorded as unmeasurable, not quietly dropped |
| P4 | 7 of 8 CERT-In Annexure I categories are not observable from outside an estate | The clock will not start itself, and the observability note says which categories and why |
| P4 | CII status is conferred by gazette notification under s.70 IT Act, 2000 | The register records what the organisation declared; there is no function that infers it |

### Next

- [ ] Tenancy's last mile, IF the deployment model calls for it: per-request
      org resolution needs an auth model (token -> org), and org lifecycle needs
      a surface. Today `tenancy.using()` exists and nothing calls it, so every
      request resolves to `SKOPOS_ORG_ID` — one organisation per deployment,
      with the enforcement floor underneath it. That is the right shape for
      one-instance-per-customer and the wrong one for SaaS; the question is the
      deployment model, not the code.
- [ ] Operational: run the scheduler continuously so forecasts accumulate
      enough resolved outcomes to publish a skill score.
- [ ] `Method.PARENT_ZONE`, which would unlock active takeover corroboration —
      specified in `docs/P1-BUILD-SPEC.md` §11, deferred by sponsor decision
- [x] Tenancy (FR-M0-001): org_id on every table, RLS enforced by an
      unprivileged runtime role — see D34. "Postgres roles per org" was
      declined with a stated reason, not missed.
- [ ] Run it against a REAL estate. Everything so far is verified against
      `sample_data/assets.csv` — 7 assets, 64 findings. Every defect worth
      recording in this history was found by running against something
      real, never by reading the code.

---

## P0 - governance before capability

The phase deliberately shipped no new collection. It shipped the thing that
decides whether collection may happen at all.

**D7 - PostgreSQL, not sqlite.** The sponsor stood up `skopos-db-1`; a compose
file is still single-node, so SRS CON-02 is met rather than deferred.

**D8 - the gate is structural.** `core/gate.py` holds the only authorisation
decision in the product. Collectors cannot run without a `Permit`.

**D9 - three exposure classes.** Passive needs no ownership proof; active does;
prohibited is refused *before* scope and ownership are consulted.

**D10 - exclude wins unconditionally.** Not most-specific, not last-wins.

**D11 - append-only is enforced by the database**, not by this code's manners.

---

## P1 - see it

**D12 - a sentinel token was not enough.** `dataclasses.replace()` copies a
sentinel forward, so a PASSIVE permit - obtainable for any in-scope name with no
ownership proof at all - could be mutated into an ACTIVE one for an arbitrary
host. Measured, not theorised; the P0 test passed throughout because it only
covered direct construction. Permits are now HMAC-sealed over the fields that
decide what they authorise. Frozen does not mean immutable when the language
ships a copy-with-changes helper.

**D13 - provenance decides whose statement a CVE is.** `declared_cves()` promotes
a CVE named on an asset row to STRONG with the evidence line "the inventory names
CVE-... on this asset". Measured: a `Server:` header reading `blocks
cve-2021-44228` produced exactly that. Collector columns are prefixed `obs_` and
skipped, so the promotion keys on WHO WROTE THE COLUMN rather than on what it
says - a CVE nobody thought to pattern-match still cannot be promoted.

**D14 - one egress choke point, enforced by declared markers.** A filename
allowlist is the convention `gate.py` rejects, because a plugin author adds
themselves to it. A module may do I/O only if it carries
`# NETWORK-BOUNDARY: <operation>`, and every marker must name a real key in
`gate.OPERATIONS`.

**D15 - addresses are authorised, not just names.** Measured: a CIDR exclusion
could never fire for a hostname, so D10 lost silently for exactly the operations
that do the connecting. `authorise_target()` checks the addresses and seals them
onto the permit. A sweep additionally needs an address positively in scope,
because ownership is proven over a NAME and a sweep is delivered to an ADDRESS.
ASN is dropped rather than faked - there is no IP-to-ASN mapping here, and the
refusal says so.

**D16 - the fingerprint writes the catalogue's spelling, never the banner.** The
join needs `tokens(product)` to be a SUBSET of the entry's tokens, so every extra
token is a veto: `Apache/2.4.54 (Ubuntu)` matches nothing at all. The breadth cap
is VENDOR SPAN, not hit count - measured, hit count inverts the populations
(`Cisco` 96 hits/1 vendor is precise; `Security Gateway` 28 hits/8 vendors is
not). The audit caught two of the shipped signatures before release.

**D17 - a banner can never determine a version.** `engine.score_exposure` marks
NOT_AFFECTED as a VERSION_RANGE determination, which RETIRES a finding, so a
spoofed high version would delete entries from the customer's worklist. The
refusal is a column name: `obs_version` is not in `inventory.ALIASES['version']`,
so `affected.evaluate()` cannot reach it.

**D18 - the DNS comparand is `(rcode, digest)`.** Measured live: NXDOMAIN and
NODATA produce the identical sha256, so a digest alone makes a zone deletion and
a name creation invisible. TTL is excluded, or every record set "changes" every
run as the counter ticks down. `socket.getaddrinfo` is not used at all, because
it collapses NXDOMAIN and SERVFAIL into one opaque error - "conclusively gone"
and "we could not look" are opposite facts.

**D19 - takeover stops where the evidence stops.** There is no `vulnerable`
verdict in this phase or any later one: the only confirming experiment is
registering the resource, which the gate refuses. `CLAIMABLE_LOOKING` is rejected
by `TakeoverFinding`'s constructor, so the ceiling is a property of the type. The
headline finding is `REGISTRABLE_DOMAIN_UNREGISTERED`, which RDAP settles
passively.

**Stated costs.** `discover`, `fingerprint` and `dns-sweep` hard-require
Postgres, which cuts against NFR-USE-003; `scan` and `intel` stay fully offline.
Active takeover corroboration is deferred by sponsor decision (2026-08-23): the
name that most needs probing is the one that structurally cannot be verified,
because RFC 1034 forbids a CNAME coexisting with a TXT record.

**399 tests** (373 offline + 26 live-database).

---

## P2-P4 - decide it, forecast it, evidence it

**D20 - the determination is a range comparison, and its coverage is published.**
`VERSION_RANGE` closes D3: an observed version compared against a CNA-published
affected range either confirms or RETIRES a finding. Measured over the full KEV
corpus, not a sample: 47.5% determinable (668 structured ranges + 128 exact
versions; 878 uncomparable). An earlier random-40 sample said 67.5% and was
wrong - age-stratified, the rate runs 0% / 20% / 90% by CVE age, so a sample
drawn without stratifying measures the sample's age distribution instead of the
corpus. The figure is stated on every run and travels with the STIX bundle.

**D21 - the ATT&CK triad was built, measured, and closed.** The intent was
CVE -> technique -> threat group. Measured: 0 CVE references in ATT&CK
`external_references`, and only 5 of 191 groups mention a CVE in prose. The CTID
mapping covers 419 of 1,674 KEV entries, but resolving technique -> group
implicates a MEDIAN OF 57 GROUPS per CVE, with a maximum of 139 of 191. An
attribution that names 57 groups is not attribution. Closed; SSVC shipped in its
place, because a CISA-ADP decision is a stated judgement with a named author
rather than an inference this product would be making up.

**D22 - the Crosshair counts convergence, it does not attribute.** Seven
independent signals, a count, and three tiers (`CONVERGED_AT = 4`). It says how
many things point at an asset, never who is pointing. The distinction is the
whole reason the view survived D21.

**D23 - the forecaster refuses three of its four cells.** Reference classes are
(ransomware x weaponised). Measured: only ransomware+weaponised has usable data -
n=58, median 8 days, IQR 1-124. The other three span 1,380 to 2,360 days, which
is not a forecast, it is a shrug with a number on it. `MIN_SAMPLE = 20` and
`MAX_USEFUL_SPREAD_DAYS = 400` are enforced in the type, so an unusable cell
cannot be rendered as a prediction. The KEV backfill also skews the base rate -
the unwindowed median is 777 days - so the window starts 2023-01-01 and the
measurements behind that date are recorded in `core/artefacts.py`.

**D24 - the backtest publishes what it cannot measure.** No skill score below
`MIN_RESOLVED_TO_PUBLISH = 30` resolved forecasts. Lead time carries
`LEAD_TIME_UNMEASURABLE`: on a KEV-only corpus every forecast is issued after the
CVE is already known-exploited, so the median is -1258 days. The SRS lead-time
target is therefore recorded as structurally unmeasurable here rather than
quietly dropped. The resolver requires a genuine EPSS crossing, because 80 of 128
forecasts were already above the threshold when issued and counting those would
have manufactured a hit rate.

**D25 - an exposure is not an incident, so the six-hour clock will not start
itself.** There is no `clock_from_finding()` and no endpoint that opens one; the
only constructor takes a `Declaration`, which requires a named person, a summary
in their own words, and a timezone-aware time of AWARENESS. Measured against
Annexure I: 7 of the 8 reportable categories are NOT_OBSERVABLE from outside an
estate - each describes something an adversary DID. A tool that started a
national-CERT countdown on every unpatched perimeter service would push its users
toward over-reporting, so the reason is a published string,
`cert_in.WHY_NOT_AUTOMATIC`, not just an absent function.

**D26 - no coverage percentage against any control framework.** Eight entries,
each naming what it contributes, what it does NOT do, and which evidence it draws
on. A percentage would be summed and shown to a board, and the board would be
receiving a number no external scanner has the basis to produce. The A.8.8 entry
carries the 47.5% limit from D20 and states that this product does not patch
anything; the A.5.7 entry carries the median-57-groups finding from D21.

**D27 - SKOPOS does not designate Critical Information Infrastructure.** Under
s.70 of the IT Act, 2000, the appropriate Government declares a computer resource
a protected system BY NOTIFICATION IN THE OFFICIAL GAZETTE. That status cannot be
inferred from a hostname, and an organisation acting on a guess would either
over-report to a national agency or believe itself covered when it is not. The
register records what the organisation stated, with the basis attached: a
`GAZETTE` entry without a notification reference is REFUSED at construction,
because it is the one claim here that could mislead a regulator. Assets with no
designation are listed as a QUESTION, never as a finding - the answer may
legitimately be that they were always out of scope.

**D28 - the notification draft leaves the judgements blank.** `notification_draft`
takes a `Declaration`, so there is no path from a finding to a regulatory
document. It fills only what SKOPOS can substantiate and marks impact, root cause,
data affected, remediation and contact `[TO BE COMPLETED BY REPORTER]` - a
pre-filled guess would be filed verbatim by somebody working against a six-hour
deadline. Related findings are cited by (asset, CVE) and their BASIS is read back
from the store, never taken from the request, so a caller cannot post
`basis: version_range` and receive a document describing a worklist entry as a
confirmed vulnerable version. The route stores nothing and transmits nothing;
filing is an act by the organisation, through CERT-In's own channel.

**D29 - a module without a surface is not shipped.** An audit for modules
imported by nothing outside their own tests found four: `stix.py`, `alerting.py`,
`latency.py` and `artefacts.py` — 956 lines, 60 tests, all passing, none
reachable by a user. `latency.py` was worse than unwired: `data/artefacts.json`
had never been vendored, so its INPUT did not exist in the repo either and the
P3 measurement lived only in a transcript. Fixed by vendoring the artefact index
(834 of 1,674 KEV entries, 49.8%), adding `--only-artefacts` to the refresher so
the other four corpora stay byte-identical, and giving all four modules routes.
The measurement reproduces exactly: ransomware-linked + packaged module, n=58,
median 8 days, IQR 1-124; the other three classes span 1,525 / 1,703 / 2,405
days and refuse. `test_surfaces.py` covers the routes.

**D30 - the alert route decides and does not deliver.** `alerting.dispatch` can
post to a webhook or an SMTP server, and it stays configuration-driven. A GET
that caused the server to send findings outward would let anyone who can reach
the API choose the moment the estate is described to a third party, so
`/api/v1/alerts` returns the decision with `delivered: false` and a test asserts
no route references `dispatch`, `send_webhook` or `send_email`. Related
correction: this file and ARCHITECTURE.md both claimed `egress.py` was the ONLY
module performing I/O. It never was — `collect/ct.py` and `core/alerting.py`
also do, each under its own `# NETWORK-BOUNDARY:` marker, which is the rule the
test actually enforces.

**D31 - the daily jobs are opt-in, and the cost of that is stated.** EPSS
publishes today's scores and never republishes yesterday's, so a missed day is a
permanent hole in every velocity figure computed afterwards. That argues for a
scheduler running by default, and the gate argues louder against it: a stack
that began phoning out because somebody ran `docker compose up` would be making
an egress decision on the operator's behalf. So the `scheduler` compose profile
is off unless started explicitly, and both the compose comment and `.env.example`
say what leaving it off costs. It runs immediately on start rather than sleeping
first, because a scheduler that waits a day before its first run is
indistinguishable from one that is broken.

**D32 - TAXII's `date_added` is the SCAN RUN's timestamp, never `now()`.** The
obvious implementation regenerates the bundle per request with a fresh timestamp
on every object, and then `added_after` either returns everything forever or
nothing ever — the consumer's incremental poll silently stops working while the
server keeps answering 200. Object ids were already deterministic (uuid5 over a
fixed namespace), so stamping every object in run N with run N's `scanned_at`
gives a consumer exactly the delta it asked for. Verified live: two identical
requests return identical manifests, `added_after=<that stamp>` returns 0
objects, `added_after=2020` returns all 136.

The collection is READ-ONLY and that is a refusal, not a gap. Accepting objects
would mean ingesting third-party claims into a product whose discipline is that
every statement carries who made it and how it was learned; an inbound STIX
object arrives with none of that. Registration follows the takeover precedent —
no `SKOPOS_API_TOKEN`, no routes at all, because a 401 that can be probed is
still an admission the data exists. `/taxii2/` under the console catch-all also
had to 404 rather than serve the SPA shell: a TAXII client receiving HTML from a
discovery endpoint cannot tell "not configured" from "not a TAXII server".

**D33 - a scan does not deliver alerts unless somebody said so, and never via
the request.** Running a scan describes your estate to yourself; delivering
alerts describes it to a webhook or a mail server, which is a third party even
when you own it. `SKOPOS_ALERT_ON_SCAN` gates it, in the ENVIRONMENT rather than
as a parameter — if the caller could ask for delivery, anyone who can reach the
endpoint could choose the moment the estate is described to a third party. The
switch fails closed on any unrecognised value, so a typo cannot send findings
out.

`deliver_for_run` is the single entry point so the API and any future caller
cannot drift into different rules, and it always reports which of FOUR states a
run was in. Three are "nothing was sent", and the third is why the function
exists: delivery switched on with NO CHANNEL CONFIGURED looks identical to a
quiet run from the outside, and a silent alerting integration is worse than none
because it is mistaken for coverage. A delivery failure never fails the scan —
the findings are persisted and correct; what failed is telling somebody.

**D34 - tenancy is a ROLE change with policies attached, not policies alone.**
Measured before writing migration 006: the application connected as `skopos`,
which is `rolsuper`, `rolbypassrls`, and the OWNER of every table. RLS does not
apply to such a role — not weakly, at all. Policies added under that
configuration would have produced a schema that reviews as multi-tenant and
enforces nothing, which is worse than no tenancy because it would be believed.

So `skopos_app` (present since 001, NOLOGIN, never used) became the runtime
identity: no superuser, no BYPASSRLS, owns nothing. `skopos` remains owner and
migrator. Proven live on the same data: as the app role, org `default` sees 576
findings and org `acme` sees 0; with the GUC unset, 0 — the correct failure
direction, since an empty result is noticed in minutes and the opposite default
is noticed by a customer. As the superuser, `acme` sees all 576, which is the
measurement that made the role change necessary.

Three details that carry weight. The column DEFAULT is
`current_setting('skopos.org_id', true)`, so writes land in the caller's tenant
without editing a single INSERT — with a literal default every tenant but one
would fail `WITH CHECK`. Uniqueness became per-tenant: without it, one tenant
scoping `example.com` silently prevents every other tenant from doing so, and
the second rule vanishes into `ON CONFLICT DO NOTHING` with no error. And
`epss_history` deliberately keeps a GLOBAL key and no policy — an EPSS score is
a public fact about a CVE, and per-tenant copies would leave a tenant whose
snapshot job never ran with no velocity data while the row it needed was already
in the table.

Stated limit, everywhere the feature is described: this defends against a BUG —
a forgotten filter, a new query, a bad join. It is NOT isolation against a
compromised application, because anything able to run SQL on that connection can
also change the session variable. "Postgres roles per org", which the SRS asks
for, was deliberately not done: a role per tenant means DDL at signup and an
application permanently holding CREATE ROLE, a larger standing privilege than
the accidental-leak risk it removes.

**Two defects this work surfaced, both found by running it.** Migration 006
changed four unique constraints, and every `ON CONFLICT` target in the stores
still named the old columns — the first scan after the migration failed with
`InvalidColumnReference`. And the tenancy fixture called `ensure_app_role`
against a throwaway DATABASE, but a PostgreSQL role is CLUSTER-wide: it rewrote
the real `skopos_app` password for every database on the server, and the running
application began failing authentication the moment the suite passed. Both are
in the git history rather than quietly fixed; `ensure_app_role` now takes a role
name so tests use a throwaway.

**767 tests** (704 offline + 63 live-database).

---

**D35 - the console grew to six sections on the condition it set itself.**
`App.tsx` shipped as one screen with a note saying the other SRS views arrive
"when they have something to project", because half-built views make a product
look broader and be worse. Measured: 24 API routes, 3 panels, and every surface
from P3 onward reachable only by curl — the compliance pack, the accuracy
scoreboard, the alert decision and the tenancy posture. Those have engines now,
so they got screens. The Executive and Operations projections are still absent
for the original reason: a re-skinned Management view with fewer columns is not
an executive view.

The panels carry the refusals as CONTENT rather than footnotes, because that is
the whole reason these screens differ from a competitor's. Seven of eight
CERT-In categories render as "cannot observe" in the same table as the one that
can; the CII register leads with "SKOPOS does not designate"; every control
shows what it does NOT do beside what it contributes, with no coverage
percentage anywhere; and the accuracy panel shows "not published" where a Brier
score would go, because a provisional figure gets screenshotted and the asterisk
does not travel with it. There is no button that files a CERT-In notification,
no button that sends an alert, and no button that downloads the STIX bundle —
each would be a path the module behind it deliberately refuses to provide.

**D36 - a type-check is not a render.** `npm run build` passed while two panels
had never executed. `tsc` proves shapes agree with the declarations; it does not
prove a `.map` over a field the API returns as null will not throw on a live
page. `frontend/scripts/render-check.tsx` server-renders every panel against the
RUNNING API and fails if one throws.

Its first version was worse than useless: a failed fetch became `null`, `null`
is a legitimate state every panel renders as an empty state, and the check
reported "ok" for eleven panels while two of them had quietly rendered "no scan
on record" against a still-warming container. It now fails loudly on any
non-200. Two other things the sweep caught: `.chip`, `.gap-list`, `.num` and
`.lede` were referenced by the existing Crosshair and Coverage panels and had
never been written, so those elements had been rendering as unstyled defaults;
and the `IntelStatus` type was two fields behind the API it describes.

## Running it

```bash
cp .env.example .env      # then set POSTGRES_PASSWORD
docker compose up -d      # skopos-db-1 (postgres:16) + skopos-app-1

export SKOPOS_DATABASE_URL=postgresql://skopos:<pw>@127.0.0.1:55443/skopos
python main.py scope add example.com --kind wildcard --actor you@example.com
python main.py discover example.com --actor you@example.com -o discovered.csv
python main.py dns-sweep discovered.csv --actor you@example.com
python main.py verify api.example.com --method dns_txt --actor you@example.com
python main.py fingerprint discovered.csv --actor you@example.com -o assets.csv
python main.py scan assets.csv
```

Console and API on <http://127.0.0.1:8100>, OpenAPI at `/api/docs`, Postgres on
`127.0.0.1:55443` (loopback only). `/api/v1/takeover` is not registered at all
unless `SKOPOS_API_TOKEN` is set.
