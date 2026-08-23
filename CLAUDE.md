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
etlm/
├── main.py                 CLI — `scan`, `intel`
├── core/
│   ├── models.py           Asset, Exploited, Exposure, MatchBasis, Confidence
│   ├── intel.py            vendored corpus + staleness reporting
│   ├── inventory.py        aliased CSV/JSON ingest; rejects are RETURNED
│   └── match.py            the join, and what it refuses to claim
├── data/
│   ├── kev.json            CISA KEV, verbatim (public domain)
│   └── epss.json           FIRST EPSS, KEV subset (stated boundary)
├── tools/refresh_intel.py  regenerates data/; refuses partial catalogues
├── sample_data/assets.csv
└── tests/
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
  empty catalogue produces a report identical to a secure estate.
- **Truncation says so.** A capped list that does not announce the cap reads as a
  complete one.

---

## Status

**TEPS implemented and golden-tested against SRS §9.1** — the published worked
example reproduces exactly at 78, with every intermediate factor matching
(E=0.817, X=1.000, A=0.850, B=1.000). 28 tests.

**Phase 1 spine complete** — corpus, models, inventory ingest, matcher, CLI,
8 tests. Verified end to end against the real catalogue (1,674 entries,
version 2026.08.21).

### Next

- [ ] NVD CPE affected ranges - the `VERSION_RANGE` determination (closes D3)
- [ ] Run-over-run diff: what is *new* since the last scan
- [ ] Wire the gate into the API and the console (routes + audit payloads)
- [ ] Active collectors, which are now unable to run without a Permit
- [ ] Tenancy (FR-M0-001): org_id on every table, RLS, and Postgres roles per org

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
