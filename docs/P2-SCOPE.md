<p align="center">
  <img src="skopos-logo.png" alt="SKOPOS" width="420">
</p>

# P2 — Judge it, and start the clock on measurement

**Phase goal:** prioritisation that survives the NVD gap, and the beginning of a
record that makes this product's forecasts checkable. First public release, v0.5.

Everything below is scoped against the code as it stands after P1, and the three
numbers that shape it were measured, not assumed.

---

## Contents

1. [What was measured before scoping](#1-what-was-measured-before-scoping)
2. [The seven workstreams](#2-the-seven-workstreams)
3. [W1 — CNA affected ranges](#w1--cna-affected-ranges-the-determination-tier)
4. [W2 — The forecast record](#w2--the-forecast-record-the-one-with-a-deadline)
5. [W3 — Exploit artefacts](#w3--exploit-artefacts)
6. [W4 — EPSS history](#w4--epss-history)
7. [W5 — Alerting](#w5--alerting)
8. [W6 — STIX 2.1 export](#w6--stix-21-export)
9. [W7 — Coverage feeds](#w7--coverage-feeds-euvd-osv)
10. [Sequencing, and the one thing that cannot wait](#10-sequencing-and-the-one-thing-that-cannot-wait)
11. [Open decisions](#11-open-decisions)

---

## 1. What was measured before scoping

### The determination tier is built and has never fired

`core/affected.py` is complete — `evaluate()`, `evaluate_range()`,
`affected_products()` — and `engine.score_exposure()` already accepts
`affected_versions`. **Nothing has ever passed it.** Verified against all four
shapes of version data:

| asset version | CNA entry | verdict |
|---|---|---|
| `10.3.6.0.0` | `{"version": "10.3.6.0.0"}` | `AFFECTED` |
| `10.3.7.0.0` | `{"version": "10.3.6.0.0"}` | `NOT_AFFECTED` |
| `10.0.17763.1` | `{"version": "10.0.17763.0", "lessThan": "10.0.17763.2803"}` | `AFFECTED` |
| `10.0.17763.9999` | same | `NOT_AFFECTED` |
| `1.0` | `{"version": "n/a"}` | `UNKNOWN` |
| *absent* | any range | `UNKNOWN` |

So W1 is not "build the determination tier". It is "feed the one that exists".

### How much of KEV carries usable version data — 47.5%, measured in full

**This section originally claimed ≈67.5% and that figure was not safe to
publish.** It came from a single 40-CVE random sample, and a second measurement
contradicted it. Both are recorded here, because the disagreement is the useful
part.

**Measurement 1 — 40 CVEs sampled at random:**

| | share | usable? |
|---|---:|---|
| structured range (`lessThan` / `lessThanOrEqual`) | 30.0% | yes — `evaluate_range` |
| exact versions only (`"10.3.6.0.0"`) | 37.5% | yes — equality is still a determination |
| placeholder or prose (`"n/a"`, `"Access 21.08.0.1, 21.08.0.0…"`) | 32.5% | no |

→ 67.5% reachable.

**Measurement 2 — the same question, stratified by CVE age (n=20 per bucket):**

| CVE era | determinable |
|---|---:|
| CVE-2010…2015 | **0%** |
| CVE-2018…2021 | **20%** |
| CVE-2024…2026 | **90%** |

Weighted by KEV's actual age distribution — ≤2015 11.9%, 2016–17 8.7%,
2018–21 33.9%, 2022–23 17.6%, 2024+ 27.9% — measurement 2 implies roughly
**41%**, not 67.5%.

**RESOLVED — the full corpus settles it at 47.5%.** All 1,674 CVEs fetched, zero
failures: 668 structured ranges + 128 exact versions = 796 determinable, 878
uncomparable.

So the random sample (67.5%) was badly high and the age-weighted estimate (41%)
was slightly low. The sample's biggest error was `exact versions`: it suggested
37.5%, and the true figure is 7.6%. Stratifying was the more reliable method
even though neither was right.

What the measurements agreed on all along, and what actually matters for
scoping, is the *shape*:

> **The determination tier's value is strongly age-dependent.** An estate
> running software whose CVEs predate about 2018 gets almost no determinations
> from W1 — the CNAs of that era published prose, not ranges. An estate on
> recent software gets nearly all of them.

That is a more useful statement than any single percentage, and it changes who
W1 is for. A blended average conceals it, which is why the original figure was
worse than uninformative: it implied a uniform two-thirds that no real estate
experiences.

> A third measurement error is worth recording too. The first attempt returned
> 0% across the board, and the fault was mine — `affected_products()` takes the
> *whole* record and unwraps `containers.cna` itself, and I passed it the
> already-unwrapped container. A 0% reading would have killed the workstream on
> a parsing error.

### The determination tier needs both sides, and only one comes from us

`evaluate()` reads `asset.version`. By D17 a fingerprinted version goes to
`obs_version` and **structurally cannot reach it** — a banner is the assertion of
the party whose patch state is the question.

So determinations fire **only where the customer supplied a version**. Measured
on the sample inventory: 9 of 9 assets carry one. On a CT-discovered,
fingerprinted estate: none do.

**This is the most important scoping fact in P2.** W1 transforms the
inventory-fed path and does nothing at all for the discovery-fed path. That is
the correct behaviour, not a gap to close — but it means the phase goal
"prioritisation that survives the NVD gap" is delivered for CMDB users and is
delivered for discovery users by W3 and W4 instead.

---

## 2. The seven workstreams

| | Workstream | Delivers | Size | Depends on |
|---|---|---|---|---|
| **W1** | CNA affected ranges | the `VERSION_RANGE` determination | M | — |
| **W2** | The forecast record | a checkable accuracy claim, later | S | — |
| **W3** | Exploit artefacts | exploitability that is not just EPSS | M | — |
| **W4** | EPSS history | velocity, and W2's resolution signal | S | W2 schema |
| **W5** | Alerting | the "continuously" half of the objective | M | P1 diff |
| **W6** | STIX 2.1 export | interoperability | S | — |
| **W7** | EUVD / OSV | coverage beyond KEV | L | W1 shape |

Sizes are relative: **S** ≈ a day, **M** ≈ two to three, **L** ≈ a week or more.

---

## W1 — CNA affected ranges (the determination tier)

**Turns `PRODUCT_MATCH` into `VERSION_RANGE` for the portion of KEV whose
CNA published comparable version data — heavily weighted toward recent
CVEs. See §1: 90% for 2024+, 20% for 2018–2021, 0% for pre-2016.**

### Approach

Vendor the affected data for the KEV subset only, exactly as KEV and EPSS are
vendored (D1). The full `cvelistV5` repository is ~2.6 GB; the KEV subset is
1,674 records fetched one apiece from `cveawg.mitre.org`. **Measured at ~1.4 s
per CVE end to end — roughly 39 minutes for the corpus, not the ~10 first
estimated from the sleep interval alone.** Written to `data/affected.json`,
regenerated by `tools/refresh_intel.py`, refusing to write a partial file.

### Build

| File | |
|---|---|
| `tools/refresh_intel.py` | EDIT — fetch CNA `affected[]` for every KEV CVE |
| `data/affected.json` | NEW — versioned input, like `kev.json` |
| `core/intel.py` | EDIT — load it; expose `affected_for(cve)` |
| `core/engine.py` | EDIT — pass `affected_versions` into `score_exposure` |
| `main.py`, `api/app.py` | EDIT — report determinations vs worklist separately |

### The safety work this turns on

`score_exposure` already sets `basis = VERSION_RANGE` for **`NOT_AFFECTED` as
well as `AFFECTED`**, and `NOT_AFFECTED` **retires the finding**. That path has
been inert only because nothing passed `affected_versions`. W1 makes it live, so
it needs, in the same commit:

- a test that a retirement requires an `OPERATOR`-attested version
- the retirement recorded with its evidence, because deleting an entry from a
  customer's worklist is the most consequential thing this product does
- `UNKNOWN` reported as its own count — "we compared and it does not apply" and
  "we could not compare" must not render alike

### Honesty requirement

The scan output must state the three-way split — determined affected, determined
not affected, could not determine — and say plainly that a substantial part of
the catalogue carries no comparable version data at all, so that portion stays a
worklist permanently.

The share is **read from the vendored corpus**, never hard-coded. It moves with
every refresh, and a constant baked into a report becomes a false claim the first
time the corpus changes underneath it.

---

## W2 — The forecast record (the one with a deadline)

**Every other workstream costs the same whenever it is built. This one gets
strictly more expensive every week it is not.**

A Brier score needs *resolved* forecasts. Resolution takes calendar time —
a CVE is added to KEV, an EPSS score crosses a threshold, an incident is
published — and **history cannot be backfilled**. A record started in P3 cannot
produce a measured accuracy claim until well into P4.

So this ships first, even though it produces no visible feature.

### What is written

Every finding, at the moment it is issued, with **its full input vector** — not
its score. A score is a conclusion; the inputs are what makes it checkable, and
they are what a later model version has to be re-run against.

```
forecast(
  id, issued_at, run_id, asset, cve,
  model_version,                    -- so a model change does not corrupt history
  inputs      JSONB,                -- every factor value that produced the score
  teps, band,
  resolved_at, outcome, resolution_source
)
```

`outcome` is filled later by a resolver: `KEV_ADDED`, `EPSS_CROSSED`,
`NO_EVENT`, `UNRESOLVED`.

### Build

| File | |
|---|---|
| `db/004_forecast.sql` | NEW — `forecast` table |
| `core/forecast.py` | NEW — write on issue; resolve on later evidence |
| `core/engine.py` | EDIT — emit the input vector alongside the score |
| `tools/resolve_forecasts.py` | NEW — nightly; marks outcomes |

### Non-negotiable

Write forecasts **even against crude expert priors**. A record of a bad model is
evidence; no record is nothing. The first published Brier score will be poor, and
publishing a poor number is the entire wedge — the competitor's evidence page has
been frozen since 2021.

---

## W3 — Exploit artefacts

**Exploitability that is not a restatement of EPSS.**

EPSS is a *forecast* of exploitation. An exploit artefact is an *observation*
that working code exists. Conflating them double-counts one signal;
`core/scoring.py` currently has only the forecast.

| Source | What it proves | Note |
|---|---|---|
| ExploitDB | published exploit code | stable CSV index |
| Metasploit | a weaponised, packaged module | the strongest single signal |
| Nuclei templates | a detection exists, so scanning is trivial | ProjectDiscovery repo |
| GitHub PoC search | code claims to exist | **noisy; see decisions** |

Feeds `scoring.Exploitability` as a distinct term with its own attestation, and
`weaponisation latency` (KEV date − artefact date) becomes computable, which P3
needs.

---

## W4 — EPSS history

Currently only *today's* EPSS is vendored, for the KEV subset. Retaining it daily
gives:

- **velocity** — a score moving 0.02 → 0.31 in four days is a stronger signal
  than either endpoint, and P3's velocity detector needs the series
- **W2's resolution signal** — `EPSS_CROSSED` cannot be detected without history
- an honest staleness statement per finding

Small: one table, one nightly append, one accessor. Should land with W2 because
it is one of W2's two resolution sources.

---

## W5 — Alerting

P1 already computes run-over-run diff (`/api/v1/changes`, keyed on
`(asset, cve)`). Alerting is the delivery of that, plus a rule about what is
worth waking somebody for.

Deliberately narrow: **a new finding at or above a threshold band, a new
takeover finding, or a DNS record that disappeared.** Not "everything that
changed" — an alert feed that fires on band drift is one nobody reads, which is
the same failure the diff key was chosen to avoid.

Channels: webhook and SMTP. No Slack/Teams SDKs — a webhook covers both and adds
no dependency.

---

## W6 — STIX 2.1 export

Findings as STIX 2.1 bundles (`vulnerability`, `infrastructure`, `relationship`).
Straightforward, self-contained, no server.

**A TAXII 2.1 *server* is scoped out of P2** — see decisions.

---

## W7 — Coverage feeds (EUVD, OSV)

Extends beyond KEV: OSV for open-source ecosystems (npm, PyPI, Go, Maven), EUVD
for the European catalogue.

Large, and it changes a load-bearing assumption. Everything in this product is
currently built on *actively exploited* — that is what makes the worklist short
and defensible. OSV covers hundreds of thousands of advisories with no
exploitation filter, so ingesting it naively converts SKOPOS into the vulnerability
scanner it was written not to be.

**If W7 ships, it must ship with a distinct badge and a separate default view.**
This is the workstream most likely to damage the product if done casually.

---

## 10. Sequencing, and the one thing that cannot wait

```
week 1     W2 forecast record  +  W4 EPSS history      ← start the clock
week 2-3   W1 CNA affected ranges                      ← the headline capability
week 4     W3 exploit artefacts
week 5     W5 alerting
week 6     W6 STIX export                              ← v0.5 public release
week 7-8   W7 coverage feeds (if approved)
```

**W2 first is the whole point of this phase's title.** It is the least visible
item and the only one with a deadline. Building it in week 6 costs five weeks of
evidence that can never be recovered.

W1 second because it is the headline capability and the one users will notice.

---

## 11. Open decisions

| # | Decision | Recommendation |
|---|---|---|
| **1** | **TAXII 2.1 server** — the plan lists it; it is a whole authenticated server with collections, filtering and pagination. | **Cut from P2.** STIX export delivers the interoperability; a TAXII server delivers a *subscription mechanism* nobody has asked for yet. Revisit when a consumer exists. |
| **2** | **GitHub PoC search** in W3 | **Cut.** The signal-to-noise is poor (repos named for a CVE that contain nothing), it needs an authenticated API with a rate limit, and ExploitDB + Metasploit + Nuclei already cover the observation. |
| **3** | **W7 coverage feeds** — hundreds of thousands of advisories with no exploitation filter | **Defer to P3+, or ship behind an explicit opt-in and a separate view.** The short defensible worklist is the product's main claim. |
| **4** | **`affected.json` scope** — KEV subset (1,674) or all CVEs (~290k) | **KEV subset.** Consistent with D1, keeps the vendored corpus reviewable, and the join only ever asks about KEV entries. |
| **5** | **Retirement evidence** — W1 makes `NOT_AFFECTED` retire findings | **Record every retirement with the range and the version that produced it.** Removing an entry from a customer's worklist is the most consequential act in the product and must be auditable. |

---

*Companion documents: `ARCHITECTURE.md` for the shape; `CLAUDE.md` for decisions
D1–D19; `P1-BUILD-SPEC.md` for the previous phase's design pass.*
