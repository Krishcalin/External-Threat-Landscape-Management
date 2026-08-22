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

- [ ] NVD CPE affected ranges → the `VERSION_RANGE` determination (closes D3)
- [ ] Persistence (PostgreSQL) + run-over-run diff: what is *new* since last scan
- [ ] Ownership and SLA — the "accountable remediation" half of the objective
- [ ] FastAPI + TypeScript console
- [ ] Opt-in collectors (CT logs, DNS) — the "continuously" half
