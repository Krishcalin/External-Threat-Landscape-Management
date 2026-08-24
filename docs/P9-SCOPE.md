<p align="center">
  <img src="skopos-logo.png" alt="SKOPOS" width="420">
</p>

# P9 — Absorbing the CTI platform

## What changed, and what deliberately did not

P8's R1–R5 built SKOPOS *towards* OpenCTI and OpenAEV: a TAXII push connector,
observables, SSVC labels, and a validation-target handoff. P9 reverses the
direction for **one half of that pair only**.

| | Direction | Status |
|---|---|---|
| **CTI** — ingest, correlate, decay | absorbed into SKOPOS | **this phase** |
| **AEV** — validate by executing | still refused, still handed off | unchanged |

**The AEV refusal stands exactly as written.** `core/gate.py` classifies
`exploit_attempt` and `credential_replay` as `PROHIBITED` unconditionally under
FR-GOV-007; `docs/REFUSALS.md` §3a still names OpenAEV as the alternative, and
`GET /api/v1/export/validation-targets` still produces the list to point it at.
Nothing in this phase touches that, and the decision to defer it was explicit.

---

## Why ingesting CTI does not contradict §1

`docs/REFUSALS.md` §1 refuses threat actor attribution, because P3 measured
CVE→technique→group at a **median of 57 groups per CVE**.

That refusal is about SKOPOS *inferring* attribution. It says nothing about
carrying somebody else's, and the distinction is the one SSVC already turns on:
a stated judgement with a named author is categorically different from an
inference this product would be making up.

So `core/cti.py` has **no field for SKOPOS's own opinion of an indicator**, and
a test parses the dataclass to keep it that way. Every value is a named source's
claim, carried with that source's date.

---

## The measurement that shaped the whole design

Measured 2026-08-24 against CIRCL's OSINT feed — MISP's own default, and where
most deployments start:

| Feed age | Events | Share |
|---|---:|---:|
| 2026 | 292 | 17.4% |
| 2025 | 31 | 1.8% |
| **older than 2020** | **1,143** | **68.0%** |

The two largest years are **2016 (20.7%) and 2017 (20.4%)**. Only 19.2% is from
2025 or later.

Ingested flat, that is a machine for generating confident nonsense: an address
that served malware in 2016 has been reassigned several times since, and a hit
on it today is a fact about a 2016 lease.

**So decay is the centre of the module rather than a refinement of it.**

### Decay is per-type, because indicator types age differently

| Kind | Half-life | Why |
|---|---:|---|
| `ipv4` / `ipv6` | 30 days | A lease. Cloud and hosting ranges churn in weeks |
| `url` | 60 days | A path on a host — outlives the address, rarely the domain |
| `domain` / `hostname` | 90 days | A registration. Persists for years |
| `email` | 180 days | An address a human keeps |
| `md5` / `sha1` / `sha256` | **0 — never decays** | **The artefact itself.** A file whose hash matched in 2014 is still that file; discounting it would discard *true* information |

That zero is a decision, not a gap, and a test asserts it.

Reporting floor is a weight of **0.05** — a little over four half-lives, so 130
days for an address and 390 for a domain.

---

## Two filters that each turned out to matter more than they look

### `to_ids` is the difference between a corpus and a corpus containing GitHub

MISP marks every attribute with `to_ids` — the publisher's own statement of
whether the value is suitable for automated detection rather than context for a
human reader.

Measured across the 12 most recent CIRCL events, **42,096 attributes**:

| | count | share |
|---|---:|---:|
| `to_ids: true` | 41,495 | 98.6% |
| `to_ids: false` | 601 | 1.4% |

**Every one of the 601 was type `url`**, and they are reference links — the
first attribute of the sample event is `https://api.github.com/repos/...`.
Without this filter SKOPOS would report github.com as a threat indicator
against any estate hosting there.

### The port makes a ThreatFox indicator match nothing

ThreatFox's most common `ioc_type` is `ip:port`, with the port inline:
`185.157.163.138:50810`. Stored verbatim it never matches anything, because no
estate inventory records an address with a port glued to it. The port is
stripped and dropped rather than kept — an attacker's C2 port is not a property
of the estate.

---

## Bulk automation is flagged by the source, so it is carried rather than judged

Within the decay horizon the feed is roughly half curated reporting (APT36,
Secret Blizzard, CISA advisories) and half automated daily bulk dumps of ~3,500
attributes each. MISP already distinguishes them:

| | `automation-level=unsupervised` | no tag |
|---|---:|---:|
| Maltrail bulk events | **162** | 0 |
| everything else | 124 | 1,394 |

The tag is the publisher's own, so it rides on every indicator and SKOPOS
invents no quality score of its own. A reader can tell a hand-written APT report
from an unsupervised aggregation — a distinction they should be making and this
product should not make for them.

---

## What was built

| Module | Does |
|---|---|
| `core/cti.py` | The model: `Indicator`, `Sighting`, `CTICorpus`, decay, TLP, correlation |
| `collect/misp.py` | MISP feed parser — manifest, events, `to_ids`, composite values |
| `collect/abusech.py` | ThreatFox + MalwareBazaar parsers |
| `tools/refresh_intel.py` | `fetch_cti()` + `--only-cti`, one-failing-publisher-carries-forward |
| `core/gate.py` | `cti_feed_read` registered PASSIVE |
| `core/lookup.py`, `api/app.py` | `cti` / `cti_coverage` on every lookup |

`collect/` modules are **pure parsers with no network**, matching
`collect/shadowserver.py`: fetching lives in `tools/`, so a refresh failure is a
refresh failure rather than a scan failure, and every parser is testable against
a fixture.

---

## TLP is modelled, because it has a redistribution consequence

It is the one piece of CTI metadata that constrains what SKOPOS may do next. A
platform that ingests TLP:RED and then exports it has broken the terms it
received the intelligence under, and no downstream care repairs that.

`MAX_EXPORTABLE_TLP = "GREEN"`, and **an unrecognised marking is treated as
restricted**. A feed inventing a marking is far likelier to be tightening than
loosening, and the failure direction matters more than the convenience.

---

## Sources carried, and sources refused with the measurement

**Carried** (keyless, bulk, reproducible): `circl_osint`, `threatfox`,
`malwarebazaar`.

**Refused**, each recorded in `core/cti.py:EXCLUDED` with the measurement:

| Source | Measured 2026-08-24 |
|---|---|
| AlienVault OTX | `/api/v1/pulses/subscribed` → **403**. A keyed bulk feed cannot be vendored, so a scan against it is not reproducible by whoever reads the report |
| Censys | `/api/v2/hosts` → **401**, and the free tier excludes commercial use |
| VirusTotal | Enrichment, not a feed — nothing to vendor, rate-limited, non-commercial |
| GreyNoise community | Keyless and working (`185.220.101.1` → `classification: malicious`), but answers **per address**, so it is enrichment not a corpus — and it describes the internet's scanners, not an estate's assets |

---

## Closing the gaps

The three gaps this document originally listed are now closed.

### STIX/TAXII ingest — `collect/stix_ingest.py`

The largest one. SKOPOS could produce STIX and not consume it, which is exactly
what made it depend on OpenCTI rather than replace it. A consumer is worth more
than any number of per-vendor parsers, because every CTI platform and every
commercial feed speaks STIX.

**The hard part is the pattern, not the bundle.** Almost no real feed ships bare
observables; it ships `indicator` SDOs carrying a STIX Patterning expression:

```
[domain-name:value = 'evil.example.com']
[file:hashes.'SHA-256' = 'a1b2…']
[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']
```

Temporal and behavioural forms (`REPEATS`, `WITHIN`, `START`/`STOP`) are counted
as `unsupported` and dropped — deliberately. They describe behaviour, and SKOPOS
holds an external inventory rather than telemetry, so it could never evaluate
them. That is a statement about this product's inputs, not a gap in the parser.
What failed to parse is **sampled, not merely counted**: a number alone cannot
be acted on.

**TLP arrives as an object reference, not a tag.** MISP writes `tlp:amber` as a
string; STIX writes a `marking-definition` and points at it. A consumer ignoring
those refs silently strips every handling restriction it was given — the one
mistake here with a consequence outside the software. So markings resolve
through the bundle, the six specification-standard TLP ids resolve even when a
bundle references them without defining them, **the most restrictive marking
wins**, and an unresolvable reference is treated as RED.

### The entity graph — `entities()`

Actors, malware, campaigns, tools and intrusion sets are extracted **separately
from indicators**, because a threat actor's name is not something an asset can
match and correlating it would be a category error.

This is also where the attribution question resolves. `_entity_context` walks
the bundle's `relationship` objects to find the actor an indicator was tied to —
and that is attribution **§1 permits**, because the bundle's author asserted it
in an object they signed. SKOPOS repeats it with their name attached; it does
not compute one.

### Promotion — sightings become findings, and reach TEPS

Three rules in `core/rules.py`: `cti.asset_in_intelligence`,
`cti.asset_named_by_actor_report`, and `cti.stale_corpus` — the last a COVERAGE
finding about SKOPOS itself, so a reader does not mistake a stale corpus for a
quiet estate.

`AdversaryInterest` gained **`observed_in_intel`** — deliberately a fourth leg
rather than one of the triad. The three triad legs are unsupplied because open
data cannot say whether an adversary has a *reason* to target an estate. A
sighting says something different: somebody observed this asset and wrote it
down. Folding it into `tech_match` would let an observation masquerade as the
inference the triad asks for.

**`MODEL_VERSION` moved to `teps-1.1.0`.** A scoring change that did not move
the version would make two incomparable numbers look like one measurement.
`core/backtest.py:score` already filters to a single `model_version` before
computing anything, so the two models are never pooled — the architecture
handled this correctly and the bump is safe.

A score with no CTI behind it is **unchanged** from teps-1.0.0, and a test
asserts that.

---

## The budget bug the first ingest exposed

The first real ingest took the 200 most recent events inside the decay horizon
and produced **94,449 indicators — 92,613 of them from daily automated
"Maltrail IOC" dumps** and only 1,836 from everything else. Every one carried
`automation-level=unsupervised`.

Sorting by date and truncating had systematically starved the curated
reporting — APT36, Secret Blizzard, the CISA advisories — because an automated
feed publishes every day and an analyst report does not. **Recency was deciding
the budget, and recency is the wrong judge.**

The tempting justification for simply dropping the bulk events would be that
they duplicate `core/blocklists.py`. **Measured, they do not**: only 59 of
92,513 values appear in the vendored abuse feeds. So they are cut back rather
than excluded, and `tools/refresh_intel.py` now allocates the two budgets
separately using MISP's own tag.

It also produced a **55 MB** corpus, against 1.6 MB for the next largest
vendored file. Gitignoring it was not an option — vendored means reproducible
means committed, which is the whole basis of `core/blocklists.py`'s design.

---

## What is still open

- **A TAXII 2.1 *pull* client.** `collect/stix_ingest.py` consumes any bundle,
  but something still has to fetch it on a schedule with pagination and
  `added_after` bookkeeping. SKOPOS serves TAXII (`core/taxii.py`) and pushes to
  it (`collect/opencti.py`); polling somebody else's is the remaining leg.
- **Entity persistence.** `entities()` extracts them; nothing stores or queries
  them yet, so "what is this indicator part of?" is answerable only within a
  single bundle.
- **AEV**, deferred by explicit decision.
