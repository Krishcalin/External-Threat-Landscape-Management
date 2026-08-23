<p align="center">
  <img src="skopos-logo.png" alt="SKOPOS" width="420">
</p>

# What SKOPOS refuses to do, and the measurement behind each refusal

Every capability on this page is one a competitor sells. Each is absent from
SKOPOS for a stated reason, and in most cases that reason is a number this
project measured itself and then had to accept.

This document exists because the first question anybody comparing SKOPOS to a
commercial platform asks is *"why does it not do X?"* — and the answer should be
one click away, not archaeology through seven phase documents.

**A refusal is not a gap.** A gap is something not yet built. A refusal is
something built far enough to measure, measured, and then removed or declined.
Where the distinction matters it is marked.

---

## Contents

1. [Threat actor attribution](#1-threat-actor-attribution)
2. [A single risk score](#2-a-single-risk-score)
3. [Dark web collection](#3-dark-web-collection)
4. [Confirming a subdomain takeover](#4-confirming-a-subdomain-takeover)
5. [Starting a regulatory clock](#5-starting-a-regulatory-clock)
6. [Declaring critical infrastructure](#6-declaring-critical-infrastructure)
7. [A compliance coverage percentage](#7-a-compliance-coverage-percentage)
8. [Supplier vulnerability findings](#8-supplier-vulnerability-findings)
9. [Three cells of the time-to-attack forecast](#9-three-cells-of-the-time-to-attack-forecast)
10. [Adaptive awareness training](#10-adaptive-awareness-training)
11. [What is a gap rather than a refusal](#11-what-is-a-gap-rather-than-a-refusal)

---

## 1. Threat actor attribution

**Refused. Built, measured, closed.**

Recorded Future tracks 4,000+ threat actor organisations and 430 nation-state
groups, and surfaces them throughout. Nearly every commercial platform in this
category answers *"who is targeting you?"*

P3 built the chain — CVE → ATT&CK technique → threat group — far enough to
measure it:

| Measurement | Result |
|---|---|
| CVE references in ATT&CK `external_references` | **0** |
| Groups whose prose mentions a CVE | 5 of 191 |
| CTID mapping coverage of KEV | 419 of 1,674 entries |
| **Groups implicated per CVE via technique** | **median 57**, max **139 of 191** |

An attribution that names 57 groups is not attribution. It is a list of
everybody, delivered with the confidence of a finding.

SSVC shipped in its place, because CISA-ADP publishes decision points as a
**stated judgement with a named author** — categorically different from an
inference this product would be making up.

`CrosshairPanel` renders the refusal on screen rather than hiding it. The
Crosshair says **how many things point at an asset, never who is pointing**.

> Recorded on: `docs/P3-SCOPE.md` · enforced by: nothing in `core/` resolves a
> group from a CVE.

---

## 2. A single risk score

**Refused by design.**

Recorded Future produces a 0–99 score from 40+ risk rules, banded into High
(65–99), Moderate (25–64) and Informational (5–24).

The number is what survives into a board deck, and by the time it gets there
nobody can say which of the forty rules produced it. A scalar is not a summary
of forty facts; it is a replacement for them.

SKOPOS decomposes **TEPS** into four factors — exposure, exploitability,
adversary interest, business impact — and never displays a bare total. The
`core/rules.py` catalogue publishes all 39 checks individually with per-rule
evidence, which is the same information without the collapse.

> Enforced by: `tests/test_rules.py::test_the_catalogue_refuses_to_offer_a_score`
> and the TEPS decomposition being one click away on every finding.

---

## 3. Dark web collection

**Refused on governance grounds. A real capability gap remains.**

Recorded Future collects from hundreds of Tor sites, IRC channels, forums, shops,
markets and paste sites, with deep NLP in 12 languages.

**FR-GOV-003** prohibits authenticating to, transacting on, or scraping
access-controlled criminal forums. It permits public index pages.

So SKOPOS takes the part that is lawfully observable — ransomware leak-site
index pages — and stops there. What remains uncovered is genuine: credential
markets, forum chatter, initial-access-broker listings. That is a real gap and
it is not going to close.

> Enforced by: the egress allowlist, and the absence of any credential handling
> in `collect/`.

---

## 4. Confirming a subdomain takeover

**Refused on capability grounds. The ceiling is permanent.**

SKOPOS reports a dangling record as `registrable_domain_unregistered` — the
strongest passive statement available. It never reports "vulnerable to
takeover".

The only experiment that would establish claimability is **registering the
resource**, which is an act against a third party's namespace. FR-GOV-007
prohibits offensive capability, and the reason given on screen is capability,
not caution.

> Recorded on: `core/takeover.py` module docstring · rule
> `takeover.registrable_domain_unregistered`.

---

## 5. Starting a regulatory clock

**Refused. Measured at 1 of 8.**

CERT-In Direction No. 20(3)/2022 requires reporting within six hours of becoming
aware of an incident. Of its eight Annexure I reportable categories, **seven
describe something an adversary did** — unobservable from outside an estate.
Even "targeted scanning" is invisible: somebody scanning *you* cannot be seen
from outside *your* perimeter.

There is no `clock_from_finding()` and no endpoint that opens one. The only
constructor takes a `Declaration` requiring a named person, a summary in their
own words, and a timezone-aware time of awareness.

A tool that started a national-CERT countdown on every unpatched perimeter
service would push its users toward over-reporting.

> Recorded on: `docs/P4-SCOPE.md` · published as `core/cert_in.WHY_NOT_AUTOMATIC`.

---

## 6. Declaring critical infrastructure

**Refused on legal grounds.**

Under s.70 of the IT Act, 2000, the appropriate Government declares a computer
resource a protected system **by notification in the Official Gazette**. That is
a legal status and it cannot be inferred from a hostname.

The CII register records what the *organisation* stated, with the basis
attached. A `GAZETTE` basis is refused at construction without a notification
reference — the one claim here that could mislead a regulator.

> Recorded on: `docs/P4-SCOPE.md` · enforced by: `core/cii.py`.

---

## 7. A compliance coverage percentage

**Refused by design.**

The control mapping states what each control is *contributed to*, what it
explicitly does **not** do, and which evidence it draws on. There is no
percentage in any field or any sentence.

A percentage would be summed, shown to a board, and the board would be receiving
a number no external scanner has the basis to produce.

> Enforced by: a test checking for numeric *fields* rather than the word, because
> a crude word-ban fires on the disclaimer that exists to prevent the thing.

---

## 8. Supplier vulnerability findings

**Refused structurally. This follows from the gate, not from a policy choice.**

A supplier's estate belongs to somebody else. The customer cannot prove ownership
of it, and `core/gate.py` refuses every active operation against an unverified
asset. No active probe means no fingerprint; no fingerprint means no product
name; no product name means **SKOPOS never reports a supplier vulnerability**.

The panel says so where a competitor would put a count.

Measured before the screen was built: SPF 8/8 and DMARC 8/8 across real domains,
so presence separates nobody. Enforcement, CAA and MTA-STS lead instead.

> Recorded on: `docs/P6-SCOPE.md` · enforced by: `core/gate.py`.

---

## 9. Three cells of the time-to-attack forecast

**Refused per-cell, in the type system.**

Four reference classes were built from published exploit artefacts against KEV
addition dates. Only one has usable data:

| Class | n | median | IQR | usable |
|---|---:|---:|---|:---:|
| ransomware-linked, packaged module | 58 | 8 days | 1–124 | **yes** |
| not ransomware, packaged module | 129 | 120 | 10–1713 | no |
| not ransomware, no module | 31 | −14 | −145–1380 | no |
| ransomware-linked, no module | 10 | −30 | −45–2360 | no |

`MIN_SAMPLE = 20` and `MAX_USEFUL_SPREAD_DAYS = 400` are enforced **in the
type**, so an unusable cell cannot be rendered as a prediction. A median drawn
from a 2,360-day spread is a shrug with a number on it.

> Recorded on: `docs/P3-SCOPE.md` · enforced by: `core/latency.py`.

---

## 10. Adaptive awareness training

**Dropped, not deferred.**

The SRS listed it as pillar M8. Read carefully, it was six branded slogans with
no mechanism and no output — even in the original.

Building a hollow pillar to claim parity is the one thing this plan should not
do. Eight pillars of substance rather than nine of coverage.

> Recorded on: `docs/P6-SCOPE.md`.

---

## 11. What is a gap rather than a refusal

Stated separately so the two are not confused. These are absent because they
have not been built, not because they were declined:

- **A 13-billion-entity intelligence graph** across a million sources. This is
  collection infrastructure, not code.
- **Malware intelligence and sandbox detonation.** A different product.
- **Geopolitical intelligence.** An analyst organisation, not software.
- **Identity intelligence at scale.** Domain-level breach exposure is planned;
  monitoring a million external identities is not.
- **Multi-tenant SaaS.** Row-level security is built and proven, but an
  organisation can still only be created by hand in the database.

---

## The through-line

Two things separate this list from a feature comparison.

**Most of these were measured before being refused.** 57 groups per CVE, 1 of 8
CERT-In categories, 1 of 4 latency cells, 8/8 SPF. The refusals are conclusions,
not positions.

**And the product publishes its own accuracy record**, which no competitor in
this category does. `core/backtest.py` scores forecasts against outcomes,
publishes no skill score below 30 resolved forecasts, and reports lead time as
structurally unmeasurable rather than inventing a number.

A product willing to say what it cannot do has some claim on being believed when
it says what it can.
