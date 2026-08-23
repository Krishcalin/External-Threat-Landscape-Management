<p align="center">
  <img src="skopos-logo.png" alt="SKOPOS" width="420">
</p>

# P3 — Decide it, and find out whether the decisions were any good

> **This document is a RETROSPECTIVE.** P2, P6 and P7 were written before their
> phase was built, and carry a "what would make this plan wrong" section for
> that reason. P3 was built first and written up afterwards, so what follows is
> a record rather than a plan. It is marked here because a retrospective
> presented as foresight is a small dishonesty, and this phase is largely about
> refusing those.

**Phase goal:** turn a ranked worklist into decisions somebody can defend, and
start measuring whether the product's predictions hold. v1.0.

The defining feature of P3 is what it *did not ship*. Two of the four
workstreams were built, measured, and closed — and the measurements are the most
valuable output of the phase.

---

## Contents

1. [What was measured, and what it killed](#1-what-was-measured-and-what-it-killed)
2. [W1 — The ATT&CK triad (CLOSED)](#w1--the-attck-triad-closed)
3. [W2 — SSVC, shipped in its place](#w2--ssvc-shipped-in-its-place)
4. [W3 — The Crosshair](#w3--the-crosshair)
5. [W4 — Time-to-attack (REFUSES 3 OF 4)](#w4--time-to-attack-refuses-three-of-four-cells)
6. [W5 — The backtesting scoreboard](#w5--the-backtesting-scoreboard)
7. [What P3 left owing](#what-p3-left-owing)

---

## 1. What was measured, and what it killed

| Question | Measurement | Consequence |
|---|---|---|
| Can a CVE be attributed to a threat actor? | 0 CVE refs in ATT&CK `external_references`; 5 of 191 groups mention one in prose; technique→group implicates a **median of 57 groups**, max 139 of 191 | **W1 closed.** SSVC shipped instead |
| How long after public exploit code does exploitation follow? | Only **1 of 4** reference classes has usable data (n=58, median 8d, IQR 1–124); the others span 1,380–2,360 days | **W4 refuses three cells** |
| Can lead time be measured on this corpus? | Median **−1258 days** — every forecast is issued *after* CISA lists the CVE | Recorded as structurally unmeasurable, not dropped |
| What share of the catalogue is version-determinable? | **47.5%** over the full corpus (668 structured + 128 exact; 878 uncomparable) | Stated on every run and in the STIX bundle |

**One measurement error worth recording.** An earlier random-40 sample put
determinability at 67.5%. Age-stratified, the true rate runs **0% / 20% / 90%**
by CVE age — so a sample drawn without stratifying measures the sample's age
distribution rather than the corpus. The published figure was corrected to 47.5%
across `docs/P2-SCOPE.md`, the README and `core/stix.py`'s outbound caveat.

---

## W1 — The ATT&CK triad (CLOSED)

**The intent:** CVE → ATT&CK technique → threat group, so a finding could say
who is known to use it.

**Why it was closed rather than deferred.** It was built far enough to measure,
and the measurement is unambiguous: the CTID mapping covers 419 of 1,674 KEV
entries, but resolving technique → group implicates a **median of 57 groups per
CVE**. An attribution that names 57 groups is not attribution; it is a list of
everybody.

Nothing in P4–P7 reopens this, and `CrosshairPanel` renders the refusal on
screen rather than hiding it. The P7 direction asked for "threat actors who have
targeted this and are targeting now", and `docs/P7-SCOPE.md` splits that back
into the two claims it conflates: attribution from a CVE (refused, measured) and
an asset appearing in an abuse feed today (an observation, supportable).

---

## W2 — SSVC, shipped in its place

CISA-ADP publishes SSVC decision points — `exploitation`, `automatable`,
`technical_impact` — as a **stated judgement with a named author**, which is
categorically different from an inference this product would be making up.

1,674 decisions vendored. `automatable` breaks 675 yes / 999 no, and it is used
where it can actually matter: the order the worklist is worked in. It does not
change the exploitability factor, because KEV membership already short-circuits
that to 1.0.

---

## W3 — The Crosshair

Seven independent signals, a count, and three tiers (`CONVERGED_AT = 4`). It
says **how many things point at an asset, never who is pointing** — which is the
whole reason the view survived W1's closure.

Coverage gaps sit at the top of the panel rather than the bottom, because a
finding reaches the converged tier partly because somebody supplied a version and
probed the host. An empty top tier on an uninstrumented estate is not good news,
and the panel refuses to let it read as good news.

---

## W4 — Time-to-attack (refuses three of four cells)

Reference classes are (ransomware × weaponised), built from published exploit
artefacts against KEV addition dates.

| Class | n | median | IQR | usable |
|---|---:|---:|---|:---:|
| ransomware-linked, packaged module | 58 | 8 days | 1–124 | **yes** |
| not ransomware, packaged module | 129 | 120 | 10–1713 | no |
| not ransomware, no module | 31 | −14 | −145–1380 | no |
| ransomware-linked, no module | 10 | −30 | −45–2360 | no |

`MIN_SAMPLE = 20` and `MAX_USEFUL_SPREAD_DAYS = 400` are enforced **in the
type**, so an unusable cell cannot be rendered as a prediction. A median drawn
from a 2,360-day spread is a shrug with a number on it.

The KEV backfill also skews the base rate — the unwindowed median is **777
days**, which is a fact about CISA's backlog rather than about warning time — so
the window starts 2023-01-01 and the measurements behind that date live in
`core/artefacts.py`.

---

## W5 — The backtesting scoreboard

Every finding is a prediction, and P2 started writing the input vector at the
moment it exists. P3 built the scoring.

- No skill score below `MIN_RESOLVED_TO_PUBLISH = 30` resolved forecasts.
- Lead time carries `LEAD_TIME_UNMEASURABLE` rather than a number.
- The resolver requires a **genuine EPSS crossing**: 80 of 128 forecasts were
  already above the threshold when issued, and counting those would have
  manufactured a hit rate.

---

## What P3 left owing

Recorded here because it was discovered in P5 and belongs in this phase's story:
**`core/latency.py` shipped with no input.** `data/artefacts.json` had never
been vendored, so the measurements above lived only in a session transcript and
no user could reach the module at all. P5's orphan audit (D29) found it,
vendored the artefact index — 834 of 1,674 KEV entries, 49.8% — and reproduced
every figure above exactly.

A phase that measures carefully and leaves the measurement unreachable has done
half the work.
