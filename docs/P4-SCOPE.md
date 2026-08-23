<p align="center">
  <img src="skopos-logo.png" alt="SKOPOS" width="420">
</p>

# P4 — The India compliance pack, and the things it will not say

> **This document is a RETROSPECTIVE**, written after the phase was built. P2,
> P6 and P7 were written in advance and carry a "what would make this plan
> wrong" section; this one is a record. Marked because a retrospective
> presented as foresight is exactly the kind of small dishonesty this phase
> exists to avoid.

**Phase goal:** answer the questions an Indian regulator and an ISO assessor
actually ask, without inventing a single fact.

Two things go wrong in every compliance feature ever built, and both are the
category's default behaviour: **starting a regulatory clock on a finding**, and
**showing a coverage percentage**. Most of P4 is machinery to make both
impossible.

---

## Contents

1. [What was measured before building](#1-what-was-measured-before-building)
2. [W1 — CERT-In reporting](#w1--cert-in-reporting)
3. [W2 — The control mapping](#w2--the-control-mapping)
4. [W3 — The CII exposure register](#w3--the-cii-exposure-register)
5. [W4 — The notification draft](#w4--the-notification-draft)
6. [The through-line](#the-through-line)

---

## 1. What was measured before building

| Question | Measurement | Consequence |
|---|---|---|
| How much of CERT-In's reportable list can an outside-in product observe? | **1 of 8** Annexure I categories. The other seven describe something an adversary *did* | The clock cannot start itself, and the note says which categories and why |
| Can CII status be inferred? | No. s.70 of the IT Act, 2000: the appropriate Government declares it **by notification in the Official Gazette** | The register records declarations; there is no function that infers |
| What can be claimed against a control? | Contribution, not satisfaction | Eight entries, no percentage anywhere |

---

## W1 — CERT-In reporting

**Direction No. 20(3)/2022-CERT-In**, dated 28 April 2022, effective 28 June
2022. Six hours from becoming aware.

**An exposure is not an incident.** There is no `clock_from_finding()` and no
endpoint that opens one. The only constructor takes a `Declaration`, which
requires a named person, a summary in their own words, and a **timezone-aware**
time of awareness — a six-hour deadline computed from an ambiguous timestamp is
worse than no deadline.

Seven of eight Annexure I categories are `NOT_OBSERVABLE`, including targeted
scanning: somebody scanning *you* is not visible from outside your estate. A
tool that started a national-CERT countdown on every unpatched perimeter service
would push its users toward over-reporting, so the reason is a published string,
`cert_in.WHY_NOT_AUTOMATIC`, rather than merely an absent function.

---

## W2 — The control mapping

Five ISO/IEC 27001:2022 controls and three NIST CSF 2.0 entries. Titles are
quoted **verbatim** — paraphrasing a control title is how a mapping drifts into
describing something the standard does not say.

Every entry carries three fields: what it **contributes**, what it **does not
do**, and which **evidence** it draws on. The second is given equal weight to
the first on screen.

**No coverage percentage, in any field or any sentence.** It would be summed,
shown to a board, and the board would be receiving a number no external scanner
has the basis to produce. A test checks for numeric *fields* rather than the
word, because a crude word-ban fires on the disclaimer that exists to prevent
the thing.

Two entries carry measurements from earlier phases rather than restating them:

- **A.8.8 Management of Technical Vulnerabilities** carries the 47.5%
  determinability limit and states plainly that this product does not patch
  anything.
- **A.5.7 Threat intelligence** carries the median-57-groups finding and states
  that this product cannot tell you who is targeting you.

---

## W3 — The CII exposure register

Under **s.70A of the IT Act, 2000** (gazette notification 16 January 2014),
NCIIPC is the national nodal agency. Under **s.70**, the appropriate Government
declares a computer resource a protected system by notification in the Official
Gazette.

**That is a legal status and it cannot be inferred from a hostname.** An
organisation acting on a guess would either over-report to a national agency or
believe itself covered when it is not.

So the register records what the **organisation** stated, with the basis
attached:

| Basis | Weight |
|---|---|
| `GAZETTE` | declared a protected system by notification. **Refused at construction without a notification reference** — the one claim here that could mislead a regulator |
| `ORGANISATION_ASSESSED` | the organisation's own position. Explicitly *not* a legal designation |
| `UNDECLARED` | a QUESTION for the organisation, never a finding — the answer may legitimately be "out of scope, always was" |

An empty register is not an estate with no critical infrastructure. It is an
estate nobody has declared, and the payload says so.

---

## W4 — The notification draft

`notification_draft()` takes a `Declaration`, so **there is no path from a
finding to a regulatory document**. The determination that an incident occurred
is the reporter's, and this module refuses to make it for them.

It fills only what can be substantiated and marks impact, root cause, data
affected, remediation and contact `[TO BE COMPLETED BY REPORTER]` — a pre-filled
guess gets filed verbatim by somebody working against a six-hour deadline.

**The integrity property worth naming:** related findings are cited by
`(asset, CVE)` and their **basis is read back from the store**, never taken from
the request. A caller cannot post `basis: version_range` and receive a
regulator-facing document describing a worklist entry as a confirmed vulnerable
version. Overstating to CERT-In is worse than overstating on a dashboard.

The route stores nothing and transmits nothing. Filing is an act by the
organisation, through CERT-In's own channel.

---

## The through-line

Every workstream in P4 is a refusal with useful machinery around it:

- the clock will not start itself, and says why;
- the mapping will not produce a percentage, and says why;
- the register will not designate, and says who can;
- the draft will not guess a judgement, and marks where one is needed.

A compliance feature whose main output is *"we cannot tell you this"* is unusual.
Measured against what the data supports, it is the correct answer — and the
alternative is a product that makes an organisation feel covered while leaving
them exposed to the regulator it was bought to satisfy.
