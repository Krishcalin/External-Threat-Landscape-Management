# P6 — Third-party, and the projections

Weeks 43–48. Out: **eight pillars of substance rather than nine of coverage.** v2.0.

| Workstream | What it is |
|---|---|
| [W1](#w1--the-supplier-register) | Supplier register: passive posture assessment and concentration analysis |
| [W2](#w2--the-projections) | Executive and Operations views, as projections of the graph Management already renders |
| [W3](#w3--itsm-and-tip-connectors) | ITSM and TIP connectors |
| [W4](#w4--helm-and-performance) | Helm chart and performance hardening |

---

## Dropped, not deferred: M8 adaptive awareness training

Six branded slogans with no mechanism and no output, even in the original.
Building a hollow pillar to claim parity is the one thing this plan should not
do — it is the same failure as a coverage percentage, a provisional Brier score,
or an attribution that names 57 threat groups. Nine pillars of coverage would
read better on a comparison grid and would make the eight real ones less
believable.

---

## What was measured before any of this was planned

Three questions, answered against the running system rather than reasoned about.

### 1. What may this product do to a supplier's estate? — the gate already decided

A supplier's infrastructure is **somebody else's estate**. The customer cannot
prove ownership of it, and FR-GOV-001 makes active collectors fail closed
against an unverified asset. Measured, with the supplier's domain explicitly
placed in scope and no ownership verification:

| Operation | Exposure | Result |
|---|---|---|
| `ct_log_search` | passive | allowed |
| `passive_dns` | passive | allowed |
| `rdap_lookup` | passive | allowed |
| `dns_resolve_recursive` | passive | allowed |
| `whois_lookup` | passive | allowed |
| `http_probe` | active | **refused — OwnershipNotVerified** |
| `tls_handshake` | active | **refused — OwnershipNotVerified** |
| `port_scan` | active | **refused — OwnershipNotVerified** |
| `service_banner_read` | active | **refused — OwnershipNotVerified** |

**"Passive posture assessment" is not a cautious choice in this plan. It is the
only thing the architecture permits**, and it was permitted that way before
anybody thought about suppliers. No scope rule and no configuration setting can
change it; the refusal is decided before scope is consulted.

**The consequence that shapes everything else in W1.** No active probe means no
fingerprint, no fingerprint means no product name, and no product name means
**no CVE join for a supplier, ever**. A supplier's posture in this product can
never be a vulnerability list — not a shorter one, not a lower-confidence one,
none. Anything that looks like a supplier CVE count on a screen is a fabrication.

So W1 assesses what is genuinely observable without touching them, which is a
different and smaller claim: **how a supplier configures the things they publish
to the world.**

### 2. Is there anything for the Executive and Operations views to project?

`App.tsx` shipped as one screen with a note saying the other SRS views arrive
"when they have something to project", and a warning that a re-skinned
Management view with fewer columns is not an executive view. Measured:

- **10 scan runs on record**, each with its own summary and catalogue version.
  A trend needs a series and there is one.
- **64 of 64 findings carry an owner, a due date and a required action**, across
  6 distinct owning teams. A work queue needs assignment and a clock; both exist.

So the two views project genuinely different things, not the same table
filtered:

| View | The question it answers | Projects |
|---|---|---|
| Management (shipped) | what should we work on | ranked findings, evidence, decomposition |
| Executive | is the programme working | trend across runs, forecast accuracy, coverage gaps, supplier concentration |
| Operations | what is on my desk this week | queue by owner and due date, what is new since last run, what is overdue |

The condition the file set itself is met. Had the measurement come back
differently — no run history, no owners — the honest answer would have been to
keep one screen and say why.

### 3. Is the TIP connector already built?

SKOPOS ships STIX 2.1 and a TAXII 2.1 server. **TAXII is the standard TIP
interface**: MISP and OpenCTI both consume it. A bespoke connector for either
must justify what it adds over the protocol both of them already speak, and the
default answer is *nothing*. See W3.

---

## W1 — the supplier register

**The register is declared, never inferred.** Same discipline as the CII
register: SKOPOS does not get to decide who your suppliers are, and a tool that
guessed at supplier relationships from DNS would be inventing a commercial fact.
The customer declares them, with a tier and a stated dependency, and SKOPOS adds
only what it observed from outside.

### Posture: what is actually observable

Everything below comes from records the supplier publishes deliberately. None of
it touches them.

| Signal | Source | What it means, and does not |
|---|---|---|
| SPF, DMARC, MTA-STS | TXT at the apex and derived names | Whether they have configured email authentication. NOT whether their mail is secure. |
| CAA | DNS | Whether they constrain who may issue certificates for their names. |
| Certificate hygiene | CT logs | Issuer, and how close to expiry. NOT whether TLS is correctly configured — that needs a handshake, which is refused. |
| Registration hygiene | RDAP | Registrar lock, expiry. A domain expiring in 14 days is a real and cheap finding. |
| Name server, mail provider | NS, MX | Who they actually depend on — the input to concentration. |

**What a posture assessment here is worth, stated on the screen:** it measures
published configuration, which correlates with how an organisation runs things
and is not a measurement of their security. A supplier with perfect DMARC can be
breached tomorrow. The value is that it is comparable across a register and
costs the supplier nothing.

### Concentration: the output that does not exist elsewhere

Across the declared register, which providers recur. *"14 of your 30 suppliers
resolve mail through the same provider; an outage there reaches half your supply
chain in one event."* That is computable from NS and MX alone, it is invisible
to each supplier individually, and it is the one thing in W1 a customer cannot
get by asking their suppliers for a questionnaire.

**Honest limit:** shared infrastructure is a correlation in availability and
blast radius, not proof of a shared vulnerability. The screen must say so, or it
becomes a fourth-party risk claim the data does not support.

### Collection delta

Small, because the collectors already exist:

- `MX` is a defined `RRType` and is **not** in `DEFAULT_RRTYPES` — one constant,
  and the wire parser already handles it.
- DMARC and MTA-STS live at derived names (`_dmarc.<domain>`), so the sweep must
  query a derived name rather than only the apex.
- CT currently parses `not_before` and `name_value`; issuer is not read, so CA
  concentration needs one extra field.

---

## W2 — the projections

One graph, three audiences. No new engine: if a projection needs data that does
not exist, the projection is wrong, not the data.

**Executive** — trend across runs, forecast accuracy (including that no figure
is published yet), coverage gaps, supplier concentration. The honest headline
for an executive is usually *what we still cannot see*, and this is the only
view where that belongs at the top.

**Operations** — the queue: by owner, by due date, what is new since the last
run, what is overdue. Everything already on a finding.

Both are `<section>`s beside the four that exist, not a second application.

---

## W3 — ITSM and TIP connectors

**ITSM is real work.** A finding becomes a ticket in the customer's own system.
It carries the same discipline as alert delivery, for the same reason: creating
a ticket is describing the estate to a third party, so it is switched on in the
environment, never by a request parameter, and never by a console button.

Two things it must not do. It must not create a ticket per finding per run —
that is how an integration gets switched off in week two; identity is
`(asset, cve)` as everywhere else, and an existing open ticket is updated rather
than duplicated. And a ticket must carry the worklist/determination distinction
in its body, because a ticket saying "CVE-2018-13379 on fw-01" reads as a
determination to whoever picks it up.

**TIP is provisionally NOT a connector.** TAXII 2.1 is the interface MISP and
OpenCTI already speak. Before writing either, the question to answer is what a
bespoke connector adds over the protocol — and if the answer is "nothing", W3
ships ITSM plus a documented TAXII integration path, and says so. That decision
is recorded here in advance so it cannot be quietly reversed into two more
half-connectors.

---

## W4 — Helm and performance

**Helm.** The compose stack already separates a migration identity from an
unprivileged runtime identity; the chart must preserve that split rather than
running everything as one Secret with superuser rights. Both the app password
and the API token are Secrets, never values in `values.yaml`.

**Performance hardening waits on a measurement.** Nothing here has been profiled
and nothing is known to be slow. The one structural candidate visible by
inspection is that every store opens a **connection per operation** — fine at
one request, and the first thing to check under load. Optimising before
measuring is how a codebase acquires complexity it cannot justify, which is the
same mistake as building M8.

---

## What would make this plan wrong

Stated in advance, so it is checkable rather than defended:

- If a customer's suppliers turn out to publish almost no DMARC/CAA/MTA-STS,
  posture assessment produces a column of "not configured" and says nothing
  useful. **Measure against a real register before building the screen.**
- If a register is small — five suppliers, not fifty — concentration analysis
  has nothing to concentrate. It needs a threshold below which it declines to
  draw a conclusion, exactly as the latency reference classes do.
- If the ITSM systems in reach need per-tenant OAuth apps, the connector is a
  larger piece than this phase, and the honest move is to ship a generic webhook
  with a documented payload instead of a half-finished ServiceNow integration.
