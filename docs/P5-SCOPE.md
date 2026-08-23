<p align="center">
  <img src="skopos-logo.png" alt="SKOPOS" width="420">
</p>

# P5 — Ship what was already built, then interoperate

> **This document is a RETROSPECTIVE**, written after the phase was built. P2,
> P6 and P7 were written in advance and carry a "what would make this plan
> wrong" section; this one is a record.

**Phase goal:** make the product reachable — by users, by other tools, and by
more than one tenant. v2.0.

P5 began with an audit that found the phase's real work: **four modules, 956
lines and 60 passing tests, that no user could reach.** Tests passing is not
shipped.

---

## Contents

1. [W1 — The orphan audit](#w1--the-orphan-audit)
2. [W2 — The console](#w2--the-console)
3. [W3 — TAXII 2.1](#w3--taxii-21)
4. [W4 — Alert delivery from a scan](#w4--alert-delivery-from-a-scan)
5. [W5 — Tenancy](#w5--tenancy)
6. [What P5 got wrong and corrected](#what-p5-got-wrong-and-corrected)

---

## W1 — The orphan audit

A sweep for modules imported by nothing outside their own test files found four:
`stix.py`, `alerting.py`, `latency.py`, `artefacts.py`.

`latency.py` was worse than unwired: **`data/artefacts.json` had never been
vendored**, so its input did not exist in the repo either and P3's
time-to-attack measurement lived only in a session transcript.

Fixed by vendoring the artefact index (**834 of 1,674 KEV entries, 49.8%**) and
adding `--only-artefacts` to the refresher — every other path in that script
refetches KEV and EPSS unconditionally, and rewriting the vendored corpus to add
one file is how a scan silently starts answering from different data. The other
four corpora verify byte-identical by sha256.

The P3 figures reproduced exactly: ransomware-linked + packaged module, n=58,
median 8 days, IQR 1–124.

**This pattern recurred twice more** — once in P6 and once after P7 — and is now
checked with a real import-graph walk rather than a grep, because a
mutually-referencing pair looks reachable to a naive check.

---

## W2 — The console

`App.tsx` shipped in P1 as one screen, with a note saying the other SRS views
would arrive "when they have something to project". Measured: 24 API routes, 3
panels, 10 client fetches. Everything from P3 onward was curl-only.

The condition the file set itself was met, so it grew to six sections. The
refusals are rendered as **content, not footnotes** — a compliance screen that
buries its limits in a tooltip may as well not have them.

**A type-check is not a render.** `npm run build` passed while two panels had
never executed. `frontend/scripts/render-check.tsx` server-renders every panel
against the running API. Its first version was worse than useless: a failed
fetch became `null`, `null` is a legitimate empty state, and it reported "ok" for
eleven panels while two rendered "no scan on record" against a warming
container.

---

## W3 — TAXII 2.1

The export route hands back a bundle — enough for a human with curl, and nothing
that runs on a schedule.

**The one property that makes incremental polling honest:** `date_added` must not
move. The obvious implementation regenerates the bundle per request with `now()`
on every object, and then `added_after` returns everything forever or nothing
ever — the consumer's poll silently stops working while the server keeps
answering 200.

So `date_added` is the **scan run's** `scanned_at`. Verified live: two identical
requests return identical manifests, `added_after=<that stamp>` returns 0
objects, `added_after=2020` returns all 136.

**Read-only, and that is a refusal rather than a gap.** Accepting objects would
mean ingesting third-party claims into a product whose discipline is that every
statement carries who made it and how it was learned; an inbound STIX object
arrives with none of that.

Registration follows the takeover precedent: no `SKOPOS_API_TOKEN`, no routes at
all — a 401 that can be probed is still an admission the data exists. `/taxii2/`
also had to 404 under the console catch-all rather than serve the SPA shell,
because a TAXII client receiving HTML from a discovery endpoint cannot tell "not
configured" from "not a TAXII server".

---

## W4 — Alert delivery from a scan

Running a scan describes your estate **to yourself**. Delivering alerts describes
it to a webhook or a mail server, which is a third party even when you own it,
and consent to the first is not consent to the second.

`SKOPOS_ALERT_ON_SCAN` gates it, **in the environment rather than as a request
parameter** — if the caller could ask for delivery, anyone who can reach the
endpoint could choose the moment the estate is described to somebody else. The
switch fails closed on any unrecognised value, so a typo cannot send findings out.

`deliver_for_run` always reports which of **four** states a run was in. Three are
"nothing was sent", and the third is why the function exists: **switched on with
no channel configured looks identical to a quiet run from the outside**, and a
silent alerting integration is worse than none because it is mistaken for
coverage.

---

## W5 — Tenancy

**The role change is the feature; the policies are the detail.**

Measured before writing migration 006: the application connected as `skopos`,
which is `rolsuper`, `rolbypassrls`, and the **owner of every table**. Row-level
security does not apply to such a role — not weakly, at all. Policies added
under that configuration would have produced a schema that reviews as
multi-tenant and enforces nothing.

So `skopos_app` — present since migration 001, `NOLOGIN`, never once used —
became the runtime identity. Proven live on the same 576 findings:

| Connected as | Org | Sees |
|---|---|---|
| `skopos_app` | `default` | 576 |
| `skopos_app` | `acme` | **0** |
| `skopos_app` | *(GUC unset)* | **0** |
| `skopos` (superuser) | `acme` | **576** — the measurement that made the role change necessary |

Three details that carry weight: the `org_id` column default is
`current_setting('skopos.org_id', true)`, so writes land in the caller's tenant
without editing a single INSERT; uniqueness became per-tenant, or one tenant
scoping `example.com` silently prevents every other; and `epss_history` keeps a
**global** key and no policy, because an EPSS score is a public fact about a CVE.

**The claim is bounded everywhere it appears.** This defends against a *bug* — a
forgotten filter, a new query, a bad join. It is **not** isolation against a
compromised application, because anything able to run SQL on that connection can
also change the session variable. The SRS's "Postgres roles per org" was
deliberately not done: a role per tenant means DDL at signup and an application
permanently holding `CREATE ROLE`, a larger standing privilege than the risk it
removes.

---

## What P5 got wrong and corrected

Recorded because the corrections are part of the phase.

- **Two claims in the docs were false.** `CLAUDE.md` and `ARCHITECTURE.md` both
  said `egress.py` was the ONLY module performing I/O. It never was —
  `collect/ct.py` and `core/alerting.py` also do, each under its own
  `# NETWORK-BOUNDARY:` marker, which is the rule the test actually enforces.

- **Migration 006 broke every scan.** It changed four unique constraints and
  every `ON CONFLICT` target in the stores still named the old columns; the first
  scan after migrating died with `InvalidColumnReference`.

- **A test broke the running application.** The tenancy fixture called
  `ensure_app_role` against a throwaway *database*, but a PostgreSQL role is
  **cluster-wide** — it rewrote the real `skopos_app` password for every database
  on the server, and the app began failing authentication the moment the suite
  passed. `ensure_app_role` now takes a role name.

- **A commit was pushed with two failing tests**, and its message claimed three
  clean runs. The command chained `git push` after `pytest` without gating on the
  exit code. The failures were a real 6%-per-login bug, not flakes.

- **Tenancy was declared complete when it was not.** Enforcement was perfect at
  the database and *nothing resolved an org per request* —
  `tenancy.using()` existed and nothing called it. That was corrected in the
  README rather than left standing, and closed in P7 when a session began
  carrying the org.
