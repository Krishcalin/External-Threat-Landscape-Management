<p align="center">
  <img src="docs/skopos-logo.png" alt="SKOPOS — External Threat Landscape Management" width="620">
</p>

<p align="center">
  <strong>An open-source External Threat Landscape Management platform.</strong><br>
  It continuously connects what your organisation exposes to the internet with
  what adversaries are actively exploiting, and drives accountable remediation.
</p>

<p align="center">
  Python · FastAPI · TypeScript · PostgreSQL · MIT
</p>

> A vulnerability scanner produces findings about a system. A threat feed
> produces statements about the world. Neither is a statement about *you*.
> SKOPOS produces **exposures** — a pairing of something you run with something
> adversaries are known to be exploiting — and scores that pairing by how much it
> should actually worry you.
>
> The join is the product. Everything else exists to make the join honest.

---

## Contents

**Start here**
1. [What it will not tell you](#1-what-it-will-not-tell-you) — read before the feature list
2. [Quick start](#2-quick-start) — Docker, then six commands
3. [The operator journey](#3-the-operator-journey)
4. [Command reference](#4-command-reference)

**How it works**

5. [Safety model](#5-safety-model)
6. [Discovery and fingerprinting](#6-discovery-and-fingerprinting)
7. [Scoring](#7-scoring)
8. [OverWatch integration](#8-overwatch-integration)
9. [Data sources](#9-data-sources)

**Going deeper**

10. [Project status](#10-project-status)
11. [Documentation map](#11-documentation-map)
12. [Contributing](#12-contributing)
13. [Licence and responsible use](#13-licence-and-responsible-use)

> **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — the full architecture: the
> authorisation gate, the egress boundary, the pipeline, the storage model, the
> module map, and the twenty-two invariants a change must not break. Read this
> before modifying anything.

---

## 1. What it will not tell you

This matters more than the feature list, so it comes first.

**A product match is a worklist entry, not a verdict.** The CISA KEV catalogue
carries 1,674 exploited vulnerabilities and **not one structured affected-version
range**. So when SKOPOS says your Confluence server corresponds to
CVE-2021-26084, it means "this asset runs a product with an exploited
vulnerability" and never "this asset is vulnerable". Somebody has to check the
version. Every run says so, in those words.

The industry norm is to present that list with the confidence of a
determination. That list is mostly wrong, everyone who has worked one knows it is
mostly wrong, and the effect is that the true entries get discounted along with
the false ones.

**A banner is not a fact.** A `Server:` header is a claim by the party whose patch
state is the entire question, and one line of configuration removes it. SKOPOS
records *how* it learned something — `self_reported`, `inferred`, or `operator` —
and structurally refuses to let an observed version reach the field a published
affected range is evaluated against.

**A dangling subdomain is never reported as "vulnerable".** The only experiment
that would establish it is registering the resource, which this product refuses
to perform. The ceiling is permanent, and the reason given is capability, not
caution.

**An exposure is not an incident, so nothing here starts a regulatory clock.**
CERT-In Direction No. 20(3)/2022 requires reporting within six hours of becoming
aware of an incident. Seven of its eight reportable categories describe something
an adversary *did*, and this product looks at your estate from outside — so it
cannot observe them, and says which ones and why. There is no function that opens
a six-hour countdown from a finding, because a tool that did would push its users
toward over-reporting to a national CERT. The clock takes a declaration by a
named person; the notification draft leaves impact, root cause and remediation
marked `[TO BE COMPLETED BY REPORTER]` rather than guessing them.

**It does not decide what is Critical Information Infrastructure.** Under s.70 of
the IT Act, 2000, the appropriate Government declares a computer resource a
protected system by notification in the Official Gazette. That is a legal status,
not something inferable from a hostname. The CII register records what *your
organisation* declared, with the basis attached, and refuses a gazette claim that
carries no notification reference. Assets with no designation are raised as a
question, never as a finding.

**No coverage percentage, against any framework.** The control mapping says what
each control it touches is *contributed to*, what it explicitly does **not** do,
and which evidence it draws on. A percentage would be summed and shown to a
board, and the board would be receiving a number no external scanner has the
basis to produce.

**Nothing leaves the building because a scan ran.** A scan describes your
estate to yourself; delivering alerts describes it to a webhook endpoint or a
mail server, and consent to the first is not consent to the second. Delivery is
off unless `SKOPOS_ALERT_ON_SCAN` is set, it is never a request parameter — if
the caller could ask for it, anyone who could reach the API could choose the
moment your estate is described to a third party — and a run reports which of
four states it was in, including "switched on with no channel configured", which
from the outside looks exactly like a quiet run.

**A thin result is not a clean estate.** Every run reports what it could *not*
see: sources that failed, sources left out by their terms, names the gate
refused, records the resolvers disagreed about. "0 findings" and "0 findings and
380 assets we could not join" are different sentences, and only the second is
actionable.

[↑ Contents](#contents)

---

## 2. Quick start

You need Docker. Nothing else.

```bash
cp .env.example .env          # set POSTGRES_PASSWORD to anything random
docker compose up -d          # skopos-db-1 (postgres:16) + skopos-app-1
```

Console and API come up on <http://127.0.0.1:8100>; OpenAPI at `/api/docs`.

For the CLI:

```bash
export SKOPOS_DATABASE_URL=postgresql://skopos:<password>@127.0.0.1:55443/skopos
```

[↑ Contents](#contents)

---

## 3. The operator journey

**Nothing runs until something is in scope.** That is deliberate — an unscoped
tool is an unbounded reconnaissance tool.

```bash
# 1. Declare what you are responsible for.
python main.py scope add example.com --kind wildcard --actor you@example.com
python main.py scope add vpn.example.com --kind domain --exclude \
       --note "managed by a third party" --actor you@example.com

# 2. Find names. Passive: touches nothing you own.
python main.py discover example.com --actor you@example.com -o discovered.csv

# 3. Resolve them, track change, assess dangling records.
python main.py dns-sweep discovered.csv --actor you@example.com
python main.py takeover

# 4. Prove you own something before touching it.
python main.py verify api.example.com --method dns_txt --actor you@example.com

# 5. Identify what it runs. ACTIVE — verified assets only.
python main.py fingerprint discovered.csv --actor you@example.com -o assets.csv

# 6. Join it to what is being exploited.
python main.py scan assets.csv
```

Every command that touches anything takes `--dry-run` or `--plan` first, and
those genuinely contact nothing.

`--actor` is required everywhere and has no default. It is **asserted, not
authenticated** — the audit chain records who *claimed* to do something.

[↑ Contents](#contents)

---

## 4. Command reference

| Command | Does | Needs DB |
|---|---|:---:|
| `scope add \| list \| check` | what SKOPOS may look at. Nothing runs until set. | yes |
| `verify` | record proof of ownership (DNS TXT, well-known file, attestation) | yes |
| `discover` | passive name discovery across CT, passive DNS, indexes, archives | yes |
| `dns-sweep` | resolve across three resolvers; track change; assess takeover | yes |
| `dns-runs` | what past sweeps saw, and what they could not | yes |
| `takeover` | dangling records and how far the evidence went | yes |
| `fingerprint` | identify what each host runs (**active**, verified assets only) | yes |
| `scan` | join an inventory to the exploited catalogue and score it | no |
| `intel` | what the vendored catalogue is, and how old | no |

The database is required wherever the gate must consult scope and ownership
records. There is deliberately no file-based fallback and no `--assume-verified`:
a YAML the operator wrote thirty seconds earlier would make the ownership check a
formality rather than a control.

[↑ Contents](#contents)

---

## 5. Safety model

SKOPOS can touch things on the internet. **One module decides whether it may**,
and collectors do not get a vote.

Collectors check nothing. They cannot run without a `Permit`, and a `Permit` can
only come out of `core.gate.authorise()` — every field that decides what it
authorises is HMAC-sealed, so it can be neither constructed nor mutated into
something broader. That turns "every collector remembers to check" into "the
unsafe path does not exist", which matters because the product is meant to take
third-party collector plugins.

| Class | Needs | Examples |
|---|---|---|
| **Passive** | scope only | CT logs, passive DNS, RDAP, web archive |
| **Active** | scope **+ current ownership + address check** | HTTP probe, TLS handshake, port sweep |
| **Prohibited** | nothing lifts these | exploit attempt, credential replay, forum authentication |

Prohibited operations are refused *before* scope and ownership are consulted, so
the refusal cannot be argued around by editing scope.

Four more rules worth knowing up front:

- **Ownership verification expires after 180 days.** Domains change hands and
  subdomains get delegated; a verification proves control when it was checked and
  says nothing about today.
- **Exclude wins unconditionally** — not most-specific, not last-wins. Every
  specificity scheme eventually lets a narrow include beat a broad exclude, and
  then the tool probes the thing it was told not to.
- **Addresses are checked, not just names.** Proving you own a name does not
  establish that you own what it points at.
- **Every state change lands in a hash-chained audit log** the application role
  can only append to — `UPDATE` and `DELETE` are refused by the database itself,
  not by this code's good manners.

→ [Full details in ARCHITECTURE.md §2–3](docs/ARCHITECTURE.md#2-the-gate--the-one-authorisation-decision)

[↑ Contents](#contents)

---

## 6. Discovery and fingerprinting

Discovery reads four classes of source — certificate transparency, passive DNS,
published name indexes, and a web archive — and each class is kept distinct
because their dates mean different things. A CT `not_before` is "a certificate
was issued". A crawl timestamp is "a page was fetched once". Only a passive-DNS
sighting means "a resolver saw this resolve", so only that populates `last_seen`.

**Fingerprinting is the step that makes everything else pay off.** Certificate
transparency finds *names*, not technologies, so discovery writes
`product=unknown` — which matches **0** of the catalogue's 1,674 entries. Not by
luck: `unknown` is a stopword and tokenises to nothing.

Measured over a four-host sample running Ivanti Connect Secure, Apache HTTP
Server, Exchange Server and Confluence:

| | exposures |
|---|---:|
| `product=unknown` (discovery output) | 0 |
| after fingerprinting | 43 |

The exact figure depends on your estate and the catalogue version; the zero does
not.

→ [Why the join works this way, in ARCHITECTURE.md §5](docs/ARCHITECTURE.md#5-the-join-and-the-two-tiers-of-claim)

[↑ Contents](#contents)

---

## 7. Scoring

TEPS — Threat-weighted Exposure Preemption Score — combines exposure,
exploitability, adversary interest and business criticality. It is implemented to
the specification exactly and golden-tested against the published worked example,
which reproduces at 78 with every intermediate factor matching.

Rankings are an **ordered tuple**, not a single float: ransomware-linked first,
then CISA due date, then EPSS, then match confidence. A single blended number
invites a threshold, the threshold gets tuned until the list looks reasonable,
and the tuning quietly becomes the product's real opinion where nobody can see
it.

[↑ Contents](#contents)

---

## 8. OverWatch integration

SKOPOS ingests cloud context from OverWatch, the sibling CNAPP, and reconciles
outside-in observation against inside-out cloud modelling:

| Outcome | Means |
|---|---|
| **confirmed** | both agree it is reachable |
| **unexplained exposure** | we reached it; your cloud model says it is closed |
| **discovery blind spot** | your cloud model says exposed; we could not reach it |
| **agreed not exposed** | both agree |
| **inconclusive** | one side has no verdict — never dressed up as agreement |

The middle two are why the integration exists.

[↑ Contents](#contents)

---

## 9. Data sources

CISA KEV and FIRST EPSS are **vendored into the repository**, not fetched at scan
time. A scan records which catalogue version answered it, and that is only
reproducible if the corpus is in the repo. `tools/refresh_intel.py` regenerates
them and refuses to write a partial catalogue.

Discovery sources are individually registered with their terms and a review date:

| Source | Class | Terms | Default |
|---|---|---|---|
| certspotter, crt.sh | CT | open | on |
| mnemonic | passive DNS | open | on |
| anubis | name index | open | on |
| wayback | web archive | open | off |
| AlienVault OTX | passive DNS | credentialed | off |
| HackerTarget | name index | noncommercial | off |

Sources whose terms read as excluding commercial use are **off by default** —
SKOPOS may be run commercially and will not make that call for you. A
credentialed source with no credential reports `UNCONFIGURED`, never `OK` with
zero results.

[↑ Contents](#contents)

---

## 10. Project status

**P0 through P7 complete.** 1,081 tests (1,018 offline, 63 against a live PostgreSQL).

**Shipping:** passive discovery across four data classes, DNS records with
run-over-run change tracking, dangling-record assessment, gated active
fingerprinting, the exposure join, TEPS scoring, OverWatch reconciliation,
run-over-run finding diff, CNA affected-range determinations, SSVC decisions,
the Crosshair convergence view, the forecast record and its backtesting
scoreboard, the India compliance pack, and the governance layer underneath all
of it.

**What each phase measured before it built.** P2 found that only **47.5%** of KEV
carries version data comparable enough to turn a worklist entry into a
determination, and says so on every run. P3 tried the ATT&CK triad, found a
technique implicates a **median of 57 threat groups**, and shipped SSVC instead;
it also found only **one of four** latency reference classes has enough resolved
samples to forecast from, so the other three refuse. P4 found that **seven of
eight** CERT-In reportable categories are not observable from outside an estate.

**The console** has thirteen sections — Worklist, Operations, Executive,
Crosshair, Graph, Lookup, Brand, Suppliers, Alerts, Compliance, Accuracy, This
instance, and Account. It is behind a login with TOTP two-factor. Operations,
Executive and Worklist are the SRS's three projections of one graph, adjacent so
it is obvious they are the same data asked three different questions.

**Accounts are administered from the console, and the limits are stated rather
than overclaimed.** An administrator cannot disable themselves or the last
remaining administrator, because there is no recovery path from an instance with
none. They cannot *choose* a password — every issued credential is generated, so
the house pattern that makes every account on an instance guessable never forms.
And `is_admin` appears nowhere in the authorisation path for scanning: creating
accounts confers no authority over any estate, which stays gated on verified
ownership for everybody.

What an administrator **can** do is create an account, reset a forgotten
password, disable an account, and clear a second-factor enrolment. The first two
issue a one-time password shown exactly once, and until it is changed the account
reaches nothing but the change form. **Resetting a password and a second factor
together is a takeover** — that is true of every system where one person can do
both, it is not preventable while they can, and SKOPOS says so on the screen
instead of implying otherwise. Every account action is written to the
hash-chained audit log; no issued password ever is.

**Three of the four paid feeds were replaced, and the fourth was kept because it
costs $42 a year.** Measured rather than assumed, on 2026-08-22/23:

- **Shodan → InternetDB.** Shodan's own keyless endpoint returns the same two
  fields SKOPOS extracted from the paid API — `ports` and `vulns` — plus
  versioned `cpes`, which are *better* input than free-text banners because a
  CPE is already the catalogue's identifier format. It loses banner data (no
  product tied to a port) and refreshes **weekly**, both stated on every answer.
  It is **free for non-commercial use only**, so it stays inert until the
  operator sets `SKOPOS_INTERNETDB_ACK` — SKOPOS will not decide an operator's
  commerciality for them. Where a paid key exists it is used first.
- **VirusTotal → seven vendored abuse feeds.** No open-source equivalent of a
  70-engine aggregate exists. What does exist is bulk lists: 61,660 entries,
  1.7 MB, queried in-process with no network call. The pattern is D1's, applied
  again — the free thing is the file, the keyed thing is the question.
- **Nothing → Shadowserver.** Free daily reports on netblocks you have *proven*
  you own, which is machinery `core/ownership.py` already has. The one exception
  to the licence wall: free commercially too.
- **HIBP kept.** `/breachedaccount` is the only endpoint that requires payment,
  no legitimate substitute exists, and $3.50/month is not where a budget goes.

**Two feeds the sources still recommend are dead or dying**, found by fetching
them rather than by reading a list. abuse.ch's **SSL Blacklist was deprecated on
2025-01-03** and still answers HTTP 200 with a header saying so — a naive
fetcher vendors an empty list and every lookup against it reads as clean; it is
recorded in `core/blocklists.REJECTED` rather than silently omitted. **Feodo
Tracker** serves five entries whose own header says last updated 2026-03-04, so
the corpus carries the publisher's date beside the fetch date: a fetch date is
not a data date.

**Third parties are assessed passively, and cannot be assessed any other way.**
A supplier's estate belongs to somebody else, the customer cannot prove
ownership of it, and the gate refuses every active operation against an
unverified asset. No active probe means no fingerprint, no fingerprint means no
product name, and no product name means **SKOPOS never reports a supplier
vulnerability** — the panel says so where a competitor would put a count. What
it reports instead is published configuration, and which providers the register
shares. Measured before the screen was built: SPF 8/8 and DMARC 8/8 across real
domains, so presence separates nobody; enforcement, CAA and MTA-STS lead.

**Next:** P6 W3 (ITSM connector; TIP is provisionally already served by TAXII)
and W4 (Helm, performance). Then the last mile of tenancy, if the deployment
model calls for it — see below.

**Tenancy serves one organisation per deployment today.** The enforcement is
built and proven; the last mile is not. Every request resolves to
`SKOPOS_ORG_ID`, there is no per-request tenant resolution, and an organisation
can only be created by hand in the database. What that buys is a hard floor
under a single-tenant install — not multi-tenant SaaS.

**What the enforcement is honestly worth.** Rows carry an `org_id` and
PostgreSQL row-level security filters every query against a session variable
the application sets per connection. The load-bearing part is not the policies:
the application now connects as an **unprivileged role that owns nothing and
cannot bypass RLS**. Before that change it connected as a superuser, and RLS
does not apply to such a role at all — the schema would have reviewed as
multi-tenant and enforced nothing. This prevents cross-tenant leakage *through a
bug*: a forgotten filter, a new query, a bad join. It is **not** isolation
against a compromised application, because anything that can run SQL on that
connection can also change the session variable. `GET /api/v1/tenancy` reports
which identity is actually serving, so you can tell the two apart.

**Sharing findings over TAXII 2.1.** Set `SKOPOS_API_TOKEN` and the server
registers at `/taxii2/` — discovery, collections, objects, and a manifest, with
`added_after` polling that works because `date_added` is the scan run's
timestamp rather than the moment of the request. The collection is read-only:
accepting objects would mean ingesting third-party claims into a product whose
whole discipline is that every statement carries who made it. Without the token
the routes are **not registered at all**, because a 401 that can be probed is
still an admission the data exists.

**Optional, off by default.** A `scheduler` profile runs the two jobs whose
missed days cannot be refilled — an EPSS snapshot and forecast resolution:

```bash
docker compose --profile scheduler up -d
```

It is opt-in because it makes outbound requests every day without further
prompting, and a stack that started doing that on `docker compose up` would be
making an egress decision for you. Leaving it off has a cost too: EPSS never
republishes a past day, so each day it does not run is a hole no later effort
fills.

**Not shipping, deliberately:** closed-forum collection, active takeover
corroboration, version determinations from banners, multi-tenancy, and any
prediction claim the backtesting harness cannot support.

→ [Reasoning for each, in ARCHITECTURE.md §11](docs/ARCHITECTURE.md#11-what-is-deliberately-absent)

[↑ Contents](#contents)

---

## 11. Documentation map

| Document | What it is for |
|---|---|
| **README.md** (this file) | what the product is, and how to run it |
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | how it is built: the gate, the egress boundary, the pipeline, storage, the module map, and the invariants |
| **CLAUDE.md** | the decision log, with the reasoning and the measurements behind each |
| **docs/P1-BUILD-SPEC.md** | the adversarial design pass over P1, and the 86 problems it raised |
| **[docs/P2-SCOPE.md](docs/P2-SCOPE.md)** | P2: prioritisation that survives the NVD gap. Written in advance |
| **[docs/P3-SCOPE.md](docs/P3-SCOPE.md)** | P3: decisions, and the two workstreams the measurements closed. **Retrospective** |
| **[docs/P4-SCOPE.md](docs/P4-SCOPE.md)** | P4: the India compliance pack, and the things it will not say. **Retrospective** |
| **[docs/P5-SCOPE.md](docs/P5-SCOPE.md)** | P5: the orphan audit, TAXII, tenancy — and what it got wrong. **Retrospective** |
| **[docs/P6-SCOPE.md](docs/P6-SCOPE.md)** | P6: third-party posture and the projections. Written in advance |
| **[docs/P7-SCOPE.md](docs/P7-SCOPE.md)** | P7: auth, ad-hoc lookup, brand imitation, the graph. Written in advance |

Phase documents marked **Retrospective** were written after the phase was built.
P2, P6 and P7 were written before, and carry a "what would make this plan wrong"
section for that reason — a retrospective presented as foresight would be
exactly the kind of quiet overclaim these documents exist to record.

[↑ Contents](#contents)

---

## 12. Contributing

Read [ARCHITECTURE.md §9](docs/ARCHITECTURE.md#9-invariants-a-change-must-not-break)
first — twenty-two invariants, each with a test that fails if it is violated.

```bash
pip install -r requirements.txt
python -m pytest tests/ -q                       # 384 pass, 30 skip loudly

docker compose up -d db                          # for the other 30
export SKOPOS_TEST_ADMIN_DSN=postgresql://skopos:<pw>@127.0.0.1:55443/skopos
python -m pytest tests/ -q                       # 414 pass
```

Database tests build a **throwaway database** and drop it. The audit log is
append-only by design, so a test that wrote into the real one would leave a row
nothing could ever remove.

Adding a collector is seven steps and they are written down:
[ARCHITECTURE.md §10](docs/ARCHITECTURE.md#10-adding-a-collector).

[↑ Contents](#contents)

---

## 13. Licence and responsible use

MIT.

**Use it on estates you are responsible for.** The ownership gate exists to help
you stay on the right side of that line, not to be worked around. SKOPOS will not
authenticate to criminal forums, will not attempt exploitation, and will not
claim a subdomain to prove it could — those are refusals in code, not policy.

[↑ Contents](#contents)
