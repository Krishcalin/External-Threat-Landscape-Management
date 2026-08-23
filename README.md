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
> module map, and the thirteen invariants a change must not break. Read this
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

**P0 and P1 complete.** 414 tests (384 offline, 30 against a live PostgreSQL).

**Shipping:** passive discovery across four data classes, DNS records with
run-over-run change tracking, dangling-record assessment, gated active
fingerprinting, the exposure join, TEPS scoring, OverWatch reconciliation,
run-over-run finding diff, and the governance layer underneath all of it.

**Next:** CNA affected ranges — the only thing that turns a worklist into a
verdict — then the forecast record that makes accuracy measurable.

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
| **CLAUDE.md** | decisions D1–D19 with the reasoning and the measurements behind each |
| **docs/P1-BUILD-SPEC.md** | the adversarial design pass over P1, and the 86 problems it raised |

[↑ Contents](#contents)

---

## 12. Contributing

Read [ARCHITECTURE.md §9](docs/ARCHITECTURE.md#9-invariants-a-change-must-not-break)
first — thirteen invariants, each with a test that fails if it is violated.

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
