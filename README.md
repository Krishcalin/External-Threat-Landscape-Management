# SKOPOS

**An open-source External Threat Landscape Management platform.** It continuously
connects what your organisation exposes to the internet with what adversaries are
actively exploiting, and drives accountable remediation.

Python · FastAPI · TypeScript · PostgreSQL · MIT

---

## The idea in one paragraph

A vulnerability scanner produces findings about a system. A threat feed produces
statements about the world. Neither is a statement about *you*. SKOPOS produces
**exposures** — a pairing of something you run with something adversaries are
known to be exploiting — and then scores that pairing by how much it should
actually worry you.

The join is the product. Everything else exists to make the join honest.

---

## What it will not tell you

This matters more than the feature list, so it comes first.

**A product match is a worklist entry, not a verdict.** The CISA KEV catalogue
carries 1,674 exploited vulnerabilities and **not one structured affected-version
range**. So when SKOPOS says your Confluence server corresponds to
CVE-2021-26084, it means "this asset runs a product with an exploited
vulnerability" and never "this asset is vulnerable". Somebody has to check the
version. Every run says so, in those words.

The industry norm is to present that list with the confidence of a
determination. That list is mostly wrong, everyone who has worked one knows it
is mostly wrong, and the effect is that the true entries get discounted along
with the false ones.

**A banner is not a fact.** A `Server:` header is a claim by the party whose
patch state is the entire question, and one line of configuration removes it.
SKOPOS records *how* it learned something — `self_reported`, `inferred`, or
`operator` — and structurally refuses to let an observed version reach the field
a published affected range is evaluated against.

**A dangling subdomain is never reported as "vulnerable".** The only experiment
that would establish it is registering the resource, which this product refuses
to perform. The ceiling is permanent, and the reason given is capability, not
caution.

**A thin result is not a clean estate.** Every run reports what it could *not*
see: sources that failed, sources left out by their terms, names the gate
refused, records the resolvers disagreed about. "0 findings" and "0 findings and
380 assets we could not join" are different sentences, and only the second is
actionable.

---

## Safety model

SKOPOS can touch things on the internet. One module decides whether it may.

Collectors do not check permissions. **They cannot run without a `Permit`, and a
`Permit` can only come out of `core.gate.authorise()`** — every field that
decides what it authorises is HMAC-sealed, so it can be neither constructed nor
mutated into something broader. That turns "every collector remembers to check"
into "the unsafe path does not exist", which matters because the product is meant
to take third-party collector plugins.

Three classes of operation:

| | |
|---|---|
| **Passive** | reads third-party or already-public sources — CT logs, passive DNS, RDAP. Needs scope, not ownership. |
| **Active** | connects to your asset — HTTP probe, TLS handshake, port sweep. Needs a **current** ownership verification, and the addresses are checked too. |
| **Prohibited** | refused *before* scope and ownership are consulted, so the refusal cannot be argued around by editing scope. |

Ownership verification expires after 180 days, because domains change hands and
subdomains get delegated — a verification proves control when it was checked and
says nothing about today.

Scope resolves with **exclude winning unconditionally**: not most-specific, not
last-wins. Every specificity scheme eventually lets a narrow include beat a broad
exclude, and then the tool probes the thing it was told not to.

Every state change lands in a **hash-chained audit log** the application role can
only append to — `UPDATE` and `DELETE` are refused by the database itself, not by
this code's good manners.

---

## Quick start

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

### The operator journey

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

### Why step 5 is the one that matters

Certificate transparency finds *names*, not technologies. Discovery therefore
writes `product=unknown`, which matches **0** of the catalogue's 1,674 entries —
not by luck, but because `unknown` is a stopword and cannot join anything.

Measured over a four-host sample running Ivanti Connect Secure, Apache HTTP
Server, Exchange Server and Confluence:

| | exposures |
|---|---:|
| `product=unknown` (discovery output) | 0 |
| after fingerprinting | 43 |

The exact figure depends on what your estate runs and on the catalogue version;
the zero does not. Fingerprinting is what connects discovery to scoring.

---

## Commands

| | |
|---|---|
| `scope add \| list \| check` | what SKOPOS may look at. Nothing runs until set. |
| `verify` | record proof of ownership (DNS TXT, well-known file, or attestation) |
| `discover` | passive name discovery across CT, passive DNS, indexes, archives |
| `dns-sweep` | resolve across three resolvers; track change; assess takeover |
| `dns-runs` / `takeover` | what past sweeps saw, and what they could not |
| `fingerprint` | identify what each host runs (**active**, verified assets only) |
| `scan` | join an inventory to the exploited catalogue and score it |
| `intel` | what the vendored catalogue is, and how old |

`scan` and `intel` run fully offline. `discover`, `fingerprint` and `dns-sweep`
require the database, because they need the scope and ownership records the gate
consults — there is deliberately no file-based fallback and no
`--assume-verified`.

---

## Scoring

TEPS — Threat-weighted Exposure Preemption Score — combines exposure,
exploitability, adversary interest and business criticality. It is implemented to
the specification exactly and golden-tested against the published worked example,
which reproduces at 78 with every intermediate factor matching.

Rankings are an **ordered tuple**, not a single float: ransomware-linked first,
then CISA due date, then EPSS, then match confidence. A single blended number
invites a threshold, the threshold gets tuned until the list looks reasonable,
and the tuning quietly becomes the product's real opinion where nobody can see
it.

---

## OverWatch integration

SKOPOS ingests cloud context from OverWatch, the sibling CNAPP, and reconciles
outside-in observation against inside-out cloud modelling:

| | |
|---|---|
| **confirmed** | both agree it is reachable |
| **unexplained exposure** | we reached it; your cloud model says it is closed |
| **discovery blind spot** | your cloud model says exposed; we could not reach it |
| **agreed not exposed** | both agree |
| **inconclusive** | one side has no verdict — never dressed up as agreement |

The middle two are why the integration exists.

---

## Status

**P0 and P1 complete.** 414 tests (384 offline, 30 against a live PostgreSQL).

Shipping: passive discovery across four data classes, DNS records with
run-over-run change tracking, dangling-record assessment, gated active
fingerprinting, the exposure join, TEPS scoring, OverWatch reconciliation,
run-over-run finding diff, and the governance layer underneath all of it.

Not shipping, deliberately — `CLAUDE.md` carries the reasoning on each: closed
forum collection, active takeover corroboration, version determinations from
banners, multi-tenancy, and any prediction claim the backtesting harness cannot
support.

---

## Data sources

CISA KEV and FIRST EPSS are **vendored into the repository**, not fetched at scan
time. A scan records which catalogue version answered it, and that is only
reproducible if the corpus is in the repo. `tools/refresh_intel.py` regenerates
them and refuses to write a partial catalogue.

Discovery sources are individually registered with their terms and a review date.
Sources whose terms read as excluding commercial use are **off by default** —
SKOPOS may be run commercially and will not make that call for you.

---

## Licence

MIT.

**Use it on estates you are responsible for.** The ownership gate exists to help
you stay on the right side of that line, not to be worked around.
