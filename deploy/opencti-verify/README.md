# Verifying the SKOPOS → OpenCTI connector

Four integrations were built against Filigran's documentation and **none has
touched a real OpenCTI**. The wire format is proven only against a stub written
from the same documentation, which proves this codebase's reading of the docs
rather than OpenCTI's actual behaviour. This directory closes that.

**This is a throwaway.** Do not use it for anything real: trivial credentials,
one worker, no persistence guarantees, and heaps roughly an eighth of Filigran's
documented minimum.

---

## What the sizing is actually up against

Filigran documents ~7 cores / ~18 GB before a single connector, and practitioners
report needing 32–64 GB for modest production. This host has **15.7 GB total with
a 7.6 GiB WSL ceiling**, so the reference compose cannot start — quite apart from
it now bundling XTM One and PostgreSQL 17.

The heaps here are cut to fit a verification instance holding a few hundred
objects:

| Component | Filigran's documented minimum | Here |
|---|---|---|
| Elasticsearch heap | 8 GB | **1 GB** |
| Platform (Node) heap | 8 GB | **1.5 GB** |
| Workers | 3 | **1** |
| Total footprint | ~18 GB | **~4 GB** |

That is enough to answer the only question being asked and nothing more. Start a
live connector against it and it will fall over.

---

## Five traps worth knowing before you start

**`APP__ENCRYPTION_KEY` is mandatory since v7 and is not in the quickstart.**
Without it the platform crash-loops on `app:encryption_key configuration is
missing or invalid` during admin initialisation — every dependency reports
healthy while the platform restarts every twelve seconds, which reads like a
dependency problem and is not one. Generate with `openssl rand -base64 32`.

This was the first thing a real instance taught us that reading the
documentation had not: the compose in this directory was written from Filigran's
own docs and still would not start.

**Do not use an `-lts` tag.** An LTS build validates only `lts` or `ci` licence
types at application root and **refuses to start without a paid licence** — it
comes up as a login wall, not an error you can read. `7.260817.0` is current
stable and starts free.

**Do not let Elasticsearch float to 9.** OpenCTI does not support it (issue
#10729, flagged breaking) and a `:8` tag will eventually resolve there. The
compose pins `8.19.16`.

If Elasticsearch exits immediately, the usual cause is `vm.max_map_count`:

```bash
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

**A 404 on push means the ingester is STOPPED, not missing.** OpenCTI's POST
handler is `if (!ingestion || ingestion.ingestion_running !== true) throw
TaxiiError("Collection not found", 404)`. A newly created TAXII Push ingester
is not running, and the discovery endpoint at
`/taxii2/root/collections/` lists it anyway with `can_write: true` — so the
collection demonstrably exists while every POST to it 404s. Toggle it on in
**Data → Ingestion → TAXII Push**, or:

```bash
curl -s -X POST http://127.0.0.1:8081/graphql -H 'Content-Type: application/json'   -H 'Authorization: Bearer 1b8f0c2e-4a6d-4b9e-9c3a-7d5e2f8a1b40'   -d '{"query":"mutation { ingestionTaxiiCollectionFieldPatch(id: \"<ID>\", input: [{key: \"ingestion_running\", value: [\"true\"]}]) { ingestion_running } }"}'
```

**The media type the collection advertises is the one it rejects.** Its own
discovery document lists `media_types: ["application/stix+json;version=2.1"]`.
Post that and you get a 400, `UNSUPPORTED_ERROR`. The validator accepts only
`application/taxii+json` or `application/vnd.oasis.stix+json`, each carrying
`version=2.1`.

---

## Running it

```bash
docker compose -f deploy/opencti-verify/docker-compose.yml up -d
```

First start pulls ~2 GB and takes several minutes; the platform's own migration
runs before it answers. Watch for readiness rather than guessing:

```bash
docker compose -f deploy/opencti-verify/docker-compose.yml ps
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/health
```

Console at <http://127.0.0.1:8081> — `admin@skopos.local` /
`verify-only-not-a-real-password`.

---

## The short way

```bash
bash deploy/opencti-verify/clean-run.sh
```

Wipes, starts, creates **and enables** the ingester, pushes, and checks — about
four minutes. It wipes first on purpose: verifying against an instance that
already holds objects proves less than it looks like, because a relationship
can resolve against a pre-existing entity instead of the one in its own bundle.
That is precisely how the dangling-reference bug below survived every test.

The rest of this page is the manual path, and what each step is guarding
against.

---

## Creating the TAXII Push ingester

This is the whole of the OpenCTI-side setup. **No connector code runs inside
OpenCTI.**

1. **Data → Ingestion → TAXII Push → `+`**
2. Name it `SKOPOS`, and scope it to a user. The confidence level of that
   user's account is what SKOPOS's findings will carry — connectors and feeds
   write at their service account's confidence, and that is what decides who can
   overwrite whom during ingestion.
3. Copy the **collection id** it gives you.

Then point SKOPOS at it:

```bash
# in .env
SKOPOS_OPENCTI_ON_SCAN=true
SKOPOS_OPENCTI_URL=http://127.0.0.1:8081
SKOPOS_OPENCTI_TOKEN=1b8f0c2e-4a6d-4b9e-9c3a-7d5e2f8a1b40
SKOPOS_OPENCTI_COLLECTION=<the collection id>
```

> **`http://` will be refused.** `collect/opencti.py` requires https, because a
> bundle describing where an estate is weak does not travel in clear. For a
> loopback verification run, pass the URL directly to `push()` in the harness
> below rather than weakening the guard — the guard is correct and should stay.

---

## What the live run actually settled

`python deploy/opencti-verify/verify.py <collection-id>` — **12 checks, all
green** against OpenCTI 7.260817.0.

| Claim built from docs | Verdict on a real instance |
|---|---|
| Observables merge rather than duplicate | **Holds.** Two pushes, still one `verify-api.skopos.test` |
| SSVC labels arrive | **Holds.** All three decision points |
| `consists-of` renders | **Holds.** 6 edges |
| `belongs-to` (ownership) survives | **Holds.** 2 edges |
| Worklist stays confidence 40, determinations 90 | **Holds — once a real bug was fixed.** See below |
| `resolves-to` is dropped (issue #6928) | **Does NOT reproduce.** Both edges survived. The issue is either fixed in 7.x or specific to file import rather than TAXII push |
| `x_` custom properties survive | **They do not.** Every `x_` is stripped, on relationships as well as SDOs — OpenCTI's own `x_opencti_*` included |

### The `x_` answer, and why it does not hurt

`x_skopos_teps` is transmitted and discarded on every push. That was the
accepted risk in `collect/opencti.py` and it landed on the bad side.

It costs nothing because the score was never load-bearing — the basis reaches a
consumer three more ways, all standard STIX: `confidence`, `relationship_type`,
and `description` (verified as carrying the "NOT an assertion" caveat intact).
**It is also the retrospective justification for R3 putting SSVC in labels
rather than a property.** Labels survived; properties did not. That decision
was necessary rather than merely cautious, and this is the measurement that
says so.

### Two bugs the stub could never have caught

The stub validated STIX **shape**. Both of these produce perfectly well-shaped
STIX, which is exactly why they survived every test until a real platform
tried to resolve the graph.

**1. Every asset→CVE edge pointed at an infrastructure that did not exist.**
`relationship()` built `source_ref` as `_id("infrastructure", asset)` while
`infrastructure()` had gained an org component and built
`_id("infrastructure", org, asset)`. Different arity — they could never agree,
at any org value including the default. OpenCTI rejected both edges per bundle
with `MISSING_REFERENCE_ERROR`, meaning **the single most important statement
in the export — this asset has this vulnerability — had never once landed.**
Fixed by deriving the id from `infrastructure()` rather than recomputing it.

**2. `bundle()` never emitted `resolves-to`.** `exposure_bundle()` did, from
the same data, with a comment explaining that the join is one a consumer cannot
make for itself. The finding-export path simply never got it. The harness was
one run away from recording "OpenCTI dropped it" about an edge SKOPOS had
never sent — a false conclusion about somebody else's software.

`tests/test_stix_coverage.py` now checks referential integrity across the whole
bundle at three org values, which is the property that was missing.

---

## Teardown

```bash
docker compose -f deploy/opencti-verify/docker-compose.yml down -v
```

It is ~4 GB of RAM on a machine that does not have much spare. Take it down when
the verification is finished.
