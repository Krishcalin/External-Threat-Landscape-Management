#!/usr/bin/env bash
#
# One command: wipe, start, create + ENABLE the ingester, push, check.
#
# WHY THIS EXISTS RATHER THAN THE MANUAL STEPS IN THE README
# ------------------------------------------------------------
# The manual path has two traps that each cost an afternoon — a new TAXII Push
# ingester is created STOPPED and answers 404 to every POST while the discovery
# endpoint lists it as writable, and the media type the collection advertises
# is one the platform rejects. This does it right by construction.
#
# It also wipes first, ON PURPOSE. Verifying against an instance that already
# holds objects from an earlier push proves less than it appears to: a
# relationship can resolve against a pre-existing entity rather than the one in
# its own bundle, which is exactly how a dangling-reference bug survives.
#
#   bash deploy/opencti-verify/clean-run.sh
#
# ~4 GB of RAM and roughly four minutes. Tear down when finished:
#   docker compose -f deploy/opencti-verify/docker-compose.yml down -v
set -u
cd "$(dirname "$0")/../.." || exit 1

CF="deploy/opencti-verify/docker-compose.yml"
TOK="1b8f0c2e-4a6d-4b9e-9c3a-7d5e2f8a1b40"     # throwaway; see docker-compose.yml
gq() { curl -s --max-time 30 -X POST http://127.0.0.1:8081/graphql \
        -H "Content-Type: application/json" -H "Authorization: Bearer $TOK" -d "$1"; }

echo "== wiping any previous instance =="
docker compose -f "$CF" down -v >/dev/null 2>&1

echo "== starting =="
docker compose -f "$CF" up -d >/dev/null 2>&1 || { echo "compose up failed"; exit 1; }

# NOT /health — it requires a token and answers 401 forever, which reads as
# "never ready". The SPA at the root is served once the platform genuinely is.
echo "== waiting for the platform =="
code=""
for i in $(seq 1 100); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8081/ 2>/dev/null)
  [ "$code" = "200" ] && { echo "   ready after ~$((i*6))s"; break; }
  sleep 6
done
[ "$code" = "200" ] || { echo "never became ready (last HTTP $code)"; exit 1; }

# GraphQL answers before the admin user is finished provisioning on a fresh volume.
user=""
for i in $(seq 1 20); do
  user=$(gq '{"query":"query { me { id } }"}' \
    | python -c "import json,sys;print((json.load(sys.stdin).get('data') or {}).get('me',{}).get('id',''))" 2>/dev/null)
  [ -n "$user" ] && break
  sleep 5
done
[ -n "$user" ] || { echo "admin user never appeared"; exit 1; }

echo "== creating the TAXII Push ingester =="
collection=$(gq "{\"query\":\"mutation(\$i: IngestionTaxiiCollectionAddInput!) { ingestionTaxiiCollectionAdd(input: \$i) { id } }\",\"variables\":{\"i\":{\"name\":\"SKOPOS\",\"description\":\"verification\",\"user_id\":\"$user\",\"authorized_members\":[]}}}" \
  | python -c "import json,sys;d=json.load(sys.stdin);print(((d.get('data') or {}).get('ingestionTaxiiCollectionAdd') or {}).get('id',''))" 2>/dev/null)
[ -n "$collection" ] || { echo "could not create the ingester"; exit 1; }
echo "   collection: $collection"

# THE TRAP. A new ingester is not running, and every POST to it 404s with
# "Collection not found" while discovery lists it with can_write: true.
echo "== enabling it =="
gq "{\"query\":\"mutation { ingestionTaxiiCollectionFieldPatch(id: \\\"$collection\\\", input: [{key: \\\"ingestion_running\\\", value: [\\\"true\\\"]}]) { ingestion_running } }\"}" >/dev/null

echo
python deploy/opencti-verify/verify.py "$collection"
