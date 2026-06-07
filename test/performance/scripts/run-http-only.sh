#!/bin/bash
# run-http-only.sh - run ONLY the 8 hey HTTP feature scenarios for a group (180s each).
# Used to re-run group3/group4 HTTP scenarios without re-doing WS. Usage: run-http-only.sh <outdir>
set -u
cd "$(dirname "$0")/../../.." || exit 1
BASE="${HTTP_BASE:-https://127.0.0.1:30988}"
DUR="${PERF_DURATION:-180}"
CONN="${PERF_CONN:-50}"
QPS="${PERF_QPS:-10}"
OUTDIR="$1"
mkdir -p "$OUTDIR"
APIKEY='pk_perftest_1234567890abcdef'
rt() { curl -s -X POST "http://$1:8090/realms/gateway-test/protocol/openid-connect/token" \
  -d 'grant_type=password' -d 'client_id=gateway' -d 'client_secret=gateway-secret' \
  -d 'username=testuser' -d 'password=testpass' | jq -r '.access_token'; }
hscn() {
  local name="$1" path="$2"; shift 2
  local out="$OUTDIR/${name}.txt"
  echo ">>> [$name] $path ${DUR}s c=$CONN q=$QPS"
  hey -z "${DUR}s" -c "$CONN" -q "$QPS" -t 20 -H 'Accept: application/json' "$@" "$BASE$path" > "$out" 2>&1
  echo "    rps=$(grep 'Requests/sec' "$out" | awk '{print $2}') $(grep -E '^\s+\[[0-9]+\]' "$out" | tr -d '\n')"
}
date
hscn basic     /api/v1/validated/items
hscn apikey    /api/v1/validated/apikey/items -H "X-API-Key: $APIKEY"
TOK="$(rt localhost)"; hscn oidc /api/v1/validated/oidc/items -H "Authorization: Bearer $TOK"
hscn ratelimit /api/v1/validated/ratelimit/items
hscn transform /api/v1/validated/transform/items
hscn encoding  /api/v1/validated/encoding/items -H 'Accept-Encoding: gzip'
hscn cache     /api/v1/validated/cache/items
hscn cors      /api/v1/validated/cors/items -H 'Origin: http://example.com'
date
