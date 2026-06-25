#!/bin/bash
# run-http-group.sh - run HTTP/HTTPS feature scenarios (groups 3 & 4) 180s each via hey,
# plus WS/WSS scenarios via k6. Emits per-scenario .txt/.json + summary.json.
set -u
cd "$(dirname "$0")/../../.." || exit 1
ROOT="$(pwd)"
BASE="${HTTP_BASE:-https://127.0.0.1:30988}"
WSBASE="${WS_BASE:-wss://127.0.0.1:30988}"
DUR="${PERF_DURATION:-180}"
CONN="${PERF_CONN:-50}"
QPS="${PERF_QPS:-10}"
OUTDIR="$1"; GROUP="$2"
mkdir -p "$OUTDIR"
APIKEY='pk_perftest_1234567890abcdef'
TOK_LH="$(cat /tmp/tok_lh.txt 2>/dev/null)"
TOK_IP="$(cat /tmp/tok_ip.txt 2>/dev/null)"
WSJS="$ROOT/test/performance/configs/websocket/ws-feature-180s.js"

# PERF_PARALLEL=1 runs all scenarios concurrently so the GROUP wall-clock is a
# single ~DUR (3 min) steady-state window with the full feature stack under load.
PARALLEL="${PERF_PARALLEL:-0}"

# hey scenario: $1=name $2=path [extra hey args...]
hscn() {
  local name="$1" path="$2"; shift 2
  local out="$OUTDIR/${name}.txt"
  echo ">>> [$GROUP/$name] hey $path ${DUR}s c=$CONN q=$QPS"
  hey -z "${DUR}s" -c "$CONN" -q "$QPS" -t 20 -H 'Accept: application/json' "$@" "$BASE$path" > "$out" 2>&1
  local rps p50 p95 p99
  rps=$(grep 'Requests/sec' "$out" | awk '{print $2}')
  echo "    rps=$rps $(grep -E '^\s+\[[0-9]+\]' "$out" | tr -d '\n')"
}
# parallel dispatch helper
maybe_bg() { if [ "$PARALLEL" = "1" ]; then "$@" & else "$@"; fi; }

# ws scenario via k6: $1=name $2=wsurl [WS_HEADER]
wscn() {
  local name="$1" url="$2" hdr="${3:-}"
  echo ">>> [$GROUP/$name] k6 WS $url (180s)"
  WS_URL="$url" WS_HEADER="$hdr" WS_VUS=20 WS_OUT="$OUTDIR/${name}" \
    k6 run --quiet "$WSJS" > "$OUTDIR/${name}.log" 2>&1 || true
  jq -c '{sessions,msgs_per_sec_recv,messages_received,connection_errors,success_rate,connect_ms,msg_latency_ms}' "$OUTDIR/${name}.json" 2>/dev/null || echo "    (k6 result missing)"
}

# Refresh OIDC token from a given issuer host right before an OIDC scenario
# (Keycloak access tokens live 300s; a single 180s scenario fits within a fresh token).
refresh_tok() { # $1=host
  curl -s -X POST "http://$1:8090/realms/gateway-test/protocol/openid-connect/token" \
    -d 'grant_type=password' -d 'client_id=gateway' -d 'client_secret=gateway-secret' \
    -d 'username=testuser' -d 'password=testpass' | jq -r '.access_token'
}

if [ "$GROUP" = "group3" ] || [ "$GROUP" = "group4" ]; then
  TOK_LH="$(refresh_tok localhost)"
  TOK_IP="$(refresh_tok 127.0.0.1)"
  maybe_bg hscn basic     /api/v1/validated/items
  maybe_bg hscn apikey    /api/v1/validated/apikey/items -H "X-API-Key: $APIKEY"
  maybe_bg hscn oidc      /api/v1/validated/oidc/items   -H "Authorization: Bearer $TOK_LH"
  maybe_bg hscn ratelimit /api/v1/validated/ratelimit/items
  maybe_bg hscn transform /api/v1/validated/transform/items
  maybe_bg hscn encoding  /api/v1/validated/encoding/items -H 'Accept-Encoding: gzip'
  maybe_bg hscn cache     /api/v1/validated/cache/items
  maybe_bg hscn cors      /api/v1/validated/cors/items -H 'Origin: http://example.com'
  # WS scenarios (use 127.0.0.1 issuer token for ws-oidc route)
  maybe_bg wscn ws-plain  "$WSBASE/ws"
  maybe_bg wscn ws-apikey "$WSBASE/ws-perf-apikey" "X-API-Key: $APIKEY"
  maybe_bg wscn ws-oidc   "$WSBASE/ws-perf-oidc"   "Authorization: Bearer $TOK_IP"
  # group4 = https + mirroring: also drive the REST AGGREGATE fan-out route so
  # gateway_aggregate_* metrics increment for this scenario group.
  if [ "$GROUP" = "group4" ]; then
    maybe_bg hscn aggregate /api/v1/items
    # NEW NDJSON-strategy aggregate route (strategy=ndjson + timeField/keyField/
    # limit). Drives the new NDJSON line-merge code path under load so the
    # gateway_aggregate_merge_duration_seconds histogram and aggregate counters
    # increment for the NDJSON merger specifically. Backends emit
    # application/x-ndjson; gateway returns application/stream+json.
    maybe_bg hscn ndjson_aggregate /aggregate-ndjson
  fi
  [ "$PARALLEL" = "1" ] && wait
fi

# summary
python3 - "$OUTDIR" <<'PY'
import json, os, sys, glob, re
od = sys.argv[1]
out = {}
def parse_hey(p):
    t = open(p).read()
    def num(rx):
        m = re.search(rx, t); return float(m.group(1)) if m else None
    rps = num(r'Requests/sec:\s+([\d.]+)')
    p50 = num(r'\n\s+50%+\s+in\s+([\d.]+)\s+secs')
    p95 = num(r'\n\s+95%+\s+in\s+([\d.]+)\s+secs')
    p99 = num(r'\n\s+99%+\s+in\s+([\d.]+)\s+secs')
    avg = num(r'Average:\s+([\d.]+)\s+secs')
    codes = {}
    for m in re.finditer(r'\[(\d{3})\]\s+(\d+)\s+responses', t):
        codes[m.group(1)] = int(m.group(2))
    return {"rps": round(rps) if rps else None,
            "avg_ms": round(avg*1000,2) if avg else None,
            "p50_ms": round(p50*1000,2) if p50 else None,
            "p95_ms": round(p95*1000,2) if p95 else None,
            "p99_ms": round(p99*1000,2) if p99 else None,
            "codes": codes}
for f in sorted(glob.glob(os.path.join(od, "*.txt"))):
    name = os.path.splitext(os.path.basename(f))[0]
    out[name] = parse_hey(f)
for f in sorted(glob.glob(os.path.join(od, "ws-*.json"))):
    name = os.path.splitext(os.path.basename(f))[0]
    try: out[name] = json.load(open(f))
    except Exception: pass
json.dump(out, open(os.path.join(od, "summary.json"), "w"), indent=2)
print("wrote", os.path.join(od, "summary.json"))
PY
