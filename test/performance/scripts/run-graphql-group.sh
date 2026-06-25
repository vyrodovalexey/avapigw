#!/bin/bash
# run-graphql-group.sh - run GraphQL feature scenarios (groups 5 & 6) 180s each via hey (POST /graphql),
# plus a WS/WSS scenario via k6. Emits per-scenario .txt/.json + summary.json.
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
QFILE="/tmp/gql-query.json"
echo '{"query":"{ items { id name price } }"}' > "$QFILE"

gscn() {
  local name="$1"; shift
  local out="$OUTDIR/${name}.txt"
  echo ">>> [$GROUP/$name] hey POST /graphql ${DUR}s c=$CONN q=$QPS"
  hey -z "${DUR}s" -c "$CONN" -q "$QPS" -t 20 -m POST \
    -H 'Content-Type: application/json' -D "$QFILE" "$@" "$BASE/graphql" > "$out" 2>&1
  local rps; rps=$(grep 'Requests/sec' "$out" | awk '{print $2}')
  echo "    rps=$rps $(grep -E '^\s+\[[0-9]+\]' "$out" | tr -d '\n')"
}

wscn() {
  local name="$1" url="$2" hdr="${3:-}"
  echo ">>> [$GROUP/$name] k6 WS $url (180s)"
  WS_URL="$url" WS_HEADER="$hdr" WS_VUS=20 WS_OUT="$OUTDIR/${name}" \
    k6 run --quiet "$WSJS" > "$OUTDIR/${name}.log" 2>&1 || true
  jq -c '{sessions,msgs_per_sec_recv,messages_received,connection_errors,success_rate}' "$OUTDIR/${name}.json" 2>/dev/null || echo "    (k6 result missing)"
}

refresh_tok() { # $1=host
  curl -s -X POST "http://$1:8090/realms/gateway-test/protocol/openid-connect/token" \
    -d 'grant_type=password' -d 'client_id=gateway' -d 'client_secret=gateway-secret' \
    -d 'username=testuser' -d 'password=testpass' | jq -r '.access_token'
}

PARALLEL="${PERF_PARALLEL:-0}"
maybe_bg() { if [ "$PARALLEL" = "1" ]; then "$@" & else "$@"; fi; }

TOK_LH="$(refresh_tok localhost)"
maybe_bg gscn basic
maybe_bg gscn apikey    -H "X-API-Key: $APIKEY"
maybe_bg gscn oidc      -H "Authorization: Bearer $TOK_LH"
maybe_bg gscn ratelimit
maybe_bg gscn transform
maybe_bg gscn cors      -H 'Origin: http://example.com'
maybe_bg wscn ws        "$WSBASE/ws"
# group6 = tls graphql + mirroring: drive the GraphQL AGGREGATE fan-out route
# (do04-graphql-route has aggregate enabled). The /graphql query path is the
# aggregate route; gscn already POSTs to /graphql so the aggregate scenario is
# the same path. Add an explicit aggregate-labeled run for clarity/metrics.
if [ "$GROUP" = "group6" ]; then
  maybe_bg gscn aggregate
fi
[ "$PARALLEL" = "1" ] && wait

# summary (reuse hey parser)
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
for f in sorted(glob.glob(os.path.join(od, "ws*.json"))):
    name = os.path.splitext(os.path.basename(f))[0]
    try: out[name] = json.load(open(f))
    except Exception: pass
json.dump(out, open(os.path.join(od, "summary.json"), "w"), indent=2)
print("wrote", os.path.join(od, "summary.json"))
PY
