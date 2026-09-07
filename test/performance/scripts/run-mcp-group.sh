#!/bin/bash
# run-mcp-group.sh - run MCP feature scenarios (groups 7 & 8) 180s each via hey
# (POST /mcp JSON-RPC), exercising the gateway MCP hub with OIDC auth + a
# Redis-Sentinel-backed rate limit. Emits per-scenario .txt + summary.json.
#
# Added for the a-h PT scenario matrix (task: g. MCP, h. TLS MCP). Mirrors the
# structure of run-graphql-group.sh / run-http-group.sh so run-pt-local.sh /
# run-pt-suite.sh can drive PT-07 (plaintext MCP :8080/mcp) and PT-08 (TLS MCP
# :8443/mcp) with a single 180s steady-state window.
#
# The gateway MCP dispatcher (internal/gateway/mcp_handler.go) enforces:
#   * params._meta carries the VENDORED keys
#       io.modelcontextprotocol/protocolVersion (a HUB-supported revision)
#       io.modelcontextprotocol/clientCapabilities
#   * MCP-Protocol-Version request header == _meta protocolVersion
#   * Mcp-Method request header == the JSON-RPC method (Mcp-Name also required
#     for tools/call / resources/read / prompts/get)
# so the ammo below is a spec-correct tools/list request. OIDC is enforced at
# the route (pt-mcp-oidc-ratelimit) => unauthenticated probes legitimately 401
# and, above requestsPerSecond, the sentinel limiter legitimately 429s.
set -u
cd "$(dirname "$0")/../../.." || exit 1
ROOT="$(pwd)"
BASE="${HTTP_BASE:-http://127.0.0.1:8080}"
DUR="${PERF_DURATION:-180}"
CONN="${PERF_CONN:-40}"
QPS="${PERF_QPS:-15}"
OUTDIR="$1"; GROUP="$2"
mkdir -p "$OUTDIR"

# HUB-supported protocol revision (internal/mcp/protocol/protocol.go LatestVersion).
MCP_VER="${MCP_VER:-2026-07-28}"
# Spec-correct tools/list body with the vendored _meta keys.
BODY="/tmp/mcp-toolslist.json"
cat > "$BODY" <<JSON
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"$MCP_VER","io.modelcontextprotocol/clientCapabilities":{}}}}
JSON

# Spec-correct tools/call body with a BARE (non-namespaced) tool name. A bare
# name bypasses the namespaced-owner pin and drives the route's
# WeightedUpstreams selection (gateway/mcp_select.go pickWeightedUpstream), so
# the weighted-selection counter avapigw_mcp_upstream_selected_total{route,
# upstream} increments across BOTH mcp-backend-1/2 (70/30 in gateway-pt-docker
# .yaml). The selection is attributed BEFORE the upstream call, so the split is
# measured even though the Phase-1 mock 502s on the vendored _meta handshake.
CALLBODY="/tmp/mcp-toolscall.json"
cat > "$CALLBODY" <<JSON
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"$MCP_VER","io.modelcontextprotocol/clientCapabilities":{}}}}
JSON

refresh_tok() { # $1=host
  curl -s -X POST "http://$1:8090/realms/gateway-test/protocol/openid-connect/token" \
    -d 'grant_type=password' -d 'client_id=gateway' -d 'client_secret=gateway-secret' \
    -d 'username=testuser' -d 'password=testpass' | jq -r '.access_token'
}
# Config JWT issuer is http://localhost:8090/... so the token MUST be minted via
# the localhost vhost (Keycloak stamps iss from the request Host); a 127.0.0.1
# token is rejected as "token issuer is invalid".
TOK="$(refresh_tok localhost)"

PARALLEL="${PERF_PARALLEL:-0}"
maybe_bg() { if [ "$PARALLEL" = "1" ]; then "$@" & else "$@"; fi; }

# mcp scenario: $1=name [extra hey args...]
mscn() {
  local name="$1"; shift
  local out="$OUTDIR/${name}.txt"
  echo ">>> [$GROUP/$name] hey POST /mcp ${DUR}s c=$CONN q=$QPS"
  hey -z "${DUR}s" -c "$CONN" -q "$QPS" -t 20 -m POST \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H "MCP-Protocol-Version: $MCP_VER" \
    -H 'Mcp-Method: tools/list' \
    -D "$BODY" "$@" "$BASE/mcp" > "$out" 2>&1
  local rps; rps=$(grep 'Requests/sec' "$out" | awk '{print $2}')
  echo "    rps=$rps $(grep -E '^\s+\[[0-9]+\]' "$out" | tr -d '\n')"
}

# weighted mcp scenario: bare-name tools/call to drive WeightedUpstreams
# selection. $1=name [extra hey args...]
wscn() {
  local name="$1"; shift
  local out="$OUTDIR/${name}.txt"
  echo ">>> [$GROUP/$name] hey POST /mcp tools/call(bare) ${DUR}s c=$CONN q=$QPS"
  hey -z "${DUR}s" -c "$CONN" -q "$QPS" -t 20 -m POST \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H "MCP-Protocol-Version: $MCP_VER" \
    -H 'Mcp-Method: tools/call' \
    -H 'Mcp-Name: echo' \
    -D "$CALLBODY" "$@" "$BASE/mcp" > "$out" 2>&1
  local rps; rps=$(grep 'Requests/sec' "$out" | awk '{print $2}')
  echo "    rps=$rps $(grep -E '^\s+\[[0-9]+\]' "$out" | tr -d '\n')"
}

# g / h : OIDC auth (Bearer) + sentinel rate limit are BOTH on the route.
#   oidc      : authenticated steady-state (expect 200s, some 429 at burst)
#   ratelimit : authenticated but pushed above the 100 rps route budget so the
#               Redis-Sentinel limiter denies the excess (expect 200 + 429 mix)
#   weighted  : authenticated bare-name tools/call => weighted upstream selection
#               across BOTH mocks (avapigw_mcp_upstream_selected_total split).
#               Upstream 502s are the EXPECTED Phase-1 mock _meta limitation;
#               selection is counted BEFORE the upstream call.
#   noauth    : NO bearer => OIDC rejects (expect 401) — proves auth is enforced
maybe_bg mscn oidc      -H "Authorization: Bearer $TOK"
maybe_bg mscn ratelimit -H "Authorization: Bearer $TOK" -c 80 -q 40
maybe_bg wscn weighted  -H "Authorization: Bearer $TOK"
maybe_bg mscn noauth
[ "$PARALLEL" = "1" ] && wait

# summary (reuse the hey parser used by the http/graphql groups)
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
json.dump(out, open(os.path.join(od, "summary.json"), "w"), indent=2)
print("wrote", os.path.join(od, "summary.json"))
PY
