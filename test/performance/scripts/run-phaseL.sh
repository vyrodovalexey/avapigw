#!/bin/bash
# run-phaseL.sh - Phase L perf matrix driver: 8 scenario groups, 180s steady-state
# each, against the compose-network perf gateway (avapigw-pt) with metrics
# verification in VictoriaMetrics after every group.
#
# Endpoints (perf gateway container avapigw-pt, published to host):
#   HTTP  :18080  (8080 in-container; host 8080 held by paused vmauth)
#   HTTPS :8443
#   gRPC  :9000   gRPC-TLS :9443
#   metrics :9090 (scraped by VM job avapigw-gateway)
#
# Tools: hey (HTTP/HTTPS/GraphQL/MCP), ghz (gRPC), k6 (WS/WSS).
set -u
cd "$(dirname "$0")/../../.." || exit 1
ROOT="$(pwd)"
PROTO="$ROOT/test/performance/proto/test_service.proto"
VM="http://127.0.0.1:8428"
VMSNAP="$ROOT/test/performance/scripts/phaseL-vmsnap.py"
WSJS="$ROOT/test/performance/configs/websocket/ws-feature-persistent.js"

HTTP="http://127.0.0.1:18080"
HTTPS="https://127.0.0.1:8443"
WS="ws://127.0.0.1:18080"
WSS="wss://127.0.0.1:8443"
GRPC="127.0.0.1:9000"
GRPCS="127.0.0.1:9443"

DUR="${PERF_DURATION:-180}"       # seconds
GDUR="${DUR}s"
CONN="${PERF_CONN:-40}"
QPS="${PERF_QPS:-15}"             # per-connection => ~600 rps target per hscn
GCONC="${PERF_GCONC:-50}"
GCONN="${PERF_GCONN:-10}"
APIKEY='pk_perftest_1234567890abcdef'

OUT="$1"; SCEN="$2"
mkdir -p "$OUT"

tok() { curl -s -X POST "http://localhost:8090/realms/gateway-test/protocol/openid-connect/token" \
  -d 'grant_type=password' -d 'client_id=gateway' -d 'client_secret=gateway-secret' \
  -d 'username=testuser' -d 'password=testpass' | jq -r '.access_token'; }

snap() { python3 "$VMSNAP" "$VM" "$OUT/vm_$1.json" >/dev/null 2>&1 || true; }

PAR=1
maybe_bg() { if [ "$PAR" = "1" ]; then "$@" & else "$@"; fi; }

# hey HTTP scenario: name path base [extra hey args...]
hscn() {
  local name="$1" path="$2" base="$3"; shift 3
  local out="$OUT/${name}.txt"
  hey -z "$GDUR" -c "$CONN" -q "$QPS" -t 25 -H 'Accept: application/json' "$@" "$base$path" > "$out" 2>&1
  echo "  [$name] $(grep 'Requests/sec' "$out" | awk '{print "rps="$2}') $(grep -A20 'Status code distribution' "$out" | grep -E '\[[0-9]+\]' | tr '\n' ' ')"
}
# hey POST scenario (graphql/mcp): name path base body [extra...]
pscn() {
  local name="$1" path="$2" base="$3" body="$4"; shift 4
  local out="$OUT/${name}.txt"
  hey -z "$GDUR" -c "$CONN" -q "$QPS" -t 25 -m POST -H 'Content-Type: application/json' -d "$body" "$@" "$base$path" > "$out" 2>&1
  echo "  [$name] $(grep 'Requests/sec' "$out" | awk '{print "rps="$2}') $(grep -A20 'Status code distribution' "$out" | grep -E '\[[0-9]+\]' | tr '\n' ' ')"
}
# ghz gRPC scenario: name tlsflag target call data meta [conc]
gscn() {
  local name="$1" tls="$2" target="$3" call="$4" data="$5" meta="$6"; local c="${7:-$GCONC}"
  local cn="$GCONN"; [ "$c" -lt "$cn" ] && cn="$c"
  ghz "$tls" --proto "$PROTO" --call "$call" -m "$meta" -d "$data" -z "$GDUR" -c "$c" --connections "$cn" \
    -O json -o "$OUT/${name}.json" "$target" 2>"$OUT/${name}.err" || true
  jq -r '"  ['"$name"'] rps=\(.rps|floor) count=\(.count) p50=\(.latencyDistribution[]?|select(.percentage==50)|.latency/1e6)ms p95=\(.latencyDistribution[]?|select(.percentage==95)|.latency/1e6)ms p99=\(.latencyDistribution[]?|select(.percentage==99)|.latency/1e6)ms status=\(.statusCodeDistribution)"' "$OUT/${name}.json" 2>/dev/null || echo "  [$name] ghz failed (see ${name}.err)"
}
# k6 WS scenario: name url [header]
wscn() {
  local name="$1" url="$2" hdr="${3:-}"
  WS_URL="$url" WS_HEADER="$hdr" WS_VUS="${WS_VUS:-12}" WS_OUT="$OUT/${name}" \
    k6 run --quiet "$WSJS" > "$OUT/${name}.log" 2>&1 || true
  jq -c '{sessions,msgs_per_sec_recv,messages_received,connection_errors,success_rate,msg_latency_ms}' "$OUT/${name}.json" 2>/dev/null | sed "s/^/  [$name] /" || echo "  [$name] k6 result missing"
}

echo "=================================================================="
echo " SCENARIO $SCEN  dur=${DUR}s  out=$OUT"
echo "=================================================================="
snap "${SCEN}_before"
START=$(date +%s)

TOK="$(tok)"

case "$SCEN" in
  s1-grpc)
    gscn unary        --insecure "$GRPC" api.v1.TestService/Unary               '{"message":"perf"}'          '{"x-perf-baseline":"true"}' &
    gscn serverstream --insecure "$GRPC" api.v1.TestService/ServerStream        '{"count":5,"interval_ms":10}' '{"x-perf-baseline":"true"}' &
    gscn bidistream   --insecure "$GRPC" api.v1.TestService/BidirectionalStream '{"value":3,"operation":"double"}' '{"x-perf-baseline":"true"}' &
    gscn mtls_unary   --insecure "$GRPC" api.v1.TestService/Unary               '{"message":"perf"}'          '{"x-test-scenario":"mtls"}' &
    gscn oidc_unary   --insecure "$GRPC" api.v1.TestService/Unary               '{"message":"perf"}'          "{\"x-test-scenario\":\"oidc\",\"authorization\":\"Bearer $TOK\"}" &
    wait ;;
  s2-grpc-tls)
    gscn tls_unary        --skipTLS "$GRPCS" api.v1.TestService/Unary        '{"message":"perf"}'           '{"x-perf-baseline":"true"}' &
    gscn tls_serverstream --skipTLS "$GRPCS" api.v1.TestService/ServerStream '{"count":10,"interval_ms":10}' '{"x-perf-baseline":"true"}' &
    gscn tls_mtls_stream  --skipTLS "$GRPCS" api.v1.TestService/ServerStream '{"count":5,"interval_ms":10}'  '{"x-test-scenario":"mtls-stream"}' &
    gscn tls_oidc_unary   --skipTLS "$GRPCS" api.v1.TestService/Unary        '{"message":"perf"}'           "{\"x-test-scenario\":\"oidc\",\"authorization\":\"Bearer $TOK\"}" &
    wait ;;
  s3-http|s4-https)
    if [ "$SCEN" = "s3-http" ]; then B="$HTTP"; WB="$WS"; else B="$HTTPS"; WB="$WSS"; fi
    maybe_bg hscn basic     /api/v1/validated/items          "$B"
    maybe_bg hscn apikey    /api/v1/validated/apikey/items   "$B" -H "X-API-Key: $APIKEY"
    maybe_bg hscn oidc      /api/v1/validated/oidc/items     "$B" -H "Authorization: Bearer $TOK"
    maybe_bg hscn ratelimit /api/v1/validated/ratelimit/items "$B"
    maybe_bg hscn transform /api/v1/validated/transform/items "$B"
    maybe_bg hscn encoding  /api/v1/validated/encoding/items "$B" -H 'Accept-Encoding: gzip'
    maybe_bg hscn cache     /api/v1/validated/cache/items    "$B"
    maybe_bg hscn cors      /api/v1/validated/cors/items     "$B" -H 'Origin: http://example.com'
    maybe_bg wscn ws-plain  "$WB/ws"
    maybe_bg wscn ws-apikey "$WB/ws-perf-apikey" "X-API-Key: $APIKEY"
    maybe_bg wscn ws-oidc   "$WB/ws-perf-oidc"   "Authorization: Bearer $TOK"
    wait ;;
  s5-graphql|s6-graphql-tls)
    if [ "$SCEN" = "s5-graphql" ]; then B="$HTTP"; WB="$WS"; else B="$HTTPS"; WB="$WSS"; fi
    Q='{"query":"query { items { id name price } }"}'
    maybe_bg pscn gql-base      /graphql "$B" "$Q"
    maybe_bg pscn gql-oidc      /graphql "$B" "$Q" -H "Authorization: Bearer $TOK"
    maybe_bg pscn gql-apikey    /graphql "$B" "$Q" -H "X-API-Key: $APIKEY"
    maybe_bg pscn gql-ratelimit /graphql "$B" "$Q" -H "X-Perf-Scenario: ratelimit"
    maybe_bg pscn gql-transform /graphql "$B" "$Q" -H "X-Perf-Scenario: transform"
    maybe_bg pscn gql-cors      /graphql "$B" "$Q" -H "Origin: http://example.com"
    maybe_bg wscn ws-plain  "$WB/ws"
    maybe_bg wscn ws-oidc   "$WB/ws-perf-oidc" "Authorization: Bearer $TOK"
    wait ;;
  s7-mcp|s8-mcp-tls)
    if [ "$SCEN" = "s7-mcp" ]; then B="$HTTP"; else B="$HTTPS"; fi
    MB='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"m1.echo","arguments":{"message":"perf"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
    # OIDC + sentinel rate-limit MCP tools/call (upstream 502 expected: mock _meta limitation)
    pscn mcp-toolscall /mcp "$B" "$MB" \
      -H "Authorization: Bearer $TOK" \
      -H 'Mcp-Method: tools/call' -H 'Mcp-Name: m1.echo' -H 'MCP-Protocol-Version: 2026-07-28'
    ;;
  *) echo "unknown scenario $SCEN"; exit 1 ;;
esac

END=$(date +%s)
echo "elapsed_seconds=$((END-START))" | tee "$OUT/${SCEN}_elapsed.txt"
snap "${SCEN}_after"
echo "  metrics snapshot saved: $OUT/vm_${SCEN}_after.json"
