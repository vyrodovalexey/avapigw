#!/bin/bash
# run-pt-local.sh - Drive the 6 PT scenario groups (PT-01..06), ~180s steady-state
# each, against the LOCAL PT gateway (container avapigw-pt on the compose network,
# ports published on the host: HTTP 8080 / HTTPS 8443 / gRPC 9000 / gRPC-TLS 9443,
# metrics 9090 scraped by compose VictoriaMetrics as job avapigw-gateway).
#
# Group -> listener mapping (required scenario matrix):
#   PT-01 grpc & streaming (mTLS+OIDC)          -> plaintext gRPC :9000 (GRPC_INSECURE=1)
#   PT-02 TLS grpc & streaming (mTLS+OIDC)      -> gRPC-TLS :9443
#   PT-03 http & ws feature stack               -> HTTP :8080
#   PT-04 https & wss feature stack (same as 3) -> HTTPS :8443 (runner group3)
#   PT-05 graphql & ws feature stack            -> HTTP :8080
#   PT-06 TLS graphql & wss (same as 5)         -> HTTPS :8443 (runner group5)
#
# Reuses the existing group runners:
#   PT-01/PT-02 -> run-grpc-group.sh    (ghz)
#   PT-03/PT-04 -> run-http-group.sh    (hey + k6)
#   PT-05/PT-06 -> run-graphql-group.sh (hey + k6)
#
# Env overrides honored: PERF_DURATION, PERF_CONN/CONC, PERF_QPS, PT_GROUPS, VM_URL
set -u
cd "$(dirname "$0")/../../.." || exit 1
ROOT="$(pwd)"
SCRIPTS="$ROOT/test/performance/scripts"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="${PT_OUT:-$ROOT/.yandextank/pt-local_$TS}"
VM="${VM_URL:-http://127.0.0.1:8428}"
GW_CONTAINER="${GW_CONTAINER:-avapigw-pt}"

export PERF_DURATION="${PERF_DURATION:-180}"   # 3 minutes steady-state
export PERF_CONN="${PERF_CONN:-40}"
export PERF_CONC="${PERF_CONC:-40}"
export PERF_QPS="${PERF_QPS:-15}"
export PERF_PARALLEL="${PERF_PARALLEL:-1}"     # scenarios concurrent => one 3-min window
GRPC_DUR="${PERF_DURATION}s"

mkdir -p "$OUT"
echo "PT local suite output: $OUT"
echo "duration=${PERF_DURATION}s conn=$PERF_CONN conc=$PERF_CONC qps=$PERF_QPS parallel=$PERF_PARALLEL"

# refresh OIDC tokens for the group scripts (Keycloak access tokens live 300s;
# each group runner refreshes again right before its OIDC scenario)
curl -s -X POST "http://localhost:8090/realms/gateway-test/protocol/openid-connect/token" \
  -d 'grant_type=password' -d 'client_id=gateway' -d 'client_secret=gateway-secret' \
  -d 'username=testuser' -d 'password=testpass' | jq -r '.access_token' > /tmp/tok_lh.txt
curl -s -X POST "http://127.0.0.1:8090/realms/gateway-test/protocol/openid-connect/token" \
  -d 'grant_type=password' -d 'client_id=gateway' -d 'client_secret=gateway-secret' \
  -d 'username=testuser' -d 'password=testpass' | jq -r '.access_token' > /tmp/tok_ip.txt

# Snapshot a curated set of gateway metrics from VictoriaMetrics into a JSON file.
# Metric names verified against the live /metrics of THIS build (see report).
snap() { # $1=label
  local f="$OUT/vm_$1.json"
  python3 - "$VM" "$f" <<'PY'
import sys, json, urllib.request, urllib.parse
vm, out = sys.argv[1], sys.argv[2]
queries = {
  # core HTTP
  "requests_total": "sum(gateway_requests_total)",
  "route_requests_total": "sum(gateway_route_requests_total)",
  "request_duration_p50": "histogram_quantile(0.50, sum(rate(gateway_request_duration_seconds_bucket[1m])) by (le))",
  "request_duration_p95": "histogram_quantile(0.95, sum(rate(gateway_request_duration_seconds_bucket[1m])) by (le))",
  "request_duration_p99": "histogram_quantile(0.99, sum(rate(gateway_request_duration_seconds_bucket[1m])) by (le))",
  "backend_requests_total": "sum(gateway_backend_requests_total)",
  # auth families
  "route_auth_successes": "sum(gateway_route_auth_successes_total)",
  "route_auth_failures": "sum(gateway_route_auth_failures_total)",
  "auth_requests": "sum(gateway_auth_requests_total)",
  "jwt_validation_total": "sum(gateway_jwt_validation_total)",
  "apikey_validation_total": "sum(gateway_apikey_validation_total)",
  "backend_auth_successes": "sum(gateway_backend_auth_successes_total)",
  "backend_auth_token_refresh": "sum(gateway_backend_auth_token_refresh_total)",
  # redis sentinel rate limiting (distributed limiter)
  "redis_rl_allowed": "sum(gateway_middleware_redis_rate_limit_allowed_total)",
  "redis_rl_denied": "sum(gateway_middleware_redis_rate_limit_denied_total)",
  "route_ratelimit_hits": "sum(gateway_route_ratelimit_hits_total)",
  # redis sentinel cache
  "cache_hits": "sum(gateway_cache_hits_total)",
  "cache_misses": "sum(gateway_cache_misses_total)",
  "route_cache_hits": "sum(gateway_route_cache_hits_total)",
  "route_cache_misses": "sum(gateway_route_cache_misses_total)",
  # grpc
  "grpc_stream_count": "sum(gateway_grpc_stream_duration_seconds_count)",
  "grpc_stream_active": "sum(gateway_grpc_stream_active)",
  "grpc_msgs_sent": "sum(gateway_grpc_stream_messages_sent_total)",
  "grpc_msgs_received": "sum(gateway_grpc_stream_messages_received_total)",
  "grpc_backend_auth_success": "sum(gateway_grpc_proxy_backend_auth_success_total)",
  # websocket
  "ws_connections": "sum(gateway_ws_connections_total)",
  "ws_connections_active": "sum(gateway_ws_connections_active)",
  "ws_msgs_received": "sum(gateway_ws_messages_received_total)",
  "ws_msgs_sent": "sum(gateway_ws_messages_sent_total)",
  # transform / encoding / cors
  "transform_operations": "sum(gateway_transform_operations_total)",
  "encoding_encode": "sum(gateway_encoding_encode_total)",
  "encoding_negotiations": "sum(gateway_encoding_negotiations_total)",
  "cors_requests": "sum(gateway_middleware_cors_requests_total)",
  # TLS (listener handshakes + backend mTLS handshakes)
  "tls_handshakes": "sum(gateway_tls_handshake_duration_seconds_count)",
  "backend_tls_handshakes": "sum(gateway_backend_tls_handshake_duration_seconds_count)",
  # openapi validation: no dedicated series wired in this build (see report
  # finding); validated-route liveness via per-route request counter
  "openapi_validated_route_requests": 'sum(gateway_route_requests_total{route=~"pt-validated-.*"})',
  # graphql proxy counter (exists but not wired -> expected to stay 0; recorded
  # deliberately as evidence of the metrics gap)
  "graphql_requests_total": "sum(avapigw_graphql_requests_total)",
  # vault integration
  "vault_requests": "sum(gateway_vault_requests_total)",
}
res = {}
for k, q in queries.items():
    try:
        u = vm + "/api/v1/query?query=" + urllib.parse.quote(q)
        d = json.load(urllib.request.urlopen(u, timeout=10))
        r = d.get("data", {}).get("result", [])
        res[k] = float(r[0]["value"][1]) if r else None
    except Exception as e:
        res[k] = f"ERR:{e}"
json.dump(res, open(out, "w"), indent=2)
print("  snap", out, json.dumps({k: res[k] for k in ("requests_total","grpc_stream_count","ws_connections")}))
PY
}

# gateway container resource usage snapshot
gwstats() { # $1=label
  docker stats --no-stream --format '{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}}' "$GW_CONTAINER" \
    > "$OUT/$1_gwstats.txt" 2>/dev/null || true
}

run_group() {
  local pt="$1" runner="$2" group="$3" desc="$4"
  echo ""
  echo "=================================================================="
  echo " $pt  ($group)  $desc"
  echo "=================================================================="
  local gdir="$OUT/$pt"
  mkdir -p "$gdir"
  snap "${pt}_before"
  local start=$(date +%s)
  case "$pt" in
    PT-01)
      GRPC_TARGET=127.0.0.1:9000 GRPC_INSECURE=1 PERF_DURATION="$GRPC_DUR" PERF_CONC="$PERF_CONC" \
        "$SCRIPTS/run-grpc-group.sh" "$gdir" "$group" 2>&1 | tee "$gdir/run.log" ;;
    PT-02)
      GRPC_TARGET=127.0.0.1:9443 GRPC_INSECURE=0 PERF_DURATION="$GRPC_DUR" PERF_CONC="$PERF_CONC" \
        "$SCRIPTS/run-grpc-group.sh" "$gdir" "$group" 2>&1 | tee "$gdir/run.log" ;;
    PT-03)
      HTTP_BASE=http://127.0.0.1:8080 WS_BASE=ws://127.0.0.1:8080 \
        "$SCRIPTS/run-http-group.sh" "$gdir" "$group" 2>&1 | tee "$gdir/run.log" ;;
    PT-04)
      HTTP_BASE=https://127.0.0.1:8443 WS_BASE=wss://127.0.0.1:8443 \
        "$SCRIPTS/run-http-group.sh" "$gdir" "$group" 2>&1 | tee "$gdir/run.log" ;;
    PT-05)
      HTTP_BASE=http://127.0.0.1:8080 WS_BASE=ws://127.0.0.1:8080 \
        "$SCRIPTS/run-graphql-group.sh" "$gdir" "$group" 2>&1 | tee "$gdir/run.log" ;;
    PT-06)
      HTTP_BASE=https://127.0.0.1:8443 WS_BASE=wss://127.0.0.1:8443 \
        "$SCRIPTS/run-graphql-group.sh" "$gdir" "$group" 2>&1 | tee "$gdir/run.log" ;;
  esac
  local end=$(date +%s)
  echo "elapsed_seconds=$((end-start))" | tee "$gdir/elapsed.txt"
  gwstats "$pt"
  snap "${pt}_after"
}

GROUPS_TO_RUN="${PT_GROUPS:-PT-01 PT-02 PT-03 PT-04 PT-05 PT-06}"
# PT-04/PT-06 reuse the group3/group5 scenario sets over the TLS listeners:
# aggregate/mirroring is NOT part of the required matrix for this suite.
case " $GROUPS_TO_RUN " in *" PT-01 "*) run_group "PT-01" grpc    group1 "grpc & streaming: mTLS + OIDC (plaintext gRPC listener :9000)" ;; esac
case " $GROUPS_TO_RUN " in *" PT-02 "*) run_group "PT-02" grpc    group2 "TLS grpc & streaming: mTLS + OIDC (gRPC-TLS listener :9443)" ;; esac
case " $GROUPS_TO_RUN " in *" PT-03 "*) run_group "PT-03" http    group3 "http & ws: basic/apikey/oidc + sentinel ratelimit + transform + encoding + sentinel cache + cors + openapi" ;; esac
case " $GROUPS_TO_RUN " in *" PT-04 "*) run_group "PT-04" http    group3 "https & wss: same feature stack over TLS" ;; esac
case " $GROUPS_TO_RUN " in *" PT-05 "*) run_group "PT-05" graphql group5 "graphql & ws: basic/apikey/oidc + ratelimit + transform + cors" ;; esac
case " $GROUPS_TO_RUN " in *" PT-06 "*) run_group "PT-06" graphql group5 "TLS graphql & wss: same feature stack over TLS" ;; esac

echo ""
echo "All PT groups complete. Results in: $OUT"
