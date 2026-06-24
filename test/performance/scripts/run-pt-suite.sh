#!/bin/bash
# run-pt-suite.sh - Drive the 6 PT scenario groups (PT-01..06), 3 min steady-state each,
# against the deployed operator-mode gateway via kubectl port-forward, and snapshot
# VictoriaMetrics gateway metrics before/after each group.
#
# Reuses the existing group runners:
#   PT-01/PT-02 -> run-grpc-group.sh   (ghz, gRPC-TLS via PF 19443)
#   PT-03/PT-04 -> run-http-group.sh   (hey + k6, HTTPS/WSS via PF 18443)
#   PT-05/PT-06 -> run-graphql-group.sh(hey + k6, HTTPS/WSS via PF 18443)
#
# Aggregate (mirroring) CRDs are applied for PT-02/04/06.
#
# Env overrides honored by the group scripts:
#   HTTP_BASE, WS_BASE, GRPC_TARGET, PERF_DURATION, PERF_CONN/CONC, PERF_QPS
set -u
cd "$(dirname "$0")/../../.." || exit 1
ROOT="$(pwd)"
SCRIPTS="$ROOT/test/performance/scripts"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="${PT_OUT:-$ROOT/.yandextank/pt-suite_$TS}"
VM="${VM_URL:-http://localhost:8428}"
NS="avapigw-test"

# Port-forward endpoints (set up by caller or here)
export HTTP_BASE="${HTTP_BASE:-https://127.0.0.1:18443}"
export WS_BASE="${WS_BASE:-wss://127.0.0.1:18443}"
export GRPC_TARGET="${GRPC_TARGET:-127.0.0.1:19443}"
export PERF_DURATION="${PERF_DURATION:-180}"   # 3 minutes steady-state (hey/k6 use seconds)
export PERF_CONN="${PERF_CONN:-40}"
export PERF_CONC="${PERF_CONC:-40}"
export PERF_QPS="${PERF_QPS:-15}"
export PERF_PARALLEL="${PERF_PARALLEL:-1}"   # run group scenarios concurrently => single 3-min window
GRPC_DUR="${PERF_DURATION}s"

mkdir -p "$OUT"
echo "PT suite output: $OUT"
echo "HTTP_BASE=$HTTP_BASE GRPC_TARGET=$GRPC_TARGET dur=${PERF_DURATION}s"

# refresh OIDC tokens for the group scripts
curl -s -X POST "http://localhost:8090/realms/gateway-test/protocol/openid-connect/token" \
  -d 'grant_type=password' -d 'client_id=gateway' -d 'client_secret=gateway-secret' \
  -d 'username=testuser' -d 'password=testpass' | jq -r '.access_token' > /tmp/tok_lh.txt
cp /tmp/tok_lh.txt /tmp/tok_ip.txt

# Snapshot a curated set of gateway metrics from VictoriaMetrics into a JSON file.
snap() { # $1=label
  local f="$OUT/vm_$1.json"
  python3 - "$VM" "$f" <<'PY'
import sys, json, urllib.request, urllib.parse
vm, out = sys.argv[1], sys.argv[2]
queries = {
  "requests_total": "sum(gateway_requests_total)",
  "request_duration_p95": "histogram_quantile(0.95, sum(rate(gateway_request_duration_seconds_bucket[1m])) by (le))",
  "request_duration_p99": "histogram_quantile(0.99, sum(rate(gateway_request_duration_seconds_bucket[1m])) by (le))",
  "aggregate_requests_total": "gateway_aggregate_requests_total",
  "aggregate_targets_total": "gateway_aggregate_targets_total",
  "aggregate_results_success": 'gateway_aggregate_results_total{result="success"}',
  "aggregate_results_error": 'gateway_aggregate_results_total{result="error"}',
  "aggregate_duration_count": "gateway_aggregate_duration_seconds_count",
  "auth_requests": "sum(gateway_auth_requests_total)",
  "auth_requests_grpc": 'sum(gateway_auth_requests_total{method="grpc"})',
  "cache_ops": "sum(gateway_cache_operations_total)",
  "grpc_direct_requests": "sum(gateway_grpc_proxy_direct_requests_total)",
  "grpc_stream_count": "sum(gateway_grpc_stream_duration_seconds_count)",
  "grpc_ratelimit_rejected": "sum(gateway_grpc_proxy_rate_limit_rejected_total)",
  "ws_connections": "sum(gateway_websocket_proxy_connections_total)",
  "transform_count": "sum(gateway_transform_requests_total)",
  "encoding_count": "sum(gateway_encoding_requests_total)",
  "cors_count": "sum(gateway_cors_requests_total)",
  "openapi_count": "sum(gateway_openapi_validation_total)",
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
print("  snap", out, json.dumps({k: res[k] for k in ("requests_total","aggregate_requests_total")}))
PY
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
  if [ "$runner" = "grpc" ]; then
    PERF_DURATION="$GRPC_DUR" PERF_CONC="$PERF_CONC" "$SCRIPTS/run-grpc-group.sh" "$gdir" "$group" 2>&1 | tee "$gdir/run.log"
  elif [ "$runner" = "http" ]; then
    "$SCRIPTS/run-http-group.sh" "$gdir" "$group" 2>&1 | tee "$gdir/run.log"
  else
    "$SCRIPTS/run-graphql-group.sh" "$gdir" "$group" 2>&1 | tee "$gdir/run.log"
  fi
  local end=$(date +%s)
  echo "elapsed_seconds=$((end-start))" | tee "$gdir/elapsed.txt"
  snap "${pt}_after"
}

GROUPS_TO_RUN="${PT_GROUPS:-PT-01 PT-02 PT-03 PT-04 PT-05 PT-06}"
case " $GROUPS_TO_RUN " in *" PT-01 "*) run_group "PT-01" grpc    group1 "grpc and streaming: mTLS + OIDC" ;; esac
case " $GROUPS_TO_RUN " in *" PT-02 "*) run_group "PT-02" grpc    group2 "tls grpc and streaming: mTLS + OIDC + mirroring aggregate" ;; esac
case " $GROUPS_TO_RUN " in *" PT-03 "*) run_group "PT-03" http    group3 "http and ws: basic/apikey/oidc + ratelimit + transform + encoding + cache + cors + openapi" ;; esac
case " $GROUPS_TO_RUN " in *" PT-04 "*) run_group "PT-04" http    group4 "https and wss: PT-03 stack + mirroring aggregate REST" ;; esac
case " $GROUPS_TO_RUN " in *" PT-05 "*) run_group "PT-05" graphql group5 "graphql and ws: basic/apikey/oidc + ratelimit + transform + cors" ;; esac
case " $GROUPS_TO_RUN " in *" PT-06 "*) run_group "PT-06" graphql group6 "tls graphql and wss: PT-05 stack + mirroring aggregate GraphQL" ;; esac

echo ""
echo "All PT groups complete. Results in: $OUT"
