#!/bin/bash
# run-pt-mcp-local.sh - Drive the two MCP PT scenario groups (PT-07 mcp, PT-08
# tls mcp), ~180s steady-state each, against the LOCAL PT gateway (container
# avapigw-pt on the compose network; MCP path /mcp on HTTP :8080 and HTTPS
# :8443). Snapshots the MCP-specific VictoriaMetrics gateway series before/after
# each group so the avapigw_mcp_* families can be verified fresh.
#
# Companion to run-pt-local.sh (which covers PT-01..06 = scenarios a-f). This
# script adds scenarios g (MCP) and h (TLS MCP), reusing run-mcp-group.sh.
#
#   PT-07 mcp & OIDC + sentinel ratelimit       -> HTTP  :8080/mcp
#   PT-08 tls mcp & OIDC + sentinel ratelimit   -> HTTPS :8443/mcp
#
# Env overrides honored: PERF_DURATION, PERF_CONN, PERF_QPS, PT_GROUPS, VM_URL
set -u
cd "$(dirname "$0")/../../.." || exit 1
ROOT="$(pwd)"
SCRIPTS="$ROOT/test/performance/scripts"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="${PT_OUT:-$ROOT/.yandextank/pt-mcp-local_$TS}"
VM="${VM_URL:-http://127.0.0.1:8428}"
GW_CONTAINER="${GW_CONTAINER:-avapigw-pt}"

export PERF_DURATION="${PERF_DURATION:-180}"   # 3 minutes steady-state
export PERF_CONN="${PERF_CONN:-40}"
export PERF_QPS="${PERF_QPS:-15}"
export PERF_PARALLEL="${PERF_PARALLEL:-1}"     # scenarios concurrent => one 3-min window

mkdir -p "$OUT"
echo "PT MCP local suite output: $OUT"
echo "duration=${PERF_DURATION}s conn=$PERF_CONN qps=$PERF_QPS parallel=$PERF_PARALLEL"

# Snapshot the MCP-relevant gateway metrics from VictoriaMetrics.
# Metric names verified against the live /metrics of this build
# (internal/mcp/metrics/metrics.go): avapigw_mcp_requests_total /
# avapigw_mcp_request_duration_seconds carry labels
# upstream, mcp_method, mcp_name, protocol_version, result_type, outcome.
snap() { # $1=label
  local f="$OUT/vm_$1.json"
  python3 - "$VM" "$f" <<'PY'
import sys, json, urllib.request, urllib.parse
vm, out = sys.argv[1], sys.argv[2]
queries = {
  # MCP request rate / latency (labelled families)
  "mcp_requests_total": "sum(avapigw_mcp_requests_total)",
  "mcp_requests_by_outcome": 'sum by (outcome) (avapigw_mcp_requests_total)',
  "mcp_requests_by_method": 'sum by (mcp_method) (avapigw_mcp_requests_total)',
  "mcp_duration_count": "sum(avapigw_mcp_request_duration_seconds_count)",
  "mcp_duration_p95": "histogram_quantile(0.95, sum(rate(avapigw_mcp_request_duration_seconds_bucket[1m])) by (le))",
  "mcp_duration_p99": "histogram_quantile(0.99, sum(rate(avapigw_mcp_request_duration_seconds_bucket[1m])) by (le))",
  "mcp_schema_rejections": "sum(avapigw_mcp_schema_rejections_total)",
  "mcp_header_mismatches": "sum(avapigw_mcp_header_mismatches_total)",
  # core route counter for the MCP route + auth + sentinel rate limit families
  "route_requests_mcp": 'sum(gateway_route_requests_total{route=~".*mcp.*"})',
  "route_requests_total": "sum(gateway_route_requests_total)",
  "route_auth_successes": "sum(gateway_route_auth_successes_total)",
  "route_auth_failures": "sum(gateway_route_auth_failures_total)",
  "route_ratelimit_hits": "sum(gateway_route_ratelimit_hits_total)",
  "redis_rl_allowed": "sum(gateway_middleware_redis_rate_limit_allowed_total)",
  "redis_rl_denied": "sum(gateway_middleware_redis_rate_limit_denied_total)",
  # TLS handshakes (PT-08 exercises the HTTPS listener)
  "tls_handshakes": "sum(gateway_tls_handshake_duration_seconds_count)",
}
res = {}
for k, q in queries.items():
    try:
        u = vm + "/api/v1/query?query=" + urllib.parse.quote(q)
        d = json.load(urllib.request.urlopen(u, timeout=10))
        r = d.get("data", {}).get("result", [])
        if len(r) == 1 and "value" in r[0]:
            res[k] = float(r[0]["value"][1])
        elif r:
            res[k] = {tuple(sorted(s["metric"].items()))[0][1] if s["metric"] else "_": float(s["value"][1]) for s in r}
        else:
            res[k] = None
    except Exception as e:
        res[k] = f"ERR:{e}"
# tuple keys aren't JSON-serialisable; coerce dict keys to str
def norm(v):
    if isinstance(v, dict):
        return {str(k): val for k, val in v.items()}
    return v
res = {k: norm(v) for k, v in res.items()}
json.dump(res, open(out, "w"), indent=2)
print("  snap", out, json.dumps({k: res[k] for k in ("mcp_requests_total","mcp_duration_count","route_requests_mcp")}))
PY
}

gwstats() { # $1=label
  docker stats --no-stream --format '{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}}' "$GW_CONTAINER" \
    > "$OUT/$1_gwstats.txt" 2>/dev/null || true
}

run_group() {
  local pt="$1" group="$2" desc="$3" base="$4"
  echo ""
  echo "=================================================================="
  echo " $pt  ($group)  $desc"
  echo "=================================================================="
  local gdir="$OUT/$pt"
  mkdir -p "$gdir"
  snap "${pt}_before"
  local start; start=$(date +%s)
  HTTP_BASE="$base" "$SCRIPTS/run-mcp-group.sh" "$gdir" "$group" 2>&1 | tee "$gdir/run.log"
  local end; end=$(date +%s)
  echo "elapsed_seconds=$((end-start))" | tee "$gdir/elapsed.txt"
  gwstats "$pt"
  snap "${pt}_after"
}

GROUPS_TO_RUN="${PT_GROUPS:-PT-07 PT-08}"
case " $GROUPS_TO_RUN " in *" PT-07 "*) run_group "PT-07" group7 "mcp & OIDC + sentinel ratelimit (HTTP listener :8080/mcp)"  "http://127.0.0.1:8080" ;; esac
case " $GROUPS_TO_RUN " in *" PT-08 "*) run_group "PT-08" group8 "tls mcp & OIDC + sentinel ratelimit (HTTPS listener :8443/mcp)" "https://127.0.0.1:8443" ;; esac

echo ""
echo "All MCP PT groups complete. Results in: $OUT"
