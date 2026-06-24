#!/bin/bash
# run-grpc-group.sh - run gRPC perf scenarios (groups 1 & 2) for 180s each via ghz.
# Emits per-scenario ghz JSON + a group summary.json with {count,rps,p50,p95,p99,status}.
# Target: gateway GRPC-TLS listener NodePort 30159 (use --skipTLS for TLS-listener-as-plaintext-equivalent
# since ghz negotiates the TLS handshake when -t given; here we use insecure TLS via -t flag handling).
set -u
cd "$(dirname "$0")/../../.." || exit 1
ROOT="$(pwd)"
PROTO="$ROOT/test/performance/proto/test_service.proto"
GRPC_TARGET="${GRPC_TARGET:-127.0.0.1:30159}"
DUR="${PERF_DURATION:-180s}"
CONC="${PERF_CONC:-50}"
CONNS="${PERF_CONNS:-10}"
OUTDIR="$1"; GROUP="$2"
mkdir -p "$OUTDIR"
TOK_LH="$(cat /tmp/tok_lh.txt 2>/dev/null)"

# ghz wrapper. $1=name $2=call $3=data $4=metadata-json [extra...]
run() {
  local name="$1" call="$2" data="$3" meta="$4"; shift 4
  echo ">>> [$GROUP/$name] ghz $call dur=$DUR conc=$CONC"
  ghz --skipTLS --proto "$PROTO" --call "$call" \
    -m "$meta" -d "$data" -z "$DUR" -c "$CONC" --connections "$CONNS" \
    -O json -o "$OUTDIR/${name}.json" "$@" "$GRPC_TARGET" 2>"$OUTDIR/${name}.err" || true
  # compact line
  jq -r '"    rps=\(.rps|floor) count=\(.count) p50=\(.latencyDistribution[]|select(.percentage==50)|.latency/1e6)ms p95=\(.latencyDistribution[]|select(.percentage==95)|.latency/1e6)ms p99=\(.latencyDistribution[]|select(.percentage==99)|.latency/1e6)ms status=\(.statusCodeDistribution)"' "$OUTDIR/${name}.json" 2>/dev/null || echo "    (ghz failed; see ${name}.err)"
}

PARALLEL="${PERF_PARALLEL:-0}"
maybe_bg() { if [ "$PARALLEL" = "1" ]; then "$@" & else "$@"; fi; }

if [ "$GROUP" = "group1" ]; then
  maybe_bg run unary       api.v1.TestService/Unary               '{"message":"perf"}'        '{"x-perf-baseline":"true"}'
  maybe_bg run serverstream api.v1.TestService/ServerStream        '{"count":5,"interval_ms":10}' '{"x-perf-baseline":"true"}'
  maybe_bg run bidistream  api.v1.TestService/BidirectionalStream '{"value":3,"operation":"double"}' '{"x-perf-baseline":"true"}'
  maybe_bg run oidc_unary  api.v1.TestService/Unary               '{"message":"perf"}'        "{\"x-test-scenario\":\"oidc\",\"authorization\":\"Bearer $TOK_LH\"}"
  maybe_bg run mtls_unary  api.v1.TestService/Unary               '{"message":"perf"}'        '{"x-test-scenario":"mtls"}'
  [ "$PARALLEL" = "1" ] && wait
elif [ "$GROUP" = "group2" ]; then
  # TLS group: same TLS listener; exercise TLS unary (more conns), TLS serverstream(10x10ms), mTLS stream, TLS OIDC
  maybe_bg run tls_unary       api.v1.TestService/Unary        '{"message":"perf"}'           '{"x-perf-baseline":"true"}'
  maybe_bg run tls_serverstream api.v1.TestService/ServerStream '{"count":10,"interval_ms":10}' '{"x-perf-baseline":"true"}'
  maybe_bg run mtls_stream     api.v1.TestService/ServerStream '{"count":5,"interval_ms":10}' '{"x-test-scenario":"mtls-stream"}'
  maybe_bg run tls_oidc_unary  api.v1.TestService/Unary        '{"message":"perf"}'           "{\"x-test-scenario\":\"oidc\",\"authorization\":\"Bearer $TOK_LH\"}"
  [ "$PARALLEL" = "1" ] && wait
fi

# Build group summary.json
python3 - "$OUTDIR" <<'PY'
import json, os, sys, glob
od = sys.argv[1]
out = {}
for f in sorted(glob.glob(os.path.join(od, "*.json"))):
    name = os.path.splitext(os.path.basename(f))[0]
    if name == "summary": continue
    try:
        d = json.load(open(f))
    except Exception:
        continue
    if "rps" not in d: continue
    def pct(p):
        for e in d.get("latencyDistribution", []):
            if e.get("percentage") == p: return round(e["latency"]/1e6, 2)
        return None
    out[name] = {
        "count": d.get("count"),
        "rps": round(d.get("rps", 0)),
        "avg_ms": round(d.get("average", 0)/1e6, 2),
        "p50": pct(50), "p95": pct(95), "p99": pct(99),
        "status": d.get("statusCodeDistribution", {}),
    }
json.dump(out, open(os.path.join(od, "summary.json"), "w"), indent=2)
print("wrote", os.path.join(od, "summary.json"))
PY
