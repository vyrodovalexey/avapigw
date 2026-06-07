#!/bin/bash
# run-feature-scenario.sh - run a single HTTP/HTTPS/GraphQL feature scenario with hey for 180s
# and emit a compact metrics line. Used by the perf agent for groups 3-6.
# Usage: run-feature-scenario.sh <name> <url> <outdir> [extra hey args...]
set -u
NAME="$1"; URL="$2"; OUTDIR="$3"; shift 3
DUR="${PERF_DURATION:-180}"; CONN="${PERF_CONN:-50}"; QPS="${PERF_QPS:-10}"
OUT="$OUTDIR/${NAME}.txt"
mkdir -p "$OUTDIR"
hey -z "${DUR}s" -c "$CONN" -q "$QPS" -t 15 -H 'Accept: application/json' "$@" "$URL" > "$OUT" 2>&1
RPS=$(grep 'Requests/sec' "$OUT" | awk '{print $2}')
P50=$(grep '50%' "$OUT" | head -1 | awk '{print $3}')
P95=$(grep '95%' "$OUT" | head -1 | awk '{print $3}')
P99=$(grep '99%' "$OUT" | head -1 | awk '{print $3}')
AVG=$(grep 'Average:' "$OUT" | head -1 | awk '{print $2}')
CODES=$(grep -E '^\s+\[[0-9]+\]' "$OUT" | tr -d '\n' | sed 's/  */ /g')
echo "[$NAME] rps=$RPS avg=${AVG}s p50=${P50}s p95=${P95}s p99=${P99}s codes:${CODES}"
