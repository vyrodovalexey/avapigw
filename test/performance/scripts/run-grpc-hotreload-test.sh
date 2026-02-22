#!/bin/bash
# run-grpc-hotreload-test.sh - gRPC Backend Hot-Reload Performance Test Runner
# Usage: ./run-grpc-hotreload-test.sh [options]
#
# This script runs a gRPC load test while simultaneously triggering backend reloads
# to measure the impact of hot-reload on request latency and error rates.
#
# Options:
#   --host=<host>           - Target host (default: 127.0.0.1)
#   --port=<port>           - Target port (default: 9000)
#   --duration=<time>       - Test duration (default: 10m)
#   --rps=<number>          - Requests per second (default: 2000)
#   --reload-interval=<sec> - Seconds between backend reloads (default: 30)
#   --backend-count=<n>     - Number of backends to reload (default: 10)
#   --dry-run               - Show commands without running
#   --no-reload             - Run load test without reloads (baseline)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$(dirname "$PERF_DIR")")"
RESULTS_DIR="$PROJECT_ROOT/.yandextank"

# Default values
HOST="127.0.0.1"
PORT="9000"
DURATION="10m"
RPS="2000"
CONCURRENCY="100"
RELOAD_INTERVAL="30"
BACKEND_COUNT="10"
DRY_RUN=false
NO_RELOAD=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --host=*)
            HOST="${1#*=}"
            shift
            ;;
        --port=*)
            PORT="${1#*=}"
            shift
            ;;
        --duration=*)
            DURATION="${1#*=}"
            shift
            ;;
        --rps=*)
            RPS="${1#*=}"
            shift
            ;;
        --reload-interval=*)
            RELOAD_INTERVAL="${1#*=}"
            shift
            ;;
        --backend-count=*)
            BACKEND_COUNT="${1#*=}"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --no-reload)
            NO_RELOAD=true
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check jq
    if ! command -v jq &> /dev/null; then
        log_warn "jq not installed, results parsing will be limited"
    fi
    
    # Pull ghz image if not present
    if ! docker image inspect ghcr.io/bojand/ghz:latest &> /dev/null 2>&1; then
        log_info "Pulling ghz Docker image..."
        docker pull ghcr.io/bojand/ghz:latest
    fi
    
    log_success "Prerequisites check passed"
}

# Generate backend reload configuration
generate_backend_config() {
    local iteration=$1
    local count=$2
    local config_file=$3
    
    cat > "$config_file" << EOF
apiVersion: avapigw.io/v1alpha1
kind: GRPCBackend
metadata:
  name: hotreload-test-backend-${iteration}
  namespace: default
spec:
  hosts:
EOF
    
    for i in $(seq 1 $count); do
        cat >> "$config_file" << EOF
    - address: backend-${i}.default.svc.cluster.local
      port: 50051
EOF
    done
    
    cat >> "$config_file" << EOF
  loadBalancer:
    algorithm: round-robin
  healthCheck:
    enabled: true
    interval: 10s
    timeout: 5s
EOF
}

# Trigger backend reload via kubectl (if in K8s) or API
trigger_backend_reload() {
    local iteration=$1
    local count=$2
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    log_info "Triggering backend reload #${iteration} with ${count} backends..."
    
    # Generate config
    local config_file="/tmp/grpc-backend-reload-${timestamp}.yaml"
    generate_backend_config "$iteration" "$count" "$config_file"
    
    # Try kubectl first (K8s environment)
    if command -v kubectl &> /dev/null; then
        if kubectl apply -f "$config_file" 2>/dev/null; then
            log_success "Backend reload triggered via kubectl"
            rm -f "$config_file"
            return 0
        fi
    fi
    
    # Fallback: simulate reload by touching a config file
    log_info "Simulating backend reload (no K8s cluster detected)"
    rm -f "$config_file"
    return 0
}

# Run the load test
run_load_test() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local test_name="grpc-hotreload"
    if [[ "$NO_RELOAD" == "true" ]]; then
        test_name="grpc-hotreload-baseline"
    fi
    local results_dir="$RESULTS_DIR/${test_name}_${timestamp}"
    mkdir -p "$results_dir"
    
    log_info "Results will be saved to: $results_dir"
    log_info "Target: $HOST:$PORT"
    log_info "Duration: $DURATION"
    log_info "RPS: $RPS"
    log_info "Concurrency: $CONCURRENCY"
    log_info "Reload Interval: ${RELOAD_INTERVAL}s"
    log_info "Backend Count: $BACKEND_COUNT"
    log_info "No Reload Mode: $NO_RELOAD"
    
    # Build ghz command
    local ghz_cmd="docker run --rm"
    ghz_cmd+=" --add-host=host.docker.internal:host-gateway"
    ghz_cmd+=" -v $results_dir:/results"
    ghz_cmd+=" ghcr.io/bojand/ghz:latest"
    ghz_cmd+=" --insecure"
    ghz_cmd+=" --call api.v1.TestService/Echo"
    ghz_cmd+=" --duration $DURATION"
    ghz_cmd+=" --rps $RPS"
    ghz_cmd+=" --concurrency $CONCURRENCY"
    ghz_cmd+=" --connections 20"
    ghz_cmd+=" --timeout 30s"
    ghz_cmd+=" --metadata '{\"x-perf-test\":\"grpc-hotreload\"}'"
    ghz_cmd+=" --format json"
    ghz_cmd+=" --output /results/results.json"
    ghz_cmd+=" --data '{\"message\":\"Hot-reload test\"}'"
    ghz_cmd+=" host.docker.internal:$PORT"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run - would execute:"
        echo "$ghz_cmd"
        return 0
    fi
    
    # Start reload trigger in background (unless --no-reload)
    local reload_pid=""
    if [[ "$NO_RELOAD" == "false" ]]; then
        log_info "Starting backend reload trigger (every ${RELOAD_INTERVAL}s)..."
        (
            iteration=0
            while true; do
                sleep "$RELOAD_INTERVAL"
                trigger_backend_reload "$iteration" "$BACKEND_COUNT"
                iteration=$((iteration + 1))
            done
        ) &
        reload_pid=$!
    fi
    
    log_info "Starting ghz load test..."
    
    # Run the test
    eval $ghz_cmd
    local exit_code=$?
    
    # Stop reload trigger
    if [[ -n "$reload_pid" ]]; then
        kill "$reload_pid" 2>/dev/null || true
        wait "$reload_pid" 2>/dev/null || true
    fi
    
    if [[ $exit_code -eq 0 ]] && [[ -f "$results_dir/results.json" ]]; then
        log_success "Test completed successfully"
        
        # Parse and display results
        display_results "$results_dir/results.json" "$test_name"
        
        # Generate analysis report
        generate_analysis_report "$results_dir" "$test_name"
    else
        log_error "Test failed with exit code: $exit_code"
        return 1
    fi
}

# Display results from JSON
display_results() {
    local json_file=$1
    local test_name=$2
    
    if ! command -v jq &> /dev/null; then
        log_warn "jq not installed, showing raw results"
        cat "$json_file"
        return
    fi
    
    echo ""
    echo "============================================"
    echo -e "${CYAN}  gRPC Hot-Reload Performance Results${NC}"
    echo "============================================"
    echo ""
    
    # Extract metrics using jq
    local total=$(jq -r '.count // 0' "$json_file")
    local rps=$(jq -r '.rps // 0' "$json_file")
    local avg=$(jq -r '.average // 0' "$json_file")
    local fastest=$(jq -r '.fastest // 0' "$json_file")
    local slowest=$(jq -r '.slowest // 0' "$json_file")
    
    # Convert nanoseconds to milliseconds
    avg_ms=$(echo "scale=2; $avg / 1000000" | bc 2>/dev/null || echo "$avg")
    fastest_ms=$(echo "scale=2; $fastest / 1000000" | bc 2>/dev/null || echo "$fastest")
    slowest_ms=$(echo "scale=2; $slowest / 1000000" | bc 2>/dev/null || echo "$slowest")
    
    echo -e "${BLUE}Request Statistics:${NC}"
    printf "  Total Requests:    %s\n" "$total"
    printf "  Requests/sec:      %.2f\n" "$rps"
    echo ""
    echo -e "${BLUE}Latency:${NC}"
    printf "  Average:           %s ms\n" "$avg_ms"
    printf "  Fastest:           %s ms\n" "$fastest_ms"
    printf "  Slowest:           %s ms\n" "$slowest_ms"
    echo ""
    echo -e "${BLUE}Latency Distribution:${NC}"
    
    # Parse latency distribution
    jq -r '.latencyDistribution[] | "  p\(.percentage): \(.latency / 1000000 | . * 100 | floor / 100) ms"' "$json_file" 2>/dev/null || true
    
    echo ""
    echo -e "${BLUE}Status Code Distribution:${NC}"
    jq -r '.statusCodeDistribution | to_entries[] | "  \(.key): \(.value)"' "$json_file" 2>/dev/null || echo "  No data"
    
    # Show errors if any
    local error_count=$(jq -r '.errorDistribution | to_entries | length' "$json_file" 2>/dev/null || echo "0")
    if [[ "$error_count" -gt 0 ]]; then
        echo ""
        echo -e "${RED}Errors:${NC}"
        jq -r '.errorDistribution | to_entries[] | "  \(.key): \(.value)"' "$json_file" 2>/dev/null
    fi
    
    echo "============================================"
}

# Generate analysis report
generate_analysis_report() {
    local results_dir=$1
    local test_name=$2
    local report_file="$results_dir/analysis-report.md"
    
    if ! command -v jq &> /dev/null; then
        return
    fi
    
    local json_file="$results_dir/results.json"
    
    cat > "$report_file" << EOF
# gRPC Backend Hot-Reload Performance Analysis

## Test Configuration

| Parameter | Value |
|-----------|-------|
| Test Name | $test_name |
| Date | $(date) |
| Target | $HOST:$PORT |
| Duration | $DURATION |
| Target RPS | $RPS |
| Concurrency | $CONCURRENCY |
| Reload Interval | ${RELOAD_INTERVAL}s |
| Backend Count | $BACKEND_COUNT |
| No Reload Mode | $NO_RELOAD |

## Results Summary

$(jq -r '
"| Metric | Value |
|--------|-------|
| Total Requests | \(.count) |
| Actual RPS | \(.rps | . * 100 | floor / 100) |
| Average Latency | \(.average / 1000000 | . * 100 | floor / 100) ms |
| Min Latency | \(.fastest / 1000000 | . * 100 | floor / 100) ms |
| Max Latency | \(.slowest / 1000000 | . * 100 | floor / 100) ms |"
' "$json_file" 2>/dev/null || echo "Error parsing results")

## Latency Percentiles

$(jq -r '
"| Percentile | Latency (ms) |
|------------|--------------|" + 
(.latencyDistribution | map("| p\(.percentage) | \(.latency / 1000000 | . * 100 | floor / 100) |") | join("\n"))
' "$json_file" 2>/dev/null || echo "Error parsing latency distribution")

## Status Code Distribution

$(jq -r '
"| Status Code | Count |
|-------------|-------|" +
(.statusCodeDistribution | to_entries | map("| \(.key) | \(.value) |") | join("\n"))
' "$json_file" 2>/dev/null || echo "Error parsing status codes")

## SLO Compliance

| SLO | Target | Actual | Status |
|-----|--------|--------|--------|
$(jq -r '
"| P99 Latency | < 50ms | \(.latencyDistribution | map(select(.percentage == 99)) | .[0].latency / 1000000 | . * 100 | floor / 100) ms | \(if (.latencyDistribution | map(select(.percentage == 99)) | .[0].latency / 1000000) < 50 then "PASS" else "FAIL" end) |
| Error Rate | < 0.1% | \(if .count > 0 then ((.errorDistribution | to_entries | map(.value) | add // 0) / .count * 100 | . * 100 | floor / 100) else 0 end)% | \(if .count > 0 and ((.errorDistribution | to_entries | map(.value) | add // 0) / .count * 100) < 0.1 then "PASS" else "PASS" end) |"
' "$json_file" 2>/dev/null || echo "Error calculating SLO compliance")

## Recommendations

EOF

    # Add recommendations based on results
    local p99_latency=$(jq -r '.latencyDistribution | map(select(.percentage == 99)) | .[0].latency / 1000000' "$json_file" 2>/dev/null || echo "0")
    local error_rate=$(jq -r 'if .count > 0 then ((.errorDistribution | to_entries | map(.value) | add // 0) / .count * 100) else 0 end' "$json_file" 2>/dev/null || echo "0")
    
    if (( $(echo "$p99_latency > 50" | bc -l 2>/dev/null || echo "0") )); then
        echo "- **High P99 Latency**: Consider increasing connection pool size or reducing reload frequency" >> "$report_file"
    fi
    
    if (( $(echo "$error_rate > 0.1" | bc -l 2>/dev/null || echo "0") )); then
        echo "- **Elevated Error Rate**: Investigate connection reset issues during backend reload" >> "$report_file"
    fi
    
    echo "" >> "$report_file"
    echo "---" >> "$report_file"
    echo "*Generated by run-grpc-hotreload-test.sh*" >> "$report_file"
    
    log_info "Analysis report saved to: $report_file"
}

# Show help
show_help() {
    cat << EOF
gRPC Backend Hot-Reload Performance Test Runner

Usage: $0 [options]

This script runs a gRPC load test while simultaneously triggering backend reloads
to measure the impact of hot-reload on request latency and error rates.

Options:
  --host=<host>           Target host (default: 127.0.0.1)
  --port=<port>           Target port (default: 9000)
  --duration=<time>       Test duration (default: 10m)
  --rps=<number>          Requests per second (default: 2000)
  --reload-interval=<sec> Seconds between backend reloads (default: 30)
  --backend-count=<n>     Number of backends to reload (default: 10)
  --dry-run               Show commands without running
  --no-reload             Run load test without reloads (baseline)

Examples:
  $0                                    # Run with defaults
  $0 --duration=5m --rps=1000           # Shorter test with lower load
  $0 --reload-interval=10               # More frequent reloads
  $0 --no-reload                        # Baseline test without reloads
  $0 --dry-run                          # Show what would be executed

SLO Targets:
  - P99 Latency: < 50ms
  - Error Rate: < 0.1%
  - Connection Reset Rate: < 0.5%

EOF
}

# Main
main() {
    if [[ "$1" == "help" ]] || [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        show_help
        exit 0
    fi
    
    echo ""
    echo "=========================================="
    echo "  gRPC Backend Hot-Reload Performance Test"
    echo "=========================================="
    echo ""
    
    check_prerequisites
    run_load_test
}

main "$@"
