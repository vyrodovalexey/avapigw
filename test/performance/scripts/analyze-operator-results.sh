#!/bin/bash
# analyze-operator-results.sh - Analyze Operator Performance Test Results
# Usage: ./analyze-operator-results.sh <results-dir> [options]
#
# Options:
#   --summary         - Show brief summary only
#   --detailed        - Show detailed analysis
#   --charts          - Generate charts (requires Python with matplotlib)
#   --compare=<dir>   - Compare with another test run
#   --export=<format> - Export results (json, csv)
#   --baseline=<file> - Compare against baseline metrics

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

# Arguments
RESULTS_DIR="${1:-}"
SUMMARY_ONLY=false
DETAILED=false
GENERATE_CHARTS=false
COMPARE_DIR=""
EXPORT_FORMAT=""
BASELINE_FILE=""

# Parse options
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --summary)
            SUMMARY_ONLY=true
            shift
            ;;
        --detailed)
            DETAILED=true
            shift
            ;;
        --charts)
            GENERATE_CHARTS=true
            shift
            ;;
        --compare=*)
            COMPARE_DIR="${1#*=}"
            shift
            ;;
        --export=*)
            EXPORT_FORMAT="${1#*=}"
            shift
            ;;
        --baseline=*)
            BASELINE_FILE="${1#*=}"
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

# Check if results directory exists
check_results_dir() {
    if [ -z "$RESULTS_DIR" ]; then
        # Find latest results
        RESULTS_DIR=$(ls -td "$PERF_DIR/results/operator_"*/ 2>/dev/null | head -1)
        if [ -z "$RESULTS_DIR" ]; then
            log_error "No results directory specified and no operator results found"
            exit 1
        fi
        log_info "Using latest results: $RESULTS_DIR"
    fi
    
    if [ ! -d "$RESULTS_DIR" ]; then
        log_error "Results directory not found: $RESULTS_DIR"
        exit 1
    fi
}

# Parse test logs for metrics
parse_test_logs() {
    local log_file=$1
    
    if [ ! -f "$log_file" ]; then
        return
    fi
    
    # Extract key metrics from Go test output
    grep -E "(Throughput|Latency|Memory|Goroutine|Total|Success|Failed)" "$log_file" 2>/dev/null || true
}

# Extract reconciliation metrics
extract_reconciliation_metrics() {
    local log_file="$RESULTS_DIR/reconciliation.log"
    
    if [ ! -f "$log_file" ]; then
        log_warn "Reconciliation log not found"
        return
    fi
    
    echo ""
    echo -e "${CYAN}Reconciliation Metrics:${NC}"
    echo "========================"
    
    # Extract throughput
    local throughput=$(grep -oP "Throughput: \K[0-9.]+" "$log_file" | tail -1)
    if [ -n "$throughput" ]; then
        echo "  Throughput: $throughput reconciles/sec"
    fi
    
    # Extract latencies
    local p50=$(grep -oP "Latency P50: \K[0-9.]+ms" "$log_file" | tail -1)
    local p95=$(grep -oP "Latency P95: \K[0-9.]+ms" "$log_file" | tail -1)
    local p99=$(grep -oP "Latency P99: \K[0-9.]+ms" "$log_file" | tail -1)
    
    if [ -n "$p50" ]; then
        echo "  P50 Latency: $p50"
    fi
    if [ -n "$p95" ]; then
        echo "  P95 Latency: $p95"
    fi
    if [ -n "$p99" ]; then
        echo "  P99 Latency: $p99"
    fi
    
    # Extract success/failure counts
    local total=$(grep -oP "Total Reconciliations: \K[0-9]+" "$log_file" | tail -1)
    local success=$(grep -oP "Successful: \K[0-9]+" "$log_file" | tail -1)
    local failed=$(grep -oP "Failed: \K[0-9]+" "$log_file" | tail -1)
    
    if [ -n "$total" ]; then
        echo "  Total Reconciliations: $total"
    fi
    if [ -n "$success" ]; then
        echo "  Successful: $success"
    fi
    if [ -n "$failed" ]; then
        echo "  Failed: $failed"
    fi
}

# Extract gRPC metrics
extract_grpc_metrics() {
    local log_file="$RESULTS_DIR/grpc.log"
    
    if [ ! -f "$log_file" ]; then
        log_warn "gRPC log not found"
        return
    fi
    
    echo ""
    echo -e "${CYAN}gRPC Metrics:${NC}"
    echo "============="
    
    # Extract throughput
    local throughput=$(grep -oP "Throughput: \K[0-9.]+" "$log_file" | tail -1)
    if [ -n "$throughput" ]; then
        echo "  Throughput: $throughput requests/sec"
    fi
    
    # Extract latencies
    local p50=$(grep -oP "Latency P50: \K[0-9.]+ms" "$log_file" | tail -1)
    local p95=$(grep -oP "Latency P95: \K[0-9.]+ms" "$log_file" | tail -1)
    local p99=$(grep -oP "Latency P99: \K[0-9.]+ms" "$log_file" | tail -1)
    
    if [ -n "$p50" ]; then
        echo "  P50 Latency: $p50"
    fi
    if [ -n "$p95" ]; then
        echo "  P95 Latency: $p95"
    fi
    if [ -n "$p99" ]; then
        echo "  P99 Latency: $p99"
    fi
}

# Extract config push metrics
extract_config_push_metrics() {
    local log_file="$RESULTS_DIR/config_push.log"
    
    if [ ! -f "$log_file" ]; then
        log_warn "Config push log not found"
        return
    fi
    
    echo ""
    echo -e "${CYAN}Config Push Metrics:${NC}"
    echo "===================="
    
    # Extract throughput
    local throughput=$(grep -oP "Throughput: \K[0-9.]+" "$log_file" | tail -1)
    if [ -n "$throughput" ]; then
        echo "  Throughput: $throughput pushes/sec"
    fi
    
    # Extract latencies
    local p50=$(grep -oP "Latency P50: \K[0-9.]+ms" "$log_file" | tail -1)
    local p95=$(grep -oP "Latency P95: \K[0-9.]+ms" "$log_file" | tail -1)
    local p99=$(grep -oP "Latency P99: \K[0-9.]+ms" "$log_file" | tail -1)
    
    if [ -n "$p50" ]; then
        echo "  P50 Latency: $p50"
    fi
    if [ -n "$p95" ]; then
        echo "  P95 Latency: $p95"
    fi
    if [ -n "$p99" ]; then
        echo "  P99 Latency: $p99"
    fi
}

# Extract resource metrics
extract_resource_metrics() {
    local metrics_file="$RESULTS_DIR/resource_metrics.txt"
    local usage_file="$RESULTS_DIR/resource_usage.txt"
    
    echo ""
    echo -e "${CYAN}Resource Metrics:${NC}"
    echo "================="
    
    if [ -f "$usage_file" ]; then
        echo "  Resource Usage:"
        cat "$usage_file" | while read line; do
            echo "    $line"
        done
    fi
    
    if [ -f "$metrics_file" ]; then
        # Extract memory stats
        local heap_alloc=$(grep "go_memstats_heap_alloc_bytes" "$metrics_file" | tail -1 | awk '{print $2}')
        if [ -n "$heap_alloc" ]; then
            local heap_mb=$(echo "scale=2; $heap_alloc / 1024 / 1024" | bc)
            echo "  Heap Allocated: ${heap_mb}MB"
        fi
        
        # Extract goroutine count
        local goroutines=$(grep "go_goroutines" "$metrics_file" | tail -1 | awk '{print $2}')
        if [ -n "$goroutines" ]; then
            echo "  Goroutines: $goroutines"
        fi
    fi
}

# Check SLO compliance
check_slo_compliance() {
    echo ""
    echo -e "${CYAN}SLO Compliance:${NC}"
    echo "==============="
    
    local all_passed=true
    
    # Define SLOs
    local slo_p99_latency_ms=100
    local slo_throughput_rps=1000
    local slo_memory_mb=256
    local slo_error_rate=0.1
    
    # Check reconciliation P99 latency
    local p99=$(grep -oP "Latency P99: \K[0-9.]+" "$RESULTS_DIR/reconciliation.log" 2>/dev/null | tail -1)
    if [ -n "$p99" ]; then
        if (( $(echo "$p99 <= $slo_p99_latency_ms" | bc -l) )); then
            echo -e "  ${GREEN}[PASS]${NC} P99 Latency: ${p99}ms <= ${slo_p99_latency_ms}ms"
        else
            echo -e "  ${RED}[FAIL]${NC} P99 Latency: ${p99}ms > ${slo_p99_latency_ms}ms"
            all_passed=false
        fi
    fi
    
    # Check throughput
    local throughput=$(grep -oP "Throughput: \K[0-9.]+" "$RESULTS_DIR/reconciliation.log" 2>/dev/null | tail -1)
    if [ -n "$throughput" ]; then
        if (( $(echo "$throughput >= $slo_throughput_rps" | bc -l) )); then
            echo -e "  ${GREEN}[PASS]${NC} Throughput: ${throughput} RPS >= ${slo_throughput_rps} RPS"
        else
            echo -e "  ${RED}[FAIL]${NC} Throughput: ${throughput} RPS < ${slo_throughput_rps} RPS"
            all_passed=false
        fi
    fi
    
    # Check memory usage
    if [ -f "$RESULTS_DIR/resource_metrics.txt" ]; then
        local heap_alloc=$(grep "go_memstats_heap_alloc_bytes" "$RESULTS_DIR/resource_metrics.txt" | tail -1 | awk '{print $2}')
        if [ -n "$heap_alloc" ]; then
            local heap_mb=$(echo "scale=2; $heap_alloc / 1024 / 1024" | bc)
            if (( $(echo "$heap_mb <= $slo_memory_mb" | bc -l) )); then
                echo -e "  ${GREEN}[PASS]${NC} Memory Usage: ${heap_mb}MB <= ${slo_memory_mb}MB"
            else
                echo -e "  ${RED}[FAIL]${NC} Memory Usage: ${heap_mb}MB > ${slo_memory_mb}MB"
                all_passed=false
            fi
        fi
    fi
    
    echo ""
    if [ "$all_passed" = true ]; then
        echo -e "${GREEN}Overall: All SLOs PASSED${NC}"
    else
        echo -e "${RED}Overall: Some SLOs FAILED${NC}"
    fi
}

# Display summary
display_summary() {
    echo ""
    echo "============================================"
    echo -e "${CYAN}  Operator Performance Test Summary${NC}"
    echo "============================================"
    
    extract_reconciliation_metrics
    extract_grpc_metrics
    extract_config_push_metrics
    extract_resource_metrics
    check_slo_compliance
    
    echo "============================================"
}

# Display detailed analysis
display_detailed() {
    display_summary
    
    echo ""
    echo "============================================"
    echo -e "${CYAN}  Detailed Analysis${NC}"
    echo "============================================"
    
    # Show test-by-test breakdown
    for log_file in "$RESULTS_DIR"/*.log; do
        if [ -f "$log_file" ]; then
            local test_name=$(basename "$log_file" .log)
            echo ""
            echo -e "${BLUE}$test_name:${NC}"
            echo "---"
            
            # Show last 20 lines of each log
            tail -20 "$log_file"
        fi
    done
    
    echo "============================================"
}

# Generate charts using Python
generate_charts() {
    log_info "Generating performance charts..."
    
    # Check if Python is available
    if ! command -v python3 &> /dev/null; then
        log_warn "Python3 not found, skipping chart generation"
        return
    fi
    
    # Create Python script for chart generation
    cat > /tmp/generate_operator_charts.py << 'PYTHON_SCRIPT'
#!/usr/bin/env python3
import sys
import os
import json
import re

try:
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("matplotlib or numpy not installed. Install with: pip install matplotlib numpy")
    sys.exit(1)

def parse_log_file(log_file):
    """Parse a log file and extract metrics."""
    metrics = {
        'throughput': [],
        'p50_latency': [],
        'p95_latency': [],
        'p99_latency': [],
        'crd_counts': [],
    }
    
    if not os.path.exists(log_file):
        return metrics
    
    with open(log_file, 'r') as f:
        content = f.read()
    
    # Extract throughput values
    for match in re.finditer(r'Throughput: ([0-9.]+)', content):
        metrics['throughput'].append(float(match.group(1)))
    
    # Extract latency values
    for match in re.finditer(r'Latency P50: ([0-9.]+)ms', content):
        metrics['p50_latency'].append(float(match.group(1)))
    
    for match in re.finditer(r'Latency P95: ([0-9.]+)ms', content):
        metrics['p95_latency'].append(float(match.group(1)))
    
    for match in re.finditer(r'Latency P99: ([0-9.]+)ms', content):
        metrics['p99_latency'].append(float(match.group(1)))
    
    # Extract CRD counts
    for match in re.finditer(r'CRD Count: ([0-9]+)', content):
        metrics['crd_counts'].append(int(match.group(1)))
    
    return metrics

def generate_latency_chart(metrics, output_dir):
    """Generate latency distribution chart."""
    if not metrics['p50_latency']:
        return
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = range(len(metrics['p50_latency']))
    
    ax.plot(x, metrics['p50_latency'], 'b-', label='P50', marker='o')
    ax.plot(x, metrics['p95_latency'], 'g-', label='P95', marker='s')
    ax.plot(x, metrics['p99_latency'], 'r-', label='P99', marker='^')
    
    ax.axhline(y=100, color='r', linestyle='--', alpha=0.5, label='SLO (100ms)')
    
    ax.set_xlabel('Test Run')
    ax.set_ylabel('Latency (ms)')
    ax.set_title('Reconciliation Latency Distribution')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'latency_distribution.png'), dpi=150)
    plt.close()
    print(f"Generated: {output_dir}/latency_distribution.png")

def generate_throughput_chart(metrics, output_dir):
    """Generate throughput chart."""
    if not metrics['throughput']:
        return
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = range(len(metrics['throughput']))
    
    ax.bar(x, metrics['throughput'], color='steelblue', alpha=0.7)
    ax.axhline(y=1000, color='r', linestyle='--', alpha=0.5, label='SLO (1000 RPS)')
    
    ax.set_xlabel('Test Run')
    ax.set_ylabel('Throughput (reconciles/sec)')
    ax.set_title('Reconciliation Throughput')
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'throughput.png'), dpi=150)
    plt.close()
    print(f"Generated: {output_dir}/throughput.png")

def generate_scaling_chart(metrics, output_dir):
    """Generate scaling chart (latency vs CRD count)."""
    if not metrics['crd_counts'] or not metrics['p99_latency']:
        return
    
    if len(metrics['crd_counts']) != len(metrics['p99_latency']):
        return
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    ax.plot(metrics['crd_counts'], metrics['p99_latency'], 'b-', marker='o')
    ax.axhline(y=100, color='r', linestyle='--', alpha=0.5, label='SLO (100ms)')
    
    ax.set_xlabel('CRD Count')
    ax.set_ylabel('P99 Latency (ms)')
    ax.set_title('Latency Scaling with CRD Count')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'scaling.png'), dpi=150)
    plt.close()
    print(f"Generated: {output_dir}/scaling.png")

def main():
    if len(sys.argv) < 2:
        print("Usage: generate_operator_charts.py <results_dir>")
        sys.exit(1)
    
    results_dir = sys.argv[1]
    
    # Parse reconciliation log
    reconciliation_metrics = parse_log_file(os.path.join(results_dir, 'reconciliation.log'))
    
    # Generate charts
    generate_latency_chart(reconciliation_metrics, results_dir)
    generate_throughput_chart(reconciliation_metrics, results_dir)
    generate_scaling_chart(reconciliation_metrics, results_dir)
    
    print("Chart generation complete!")

if __name__ == '__main__':
    main()
PYTHON_SCRIPT

    python3 /tmp/generate_operator_charts.py "$RESULTS_DIR"
    rm -f /tmp/generate_operator_charts.py
    
    log_success "Charts generated in $RESULTS_DIR"
}

# Export results
export_results() {
    local format=$1
    local output_file="$RESULTS_DIR/results.$format"
    
    log_info "Exporting results to $format format..."
    
    case $format in
        json)
            # Create JSON export
            cat > "$output_file" << EOF
{
  "test_date": "$(date -Iseconds)",
  "results_dir": "$RESULTS_DIR",
  "reconciliation": {
    "throughput": $(grep -oP "Throughput: \K[0-9.]+" "$RESULTS_DIR/reconciliation.log" 2>/dev/null | tail -1 || echo "null"),
    "p50_latency_ms": $(grep -oP "Latency P50: \K[0-9.]+" "$RESULTS_DIR/reconciliation.log" 2>/dev/null | tail -1 || echo "null"),
    "p95_latency_ms": $(grep -oP "Latency P95: \K[0-9.]+" "$RESULTS_DIR/reconciliation.log" 2>/dev/null | tail -1 || echo "null"),
    "p99_latency_ms": $(grep -oP "Latency P99: \K[0-9.]+" "$RESULTS_DIR/reconciliation.log" 2>/dev/null | tail -1 || echo "null")
  },
  "grpc": {
    "throughput": $(grep -oP "Throughput: \K[0-9.]+" "$RESULTS_DIR/grpc.log" 2>/dev/null | tail -1 || echo "null"),
    "p99_latency_ms": $(grep -oP "Latency P99: \K[0-9.]+" "$RESULTS_DIR/grpc.log" 2>/dev/null | tail -1 || echo "null")
  },
  "config_push": {
    "throughput": $(grep -oP "Throughput: \K[0-9.]+" "$RESULTS_DIR/config_push.log" 2>/dev/null | tail -1 || echo "null"),
    "p99_latency_ms": $(grep -oP "Latency P99: \K[0-9.]+" "$RESULTS_DIR/config_push.log" 2>/dev/null | tail -1 || echo "null")
  }
}
EOF
            ;;
        csv)
            # Create CSV export
            cat > "$output_file" << EOF
metric,value
reconciliation_throughput,$(grep -oP "Throughput: \K[0-9.]+" "$RESULTS_DIR/reconciliation.log" 2>/dev/null | tail -1 || echo "")
reconciliation_p50_latency_ms,$(grep -oP "Latency P50: \K[0-9.]+" "$RESULTS_DIR/reconciliation.log" 2>/dev/null | tail -1 || echo "")
reconciliation_p95_latency_ms,$(grep -oP "Latency P95: \K[0-9.]+" "$RESULTS_DIR/reconciliation.log" 2>/dev/null | tail -1 || echo "")
reconciliation_p99_latency_ms,$(grep -oP "Latency P99: \K[0-9.]+" "$RESULTS_DIR/reconciliation.log" 2>/dev/null | tail -1 || echo "")
grpc_throughput,$(grep -oP "Throughput: \K[0-9.]+" "$RESULTS_DIR/grpc.log" 2>/dev/null | tail -1 || echo "")
grpc_p99_latency_ms,$(grep -oP "Latency P99: \K[0-9.]+" "$RESULTS_DIR/grpc.log" 2>/dev/null | tail -1 || echo "")
config_push_throughput,$(grep -oP "Throughput: \K[0-9.]+" "$RESULTS_DIR/config_push.log" 2>/dev/null | tail -1 || echo "")
config_push_p99_latency_ms,$(grep -oP "Latency P99: \K[0-9.]+" "$RESULTS_DIR/config_push.log" 2>/dev/null | tail -1 || echo "")
EOF
            ;;
        *)
            log_error "Unknown export format: $format"
            return 1
            ;;
    esac
    
    log_success "Results exported to: $output_file"
}

# Compare with another run
compare_results() {
    local dir1="$RESULTS_DIR"
    local dir2="$COMPARE_DIR"
    
    if [ ! -d "$dir2" ]; then
        log_error "Comparison directory not found: $dir2"
        return 1
    fi
    
    echo ""
    echo "============================================"
    echo -e "${CYAN}  Results Comparison${NC}"
    echo "============================================"
    echo ""
    
    printf "%-30s %15s %15s %10s\n" "Metric" "Run 1" "Run 2" "Change"
    echo "--------------------------------------------------------------------"
    
    # Compare reconciliation throughput
    local t1=$(grep -oP "Throughput: \K[0-9.]+" "$dir1/reconciliation.log" 2>/dev/null | tail -1)
    local t2=$(grep -oP "Throughput: \K[0-9.]+" "$dir2/reconciliation.log" 2>/dev/null | tail -1)
    
    if [ -n "$t1" ] && [ -n "$t2" ]; then
        local diff=$(echo "scale=1; ($t2 - $t1) * 100 / $t1" | bc)
        printf "%-30s %15.2f %15.2f %+9.1f%%\n" "Reconciliation Throughput" "$t1" "$t2" "$diff"
    fi
    
    # Compare P99 latency
    local l1=$(grep -oP "Latency P99: \K[0-9.]+" "$dir1/reconciliation.log" 2>/dev/null | tail -1)
    local l2=$(grep -oP "Latency P99: \K[0-9.]+" "$dir2/reconciliation.log" 2>/dev/null | tail -1)
    
    if [ -n "$l1" ] && [ -n "$l2" ]; then
        local diff=$(echo "scale=1; ($l2 - $l1) * 100 / $l1" | bc)
        printf "%-30s %12.2f ms %12.2f ms %+9.1f%%\n" "Reconciliation P99 Latency" "$l1" "$l2" "$diff"
    fi
    
    echo "============================================"
}

# Show help
show_help() {
    cat << EOF
Operator Performance Results Analyzer

Usage: $0 <results-dir> [options]

Options:
  --summary         Show brief summary only
  --detailed        Show detailed analysis
  --charts          Generate charts (requires Python with matplotlib)
  --compare=<dir>   Compare with another test run
  --export=<format> Export results (json, csv)
  --baseline=<file> Compare against baseline metrics

Examples:
  $0 results/operator_local_20240101_120000/
  $0 results/operator_local_20240101_120000/ --detailed
  $0 results/run1/ --compare=results/run2/
  $0 --charts --export=json

EOF
}

# Main
main() {
    if [ "$1" = "help" ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        show_help
        exit 0
    fi
    
    check_results_dir
    
    if [ -n "$EXPORT_FORMAT" ]; then
        export_results "$EXPORT_FORMAT"
    fi
    
    if [ "$GENERATE_CHARTS" = true ]; then
        generate_charts
    fi
    
    if [ -n "$COMPARE_DIR" ]; then
        compare_results
    elif [ "$DETAILED" = true ]; then
        display_detailed
    else
        display_summary
    fi
}

main "$@"
