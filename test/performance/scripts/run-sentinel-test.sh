#!/bin/bash
# run-sentinel-test.sh - Redis Sentinel vs Standalone Cache Performance Test Runner
# Usage: ./run-sentinel-test.sh [options]
#
# This script runs performance tests comparing Redis Sentinel cache vs Redis Standalone cache.
# It starts the gateway with each configuration, runs Yandex Tank tests, and generates
# comparison charts.
#
# Options:
#   --dry-run         - Validate configuration without running
#   --no-gateway      - Don't start gateway (assume it's already running)
#   --verbose         - Enable verbose output
#   --sentinel-only   - Run only the Sentinel cache test
#   --standalone-only - Run only the Standalone cache test
#   --skip-charts     - Skip chart generation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$(dirname "$PERF_DIR")")"

# Default values
DRY_RUN=false
START_GATEWAY=true
VERBOSE=false
RUN_SENTINEL=true
RUN_STANDALONE=true
SKIP_CHARTS=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --no-gateway)
            START_GATEWAY=false
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --sentinel-only)
            RUN_STANDALONE=false
            shift
            ;;
        --standalone-only)
            RUN_SENTINEL=false
            shift
            ;;
        --skip-charts)
            SKIP_CHARTS=true
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Logging functions
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

log_header() {
    echo ""
    echo -e "${CYAN}=========================================="
    echo -e "  $1"
    echo -e "==========================================${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check Docker Compose
    if ! docker compose version &> /dev/null && ! docker-compose version &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check if Yandex Tank image exists
    if ! docker image inspect yandex/yandex-tank:latest &> /dev/null; then
        log_info "Pulling Yandex Tank image..."
        docker pull yandex/yandex-tank:latest
    fi
    
    # Check Python for chart generation
    if [ "$SKIP_CHARTS" = false ]; then
        if ! command -v python3 &> /dev/null; then
            log_warn "Python3 not found - chart generation will be skipped"
            SKIP_CHARTS=true
        else
            # Check for matplotlib
            if ! python3 -c "import matplotlib" 2>/dev/null; then
                log_warn "matplotlib not installed - chart generation will be skipped"
                log_info "Install with: pip3 install matplotlib numpy"
                SKIP_CHARTS=true
            fi
        fi
    fi
    
    log_success "Prerequisites check passed"
}

# Check gateway connectivity
check_gateway() {
    local port=${1:-8080}
    
    log_info "Checking gateway connectivity on port $port..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/health" | grep -q "200"; then
            log_success "Gateway is responding on port $port"
            return 0
        fi
        
        if [ $attempt -eq 1 ]; then
            log_info "Waiting for gateway to be ready..."
        fi
        
        sleep 1
        ((attempt++))
    done
    
    log_error "Gateway is not responding on port $port after ${max_attempts} seconds"
    return 1
}

# Start gateway with specific config
start_gateway() {
    local config_file=$1
    
    if [ "$START_GATEWAY" = false ]; then
        log_info "Skipping gateway start (--no-gateway specified)"
        return 0
    fi
    
    log_info "Starting gateway with config: $config_file"
    
    # Stop any existing gateway
    stop_gateway
    
    # Start gateway in background
    cd "$PROJECT_ROOT"
    
    if [ -f "bin/gateway" ]; then
        log_info "Starting gateway from bin/gateway..."
        ./bin/gateway -config "test/performance/configs/$config_file" &
        GATEWAY_PID=$!
        echo $GATEWAY_PID > "$PERF_DIR/results/.gateway.pid"
    else
        log_info "Building and starting gateway..."
        make build
        ./bin/gateway -config "test/performance/configs/$config_file" &
        GATEWAY_PID=$!
        echo $GATEWAY_PID > "$PERF_DIR/results/.gateway.pid"
    fi
    
    # Wait for gateway to be ready
    check_gateway 8080
}

# Stop gateway
stop_gateway() {
    if [ -f "$PERF_DIR/results/.gateway.pid" ]; then
        local pid=$(cat "$PERF_DIR/results/.gateway.pid")
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping gateway (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 2
        fi
        rm -f "$PERF_DIR/results/.gateway.pid"
    fi
    
    # Also try to kill any gateway process
    pkill -f "bin/gateway" 2>/dev/null || true
}

# Run a single cache test
run_cache_test() {
    local test_name=$1
    local config_file=$2
    local tank_config=$3
    
    log_header "Running $test_name Test"
    
    # Create results directory with timestamp
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local results_dir="$PERF_DIR/results/${test_name}_${timestamp}"
    mkdir -p "$results_dir"
    mkdir -p "$results_dir/ammo"
    
    log_info "Results will be saved to: $results_dir"
    
    # Start gateway with appropriate config
    start_gateway "$config_file"
    
    # Copy config file to results directory
    cp "$PERF_DIR/configs/$tank_config" "$results_dir/load.yaml"
    
    # Copy ammo file
    cp "$PERF_DIR/ammo/cache-get.txt" "$results_dir/ammo/cache-get.txt"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "Dry run - would execute Yandex Tank test"
        echo "$results_dir"
        return 0
    fi
    
    # Build Docker command
    local docker_cmd="docker run --rm"
    docker_cmd+=" -v $results_dir:/var/loadtest"
    docker_cmd+=" -v $results_dir/ammo:/var/loadtest/ammo"
    docker_cmd+=" --add-host=host.docker.internal:host-gateway"
    docker_cmd+=" -w /var/loadtest"
    
    if [ "$VERBOSE" = true ]; then
        docker_cmd+=" -e VERBOSE=1"
    fi
    
    docker_cmd+=" yandex/yandex-tank:latest"
    docker_cmd+=" -c /var/loadtest/load.yaml"
    
    log_info "Starting Yandex Tank..."
    if [ "$VERBOSE" = true ]; then
        log_info "Command: $docker_cmd"
    fi
    
    # Run the test
    eval $docker_cmd
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        log_success "Test completed successfully"
        log_info "Results saved to: $results_dir"
    else
        log_error "Test failed with exit code: $exit_code"
    fi
    
    # Stop gateway after test
    stop_gateway
    
    # Return results directory path
    echo "$results_dir"
    return $exit_code
}

# Parse phout file and extract metrics
parse_results() {
    local results_dir=$1
    local output_file=$2
    
    local phout_file=$(find "$results_dir" -name "phout_*.log" -o -name "phout*.log" -o -name "phout*.txt" 2>/dev/null | head -1)
    
    if [ -z "$phout_file" ] || [ ! -f "$phout_file" ]; then
        log_warn "phout file not found in $results_dir"
        return 1
    fi
    
    log_info "Parsing results from $phout_file..."
    
    # Calculate statistics using awk
    awk -F'\t' '{print $3 / 1000}' "$phout_file" | sort -n > /tmp/perf_latencies.txt
    
    awk -F'\t' -v lat_file="/tmp/perf_latencies.txt" '
    BEGIN {
        total = 0
        errors = 0
        sum_latency = 0
        min_latency = 999999999
        max_latency = 0
        http_2xx = 0
        http_4xx = 0
        http_5xx = 0
        net_errors = 0
    }
    {
        total++
        latency = $3 / 1000  # interval_real (total time) in ms
        proto_code = $12
        net_code = $11
        
        sum_latency += latency
        
        if (latency < min_latency) min_latency = latency
        if (latency > max_latency) max_latency = latency
        
        if (proto_code >= 200 && proto_code < 300) http_2xx++
        else if (proto_code >= 400 && proto_code < 500) http_4xx++
        else if (proto_code >= 500) http_5xx++
        
        if (net_code != 0) net_errors++
        if (proto_code >= 400 || net_code != 0) errors++
    }
    END {
        if (total == 0) {
            print "No data found"
            exit 1
        }
        
        avg_latency = sum_latency / total
        error_rate = (errors / total) * 100
        
        n = 0
        while ((getline line < lat_file) > 0) {
            n++
            sorted[n] = line + 0
        }
        close(lat_file)
        
        p50 = sorted[int(n * 0.50)]
        p90 = sorted[int(n * 0.90)]
        p95 = sorted[int(n * 0.95)]
        p99 = sorted[int(n * 0.99)]
        
        printf "TOTAL_REQUESTS=%d\n", total
        printf "ERRORS=%d\n", errors
        printf "ERROR_RATE=%.2f\n", error_rate
        printf "AVG_LATENCY=%.2f\n", avg_latency
        printf "MIN_LATENCY=%.2f\n", min_latency
        printf "MAX_LATENCY=%.2f\n", max_latency
        printf "P50_LATENCY=%.2f\n", p50
        printf "P90_LATENCY=%.2f\n", p90
        printf "P95_LATENCY=%.2f\n", p95
        printf "P99_LATENCY=%.2f\n", p99
        printf "HTTP_2XX=%d\n", http_2xx
        printf "HTTP_4XX=%d\n", http_4xx
        printf "HTTP_5XX=%d\n", http_5xx
        printf "NET_ERRORS=%d\n", net_errors
    }
    ' "$phout_file" > "$output_file"
    
    rm -f /tmp/perf_latencies.txt
    
    log_success "Results parsed successfully"
}

# Generate comparison report
generate_comparison_report() {
    local sentinel_results=$1
    local standalone_results=$2
    local output_dir=$3
    
    log_header "Generating Comparison Report"
    
    mkdir -p "$output_dir"
    
    # Parse both result sets
    parse_results "$sentinel_results" "/tmp/sentinel_metrics.txt"
    parse_results "$standalone_results" "/tmp/standalone_metrics.txt"
    
    # Source the metrics
    source /tmp/sentinel_metrics.txt
    SENTINEL_TOTAL=$TOTAL_REQUESTS
    SENTINEL_AVG=$AVG_LATENCY
    SENTINEL_P50=$P50_LATENCY
    SENTINEL_P95=$P95_LATENCY
    SENTINEL_P99=$P99_LATENCY
    SENTINEL_ERRORS=$ERROR_RATE
    
    source /tmp/standalone_metrics.txt
    STANDALONE_TOTAL=$TOTAL_REQUESTS
    STANDALONE_AVG=$AVG_LATENCY
    STANDALONE_P50=$P50_LATENCY
    STANDALONE_P95=$P95_LATENCY
    STANDALONE_P99=$P99_LATENCY
    STANDALONE_ERRORS=$ERROR_RATE
    
    # Calculate differences
    AVG_DIFF=$(echo "scale=2; $SENTINEL_AVG - $STANDALONE_AVG" | bc)
    P50_DIFF=$(echo "scale=2; $SENTINEL_P50 - $STANDALONE_P50" | bc)
    P95_DIFF=$(echo "scale=2; $SENTINEL_P95 - $STANDALONE_P95" | bc)
    P99_DIFF=$(echo "scale=2; $SENTINEL_P99 - $STANDALONE_P99" | bc)
    
    # Generate report
    cat > "$output_dir/comparison_report.txt" << EOF
================================================================================
Redis Cache Performance Comparison Report
Generated: $(date)
================================================================================

SUMMARY
-------
This report compares the performance of Redis Sentinel cache vs Redis Standalone
cache for the avapigw API Gateway.

TEST CONFIGURATION
------------------
- Duration: 5 minutes (1m warmup + 3m sustain + 1m cooldown)
- Target RPS: 2000
- Endpoints: /api/v1/items (cached), /health (direct response)

RESULTS COMPARISON
------------------

                        | Redis Standalone | Redis Sentinel | Difference
------------------------|------------------|----------------|------------
Total Requests          | $STANDALONE_TOTAL | $SENTINEL_TOTAL | -
Average Latency (ms)    | $STANDALONE_AVG | $SENTINEL_AVG | $AVG_DIFF
P50 Latency (ms)        | $STANDALONE_P50 | $SENTINEL_P50 | $P50_DIFF
P95 Latency (ms)        | $STANDALONE_P95 | $SENTINEL_P95 | $P95_DIFF
P99 Latency (ms)        | $STANDALONE_P99 | $SENTINEL_P99 | $P99_DIFF
Error Rate (%)          | $STANDALONE_ERRORS | $SENTINEL_ERRORS | -

ANALYSIS
--------
EOF

    # Add analysis based on results
    if (( $(echo "$AVG_DIFF > 0" | bc -l) )); then
        echo "- Redis Sentinel adds approximately ${AVG_DIFF}ms average latency overhead" >> "$output_dir/comparison_report.txt"
    else
        echo "- Redis Sentinel performs similarly or better than Standalone" >> "$output_dir/comparison_report.txt"
    fi
    
    if (( $(echo "$P99_DIFF > 10" | bc -l) )); then
        echo "- P99 latency is significantly higher with Sentinel (${P99_DIFF}ms difference)" >> "$output_dir/comparison_report.txt"
        echo "  This is expected due to Sentinel's master discovery overhead" >> "$output_dir/comparison_report.txt"
    fi
    
    cat >> "$output_dir/comparison_report.txt" << EOF

RECOMMENDATIONS
---------------
- For high-availability requirements, Redis Sentinel is recommended despite
  the small latency overhead
- For maximum performance in non-HA scenarios, Redis Standalone is preferred
- Consider the trade-off between availability and latency for your use case

RESULT DIRECTORIES
------------------
- Standalone Results: $standalone_results
- Sentinel Results: $sentinel_results

================================================================================
EOF

    log_success "Comparison report generated: $output_dir/comparison_report.txt"
    
    # Display report
    cat "$output_dir/comparison_report.txt"
    
    # Cleanup
    rm -f /tmp/sentinel_metrics.txt /tmp/standalone_metrics.txt
}

# Generate comparison charts
generate_charts() {
    local sentinel_results=$1
    local standalone_results=$2
    local output_dir=$3
    
    if [ "$SKIP_CHARTS" = true ]; then
        log_info "Skipping chart generation"
        return 0
    fi
    
    log_header "Generating Comparison Charts"
    
    mkdir -p "$output_dir/charts"
    
    # Create Python script for chart generation
    cat > /tmp/generate_cache_charts.py << 'PYTHON_SCRIPT'
#!/usr/bin/env python3
import sys
import os
import glob
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

def parse_phout(results_dir):
    """Parse phout file and return latencies."""
    phout_files = glob.glob(os.path.join(results_dir, '**/phout*.log'), recursive=True)
    phout_files += glob.glob(os.path.join(results_dir, '**/phout*.txt'), recursive=True)
    
    if not phout_files:
        print(f"Warning: No phout file found in {results_dir}")
        return []
    
    latencies = []
    with open(phout_files[0], 'r') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 3:
                try:
                    latency = float(parts[2]) / 1000  # Convert to ms
                    latencies.append(latency)
                except ValueError:
                    continue
    
    return latencies

def generate_latency_comparison(sentinel_latencies, standalone_latencies, output_dir):
    """Generate latency distribution comparison chart."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # Histogram comparison
    ax1 = axes[0, 0]
    bins = np.linspace(0, max(np.percentile(sentinel_latencies, 99), np.percentile(standalone_latencies, 99)), 50)
    ax1.hist(standalone_latencies, bins=bins, alpha=0.7, label='Redis Standalone', color='blue')
    ax1.hist(sentinel_latencies, bins=bins, alpha=0.7, label='Redis Sentinel', color='orange')
    ax1.set_xlabel('Latency (ms)')
    ax1.set_ylabel('Frequency')
    ax1.set_title('Latency Distribution Comparison')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Box plot comparison
    ax2 = axes[0, 1]
    bp = ax2.boxplot([standalone_latencies, sentinel_latencies], 
                      labels=['Standalone', 'Sentinel'],
                      patch_artist=True)
    bp['boxes'][0].set_facecolor('blue')
    bp['boxes'][0].set_alpha(0.7)
    bp['boxes'][1].set_facecolor('orange')
    bp['boxes'][1].set_alpha(0.7)
    ax2.set_ylabel('Latency (ms)')
    ax2.set_title('Latency Box Plot Comparison')
    ax2.grid(True, alpha=0.3)
    
    # Percentile comparison
    ax3 = axes[1, 0]
    percentiles = [50, 75, 90, 95, 99]
    standalone_pcts = [np.percentile(standalone_latencies, p) for p in percentiles]
    sentinel_pcts = [np.percentile(sentinel_latencies, p) for p in percentiles]
    
    x = np.arange(len(percentiles))
    width = 0.35
    
    bars1 = ax3.bar(x - width/2, standalone_pcts, width, label='Standalone', color='blue', alpha=0.7)
    bars2 = ax3.bar(x + width/2, sentinel_pcts, width, label='Sentinel', color='orange', alpha=0.7)
    
    ax3.set_xlabel('Percentile')
    ax3.set_ylabel('Latency (ms)')
    ax3.set_title('Latency Percentiles Comparison')
    ax3.set_xticks(x)
    ax3.set_xticklabels([f'P{p}' for p in percentiles])
    ax3.legend()
    ax3.grid(True, alpha=0.3)
    
    # Add value labels on bars
    for bar in bars1:
        height = bar.get_height()
        ax3.annotate(f'{height:.1f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8)
    for bar in bars2:
        height = bar.get_height()
        ax3.annotate(f'{height:.1f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8)
    
    # Summary statistics
    ax4 = axes[1, 1]
    ax4.axis('off')
    
    stats_text = f"""
    Summary Statistics
    ==================
    
    Redis Standalone:
      - Total Requests: {len(standalone_latencies):,}
      - Avg Latency: {np.mean(standalone_latencies):.2f} ms
      - P50: {np.percentile(standalone_latencies, 50):.2f} ms
      - P95: {np.percentile(standalone_latencies, 95):.2f} ms
      - P99: {np.percentile(standalone_latencies, 99):.2f} ms
    
    Redis Sentinel:
      - Total Requests: {len(sentinel_latencies):,}
      - Avg Latency: {np.mean(sentinel_latencies):.2f} ms
      - P50: {np.percentile(sentinel_latencies, 50):.2f} ms
      - P95: {np.percentile(sentinel_latencies, 95):.2f} ms
      - P99: {np.percentile(sentinel_latencies, 99):.2f} ms
    
    Difference (Sentinel - Standalone):
      - Avg: {np.mean(sentinel_latencies) - np.mean(standalone_latencies):+.2f} ms
      - P95: {np.percentile(sentinel_latencies, 95) - np.percentile(standalone_latencies, 95):+.2f} ms
      - P99: {np.percentile(sentinel_latencies, 99) - np.percentile(standalone_latencies, 99):+.2f} ms
    """
    
    ax4.text(0.1, 0.9, stats_text, transform=ax4.transAxes, fontsize=10,
             verticalalignment='top', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.suptitle('Redis Cache Performance Comparison: Sentinel vs Standalone', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'charts', 'cache_comparison.png'), dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"Chart saved: {os.path.join(output_dir, 'charts', 'cache_comparison.png')}")

def generate_latency_over_time(sentinel_latencies, standalone_latencies, output_dir):
    """Generate latency over time comparison chart."""
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8), sharex=True)
    
    # Sample every Nth point for readability
    sample_rate = max(1, len(standalone_latencies) // 1000)
    
    standalone_sampled = standalone_latencies[::sample_rate]
    sentinel_sampled = sentinel_latencies[::sample_rate]
    
    # Time axis (assuming ~2000 RPS, 5 min test)
    time_standalone = np.linspace(0, 300, len(standalone_sampled))
    time_sentinel = np.linspace(0, 300, len(sentinel_sampled))
    
    # Rolling average
    window = 50
    standalone_rolling = np.convolve(standalone_sampled, np.ones(window)/window, mode='valid')
    sentinel_rolling = np.convolve(sentinel_sampled, np.ones(window)/window, mode='valid')
    
    ax1.plot(time_standalone[:len(standalone_rolling)], standalone_rolling, 
             color='blue', alpha=0.8, label='Standalone (rolling avg)')
    ax1.set_ylabel('Latency (ms)')
    ax1.set_title('Redis Standalone Cache - Latency Over Time')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    ax2.plot(time_sentinel[:len(sentinel_rolling)], sentinel_rolling, 
             color='orange', alpha=0.8, label='Sentinel (rolling avg)')
    ax2.set_xlabel('Time (seconds)')
    ax2.set_ylabel('Latency (ms)')
    ax2.set_title('Redis Sentinel Cache - Latency Over Time')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    plt.suptitle('Latency Over Time Comparison', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'charts', 'latency_over_time.png'), dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"Chart saved: {os.path.join(output_dir, 'charts', 'latency_over_time.png')}")

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: generate_cache_charts.py <sentinel_results_dir> <standalone_results_dir> <output_dir>")
        sys.exit(1)
    
    sentinel_dir = sys.argv[1]
    standalone_dir = sys.argv[2]
    output_dir = sys.argv[3]
    
    print(f"Parsing Sentinel results from: {sentinel_dir}")
    sentinel_latencies = parse_phout(sentinel_dir)
    
    print(f"Parsing Standalone results from: {standalone_dir}")
    standalone_latencies = parse_phout(standalone_dir)
    
    if not sentinel_latencies or not standalone_latencies:
        print("Error: Could not parse results")
        sys.exit(1)
    
    print(f"Generating charts to: {output_dir}")
    generate_latency_comparison(sentinel_latencies, standalone_latencies, output_dir)
    generate_latency_over_time(sentinel_latencies, standalone_latencies, output_dir)
    
    print("Chart generation complete!")
PYTHON_SCRIPT

    chmod +x /tmp/generate_cache_charts.py
    
    # Run chart generation
    python3 /tmp/generate_cache_charts.py "$sentinel_results" "$standalone_results" "$output_dir"
    
    rm -f /tmp/generate_cache_charts.py
    
    log_success "Charts generated in $output_dir/charts/"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    stop_gateway
}

# Set trap for cleanup
trap cleanup EXIT

# Main execution
main() {
    log_header "Redis Cache Performance Test Suite"
    
    echo "This test compares Redis Sentinel cache vs Redis Standalone cache"
    echo "for the avapigw API Gateway."
    echo ""
    
    check_prerequisites
    
    # Create comparison results directory
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local comparison_dir="$PERF_DIR/results/cache_comparison_${timestamp}"
    mkdir -p "$comparison_dir"
    
    local sentinel_results=""
    local standalone_results=""
    
    # Run Redis Standalone test (baseline)
    if [ "$RUN_STANDALONE" = true ]; then
        standalone_results=$(run_cache_test "redis-standalone-cache" "gateway-perftest-redis-standalone.yaml" "redis-standalone-cache-throughput.yaml")
        
        # Brief pause between tests
        if [ "$RUN_SENTINEL" = true ]; then
            log_info "Pausing 10 seconds before next test..."
            sleep 10
        fi
    fi
    
    # Run Redis Sentinel test
    if [ "$RUN_SENTINEL" = true ]; then
        sentinel_results=$(run_cache_test "sentinel-cache" "gateway-perftest-sentinel.yaml" "sentinel-cache-throughput.yaml")
    fi
    
    # Generate comparison if both tests ran
    if [ "$RUN_STANDALONE" = true ] && [ "$RUN_SENTINEL" = true ]; then
        generate_comparison_report "$sentinel_results" "$standalone_results" "$comparison_dir"
        generate_charts "$sentinel_results" "$standalone_results" "$comparison_dir"
        
        log_header "Test Suite Complete"
        echo ""
        echo "Results:"
        echo "  - Standalone: $standalone_results"
        echo "  - Sentinel: $sentinel_results"
        echo "  - Comparison: $comparison_dir"
        echo ""
        echo "View the comparison report:"
        echo "  cat $comparison_dir/comparison_report.txt"
        echo ""
        if [ "$SKIP_CHARTS" = false ]; then
            echo "View the charts:"
            echo "  open $comparison_dir/charts/cache_comparison.png"
            echo "  open $comparison_dir/charts/latency_over_time.png"
        fi
    else
        log_header "Test Complete"
        if [ -n "$standalone_results" ]; then
            echo "Standalone results: $standalone_results"
        fi
        if [ -n "$sentinel_results" ]; then
            echo "Sentinel results: $sentinel_results"
        fi
    fi
}

main
