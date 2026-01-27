#!/bin/bash
# run-audit-perftest.sh - Run audit logging performance comparison test
# Purpose: Compare gateway performance with and without audit logging
# Usage: ./run-audit-perftest.sh [options]
#
# Options:
#   --skip-baseline    Skip baseline test (audit disabled)
#   --skip-audit       Skip audit test (audit enabled)
#   --skip-gateway     Don't start/stop gateway (assume running)
#   --dry-run          Show what would be run without executing
#   --results-dir=<d>  Custom results directory

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
CONFIGS_DIR="$PERF_DIR/configs"
AMMO_DIR="$PERF_DIR/ammo"
RESULTS_BASE_DIR="$PROJECT_ROOT/.yandextank"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Default values
SKIP_BASELINE=false
SKIP_AUDIT=false
SKIP_GATEWAY=false
DRY_RUN=false
RESULTS_DIR="${RESULTS_BASE_DIR}/audit-perftest_${TIMESTAMP}"

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-baseline)
            SKIP_BASELINE=true
            shift
            ;;
        --skip-audit)
            SKIP_AUDIT=true
            shift
            ;;
        --skip-gateway)
            SKIP_GATEWAY=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --results-dir=*)
            RESULTS_DIR="${1#*=}"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_header() {
    echo ""
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker is not running"
        exit 1
    fi

    if ! docker images | grep -q "yandex/yandex-tank"; then
        log_warn "Yandex Tank image not found, pulling..."
        docker pull yandex/yandex-tank
    fi

    # Check backends
    for port in 8801 8802; do
        if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/health" 2>/dev/null | grep -q "200"; then
            log_success "Backend on port ${port} is available"
        else
            log_error "Backend on port ${port} is not available"
            exit 1
        fi
    done

    log_success "Prerequisites check passed"
}

# Start gateway with specific config
start_gateway() {
    local config_file=$1
    local log_file=$2

    if [ "$SKIP_GATEWAY" = true ]; then
        log_info "Skipping gateway start (--skip-gateway)"
        return 0
    fi

    # Stop any existing gateway
    stop_gateway

    log_info "Starting gateway with config: $(basename "$config_file")"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would start gateway with: $config_file"
        return 0
    fi

    cd "$PROJECT_ROOT"
    nohup ./bin/gateway -config "$config_file" -log-level warn > "$log_file" 2>&1 &
    local pid=$!
    echo $pid > "$RESULTS_DIR/.gateway.pid"

    # Wait for gateway to be ready
    local count=0
    while ! curl -s -o /dev/null http://127.0.0.1:8080/health 2>/dev/null && [ $count -lt 30 ]; do
        sleep 1
        ((count++))
        if ! kill -0 "$pid" 2>/dev/null; then
            log_error "Gateway process died unexpectedly"
            cat "$log_file"
            exit 1
        fi
    done

    if curl -s -o /dev/null http://127.0.0.1:8080/health 2>/dev/null; then
        log_success "Gateway is ready (PID: $pid)"
    else
        log_error "Gateway failed to start within 30 seconds"
        exit 1
    fi
}

# Stop gateway
stop_gateway() {
    if [ -f "$RESULTS_DIR/.gateway.pid" ]; then
        local pid=$(cat "$RESULTS_DIR/.gateway.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            sleep 2
            kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$RESULTS_DIR/.gateway.pid"
    fi

    # Also kill any lingering gateway processes
    pkill -f "gateway.*gateway-perftest-audit" 2>/dev/null || true
    sleep 1
}

# Run Yandex Tank test
run_tank_test() {
    local test_name=$1
    local results_subdir=$2

    mkdir -p "$results_subdir"

    log_info "Running Yandex Tank test: $test_name"
    log_info "Results: $results_subdir"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would run Yandex Tank for: $test_name"
        return 0
    fi

    # Copy config and ammo
    cp "$CONFIGS_DIR/audit-throughput.yaml" "$results_subdir/load.yaml"
    mkdir -p "$results_subdir/ammo"
    cp "$AMMO_DIR/http-get.txt" "$results_subdir/ammo/http-get.txt"

    # Run Yandex Tank
    docker run --rm \
        --add-host=host.docker.internal:host-gateway \
        -v "$results_subdir:/var/loadtest" \
        -v "$results_subdir/ammo:/var/loadtest/ammo" \
        -w /var/loadtest \
        yandex/yandex-tank:latest \
        -c /var/loadtest/load.yaml \
        2>&1 | tee "$results_subdir/tank.log"

    log_success "Test '$test_name' completed"
}

# Parse phout.txt and extract metrics
parse_phout() {
    local phout_file=$1
    local output_json=$2

    if [ ! -f "$phout_file" ]; then
        # Try to find phout in subdirectories
        phout_file=$(find "$(dirname "$phout_file")" -name "phout*.log" -o -name "phout.txt" 2>/dev/null | head -1)
        if [ -z "$phout_file" ] || [ ! -f "$phout_file" ]; then
            log_warn "phout file not found"
            return 1
        fi
    fi

    log_info "Parsing results from: $phout_file"

    python3 - "$phout_file" "$output_json" << 'PYTHON_SCRIPT'
import sys
import json
import os

phout_file = sys.argv[1]
output_file = sys.argv[2]

latencies = []
connect_times = []
response_codes = {}
net_codes = {}
total_requests = 0
start_time = None
end_time = None

with open(phout_file, 'r') as f:
    for line in f:
        parts = line.strip().split('\t')
        if len(parts) < 12:
            continue
        try:
            timestamp = float(parts[0])
            interval_real = int(parts[2])  # total response time in microseconds
            connect_time = int(parts[3])
            net_code = parts[10]
            proto_code = parts[11]

            if start_time is None:
                start_time = timestamp
            end_time = timestamp

            latencies.append(interval_real)
            connect_times.append(connect_time)
            total_requests += 1

            response_codes[proto_code] = response_codes.get(proto_code, 0) + 1
            net_codes[net_code] = net_codes.get(net_code, 0) + 1
        except (ValueError, IndexError):
            continue

if total_requests == 0:
    print("No valid requests found in phout file")
    sys.exit(1)

latencies.sort()
duration = end_time - start_time if start_time and end_time else 1

def percentile(data, p):
    idx = int(len(data) * p / 100)
    return data[min(idx, len(data) - 1)]

# Convert microseconds to milliseconds
results = {
    "total_requests": total_requests,
    "duration_seconds": round(duration, 2),
    "avg_rps": round(total_requests / duration, 2) if duration > 0 else 0,
    "latency": {
        "avg_ms": round(sum(latencies) / len(latencies) / 1000, 3),
        "min_ms": round(min(latencies) / 1000, 3),
        "max_ms": round(max(latencies) / 1000, 3),
        "p50_ms": round(percentile(latencies, 50) / 1000, 3),
        "p75_ms": round(percentile(latencies, 75) / 1000, 3),
        "p90_ms": round(percentile(latencies, 90) / 1000, 3),
        "p95_ms": round(percentile(latencies, 95) / 1000, 3),
        "p99_ms": round(percentile(latencies, 99) / 1000, 3),
        "p995_ms": round(percentile(latencies, 99.5) / 1000, 3),
    },
    "connect_time": {
        "avg_ms": round(sum(connect_times) / len(connect_times) / 1000, 3),
        "p95_ms": round(percentile(sorted(connect_times), 95) / 1000, 3),
    },
    "response_codes": response_codes,
    "net_codes": net_codes,
    "error_rate": round((1 - response_codes.get("200", 0) / total_requests) * 100, 2) if total_requests > 0 else 0,
}

with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

print(json.dumps(results, indent=2))
PYTHON_SCRIPT
}

# Compare results
compare_results() {
    local baseline_json=$1
    local audit_json=$2
    local comparison_json=$3

    log_header "Comparing Results: Baseline vs Audit Enabled"

    python3 - "$baseline_json" "$audit_json" "$comparison_json" << 'PYTHON_SCRIPT'
import sys
import json

baseline_file = sys.argv[1]
audit_file = sys.argv[2]
output_file = sys.argv[3]

with open(baseline_file) as f:
    baseline = json.load(f)
with open(audit_file) as f:
    audit = json.load(f)

def pct_change(baseline_val, audit_val):
    if baseline_val == 0:
        return 0
    return round((audit_val - baseline_val) / baseline_val * 100, 2)

comparison = {
    "baseline": baseline,
    "audit_enabled": audit,
    "comparison": {
        "total_requests": {
            "baseline": baseline["total_requests"],
            "audit": audit["total_requests"],
            "change_pct": pct_change(baseline["total_requests"], audit["total_requests"])
        },
        "avg_rps": {
            "baseline": baseline["avg_rps"],
            "audit": audit["avg_rps"],
            "change_pct": pct_change(baseline["avg_rps"], audit["avg_rps"])
        },
        "latency": {}
    }
}

for metric in ["avg_ms", "p50_ms", "p75_ms", "p90_ms", "p95_ms", "p99_ms", "p995_ms"]:
    b_val = baseline["latency"][metric]
    a_val = audit["latency"][metric]
    comparison["comparison"]["latency"][metric] = {
        "baseline": b_val,
        "audit": a_val,
        "change_pct": pct_change(b_val, a_val),
        "overhead_ms": round(a_val - b_val, 3)
    }

# Determine pass/fail (5% threshold)
max_overhead_pct = max(
    abs(comparison["comparison"]["latency"][m]["change_pct"])
    for m in ["avg_ms", "p50_ms", "p95_ms", "p99_ms"]
)
comparison["verdict"] = {
    "max_latency_overhead_pct": max_overhead_pct,
    "threshold_pct": 5.0,
    "passed": max_overhead_pct <= 5.0,
    "message": "PASS: Audit logging overhead is within 5% threshold" if max_overhead_pct <= 5.0
               else f"FAIL: Audit logging overhead ({max_overhead_pct}%) exceeds 5% threshold"
}

with open(output_file, 'w') as f:
    json.dump(comparison, f, indent=2)

# Print summary
print("\n" + "=" * 70)
print("  AUDIT LOGGING PERFORMANCE COMPARISON")
print("=" * 70)
print(f"\n{'Metric':<25} {'Baseline':>12} {'Audit':>12} {'Change':>10} {'Overhead':>12}")
print("-" * 70)
print(f"{'Total Requests':<25} {baseline['total_requests']:>12,} {audit['total_requests']:>12,} {pct_change(baseline['total_requests'], audit['total_requests']):>9.2f}%")
print(f"{'Avg RPS':<25} {baseline['avg_rps']:>12.1f} {audit['avg_rps']:>12.1f} {pct_change(baseline['avg_rps'], audit['avg_rps']):>9.2f}%")
print()
print(f"{'Latency Metric':<25} {'Baseline':>12} {'Audit':>12} {'Change':>10} {'Overhead':>12}")
print("-" * 70)
for metric in ["avg_ms", "p50_ms", "p75_ms", "p90_ms", "p95_ms", "p99_ms", "p995_ms"]:
    c = comparison["comparison"]["latency"][metric]
    label = metric.replace("_ms", "").replace("p", "P").replace("avg", "Average")
    print(f"  {label:<23} {c['baseline']:>10.3f}ms {c['audit']:>10.3f}ms {c['change_pct']:>9.2f}% {c['overhead_ms']:>+10.3f}ms")

print()
print("=" * 70)
verdict = comparison["verdict"]
if verdict["passed"]:
    print(f"  ✅ {verdict['message']}")
else:
    print(f"  ❌ {verdict['message']}")
print(f"  Max overhead: {verdict['max_latency_overhead_pct']:.2f}% (threshold: {verdict['threshold_pct']}%)")
print("=" * 70)
print()
PYTHON_SCRIPT
}

# Generate comparison charts
generate_charts() {
    local comparison_json=$1
    local charts_dir=$2

    mkdir -p "$charts_dir"

    log_info "Generating comparison charts..."

    python3 - "$comparison_json" "$charts_dir" << 'PYTHON_SCRIPT'
import sys
import json
import os

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("matplotlib/numpy not available, skipping chart generation")
    sys.exit(0)

comparison_file = sys.argv[1]
charts_dir = sys.argv[2]

with open(comparison_file) as f:
    data = json.load(f)

baseline = data["baseline"]
audit = data["audit_enabled"]
comparison = data["comparison"]

# Chart 1: Latency Comparison Bar Chart
fig, ax = plt.subplots(figsize=(12, 6))
metrics = ["avg_ms", "p50_ms", "p75_ms", "p90_ms", "p95_ms", "p99_ms"]
labels = ["Average", "P50", "P75", "P90", "P95", "P99"]
baseline_vals = [baseline["latency"][m] for m in metrics]
audit_vals = [audit["latency"][m] for m in metrics]

x = np.arange(len(labels))
width = 0.35

bars1 = ax.bar(x - width/2, baseline_vals, width, label='Baseline (No Audit)', color='#2196F3', alpha=0.8)
bars2 = ax.bar(x + width/2, audit_vals, width, label='Audit Enabled', color='#FF9800', alpha=0.8)

ax.set_xlabel('Latency Percentile', fontsize=12)
ax.set_ylabel('Latency (ms)', fontsize=12)
ax.set_title('Audit Logging Performance Impact - Latency Comparison', fontsize=14, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.legend()
ax.grid(axis='y', alpha=0.3)

# Add value labels on bars
for bar in bars1:
    height = bar.get_height()
    ax.annotate(f'{height:.1f}',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3), textcoords="offset points",
                ha='center', va='bottom', fontsize=8)
for bar in bars2:
    height = bar.get_height()
    ax.annotate(f'{height:.1f}',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3), textcoords="offset points",
                ha='center', va='bottom', fontsize=8)

plt.tight_layout()
plt.savefig(os.path.join(charts_dir, 'latency_comparison.png'), dpi=150)
plt.close()

# Chart 2: Overhead Percentage
fig, ax = plt.subplots(figsize=(10, 6))
overhead_pcts = [comparison["latency"][m]["change_pct"] for m in metrics]
colors = ['#4CAF50' if abs(v) <= 5 else '#F44336' for v in overhead_pcts]

bars = ax.bar(labels, overhead_pcts, color=colors, alpha=0.8, edgecolor='black', linewidth=0.5)
ax.axhline(y=5, color='red', linestyle='--', linewidth=1.5, label='5% Threshold')
ax.axhline(y=-5, color='red', linestyle='--', linewidth=1.5)
ax.axhline(y=0, color='black', linestyle='-', linewidth=0.5)

ax.set_xlabel('Latency Percentile', fontsize=12)
ax.set_ylabel('Overhead (%)', fontsize=12)
ax.set_title('Audit Logging Latency Overhead', fontsize=14, fontweight='bold')
ax.legend()
ax.grid(axis='y', alpha=0.3)

for bar, val in zip(bars, overhead_pcts):
    height = bar.get_height()
    ax.annotate(f'{val:+.2f}%',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3 if height >= 0 else -15), textcoords="offset points",
                ha='center', va='bottom', fontsize=10, fontweight='bold')

verdict = data["verdict"]
verdict_text = f"{'✅ PASS' if verdict['passed'] else '❌ FAIL'}: Max overhead {verdict['max_latency_overhead_pct']:.2f}%"
ax.text(0.5, -0.12, verdict_text, transform=ax.transAxes, ha='center', fontsize=12, fontweight='bold',
        color='green' if verdict['passed'] else 'red')

plt.tight_layout()
plt.savefig(os.path.join(charts_dir, 'overhead_percentage.png'), dpi=150)
plt.close()

# Chart 3: Summary Dashboard
fig, axes = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle('Audit Logging Performance Test - Summary Dashboard', fontsize=16, fontweight='bold')

# Subplot 1: RPS comparison
ax1 = axes[0, 0]
rps_data = [baseline["avg_rps"], audit["avg_rps"]]
bars = ax1.bar(['Baseline', 'Audit Enabled'], rps_data,
               color=['#2196F3', '#FF9800'], alpha=0.8, edgecolor='black', linewidth=0.5)
ax1.set_ylabel('Requests/Second')
ax1.set_title('Throughput (RPS)')
for bar, val in zip(bars, rps_data):
    ax1.annotate(f'{val:.0f}', xy=(bar.get_x() + bar.get_width() / 2, val),
                 xytext=(0, 3), textcoords="offset points", ha='center', fontsize=11, fontweight='bold')
ax1.grid(axis='y', alpha=0.3)

# Subplot 2: Latency percentiles
ax2 = axes[0, 1]
x = np.arange(len(labels))
ax2.plot(x, baseline_vals, 'o-', color='#2196F3', label='Baseline', linewidth=2, markersize=6)
ax2.plot(x, audit_vals, 's-', color='#FF9800', label='Audit Enabled', linewidth=2, markersize=6)
ax2.set_xticks(x)
ax2.set_xticklabels(labels)
ax2.set_ylabel('Latency (ms)')
ax2.set_title('Latency Distribution')
ax2.legend()
ax2.grid(alpha=0.3)

# Subplot 3: Overhead bars
ax3 = axes[1, 0]
bars = ax3.bar(labels, overhead_pcts,
               color=['#4CAF50' if abs(v) <= 5 else '#F44336' for v in overhead_pcts],
               alpha=0.8, edgecolor='black', linewidth=0.5)
ax3.axhline(y=5, color='red', linestyle='--', linewidth=1, label='±5% Threshold')
ax3.axhline(y=-5, color='red', linestyle='--', linewidth=1)
ax3.axhline(y=0, color='black', linestyle='-', linewidth=0.5)
ax3.set_ylabel('Overhead (%)')
ax3.set_title('Latency Overhead')
ax3.legend(fontsize=8)
ax3.grid(axis='y', alpha=0.3)

# Subplot 4: Summary text
ax4 = axes[1, 1]
ax4.axis('off')
summary_text = f"""
Test Summary
{'─' * 40}
Baseline Total Requests:  {baseline['total_requests']:,}
Audit Total Requests:     {audit['total_requests']:,}

Baseline Avg RPS:         {baseline['avg_rps']:.1f}
Audit Avg RPS:            {audit['avg_rps']:.1f}
RPS Change:               {comparison['avg_rps']['change_pct']:+.2f}%

Baseline Avg Latency:     {baseline['latency']['avg_ms']:.3f} ms
Audit Avg Latency:        {audit['latency']['avg_ms']:.3f} ms
Latency Overhead:         {comparison['latency']['avg_ms']['overhead_ms']:+.3f} ms

Baseline P99 Latency:     {baseline['latency']['p99_ms']:.3f} ms
Audit P99 Latency:        {audit['latency']['p99_ms']:.3f} ms
P99 Overhead:             {comparison['latency']['p99_ms']['overhead_ms']:+.3f} ms

{'─' * 40}
Verdict: {'PASS ✅' if verdict['passed'] else 'FAIL ❌'}
Max Overhead: {verdict['max_latency_overhead_pct']:.2f}%
Threshold: {verdict['threshold_pct']}%
"""
ax4.text(0.1, 0.95, summary_text, transform=ax4.transAxes, fontsize=10,
         verticalalignment='top', fontfamily='monospace',
         bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

plt.tight_layout()
plt.savefig(os.path.join(charts_dir, 'summary_dashboard.png'), dpi=150)
plt.close()

print(f"Charts saved to: {charts_dir}")
print(f"  - latency_comparison.png")
print(f"  - overhead_percentage.png")
print(f"  - summary_dashboard.png")
PYTHON_SCRIPT
}

# Main
main() {
    log_header "Audit Logging Performance Test"
    echo "Purpose: Verify audit logging doesn't degrade performance by >5%"
    echo "Method:  A/B comparison (baseline vs audit enabled)"
    echo ""

    check_prerequisites

    mkdir -p "$RESULTS_DIR"
    local baseline_dir="$RESULTS_DIR/baseline"
    local audit_dir="$RESULTS_DIR/audit-enabled"

    # Phase 1: Baseline test (audit disabled)
    if [ "$SKIP_BASELINE" = false ]; then
        log_header "Phase 1: Baseline Test (Audit Disabled)"
        start_gateway "$CONFIGS_DIR/gateway-perftest-audit-disabled.yaml" "$RESULTS_DIR/gateway-baseline.log"
        sleep 3  # Let gateway warm up
        run_tank_test "baseline" "$baseline_dir"
        stop_gateway
        sleep 3  # Cool down between tests
    else
        log_info "Skipping baseline test"
    fi

    # Phase 2: Audit enabled test
    if [ "$SKIP_AUDIT" = false ]; then
        log_header "Phase 2: Audit Enabled Test"
        start_gateway "$CONFIGS_DIR/gateway-perftest-audit-enabled.yaml" "$RESULTS_DIR/gateway-audit.log"
        sleep 3  # Let gateway warm up
        run_tank_test "audit-enabled" "$audit_dir"
        stop_gateway
    else
        log_info "Skipping audit test"
    fi

    # Phase 3: Parse and compare results
    if [ "$DRY_RUN" = false ]; then
        log_header "Phase 3: Analyzing Results"

        # Find phout files
        local baseline_phout=$(find "$baseline_dir" -name "phout*.log" -o -name "phout.txt" 2>/dev/null | head -1)
        local audit_phout=$(find "$audit_dir" -name "phout*.log" -o -name "phout.txt" 2>/dev/null | head -1)

        if [ -n "$baseline_phout" ] && [ -n "$audit_phout" ]; then
            parse_phout "$baseline_phout" "$RESULTS_DIR/baseline-results.json"
            echo ""
            parse_phout "$audit_phout" "$RESULTS_DIR/audit-results.json"
            echo ""

            # Compare
            compare_results "$RESULTS_DIR/baseline-results.json" "$RESULTS_DIR/audit-results.json" "$RESULTS_DIR/comparison.json"

            # Generate charts
            generate_charts "$RESULTS_DIR/comparison.json" "$RESULTS_DIR/charts"

            log_success "All results saved to: $RESULTS_DIR"
        else
            log_warn "Could not find phout files for analysis"
            [ -z "$baseline_phout" ] && log_warn "  Missing baseline phout"
            [ -z "$audit_phout" ] && log_warn "  Missing audit phout"
        fi
    fi
}

# Cleanup on exit
cleanup() {
    stop_gateway 2>/dev/null || true
}
trap cleanup EXIT

main
