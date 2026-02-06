#!/bin/bash
# run-operator-test.sh - Operator Performance Test Runner
# Usage: ./run-operator-test.sh [test-type] [options]
#
# Test types:
#   local           - Run local Go-based performance tests
#   reconciliation  - Run reconciliation performance tests
#   grpc            - Run gRPC communication tests
#   config-push     - Run configuration push tests
#   k8s             - Run Kubernetes-based tests (requires K8s cluster)
#   all             - Run all tests
#
# Options:
#   --duration=<time>   - Override test duration (e.g., --duration=5m)
#   --crd-count=<num>   - Number of CRDs to test with (default: 100)
#   --concurrency=<num> - Concurrency level (default: 10)
#   --verbose           - Enable verbose output
#   --no-build          - Skip building the operator
#   --output=<dir>      - Output directory for results

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
TEST_TYPE="${1:-local}"
DURATION="30s"
CRD_COUNT=100
CONCURRENCY=10
VERBOSE=false
BUILD_OPERATOR=true
OUTPUT_DIR=""

# Parse options
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --duration=*)
            DURATION="${1#*=}"
            shift
            ;;
        --crd-count=*)
            CRD_COUNT="${1#*=}"
            shift
            ;;
        --concurrency=*)
            CONCURRENCY="${1#*=}"
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --no-build)
            BUILD_OPERATOR=false
            shift
            ;;
        --output=*)
            OUTPUT_DIR="${1#*=}"
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

# Setup output directory
setup_output_dir() {
    if [ -z "$OUTPUT_DIR" ]; then
        local timestamp=$(date +%Y%m%d_%H%M%S)
        OUTPUT_DIR="$PERF_DIR/results/operator_${TEST_TYPE}_${timestamp}"
    fi
    mkdir -p "$OUTPUT_DIR"
    log_info "Results will be saved to: $OUTPUT_DIR"
}

# Build operator if needed
build_operator() {
    if [ "$BUILD_OPERATOR" = false ]; then
        log_info "Skipping operator build (--no-build specified)"
        return 0
    fi

    log_info "Building operator..."
    cd "$PROJECT_ROOT"
    
    if ! make build-operator; then
        log_error "Failed to build operator"
        exit 1
    fi
    
    log_success "Operator built successfully"
}

# Run local Go-based performance tests
run_local_tests() {
    log_info "Running local performance tests..."
    
    cd "$PROJECT_ROOT"
    
    local test_flags="-v -tags=performance -timeout=30m"
    
    if [ "$VERBOSE" = true ]; then
        test_flags="$test_flags -v"
    fi
    
    # Run reconciliation tests
    log_info "Running reconciliation tests..."
    go test $test_flags \
        -run "TestReconciliation" \
        ./test/performance/operator/... \
        2>&1 | tee "$OUTPUT_DIR/reconciliation.log"
    
    # Run gRPC tests
    log_info "Running gRPC tests..."
    go test $test_flags \
        -run "TestGRPC" \
        ./test/performance/operator/... \
        2>&1 | tee "$OUTPUT_DIR/grpc.log"
    
    # Run config push tests
    log_info "Running config push tests..."
    go test $test_flags \
        -run "TestConfigPush" \
        ./test/performance/operator/... \
        2>&1 | tee "$OUTPUT_DIR/config_push.log"
    
    log_success "Local tests completed"
}

# Run reconciliation performance tests
run_reconciliation_tests() {
    log_info "Running reconciliation performance tests..."
    
    cd "$PROJECT_ROOT"
    
    go test -v -tags=performance -timeout=30m \
        -run "TestReconciliation" \
        ./test/performance/operator/... \
        2>&1 | tee "$OUTPUT_DIR/reconciliation.log"
    
    log_success "Reconciliation tests completed"
}

# Run gRPC performance tests
run_grpc_tests() {
    log_info "Running gRPC performance tests..."
    
    cd "$PROJECT_ROOT"
    
    go test -v -tags=performance -timeout=30m \
        -run "TestGRPC" \
        ./test/performance/operator/... \
        2>&1 | tee "$OUTPUT_DIR/grpc.log"
    
    log_success "gRPC tests completed"
}

# Run config push performance tests
run_config_push_tests() {
    log_info "Running config push performance tests..."
    
    cd "$PROJECT_ROOT"
    
    go test -v -tags=performance -timeout=30m \
        -run "TestConfigPush" \
        ./test/performance/operator/... \
        2>&1 | tee "$OUTPUT_DIR/config_push.log"
    
    log_success "Config push tests completed"
}

# Run Kubernetes-based tests
run_k8s_tests() {
    log_info "Running Kubernetes-based performance tests..."
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if cluster is accessible
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_info "Kubernetes cluster is accessible"
    
    # Deploy operator if not already deployed
    log_info "Checking operator deployment..."
    if ! kubectl get deployment avapigw-operator -n avapigw-system &> /dev/null; then
        log_info "Deploying operator..."
        cd "$PROJECT_ROOT"
        make helm-install-operator
    fi
    
    # Wait for operator to be ready
    log_info "Waiting for operator to be ready..."
    kubectl wait --for=condition=available deployment/avapigw-operator \
        -n avapigw-system --timeout=120s
    
    # Create test CRDs
    log_info "Creating $CRD_COUNT test CRDs..."
    create_test_crds "$CRD_COUNT"
    
    # Collect metrics
    log_info "Collecting operator metrics..."
    collect_operator_metrics
    
    # Cleanup test CRDs
    log_info "Cleaning up test CRDs..."
    cleanup_test_crds
    
    log_success "Kubernetes tests completed"
}

# Create test CRDs
create_test_crds() {
    local count=$1
    local start_time=$(date +%s)
    
    for i in $(seq 1 $count); do
        cat <<EOF | kubectl apply -f - > /dev/null
apiVersion: avapigw.vyrodovalexey.github.com/v1alpha1
kind: APIRoute
metadata:
  name: perf-test-route-$i
  namespace: avapigw-test
spec:
  match:
    - uri:
        prefix: /api/v1/perf-test-$i
      methods:
        - GET
        - POST
  route:
    - destination:
        host: backend-service
        port: 8080
      weight: 100
  timeout: 30s
EOF
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_info "Created $count CRDs in ${duration}s ($(echo "scale=2; $count / $duration" | bc) CRDs/sec)"
    echo "crd_creation_time=$duration" >> "$OUTPUT_DIR/metrics.txt"
    echo "crd_creation_rate=$(echo "scale=2; $count / $duration" | bc)" >> "$OUTPUT_DIR/metrics.txt"
}

# Collect operator metrics
collect_operator_metrics() {
    local metrics_file="$OUTPUT_DIR/operator_metrics.txt"
    
    # Get operator pod name
    local pod_name=$(kubectl get pods -n avapigw-system -l app=avapigw-operator -o jsonpath='{.items[0].metadata.name}')
    
    if [ -z "$pod_name" ]; then
        log_warn "Could not find operator pod"
        return
    fi
    
    # Collect metrics from operator
    kubectl exec -n avapigw-system "$pod_name" -- curl -s http://localhost:8080/metrics > "$metrics_file" 2>/dev/null || true
    
    # Extract key metrics
    if [ -f "$metrics_file" ]; then
        log_info "Extracting key metrics..."
        
        # Reconciliation metrics
        grep "controller_runtime_reconcile" "$metrics_file" >> "$OUTPUT_DIR/reconcile_metrics.txt" 2>/dev/null || true
        
        # gRPC metrics
        grep "avapigw_operator_grpc" "$metrics_file" >> "$OUTPUT_DIR/grpc_metrics.txt" 2>/dev/null || true
        
        # Resource metrics
        grep "go_memstats" "$metrics_file" >> "$OUTPUT_DIR/resource_metrics.txt" 2>/dev/null || true
        grep "go_goroutines" "$metrics_file" >> "$OUTPUT_DIR/resource_metrics.txt" 2>/dev/null || true
    fi
    
    # Get resource usage
    log_info "Collecting resource usage..."
    kubectl top pod -n avapigw-system -l app=avapigw-operator >> "$OUTPUT_DIR/resource_usage.txt" 2>/dev/null || true
}

# Cleanup test CRDs
cleanup_test_crds() {
    kubectl delete apiroutes -n avapigw-test -l app.kubernetes.io/created-by=perf-test --ignore-not-found > /dev/null 2>&1 || true
    kubectl delete apiroutes -n avapigw-test --all --ignore-not-found > /dev/null 2>&1 || true
}

# Run all tests
run_all_tests() {
    log_info "Running all operator performance tests..."
    
    run_local_tests
    
    # Only run K8s tests if cluster is available
    if kubectl cluster-info &> /dev/null 2>&1; then
        run_k8s_tests
    else
        log_warn "Kubernetes cluster not available, skipping K8s tests"
    fi
    
    log_success "All tests completed"
}

# Run benchmarks
run_benchmarks() {
    log_info "Running Go benchmarks..."
    
    cd "$PROJECT_ROOT"
    
    go test -v -tags=performance -bench=. -benchmem -timeout=30m \
        ./test/performance/operator/... \
        2>&1 | tee "$OUTPUT_DIR/benchmarks.log"
    
    log_success "Benchmarks completed"
}

# Generate summary report
generate_summary() {
    log_info "Generating summary report..."
    
    local summary_file="$OUTPUT_DIR/summary.md"
    
    cat > "$summary_file" << EOF
# Operator Performance Test Summary

**Date:** $(date)
**Test Type:** $TEST_TYPE
**Duration:** $DURATION
**CRD Count:** $CRD_COUNT
**Concurrency:** $CONCURRENCY

## Test Results

EOF

    # Add test results
    for log_file in "$OUTPUT_DIR"/*.log; do
        if [ -f "$log_file" ]; then
            local test_name=$(basename "$log_file" .log)
            echo "### $test_name" >> "$summary_file"
            echo '```' >> "$summary_file"
            tail -50 "$log_file" >> "$summary_file"
            echo '```' >> "$summary_file"
            echo "" >> "$summary_file"
        fi
    done

    # Add metrics if available
    if [ -f "$OUTPUT_DIR/metrics.txt" ]; then
        echo "## Metrics" >> "$summary_file"
        echo '```' >> "$summary_file"
        cat "$OUTPUT_DIR/metrics.txt" >> "$summary_file"
        echo '```' >> "$summary_file"
    fi

    log_success "Summary report generated: $summary_file"
}

# Show help
show_help() {
    cat << EOF
Operator Performance Test Runner

Usage: $0 [test-type] [options]

Test types:
  local           Run local Go-based performance tests (default)
  reconciliation  Run reconciliation performance tests
  grpc            Run gRPC communication tests
  config-push     Run configuration push tests
  k8s             Run Kubernetes-based tests (requires K8s cluster)
  benchmarks      Run Go benchmarks
  all             Run all tests

Options:
  --duration=<time>   Override test duration (e.g., --duration=5m)
  --crd-count=<num>   Number of CRDs to test with (default: 100)
  --concurrency=<num> Concurrency level (default: 10)
  --verbose           Enable verbose output
  --no-build          Skip building the operator
  --output=<dir>      Output directory for results

Examples:
  $0 local
  $0 reconciliation --duration=1m --crd-count=500
  $0 k8s --crd-count=1000
  $0 all --verbose

Performance Targets:
  - Reconciliation latency (P99): < 100ms
  - gRPC latency (P99): < 10ms
  - Throughput: > 1000 reconciles/second
  - Memory usage: < 256MB
  - CPU usage: < 500m

EOF
}

# Main execution
main() {
    if [[ "$TEST_TYPE" == "help" ]] || [[ "$TEST_TYPE" == "--help" ]] || [[ "$TEST_TYPE" == "-h" ]]; then
        show_help
        exit 0
    fi
    
    echo ""
    echo "=========================================="
    echo "  Operator Performance Test Runner"
    echo "=========================================="
    echo ""
    
    setup_output_dir
    build_operator
    
    case $TEST_TYPE in
        local)
            run_local_tests
            ;;
        reconciliation)
            run_reconciliation_tests
            ;;
        grpc)
            run_grpc_tests
            ;;
        config-push)
            run_config_push_tests
            ;;
        k8s)
            run_k8s_tests
            ;;
        benchmarks)
            run_benchmarks
            ;;
        all)
            run_all_tests
            ;;
        *)
            log_error "Unknown test type: $TEST_TYPE"
            show_help
            exit 1
            ;;
    esac
    
    generate_summary
    
    echo ""
    log_success "All tests completed. Results saved to: $OUTPUT_DIR"
}

main
