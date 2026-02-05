#!/bin/bash
# run-operator-scenarios.sh - Run all three operator performance test scenarios
# Usage: ./run-operator-scenarios.sh [scenario] [options]
#
# Scenarios:
#   baseline        - Static config baseline (no operator)
#   crd             - CRD-configured routes via operator
#   ingress         - Ingress controller mode
#   all             - Run all scenarios sequentially
#
# Options:
#   --dry-run           - Show commands without running
#   --duration=<time>   - Override test duration (default: 5m)
#   --namespace=<ns>    - K8s namespace (default: avapigw-test)
#   --output=<dir>      - Output directory for results
#   --compare           - Generate comparison report after all tests

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

# Default values
SCENARIO="${1:-all}"
DRY_RUN=false
DURATION="5m"
K8S_NAMESPACE="avapigw-test"
OUTPUT_DIR=""
COMPARE=false

# Parse options
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true; shift ;;
        --duration=*) DURATION="${1#*=}"; shift ;;
        --namespace=*) K8S_NAMESPACE="${1#*=}"; shift ;;
        --output=*) OUTPUT_DIR="${1#*=}"; shift ;;
        --compare) COMPARE=true; shift ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Setup output directory
setup_output() {
    if [[ -z "$OUTPUT_DIR" ]]; then
        local timestamp=$(date +%Y%m%d_%H%M%S)
        OUTPUT_DIR="$PERF_DIR/results/operator-scenarios_${timestamp}"
    fi
    mkdir -p "$OUTPUT_DIR"/{baseline,crd,ingress}
    log_info "Results will be saved to: $OUTPUT_DIR"
}

# ==============================================================================
# Scenario 1: Static Config Baseline (No Operator)
# ==============================================================================

run_baseline_scenario() {
    log_info "=========================================="
    log_info "Scenario 1: Static Config Baseline"
    log_info "=========================================="
    log_info "Gateway with static YAML configuration (no operator)"
    
    local results_dir="$OUTPUT_DIR/baseline"
    mkdir -p "$results_dir/ammo"
    
    # Copy config and ammo
    cp "$PERF_DIR/configs/operator/static-config-baseline.yaml" "$results_dir/load.yaml"
    cp "$PERF_DIR/ammo/http-get.txt" "$results_dir/ammo/"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run - would run Yandex Tank with static-config-baseline.yaml"
        return 0
    fi
    
    # Start gateway with static config
    log_info "Starting gateway with static configuration..."
    "$SCRIPT_DIR/start-gateway.sh" --config="$PERF_DIR/configs/gateway-perftest.yaml" &
    local gateway_pid=$!
    sleep 5
    
    # Check gateway health
    if ! curl -s http://127.0.0.1:8080/health > /dev/null; then
        log_error "Gateway health check failed"
        kill $gateway_pid 2>/dev/null || true
        return 1
    fi
    
    # Run Yandex Tank
    log_info "Running Yandex Tank..."
    docker run --rm \
        -v "$results_dir:/var/loadtest" \
        -v "$results_dir/ammo:/var/loadtest/ammo" \
        --add-host=host.docker.internal:host-gateway \
        -w /var/loadtest \
        yandex/yandex-tank:latest \
        -c /var/loadtest/load.yaml
    
    local exit_code=$?
    
    # Stop gateway
    kill $gateway_pid 2>/dev/null || true
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "Baseline scenario completed"
    else
        log_error "Baseline scenario failed"
        return 1
    fi
}

# ==============================================================================
# Scenario 2: CRD-Configured Routes via Operator
# ==============================================================================

run_crd_scenario() {
    log_info "=========================================="
    log_info "Scenario 2: CRD-Configured Routes"
    log_info "=========================================="
    log_info "Routes/backends configured via APIRoute/Backend CRDs"
    
    local results_dir="$OUTPUT_DIR/crd"
    mkdir -p "$results_dir/ammo"
    
    # Copy config and ammo
    cp "$PERF_DIR/configs/operator/crd-reconciliation.yaml" "$results_dir/load.yaml"
    cp "$PERF_DIR/ammo/crd-routes.txt" "$results_dir/ammo/"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run - would run Yandex Tank with crd-reconciliation.yaml"
        return 0
    fi
    
    # Check if K8s is available
    if ! kubectl cluster-info &> /dev/null; then
        log_warn "Kubernetes not available, skipping CRD scenario"
        log_info "To run this scenario, ensure Docker Desktop K8s is enabled"
        return 0
    fi
    
    # Deploy operator and gateway via Helm
    log_info "Deploying operator and gateway via Helm..."
    helm upgrade --install avapigw "$PROJECT_ROOT/helm/avapigw/" \
        -f "$PROJECT_ROOT/helm/avapigw/values-local.yaml" \
        -n "$K8S_NAMESPACE" --create-namespace \
        --set operator.enabled=true \
        --wait --timeout=120s
    
    # Wait for gateway to be ready
    log_info "Waiting for gateway to be ready..."
    kubectl wait --for=condition=available deployment/avapigw \
        -n "$K8S_NAMESPACE" --timeout=120s
    
    # Get NodePort
    local http_port=$(kubectl get svc avapigw -n "$K8S_NAMESPACE" \
        -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}')
    
    # Update config with correct port
    sed -i.bak "s/host.docker.internal:8080/host.docker.internal:${http_port}/g" \
        "$results_dir/load.yaml"
    
    # Apply test CRDs
    log_info "Applying test APIRoute CRDs..."
    kubectl apply -f - <<EOF
apiVersion: avapigw.vyrodovalexey.github.com/v1alpha1
kind: APIRoute
metadata:
  name: perf-test-items
  namespace: $K8S_NAMESPACE
spec:
  match:
    - uri:
        prefix: /api/v1/items
      methods: [GET, POST]
  route:
    - destination:
        host: host.docker.internal
        port: 8801
      weight: 50
    - destination:
        host: host.docker.internal
        port: 8802
      weight: 50
  timeout: 30s
---
apiVersion: avapigw.vyrodovalexey.github.com/v1alpha1
kind: APIRoute
metadata:
  name: perf-test-users
  namespace: $K8S_NAMESPACE
spec:
  match:
    - uri:
        prefix: /api/v1/users
      methods: [GET, POST]
  route:
    - destination:
        host: host.docker.internal
        port: 8801
      weight: 100
  timeout: 30s
EOF
    
    # Wait for reconciliation
    sleep 5
    
    # Check gateway health
    if ! curl -s "http://127.0.0.1:${http_port}/health" > /dev/null; then
        log_error "Gateway health check failed"
        return 1
    fi
    
    # Run Yandex Tank
    log_info "Running Yandex Tank..."
    docker run --rm \
        -v "$results_dir:/var/loadtest" \
        -v "$results_dir/ammo:/var/loadtest/ammo" \
        --add-host=host.docker.internal:host-gateway \
        -w /var/loadtest \
        yandex/yandex-tank:latest \
        -c /var/loadtest/load.yaml
    
    local exit_code=$?
    
    # Cleanup CRDs
    kubectl delete apiroutes -n "$K8S_NAMESPACE" --all --ignore-not-found
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "CRD scenario completed"
    else
        log_error "CRD scenario failed"
        return 1
    fi
}

# ==============================================================================
# Scenario 3: Ingress Controller Mode
# ==============================================================================

run_ingress_scenario() {
    log_info "=========================================="
    log_info "Scenario 3: Ingress Controller Mode"
    log_info "=========================================="
    log_info "Routes configured via Kubernetes Ingress resources"
    
    local results_dir="$OUTPUT_DIR/ingress"
    mkdir -p "$results_dir/ammo"
    
    # Copy config and ammo
    cp "$PERF_DIR/configs/operator/ingress-controller.yaml" "$results_dir/load.yaml"
    cp "$PERF_DIR/ammo/ingress-routes.txt" "$results_dir/ammo/"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run - would run Yandex Tank with ingress-controller.yaml"
        return 0
    fi
    
    # Check if K8s is available
    if ! kubectl cluster-info &> /dev/null; then
        log_warn "Kubernetes not available, skipping Ingress scenario"
        log_info "To run this scenario, ensure Docker Desktop K8s is enabled"
        return 0
    fi
    
    # Ensure operator is deployed with Ingress controller enabled
    log_info "Deploying operator with Ingress controller enabled..."
    helm upgrade --install avapigw "$PROJECT_ROOT/helm/avapigw/" \
        -f "$PROJECT_ROOT/helm/avapigw/values-local.yaml" \
        -n "$K8S_NAMESPACE" --create-namespace \
        --set operator.enabled=true \
        --set operator.ingressController.enabled=true \
        --set operator.ingressController.ingressClassName=avapigw \
        --wait --timeout=120s
    
    # Wait for gateway to be ready
    log_info "Waiting for gateway to be ready..."
    kubectl wait --for=condition=available deployment/avapigw \
        -n "$K8S_NAMESPACE" --timeout=120s
    
    # Get NodePort
    local http_port=$(kubectl get svc avapigw -n "$K8S_NAMESPACE" \
        -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}')
    
    # Update config with correct port
    sed -i.bak "s/host.docker.internal:8080/host.docker.internal:${http_port}/g" \
        "$results_dir/load.yaml"
    
    # Apply test Ingress
    log_info "Applying test Ingress resources..."
    kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: perf-test-ingress
  namespace: $K8S_NAMESPACE
  annotations:
    avapigw.io/timeout: "30s"
    avapigw.io/retry-attempts: "3"
spec:
  ingressClassName: avapigw
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /api/v1/users
            pathType: Prefix
            backend:
              service:
                name: backend-svc
                port:
                  number: 8801
          - path: /api/v1/orders
            pathType: Prefix
            backend:
              service:
                name: backend-svc
                port:
                  number: 8802
          - path: /api/v1/products
            pathType: Prefix
            backend:
              service:
                name: backend-svc
                port:
                  number: 8801
EOF
    
    # Wait for reconciliation
    sleep 5
    
    # Check gateway health
    if ! curl -s "http://127.0.0.1:${http_port}/health" > /dev/null; then
        log_error "Gateway health check failed"
        return 1
    fi
    
    # Run Yandex Tank
    log_info "Running Yandex Tank..."
    docker run --rm \
        -v "$results_dir:/var/loadtest" \
        -v "$results_dir/ammo:/var/loadtest/ammo" \
        --add-host=host.docker.internal:host-gateway \
        -w /var/loadtest \
        yandex/yandex-tank:latest \
        -c /var/loadtest/load.yaml
    
    local exit_code=$?
    
    # Cleanup Ingress
    kubectl delete ingress perf-test-ingress -n "$K8S_NAMESPACE" --ignore-not-found
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "Ingress scenario completed"
    else
        log_error "Ingress scenario failed"
        return 1
    fi
}

# ==============================================================================
# Generate Comparison Report
# ==============================================================================

generate_comparison_report() {
    log_info "Generating comparison report..."
    
    local report_file="$OUTPUT_DIR/comparison-report.md"
    
    cat > "$report_file" << 'EOF'
# Operator Performance Test Comparison Report

**Date:** $(date)
**Test Duration:** $DURATION

## Executive Summary

This report compares gateway performance across three configuration modes:
1. **Baseline** - Static YAML configuration (no operator)
2. **CRD** - Routes configured via APIRoute/Backend CRDs
3. **Ingress** - Routes configured via Kubernetes Ingress resources

## Test Results

| Scenario | Max RPS | Avg Latency | P95 Latency | P99 Latency | Error Rate |
|----------|---------|-------------|-------------|-------------|------------|
EOF

    # Parse results from each scenario (if available)
    for scenario in baseline crd ingress; do
        local results_dir="$OUTPUT_DIR/$scenario"
        if [[ -d "$results_dir" ]]; then
            # Extract metrics from phout.txt or results.json
            echo "| $scenario | TBD | TBD | TBD | TBD | TBD |" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" << 'EOF'

## Performance Targets

| Metric | Target | Acceptable |
|--------|--------|------------|
| Max RPS | > 2000 (baseline), > 1500 (CRD/Ingress) | > 1500 (baseline), > 1000 (CRD/Ingress) |
| P99 Latency | < 100ms | < 200ms |
| Error Rate | < 0.1% | < 1% |

## Overhead Analysis

- **CRD vs Baseline**: Expected overhead < 10%
- **Ingress vs Baseline**: Expected overhead < 15%
- **Ingress vs CRD**: Expected overhead < 5%

## Recommendations

1. For maximum performance, use static configuration
2. For dynamic configuration with minimal overhead, use CRDs
3. For Kubernetes-native integration, use Ingress controller mode

EOF

    log_success "Comparison report generated: $report_file"
}

# ==============================================================================
# Run All Scenarios
# ==============================================================================

run_all_scenarios() {
    local failed=()
    
    run_baseline_scenario || failed+=("baseline")
    sleep 10
    
    run_crd_scenario || failed+=("crd")
    sleep 10
    
    run_ingress_scenario || failed+=("ingress")
    
    if [[ "$COMPARE" == "true" ]]; then
        generate_comparison_report
    fi
    
    echo ""
    log_info "=========================================="
    log_info "All Scenarios Summary"
    log_info "=========================================="
    
    if [[ ${#failed[@]} -eq 0 ]]; then
        log_success "All scenarios completed successfully!"
    else
        log_error "Failed scenarios: ${failed[*]}"
        return 1
    fi
}

# ==============================================================================
# Help
# ==============================================================================

show_help() {
    cat << 'EOF'
Operator Performance Test Scenarios

Runs performance tests for three gateway configuration modes:
1. Baseline - Static YAML config (no operator)
2. CRD - Routes via APIRoute/Backend CRDs
3. Ingress - Routes via Kubernetes Ingress

Usage: run-operator-scenarios.sh [scenario] [options]

Scenarios:
  baseline    Static config baseline (no operator)
  crd         CRD-configured routes via operator
  ingress     Ingress controller mode
  all         Run all scenarios sequentially (default)

Options:
  --dry-run           Show commands without running
  --duration=<time>   Override test duration (default: 5m)
  --namespace=<ns>    K8s namespace (default: avapigw-test)
  --output=<dir>      Output directory for results
  --compare           Generate comparison report after all tests

Prerequisites:
  - Docker (for Yandex Tank)
  - kubectl (for CRD/Ingress scenarios)
  - Helm (for K8s deployments)
  - Backend services running (docker-compose)

Examples:
  ./run-operator-scenarios.sh baseline
  ./run-operator-scenarios.sh all --compare
  ./run-operator-scenarios.sh crd --namespace=avapigw-test
  ./run-operator-scenarios.sh all --dry-run

EOF
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    if [[ "$SCENARIO" == "help" ]] || [[ "$SCENARIO" == "--help" ]]; then
        show_help
        exit 0
    fi
    
    echo ""
    echo "=========================================="
    echo "  Operator Performance Test Scenarios"
    echo "  avapigw API Gateway"
    echo "=========================================="
    echo ""
    
    setup_output
    
    case $SCENARIO in
        baseline) run_baseline_scenario ;;
        crd) run_crd_scenario ;;
        ingress) run_ingress_scenario ;;
        all) run_all_scenarios ;;
        *)
            log_error "Unknown scenario: $SCENARIO"
            show_help
            exit 1
            ;;
    esac
}

main
