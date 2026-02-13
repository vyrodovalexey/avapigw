#!/bin/bash
# run-k8s-test.sh - Kubernetes Performance Test Runner
# Usage: ./run-k8s-test.sh [http|grpc|websocket|all] [options]
#
# Discovers K8s NodePort services and runs performance tests against
# the gateway deployed in local Kubernetes (Docker Desktop).
#
# Test types:
#   http        - HTTP throughput test via Yandex Tank (default)
#   https       - HTTPS throughput test via Yandex Tank
#   grpc        - gRPC unary test via ghz
#   grpc-tls    - gRPC TLS unary test via ghz
#   websocket   - WebSocket message test via k6
#   all         - Run all available tests sequentially
#
# Options:
#   --dry-run         - Show commands without running
#   --no-check        - Skip gateway health check
#   --verbose         - Enable verbose output
#   --namespace=<ns>  - K8s namespace (default: avapigw-test)
#   --service=<name>  - K8s service name (default: avapigw)

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

# Retry configuration constants
MAX_RETRIES=30
INITIAL_DELAY=1
MAX_DELAY=30
BACKOFF_FACTOR=2

# Default values - avapigw-test is the standard test namespace
TEST_TYPE="${1:-http}"
DRY_RUN=false
CHECK_GATEWAY=true
VERBOSE=false
K8S_NAMESPACE="avapigw-test"
K8S_SERVICE="avapigw"

# Cleanup flag for graceful shutdown
CLEANUP_DONE=false

# Parse options
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --no-check)
            CHECK_GATEWAY=false
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --namespace=*)
            K8S_NAMESPACE="${1#*=}"
            shift
            ;;
        --service=*)
            K8S_SERVICE="${1#*=}"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: $0 [http|grpc|websocket|all] [--dry-run] [--no-check] [--verbose] [--namespace=<ns>] [--service=<name>]"
            exit 1
            ;;
    esac
done

# Logging functions with consistent format
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

# ==============================================================================
# Graceful Shutdown Handler
# ==============================================================================

cleanup() {
    if [[ "$CLEANUP_DONE" == "true" ]]; then
        return 0
    fi
    CLEANUP_DONE=true
    
    echo ""
    log_info "Received shutdown signal, cleaning up..."
    
    # Kill any running test containers
    docker ps -q --filter "name=avapigw-" 2>/dev/null | xargs -r docker stop 2>/dev/null || true
    
    log_info "Cleanup completed"
    exit 0
}

# Set trap handlers for graceful shutdown
trap cleanup SIGINT SIGTERM EXIT

# ==============================================================================
# Exponential Backoff Health Check
# ==============================================================================

# Health check with exponential backoff
# Usage: health_check_with_backoff <url> <description>
health_check_with_backoff() {
    local url="$1"
    local description="${2:-service}"
    local attempt=1
    local delay=$INITIAL_DELAY
    
    log_info "Checking $description health with exponential backoff..."
    
    while [[ $attempt -le $MAX_RETRIES ]]; do
        local curl_opts="-s -o /dev/null -w %{http_code}"
        if [[ "$url" == https://* ]]; then
            curl_opts="-sk -o /dev/null -w %{http_code}"
        fi
        
        local status
        status=$(curl $curl_opts "$url" 2>/dev/null || echo "000")
        
        if [[ "$status" == "200" ]]; then
            log_success "$description is healthy"
            return 0
        fi
        
        if [[ $attempt -eq $MAX_RETRIES ]]; then
            log_error "$description health check failed after $MAX_RETRIES attempts (last status: $status)"
            return 1
        fi
        
        log_info "Attempt $attempt: $description not ready (status: $status), retrying in ${delay}s..."
        sleep $delay
        
        # Calculate next delay with exponential backoff
        delay=$((delay * BACKOFF_FACTOR))
        if [[ $delay -gt $MAX_DELAY ]]; then
            delay=$MAX_DELAY
        fi
        
        ((attempt++))
    done
    
    return 1
}

# ==============================================================================
# Prerequisites
# ==============================================================================

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi

    # Check kubectl connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Is Docker Desktop K8s running?"
        exit 1
    fi

    # Check Docker (needed for Yandex Tank)
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# ==============================================================================
# K8s Service Discovery
# ==============================================================================

discover_nodeports() {
    log_info "Discovering K8s NodePort services..."

    # Check if the service exists
    if ! kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" &> /dev/null; then
        log_error "Service '$K8S_SERVICE' not found in namespace '$K8S_NAMESPACE'"
        log_error "Deploy the gateway first:"
        log_error "  helm upgrade --install avapigw helm/avapigw/ -f helm/avapigw/values-local.yaml -n $K8S_NAMESPACE --create-namespace"
        exit 1
    fi

    # Discover ports by name for reliability
    # HTTP NodePort (port named 'http')
    K8S_HTTP_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}' 2>/dev/null)
    if [[ -z "$K8S_HTTP_PORT" ]]; then
        # Fallback to first port
        K8S_HTTP_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
    fi
    if [[ -z "$K8S_HTTP_PORT" ]]; then
        log_error "Could not discover HTTP NodePort"
        exit 1
    fi

    # HTTPS NodePort (port named 'https')
    K8S_HTTPS_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}' 2>/dev/null)

    # gRPC NodePort (port named 'grpc')
    K8S_GRPC_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" -o jsonpath='{.spec.ports[?(@.name=="grpc")].nodePort}' 2>/dev/null)

    # gRPC TLS NodePort (port named 'grpcs')
    K8S_GRPC_TLS_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" -o jsonpath='{.spec.ports[?(@.name=="grpcs")].nodePort}' 2>/dev/null)

    # Metrics NodePort (port named 'metrics')
    K8S_METRICS_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" -o jsonpath='{.spec.ports[?(@.name=="metrics")].nodePort}' 2>/dev/null)

    log_success "Discovered NodePorts:"
    log_info "  HTTP:     127.0.0.1:${K8S_HTTP_PORT}"
    if [[ -n "$K8S_HTTPS_PORT" ]]; then
        log_info "  HTTPS:    127.0.0.1:${K8S_HTTPS_PORT}"
    fi
    if [[ -n "$K8S_GRPC_PORT" ]]; then
        log_info "  gRPC:     127.0.0.1:${K8S_GRPC_PORT}"
    fi
    if [[ -n "$K8S_GRPC_TLS_PORT" ]]; then
        log_info "  gRPC TLS: 127.0.0.1:${K8S_GRPC_TLS_PORT}"
    fi
    if [[ -n "$K8S_METRICS_PORT" ]]; then
        log_info "  Metrics:  127.0.0.1:${K8S_METRICS_PORT}"
    fi
}

# ==============================================================================
# Health Checks
# ==============================================================================

check_k8s_gateway() {
    if [[ "$CHECK_GATEWAY" == "false" ]]; then
        log_info "Skipping gateway health check (--no-check)"
        return 0
    fi

    # Try HTTPS first if available, fall back to HTTP
    local health_port="${K8S_HTTPS_PORT:-$K8S_HTTP_PORT}"
    local health_scheme="http"
    if [[ -n "$K8S_HTTPS_PORT" ]]; then
        health_scheme="https"
    fi

    local health_url="${health_scheme}://127.0.0.1:${health_port}/health"
    
    if ! health_check_with_backoff "$health_url" "K8s gateway"; then
        log_error "Check pod status: kubectl get pods -n ${K8S_NAMESPACE} -l app.kubernetes.io/name=${K8S_SERVICE}"
        return 1
    fi
    
    return 0
}

check_k8s_pods() {
    log_info "Checking K8s pod status..."

    local ready_pods
    ready_pods=$(kubectl get pods -n "$K8S_NAMESPACE" -l "app=${K8S_SERVICE}" -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)

    if [[ -z "$ready_pods" ]]; then
        log_warn "No pods found with label app=${K8S_SERVICE}"
        return 0
    fi

    local total=0
    local ready=0
    for status in $ready_pods; do
        ((total++))
        if [[ "$status" == "True" ]]; then
            ((ready++))
        fi
    done

    if [[ $ready -eq $total ]]; then
        log_success "All pods ready: ${ready}/${total}"
    else
        log_warn "Not all pods ready: ${ready}/${total}"
    fi
}

# ==============================================================================
# HTTP Test (Yandex Tank)
# ==============================================================================

run_http_test() {
    log_info "=========================================="
    log_info "Running K8s HTTP Throughput Test"
    log_info "=========================================="

    local test_port="${K8S_HTTPS_PORT:-$K8S_HTTP_PORT}"
    local test_scheme="http"
    if [[ -n "$K8S_HTTPS_PORT" ]]; then
        test_scheme="https"
    fi
    log_info "Target: ${test_scheme}://127.0.0.1:${test_port}"

    # Create results directory
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local results_dir="$PERF_DIR/results/k8s/http_${timestamp}"
    mkdir -p "$results_dir/ammo"

    # Copy config and update port (use HTTPS port if available, otherwise HTTP)
    local config_file="$results_dir/load.yaml"
    local target_port="${K8S_HTTPS_PORT:-$K8S_HTTP_PORT}"
    sed "s/host.docker.internal:8443/host.docker.internal:${target_port}/g" \
        "$PERF_DIR/configs/k8s-http-throughput.yaml" > "$config_file"

    # Copy ammo file
    cp "$PERF_DIR/ammo/http-get.txt" "$results_dir/ammo/http-get.txt"

    log_info "Config: $config_file"
    log_info "Results: $results_dir"

    # Build Docker command
    local docker_cmd="docker run --rm"
    docker_cmd+=" -v $results_dir:/var/loadtest"
    docker_cmd+=" -v $results_dir/ammo:/var/loadtest/ammo"
    docker_cmd+=" --add-host=host.docker.internal:host-gateway"
    docker_cmd+=" -w /var/loadtest"

    if [[ "$VERBOSE" == "true" ]]; then
        docker_cmd+=" -e VERBOSE=1"
    fi

    docker_cmd+=" yandex/yandex-tank:latest"
    docker_cmd+=" -c /var/loadtest/load.yaml"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run - would execute:"
        echo "$docker_cmd"
        return 0
    fi

    # Check Yandex Tank image
    if ! docker image inspect yandex/yandex-tank:latest &> /dev/null; then
        log_info "Pulling Yandex Tank image..."
        docker pull yandex/yandex-tank:latest
    fi

    log_info "Starting Yandex Tank..."
    eval $docker_cmd
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_success "HTTP test completed successfully"
        log_info "Results saved to: $results_dir"
    else
        log_error "HTTP test failed with exit code: $exit_code"
        return 1
    fi
}

# ==============================================================================
# gRPC Test (ghz)
# ==============================================================================

run_grpc_test() {
    log_info "=========================================="
    log_info "Running K8s gRPC Unary Test"
    log_info "=========================================="

    # Check if gRPC port is available
    if [[ -z "$K8S_GRPC_PORT" ]]; then
        log_error "gRPC NodePort not discovered. Is the gRPC port exposed in the K8s service?"
        return 1
    fi

    log_info "Target: 127.0.0.1:${K8S_GRPC_PORT}"

    # Check if ghz is available (native or Docker)
    local use_docker=false
    if ! command -v ghz &> /dev/null; then
        if docker image inspect ghcr.io/bojand/ghz:latest &> /dev/null 2>&1; then
            use_docker=true
            log_info "Using ghz via Docker"
        else
            log_warn "ghz not found (native or Docker). Attempting to pull Docker image..."
            if docker pull ghcr.io/bojand/ghz:latest 2>/dev/null; then
                use_docker=true
            else
                log_error "ghz is not available. Install it or pull Docker image:"
                log_error "  brew install ghz  OR  docker pull ghcr.io/bojand/ghz:latest"
                return 1
            fi
        fi
    fi

    # Create results directory
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local results_dir="$PERF_DIR/results/k8s/grpc_${timestamp}"
    mkdir -p "$results_dir"

    log_info "Results: $results_dir"

    # Read config values from JSON
    local config_file="$PERF_DIR/configs/k8s-grpc-unary.json"
    local call="api.v1.TestService/Unary"
    local concurrency=10
    local total=500
    local data='{"message":"K8s gRPC performance test","timestamp":"2024-01-01T00:00:00Z"}'

    if command -v jq &> /dev/null && [[ -f "$config_file" ]]; then
        call=$(jq -r '.call' "$config_file")
        concurrency=$(jq -r '.concurrency' "$config_file")
        total=$(jq -r '.total' "$config_file")
        data=$(jq -c '.data' "$config_file")
    fi

    # Proto file for service definition (gateway doesn't expose backend reflection)
    local proto_file="$PERF_DIR/proto/test_service.proto"
    
    if [[ "$use_docker" == "true" ]]; then
        local ghz_cmd="docker run --rm"
        ghz_cmd+=" --add-host=host.docker.internal:host-gateway"
        ghz_cmd+=" -v $results_dir:/results"
        ghz_cmd+=" -v $PERF_DIR/proto:/proto:ro"
        ghz_cmd+=" ghcr.io/bojand/ghz:latest"
        ghz_cmd+=" --insecure"
        ghz_cmd+=" --proto /proto/test_service.proto"
        ghz_cmd+=" --call $call"
        ghz_cmd+=" --total $total"
        ghz_cmd+=" --concurrency $concurrency"
        ghz_cmd+=" --connections 5"
        ghz_cmd+=" --timeout 10s"
        ghz_cmd+=" --metadata '{\"x-perf-test\":\"k8s-grpc-unary\"}'"
        ghz_cmd+=" --format json"
        ghz_cmd+=" --output /results/results.json"
        ghz_cmd+=" --data '$data'"
        ghz_cmd+=" host.docker.internal:$K8S_GRPC_PORT"
    else
        local ghz_cmd="ghz"
        ghz_cmd+=" --insecure"
        ghz_cmd+=" --proto $proto_file"
        ghz_cmd+=" --call $call"
        ghz_cmd+=" --total $total"
        ghz_cmd+=" --concurrency $concurrency"
        ghz_cmd+=" --connections 5"
        ghz_cmd+=" --timeout 10s"
        ghz_cmd+=" --metadata '{\"x-perf-test\":\"k8s-grpc-unary\"}'"
        ghz_cmd+=" --format json"
        ghz_cmd+=" --output $results_dir/results.json"
        ghz_cmd+=" --data '$data'"
        ghz_cmd+=" 127.0.0.1:$K8S_GRPC_PORT"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run - would execute:"
        echo "$ghz_cmd"
        return 0
    fi

    log_info "Starting ghz..."
    eval $ghz_cmd
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_success "gRPC test completed successfully"

        # Display summary if jq is available
        local json_file="$results_dir/results.json"
        if [[ -f "$json_file" ]] && command -v jq &> /dev/null; then
            echo ""
            echo -e "${CYAN}  gRPC K8s Test Results${NC}"
            echo "  ============================================"
            local rps
            rps=$(jq -r '.rps // 0' "$json_file")
            local avg_ns
            avg_ns=$(jq -r '.average // 0' "$json_file")
            local count
            count=$(jq -r '.count // 0' "$json_file")
            local avg_ms
            avg_ms=$(echo "scale=2; $avg_ns / 1000000" | bc 2>/dev/null || echo "$avg_ns")
            printf "  Total Requests:  %s\n" "$count"
            printf "  RPS:             %.2f\n" "$rps"
            printf "  Avg Latency:     %s ms\n" "$avg_ms"
            echo "  ============================================"
            echo ""
        fi

        log_info "Results saved to: $results_dir"
    else
        log_error "gRPC test failed with exit code: $exit_code"
        return 1
    fi
}

# ==============================================================================
# gRPC TLS Test (ghz with TLS)
# ==============================================================================

run_grpc_tls_test() {
    log_info "=========================================="
    log_info "Running K8s gRPC TLS Unary Test"
    log_info "=========================================="

    # Check if gRPC TLS port is available
    if [[ -z "$K8S_GRPC_TLS_PORT" ]]; then
        log_error "gRPC TLS NodePort (grpcs) not discovered. Is Vault PKI enabled for gRPC?"
        log_error "Check service ports: kubectl get svc $K8S_SERVICE -n $K8S_NAMESPACE -o yaml"
        return 1
    fi

    log_info "Target: 127.0.0.1:${K8S_GRPC_TLS_PORT} (TLS)"

    # Check if ghz is available (native or Docker)
    local use_docker=false
    if ! command -v ghz &> /dev/null; then
        if docker image inspect ghcr.io/bojand/ghz:latest &> /dev/null 2>&1; then
            use_docker=true
            log_info "Using ghz via Docker"
        else
            log_warn "ghz not found (native or Docker). Attempting to pull Docker image..."
            if docker pull ghcr.io/bojand/ghz:latest 2>/dev/null; then
                use_docker=true
            else
                log_error "ghz is not available. Install it or pull Docker image:"
                log_error "  brew install ghz  OR  docker pull ghcr.io/bojand/ghz:latest"
                return 1
            fi
        fi
    fi

    # Create results directory
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local results_dir="$PERF_DIR/results/k8s/grpc-tls_${timestamp}"
    mkdir -p "$results_dir"

    log_info "Results: $results_dir"

    # Test configuration - use Unary method which exists in the proto
    local call="api.v1.TestService/Unary"
    local concurrency=10
    local total=500
    local data='{"message":"K8s gRPC TLS performance test"}'

    # Proto file for service definition (gateway doesn't expose backend reflection)
    local proto_file="$PERF_DIR/proto/test_service.proto"

    if [[ "$use_docker" == "true" ]]; then
        local ghz_cmd="docker run --rm"
        ghz_cmd+=" --add-host=host.docker.internal:host-gateway"
        ghz_cmd+=" -v $results_dir:/results"
        ghz_cmd+=" -v $PERF_DIR/proto:/proto:ro"
        ghz_cmd+=" ghcr.io/bojand/ghz:latest"
        # Use --skipTLS to skip TLS verification for self-signed Vault PKI certs
        ghz_cmd+=" --skipTLS"
        ghz_cmd+=" --proto /proto/test_service.proto"
        ghz_cmd+=" --call $call"
        ghz_cmd+=" --total $total"
        ghz_cmd+=" --concurrency $concurrency"
        ghz_cmd+=" --connections 5"
        ghz_cmd+=" --timeout 10s"
        ghz_cmd+=" --metadata '{\"x-perf-test\":\"k8s-grpc-tls-unary\"}'"
        ghz_cmd+=" --format json"
        ghz_cmd+=" --output /results/results.json"
        ghz_cmd+=" --data '$data'"
        ghz_cmd+=" host.docker.internal:$K8S_GRPC_TLS_PORT"
    else
        local ghz_cmd="ghz"
        # Use --skipTLS to skip TLS verification for self-signed Vault PKI certs
        ghz_cmd+=" --skipTLS"
        ghz_cmd+=" --proto $proto_file"
        ghz_cmd+=" --call $call"
        ghz_cmd+=" --total $total"
        ghz_cmd+=" --concurrency $concurrency"
        ghz_cmd+=" --connections 5"
        ghz_cmd+=" --timeout 10s"
        ghz_cmd+=" --metadata '{\"x-perf-test\":\"k8s-grpc-tls-unary\"}'"
        ghz_cmd+=" --format json"
        ghz_cmd+=" --output $results_dir/results.json"
        ghz_cmd+=" --data '$data'"
        ghz_cmd+=" 127.0.0.1:$K8S_GRPC_TLS_PORT"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run - would execute:"
        echo "$ghz_cmd"
        return 0
    fi

    log_info "Starting ghz with TLS..."
    eval $ghz_cmd
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_success "gRPC TLS test completed successfully"

        # Display summary if jq is available
        local json_file="$results_dir/results.json"
        if [[ -f "$json_file" ]] && command -v jq &> /dev/null; then
            echo ""
            echo -e "${CYAN}  gRPC TLS K8s Test Results${NC}"
            echo "  ============================================"
            local rps
            rps=$(jq -r '.rps // 0' "$json_file")
            local avg_ns
            avg_ns=$(jq -r '.average // 0' "$json_file")
            local count
            count=$(jq -r '.count // 0' "$json_file")
            local avg_ms
            avg_ms=$(echo "scale=2; $avg_ns / 1000000" | bc 2>/dev/null || echo "$avg_ns")
            printf "  Total Requests:  %s\n" "$count"
            printf "  RPS:             %.2f\n" "$rps"
            printf "  Avg Latency:     %s ms\n" "$avg_ms"
            echo "  ============================================"
            echo ""
        fi

        log_info "Results saved to: $results_dir"
    else
        log_error "gRPC TLS test failed with exit code: $exit_code"
        return 1
    fi
}

# ==============================================================================
# WebSocket Test (k6)
# ==============================================================================

run_websocket_test() {
    log_info "=========================================="
    log_info "Running K8s WebSocket Message Test"
    log_info "=========================================="
    log_info "Target: ws://127.0.0.1:${K8S_HTTP_PORT}/ws"

    # Check if k6 is available (native or Docker)
    local use_docker=false
    if ! command -v k6 &> /dev/null; then
        if docker image inspect grafana/k6:latest &> /dev/null 2>&1; then
            use_docker=true
            log_info "Using k6 via Docker"
        else
            log_warn "k6 not found (native or Docker). Attempting to pull Docker image..."
            if docker pull grafana/k6:latest 2>/dev/null; then
                use_docker=true
            else
                log_error "k6 is not available. Install it or pull Docker image:"
                log_error "  brew install k6  OR  docker pull grafana/k6:latest"
                return 1
            fi
        fi
    fi

    # Create results directory
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local results_dir="$PERF_DIR/results/k8s/websocket_${timestamp}"
    mkdir -p "$results_dir"

    log_info "Results: $results_dir"

    local ws_url="ws://host.docker.internal:${K8S_HTTP_PORT}/ws"

    if [[ "$use_docker" == "true" ]]; then
        local k6_cmd="docker run --rm"
        k6_cmd+=" --add-host=host.docker.internal:host-gateway"
        k6_cmd+=" -v $PERF_DIR/configs/websocket:/scripts:ro"
        k6_cmd+=" -v $results_dir:/results"
        k6_cmd+=" -e WS_URL=$ws_url"
        k6_cmd+=" grafana/k6:latest run"
        k6_cmd+=" --duration 30s"
        k6_cmd+=" --vus 10"
        k6_cmd+=" /scripts/websocket-message.js"
    else
        local k6_cmd="k6 run"
        k6_cmd+=" -e WS_URL=ws://127.0.0.1:${K8S_HTTP_PORT}/ws"
        k6_cmd+=" --duration 30s"
        k6_cmd+=" --vus 10"
        k6_cmd+=" $PERF_DIR/configs/websocket/websocket-message.js"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run - would execute:"
        echo "$k6_cmd"
        return 0
    fi

    log_info "Starting k6..."
    eval $k6_cmd
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_success "WebSocket test completed successfully"
        log_info "Results saved to: $results_dir"
    else
        log_error "WebSocket test failed with exit code: $exit_code"
        return 1
    fi
}

# ==============================================================================
# Run All Tests
# ==============================================================================

run_all_tests() {
    local failed_tests=()

    log_info "Running all K8s performance tests..."

    # HTTP test (always available - uses Yandex Tank via Docker)
    if ! run_http_test; then
        failed_tests+=("http")
    fi
    sleep 3

    # gRPC test (requires ghz)
    if [[ -n "$K8S_GRPC_PORT" ]]; then
        if command -v ghz &> /dev/null || docker image inspect ghcr.io/bojand/ghz:latest &> /dev/null 2>&1; then
            if ! run_grpc_test; then
                failed_tests+=("grpc")
            fi
            sleep 3
        else
            log_warn "Skipping gRPC test: ghz not available (install: brew install ghz)"
        fi
    else
        log_warn "Skipping gRPC test: gRPC NodePort not discovered"
    fi

    # gRPC TLS test (requires ghz and grpcs port)
    if [[ -n "$K8S_GRPC_TLS_PORT" ]]; then
        if command -v ghz &> /dev/null || docker image inspect ghcr.io/bojand/ghz:latest &> /dev/null 2>&1; then
            if ! run_grpc_tls_test; then
                failed_tests+=("grpc-tls")
            fi
            sleep 3
        else
            log_warn "Skipping gRPC TLS test: ghz not available (install: brew install ghz)"
        fi
    else
        log_warn "Skipping gRPC TLS test: gRPC TLS NodePort (grpcs) not discovered"
    fi

    # WebSocket test (requires k6)
    if command -v k6 &> /dev/null || docker image inspect grafana/k6:latest &> /dev/null 2>&1; then
        if ! run_websocket_test; then
            failed_tests+=("websocket")
        fi
    else
        log_warn "Skipping WebSocket test: k6 not available (install: brew install k6)"
    fi

    echo ""
    log_info "=========================================="
    log_info "K8s Performance Test Summary"
    log_info "=========================================="

    if [[ ${#failed_tests[@]} -eq 0 ]]; then
        log_success "All K8s tests passed!"
    else
        log_error "Failed tests: ${failed_tests[*]}"
        return 1
    fi
}

# ==============================================================================
# Help
# ==============================================================================

show_help() {
    cat << 'EOF'
K8s Performance Test Runner

Discovers NodePort services from Kubernetes and runs performance tests
against the gateway deployed in local K8s (Docker Desktop).

Usage: run-k8s-test.sh [http|https|grpc|grpc-tls|websocket|all] [options]

Test types:
  http        HTTP throughput test via Yandex Tank (default)
  https       HTTPS throughput test via Yandex Tank (requires HTTPS NodePort)
  grpc        gRPC unary test via ghz
  grpc-tls    gRPC TLS unary test via ghz (requires grpcs NodePort)
  websocket   WebSocket message test via k6
  all         Run all available tests sequentially

Options:
  --dry-run         Show commands without running
  --no-check        Skip gateway health check
  --verbose         Enable verbose output
  --namespace=<ns>  K8s namespace (default: avapigw-test)
  --service=<name>  K8s service name (default: avapigw)

Prerequisites:
  - kubectl configured and connected to cluster
  - Docker (for Yandex Tank)
  - ghz (for gRPC tests) - optional, skipped if not available
  - k6 (for WebSocket tests) - optional, skipped if not available

Results are saved to: test/performance/results/k8s/

Examples:
  ./run-k8s-test.sh http
  ./run-k8s-test.sh grpc-tls --dry-run
  ./run-k8s-test.sh all --verbose
  ./run-k8s-test.sh http --namespace=avapigw-test --service=avapigw

EOF
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    if [[ "$TEST_TYPE" == "help" ]] || [[ "$TEST_TYPE" == "--help" ]] || [[ "$TEST_TYPE" == "-h" ]]; then
        show_help
        exit 0
    fi

    echo ""
    echo "=========================================="
    echo "  K8s Performance Test Runner"
    echo "  avapigw Gateway"
    echo "=========================================="
    echo ""

    check_prerequisites
    discover_nodeports

    if [[ "$DRY_RUN" == "false" ]]; then
        check_k8s_pods
        check_k8s_gateway
    fi

    # Create k8s results directory
    mkdir -p "$PERF_DIR/results/k8s"

    case $TEST_TYPE in
        http)
            run_http_test
            ;;
        https)
            # HTTPS test uses the same function but targets HTTPS port
            if [[ -z "$K8S_HTTPS_PORT" ]]; then
                log_error "HTTPS NodePort not discovered. Is TLS enabled?"
                exit 1
            fi
            run_http_test
            ;;
        grpc)
            run_grpc_test
            ;;
        grpc-tls)
            run_grpc_tls_test
            ;;
        websocket)
            run_websocket_test
            ;;
        all)
            run_all_tests
            ;;
        *)
            log_error "Unknown test type: $TEST_TYPE"
            echo "Available types: http, https, grpc, grpc-tls, websocket, all"
            exit 1
            ;;
    esac
}

main
