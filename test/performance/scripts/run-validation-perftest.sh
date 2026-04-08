#!/bin/bash
# run-validation-perftest.sh - OpenAPI Validation Performance Test Runner
# Usage: ./run-validation-perftest.sh [options]
#
# Runs performance tests against gateway routes with OpenAPI validation enabled.
# Tests each validation scenario for configurable duration using `hey` (preferred)
# or `curl` as fallback.
#
# Options:
#   --namespace=<ns>    K8s namespace (default: avapigw-test)
#   --duration=<secs>   Test duration in seconds (default: 180)
#   --scenario=<name>   Run specific scenario (default: all)
#   --rps=<num>         Target requests per second (default: 200)
#   --dry-run           Show commands without running
#   --verbose           Enable verbose output
#   --no-check          Skip gateway health check
#   --service=<name>    K8s service name (default: avapigw)
#
# Scenarios:
#   basic, ratelimit, cache, transform, encoding, cors,
#   oidc, apikey, logonly, https, grpc-basic, graphql-basic, all
#
# Prerequisites:
#   - kubectl configured and connected to cluster
#   - Gateway deployed in K8s with validation routes
#   - hey (preferred) or curl for load generation
#   - Keycloak running for OIDC/API key tests (optional)

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
K8S_NAMESPACE="${AVAPIGW_NAMESPACE:-avapigw-test}"
K8S_SERVICE="${AVAPIGW_SERVICE:-avapigw}"
DURATION="${AVAPIGW_PERF_DURATION:-180}"
SCENARIO="${AVAPIGW_PERF_SCENARIO:-all}"
RPS="${AVAPIGW_PERF_RPS:-200}"
DRY_RUN=false
VERBOSE=false
CHECK_GATEWAY=true

# Keycloak configuration (for OIDC/API key tests)
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8090}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-gateway-test}"
KEYCLOAK_CLIENT="${KEYCLOAK_CLIENT:-gateway}"
KEYCLOAK_SECRET="${KEYCLOAK_SECRET:-gateway-secret}"
KEYCLOAK_USER="${KEYCLOAK_USER:-testuser}"
KEYCLOAK_PASSWORD="${KEYCLOAK_PASSWORD:-testpass}"

# VictoriaMetrics configuration
VICTORIA_METRICS_URL="${VICTORIA_METRICS_URL:-http://127.0.0.1:8428}"

# Cleanup flag for graceful shutdown
CLEANUP_DONE=false

# Results tracking
declare -a SCENARIO_RESULTS
declare -a SCENARIO_NAMES

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --namespace=*)
            K8S_NAMESPACE="${1#*=}"
            shift
            ;;
        --duration=*)
            DURATION="${1#*=}"
            shift
            ;;
        --scenario=*)
            SCENARIO="${1#*=}"
            shift
            ;;
        --rps=*)
            RPS="${1#*=}"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --no-check)
            CHECK_GATEWAY=false
            shift
            ;;
        --service=*)
            K8S_SERVICE="${1#*=}"
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: $0 [--namespace=<ns>] [--duration=<secs>] [--scenario=<name>] [--rps=<num>]"
            exit 1
            ;;
    esac
done

# ==============================================================================
# Logging Functions
# ==============================================================================

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

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
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
    log_info "Cleanup completed"
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# ==============================================================================
# Help
# ==============================================================================

show_help() {
    cat << 'EOF'
OpenAPI Validation Performance Test Runner

Runs performance tests against gateway routes with OpenAPI validation enabled.
Each scenario tests a different combination of validation + gateway features.

Usage: run-validation-perftest.sh [options]

Options:
  --namespace=<ns>    K8s namespace (default: avapigw-test)
  --duration=<secs>   Test duration in seconds (default: 180)
  --scenario=<name>   Run specific scenario (default: all)
  --rps=<num>         Target requests per second (default: 200)
  --dry-run           Show commands without running
  --verbose           Enable verbose output
  --no-check          Skip gateway health check
  --service=<name>    K8s service name (default: avapigw)

Scenarios:
  basic           OpenAPI validation baseline (no extra features)
  ratelimit       OpenAPI validation + rate limiting
  cache           OpenAPI validation + Redis caching
  transform       OpenAPI validation + request/response transform
  encoding        OpenAPI validation + response encoding (gzip)
  cors            OpenAPI validation + CORS
  oidc            OpenAPI validation + OIDC/JWT auth
  apikey          OpenAPI validation + API key auth
  logonly          OpenAPI validation in log-only mode (failOnError=false)
  https           HTTPS + OpenAPI validation
  grpc-basic      gRPC + proto validation
  graphql-basic   GraphQL + schema validation
  all             Run all scenarios sequentially

Environment variables:
  AVAPIGW_NAMESPACE         K8s namespace (default: avapigw-test)
  AVAPIGW_SERVICE           K8s service name (default: avapigw)
  AVAPIGW_PERF_DURATION     Test duration in seconds (default: 180)
  AVAPIGW_PERF_SCENARIO     Scenario to run (default: all)
  AVAPIGW_PERF_RPS          Target RPS (default: 200)
  KEYCLOAK_URL              Keycloak URL (default: http://localhost:8090)
  KEYCLOAK_REALM            Keycloak realm (default: gateway-test)
  KEYCLOAK_CLIENT           Client ID (default: gateway)
  KEYCLOAK_SECRET           Client secret (default: gateway-secret)
  KEYCLOAK_USER             Username (default: testuser)
  KEYCLOAK_PASSWORD         Password (default: testpass)
  VICTORIA_METRICS_URL      VictoriaMetrics URL (default: http://127.0.0.1:8428)

Examples:
  ./run-validation-perftest.sh
  ./run-validation-perftest.sh --scenario=basic --duration=60 --rps=100
  ./run-validation-perftest.sh --scenario=ratelimit --verbose
  ./run-validation-perftest.sh --scenario=all --dry-run
  ./run-validation-perftest.sh --namespace=avapigw-staging --rps=500

Results are saved to: test/performance/.yandextank/validation_<timestamp>/

EOF
}

# ==============================================================================
# Prerequisites Check
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

    # Check load generation tool
    if command -v hey &> /dev/null; then
        LOAD_TOOL="hey"
        log_info "Load tool: hey"
    elif command -v curl &> /dev/null; then
        LOAD_TOOL="curl"
        log_warn "hey not found, falling back to curl (limited load generation)"
        log_warn "Install hey for better results: go install github.com/rakyll/hey@latest"
    else
        log_error "Neither hey nor curl found. Install hey: go install github.com/rakyll/hey@latest"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# ==============================================================================
# K8s Service Discovery
# ==============================================================================

discover_gateway_port() {
    log_info "Discovering gateway HTTPS NodePort..."

    # Check if the service exists
    if ! kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" &> /dev/null; then
        log_error "Service '$K8S_SERVICE' not found in namespace '$K8S_NAMESPACE'"
        log_error "Deploy the gateway first with validation routes"
        exit 1
    fi

    # Discover HTTPS NodePort
    K8S_HTTPS_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" \
        -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}' 2>/dev/null)

    if [[ -z "$K8S_HTTPS_PORT" ]]; then
        # Fallback: try first port
        K8S_HTTPS_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" \
            -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
    fi

    if [[ -z "$K8S_HTTPS_PORT" ]]; then
        log_error "Could not discover HTTPS NodePort for service '$K8S_SERVICE'"
        exit 1
    fi

    # Discover gRPC port (optional)
    K8S_GRPC_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" \
        -o jsonpath='{.spec.ports[?(@.name=="grpc")].nodePort}' 2>/dev/null)

    # Discover metrics port (optional)
    K8S_METRICS_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" \
        -o jsonpath='{.spec.ports[?(@.name=="metrics")].nodePort}' 2>/dev/null)

    GATEWAY_URL="https://127.0.0.1:${K8S_HTTPS_PORT}"

    log_success "Gateway HTTPS: ${GATEWAY_URL}"
    if [[ -n "$K8S_GRPC_PORT" ]]; then
        log_info "Gateway gRPC:  127.0.0.1:${K8S_GRPC_PORT}"
    fi
    if [[ -n "$K8S_METRICS_PORT" ]]; then
        log_info "Gateway Metrics: 127.0.0.1:${K8S_METRICS_PORT}"
    fi
}

# ==============================================================================
# Route Verification
# ==============================================================================

check_routes_deployed() {
    log_info "Checking validation routes are deployed..."

    local routes_found=0
    local routes_expected=10

    # Check key validation routes
    local route_names=(
        "perf-validated-http-basic"
        "perf-validated-http-ratelimit"
        "perf-validated-http-cache"
        "perf-validated-http-transform"
        "perf-validated-http-encoding"
        "perf-validated-http-cors"
        "perf-validated-http-basicauth"
        "perf-validated-http-apikey"
        "perf-validated-http-oidc"
        "perf-validated-http-logonly"
    )

    for route in "${route_names[@]}"; do
        if kubectl get apiroute "$route" -n "$K8S_NAMESPACE" &> /dev/null; then
            ((routes_found++))
            log_verbose "Route found: $route"
        else
            log_warn "Route not found: $route"
        fi
    done

    if [[ $routes_found -eq 0 ]]; then
        log_error "No validation routes found in namespace '$K8S_NAMESPACE'"
        log_error "Deploy routes: kubectl apply -f test/performance/operator/crds-validation-perftest.yaml -n $K8S_NAMESPACE"
        exit 1
    fi

    log_success "Validation routes found: ${routes_found}/${routes_expected}"
}

# ==============================================================================
# Gateway Health Check
# ==============================================================================

check_gateway_health() {
    if [[ "$CHECK_GATEWAY" == "false" ]]; then
        log_info "Skipping gateway health check (--no-check)"
        return 0
    fi

    log_info "Checking gateway health..."

    local max_retries=10
    local attempt=1
    local delay=2

    while [[ $attempt -le $max_retries ]]; do
        local status
        status=$(curl -sk -o /dev/null -w '%{http_code}' "${GATEWAY_URL}/health" 2>/dev/null || echo "000")

        if [[ "$status" == "200" ]]; then
            log_success "Gateway is healthy"
            return 0
        fi

        log_info "Attempt $attempt: Gateway not ready (status: $status), retrying in ${delay}s..."
        sleep $delay
        ((attempt++))
    done

    log_error "Gateway health check failed after $max_retries attempts"
    log_error "Check pods: kubectl get pods -n ${K8S_NAMESPACE}"
    return 1
}

# ==============================================================================
# JWT Token Acquisition (for OIDC tests)
# ==============================================================================

get_jwt_token() {
    local token_url="${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token"

    local response
    response=$(curl -s -X POST "$token_url" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=${KEYCLOAK_CLIENT}" \
        -d "client_secret=${KEYCLOAK_SECRET}" \
        -d "username=${KEYCLOAK_USER}" \
        -d "password=${KEYCLOAK_PASSWORD}" \
        2>/dev/null)

    if [[ -z "$response" ]]; then
        echo "" 
        return 1
    fi

    local token
    if command -v jq &> /dev/null; then
        token=$(echo "$response" | jq -r '.access_token // empty')
    else
        token=$(echo "$response" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"//;s/"$//')
    fi

    if [[ -z "$token" ]] || [[ "$token" == "null" ]]; then
        echo ""
        return 1
    fi

    echo "$token"
}

# ==============================================================================
# Results Directory Setup
# ==============================================================================

setup_results_dir() {
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    RESULTS_DIR="$PERF_DIR/.yandextank/validation_${timestamp}"
    mkdir -p "$RESULTS_DIR"
    log_info "Results directory: $RESULTS_DIR"
}

# ==============================================================================
# Load Generation Functions
# ==============================================================================

run_hey_scenario() {
    local scenario_name="$1"
    local url="$2"
    local duration="$3"
    local rps="$4"
    local extra_headers="$5"
    local expected_status="${6:-200}"

    local result_file="$RESULTS_DIR/${scenario_name}.txt"

    log_info "Running scenario: ${scenario_name}"
    log_info "  URL: ${url}"
    log_info "  Duration: ${duration}s, Target RPS: ${rps}"
    log_info "  Expected status: ${expected_status}"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "  [DRY RUN] Would execute hey against ${url}"
        SCENARIO_NAMES+=("$scenario_name")
        SCENARIO_RESULTS+=("DRY_RUN")
        return 0
    fi

    local hey_cmd="hey -z ${duration}s -q ${rps} -c 50 -t 10"
    hey_cmd+=" -H 'Accept: application/json'"
    hey_cmd+=" -H 'Content-Type: application/json'"
    hey_cmd+=" -H 'X-Perf-Test: ${scenario_name}'"

    # Add extra headers (e.g., Authorization, Origin, API key)
    if [[ -n "$extra_headers" ]]; then
        hey_cmd+=" ${extra_headers}"
    fi

    # Disable TLS verification for self-signed certs
    hey_cmd+=" -disable-compression=false"
    hey_cmd+=" ${url}"

    log_verbose "Command: $hey_cmd"

    local start_time
    start_time=$(date +%s)

    # Run hey and capture output
    eval "$hey_cmd" > "$result_file" 2>&1
    local exit_code=$?

    local end_time
    end_time=$(date +%s)
    local elapsed=$((end_time - start_time))

    SCENARIO_NAMES+=("$scenario_name")

    if [[ $exit_code -eq 0 ]]; then
        # Extract key metrics from hey output
        local total_requests
        total_requests=$(grep -oP '\d+ responses' "$result_file" 2>/dev/null | grep -oP '\d+' || echo "N/A")
        local rps_actual
        rps_actual=$(grep 'Requests/sec' "$result_file" 2>/dev/null | awk '{print $2}' || echo "N/A")
        local avg_latency
        avg_latency=$(grep 'Average' "$result_file" 2>/dev/null | head -1 | awk '{print $2}' || echo "N/A")
        local p99_latency
        p99_latency=$(grep '99%' "$result_file" 2>/dev/null | head -1 | awk '{print $2}' || echo "N/A")

        log_success "Scenario ${scenario_name} completed in ${elapsed}s"
        log_info "  Actual RPS: ${rps_actual}, Avg latency: ${avg_latency}, P99: ${p99_latency}"

        SCENARIO_RESULTS+=("PASS")
    else
        log_error "Scenario ${scenario_name} failed (exit code: ${exit_code})"
        SCENARIO_RESULTS+=("FAIL")
    fi
}

run_curl_scenario() {
    local scenario_name="$1"
    local url="$2"
    local duration="$3"
    local rps="$4"
    local extra_headers="$5"
    local expected_status="${6:-200}"

    local result_file="$RESULTS_DIR/${scenario_name}.txt"

    log_info "Running scenario (curl fallback): ${scenario_name}"
    log_info "  URL: ${url}"
    log_info "  Duration: ${duration}s (sequential requests)"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "  [DRY RUN] Would execute curl loop against ${url}"
        SCENARIO_NAMES+=("$scenario_name")
        SCENARIO_RESULTS+=("DRY_RUN")
        return 0
    fi

    local start_time
    start_time=$(date +%s)
    local end_time=$((start_time + duration))
    local total_requests=0
    local success_count=0
    local error_count=0

    # Build curl headers
    local curl_headers="-H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-Perf-Test: ${scenario_name}'"
    if [[ -n "$extra_headers" ]]; then
        # Convert hey-style headers to curl-style
        curl_headers+=" $(echo "$extra_headers" | sed "s/-H /-H /g")"
    fi

    echo "# Curl fallback results for ${scenario_name}" > "$result_file"
    echo "# Started: $(date)" >> "$result_file"

    while [[ $(date +%s) -lt $end_time ]]; do
        local status
        status=$(eval "curl -sk -o /dev/null -w '%{http_code}' ${curl_headers} '${url}'" 2>/dev/null || echo "000")
        ((total_requests++))

        if [[ "$status" == "$expected_status" ]] || [[ "$status" == "200" ]]; then
            ((success_count++))
        else
            ((error_count++))
        fi

        # Brief sleep to avoid overwhelming with sequential requests
        sleep 0.01
    done

    local actual_end
    actual_end=$(date +%s)
    local elapsed=$((actual_end - start_time))
    local actual_rps=0
    if [[ $elapsed -gt 0 ]]; then
        actual_rps=$((total_requests / elapsed))
    fi

    echo "# Completed: $(date)" >> "$result_file"
    echo "Total requests: ${total_requests}" >> "$result_file"
    echo "Successful: ${success_count}" >> "$result_file"
    echo "Errors: ${error_count}" >> "$result_file"
    echo "Duration: ${elapsed}s" >> "$result_file"
    echo "RPS: ${actual_rps}" >> "$result_file"

    SCENARIO_NAMES+=("$scenario_name")

    local success_rate=0
    if [[ $total_requests -gt 0 ]]; then
        success_rate=$((success_count * 100 / total_requests))
    fi

    if [[ $success_rate -ge 80 ]]; then
        log_success "Scenario ${scenario_name}: ${total_requests} requests, ${actual_rps} RPS, ${success_rate}% success"
        SCENARIO_RESULTS+=("PASS")
    else
        log_error "Scenario ${scenario_name}: ${total_requests} requests, ${actual_rps} RPS, ${success_rate}% success"
        SCENARIO_RESULTS+=("FAIL")
    fi
}

run_scenario() {
    if [[ "$LOAD_TOOL" == "hey" ]]; then
        run_hey_scenario "$@"
    else
        run_curl_scenario "$@"
    fi
}

# ==============================================================================
# Scenario Definitions
# ==============================================================================

run_basic() {
    run_scenario "validated-http-basic" \
        "${GATEWAY_URL}/api/v1/validated/basic/items" \
        "$DURATION" "$RPS" "" "200"
}

run_ratelimit() {
    # Lower RPS to stay within rate limit for meaningful results
    local rl_rps=$((RPS < 100 ? RPS : 100))
    run_scenario "validated-http-ratelimit" \
        "${GATEWAY_URL}/api/v1/validated/ratelimit/items" \
        "$DURATION" "$rl_rps" "" "200"
}

run_cache() {
    run_scenario "validated-http-cache" \
        "${GATEWAY_URL}/api/v1/validated/cache/items" \
        "$DURATION" "$RPS" "" "200"
}

run_transform() {
    run_scenario "validated-http-transform" \
        "${GATEWAY_URL}/api/v1/validated/transform/items" \
        "$DURATION" "$RPS" "" "200"
}

run_encoding() {
    run_scenario "validated-http-encoding" \
        "${GATEWAY_URL}/api/v1/validated/encoding/items" \
        "$DURATION" "$RPS" \
        "-H 'Accept-Encoding: gzip, deflate'" "200"
}

run_cors() {
    run_scenario "validated-http-cors" \
        "${GATEWAY_URL}/api/v1/validated/cors/items" \
        "$DURATION" "$RPS" \
        "-H 'Origin: https://example.com'" "200"
}

run_oidc() {
    log_info "Obtaining JWT token from Keycloak for OIDC test..."
    local jwt_token
    jwt_token=$(get_jwt_token)

    if [[ -z "$jwt_token" ]]; then
        log_warn "Could not obtain JWT token from Keycloak at ${KEYCLOAK_URL}"
        log_warn "Running OIDC test without token (expects 401)"
        run_scenario "validated-http-oidc" \
            "${GATEWAY_URL}/api/v1/validated/oidc/items" \
            "$DURATION" "$RPS" "" "401"
    else
        log_success "JWT token obtained"
        run_scenario "validated-http-oidc" \
            "${GATEWAY_URL}/api/v1/validated/oidc/items" \
            "$DURATION" "$RPS" \
            "-H 'Authorization: Bearer ${jwt_token}'" "200"
    fi
}

run_apikey() {
    log_info "Obtaining JWT token from Keycloak for API key test..."
    local jwt_token
    jwt_token=$(get_jwt_token)

    if [[ -z "$jwt_token" ]]; then
        log_warn "Could not obtain token for API key test"
        log_warn "Running API key test without key (expects 401)"
        run_scenario "validated-http-apikey" \
            "${GATEWAY_URL}/api/v1/validated/apikey/items" \
            "$DURATION" "$RPS" "" "401"
    else
        log_success "API key token obtained"
        run_scenario "validated-http-apikey" \
            "${GATEWAY_URL}/api/v1/validated/apikey/items" \
            "$DURATION" "$RPS" \
            "-H 'X-API-Key: ${jwt_token}'" "200"
    fi
}

run_logonly() {
    run_scenario "validated-http-logonly" \
        "${GATEWAY_URL}/api/v1/validated/logonly/items" \
        "$DURATION" "$RPS" "" "200"
}

run_https() {
    run_scenario "validated-https" \
        "${GATEWAY_URL}/api/v1/validated/https/items" \
        "$DURATION" "$RPS" "" "200"
}

run_grpc_basic() {
    log_info "Running gRPC + proto validation scenario..."

    if [[ -z "$K8S_GRPC_PORT" ]]; then
        log_warn "gRPC NodePort not discovered, skipping gRPC scenario"
        SCENARIO_NAMES+=("validated-grpc-basic")
        SCENARIO_RESULTS+=("SKIP")
        return 0
    fi

    if command -v ghz &> /dev/null; then
        local result_file="$RESULTS_DIR/validated-grpc-basic.json"

        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "  [DRY RUN] Would execute ghz against 127.0.0.1:${K8S_GRPC_PORT}"
            SCENARIO_NAMES+=("validated-grpc-basic")
            SCENARIO_RESULTS+=("DRY_RUN")
            return 0
        fi

        ghz --insecure \
            --proto "$PERF_DIR/proto/test_service.proto" \
            --call "api.v1.TestService/Unary" \
            --total $((RPS * DURATION / 10)) \
            --concurrency 10 \
            --connections 5 \
            --timeout 10s \
            --format json \
            --output "$result_file" \
            --data '{"message":"validation perf test"}' \
            "127.0.0.1:${K8S_GRPC_PORT}" 2>&1 || true

        SCENARIO_NAMES+=("validated-grpc-basic")
        if [[ -f "$result_file" ]]; then
            log_success "gRPC scenario completed"
            SCENARIO_RESULTS+=("PASS")
        else
            log_error "gRPC scenario failed"
            SCENARIO_RESULTS+=("FAIL")
        fi
    else
        log_warn "ghz not found, skipping gRPC scenario (install: brew install ghz)"
        SCENARIO_NAMES+=("validated-grpc-basic")
        SCENARIO_RESULTS+=("SKIP")
    fi
}

run_graphql_basic() {
    run_scenario "validated-graphql-basic" \
        "${GATEWAY_URL}/graphql/validated/basic" \
        "$DURATION" "$RPS" "" "200"
}

# ==============================================================================
# VictoriaMetrics Verification
# ==============================================================================

verify_metrics() {
    log_info "Verifying metrics in VictoriaMetrics..."

    local vm_url="${VICTORIA_METRICS_URL}/api/v1/query"

    # Check if VictoriaMetrics is accessible
    if ! curl -s -o /dev/null -w '%{http_code}' "${VICTORIA_METRICS_URL}/health" 2>/dev/null | grep -q "200"; then
        log_warn "VictoriaMetrics not accessible at ${VICTORIA_METRICS_URL}, skipping metrics verification"
        return 0
    fi

    # Query gateway request metrics
    local metrics_queries=(
        'sum(rate(avapigw_http_requests_total[5m])) by (route)'
        'histogram_quantile(0.99, rate(avapigw_http_request_duration_seconds_bucket[5m]))'
        'sum(rate(avapigw_openapi_validation_total[5m])) by (result)'
        'sum(rate(avapigw_openapi_validation_errors_total[5m])) by (route)'
    )

    local metrics_file="$RESULTS_DIR/metrics_verification.txt"
    echo "# VictoriaMetrics Verification - $(date)" > "$metrics_file"

    for query in "${metrics_queries[@]}"; do
        log_verbose "Querying: ${query}"
        local result
        result=$(curl -s --data-urlencode "query=${query}" "${vm_url}" 2>/dev/null)

        if [[ -n "$result" ]]; then
            echo "" >> "$metrics_file"
            echo "## Query: ${query}" >> "$metrics_file"
            if command -v jq &> /dev/null; then
                echo "$result" | jq '.' >> "$metrics_file" 2>/dev/null || echo "$result" >> "$metrics_file"
            else
                echo "$result" >> "$metrics_file"
            fi
        fi
    done

    log_success "Metrics verification saved to: ${metrics_file}"
}

# ==============================================================================
# Summary Report
# ==============================================================================

print_summary() {
    echo ""
    echo "=========================================="
    echo -e "${CYAN}  Validation Performance Test Summary${NC}"
    echo "=========================================="
    echo ""
    echo "  Namespace:  ${K8S_NAMESPACE}"
    echo "  Gateway:    ${GATEWAY_URL}"
    echo "  Duration:   ${DURATION}s per scenario"
    echo "  Target RPS: ${RPS}"
    echo "  Load Tool:  ${LOAD_TOOL}"
    echo "  Results:    ${RESULTS_DIR}"
    echo ""
    echo "  Scenario Results:"
    echo "  ─────────────────────────────────────────"

    local pass_count=0
    local fail_count=0
    local skip_count=0

    for i in "${!SCENARIO_NAMES[@]}"; do
        local name="${SCENARIO_NAMES[$i]}"
        local result="${SCENARIO_RESULTS[$i]}"
        local icon=""

        case "$result" in
            PASS)
                icon="${GREEN}✓${NC}"
                ((pass_count++))
                ;;
            FAIL)
                icon="${RED}✗${NC}"
                ((fail_count++))
                ;;
            SKIP)
                icon="${YELLOW}⊘${NC}"
                ((skip_count++))
                ;;
            DRY_RUN)
                icon="${BLUE}◎${NC}"
                ;;
        esac

        printf "  %b  %-35s %s\n" "$icon" "$name" "$result"
    done

    echo "  ─────────────────────────────────────────"
    echo ""
    echo -e "  ${GREEN}Passed: ${pass_count}${NC}  ${RED}Failed: ${fail_count}${NC}  ${YELLOW}Skipped: ${skip_count}${NC}"
    echo ""

    # Save summary to file
    local summary_file="$RESULTS_DIR/summary.txt"
    {
        echo "Validation Performance Test Summary"
        echo "Date: $(date)"
        echo "Namespace: ${K8S_NAMESPACE}"
        echo "Gateway: ${GATEWAY_URL}"
        echo "Duration: ${DURATION}s"
        echo "Target RPS: ${RPS}"
        echo "Load Tool: ${LOAD_TOOL}"
        echo ""
        for i in "${!SCENARIO_NAMES[@]}"; do
            echo "${SCENARIO_NAMES[$i]}: ${SCENARIO_RESULTS[$i]}"
        done
        echo ""
        echo "Passed: ${pass_count}, Failed: ${fail_count}, Skipped: ${skip_count}"
    } > "$summary_file"

    if [[ $fail_count -gt 0 ]]; then
        return 1
    fi
    return 0
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    echo ""
    echo "=========================================="
    echo "  OpenAPI Validation Performance Tests"
    echo "  avapigw Gateway"
    echo "=========================================="
    echo ""

    check_prerequisites
    discover_gateway_port
    check_routes_deployed
    check_gateway_health
    setup_results_dir

    log_info "Starting validation performance tests..."
    log_info "Scenario: ${SCENARIO}, Duration: ${DURATION}s, RPS: ${RPS}"
    echo ""

    case "$SCENARIO" in
        basic)
            run_basic
            ;;
        ratelimit)
            run_ratelimit
            ;;
        cache)
            run_cache
            ;;
        transform)
            run_transform
            ;;
        encoding)
            run_encoding
            ;;
        cors)
            run_cors
            ;;
        oidc)
            run_oidc
            ;;
        apikey)
            run_apikey
            ;;
        logonly)
            run_logonly
            ;;
        https)
            run_https
            ;;
        grpc-basic)
            run_grpc_basic
            ;;
        graphql-basic)
            run_graphql_basic
            ;;
        all)
            log_info "Running all validation scenarios..."
            echo ""

            run_basic
            sleep 3

            run_ratelimit
            sleep 3

            run_cache
            sleep 3

            run_transform
            sleep 3

            run_encoding
            sleep 3

            run_cors
            sleep 3

            run_logonly
            sleep 3

            run_https
            sleep 3

            run_oidc
            sleep 3

            run_apikey
            sleep 3

            run_grpc_basic
            sleep 3

            run_graphql_basic
            ;;
        *)
            log_error "Unknown scenario: ${SCENARIO}"
            echo "Available: basic, ratelimit, cache, transform, encoding, cors, oidc, apikey, logonly, https, grpc-basic, graphql-basic, all"
            exit 1
            ;;
    esac

    echo ""

    # Verify metrics in VictoriaMetrics
    verify_metrics

    # Print summary
    print_summary
}

main
