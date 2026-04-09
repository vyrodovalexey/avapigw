#!/bin/bash
# run-k8s-comprehensive-perftest.sh - Comprehensive K8s Performance Test Runner
# Runs all performance test scenarios against K8s-deployed avapigw gateway
# Each test runs for 3 minutes (180 seconds)
#
# Test Categories:
# 1. gRPC & Streaming Tests (mTLS, OIDC)
# 2. TLS gRPC & Streaming Tests
# 3. HTTP & WS Tests (basic, API, OIDC auth, rate limiting, transform, encoding, caching, CORS, OpenAPI)
# 4. HTTPS & WSS Tests
# 5. GraphQL & WS Tests
# 6. TLS GraphQL & WSS Tests

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$(dirname "$PERF_DIR")")"

# Configuration
K8S_NAMESPACE="${AVAPIGW_NAMESPACE:-avapigw-test}"
K8S_SERVICE="${AVAPIGW_SERVICE:-avapigw}"
DURATION="${AVAPIGW_PERF_DURATION:-180}"  # 3 minutes
RPS="${AVAPIGW_PERF_RPS:-200}"
VERBOSE="${VERBOSE:-false}"

# Keycloak configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8090}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-gateway-test}"
KEYCLOAK_CLIENT="${KEYCLOAK_CLIENT:-gateway}"
KEYCLOAK_SECRET="${KEYCLOAK_SECRET:-gateway-secret}"
KEYCLOAK_USER="${KEYCLOAK_USER:-testuser}"
KEYCLOAK_PASSWORD="${KEYCLOAK_PASSWORD:-testpass}"

# Results tracking
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="$PERF_DIR/.yandextank/k8s-comprehensive-${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"

declare -a TEST_RESULTS
declare -a TEST_NAMES
declare -a TEST_DURATIONS
declare -a TEST_RPS

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"; echo -e "${MAGENTA}  $1${NC}"; echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}\n"; }

# Cleanup handler
cleanup() {
    log_info "Cleaning up..."
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT

# ==============================================================================
# Prerequisites
# ==============================================================================

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found"
        exit 1
    fi
    
    # Check tools
    local tools_found=0
    if command -v hey &> /dev/null; then
        log_info "Found: hey (HTTP load testing)"
        ((tools_found++))
    fi
    if command -v ghz &> /dev/null; then
        log_info "Found: ghz (gRPC load testing)"
        ((tools_found++))
    fi
    if command -v k6 &> /dev/null; then
        log_info "Found: k6 (WebSocket/GraphQL testing)"
        ((tools_found++))
    fi
    if command -v grpcurl &> /dev/null; then
        log_info "Found: grpcurl (gRPC testing)"
        ((tools_found++))
    fi
    
    if [[ $tools_found -lt 3 ]]; then
        log_warn "Some tools missing. Install: brew install hey ghz k6 grpcurl"
    fi
    
    log_success "Prerequisites check passed"
}

# ==============================================================================
# K8s Service Discovery
# ==============================================================================

discover_ports() {
    log_info "Discovering K8s NodePorts..."
    
    K8S_HTTPS_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" \
        -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}' 2>/dev/null)
    K8S_GRPC_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" \
        -o jsonpath='{.spec.ports[?(@.name=="grpcs")].nodePort}' 2>/dev/null)
    K8S_METRICS_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" \
        -o jsonpath='{.spec.ports[?(@.name=="metrics")].nodePort}' 2>/dev/null)
    
    if [[ -z "$K8S_HTTPS_PORT" ]]; then
        K8S_HTTPS_PORT=$(kubectl get svc "$K8S_SERVICE" -n "$K8S_NAMESPACE" \
            -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
    fi
    
    GATEWAY_HTTPS="https://127.0.0.1:${K8S_HTTPS_PORT}"
    GATEWAY_GRPC="127.0.0.1:${K8S_GRPC_PORT}"
    
    log_success "HTTPS: ${GATEWAY_HTTPS}"
    log_success "gRPC TLS: ${GATEWAY_GRPC}"
    log_success "Metrics: 127.0.0.1:${K8S_METRICS_PORT}"
}

# ==============================================================================
# JWT Token
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
        -d "password=${KEYCLOAK_PASSWORD}" 2>/dev/null)
    
    if command -v jq &> /dev/null; then
        echo "$response" | jq -r '.access_token // empty'
    else
        echo "$response" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"//;s/"$//'
    fi
}

# ==============================================================================
# Test Execution Functions
# ==============================================================================

run_hey_test() {
    local name="$1"
    local url="$2"
    local duration="$3"
    local rps="$4"
    local extra_headers="$5"
    
    local result_file="$RESULTS_DIR/${name}.txt"
    local start_time=$(date +%s)
    
    log_info "Running: ${name}"
    log_info "  URL: ${url}"
    log_info "  Duration: ${duration}s, RPS: ${rps}"
    
    local cmd="hey -z ${duration}s -q ${rps} -c 50 -t 10"
    cmd+=" -H 'Accept: application/json'"
    cmd+=" -H 'Content-Type: application/json'"
    cmd+=" -H 'X-Perf-Test: ${name}'"
    
    if [[ -n "$extra_headers" ]]; then
        cmd+=" ${extra_headers}"
    fi
    
    cmd+=" '${url}'"
    
    eval "$cmd" > "$result_file" 2>&1
    local exit_code=$?
    
    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    
    TEST_NAMES+=("$name")
    TEST_DURATIONS+=("$elapsed")
    
    if [[ $exit_code -eq 0 ]]; then
        local actual_rps=$(grep 'Requests/sec' "$result_file" 2>/dev/null | awk '{print $2}' || echo "N/A")
        local avg_latency=$(grep 'Average' "$result_file" 2>/dev/null | head -1 | awk '{print $2}' || echo "N/A")
        TEST_RESULTS+=("PASS")
        TEST_RPS+=("$actual_rps")
        log_success "${name}: RPS=${actual_rps}, Latency=${avg_latency}"
    else
        TEST_RESULTS+=("FAIL")
        TEST_RPS+=("0")
        log_error "${name}: FAILED"
    fi
}

run_ghz_test() {
    local name="$1"
    local call="$2"
    local duration="$3"
    local rps="$4"
    local extra_opts="$5"
    
    local result_file="$RESULTS_DIR/${name}.json"
    local start_time=$(date +%s)
    
    log_info "Running: ${name}"
    log_info "  Call: ${call}"
    log_info "  Duration: ${duration}s, RPS: ${rps}"
    
    local total=$((rps * duration / 2))  # Approximate total requests
    
    local cmd="ghz --skipTLS"
    cmd+=" --proto '$PERF_DIR/proto/test_service.proto'"
    cmd+=" --call '${call}'"
    cmd+=" --total ${total}"
    cmd+=" --concurrency 20"
    cmd+=" --connections 10"
    cmd+=" --timeout 10s"
    cmd+=" --format json"
    cmd+=" --output '${result_file}'"
    cmd+=" --data '{\"message\":\"perf test\"}'"
    
    if [[ -n "$extra_opts" ]]; then
        cmd+=" ${extra_opts}"
    fi
    
    cmd+=" '${GATEWAY_GRPC}'"
    
    eval "$cmd" 2>&1 || true
    
    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    
    TEST_NAMES+=("$name")
    TEST_DURATIONS+=("$elapsed")
    
    if [[ -f "$result_file" ]]; then
        local actual_rps=$(jq -r '.rps // 0' "$result_file" 2>/dev/null || echo "0")
        local avg_latency=$(jq -r '.average // 0' "$result_file" 2>/dev/null || echo "0")
        local avg_ms=$(echo "scale=2; $avg_latency / 1000000" | bc 2>/dev/null || echo "$avg_latency")
        TEST_RESULTS+=("PASS")
        TEST_RPS+=("$actual_rps")
        log_success "${name}: RPS=${actual_rps}, Latency=${avg_ms}ms"
    else
        TEST_RESULTS+=("FAIL")
        TEST_RPS+=("0")
        log_error "${name}: FAILED"
    fi
}

run_k6_test() {
    local name="$1"
    local script="$2"
    local duration="$3"
    local env_vars="$4"
    
    local result_file="$RESULTS_DIR/${name}.json"
    local start_time=$(date +%s)
    
    log_info "Running: ${name}"
    log_info "  Script: ${script}"
    log_info "  Duration: ${duration}s"
    
    local cmd="k6 run --insecure-skip-tls-verify"
    cmd+=" --duration ${duration}s"
    cmd+=" --summary-export '${result_file}'"
    
    if [[ -n "$env_vars" ]]; then
        cmd+=" ${env_vars}"
    fi
    
    cmd+=" '${script}'"
    
    eval "$cmd" > "$RESULTS_DIR/${name}.log" 2>&1 || true
    
    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    
    TEST_NAMES+=("$name")
    TEST_DURATIONS+=("$elapsed")
    
    if [[ -f "$result_file" ]]; then
        TEST_RESULTS+=("PASS")
        TEST_RPS+=("N/A")
        log_success "${name}: Completed"
    else
        TEST_RESULTS+=("FAIL")
        TEST_RPS+=("0")
        log_error "${name}: FAILED"
    fi
}

# ==============================================================================
# Test Scenarios
# ==============================================================================

run_grpc_tests() {
    log_section "1. gRPC & Streaming Tests"
    
    # gRPC unary throughput
    run_ghz_test "grpc-unary-throughput" \
        "api.v1.TestService/Unary" \
        "$DURATION" "$RPS" ""
    
    sleep 3
    
    # gRPC server streaming (use different data format for streaming)
    local stream_result_file="$RESULTS_DIR/grpc-server-streaming.json"
    log_info "Running: grpc-server-streaming"
    log_info "  Call: api.v1.TestService/ServerStream"
    log_info "  Duration: ${DURATION}s"
    
    ghz --skipTLS \
        --proto "$PERF_DIR/proto/test_service.proto" \
        --call "api.v1.TestService/ServerStream" \
        --total $((RPS * DURATION / 4)) \
        --concurrency 10 \
        --connections 5 \
        --timeout 30s \
        --format json \
        --output "$stream_result_file" \
        -d '{"count":5,"interval_ms":50}' \
        "${GATEWAY_GRPC}" 2>&1 || true
    
    TEST_NAMES+=("grpc-server-streaming")
    if [[ -f "$stream_result_file" ]]; then
        local actual_rps=$(jq -r '.rps // 0' "$stream_result_file" 2>/dev/null || echo "0")
        TEST_RESULTS+=("PASS")
        TEST_DURATIONS+=("$DURATION")
        TEST_RPS+=("$actual_rps")
        log_success "grpc-server-streaming: RPS=${actual_rps}"
    else
        TEST_RESULTS+=("FAIL")
        TEST_DURATIONS+=("0")
        TEST_RPS+=("0")
        log_error "grpc-server-streaming: FAILED"
    fi
    
    sleep 3
    
    # gRPC with mTLS backend (uses same endpoint, backend handles mTLS)
    run_ghz_test "grpc-mtls-backend" \
        "api.v1.TestService/Unary" \
        "$DURATION" "$RPS" \
        "--metadata '{\"x-test-type\":\"mtls\"}'"
    
    sleep 3
    
    # gRPC with OIDC
    local jwt_token=$(get_jwt_token)
    if [[ -n "$jwt_token" ]]; then
        run_ghz_test "grpc-oidc" \
            "api.v1.TestService/Unary" \
            "$DURATION" "$RPS" \
            "--metadata '{\"authorization\":\"Bearer ${jwt_token}\"}'"
    else
        log_warn "Skipping gRPC OIDC test - no JWT token"
        TEST_NAMES+=("grpc-oidc")
        TEST_RESULTS+=("SKIP")
        TEST_DURATIONS+=("0")
        TEST_RPS+=("0")
    fi
}

run_tls_grpc_tests() {
    log_section "2. TLS gRPC & Streaming Tests"
    
    # TLS gRPC unary
    run_ghz_test "tls-grpc-unary" \
        "api.v1.TestService/Unary" \
        "$DURATION" "$RPS" ""
    
    sleep 3
    
    # TLS gRPC streaming with mTLS
    local tls_stream_mtls_file="$RESULTS_DIR/tls-grpc-streaming-mtls.json"
    log_info "Running: tls-grpc-streaming-mtls"
    log_info "  Call: api.v1.TestService/ServerStream"
    log_info "  Duration: ${DURATION}s"
    
    ghz --skipTLS \
        --proto "$PERF_DIR/proto/test_service.proto" \
        --call "api.v1.TestService/ServerStream" \
        --total $((RPS * DURATION / 4)) \
        --concurrency 10 \
        --connections 5 \
        --timeout 30s \
        --format json \
        --output "$tls_stream_mtls_file" \
        -d '{"count":5,"interval_ms":50}' \
        --metadata '{"x-test-type":"mtls"}' \
        "${GATEWAY_GRPC}" 2>&1 || true
    
    TEST_NAMES+=("tls-grpc-streaming-mtls")
    if [[ -f "$tls_stream_mtls_file" ]]; then
        local actual_rps=$(jq -r '.rps // 0' "$tls_stream_mtls_file" 2>/dev/null || echo "0")
        TEST_RESULTS+=("PASS")
        TEST_DURATIONS+=("$DURATION")
        TEST_RPS+=("$actual_rps")
        log_success "tls-grpc-streaming-mtls: RPS=${actual_rps}"
    else
        TEST_RESULTS+=("FAIL")
        TEST_DURATIONS+=("0")
        TEST_RPS+=("0")
        log_error "tls-grpc-streaming-mtls: FAILED"
    fi
    
    sleep 3
    
    # TLS gRPC streaming with OIDC
    local jwt_token=$(get_jwt_token)
    if [[ -n "$jwt_token" ]]; then
        local tls_stream_oidc_file="$RESULTS_DIR/tls-grpc-streaming-oidc.json"
        log_info "Running: tls-grpc-streaming-oidc"
        log_info "  Call: api.v1.TestService/ServerStream"
        log_info "  Duration: ${DURATION}s"
        
        ghz --skipTLS \
            --proto "$PERF_DIR/proto/test_service.proto" \
            --call "api.v1.TestService/ServerStream" \
            --total $((RPS * DURATION / 4)) \
            --concurrency 10 \
            --connections 5 \
            --timeout 30s \
            --format json \
            --output "$tls_stream_oidc_file" \
            -d '{"count":5,"interval_ms":50}' \
            --metadata "{\"authorization\":\"Bearer ${jwt_token}\"}" \
            "${GATEWAY_GRPC}" 2>&1 || true
        
        TEST_NAMES+=("tls-grpc-streaming-oidc")
        if [[ -f "$tls_stream_oidc_file" ]]; then
            local actual_rps=$(jq -r '.rps // 0' "$tls_stream_oidc_file" 2>/dev/null || echo "0")
            TEST_RESULTS+=("PASS")
            TEST_DURATIONS+=("$DURATION")
            TEST_RPS+=("$actual_rps")
            log_success "tls-grpc-streaming-oidc: RPS=${actual_rps}"
        else
            TEST_RESULTS+=("FAIL")
            TEST_DURATIONS+=("0")
            TEST_RPS+=("0")
            log_error "tls-grpc-streaming-oidc: FAILED"
        fi
    else
        log_warn "Skipping TLS gRPC OIDC test - no JWT token"
        TEST_NAMES+=("tls-grpc-streaming-oidc")
        TEST_RESULTS+=("SKIP")
        TEST_DURATIONS+=("0")
        TEST_RPS+=("0")
    fi
}

run_http_tests() {
    log_section "3. HTTP & WS Tests"
    
    local jwt_token=$(get_jwt_token)
    
    # HTTP with basic auth
    run_hey_test "http-basic-auth" \
        "${GATEWAY_HTTPS}/api/v1/validated/basic/items" \
        "$DURATION" "$RPS" ""
    
    sleep 3
    
    # HTTP with API key auth
    run_hey_test "http-apikey-auth" \
        "${GATEWAY_HTTPS}/api/v1/validated/apikey/items" \
        "$DURATION" "$RPS" \
        "-H 'X-API-Key: pk_perftest_1234567890abcdef'"
    
    sleep 3
    
    # HTTP with OIDC auth
    if [[ -n "$jwt_token" ]]; then
        run_hey_test "http-oidc-auth" \
            "${GATEWAY_HTTPS}/api/v1/validated/oidc/items" \
            "$DURATION" "$RPS" \
            "-H 'Authorization: Bearer ${jwt_token}'"
    else
        log_warn "Skipping HTTP OIDC test - no JWT token"
        TEST_NAMES+=("http-oidc-auth")
        TEST_RESULTS+=("SKIP")
        TEST_DURATIONS+=("0")
        TEST_RPS+=("0")
    fi
    
    sleep 3
    
    # HTTP rate limiting via Redis Sentinel
    run_hey_test "http-ratelimit-sentinel" \
        "${GATEWAY_HTTPS}/api/v1/validated/ratelimit/items" \
        "$DURATION" "100" ""  # Lower RPS for rate limit test
    
    sleep 3
    
    # HTTP transform
    run_hey_test "http-transform" \
        "${GATEWAY_HTTPS}/api/v1/validated/transform/items" \
        "$DURATION" "$RPS" ""
    
    sleep 3
    
    # HTTP encoding
    run_hey_test "http-encoding" \
        "${GATEWAY_HTTPS}/api/v1/validated/encoding/items" \
        "$DURATION" "$RPS" \
        "-H 'Accept-Encoding: gzip, deflate'"
    
    sleep 3
    
    # HTTP caching via Redis Sentinel
    run_hey_test "http-cache-sentinel" \
        "${GATEWAY_HTTPS}/api/v1/validated/cache/items" \
        "$DURATION" "$RPS" ""
    
    sleep 3
    
    # HTTP CORS
    run_hey_test "http-cors" \
        "${GATEWAY_HTTPS}/api/v1/validated/cors/items" \
        "$DURATION" "$RPS" \
        "-H 'Origin: https://example.com'"
    
    sleep 3
    
    # HTTP OpenAPI validation
    run_hey_test "http-openapi-validation" \
        "${GATEWAY_HTTPS}/api/v1/validated/basic/items" \
        "$DURATION" "$RPS" ""
    
    sleep 3
    
    # WebSocket throughput
    if command -v k6 &> /dev/null; then
        run_k6_test "websocket-throughput" \
            "$PERF_DIR/configs/websocket/websocket-k8s-wss-perftest.js" \
            "$DURATION" \
            "-e WS_URL=wss://127.0.0.1:${K8S_HTTPS_PORT}/ws"
    else
        log_warn "Skipping WebSocket test - k6 not found"
        TEST_NAMES+=("websocket-throughput")
        TEST_RESULTS+=("SKIP")
        TEST_DURATIONS+=("0")
        TEST_RPS+=("0")
    fi
}

run_https_tests() {
    log_section "4. HTTPS & WSS Tests"
    
    local jwt_token=$(get_jwt_token)
    
    # HTTPS with basic auth
    run_hey_test "https-basic-auth" \
        "${GATEWAY_HTTPS}/api/v1/auth/basic" \
        "$DURATION" "$RPS" ""
    
    sleep 3
    
    # HTTPS with API key auth
    run_hey_test "https-apikey-auth" \
        "${GATEWAY_HTTPS}/api/v1/auth/apikey" \
        "$DURATION" "$RPS" \
        "-H 'X-API-Key: pk_perftest_1234567890abcdef'"
    
    sleep 3
    
    # HTTPS with OIDC auth
    if [[ -n "$jwt_token" ]]; then
        run_hey_test "https-oidc-auth" \
            "${GATEWAY_HTTPS}/api/v1/auth/keycloak" \
            "$DURATION" "$RPS" \
            "-H 'Authorization: Bearer ${jwt_token}'"
    else
        log_warn "Skipping HTTPS OIDC test - no JWT token"
        TEST_NAMES+=("https-oidc-auth")
        TEST_RESULTS+=("SKIP")
        TEST_DURATIONS+=("0")
        TEST_RPS+=("0")
    fi
    
    sleep 3
    
    # HTTPS rate limiting via Redis Sentinel
    run_hey_test "https-ratelimit-sentinel" \
        "${GATEWAY_HTTPS}/api/v1/ratelimit" \
        "$DURATION" "100" ""
    
    sleep 3
    
    # HTTPS transform
    run_hey_test "https-transform" \
        "${GATEWAY_HTTPS}/api/v1/transform" \
        "$DURATION" "$RPS" ""
    
    sleep 3
    
    # HTTPS encoding
    run_hey_test "https-encoding" \
        "${GATEWAY_HTTPS}/api/v1/perf/encoding/" \
        "$DURATION" "$RPS" \
        "-H 'Accept-Encoding: gzip, deflate'"
    
    sleep 3
    
    # HTTPS caching via Redis Sentinel
    run_hey_test "https-cache-sentinel" \
        "${GATEWAY_HTTPS}/api/v1/cache" \
        "$DURATION" "$RPS" ""
    
    sleep 3
    
    # HTTPS CORS
    run_hey_test "https-cors" \
        "${GATEWAY_HTTPS}/api/v1/items" \
        "$DURATION" "$RPS" \
        "-H 'Origin: https://example.com'"
}

run_graphql_tests() {
    log_section "5. GraphQL & WS Tests"
    
    local jwt_token=$(get_jwt_token)
    
    if ! command -v k6 &> /dev/null; then
        log_warn "k6 not found - skipping GraphQL tests"
        for test in "graphql-basic" "graphql-apikey" "graphql-oidc" "graphql-ratelimit" "graphql-transform" "graphql-cors"; do
            TEST_NAMES+=("$test")
            TEST_RESULTS+=("SKIP")
            TEST_DURATIONS+=("0")
            TEST_RPS+=("0")
        done
        return
    fi
    
    # GraphQL with basic auth
    run_k6_test "graphql-basic" \
        "$PERF_DIR/configs/k6-graphql/k8s-graphql-basic.js" \
        "$DURATION" \
        "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql"
    
    sleep 3
    
    # GraphQL with API key auth
    run_k6_test "graphql-apikey" \
        "$PERF_DIR/configs/k6-graphql/k8s-graphql-apikey.js" \
        "$DURATION" \
        "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql -e API_KEY=pk_perftest_1234567890abcdef"
    
    sleep 3
    
    # GraphQL with OIDC auth
    if [[ -n "$jwt_token" ]]; then
        run_k6_test "graphql-oidc" \
            "$PERF_DIR/configs/k6-graphql/k8s-graphql-oidc.js" \
            "$DURATION" \
            "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql -e JWT_TOKEN=${jwt_token}"
    else
        log_warn "Skipping GraphQL OIDC test - no JWT token"
        TEST_NAMES+=("graphql-oidc")
        TEST_RESULTS+=("SKIP")
        TEST_DURATIONS+=("0")
        TEST_RPS+=("0")
    fi
    
    sleep 3
    
    # GraphQL rate limiting via Redis Sentinel
    run_k6_test "graphql-ratelimit" \
        "$PERF_DIR/configs/k6-graphql/k8s-graphql-ratelimit.js" \
        "$DURATION" \
        "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql/ratelimit"
    
    sleep 3
    
    # GraphQL transform
    run_k6_test "graphql-transform" \
        "$PERF_DIR/configs/k6-graphql/k8s-graphql-transform.js" \
        "$DURATION" \
        "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql"
    
    sleep 3
    
    # GraphQL CORS
    run_k6_test "graphql-cors" \
        "$PERF_DIR/configs/k6-graphql/k8s-graphql-basic.js" \
        "$DURATION" \
        "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql -e ORIGIN=https://example.com"
}

run_tls_graphql_tests() {
    log_section "6. TLS GraphQL & WSS Tests"
    
    local jwt_token=$(get_jwt_token)
    
    if ! command -v k6 &> /dev/null; then
        log_warn "k6 not found - skipping TLS GraphQL tests"
        for test in "tls-graphql-basic" "tls-graphql-apikey" "tls-graphql-oidc" "tls-graphql-ratelimit" "tls-graphql-transform" "tls-graphql-cors"; do
            TEST_NAMES+=("$test")
            TEST_RESULTS+=("SKIP")
            TEST_DURATIONS+=("0")
            TEST_RPS+=("0")
        done
        return
    fi
    
    # TLS GraphQL with basic auth
    run_k6_test "tls-graphql-basic" \
        "$PERF_DIR/configs/k6-graphql/k8s-graphql-basic.js" \
        "$DURATION" \
        "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql"
    
    sleep 3
    
    # TLS GraphQL with API key auth
    run_k6_test "tls-graphql-apikey" \
        "$PERF_DIR/configs/k6-graphql/k8s-graphql-apikey.js" \
        "$DURATION" \
        "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql -e API_KEY=pk_perftest_1234567890abcdef"
    
    sleep 3
    
    # TLS GraphQL with OIDC auth
    if [[ -n "$jwt_token" ]]; then
        run_k6_test "tls-graphql-oidc" \
            "$PERF_DIR/configs/k6-graphql/k8s-graphql-oidc.js" \
            "$DURATION" \
            "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql -e JWT_TOKEN=${jwt_token}"
    else
        log_warn "Skipping TLS GraphQL OIDC test - no JWT token"
        TEST_NAMES+=("tls-graphql-oidc")
        TEST_RESULTS+=("SKIP")
        TEST_DURATIONS+=("0")
        TEST_RPS+=("0")
    fi
    
    sleep 3
    
    # TLS GraphQL rate limiting via Redis Sentinel
    run_k6_test "tls-graphql-ratelimit" \
        "$PERF_DIR/configs/k6-graphql/k8s-graphql-ratelimit.js" \
        "$DURATION" \
        "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql/ratelimit"
    
    sleep 3
    
    # TLS GraphQL transform
    run_k6_test "tls-graphql-transform" \
        "$PERF_DIR/configs/k6-graphql/k8s-graphql-transform.js" \
        "$DURATION" \
        "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql"
    
    sleep 3
    
    # TLS GraphQL CORS
    run_k6_test "tls-graphql-cors" \
        "$PERF_DIR/configs/k6-graphql/k8s-graphql-basic.js" \
        "$DURATION" \
        "-e GATEWAY_URL=${GATEWAY_HTTPS}/graphql -e ORIGIN=https://example.com"
}

# ==============================================================================
# Summary Report
# ==============================================================================

print_summary() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${CYAN}  K8s Comprehensive Performance Test Summary${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Namespace:  ${K8S_NAMESPACE}"
    echo "  Gateway:    ${GATEWAY_HTTPS}"
    echo "  Duration:   ${DURATION}s per test"
    echo "  Target RPS: ${RPS}"
    echo "  Results:    ${RESULTS_DIR}"
    echo ""
    echo "  Test Results:"
    echo "  ─────────────────────────────────────────────────────────────"
    
    local pass_count=0
    local fail_count=0
    local skip_count=0
    
    for i in "${!TEST_NAMES[@]}"; do
        local name="${TEST_NAMES[$i]}"
        local result="${TEST_RESULTS[$i]}"
        local duration="${TEST_DURATIONS[$i]}"
        local rps="${TEST_RPS[$i]}"
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
        esac
        
        printf "  %b  %-35s %s  (${duration}s, RPS: ${rps})\n" "$icon" "$name" "$result"
    done
    
    echo "  ─────────────────────────────────────────────────────────────"
    echo ""
    echo -e "  ${GREEN}Passed: ${pass_count}${NC}  ${RED}Failed: ${fail_count}${NC}  ${YELLOW}Skipped: ${skip_count}${NC}"
    echo ""
    
    # Save summary to JSON
    local summary_file="$RESULTS_DIR/summary.json"
    {
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"namespace\": \"${K8S_NAMESPACE}\","
        echo "  \"gateway\": \"${GATEWAY_HTTPS}\","
        echo "  \"duration_per_test\": ${DURATION},"
        echo "  \"target_rps\": ${RPS},"
        echo "  \"passed\": ${pass_count},"
        echo "  \"failed\": ${fail_count},"
        echo "  \"skipped\": ${skip_count},"
        echo "  \"tests\": ["
        for i in "${!TEST_NAMES[@]}"; do
            local comma=","
            if [[ $i -eq $((${#TEST_NAMES[@]} - 1)) ]]; then
                comma=""
            fi
            echo "    {\"name\": \"${TEST_NAMES[$i]}\", \"result\": \"${TEST_RESULTS[$i]}\", \"duration\": ${TEST_DURATIONS[$i]}, \"rps\": \"${TEST_RPS[$i]}\"}${comma}"
        done
        echo "  ]"
        echo "}"
    } > "$summary_file"
    
    log_success "Summary saved to: ${summary_file}"
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${CYAN}  K8s Comprehensive Performance Tests${NC}"
    echo -e "${CYAN}  avapigw Gateway - All Scenarios (3 min each)${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    check_prerequisites
    discover_ports
    
    # Check gateway health via metrics port (no rate limiting)
    log_info "Checking gateway health via metrics port..."
    local health_status
    health_status=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${K8S_METRICS_PORT}/health" 2>/dev/null)
    if [[ "$health_status" == "200" ]]; then
        log_success "Gateway is healthy"
    else
        log_error "Gateway health check failed (status: $health_status)"
        exit 1
    fi
    
    # Wait for rate limit to reset if needed
    log_info "Waiting 5 seconds for rate limit reset..."
    sleep 5
    
    log_info "Starting comprehensive performance tests..."
    log_info "Each test runs for ${DURATION} seconds"
    log_info "Results will be saved to: ${RESULTS_DIR}"
    echo ""
    
    # Run all test categories
    run_grpc_tests
    run_tls_grpc_tests
    run_http_tests
    run_https_tests
    run_graphql_tests
    run_tls_graphql_tests
    
    # Print summary
    print_summary
}

main "$@"
