#!/bin/bash
# run-test.sh - Main Yandex Tank test runner for avapigw
# Usage: ./run-test.sh [test-name] [options]
#
# Test names:
#   Basic Tests:
#     http-throughput       - HTTP GET throughput test (default)
#     http-tls-throughput   - HTTPS GET throughput test with TLS
#     http-auth-throughput  - HTTP GET throughput test with JWT auth
#     http-post             - HTTP POST with payload test
#
#   Load Tests:
#     load-balancing        - Load balancing verification
#     rate-limiting         - Rate limiting stress test
#     circuit-breaker       - Circuit breaker test
#     mixed-workload        - Mixed HTTP workload test
#
#   Feature Tests (New):
#     smoke-test            - Quick 30s smoke test to verify setup
#     route-request-limits  - Route-level request limits testing
#     route-cors            - Route-level CORS configuration testing
#
#   Backend Tests (New):
#     backend-circuit-breaker - Backend circuit breaker behavior
#     backend-jwt-auth        - Backend JWT authentication overhead
#     backend-basic-auth      - Backend Basic authentication overhead
#
#   Vault PKI TLS Tests:
#     vault-tls-handshake     - TLS handshake with Vault-issued certs
#     vault-cert-renewal      - Certificate renewal under load
#     vault-backend-mtls      - Backend mTLS with Vault client certs
#     vault-multi-route-sni   - Multi-route SNI with Vault certs
#
#   all                   - Run all tests sequentially
#
# Options:
#   --dry-run         - Validate configuration without running
#   --duration=<time> - Override test duration (e.g., --duration=5m)
#   --rps=<number>    - Override target RPS
#   --no-gateway      - Don't start gateway (assume it's already running)
#   --verbose         - Enable verbose output
#   --secure          - Use secure gateway config with TLS/auth
#   --features        - Use features gateway config (for new feature tests)
#   --token=<token>   - JWT token for auth tests (or will fetch from Keycloak)

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
TEST_NAME="${1:-http-throughput}"
DRY_RUN=false
START_GATEWAY=true
VERBOSE=false
DURATION_OVERRIDE=""
RPS_OVERRIDE=""
USE_SECURE_CONFIG=false
USE_FEATURES_CONFIG=false
JWT_TOKEN=""

# Keycloak configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://127.0.0.1:8090}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-gateway-test}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-gateway}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-gateway-secret}"

# Parse options
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --duration=*)
            DURATION_OVERRIDE="${1#*=}"
            shift
            ;;
        --rps=*)
            RPS_OVERRIDE="${1#*=}"
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
        --secure)
            USE_SECURE_CONFIG=true
            shift
            ;;
        --features)
            USE_FEATURES_CONFIG=true
            shift
            ;;
        --token=*)
            JWT_TOKEN="${1#*=}"
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
    
    log_success "Prerequisites check passed"
}

# Get JWT token from Keycloak
get_jwt_token() {
    if [[ -n "$JWT_TOKEN" ]]; then
        log_info "Using provided JWT token"
        return 0
    fi
    
    log_info "Fetching JWT token from Keycloak..."
    
    local token_url="${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token"
    
    local response
    response=$(curl -s -X POST "$token_url" \
        -d "grant_type=client_credentials" \
        -d "client_id=${KEYCLOAK_CLIENT_ID}" \
        -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    JWT_TOKEN=$(echo "$response" | jq -r '.access_token // empty')
    
    if [[ -z "$JWT_TOKEN" ]]; then
        log_error "Failed to get JWT token from Keycloak"
        log_error "Response: $response"
        return 1
    fi
    
    log_success "JWT token obtained successfully"
    return 0
}

# Check gateway connectivity
check_gateway() {
    local port=${1:-8080}
    local protocol=${2:-http}
    
    log_info "Checking gateway connectivity on port $port..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        local curl_opts=""
        if [[ "$protocol" == "https" ]]; then
            curl_opts="-k"  # Skip certificate verification for self-signed certs
        fi
        
        if curl -s -o /dev/null -w "%{http_code}" $curl_opts "${protocol}://127.0.0.1:${port}/health" | grep -q "200"; then
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

# Check backend connectivity
check_backends() {
    log_info "Checking backend connectivity..."
    
    local backends_ok=true
    
    for port in 8801 8802; do
        if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/health" 2>/dev/null | grep -q "200"; then
            log_success "Backend on port ${port} is responding"
        else
            log_warn "Backend on port ${port} is not responding"
            backends_ok=false
        fi
    done
    
    if [ "$backends_ok" = false ]; then
        log_warn "Some backends are not available. Tests may fail."
    fi
}

# Start gateway
start_gateway() {
    if [ "$START_GATEWAY" = false ]; then
        log_info "Skipping gateway start (--no-gateway specified)"
        return 0
    fi
    
    log_info "Starting gateway for performance testing..."
    
    local config_file="gateway-perftest.yaml"
    if [ "$USE_SECURE_CONFIG" = true ]; then
        config_file="gateway-perftest-secure.yaml"
    elif [ "$USE_FEATURES_CONFIG" = true ]; then
        config_file="gateway-perftest-features.yaml"
    fi
    
    # Check if gateway is already running
    if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/health 2>/dev/null | grep -q "200"; then
        log_info "Gateway is already running"
        return 0
    fi
    
    # Start gateway in background
    cd "$PROJECT_ROOT"
    
    if [ -f "bin/gateway" ]; then
        log_info "Starting gateway from bin/gateway with config $config_file..."
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
    check_gateway 8080 http
    
    # If using secure config, also check TLS port
    if [ "$USE_SECURE_CONFIG" = true ]; then
        check_gateway 8443 https
    fi
}

# Stop gateway
stop_gateway() {
    if [ -f "$PERF_DIR/results/.gateway.pid" ]; then
        local pid=$(cat "$PERF_DIR/results/.gateway.pid")
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping gateway (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            rm -f "$PERF_DIR/results/.gateway.pid"
        fi
    fi
}

# Get config and ammo file for test
get_test_config() {
    local test_name=$1
    
    case $test_name in
        http-throughput)
            CONFIG_FILE="http-throughput.yaml"
            AMMO_FILE="http-get.txt"
            ;;
        http-tls-throughput)
            CONFIG_FILE="http-tls-throughput.yaml"
            AMMO_FILE="http-get.txt"
            USE_SECURE_CONFIG=true
            ;;
        https-throughput)
            CONFIG_FILE="https-throughput.yaml"
            AMMO_FILE="https-get.txt"
            USE_SECURE_CONFIG=true
            ;;
        http-auth-throughput)
            CONFIG_FILE="http-auth-throughput.yaml"
            AMMO_FILE="http-auth.txt"
            NEEDS_AUTH=true
            ;;
        http-post)
            CONFIG_FILE="http-post.yaml"
            AMMO_FILE="http-post.txt"
            ;;
        load-balancing)
            CONFIG_FILE="load-balancing.yaml"
            AMMO_FILE="http-get.txt"
            ;;
        rate-limiting)
            CONFIG_FILE="rate-limiting.yaml"
            AMMO_FILE="http-get.txt"
            ;;
        circuit-breaker)
            CONFIG_FILE="circuit-breaker.yaml"
            AMMO_FILE="http-get.txt"
            ;;
        mixed-workload)
            CONFIG_FILE="mixed-workload.yaml"
            AMMO_FILE="mixed.txt"
            ;;
        # New feature tests
        smoke-test)
            CONFIG_FILE="smoke-test.yaml"
            AMMO_FILE="http-get.txt"
            ;;
        route-request-limits)
            CONFIG_FILE="route-request-limits.yaml"
            AMMO_FILE="route-limits.txt"
            USE_FEATURES_CONFIG=true
            ;;
        route-cors)
            CONFIG_FILE="route-cors.yaml"
            AMMO_FILE="route-cors.txt"
            USE_FEATURES_CONFIG=true
            ;;
        backend-circuit-breaker)
            CONFIG_FILE="backend-circuit-breaker.yaml"
            AMMO_FILE="backend-cb.txt"
            USE_FEATURES_CONFIG=true
            ;;
        backend-jwt-auth)
            CONFIG_FILE="backend-jwt-auth.yaml"
            AMMO_FILE="backend-jwt.txt"
            USE_FEATURES_CONFIG=true
            ;;
        backend-basic-auth)
            CONFIG_FILE="backend-basic-auth.yaml"
            AMMO_FILE="backend-basic.txt"
            USE_FEATURES_CONFIG=true
            ;;
        max-sessions)
            CONFIG_FILE="max-sessions.yaml"
            AMMO_FILE="maxsessions.txt"
            ;;
        smoke-max-sessions)
            CONFIG_FILE="smoke-max-sessions.yaml"
            AMMO_FILE="maxsessions.txt"
            ;;
        capacity-aware-lb)
            CONFIG_FILE="capacity-aware-lb.yaml"
            AMMO_FILE="capacity-lb.txt"
            ;;
        backend-ratelimit)
            CONFIG_FILE="backend-ratelimit.yaml"
            AMMO_FILE="backend-ratelimit.txt"
            ;;
        # Vault PKI TLS tests
        vault-tls-handshake)
            CONFIG_FILE="vault-tls-handshake.yaml"
            AMMO_FILE="vault-tls-handshake.txt"
            USE_SECURE_CONFIG=true
            ;;
        vault-cert-renewal)
            CONFIG_FILE="vault-cert-renewal.yaml"
            AMMO_FILE="vault-cert-renewal.txt"
            USE_SECURE_CONFIG=true
            ;;
        vault-backend-mtls)
            CONFIG_FILE="vault-backend-mtls.yaml"
            AMMO_FILE="vault-backend-mtls.txt"
            ;;
        vault-multi-route-sni)
            CONFIG_FILE="vault-multi-route-sni.yaml"
            AMMO_FILE="vault-multi-route-sni.txt"
            USE_SECURE_CONFIG=true
            ;;
        *)
            log_error "Unknown test: $test_name"
            echo "Available tests:"
            echo "  Basic: http-throughput, http-tls-throughput, http-auth-throughput, http-post"
            echo "  Load: load-balancing, rate-limiting, circuit-breaker, mixed-workload"
            echo "  Features: smoke-test, route-request-limits, route-cors"
            echo "  Backend: backend-circuit-breaker, backend-jwt-auth, backend-basic-auth"
            echo "  Advanced: max-sessions, smoke-max-sessions, capacity-aware-lb, backend-ratelimit"
            echo "  Vault TLS: vault-tls-handshake, vault-cert-renewal, vault-backend-mtls, vault-multi-route-sni"
            exit 1
            ;;
    esac
}

# Prepare ammo file with JWT token
prepare_auth_ammo() {
    local ammo_file=$1
    local output_file=$2
    
    if [[ -z "$JWT_TOKEN" ]]; then
        log_error "JWT token is required for auth tests"
        return 1
    fi
    
    # Replace ${JWT_TOKEN} placeholder with actual token
    sed "s/\${JWT_TOKEN}/${JWT_TOKEN}/g" "$ammo_file" > "$output_file"
    
    log_success "Prepared auth ammo file with JWT token"
}

# Run a single test
run_test() {
    local test_name=$1
    
    log_info "=========================================="
    log_info "Running test: $test_name"
    log_info "=========================================="
    
    get_test_config "$test_name"
    
    # Get JWT token if needed
    if [[ "${NEEDS_AUTH:-false}" == "true" ]]; then
        if ! get_jwt_token; then
            log_error "Failed to get JWT token for auth test"
            return 1
        fi
    fi
    
    # Create results directory with timestamp
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local results_dir="$PERF_DIR/results/${test_name}_${timestamp}"
    mkdir -p "$results_dir"
    mkdir -p "$results_dir/ammo"
    
    log_info "Results will be saved to: $results_dir"
    
    # Copy config file to results directory
    cp "$PERF_DIR/configs/$CONFIG_FILE" "$results_dir/load.yaml"
    
    # Prepare ammo file
    if [[ "${NEEDS_AUTH:-false}" == "true" ]]; then
        prepare_auth_ammo "$PERF_DIR/ammo/$AMMO_FILE" "$results_dir/ammo/$AMMO_FILE"
    else
        cp "$PERF_DIR/ammo/$AMMO_FILE" "$results_dir/ammo/$AMMO_FILE"
    fi
    
    # Update config to use local ammo path (ammo is mounted at /var/loadtest/ammo/)
    # No path rewrite needed - ammo is mounted at the expected location
    
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
    
    # Add overrides if specified
    if [ -n "$RPS_OVERRIDE" ]; then
        docker_cmd+=" -o \"phantom.rps_schedule=const($RPS_OVERRIDE,5m)\""
    fi
    
    if [ "$DRY_RUN" = true ]; then
        log_info "Dry run - would execute:"
        echo "$docker_cmd"
        return 0
    fi
    
    log_info "Starting Yandex Tank..."
    log_info "Command: $docker_cmd"
    
    # Run the test
    eval $docker_cmd
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        log_success "Test completed successfully"
        log_info "Results saved to: $results_dir"
        
        # Generate summary
        if [ -f "$results_dir/phout.txt" ] || [ -f "$results_dir/phout_"*.log ]; then
            log_info "Generating results summary..."
            "$SCRIPT_DIR/analyze-results.sh" "$results_dir" --summary 2>/dev/null || true
        fi
    else
        log_error "Test failed with exit code: $exit_code"
    fi
    
    return $exit_code
}

# Run all tests
run_all_tests() {
    local tests=("http-throughput" "http-tls-throughput" "http-auth-throughput" "http-post" "load-balancing" "rate-limiting" "mixed-workload")
    local failed_tests=()
    
    log_info "Running all performance tests..."
    
    for test in "${tests[@]}"; do
        if ! run_test "$test"; then
            failed_tests+=("$test")
        fi
        
        # Brief pause between tests
        sleep 5
    done
    
    echo ""
    log_info "=========================================="
    log_info "Test Summary"
    log_info "=========================================="
    
    if [ ${#failed_tests[@]} -eq 0 ]; then
        log_success "All tests passed!"
    else
        log_error "Failed tests: ${failed_tests[*]}"
        return 1
    fi
}

# Show help
show_help() {
    cat << EOF
HTTP Performance Test Runner using Yandex Tank

Usage: $0 [test-name] [options]

Test names:
  http-throughput       HTTP GET throughput test (default)
  http-tls-throughput   HTTPS GET throughput test with TLS
  http-auth-throughput  HTTP GET throughput test with JWT auth
  http-post             HTTP POST with payload test
  load-balancing        Load balancing verification
  rate-limiting         Rate limiting stress test
  circuit-breaker       Circuit breaker test
  mixed-workload        Mixed HTTP workload test
  vault-tls-handshake   TLS handshake with Vault-issued certs
  vault-cert-renewal    Certificate renewal under load
  vault-backend-mtls    Backend mTLS with Vault client certs
  vault-multi-route-sni Multi-route SNI with Vault certs
  all                   Run all tests sequentially

Options:
  --dry-run             Validate configuration without running
  --duration=<time>     Override test duration (e.g., --duration=5m)
  --rps=<number>        Override target RPS
  --no-gateway          Don't start gateway (assume it's already running)
  --verbose             Enable verbose output
  --secure              Use secure gateway config with TLS/auth
  --token=<token>       JWT token for auth tests

Examples:
  $0 http-throughput
  $0 http-tls-throughput --secure
  $0 http-auth-throughput --token=eyJhbGc...
  $0 all --no-gateway

EOF
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
    if [[ "$TEST_NAME" == "help" ]] || [[ "$TEST_NAME" == "--help" ]] || [[ "$TEST_NAME" == "-h" ]]; then
        show_help
        exit 0
    fi
    
    echo ""
    echo "=========================================="
    echo "  avapigw Performance Test Runner"
    echo "  Using Yandex Tank"
    echo "=========================================="
    echo ""
    
    check_prerequisites
    
    if [ "$DRY_RUN" = false ]; then
        start_gateway
        check_backends
    fi
    
    if [ "$TEST_NAME" = "all" ]; then
        run_all_tests
    else
        run_test "$TEST_NAME"
    fi
}

main
