#!/bin/bash
# run-grpc-test.sh - gRPC Performance Test Runner using ghz
# Usage: ./run-grpc-test.sh [test-name] [options]
#
# Test names:
#   unary           - Unary RPC throughput test (default)
#   tls-unary       - Unary RPC with TLS
#   auth-unary      - Unary RPC with JWT auth
#   server-stream   - Server streaming test
#   client-stream   - Client streaming test
#   bidi-stream     - Bidirectional streaming test
#   all             - Run all gRPC tests sequentially
#
# Options:
#   --host=<host>     - Target host (default: 127.0.0.1)
#   --port=<port>     - Target port (default: 9000)
#   --duration=<time> - Test duration (default: 5m)
#   --rps=<number>    - Requests per second
#   --concurrency=<n> - Number of concurrent workers
#   --dry-run         - Show command without running
#   --no-gateway      - Don't check gateway (assume it's running)
#   --direct          - Test backend directly (skip gateway)
#   --token=<token>   - JWT token for auth tests

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
TEST_NAME="${1:-unary}"
HOST="127.0.0.1"
PORT="9000"
DURATION="5m"
RPS=""
CONCURRENCY=""
DRY_RUN=false
CHECK_GATEWAY=true
DIRECT_BACKEND=false
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
        --concurrency=*)
            CONCURRENCY="${1#*=}"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --no-gateway)
            CHECK_GATEWAY=false
            shift
            ;;
        --direct)
            DIRECT_BACKEND=true
            PORT="8803"
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
    
    # Pull ghz image if not present
    if ! docker image inspect ghcr.io/bojand/ghz:latest &> /dev/null 2>&1; then
        log_info "Pulling ghz Docker image..."
        docker pull ghcr.io/bojand/ghz:latest
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

# Check gRPC endpoint
check_grpc_endpoint() {
    local host=$1
    local port=$2
    
    log_info "Checking gRPC endpoint at $host:$port..."
    
    # Use grpcurl if available, otherwise try a simple connection test
    if command -v grpcurl &> /dev/null; then
        if grpcurl -plaintext "$host:$port" list &> /dev/null; then
            log_success "gRPC endpoint is responding"
            return 0
        fi
    fi
    
    # Fallback: try netcat
    if command -v nc &> /dev/null; then
        if nc -z "$host" "$port" 2>/dev/null; then
            log_success "Port $port is open"
            return 0
        fi
    fi
    
    # Fallback: try curl (won't work for gRPC but checks port)
    if curl -s --connect-timeout 5 "http://$host:$port" &>/dev/null || [[ $? -eq 52 ]] || [[ $? -eq 56 ]]; then
        log_success "Port $port is accessible"
        return 0
    fi
    
    log_warn "Could not verify gRPC endpoint (may still work)"
    return 0
}

# Get test configuration
get_test_config() {
    local test_name=$1
    
    case $test_name in
        unary)
            SERVICE="api.v1.TestService"
            METHOD="Echo"
            DATA='{"message":"Performance test message","timestamp":"2024-01-01T00:00:00Z"}'
            DEFAULT_RPS=2000
            DEFAULT_CONCURRENCY=100
            USE_TLS=false
            NEEDS_AUTH=false
            ;;
        tls-unary)
            SERVICE="api.v1.TestService"
            METHOD="Echo"
            DATA='{"message":"TLS Performance test message","timestamp":"2024-01-01T00:00:00Z"}'
            DEFAULT_RPS=2000
            DEFAULT_CONCURRENCY=100
            PORT="9443"
            USE_TLS=true
            NEEDS_AUTH=false
            ;;
        auth-unary)
            SERVICE="api.v1.ProtectedService"
            METHOD="Echo"
            DATA='{"message":"Authenticated Performance test message","timestamp":"2024-01-01T00:00:00Z"}'
            DEFAULT_RPS=2000
            DEFAULT_CONCURRENCY=100
            USE_TLS=false
            NEEDS_AUTH=true
            ;;
        server-stream)
            SERVICE="api.v1.TestService"
            METHOD="ServerStream"
            DATA='{"count":10,"message":"Stream test message"}'
            DEFAULT_RPS=2000
            DEFAULT_CONCURRENCY=50
            USE_TLS=false
            NEEDS_AUTH=false
            ;;
        client-stream)
            SERVICE="api.v1.TestService"
            METHOD="ClientStream"
            DATA='[{"message":"msg1","sequence":1},{"message":"msg2","sequence":2},{"message":"msg3","sequence":3}]'
            DEFAULT_RPS=2000
            DEFAULT_CONCURRENCY=50
            USE_TLS=false
            NEEDS_AUTH=false
            ;;
        bidi-stream)
            SERVICE="api.v1.TestService"
            METHOD="BidiStream"
            DATA='[{"message":"bidi1","sequence":1},{"message":"bidi2","sequence":2}]'
            DEFAULT_RPS=2000
            DEFAULT_CONCURRENCY=30
            USE_TLS=false
            NEEDS_AUTH=false
            ;;
        *)
            log_error "Unknown test: $test_name"
            echo "Available tests: unary, tls-unary, auth-unary, server-stream, client-stream, bidi-stream, all"
            exit 1
            ;;
    esac
    
    # Apply defaults if not overridden
    RPS=${RPS:-$DEFAULT_RPS}
    CONCURRENCY=${CONCURRENCY:-$DEFAULT_CONCURRENCY}
}

# Run a single gRPC test
run_test() {
    local test_name=$1
    
    log_info "=========================================="
    log_info "Running gRPC test: $test_name"
    log_info "=========================================="
    
    get_test_config "$test_name"
    
    # Get JWT token if needed
    if [[ "$NEEDS_AUTH" == "true" ]]; then
        if ! get_jwt_token; then
            log_error "Failed to get JWT token for auth test"
            return 1
        fi
    fi
    
    # Create results directory
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local results_dir="$PERF_DIR/results/grpc-${test_name}_${timestamp}"
    mkdir -p "$results_dir"
    
    log_info "Results will be saved to: $results_dir"
    log_info "Target: $HOST:$PORT"
    log_info "Service: $SERVICE/$METHOD"
    log_info "Duration: $DURATION"
    log_info "RPS: $RPS"
    log_info "Concurrency: $CONCURRENCY"
    log_info "TLS: $USE_TLS"
    log_info "Auth: $NEEDS_AUTH"
    
    # Build ghz command
    local ghz_cmd="docker run --rm"
    ghz_cmd+=" --add-host=host.docker.internal:host-gateway"
    ghz_cmd+=" -v $results_dir:/results"
    ghz_cmd+=" ghcr.io/bojand/ghz:latest"
    
    if [[ "$USE_TLS" == "true" ]]; then
        ghz_cmd+=" --skipTLS"  # Skip TLS verification for self-signed certs
    else
        ghz_cmd+=" --insecure"
    fi
    
    ghz_cmd+=" --call $SERVICE/$METHOD"
    ghz_cmd+=" --host host.docker.internal"
    ghz_cmd+=" --port $PORT"
    ghz_cmd+=" --duration $DURATION"
    ghz_cmd+=" --rps $RPS"
    ghz_cmd+=" --concurrency $CONCURRENCY"
    ghz_cmd+=" --connections 20"
    ghz_cmd+=" --timeout 30s"
    
    # Add metadata
    local metadata="{\"x-perf-test\":\"grpc-$test_name\"}"
    if [[ "$NEEDS_AUTH" == "true" ]] && [[ -n "$JWT_TOKEN" ]]; then
        metadata="{\"x-perf-test\":\"grpc-$test_name\",\"authorization\":\"Bearer $JWT_TOKEN\"}"
    fi
    ghz_cmd+=" --metadata '$metadata'"
    
    ghz_cmd+=" --format json"
    ghz_cmd+=" --output /results/results.json"
    ghz_cmd+=" --data '$DATA'"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run - would execute:"
        echo "$ghz_cmd"
        return 0
    fi
    
    log_info "Starting ghz..."
    
    # Run the test
    eval $ghz_cmd
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]] && [[ -f "$results_dir/results.json" ]]; then
        log_success "Test completed successfully"
        
        # Parse and display results
        display_results "$results_dir/results.json" "$test_name"
        
        # Save summary
        generate_summary "$results_dir/results.json" "$results_dir/summary.txt" "$test_name"
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
    echo -e "${CYAN}  gRPC Performance Test Results: $test_name${NC}"
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

# Generate summary file
generate_summary() {
    local json_file=$1
    local summary_file=$2
    local test_name=$3
    
    if ! command -v jq &> /dev/null; then
        return
    fi
    
    cat > "$summary_file" << EOF
gRPC Performance Test Summary
=============================
Test: $test_name
Date: $(date)
Target: $HOST:$PORT

Results:
$(jq -r '
"Total Requests: \(.count)
RPS: \(.rps)
Average Latency: \(.average / 1000000) ms
Min Latency: \(.fastest / 1000000) ms
Max Latency: \(.slowest / 1000000) ms

Latency Percentiles:
\(.latencyDistribution | map("  p\(.percentage): \(.latency / 1000000) ms") | join("\n"))

Status Codes:
\(.statusCodeDistribution | to_entries | map("  \(.key): \(.value)") | join("\n"))"
' "$json_file" 2>/dev/null || echo "Error parsing results")
EOF
    
    log_info "Summary saved to: $summary_file"
}

# Run all gRPC tests
run_all_tests() {
    local tests=("unary" "tls-unary" "auth-unary" "server-stream" "client-stream" "bidi-stream")
    local failed_tests=()
    
    log_info "Running all gRPC performance tests..."
    
    for test in "${tests[@]}"; do
        if ! run_test "$test"; then
            failed_tests+=("$test")
        fi
        
        # Brief pause between tests
        sleep 5
    done
    
    echo ""
    log_info "=========================================="
    log_info "gRPC Test Summary"
    log_info "=========================================="
    
    if [[ ${#failed_tests[@]} -eq 0 ]]; then
        log_success "All gRPC tests passed!"
    else
        log_error "Failed tests: ${failed_tests[*]}"
        return 1
    fi
}

# Show help
show_help() {
    cat << EOF
gRPC Performance Test Runner using ghz

Usage: $0 [test-name] [options]

Test names:
  unary           Unary RPC throughput test (default)
  tls-unary       Unary RPC with TLS
  auth-unary      Unary RPC with JWT auth
  server-stream   Server streaming test
  client-stream   Client streaming test
  bidi-stream     Bidirectional streaming test
  all             Run all gRPC tests sequentially

Options:
  --host=<host>     Target host (default: 127.0.0.1)
  --port=<port>     Target port (default: 9000)
  --duration=<time> Test duration (default: 5m)
  --rps=<number>    Requests per second
  --concurrency=<n> Number of concurrent workers
  --dry-run         Show command without running
  --no-gateway      Don't check gateway
  --direct          Test backend directly (port 8803)
  --token=<token>   JWT token for auth tests

Examples:
  $0 unary
  $0 tls-unary --duration=5m --rps=2000
  $0 auth-unary --token=eyJhbGc...
  $0 all --concurrency=100
  $0 unary --direct  # Test backend directly

EOF
}

# Main
main() {
    if [[ "$TEST_NAME" == "help" ]] || [[ "$TEST_NAME" == "--help" ]] || [[ "$TEST_NAME" == "-h" ]]; then
        show_help
        exit 0
    fi
    
    echo ""
    echo "=========================================="
    echo "  gRPC Performance Test Runner"
    echo "  Using ghz"
    echo "=========================================="
    echo ""
    
    check_prerequisites
    
    if [[ "$CHECK_GATEWAY" == "true" ]] && [[ "$DRY_RUN" == "false" ]]; then
        check_grpc_endpoint "$HOST" "$PORT"
    fi
    
    if [[ "$TEST_NAME" == "all" ]]; then
        run_all_tests
    else
        run_test "$TEST_NAME"
    fi
}

main
