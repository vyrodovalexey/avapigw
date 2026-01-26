#!/bin/bash
# run-websocket-test.sh - WebSocket Performance Test Runner using k6
# Usage: ./run-websocket-test.sh [test-name] [options]
#
# Test names:
#   connection      - Connection throughput test (default)
#   message         - Message throughput test
#   concurrent      - Concurrent connections test
#   tls-message     - Message throughput with TLS (WSS)
#   auth-message    - Message throughput with JWT auth
#   all             - Run all WebSocket tests sequentially
#
# Options:
#   --ws-url=<url>    - WebSocket URL (default: ws://host.docker.internal:8080/ws)
#   --duration=<time> - Test duration (default: 5m)
#   --vus=<number>    - Number of virtual users
#   --dry-run         - Show command without running
#   --no-gateway      - Don't check gateway
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
TEST_NAME="${1:-connection}"
WS_URL="ws://host.docker.internal:8080/ws"
DURATION=""
VUS=""
DRY_RUN=false
CHECK_GATEWAY=true
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
        --ws-url=*)
            WS_URL="${1#*=}"
            shift
            ;;
        --duration=*)
            DURATION="${1#*=}"
            shift
            ;;
        --vus=*)
            VUS="${1#*=}"
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
    
    # Pull k6 image if not present
    if ! docker image inspect grafana/k6:latest &> /dev/null 2>&1; then
        log_info "Pulling k6 Docker image..."
        docker pull grafana/k6:latest
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

# Check WebSocket endpoint
check_websocket_endpoint() {
    log_info "Checking WebSocket endpoint..."
    
    # Extract host and port from WS URL
    local ws_host=$(echo "$WS_URL" | sed -E 's|wss?://([^:/]+).*|\1|')
    local ws_port=$(echo "$WS_URL" | sed -E 's|wss?://[^:]+:([0-9]+).*|\1|')
    
    # Default port
    if [[ -z "$ws_port" ]] || [[ "$ws_port" == "$WS_URL" ]]; then
        ws_port="8080"
    fi
    
    # Replace host.docker.internal with localhost for local check
    if [[ "$ws_host" == "host.docker.internal" ]]; then
        ws_host="127.0.0.1"
    fi
    
    # Check if HTTP endpoint is accessible (WebSocket upgrade happens over HTTP)
    if curl -s -o /dev/null -w "%{http_code}" "http://$ws_host:$ws_port/health" 2>/dev/null | grep -q "200"; then
        log_success "Gateway HTTP endpoint is accessible"
        log_warn "Note: WebSocket support depends on gateway configuration"
        return 0
    fi
    
    log_warn "Could not verify WebSocket endpoint (gateway may not be running or WebSocket not configured)"
    return 0
}

# Get test script path and configuration
get_test_config() {
    local test_name=$1
    
    case $test_name in
        connection)
            SCRIPT_FILE="websocket-connection.js"
            USE_TLS=false
            NEEDS_AUTH=false
            ;;
        message)
            SCRIPT_FILE="websocket-message.js"
            USE_TLS=false
            NEEDS_AUTH=false
            ;;
        concurrent)
            SCRIPT_FILE="websocket-concurrent.js"
            USE_TLS=false
            NEEDS_AUTH=false
            ;;
        tls-message)
            SCRIPT_FILE="websocket-tls-message.js"
            WS_URL="wss://host.docker.internal:8443/ws"
            USE_TLS=true
            NEEDS_AUTH=false
            ;;
        auth-message)
            SCRIPT_FILE="websocket-auth-message.js"
            WS_URL="ws://host.docker.internal:8080/ws/protected"
            USE_TLS=false
            NEEDS_AUTH=true
            ;;
        *)
            log_error "Unknown test: $test_name"
            echo "Available tests: connection, message, concurrent, tls-message, auth-message, all"
            exit 1
            ;;
    esac
}

# Run a single WebSocket test
run_test() {
    local test_name=$1
    
    log_info "=========================================="
    log_info "Running WebSocket test: $test_name"
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
    local results_dir="$PERF_DIR/results/websocket-${test_name}_${timestamp}"
    mkdir -p "$results_dir"
    
    log_info "Results will be saved to: $results_dir"
    log_info "WebSocket URL: $WS_URL"
    log_info "Test script: $SCRIPT_FILE"
    log_info "TLS: $USE_TLS"
    log_info "Auth: $NEEDS_AUTH"
    
    # Build k6 command
    local k6_cmd="docker run --rm"
    k6_cmd+=" --add-host=host.docker.internal:host-gateway"
    k6_cmd+=" -v $PERF_DIR/configs/websocket:/scripts:ro"
    k6_cmd+=" -v $results_dir:/results"
    k6_cmd+=" -e WS_URL=$WS_URL"
    
    # Add Keycloak environment variables for auth tests
    if [[ "$NEEDS_AUTH" == "true" ]]; then
        k6_cmd+=" -e KEYCLOAK_URL=http://host.docker.internal:8090"
        k6_cmd+=" -e KEYCLOAK_REALM=$KEYCLOAK_REALM"
        k6_cmd+=" -e KEYCLOAK_CLIENT_ID=$KEYCLOAK_CLIENT_ID"
        k6_cmd+=" -e KEYCLOAK_CLIENT_SECRET=$KEYCLOAK_CLIENT_SECRET"
    fi
    
    # Add TLS options
    if [[ "$USE_TLS" == "true" ]]; then
        k6_cmd+=" -e K6_INSECURE_SKIP_TLS_VERIFY=true"
    fi
    
    k6_cmd+=" grafana/k6:latest run"
    
    # Add duration override if specified
    if [[ -n "$DURATION" ]]; then
        k6_cmd+=" --duration $DURATION"
    fi
    
    # Add VUs override if specified
    if [[ -n "$VUS" ]]; then
        k6_cmd+=" --vus $VUS"
    fi
    
    k6_cmd+=" /scripts/$SCRIPT_FILE"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run - would execute:"
        echo "$k6_cmd"
        return 0
    fi
    
    log_info "Starting k6..."
    
    # Run the test
    eval $k6_cmd
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "Test completed successfully"
        
        # Display results if JSON file exists
        local json_file="$results_dir/websocket-${test_name}-results.json"
        if [[ -f "$json_file" ]]; then
            display_results "$json_file" "$test_name"
        fi
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
        log_warn "jq not installed, skipping detailed results display"
        return
    fi
    
    echo ""
    echo "============================================"
    echo -e "${CYAN}  WebSocket Test Results: $test_name${NC}"
    echo "============================================"
    
    # Extract key metrics
    local metrics=$(jq -r '.metrics' "$json_file" 2>/dev/null)
    
    if [[ -n "$metrics" ]] && [[ "$metrics" != "null" ]]; then
        echo ""
        echo "Key Metrics:"
        
        # Connection time
        local conn_avg=$(jq -r '.metrics.ws_connection_time.values.avg // .metrics.wss_tls_handshake_time.values.avg // 0' "$json_file" 2>/dev/null)
        local conn_p95=$(jq -r '.metrics.ws_connection_time.values["p(95)"] // .metrics.wss_tls_handshake_time.values["p(95)"] // 0' "$json_file" 2>/dev/null)
        
        if [[ "$conn_avg" != "0" ]] && [[ "$conn_avg" != "null" ]]; then
            printf "  Connection Time (avg): %.2f ms\n" "$conn_avg"
            printf "  Connection Time (p95): %.2f ms\n" "$conn_p95"
        fi
        
        # Success rate
        local success_rate=$(jq -r '.metrics.ws_connection_success.values.rate // .metrics.ws_message_success.values.rate // .metrics.wss_message_success.values.rate // .metrics.ws_auth_message_success.values.rate // 0' "$json_file" 2>/dev/null)
        if [[ "$success_rate" != "0" ]] && [[ "$success_rate" != "null" ]]; then
            printf "  Success Rate: %.2f%%\n" "$(echo "$success_rate * 100" | bc)"
        fi
        
        # Messages
        local msgs_sent=$(jq -r '.metrics.ws_messages_sent.values.count // .metrics.wss_messages_sent.values.count // .metrics.ws_auth_messages_sent.values.count // 0' "$json_file" 2>/dev/null)
        local msgs_recv=$(jq -r '.metrics.ws_messages_received.values.count // .metrics.wss_messages_received.values.count // .metrics.ws_auth_messages_received.values.count // 0' "$json_file" 2>/dev/null)
        
        if [[ "$msgs_sent" != "0" ]] && [[ "$msgs_sent" != "null" ]]; then
            echo "  Messages Sent: $msgs_sent"
        fi
        if [[ "$msgs_recv" != "0" ]] && [[ "$msgs_recv" != "null" ]]; then
            echo "  Messages Received: $msgs_recv"
        fi
        
        # Message latency
        local msg_avg=$(jq -r '.metrics.ws_message_latency.values.avg // .metrics.wss_message_latency.values.avg // .metrics.ws_auth_message_latency.values.avg // 0' "$json_file" 2>/dev/null)
        local msg_p95=$(jq -r '.metrics.ws_message_latency.values["p(95)"] // .metrics.wss_message_latency.values["p(95)"] // .metrics.ws_auth_message_latency.values["p(95)"] // 0' "$json_file" 2>/dev/null)
        
        if [[ "$msg_avg" != "0" ]] && [[ "$msg_avg" != "null" ]]; then
            printf "  Message Latency (avg): %.2f ms\n" "$msg_avg"
            printf "  Message Latency (p95): %.2f ms\n" "$msg_p95"
        fi
        
        # Peak connections (for concurrent test)
        local peak=$(jq -r '.metrics.ws_peak_connections.values.value // 0' "$json_file" 2>/dev/null)
        if [[ "$peak" != "0" ]] && [[ "$peak" != "null" ]]; then
            echo "  Peak Concurrent: $peak"
        fi
    fi
    
    echo "============================================"
}

# Run all WebSocket tests
run_all_tests() {
    local tests=("connection" "message" "concurrent" "tls-message" "auth-message")
    local failed_tests=()
    
    log_info "Running all WebSocket performance tests..."
    
    for test in "${tests[@]}"; do
        if ! run_test "$test"; then
            failed_tests+=("$test")
        fi
        
        # Brief pause between tests
        sleep 5
    done
    
    echo ""
    log_info "=========================================="
    log_info "WebSocket Test Summary"
    log_info "=========================================="
    
    if [[ ${#failed_tests[@]} -eq 0 ]]; then
        log_success "All WebSocket tests passed!"
    else
        log_error "Failed tests: ${failed_tests[*]}"
        return 1
    fi
}

# Show help
show_help() {
    cat << EOF
WebSocket Performance Test Runner using k6

Usage: $0 [test-name] [options]

Test names:
  connection      Connection throughput test (default)
  message         Message throughput test
  concurrent      Concurrent connections test
  tls-message     Message throughput with TLS (WSS)
  auth-message    Message throughput with JWT auth
  all             Run all WebSocket tests sequentially

Options:
  --ws-url=<url>    WebSocket URL (default: ws://host.docker.internal:8080/ws)
  --duration=<time> Test duration (e.g., 5m, 300s)
  --vus=<number>    Number of virtual users
  --dry-run         Show command without running
  --no-gateway      Don't check gateway
  --token=<token>   JWT token for auth tests

Examples:
  $0 connection
  $0 message --duration=5m --vus=100
  $0 tls-message
  $0 auth-message --token=eyJhbGc...
  $0 all
  $0 concurrent --ws-url=ws://localhost:8080/ws

Note: WebSocket support requires the gateway to be configured with WebSocket
proxy capabilities. If the gateway doesn't support WebSocket, these tests
will fail to connect.

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
    echo "  WebSocket Performance Test Runner"
    echo "  Using k6"
    echo "=========================================="
    echo ""
    
    check_prerequisites
    
    if [[ "$CHECK_GATEWAY" == "true" ]] && [[ "$DRY_RUN" == "false" ]]; then
        check_websocket_endpoint
    fi
    
    if [[ "$TEST_NAME" == "all" ]]; then
        run_all_tests
    else
        run_test "$TEST_NAME"
    fi
}

main
