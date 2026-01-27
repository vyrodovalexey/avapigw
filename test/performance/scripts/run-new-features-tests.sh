#!/bin/bash
# run-new-features-tests.sh - Run performance tests for new features
# Usage: ./run-new-features-tests.sh [test-name] [options]
#
# Tests:
#   max-sessions      - Test max sessions limiting performance
#   backend-ratelimit - Test backend rate limiting performance
#   capacity-lb       - Test capacity-aware load balancer
#   all               - Run all tests sequentially
#
# Options:
#   --gateway-config=<file>  - Override gateway config
#   --skip-gateway           - Don't start/stop gateway (assume running)
#   --results-dir=<dir>      - Custom results directory
#   --dry-run                - Show what would be run without executing

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

# Default values
TEST_NAME="${1:-all}"
GATEWAY_CONFIG=""
SKIP_GATEWAY=false
RESULTS_DIR=""
DRY_RUN=false
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Parse options
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --gateway-config=*)
            GATEWAY_CONFIG="${1#*=}"
            shift
            ;;
        --skip-gateway)
            SKIP_GATEWAY=true
            shift
            ;;
        --results-dir=*)
            RESULTS_DIR="${1#*=}"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
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
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker is not running"
        exit 1
    fi
    
    # Check Yandex Tank image
    if ! docker images | grep -q "yandex/yandex-tank"; then
        log_warn "Yandex Tank image not found, pulling..."
        docker pull yandex/yandex-tank
    fi
    
    log_success "Prerequisites check passed"
}

# Check backend availability
check_backends() {
    log_info "Checking backend availability..."
    
    local backends=("127.0.0.1:8801" "127.0.0.1:8802")
    local all_available=true
    
    for backend in "${backends[@]}"; do
        if curl -s -o /dev/null -w "%{http_code}" "http://$backend/health" 2>/dev/null | grep -q "200"; then
            log_success "Backend $backend is available"
        else
            log_warn "Backend $backend is not available"
            all_available=false
        fi
    done
    
    if [ "$all_available" = false ]; then
        log_warn "Some backends are not available. Tests may fail."
        log_info "Start backends with: docker-compose -f test/docker-compose/docker-compose.yml up -d"
    fi
}

# Start gateway with specific config
start_gateway() {
    local config_file=$1
    
    if [ "$SKIP_GATEWAY" = true ]; then
        log_info "Skipping gateway start (--skip-gateway)"
        return 0
    fi
    
    log_info "Starting gateway with config: $config_file"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would start gateway with: $config_file"
        return 0
    fi
    
    # Stop any existing gateway
    "$SCRIPT_DIR/start-gateway.sh" --stop 2>/dev/null || true
    
    # Start with new config
    "$SCRIPT_DIR/start-gateway.sh" --config="$config_file" --log-level=warn
    
    # Wait for gateway to be ready
    sleep 2
    
    if curl -s -o /dev/null http://127.0.0.1:8080/health; then
        log_success "Gateway is ready"
    else
        log_error "Gateway failed to start"
        exit 1
    fi
}

# Stop gateway
stop_gateway() {
    if [ "$SKIP_GATEWAY" = true ]; then
        return 0
    fi
    
    log_info "Stopping gateway..."
    "$SCRIPT_DIR/start-gateway.sh" --stop 2>/dev/null || true
}

# Run Yandex Tank test
run_tank_test() {
    local test_name=$1
    local tank_config=$2
    local ammo_file=$3
    local results_subdir="${RESULTS_DIR:-$RESULTS_BASE_DIR/${test_name}_$TIMESTAMP}"
    
    log_header "Running Test: $test_name"
    
    mkdir -p "$results_subdir"
    
    log_info "Tank config: $tank_config"
    log_info "Ammo file: $ammo_file"
    log_info "Results dir: $results_subdir"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would run Yandex Tank with:"
        log_info "  Config: $tank_config"
        log_info "  Ammo: $ammo_file"
        log_info "  Results: $results_subdir"
        return 0
    fi
    
    # Run Yandex Tank in Docker
    docker run --rm \
        --add-host=host.docker.internal:host-gateway \
        -v "$tank_config:/var/loadtest/load.yaml:ro" \
        -v "$ammo_file:/var/loadtest/ammo/$(basename "$ammo_file"):ro" \
        -v "$results_subdir:/var/loadtest/results" \
        yandex/yandex-tank \
        -c /var/loadtest/load.yaml \
        -o "phantom.ammofile=/var/loadtest/ammo/$(basename "$ammo_file")" \
        2>&1 | tee "$results_subdir/tank.log"
    
    # Copy phout.txt to results if it exists
    if [ -f "$results_subdir/phout.txt" ]; then
        log_success "Test completed. Results in: $results_subdir"
    else
        # Try to find phout in subdirectories
        local phout=$(find "$results_subdir" -name "phout.txt" -type f 2>/dev/null | head -1)
        if [ -n "$phout" ]; then
            cp "$phout" "$results_subdir/phout.txt"
            log_success "Test completed. Results in: $results_subdir"
        else
            log_warn "phout.txt not found in results"
        fi
    fi
    
    echo "$results_subdir"
}

# Analyze test results
analyze_results() {
    local results_dir=$1
    local test_name=$2
    
    log_header "Analyzing Results: $test_name"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would analyze results in: $results_dir"
        return 0
    fi
    
    if [ -f "$results_dir/phout.txt" ]; then
        "$SCRIPT_DIR/analyze-results.sh" "$results_dir" --detailed
        "$SCRIPT_DIR/analyze-results.sh" "$results_dir" --export=json
    else
        log_warn "No phout.txt found in $results_dir"
    fi
}

# Run max sessions test
run_max_sessions_test() {
    local gateway_config="${GATEWAY_CONFIG:-$CONFIGS_DIR/gateway-maxsessions.yaml}"
    local tank_config="$CONFIGS_DIR/max-sessions.yaml"
    local ammo_file="$AMMO_DIR/maxsessions.txt"
    
    start_gateway "$gateway_config"
    
    local results_dir=$(run_tank_test "max-sessions" "$tank_config" "$ammo_file")
    
    analyze_results "$results_dir" "max-sessions"
    
    stop_gateway
}

# Run backend rate limit test
run_backend_ratelimit_test() {
    local gateway_config="${GATEWAY_CONFIG:-$CONFIGS_DIR/gateway-backend-ratelimit.yaml}"
    local tank_config="$CONFIGS_DIR/backend-ratelimit.yaml"
    local ammo_file="$AMMO_DIR/backend-ratelimit.txt"
    
    start_gateway "$gateway_config"
    
    local results_dir=$(run_tank_test "backend-ratelimit" "$tank_config" "$ammo_file")
    
    analyze_results "$results_dir" "backend-ratelimit"
    
    stop_gateway
}

# Run capacity-aware load balancer test
run_capacity_lb_test() {
    local gateway_config="${GATEWAY_CONFIG:-$CONFIGS_DIR/gateway-capacity-aware-lb.yaml}"
    local tank_config="$CONFIGS_DIR/capacity-aware-lb.yaml"
    local ammo_file="$AMMO_DIR/capacity-lb.txt"
    
    start_gateway "$gateway_config"
    
    local results_dir=$(run_tank_test "capacity-lb" "$tank_config" "$ammo_file")
    
    analyze_results "$results_dir" "capacity-lb"
    
    stop_gateway
}

# Run all tests
run_all_tests() {
    log_header "Running All New Feature Tests"
    
    local start_time=$(date +%s)
    
    run_max_sessions_test
    run_backend_ratelimit_test
    run_capacity_lb_test
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_header "All Tests Completed"
    log_success "Total duration: ${duration}s"
    log_info "Results directory: $RESULTS_BASE_DIR"
}

# Show help
show_help() {
    cat << EOF
Performance Tests for New Features

Usage: $0 [test-name] [options]

Tests:
  max-sessions      Test max sessions limiting performance
  backend-ratelimit Test backend rate limiting performance
  capacity-lb       Test capacity-aware load balancer
  all               Run all tests sequentially (default)

Options:
  --gateway-config=<file>  Override gateway config
  --skip-gateway           Don't start/stop gateway (assume running)
  --results-dir=<dir>      Custom results directory
  --dry-run                Show what would be run without executing

Examples:
  $0 max-sessions
  $0 backend-ratelimit --skip-gateway
  $0 all --dry-run
  $0 capacity-lb --gateway-config=/path/to/custom.yaml

Prerequisites:
  - Docker installed and running
  - Yandex Tank image (yandex/yandex-tank)
  - Backend services running on ports 8801, 8802

EOF
}

# Main
main() {
    case $TEST_NAME in
        max-sessions)
            check_prerequisites
            check_backends
            run_max_sessions_test
            ;;
        backend-ratelimit)
            check_prerequisites
            check_backends
            run_backend_ratelimit_test
            ;;
        capacity-lb)
            check_prerequisites
            check_backends
            run_capacity_lb_test
            ;;
        all)
            check_prerequisites
            check_backends
            run_all_tests
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown test: $TEST_NAME"
            show_help
            exit 1
            ;;
    esac
}

main
