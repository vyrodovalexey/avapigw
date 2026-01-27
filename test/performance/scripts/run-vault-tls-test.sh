#!/bin/bash
# run-vault-tls-test.sh - Vault PKI TLS Performance Test Runner
# Usage: ./run-vault-tls-test.sh [test-name] [options]
#
# Test names:
#   vault-tls-handshake     - TLS handshake performance with Vault-issued certs
#   vault-cert-renewal      - Certificate renewal under load
#   vault-backend-mtls      - Backend mTLS with Vault client certificates
#   vault-multi-route-sni   - Multiple routes with Vault certificates (SNI)
#   vault-tls-baseline      - File-based TLS baseline for comparison
#   all                     - Run all Vault TLS tests sequentially
#
# Options:
#   --dry-run         - Validate configuration without running
#   --no-gateway      - Don't start gateway (assume it's already running)
#   --verbose         - Enable verbose output
#   --skip-vault-check - Skip Vault availability check
#   --compare         - Run both Vault and file-based tests for comparison

set -e

# Colors for output
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
TEST_NAME="${1:-vault-tls-handshake}"
DRY_RUN=false
START_GATEWAY=true
VERBOSE=false
SKIP_VAULT_CHECK=false
COMPARE_MODE=false

# Vault configuration
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-myroot}"

# Parse options
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
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
        --skip-vault-check)
            SKIP_VAULT_CHECK=true
            shift
            ;;
        --compare)
            COMPARE_MODE=true
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

log_section() {
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
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    # Check if Yandex Tank image exists
    if ! docker image inspect yandex/yandex-tank:latest &> /dev/null; then
        log_info "Pulling Yandex Tank image..."
        docker pull yandex/yandex-tank:latest
    fi

    log_success "Prerequisites check passed"
}

# Check Vault availability
check_vault() {
    if [ "$SKIP_VAULT_CHECK" = true ]; then
        log_info "Skipping Vault check (--skip-vault-check)"
        return 0
    fi

    log_info "Checking Vault connectivity at $VAULT_ADDR..."

    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" "$VAULT_ADDR/v1/sys/health" 2>/dev/null || echo "000")

    if [[ "$response" == "200" ]] || [[ "$response" == "429" ]] || [[ "$response" == "472" ]] || [[ "$response" == "473" ]]; then
        log_success "Vault is accessible"

        # Verify PKI engine is configured
        local pki_check
        pki_check=$(curl -s -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/pki/roles/test-role" 2>/dev/null || echo "")

        if echo "$pki_check" | grep -q "allowed_domains\|allow_any_name"; then
            log_success "Vault PKI role 'test-role' is configured"
        else
            log_warn "Vault PKI role 'test-role' not found. Running setup..."
            "$SCRIPT_DIR/setup-vault.sh" --vault-addr="$VAULT_ADDR" --vault-token="$VAULT_TOKEN" 2>/dev/null || true

            # Also set up the test-role used by gateway config
            curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
                -H "Content-Type: application/json" \
                "$VAULT_ADDR/v1/pki/roles/test-role" \
                -d '{
                    "allowed_domains": ["localhost", "*.local", "*.test"],
                    "allow_subdomains": true,
                    "allow_localhost": true,
                    "allow_any_name": true,
                    "allow_ip_sans": true,
                    "max_ttl": "72h"
                }' > /dev/null 2>&1 || true

            log_success "Vault PKI setup completed"
        fi

        return 0
    else
        log_error "Vault is not accessible at $VAULT_ADDR (HTTP $response)"
        log_error "Start Vault with: docker run -d --name vault-test -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=myroot -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 vault:latest"
        return 1
    fi
}

# Check gateway connectivity
check_gateway() {
    local port=${1:-8080}
    local protocol=${2:-http}

    log_info "Checking gateway connectivity on port $port ($protocol)..."

    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        local curl_opts=""
        if [[ "$protocol" == "https" ]]; then
            curl_opts="-k"
        fi

        if curl -s -o /dev/null -w "%{http_code}" $curl_opts "${protocol}://127.0.0.1:${port}/health" | grep -q "200"; then
            log_success "Gateway is responding on port $port ($protocol)"
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

# Get config and ammo file for test
get_test_config() {
    local test_name=$1

    case $test_name in
        vault-tls-handshake)
            CONFIG_FILE="vault-tls-handshake.yaml"
            AMMO_FILE="vault-tls-handshake.txt"
            GATEWAY_CONFIG="gateway-perftest-vault-tls.yaml"
            NEEDS_TLS=true
            ;;
        vault-cert-renewal)
            CONFIG_FILE="vault-cert-renewal.yaml"
            AMMO_FILE="vault-cert-renewal.txt"
            GATEWAY_CONFIG="gateway-perftest-vault-tls.yaml"
            NEEDS_TLS=true
            ;;
        vault-backend-mtls)
            CONFIG_FILE="vault-backend-mtls.yaml"
            AMMO_FILE="vault-backend-mtls.txt"
            GATEWAY_CONFIG="gateway-perftest-vault-tls.yaml"
            NEEDS_TLS=false
            ;;
        vault-multi-route-sni)
            CONFIG_FILE="vault-multi-route-sni.yaml"
            AMMO_FILE="vault-multi-route-sni.txt"
            GATEWAY_CONFIG="gateway-perftest-vault-sni.yaml"
            NEEDS_TLS=true
            ;;
        vault-tls-baseline)
            CONFIG_FILE="http-tls-throughput.yaml"
            AMMO_FILE="http-get.txt"
            GATEWAY_CONFIG="gateway-perftest-secure.yaml"
            NEEDS_TLS=true
            ;;
        *)
            log_error "Unknown test: $test_name"
            echo ""
            echo "Available Vault TLS tests:"
            echo "  vault-tls-handshake     - TLS handshake with Vault-issued certs"
            echo "  vault-cert-renewal      - Certificate renewal under load"
            echo "  vault-backend-mtls      - Backend mTLS with Vault client certs"
            echo "  vault-multi-route-sni   - Multi-route SNI with Vault certs"
            echo "  vault-tls-baseline      - File-based TLS baseline for comparison"
            echo "  all                     - Run all tests"
            exit 1
            ;;
    esac
}

# Run a single test
run_test() {
    local test_name=$1

    log_section "Running test: $test_name"

    get_test_config "$test_name"

    # Create results directory with timestamp
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local results_dir="$PERF_DIR/results/${test_name}_${timestamp}"
    mkdir -p "$results_dir"
    mkdir -p "$results_dir/ammo"
    mkdir -p "$results_dir/logs"

    log_info "Results will be saved to: $results_dir"

    # Copy config file to results directory
    cp "$PERF_DIR/configs/$CONFIG_FILE" "$results_dir/load.yaml"

    # Copy ammo file
    cp "$PERF_DIR/ammo/$AMMO_FILE" "$results_dir/ammo/$AMMO_FILE"

    # Record test metadata
    cat > "$results_dir/test-metadata.json" << EOF
{
    "test_name": "$test_name",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "config_file": "$CONFIG_FILE",
    "ammo_file": "$AMMO_FILE",
    "gateway_config": "$GATEWAY_CONFIG",
    "vault_addr": "$VAULT_ADDR",
    "needs_tls": $NEEDS_TLS,
    "test_type": "vault-pki-tls"
}
EOF

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
        log_success "Test '$test_name' completed successfully"
        log_info "Results saved to: $results_dir"

        # Generate charts if possible
        if [ -f "$SCRIPT_DIR/generate-charts.py" ]; then
            log_info "Generating charts..."
            python3 "$SCRIPT_DIR/generate-charts.py" "$results_dir" --all 2>/dev/null || \
                log_warn "Chart generation failed (matplotlib may not be installed)"
        fi
    else
        log_error "Test '$test_name' failed with exit code: $exit_code"

        # Save error info
        echo "exit_code=$exit_code" > "$results_dir/tank_errors.log"
    fi

    return $exit_code
}

# Run all Vault TLS tests
run_all_tests() {
    local tests=("vault-tls-handshake" "vault-cert-renewal" "vault-backend-mtls" "vault-multi-route-sni")
    local failed_tests=()
    local passed_tests=()

    log_section "Running all Vault PKI TLS performance tests"

    for test in "${tests[@]}"; do
        if run_test "$test"; then
            passed_tests+=("$test")
        else
            failed_tests+=("$test")
        fi

        # Brief pause between tests
        sleep 5
    done

    # Print summary
    log_section "Vault TLS Test Summary"

    echo "Passed tests (${#passed_tests[@]}):"
    for test in "${passed_tests[@]}"; do
        echo -e "  ${GREEN}✓${NC} $test"
    done

    if [ ${#failed_tests[@]} -gt 0 ]; then
        echo ""
        echo "Failed tests (${#failed_tests[@]}):"
        for test in "${failed_tests[@]}"; do
            echo -e "  ${RED}✗${NC} $test"
        done
        return 1
    else
        log_success "All Vault TLS tests passed!"
    fi
}

# Run comparison tests (Vault vs file-based)
run_comparison() {
    log_section "Running Vault vs File-Based TLS Comparison"

    log_info "Step 1: Running file-based TLS baseline..."
    run_test "vault-tls-baseline"
    local baseline_exit=$?

    sleep 5

    log_info "Step 2: Running Vault-issued TLS test..."
    run_test "vault-tls-handshake"
    local vault_exit=$?

    # Generate comparison charts
    log_section "Comparison Results"

    if [ $baseline_exit -eq 0 ] && [ $vault_exit -eq 0 ]; then
        log_success "Both tests completed. Compare results in:"
        echo "  Baseline: $PERF_DIR/results/vault-tls-baseline_*/"
        echo "  Vault:    $PERF_DIR/results/vault-tls-handshake_*/"
        echo ""
        echo "Generate comparison charts with:"
        echo "  python3 $SCRIPT_DIR/generate-charts.py --compare <baseline-dir> <vault-dir>"
    else
        log_warn "One or both tests failed. Manual comparison needed."
    fi
}

# Show help
show_help() {
    cat << EOF
Vault PKI TLS Performance Test Runner using Yandex Tank

Usage: $0 [test-name] [options]

Test names:
  vault-tls-handshake     TLS handshake with Vault-issued certificates
  vault-cert-renewal      Certificate renewal under sustained load
  vault-backend-mtls      Backend mTLS with Vault client certificates
  vault-multi-route-sni   Multi-route SNI with Vault certificates
  vault-tls-baseline      File-based TLS baseline for comparison
  all                     Run all Vault TLS tests sequentially

Options:
  --dry-run               Validate configuration without running
  --no-gateway            Don't start gateway (assume it's already running)
  --verbose               Enable verbose output
  --skip-vault-check      Skip Vault availability check
  --compare               Run both Vault and file-based tests for comparison

Examples:
  $0 vault-tls-handshake
  $0 vault-cert-renewal --no-gateway
  $0 all --verbose
  $0 vault-tls-handshake --compare

Environment Variables:
  VAULT_ADDR              Vault address (default: http://127.0.0.1:8200)
  VAULT_TOKEN             Vault token (default: myroot)

EOF
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
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
    echo "============================================"
    echo "  Vault PKI TLS Performance Test Runner"
    echo "  Using Yandex Tank"
    echo "============================================"
    echo ""
    echo "Vault Address: $VAULT_ADDR"
    echo ""

    check_prerequisites

    if [ "$DRY_RUN" = false ]; then
        check_vault || exit 1
        check_backends
    fi

    if [ "$COMPARE_MODE" = true ]; then
        run_comparison
    elif [ "$TEST_NAME" = "all" ]; then
        run_all_tests
    else
        run_test "$TEST_NAME"
    fi
}

main
