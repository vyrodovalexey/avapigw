#!/bin/bash
# setup-test-env.sh - Combined Test Environment Setup Script
# Usage: ./setup-test-env.sh [options]
#
# This script sets up the complete test environment:
#   1. Starts docker-compose services (Vault, Keycloak, backends, Redis)
#   2. Waits for services to be ready
#   3. Configures Vault (PKI, KV, Transit, policies)
#   4. Configures Keycloak (realm, client, users)
#   5. Verifies the setup
#
# Options:
#   --skip-docker       Skip docker-compose (assume services are running)
#   --skip-vault        Skip Vault configuration
#   --skip-keycloak     Skip Keycloak configuration
#   --verify-only       Only verify setup, don't configure
#   --clean             Stop services and clean up
#   --namespace=<ns>    K8s namespace for Vault K8s auth (default: avapigw-test)
#   --verbose           Enable verbose output

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
DOCKER_COMPOSE_DIR="$PROJECT_ROOT/test/docker-compose"

# Retry configuration constants
MAX_RETRIES=30
INITIAL_DELAY=1
MAX_DELAY=30
BACKOFF_FACTOR=2

# Default values
SKIP_DOCKER=false
SKIP_VAULT=false
SKIP_KEYCLOAK=false
VERIFY_ONLY=false
CLEAN=false
K8S_NAMESPACE="avapigw-test"
VERBOSE=false

# Service URLs
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-myroot}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://127.0.0.1:8090}"

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-docker) SKIP_DOCKER=true; shift ;;
        --skip-vault) SKIP_VAULT=true; shift ;;
        --skip-keycloak) SKIP_KEYCLOAK=true; shift ;;
        --verify-only) VERIFY_ONLY=true; shift ;;
        --clean) CLEAN=true; shift ;;
        --namespace=*) K8S_NAMESPACE="${1#*=}"; shift ;;
        --verbose) VERBOSE=true; shift ;;
        *)
            echo -e "${RED}[ERROR] Unknown option: $1${NC}"
            echo "Usage: $0 [--skip-docker] [--skip-vault] [--skip-keycloak] [--verify-only] [--clean] [--namespace=<ns>] [--verbose]"
            exit 1
            ;;
    esac
done

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# ==============================================================================
# Health Check with Exponential Backoff
# ==============================================================================

wait_for_service() {
    local url="$1"
    local name="$2"
    local attempt=1
    local delay=$INITIAL_DELAY
    
    log_info "Waiting for $name to be ready..."
    
    while [[ $attempt -le $MAX_RETRIES ]]; do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        
        if [[ "$status" == "200" ]] || [[ "$status" == "204" ]] || [[ "$status" == "429" ]] || [[ "$status" == "472" ]] || [[ "$status" == "473" ]]; then
            log_success "$name is ready (HTTP $status)"
            return 0
        fi
        
        if [[ $attempt -eq $MAX_RETRIES ]]; then
            log_error "$name is not ready after $MAX_RETRIES attempts (last status: $status)"
            return 1
        fi
        
        if [[ "$VERBOSE" == "true" ]]; then
            log_info "Attempt $attempt: $name not ready (status: $status), retrying in ${delay}s..."
        fi
        
        sleep $delay
        
        # Exponential backoff
        delay=$((delay * BACKOFF_FACTOR))
        if [[ $delay -gt $MAX_DELAY ]]; then
            delay=$MAX_DELAY
        fi
        
        ((attempt++))
    done
    
    return 1
}

# ==============================================================================
# Docker Compose Management
# ==============================================================================

start_docker_services() {
    log_step "Starting Docker Compose services..."
    
    if [[ ! -f "$DOCKER_COMPOSE_DIR/docker-compose.yml" ]]; then
        log_error "docker-compose.yml not found at $DOCKER_COMPOSE_DIR"
        exit 1
    fi
    
    cd "$DOCKER_COMPOSE_DIR"
    
    # Start services
    docker compose up -d
    
    log_success "Docker Compose services started"
    
    # Wait for services
    log_info "Waiting for services to be ready..."
    
    # Wait for Vault
    if ! wait_for_service "$VAULT_ADDR/v1/sys/health" "Vault"; then
        log_error "Vault failed to start"
        return 1
    fi
    
    # Wait for Keycloak
    if ! wait_for_service "$KEYCLOAK_URL/realms/master" "Keycloak"; then
        log_error "Keycloak failed to start"
        return 1
    fi
    
    # Wait for backends
    wait_for_service "http://127.0.0.1:8801/health" "Backend 1" || log_warn "Backend 1 not ready"
    wait_for_service "http://127.0.0.1:8802/health" "Backend 2" || log_warn "Backend 2 not ready"
    
    # Wait for Redis
    if command -v redis-cli &> /dev/null; then
        if redis-cli -h 127.0.0.1 -p 6379 -a password ping &>/dev/null; then
            log_success "Redis is ready"
        else
            log_warn "Redis not ready (may still work)"
        fi
    fi
    
    log_success "All Docker services are ready"
}

stop_docker_services() {
    log_step "Stopping Docker Compose services..."
    
    cd "$DOCKER_COMPOSE_DIR"
    docker compose down -v
    
    log_success "Docker Compose services stopped"
}

# ==============================================================================
# Vault Configuration
# ==============================================================================

configure_vault() {
    log_step "Configuring Vault..."
    
    export VAULT_ADDR VAULT_TOKEN
    
    # Run the setup-vault.sh script
    if [[ -x "$SCRIPT_DIR/setup-vault.sh" ]]; then
        "$SCRIPT_DIR/setup-vault.sh" --vault-addr="$VAULT_ADDR" --vault-token="$VAULT_TOKEN"
    else
        log_error "setup-vault.sh not found or not executable"
        return 1
    fi
    
    log_success "Vault configured"
}

verify_vault() {
    log_info "Verifying Vault setup..."
    
    export VAULT_ADDR VAULT_TOKEN
    
    if [[ -x "$SCRIPT_DIR/setup-vault.sh" ]]; then
        "$SCRIPT_DIR/setup-vault.sh" --verify
    else
        log_error "setup-vault.sh not found"
        return 1
    fi
}

# ==============================================================================
# Keycloak Configuration
# ==============================================================================

configure_keycloak() {
    log_step "Configuring Keycloak..."
    
    # Run the setup-keycloak.sh script
    if [[ -x "$SCRIPT_DIR/setup-keycloak.sh" ]]; then
        "$SCRIPT_DIR/setup-keycloak.sh" --keycloak-url="$KEYCLOAK_URL"
    else
        log_error "setup-keycloak.sh not found or not executable"
        return 1
    fi
    
    log_success "Keycloak configured"
}

verify_keycloak() {
    log_info "Verifying Keycloak setup..."
    
    if [[ -x "$SCRIPT_DIR/setup-keycloak.sh" ]]; then
        "$SCRIPT_DIR/setup-keycloak.sh" --verify
    else
        log_error "setup-keycloak.sh not found"
        return 1
    fi
}

# ==============================================================================
# Verification
# ==============================================================================

verify_all() {
    log_step "Verifying test environment..."
    
    local errors=0
    
    # Verify Docker services
    log_info "Checking Docker services..."
    if ! wait_for_service "$VAULT_ADDR/v1/sys/health" "Vault"; then
        ((errors++))
    fi
    if ! wait_for_service "$KEYCLOAK_URL/realms/master" "Keycloak"; then
        ((errors++))
    fi
    
    # Verify Vault
    if [[ "$SKIP_VAULT" != "true" ]]; then
        verify_vault || ((errors++))
    fi
    
    # Verify Keycloak
    if [[ "$SKIP_KEYCLOAK" != "true" ]]; then
        verify_keycloak || ((errors++))
    fi
    
    echo ""
    if [[ $errors -eq 0 ]]; then
        log_success "Test environment verification passed!"
        return 0
    else
        log_error "Test environment verification failed with $errors errors"
        return 1
    fi
}

# ==============================================================================
# Print Summary
# ==============================================================================

print_summary() {
    echo ""
    echo "============================================"
    echo -e "${CYAN}  Test Environment Summary${NC}"
    echo "============================================"
    echo ""
    echo "Services:"
    echo "  Vault:     $VAULT_ADDR"
    echo "  Keycloak:  $KEYCLOAK_URL"
    echo "  Backend 1: http://127.0.0.1:8801"
    echo "  Backend 2: http://127.0.0.1:8802"
    echo "  gRPC 1:    127.0.0.1:8803"
    echo "  gRPC 2:    127.0.0.1:8804"
    echo "  Redis:     127.0.0.1:6379"
    echo ""
    echo "Vault Configuration:"
    echo "  Token:     $VAULT_TOKEN"
    echo "  PKI Role:  test-role (for $K8S_NAMESPACE namespace)"
    echo ""
    echo "Keycloak Configuration:"
    echo "  Realm:     gateway-test"
    echo "  Client:    gateway"
    echo "  Users:     testuser, adminuser, perftest-user-1, perftest-user-2"
    echo ""
    echo "Next Steps:"
    echo "  1. Run performance tests:"
    echo "     ./test/performance/scripts/run-test.sh http-throughput"
    echo ""
    echo "  2. For K8s testing, configure Vault K8s auth:"
    echo "     ./test/performance/scripts/setup-vault-k8s.sh --namespace=$K8S_NAMESPACE --setup-pki"
    echo ""
    echo "  3. Deploy to K8s:"
    echo "     helm upgrade --install avapigw helm/avapigw/ -f helm/avapigw/values-local.yaml -n $K8S_NAMESPACE --create-namespace"
    echo ""
    echo "============================================"
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    echo ""
    echo "=========================================="
    echo "  Test Environment Setup"
    echo "  avapigw API Gateway"
    echo "=========================================="
    echo ""
    
    # Clean mode
    if [[ "$CLEAN" == "true" ]]; then
        stop_docker_services
        log_success "Cleanup completed"
        exit 0
    fi
    
    # Verify only mode
    if [[ "$VERIFY_ONLY" == "true" ]]; then
        verify_all
        exit $?
    fi
    
    # Start Docker services
    if [[ "$SKIP_DOCKER" != "true" ]]; then
        start_docker_services
    else
        log_info "Skipping Docker services (--skip-docker)"
    fi
    
    # Configure Vault
    if [[ "$SKIP_VAULT" != "true" ]]; then
        configure_vault
    else
        log_info "Skipping Vault configuration (--skip-vault)"
    fi
    
    # Configure Keycloak
    if [[ "$SKIP_KEYCLOAK" != "true" ]]; then
        configure_keycloak
    else
        log_info "Skipping Keycloak configuration (--skip-keycloak)"
    fi
    
    # Verify setup
    echo ""
    verify_all
    
    # Print summary
    print_summary
    
    log_success "Test environment setup completed!"
}

main
