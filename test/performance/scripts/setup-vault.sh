#!/bin/bash
# setup-vault.sh - Configure Vault for performance testing
# Usage: ./setup-vault.sh [options]
#
# Options:
#   --vault-addr=<addr>   Vault address (default: http://127.0.0.1:8200)
#   --vault-token=<token> Vault token (default: myroot)
#   --verify              Only verify setup, don't configure
#   --clean               Remove test configuration

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-myroot}"
VERIFY_ONLY=false
CLEAN=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --vault-addr=*)
            VAULT_ADDR="${1#*=}"
            shift
            ;;
        --vault-token=*)
            VAULT_TOKEN="${1#*=}"
            shift
            ;;
        --verify)
            VERIFY_ONLY=true
            shift
            ;;
        --clean)
            CLEAN=true
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

# Check if Vault is accessible
check_vault() {
    log_info "Checking Vault connectivity at $VAULT_ADDR..."
    
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" "$VAULT_ADDR/v1/sys/health" 2>/dev/null || echo "000")
    
    if [[ "$response" == "200" ]] || [[ "$response" == "429" ]] || [[ "$response" == "472" ]] || [[ "$response" == "473" ]]; then
        log_success "Vault is accessible"
        return 0
    else
        log_error "Vault is not accessible (HTTP $response)"
        return 1
    fi
}

# Vault API helper
vault_api() {
    local method=$1
    local path=$2
    local data=${3:-}
    
    local curl_args=(-s -X "$method" -H "X-Vault-Token: $VAULT_TOKEN")
    
    if [[ -n "$data" ]]; then
        curl_args+=(-H "Content-Type: application/json" -d "$data")
    fi
    
    curl "${curl_args[@]}" "$VAULT_ADDR/v1/$path"
}

# Enable secrets engine if not already enabled
enable_secrets_engine() {
    local engine=$1
    local path=$2
    
    log_info "Enabling $engine secrets engine at $path..."
    
    # Check if already enabled
    local mounts
    mounts=$(vault_api GET "sys/mounts")
    
    if echo "$mounts" | grep -q "\"$path/\""; then
        log_info "$engine engine already enabled at $path"
        return 0
    fi
    
    # Enable the engine
    local result
    result=$(vault_api POST "sys/mounts/$path" "{\"type\": \"$engine\"}")
    
    if echo "$result" | grep -q "error"; then
        log_error "Failed to enable $engine engine: $result"
        return 1
    fi
    
    log_success "$engine engine enabled at $path"
}

# Setup PKI secrets engine
setup_pki() {
    log_info "Setting up PKI secrets engine..."
    
    # Enable PKI engine
    enable_secrets_engine "pki" "pki"
    
    # Configure PKI max lease TTL
    vault_api POST "sys/mounts/pki/tune" '{"max_lease_ttl": "87600h"}'
    
    # Generate root CA
    log_info "Generating root CA certificate..."
    local root_ca
    root_ca=$(vault_api POST "pki/root/generate/internal" '{
        "common_name": "avapigw-perftest-ca",
        "ttl": "87600h",
        "key_type": "rsa",
        "key_bits": 4096
    }')
    
    if echo "$root_ca" | grep -q "certificate"; then
        log_success "Root CA generated"
    else
        log_warn "Root CA may already exist or failed to generate"
    fi
    
    # Configure CA and CRL URLs
    vault_api POST "pki/config/urls" "{
        \"issuing_certificates\": \"$VAULT_ADDR/v1/pki/ca\",
        \"crl_distribution_points\": \"$VAULT_ADDR/v1/pki/crl\"
    }"
    
    # Create a role for issuing certificates
    log_info "Creating certificate role..."
    vault_api POST "pki/roles/perftest" '{
        "allowed_domains": ["localhost", "avapigw.local", "perftest.local"],
        "allow_subdomains": true,
        "allow_localhost": true,
        "allow_ip_sans": true,
        "max_ttl": "720h",
        "key_type": "rsa",
        "key_bits": 2048
    }'
    
    log_success "PKI secrets engine configured"
}

# Generate test certificates
generate_certificates() {
    log_info "Generating test certificates..."
    
    # Generate server certificate
    local server_cert
    server_cert=$(vault_api POST "pki/issue/perftest" '{
        "common_name": "localhost",
        "alt_names": "localhost,127.0.0.1,host.docker.internal",
        "ip_sans": "127.0.0.1",
        "ttl": "720h"
    }')
    
    if echo "$server_cert" | grep -q "certificate"; then
        log_success "Server certificate generated"
        
        # Extract and save certificate (optional - for debugging)
        # echo "$server_cert" | jq -r '.data.certificate' > /tmp/server.crt
        # echo "$server_cert" | jq -r '.data.private_key' > /tmp/server.key
    else
        log_warn "Failed to generate server certificate: $server_cert"
    fi
    
    # Generate client certificate
    local client_cert
    client_cert=$(vault_api POST "pki/issue/perftest" '{
        "common_name": "perftest-client",
        "ttl": "720h"
    }')
    
    if echo "$client_cert" | grep -q "certificate"; then
        log_success "Client certificate generated"
    else
        log_warn "Failed to generate client certificate"
    fi
}

# Setup KV secrets engine for API keys
setup_kv() {
    log_info "Setting up KV secrets engine for API keys..."
    
    # Enable KV v2 engine
    enable_secrets_engine "kv-v2" "secret"
    
    # Store test API keys
    log_info "Storing test API keys..."
    
    # API key for performance testing
    vault_api POST "secret/data/perftest/apikeys" '{
        "data": {
            "perftest-key-1": "pk_perftest_1234567890abcdef",
            "perftest-key-2": "pk_perftest_abcdef1234567890",
            "perftest-key-3": "pk_perftest_fedcba0987654321",
            "admin-key": "pk_admin_supersecretkey12345",
            "readonly-key": "pk_readonly_viewonlykey67890"
        }
    }'
    
    # Store gateway configuration secrets
    vault_api POST "secret/data/perftest/gateway" '{
        "data": {
            "jwt_secret": "perftest-jwt-secret-key-for-testing-only",
            "encryption_key": "perftest-encryption-key-32bytes!",
            "redis_password": "password"
        }
    }'
    
    log_success "KV secrets engine configured with test data"
}

# Setup Transit secrets engine for encryption
setup_transit() {
    log_info "Setting up Transit secrets engine..."
    
    # Enable Transit engine
    enable_secrets_engine "transit" "transit"
    
    # Create encryption key for performance testing
    log_info "Creating encryption keys..."
    
    vault_api POST "transit/keys/perftest-key" '{
        "type": "aes256-gcm96"
    }'
    
    vault_api POST "transit/keys/perftest-hmac" '{
        "type": "aes256-gcm96"
    }'
    
    log_success "Transit secrets engine configured"
}

# Create policies for performance testing
setup_policies() {
    log_info "Creating Vault policies..."
    
    # Performance test policy - read-only access to secrets
    local perftest_policy='
path "secret/data/perftest/*" {
  capabilities = ["read", "list"]
}

path "pki/issue/perftest" {
  capabilities = ["create", "update"]
}

path "transit/encrypt/perftest-key" {
  capabilities = ["update"]
}

path "transit/decrypt/perftest-key" {
  capabilities = ["update"]
}

path "transit/hmac/perftest-hmac" {
  capabilities = ["update"]
}
'
    
    vault_api PUT "sys/policies/acl/perftest" "{\"policy\": $(echo "$perftest_policy" | jq -Rs .)}"
    
    log_success "Policies created"
}

# Create tokens for testing
create_tokens() {
    log_info "Creating test tokens..."
    
    # Create a token with perftest policy
    local token_response
    token_response=$(vault_api POST "auth/token/create" '{
        "policies": ["perftest"],
        "ttl": "24h",
        "renewable": true,
        "display_name": "perftest-token"
    }')
    
    if echo "$token_response" | grep -q "client_token"; then
        local token
        token=$(echo "$token_response" | grep -o '"client_token":"[^"]*"' | cut -d'"' -f4)
        log_success "Test token created: $token"
        echo ""
        echo "============================================"
        echo "Performance Test Token:"
        echo "  Token: $token"
        echo "  TTL: 24h"
        echo "  Policies: perftest"
        echo "============================================"
    else
        log_warn "Failed to create test token"
    fi
}

# Verify setup
verify_setup() {
    log_info "Verifying Vault setup..."
    
    local errors=0
    
    # Check PKI
    log_info "Checking PKI engine..."
    local pki_check
    pki_check=$(vault_api GET "pki/roles/perftest")
    if echo "$pki_check" | grep -q "allowed_domains"; then
        log_success "PKI role 'perftest' exists"
    else
        log_error "PKI role 'perftest' not found"
        ((errors++))
    fi
    
    # Check KV secrets
    log_info "Checking KV secrets..."
    local kv_check
    kv_check=$(vault_api GET "secret/data/perftest/apikeys")
    if echo "$kv_check" | grep -q "perftest-key-1"; then
        log_success "API keys stored in KV"
    else
        log_error "API keys not found in KV"
        ((errors++))
    fi
    
    # Check Transit
    log_info "Checking Transit engine..."
    local transit_check
    transit_check=$(vault_api GET "transit/keys/perftest-key")
    if echo "$transit_check" | grep -q "type"; then
        log_success "Transit key 'perftest-key' exists"
    else
        log_error "Transit key 'perftest-key' not found"
        ((errors++))
    fi
    
    # Check policies
    log_info "Checking policies..."
    local policy_check
    policy_check=$(vault_api GET "sys/policies/acl/perftest")
    if echo "$policy_check" | grep -q "policy"; then
        log_success "Policy 'perftest' exists"
    else
        log_error "Policy 'perftest' not found"
        ((errors++))
    fi
    
    echo ""
    if [[ $errors -eq 0 ]]; then
        log_success "All Vault components verified successfully!"
        return 0
    else
        log_error "Verification failed with $errors errors"
        return 1
    fi
}

# Clean up test configuration
clean_setup() {
    log_info "Cleaning up Vault test configuration..."
    
    # Delete secrets
    vault_api DELETE "secret/data/perftest/apikeys" 2>/dev/null || true
    vault_api DELETE "secret/data/perftest/gateway" 2>/dev/null || true
    
    # Delete transit keys
    vault_api POST "transit/keys/perftest-key/config" '{"deletion_allowed": true}' 2>/dev/null || true
    vault_api DELETE "transit/keys/perftest-key" 2>/dev/null || true
    vault_api POST "transit/keys/perftest-hmac/config" '{"deletion_allowed": true}' 2>/dev/null || true
    vault_api DELETE "transit/keys/perftest-hmac" 2>/dev/null || true
    
    # Delete PKI role
    vault_api DELETE "pki/roles/perftest" 2>/dev/null || true
    
    # Delete policy
    vault_api DELETE "sys/policies/acl/perftest" 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Main
main() {
    echo ""
    echo "============================================"
    echo "  Vault Setup for Performance Testing"
    echo "============================================"
    echo ""
    echo "Vault Address: $VAULT_ADDR"
    echo ""
    
    # Check Vault connectivity
    if ! check_vault; then
        log_error "Cannot connect to Vault. Please ensure Vault is running."
        exit 1
    fi
    
    if [[ "$CLEAN" == "true" ]]; then
        clean_setup
        exit 0
    fi
    
    if [[ "$VERIFY_ONLY" == "true" ]]; then
        verify_setup
        exit $?
    fi
    
    # Run setup
    setup_pki
    generate_certificates
    setup_kv
    setup_transit
    setup_policies
    create_tokens
    
    echo ""
    log_info "Running verification..."
    verify_setup
    
    echo ""
    log_success "Vault setup completed successfully!"
    echo ""
    echo "Environment variables for testing:"
    echo "  export VAULT_ADDR=$VAULT_ADDR"
    echo "  export VAULT_TOKEN=$VAULT_TOKEN"
    echo ""
}

main
