#!/usr/bin/env bash
# =============================================================================
# setup-vault.sh - Configure Vault PKI for backend mTLS testing
# =============================================================================
# This script:
#   1. Enables PKI secrets engine
#   2. Generates a Root CA
#   3. Creates PKI roles for REST and gRPC servers + gateway client
#   4. Issues server certificates for rest_api_4 and grpc_3
#   5. Issues a client certificate for the gateway (avapigw)
#   6. Writes all certs to the shared Docker volume (mtls_certs)
#   7. Sets up KV v2 secrets engine for credential storage
#
# Usage:
#   ./scripts/setup-vault.sh [--verify]
# =============================================================================

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-myroot}"
PKI_MOUNT="${PKI_MOUNT:-pki}"
PKI_ROLE_SERVER="${PKI_ROLE_SERVER:-test-role}"
PKI_ROLE_CLIENT="${PKI_ROLE_CLIENT:-client-role}"
KV_MOUNT="${KV_MOUNT:-secret}"
CERT_TTL="${CERT_TTL:-8760h}"

# Docker volume mount point (used when writing certs into the container volume)
CERT_OUTPUT_DIR="${CERT_OUTPUT_DIR:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# Wait for Vault to be ready
# ---------------------------------------------------------------------------
wait_for_vault() {
    log_info "Waiting for Vault at ${VAULT_ADDR}..."
    local retries=30
    for i in $(seq 1 $retries); do
        if curl -sf "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; then
            log_info "Vault is ready"
            return 0
        fi
        sleep 2
    done
    log_error "Vault not ready after ${retries} attempts"
    return 1
}

# ---------------------------------------------------------------------------
# Helper: vault API call
# ---------------------------------------------------------------------------
vault_api() {
    local method="$1"
    local path="$2"
    shift 2
    curl -sf \
        -X "$method" \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        "${VAULT_ADDR}/v1/${path}" \
        "$@"
}

# ---------------------------------------------------------------------------
# Setup PKI secrets engine
# ---------------------------------------------------------------------------
setup_pki() {
    log_info "Setting up PKI secrets engine at '${PKI_MOUNT}'..."

    # Enable PKI engine (ignore error if already enabled)
    vault_api POST "sys/mounts/${PKI_MOUNT}" \
        -d '{"type":"pki","config":{"max_lease_ttl":"87600h"}}' 2>/dev/null || true

    # Tune max lease TTL
    vault_api POST "sys/mounts/${PKI_MOUNT}/tune" \
        -d '{"max_lease_ttl":"87600h"}' 2>/dev/null || true

    # Generate internal Root CA
    log_info "Generating Root CA..."
    vault_api POST "${PKI_MOUNT}/root/generate/internal" \
        -d '{
            "common_name": "Test Root CA",
            "ttl": "87600h",
            "issuer_name": "root-ca",
            "key_type": "rsa",
            "key_bits": 2048
        }' > /dev/null 2>&1 || log_warn "Root CA may already exist"

    # Configure URLs
    vault_api POST "${PKI_MOUNT}/config/urls" \
        -d "{
            \"issuing_certificates\": \"${VAULT_ADDR}/v1/${PKI_MOUNT}/ca\",
            \"crl_distribution_points\": \"${VAULT_ADDR}/v1/${PKI_MOUNT}/crl\"
        }" > /dev/null

    # Create server role (for backend servers)
    log_info "Creating server PKI role '${PKI_ROLE_SERVER}'..."
    vault_api POST "${PKI_MOUNT}/roles/${PKI_ROLE_SERVER}" \
        -d '{
            "allowed_domains": "localhost,rest_api_4,grpc_3",
            "allow_bare_domains": true,
            "allow_subdomains": true,
            "allow_localhost": true,
            "allow_any_name": true,
            "allow_ip_sans": true,
            "enforce_hostnames": false,
            "server_flag": true,
            "client_flag": false,
            "max_ttl": "8760h",
            "key_type": "rsa",
            "key_bits": 2048
        }' > /dev/null

    # Create client role (for gateway connecting to backends)
    log_info "Creating client PKI role '${PKI_ROLE_CLIENT}'..."
    vault_api POST "${PKI_MOUNT}/roles/${PKI_ROLE_CLIENT}" \
        -d '{
            "allowed_domains": "localhost,gateway,avapigw",
            "allow_bare_domains": true,
            "allow_subdomains": true,
            "allow_localhost": true,
            "allow_any_name": true,
            "allow_ip_sans": true,
            "enforce_hostnames": false,
            "server_flag": false,
            "client_flag": true,
            "max_ttl": "8760h",
            "key_type": "rsa",
            "key_bits": 2048
        }' > /dev/null

    log_info "PKI secrets engine configured successfully"
}

# ---------------------------------------------------------------------------
# Setup KV v2 secrets engine
# ---------------------------------------------------------------------------
setup_kv() {
    log_info "Setting up KV v2 secrets engine at '${KV_MOUNT}'..."

    # Enable KV v2 engine (ignore error if already enabled)
    vault_api POST "sys/mounts/${KV_MOUNT}" \
        -d '{"type":"kv-v2"}' 2>/dev/null || true

    log_info "KV v2 secrets engine configured"
}

# ---------------------------------------------------------------------------
# Issue certificates and write to files
# ---------------------------------------------------------------------------
issue_certificates() {
    local output_dir="$1"

    log_info "Issuing certificates to ${output_dir}..."
    mkdir -p "${output_dir}"

    # Get CA certificate
    log_info "Fetching CA certificate..."
    local ca_resp
    ca_resp=$(vault_api GET "${PKI_MOUNT}/cert/ca")
    echo "$ca_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)
cert = data.get('data', {}).get('certificate', '')
print(cert)
" > "${output_dir}/ca.crt"

    # Issue REST server certificate
    log_info "Issuing REST server certificate..."
    local rest_resp
    rest_resp=$(vault_api POST "${PKI_MOUNT}/issue/${PKI_ROLE_SERVER}" \
        -d "{
            \"common_name\": \"rest_api_4\",
            \"alt_names\": \"localhost,rest_api_4\",
            \"ip_sans\": \"127.0.0.1\",
            \"ttl\": \"${CERT_TTL}\"
        }")
    echo "$rest_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
print(data['certificate'])
" > "${output_dir}/rest-server.crt"
    echo "$rest_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
print(data['private_key'])
" > "${output_dir}/rest-server.key"

    # Issue gRPC server certificate
    log_info "Issuing gRPC server certificate..."
    local grpc_resp
    grpc_resp=$(vault_api POST "${PKI_MOUNT}/issue/${PKI_ROLE_SERVER}" \
        -d "{
            \"common_name\": \"grpc_3\",
            \"alt_names\": \"localhost,grpc_3\",
            \"ip_sans\": \"127.0.0.1\",
            \"ttl\": \"${CERT_TTL}\"
        }")
    echo "$grpc_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
print(data['certificate'])
" > "${output_dir}/grpc-server.crt"
    echo "$grpc_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
print(data['private_key'])
" > "${output_dir}/grpc-server.key"

    # Issue gateway client certificate (for avapigw to connect to mTLS backends)
    log_info "Issuing gateway client certificate..."
    local client_resp
    client_resp=$(vault_api POST "${PKI_MOUNT}/issue/${PKI_ROLE_CLIENT}" \
        -d "{
            \"common_name\": \"avapigw-client\",
            \"alt_names\": \"localhost,gateway\",
            \"ip_sans\": \"127.0.0.1\",
            \"ttl\": \"${CERT_TTL}\"
        }")
    echo "$client_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
print(data['certificate'])
" > "${output_dir}/client.crt"
    echo "$client_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
print(data['private_key'])
" > "${output_dir}/client.key"

    # Set permissions
    chmod 644 "${output_dir}"/*.crt
    chmod 600 "${output_dir}"/*.key

    log_info "All certificates issued successfully"
    log_info "  CA cert:          ${output_dir}/ca.crt"
    log_info "  REST server cert: ${output_dir}/rest-server.crt"
    log_info "  REST server key:  ${output_dir}/rest-server.key"
    log_info "  gRPC server cert: ${output_dir}/grpc-server.crt"
    log_info "  gRPC server key:  ${output_dir}/grpc-server.key"
    log_info "  Client cert:      ${output_dir}/client.crt"
    log_info "  Client key:       ${output_dir}/client.key"
}

# ---------------------------------------------------------------------------
# Copy certs into Docker volume
# ---------------------------------------------------------------------------
copy_certs_to_volume() {
    local source_dir="$1"

    log_info "Copying certificates into Docker volume 'mtls_certs'..."

    # Use a temporary container to copy files into the named volume
    docker run --rm \
        -v "$(cd "${source_dir}" && pwd)":/source:ro \
        -v docker-compose_mtls_certs:/certs \
        alpine sh -c "cp /source/* /certs/ && chmod 644 /certs/*"

    log_info "Certificates copied to Docker volume"
}

# ---------------------------------------------------------------------------
# Store backend credentials in Vault KV
# ---------------------------------------------------------------------------
store_backend_credentials() {
    log_info "Storing backend credentials in Vault KV..."

    # Store basic auth credentials for rest_api_5
    vault_api POST "${KV_MOUNT}/data/backend-auth/basic" \
        -d '{
            "data": {
                "username": "backend-user",
                "password": "backend-pass"
            }
        }' > /dev/null

    # Store OIDC client secret for backend service-to-service auth
    vault_api POST "${KV_MOUNT}/data/backend-auth/oidc" \
        -d '{
            "data": {
                "client_secret": "gateway-backend-secret"
            }
        }' > /dev/null

    log_info "Backend credentials stored in Vault KV"
}

# ---------------------------------------------------------------------------
# Verify setup
# ---------------------------------------------------------------------------
verify_setup() {
    log_info "Verifying Vault setup..."

    local errors=0

    # Check PKI engine
    if vault_api GET "sys/mounts/${PKI_MOUNT}" > /dev/null 2>&1; then
        log_info "  ✓ PKI engine mounted at '${PKI_MOUNT}'"
    else
        log_error "  ✗ PKI engine not found at '${PKI_MOUNT}'"
        errors=$((errors + 1))
    fi

    # Check KV engine
    if vault_api GET "sys/mounts/${KV_MOUNT}" > /dev/null 2>&1; then
        log_info "  ✓ KV engine mounted at '${KV_MOUNT}'"
    else
        log_error "  ✗ KV engine not found at '${KV_MOUNT}'"
        errors=$((errors + 1))
    fi

    # Check PKI roles
    for role in "${PKI_ROLE_SERVER}" "${PKI_ROLE_CLIENT}"; do
        if vault_api GET "${PKI_MOUNT}/roles/${role}" > /dev/null 2>&1; then
            log_info "  ✓ PKI role '${role}' exists"
        else
            log_error "  ✗ PKI role '${role}' not found"
            errors=$((errors + 1))
        fi
    done

    # Check CA certificate
    if vault_api GET "${PKI_MOUNT}/cert/ca" > /dev/null 2>&1; then
        log_info "  ✓ Root CA certificate exists"
    else
        log_error "  ✗ Root CA certificate not found"
        errors=$((errors + 1))
    fi

    # Try issuing a test certificate
    if vault_api POST "${PKI_MOUNT}/issue/${PKI_ROLE_SERVER}" \
        -d '{"common_name":"test.local","ttl":"1h"}' > /dev/null 2>&1; then
        log_info "  ✓ Can issue certificates"
    else
        log_error "  ✗ Cannot issue certificates"
        errors=$((errors + 1))
    fi

    # Check KV credentials
    if vault_api GET "${KV_MOUNT}/data/backend-auth/basic" > /dev/null 2>&1; then
        log_info "  ✓ Basic auth credentials stored"
    else
        log_warn "  ⚠ Basic auth credentials not found (run setup first)"
    fi

    if [ $errors -gt 0 ]; then
        log_error "Verification failed with ${errors} error(s)"
        return 1
    fi

    log_info "Vault setup verified successfully"
    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    if [ "${1:-}" = "--verify" ]; then
        wait_for_vault
        verify_setup
        exit $?
    fi

    wait_for_vault

    # Setup engines
    setup_pki
    setup_kv

    # Issue certificates
    local cert_dir
    cert_dir=$(mktemp -d)
    issue_certificates "${cert_dir}"

    # Copy to Docker volume
    copy_certs_to_volume "${cert_dir}"

    # Also keep a local copy for host-side tests
    local local_cert_dir
    local_cert_dir="$(cd "$(dirname "$0")/.." && pwd)/certs"
    mkdir -p "${local_cert_dir}"
    cp "${cert_dir}"/* "${local_cert_dir}/"
    log_info "Local copy of certificates at: ${local_cert_dir}"

    # Store credentials
    store_backend_credentials

    # Cleanup temp dir
    rm -rf "${cert_dir}"

    # Verify
    verify_setup

    log_info ""
    log_info "=== Vault setup complete ==="
    log_info "Next steps:"
    log_info "  1. Restart mTLS backends to pick up certificates:"
    log_info "     docker compose restart rest_api_4 grpc_3"
    log_info "  2. Test mTLS connection:"
    log_info "     curl --cacert ${local_cert_dir}/ca.crt \\"
    log_info "          --cert ${local_cert_dir}/client.crt \\"
    log_info "          --key ${local_cert_dir}/client.key \\"
    log_info "          https://127.0.0.1:8804/health"
}

main "$@"
