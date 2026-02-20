#!/usr/bin/env bash
# =============================================================================
# setup-keycloak.sh - Configure Keycloak for backend OIDC testing
# =============================================================================
# This script creates:
#   1. Realm "backend-test" for service-to-service authentication
#   2. Client "restapi-server" (resource server for REST backend 3)
#   3. Client "grpc-server" (resource server for gRPC backend 4)
#   4. Client "gateway-backend" (service account for avapigw to obtain tokens)
#   5. Realm "gateway-test" for frontend/user authentication testing
#   6. Client "gateway" (for user auth testing)
#   7. Test users for user auth testing
#
# Usage:
#   ./scripts/setup-keycloak.sh [--verify]
# =============================================================================

set -euo pipefail

KEYCLOAK_ADDR="${KEYCLOAK_ADDR:-http://127.0.0.1:8090}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"

# Backend OIDC realm (service-to-service)
BACKEND_REALM="backend-test"
GATEWAY_BACKEND_CLIENT_ID="gateway-backend"
GATEWAY_BACKEND_CLIENT_SECRET="gateway-backend-secret"
RESTAPI_SERVER_CLIENT_ID="restapi-server"
GRPC_SERVER_CLIENT_ID="grpc-server"

# Frontend/user auth realm
GATEWAY_REALM="gateway-test"
GATEWAY_CLIENT_ID="gateway"
GATEWAY_CLIENT_SECRET="gateway-secret"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# Wait for Keycloak to be ready
# ---------------------------------------------------------------------------
wait_for_keycloak() {
    log_info "Waiting for Keycloak at ${KEYCLOAK_ADDR}..."
    local retries=60
    for i in $(seq 1 $retries); do
        if curl -sf "${KEYCLOAK_ADDR}/health/ready" > /dev/null 2>&1; then
            log_info "Keycloak is ready"
            return 0
        fi
        # Fallback: try realm endpoint
        if curl -sf "${KEYCLOAK_ADDR}/realms/master" > /dev/null 2>&1; then
            log_info "Keycloak is ready (via realm endpoint)"
            return 0
        fi
        sleep 3
    done
    log_error "Keycloak not ready after ${retries} attempts"
    return 1
}

# ---------------------------------------------------------------------------
# Get admin token
# ---------------------------------------------------------------------------
ADMIN_TOKEN=""

get_admin_token() {
    log_info "Obtaining admin token..."
    local resp
    resp=$(curl -sf -X POST \
        "${KEYCLOAK_ADDR}/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "X-Forwarded-Proto: https" \
        -d "username=${KEYCLOAK_ADMIN}" \
        -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
        -d "grant_type=password" \
        -d "client_id=admin-cli")

    ADMIN_TOKEN=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

    if [ -z "$ADMIN_TOKEN" ]; then
        log_error "Failed to obtain admin token"
        return 1
    fi
    log_info "Admin token obtained"
}

# ---------------------------------------------------------------------------
# Helper: Keycloak admin API call
# ---------------------------------------------------------------------------
kc_api() {
    local method="$1"
    local path="$2"
    shift 2
    curl -sf \
        -X "$method" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-Proto: https" \
        "${KEYCLOAK_ADDR}/admin/${path}" \
        "$@"
}

# ---------------------------------------------------------------------------
# Create realm
# ---------------------------------------------------------------------------
create_realm() {
    local realm_name="$1"
    log_info "Creating realm '${realm_name}'..."

    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-Proto: https" \
        "${KEYCLOAK_ADDR}/admin/realms" \
        -d "{
            \"realm\": \"${realm_name}\",
            \"enabled\": true,
            \"sslRequired\": \"none\",
            \"registrationAllowed\": false,
            \"loginWithEmailAllowed\": false,
            \"duplicateEmailsAllowed\": true,
            \"resetPasswordAllowed\": false,
            \"editUsernameAllowed\": false,
            \"bruteForceProtected\": false
        }")

    if [ "$status" = "201" ]; then
        log_info "  Realm '${realm_name}' created"
    elif [ "$status" = "409" ]; then
        log_info "  Realm '${realm_name}' already exists"
    else
        log_warn "  Realm creation returned status ${status}"
    fi
}

# ---------------------------------------------------------------------------
# Create client
# ---------------------------------------------------------------------------
create_client() {
    local realm="$1"
    local client_id="$2"
    local client_secret="$3"
    local service_accounts="${4:-true}"
    local direct_access="${5:-false}"
    local standard_flow="${6:-false}"

    log_info "Creating client '${client_id}' in realm '${realm}'..."

    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-Proto: https" \
        "${KEYCLOAK_ADDR}/admin/realms/${realm}/clients" \
        -d "{
            \"clientId\": \"${client_id}\",
            \"enabled\": true,
            \"publicClient\": false,
            \"secret\": \"${client_secret}\",
            \"serviceAccountsEnabled\": ${service_accounts},
            \"directAccessGrantsEnabled\": ${direct_access},
            \"standardFlowEnabled\": ${standard_flow},
            \"protocol\": \"openid-connect\",
            \"clientAuthenticatorType\": \"client-secret\"
        }")

    if [ "$status" = "201" ]; then
        log_info "  Client '${client_id}' created"
    elif [ "$status" = "409" ]; then
        log_info "  Client '${client_id}' already exists"
    else
        log_warn "  Client creation returned status ${status}"
    fi
}

# ---------------------------------------------------------------------------
# Create realm role
# ---------------------------------------------------------------------------
create_realm_role() {
    local realm="$1"
    local role_name="$2"

    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-Proto: https" \
        "${KEYCLOAK_ADDR}/admin/realms/${realm}/roles" \
        -d "{\"name\": \"${role_name}\"}")

    if [ "$status" = "201" ] || [ "$status" = "409" ]; then
        return 0
    fi
    log_warn "  Role '${role_name}' creation returned status ${status}"
}

# ---------------------------------------------------------------------------
# Create user
# ---------------------------------------------------------------------------
create_user() {
    local realm="$1"
    local username="$2"
    local password="$3"
    local email="${4:-${username}@test.local}"

    log_info "Creating user '${username}' in realm '${realm}'..."

    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-Proto: https" \
        "${KEYCLOAK_ADDR}/admin/realms/${realm}/users" \
        -d "{
            \"username\": \"${username}\",
            \"enabled\": true,
            \"emailVerified\": true,
            \"email\": \"${email}\",
            \"firstName\": \"${username}\",
            \"lastName\": \"TestUser\",
            \"requiredActions\": [],
            \"credentials\": [{
                \"type\": \"password\",
                \"value\": \"${password}\",
                \"temporary\": false
            }]
        }")

    if [ "$status" = "201" ]; then
        log_info "  User '${username}' created"
    elif [ "$status" = "409" ]; then
        log_info "  User '${username}' already exists"
    else
        log_warn "  User creation returned status ${status}"
    fi
}

# ---------------------------------------------------------------------------
# Setup backend-test realm (service-to-service OIDC)
# ---------------------------------------------------------------------------
setup_backend_realm() {
    log_info "=== Setting up backend-test realm (service-to-service OIDC) ==="

    create_realm "${BACKEND_REALM}"

    # Resource server clients (these are the audience validators on the backends)
    # restapi-server: REST backend 3 validates tokens with this client ID
    create_client "${BACKEND_REALM}" "${RESTAPI_SERVER_CLIENT_ID}" "restapi-server-secret" "true" "false" "false"

    # grpc-server: gRPC backend 4 validates tokens with this client ID
    create_client "${BACKEND_REALM}" "${GRPC_SERVER_CLIENT_ID}" "grpc-server-secret" "true" "false" "false"

    # Gateway service account client (avapigw uses this to obtain tokens via client_credentials)
    create_client "${BACKEND_REALM}" "${GATEWAY_BACKEND_CLIENT_ID}" "${GATEWAY_BACKEND_CLIENT_SECRET}" "true" "false" "false"

    log_info "Backend realm setup complete"
    log_info "  Gateway can obtain tokens via:"
    log_info "    POST ${KEYCLOAK_ADDR}/realms/${BACKEND_REALM}/protocol/openid-connect/token"
    log_info "    grant_type=client_credentials"
    log_info "    client_id=${GATEWAY_BACKEND_CLIENT_ID}"
    log_info "    client_secret=${GATEWAY_BACKEND_CLIENT_SECRET}"
}

# ---------------------------------------------------------------------------
# Setup gateway-test realm (user authentication)
# ---------------------------------------------------------------------------
setup_gateway_realm() {
    log_info "=== Setting up gateway-test realm (user authentication) ==="

    create_realm "${GATEWAY_REALM}"

    # Gateway client (supports password grant for user auth + service accounts)
    create_client "${GATEWAY_REALM}" "${GATEWAY_CLIENT_ID}" "${GATEWAY_CLIENT_SECRET}" "true" "true" "true"

    # Create realm roles
    for role in user admin reader writer; do
        create_realm_role "${GATEWAY_REALM}" "$role"
    done

    # Create test users
    create_user "${GATEWAY_REALM}" "testuser" "testpass"
    create_user "${GATEWAY_REALM}" "adminuser" "adminpass"
    create_user "${GATEWAY_REALM}" "reader" "readerpass"

    log_info "Gateway realm setup complete"
}

# ---------------------------------------------------------------------------
# Verify setup
# ---------------------------------------------------------------------------
verify_setup() {
    log_info "Verifying Keycloak setup..."
    local errors=0

    # Check backend-test realm
    if curl -sf "${KEYCLOAK_ADDR}/realms/${BACKEND_REALM}" > /dev/null 2>&1; then
        log_info "  ✓ Realm '${BACKEND_REALM}' exists"
    else
        log_error "  ✗ Realm '${BACKEND_REALM}' not found"
        errors=$((errors + 1))
    fi

    # Check gateway-test realm
    if curl -sf "${KEYCLOAK_ADDR}/realms/${GATEWAY_REALM}" > /dev/null 2>&1; then
        log_info "  ✓ Realm '${GATEWAY_REALM}' exists"
    else
        log_error "  ✗ Realm '${GATEWAY_REALM}' not found"
        errors=$((errors + 1))
    fi

    # Test client_credentials grant on backend-test realm
    log_info "  Testing client_credentials grant on '${BACKEND_REALM}'..."
    local token_resp
    token_resp=$(curl -sf -X POST \
        "${KEYCLOAK_ADDR}/realms/${BACKEND_REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=${GATEWAY_BACKEND_CLIENT_ID}" \
        -d "client_secret=${GATEWAY_BACKEND_CLIENT_SECRET}" 2>/dev/null || echo "")

    if echo "$token_resp" | python3 -c "import sys,json; t=json.load(sys.stdin).get('access_token',''); sys.exit(0 if t else 1)" 2>/dev/null; then
        log_info "  ✓ Client credentials grant works for '${GATEWAY_BACKEND_CLIENT_ID}'"
    else
        log_error "  ✗ Client credentials grant failed for '${GATEWAY_BACKEND_CLIENT_ID}'"
        errors=$((errors + 1))
    fi

    # Test password grant on gateway-test realm
    log_info "  Testing password grant on '${GATEWAY_REALM}'..."
    local user_token_resp
    user_token_resp=$(curl -sf -X POST \
        "${KEYCLOAK_ADDR}/realms/${GATEWAY_REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=${GATEWAY_CLIENT_ID}" \
        -d "client_secret=${GATEWAY_CLIENT_SECRET}" \
        -d "username=testuser" \
        -d "password=testpass" 2>/dev/null || echo "")

    if echo "$user_token_resp" | python3 -c "import sys,json; t=json.load(sys.stdin).get('access_token',''); sys.exit(0 if t else 1)" 2>/dev/null; then
        log_info "  ✓ Password grant works for 'testuser'"
    else
        log_error "  ✗ Password grant failed for 'testuser'"
        errors=$((errors + 1))
    fi

    # Check OIDC discovery endpoints
    for realm in "${BACKEND_REALM}" "${GATEWAY_REALM}"; do
        if curl -sf "${KEYCLOAK_ADDR}/realms/${realm}/.well-known/openid-configuration" > /dev/null 2>&1; then
            log_info "  ✓ OIDC discovery endpoint for '${realm}' works"
        else
            log_error "  ✗ OIDC discovery endpoint for '${realm}' not found"
            errors=$((errors + 1))
        fi
    done

    if [ $errors -gt 0 ]; then
        log_error "Verification failed with ${errors} error(s)"
        return 1
    fi

    log_info "Keycloak setup verified successfully"
    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    if [ "${1:-}" = "--verify" ]; then
        wait_for_keycloak
        get_admin_token
        verify_setup
        exit $?
    fi

    wait_for_keycloak
    get_admin_token

    setup_backend_realm
    setup_gateway_realm

    verify_setup

    log_info ""
    log_info "=== Keycloak setup complete ==="
    log_info ""
    log_info "Backend OIDC (service-to-service):"
    log_info "  Realm:         ${BACKEND_REALM}"
    log_info "  Issuer URL:    ${KEYCLOAK_ADDR}/realms/${BACKEND_REALM}"
    log_info "  Gateway client: ${GATEWAY_BACKEND_CLIENT_ID} / ${GATEWAY_BACKEND_CLIENT_SECRET}"
    log_info "  REST server:   ${RESTAPI_SERVER_CLIENT_ID}"
    log_info "  gRPC server:   ${GRPC_SERVER_CLIENT_ID}"
    log_info ""
    log_info "User authentication:"
    log_info "  Realm:         ${GATEWAY_REALM}"
    log_info "  Issuer URL:    ${KEYCLOAK_ADDR}/realms/${GATEWAY_REALM}"
    log_info "  Client:        ${GATEWAY_CLIENT_ID} / ${GATEWAY_CLIENT_SECRET}"
    log_info "  Test users:    testuser/testpass, adminuser/adminpass, reader/readerpass"
    log_info ""
    log_info "Test token acquisition:"
    log_info "  # Service-to-service token:"
    log_info "  curl -X POST ${KEYCLOAK_ADDR}/realms/${BACKEND_REALM}/protocol/openid-connect/token \\"
    log_info "    -d grant_type=client_credentials \\"
    log_info "    -d client_id=${GATEWAY_BACKEND_CLIENT_ID} \\"
    log_info "    -d client_secret=${GATEWAY_BACKEND_CLIENT_SECRET}"
}

main "$@"
