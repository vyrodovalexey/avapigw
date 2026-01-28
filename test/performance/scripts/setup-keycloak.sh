#!/bin/bash
# setup-keycloak.sh - Configure Keycloak for performance testing
# Usage: ./setup-keycloak.sh [options]
#
# Options:
#   --keycloak-url=<url>    Keycloak URL (default: http://127.0.0.1:8090)
#   --admin-user=<user>     Admin username (default: admin)
#   --admin-pass=<pass>     Admin password (default: admin)
#   --realm=<realm>         Realm name (default: gateway-test)
#   --client-id=<id>        Client ID (default: gateway)
#   --client-secret=<secret> Client secret (default: gateway-secret)
#   --verify                Only verify setup, don't configure
#   --clean                 Remove test configuration

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
KEYCLOAK_URL="${KEYCLOAK_URL:-http://127.0.0.1:8090}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASS="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM_NAME="${KEYCLOAK_REALM:-gateway-test}"
CLIENT_ID="${KEYCLOAK_CLIENT_ID:-gateway}"
CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-gateway-secret}"
VERIFY_ONLY=false
CLEAN=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --keycloak-url=*)
            KEYCLOAK_URL="${1#*=}"
            shift
            ;;
        --admin-user=*)
            ADMIN_USER="${1#*=}"
            shift
            ;;
        --admin-pass=*)
            ADMIN_PASS="${1#*=}"
            shift
            ;;
        --realm=*)
            REALM_NAME="${1#*=}"
            shift
            ;;
        --client-id=*)
            CLIENT_ID="${1#*=}"
            shift
            ;;
        --client-secret=*)
            CLIENT_SECRET="${1#*=}"
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

# Global access token
ACCESS_TOKEN=""

# Check if Keycloak is accessible
check_keycloak() {
    log_info "Checking Keycloak connectivity at $KEYCLOAK_URL..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        local response
        response=$(curl -s -o /dev/null -w "%{http_code}" "$KEYCLOAK_URL/health/ready" 2>/dev/null || echo "000")
        
        if [[ "$response" == "200" ]]; then
            log_success "Keycloak is accessible and ready"
            return 0
        fi
        
        # Try alternative health endpoint
        response=$(curl -s -o /dev/null -w "%{http_code}" "$KEYCLOAK_URL/realms/master" 2>/dev/null || echo "000")
        if [[ "$response" == "200" ]]; then
            log_success "Keycloak is accessible"
            return 0
        fi
        
        if [[ $attempt -eq 1 ]]; then
            log_info "Waiting for Keycloak to be ready..."
        fi
        
        sleep 2
        ((attempt++))
    done
    
    log_error "Keycloak is not accessible after $max_attempts attempts"
    return 1
}

# Disable SSL requirement for realms (needed for Keycloak 26.x in dev mode)
disable_ssl_requirement() {
    log_info "Disabling SSL requirement for master realm (Keycloak 26.x compatibility)..."
    
    # Try to get token first - if it works, SSL is already disabled
    local response
    response=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$ADMIN_USER" \
        -d "password=$ADMIN_PASS" \
        -d "grant_type=password" \
        -d "client_id=admin-cli")
    
    if echo "$response" | grep -q "access_token"; then
        log_info "SSL requirement already disabled or not enforced"
        return 0
    fi
    
    # If HTTPS required error, use kcadm inside the container to disable it
    if echo "$response" | grep -q "HTTPS required"; then
        log_info "HTTPS required detected, disabling via kcadm..."
        
        local container_name="keycloak_web"
        if ! docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
            log_error "Keycloak container '$container_name' not found"
            return 1
        fi
        
        # Use kcadm inside the container to disable SSL
        docker exec "$container_name" /opt/keycloak/bin/kcadm.sh config credentials \
            --server http://localhost:8090 --realm master --user "$ADMIN_USER" --password "$ADMIN_PASS" 2>/dev/null
        
        docker exec "$container_name" /opt/keycloak/bin/kcadm.sh update realms/master \
            -s sslRequired=NONE 2>/dev/null
        
        if [[ $? -eq 0 ]]; then
            log_success "SSL requirement disabled for master realm"
        else
            log_error "Failed to disable SSL requirement"
            return 1
        fi
    fi
    
    return 0
}

# Get admin access token
get_admin_token() {
    log_info "Obtaining admin access token..."
    
    local response
    response=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$ADMIN_USER" \
        -d "password=$ADMIN_PASS" \
        -d "grant_type=password" \
        -d "client_id=admin-cli")
    
    ACCESS_TOKEN=$(echo "$response" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    
    if [[ -z "$ACCESS_TOKEN" ]]; then
        log_error "Failed to obtain admin token: $response"
        return 1
    fi
    
    log_success "Admin token obtained"
}

# Keycloak Admin API helper
keycloak_api() {
    local method=$1
    local path=$2
    local data=${3:-}
    
    local curl_args=(-s -X "$method" -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json")
    
    if [[ -n "$data" ]]; then
        curl_args+=(-d "$data")
    fi
    
    curl "${curl_args[@]}" "$KEYCLOAK_URL/admin/realms$path"
}

# Check if realm exists
realm_exists() {
    local realm=$1
    local response
    response=$(keycloak_api GET "/$realm" 2>/dev/null)
    
    if echo "$response" | grep -q "\"realm\":\"$realm\""; then
        return 0
    fi
    return 1
}

# Create realm
create_realm() {
    log_info "Creating realm '$REALM_NAME'..."
    
    if realm_exists "$REALM_NAME"; then
        log_info "Realm '$REALM_NAME' already exists"
        return 0
    fi
    
    local realm_config='{
        "realm": "'"$REALM_NAME"'",
        "enabled": true,
        "displayName": "Gateway Performance Test",
        "displayNameHtml": "<b>Gateway Performance Test</b>",
        "sslRequired": "NONE",
        "registrationAllowed": false,
        "loginWithEmailAllowed": true,
        "duplicateEmailsAllowed": false,
        "resetPasswordAllowed": true,
        "editUsernameAllowed": false,
        "bruteForceProtected": false,
        "accessTokenLifespan": 3600,
        "accessTokenLifespanForImplicitFlow": 900,
        "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespan": 36000,
        "offlineSessionIdleTimeout": 2592000,
        "accessCodeLifespan": 60,
        "accessCodeLifespanUserAction": 300,
        "accessCodeLifespanLogin": 1800,
        "actionTokenGeneratedByAdminLifespan": 43200,
        "actionTokenGeneratedByUserLifespan": 300,
        "defaultSignatureAlgorithm": "RS256",
        "revokeRefreshToken": false,
        "refreshTokenMaxReuse": 0
    }'
    
    local response
    response=$(curl -s -X POST "$KEYCLOAK_URL/admin/realms" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$realm_config" \
        -w "\n%{http_code}")
    
    local http_code
    http_code=$(echo "$response" | tail -1)
    
    if [[ "$http_code" == "201" ]] || [[ "$http_code" == "409" ]]; then
        log_success "Realm '$REALM_NAME' created"
        return 0
    else
        log_error "Failed to create realm: $response"
        return 1
    fi
}

# Create client
create_client() {
    log_info "Creating client '$CLIENT_ID'..."
    
    # Check if client exists
    local existing
    existing=$(keycloak_api GET "/$REALM_NAME/clients?clientId=$CLIENT_ID")
    
    if echo "$existing" | grep -q "\"clientId\":\"$CLIENT_ID\""; then
        log_info "Client '$CLIENT_ID' already exists"
        
        # Get client ID (UUID)
        local client_uuid
        client_uuid=$(echo "$existing" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
        
        # Update client secret
        keycloak_api PUT "/$REALM_NAME/clients/$client_uuid" '{
            "clientId": "'"$CLIENT_ID"'",
            "secret": "'"$CLIENT_SECRET"'",
            "enabled": true,
            "clientAuthenticatorType": "client-secret",
            "redirectUris": ["*"],
            "webOrigins": ["*"],
            "publicClient": false,
            "protocol": "openid-connect",
            "directAccessGrantsEnabled": true,
            "serviceAccountsEnabled": true,
            "authorizationServicesEnabled": false,
            "standardFlowEnabled": true,
            "implicitFlowEnabled": false
        }'
        
        return 0
    fi
    
    local client_config='{
        "clientId": "'"$CLIENT_ID"'",
        "secret": "'"$CLIENT_SECRET"'",
        "enabled": true,
        "clientAuthenticatorType": "client-secret",
        "redirectUris": ["*"],
        "webOrigins": ["*"],
        "publicClient": false,
        "protocol": "openid-connect",
        "directAccessGrantsEnabled": true,
        "serviceAccountsEnabled": true,
        "authorizationServicesEnabled": false,
        "standardFlowEnabled": true,
        "implicitFlowEnabled": false,
        "fullScopeAllowed": true,
        "attributes": {
            "access.token.lifespan": "3600",
            "client.secret.creation.time": "'"$(date +%s)"'"
        }
    }'
    
    local response
    response=$(curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$client_config" \
        -w "\n%{http_code}")
    
    local http_code
    http_code=$(echo "$response" | tail -1)
    
    if [[ "$http_code" == "201" ]] || [[ "$http_code" == "409" ]]; then
        log_success "Client '$CLIENT_ID' created"
        return 0
    else
        log_error "Failed to create client: $response"
        return 1
    fi
}

# Create test users
create_users() {
    log_info "Creating test users..."
    
    # Users for performance testing and gateway-test realm
    # Format: username:password:firstname:lastname:email
    local users=(
        "perftest-user-1:perftest123:Perf:Test1:perftest1@example.com"
        "perftest-user-2:perftest123:Perf:Test2:perftest2@example.com"
        "perftest-admin:adminpass123:Admin:User:admin@example.com"
        "perftest-readonly:readonly123:ReadOnly:User:readonly@example.com"
        "testuser:testpass123:Test:User:testuser@example.com"
        "adminuser:adminpass123:Admin:User:adminuser@example.com"
    )
    
    for user_data in "${users[@]}"; do
        IFS=':' read -r username password firstname lastname email <<< "$user_data"
        
        # Check if user exists
        local existing
        existing=$(keycloak_api GET "/$REALM_NAME/users?username=$username")
        
        if echo "$existing" | grep -q "\"username\":\"$username\""; then
            log_info "User '$username' already exists"
            continue
        fi
        
        local user_config='{
            "username": "'"$username"'",
            "email": "'"$email"'",
            "firstName": "'"$firstname"'",
            "lastName": "'"$lastname"'",
            "enabled": true,
            "emailVerified": true,
            "credentials": [{
                "type": "password",
                "value": "'"$password"'",
                "temporary": false
            }]
        }'
        
        local response
        response=$(curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$user_config" \
            -w "\n%{http_code}")
        
        local http_code
        http_code=$(echo "$response" | tail -1)
        
        if [[ "$http_code" == "201" ]]; then
            log_success "User '$username' created"
        elif [[ "$http_code" == "409" ]]; then
            log_info "User '$username' already exists"
        else
            log_warn "Failed to create user '$username': HTTP $http_code"
        fi
    done
}

# Create roles
create_roles() {
    log_info "Creating realm roles..."
    
    local roles=("perftest-user" "perftest-admin" "perftest-readonly")
    
    for role in "${roles[@]}"; do
        local existing
        existing=$(keycloak_api GET "/$REALM_NAME/roles/$role" 2>/dev/null)
        
        if echo "$existing" | grep -q "\"name\":\"$role\""; then
            log_info "Role '$role' already exists"
            continue
        fi
        
        local response
        response=$(curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"name": "'"$role"'", "description": "Performance test role"}' \
            -w "\n%{http_code}")
        
        local http_code
        http_code=$(echo "$response" | tail -1)
        
        if [[ "$http_code" == "201" ]] || [[ "$http_code" == "409" ]]; then
            log_success "Role '$role' created"
        else
            log_warn "Failed to create role '$role'"
        fi
    done
}

# Assign roles to users
assign_roles() {
    log_info "Assigning roles to users..."
    
    # Get user IDs
    local users_response
    users_response=$(keycloak_api GET "/$REALM_NAME/users")
    
    # Assign perftest-admin role to admin user
    local admin_id
    admin_id=$(echo "$users_response" | grep -o '"id":"[^"]*","username":"perftest-admin"' | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
    
    if [[ -n "$admin_id" ]]; then
        # Get role ID
        local role_response
        role_response=$(keycloak_api GET "/$REALM_NAME/roles/perftest-admin")
        local role_id
        role_id=$(echo "$role_response" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
        local role_name
        role_name=$(echo "$role_response" | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
        
        if [[ -n "$role_id" ]]; then
            keycloak_api POST "/$REALM_NAME/users/$admin_id/role-mappings/realm" \
                '[{"id": "'"$role_id"'", "name": "'"$role_name"'"}]'
            log_success "Assigned 'perftest-admin' role to admin user"
        fi
    fi
}

# Verify OIDC endpoints
verify_oidc() {
    log_info "Verifying OIDC endpoints..."
    
    local errors=0
    
    # Check well-known endpoint
    log_info "Checking OIDC discovery endpoint..."
    local discovery
    discovery=$(curl -s "$KEYCLOAK_URL/realms/$REALM_NAME/.well-known/openid-configuration")
    
    if echo "$discovery" | grep -q "issuer"; then
        log_success "OIDC discovery endpoint working"
        
        # Extract important URLs
        local issuer
        issuer=$(echo "$discovery" | grep -o '"issuer":"[^"]*"' | cut -d'"' -f4)
        local token_endpoint
        token_endpoint=$(echo "$discovery" | grep -o '"token_endpoint":"[^"]*"' | cut -d'"' -f4)
        local jwks_uri
        jwks_uri=$(echo "$discovery" | grep -o '"jwks_uri":"[^"]*"' | cut -d'"' -f4)
        
        echo ""
        echo "  Issuer: $issuer"
        echo "  Token Endpoint: $token_endpoint"
        echo "  JWKS URI: $jwks_uri"
    else
        log_error "OIDC discovery endpoint not working"
        ((errors++))
    fi
    
    # Check JWKS endpoint
    log_info "Checking JWKS endpoint..."
    local jwks
    jwks=$(curl -s "$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/certs")
    
    if echo "$jwks" | grep -q "keys"; then
        log_success "JWKS endpoint working"
    else
        log_error "JWKS endpoint not working"
        ((errors++))
    fi
    
    # Test token endpoint with client credentials
    log_info "Testing token endpoint with client credentials..."
    local token_response
    token_response=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$CLIENT_SECRET")
    
    if echo "$token_response" | grep -q "access_token"; then
        log_success "Client credentials flow working"
        
        local access_token
        access_token=$(echo "$token_response" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
        echo ""
        echo "  Sample Access Token (truncated): ${access_token:0:50}..."
    else
        log_error "Client credentials flow not working: $token_response"
        ((errors++))
    fi
    
    # Test password grant with test user
    log_info "Testing password grant with test user..."
    local password_response
    password_response=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$CLIENT_SECRET" \
        -d "username=perftest-user-1" \
        -d "password=perftest123")
    
    if echo "$password_response" | grep -q "access_token"; then
        log_success "Password grant flow working"
    else
        log_warn "Password grant flow not working (user may not exist yet)"
    fi
    
    return $errors
}

# Verify setup
verify_setup() {
    log_info "Verifying Keycloak setup..."
    
    local errors=0
    
    # Check realm
    log_info "Checking realm..."
    if realm_exists "$REALM_NAME"; then
        log_success "Realm '$REALM_NAME' exists"
    else
        log_error "Realm '$REALM_NAME' not found"
        ((errors++))
    fi
    
    # Check client
    log_info "Checking client..."
    local clients
    clients=$(keycloak_api GET "/$REALM_NAME/clients?clientId=$CLIENT_ID")
    if echo "$clients" | grep -q "\"clientId\":\"$CLIENT_ID\""; then
        log_success "Client '$CLIENT_ID' exists"
    else
        log_error "Client '$CLIENT_ID' not found"
        ((errors++))
    fi
    
    # Check users
    log_info "Checking users..."
    local users
    users=$(keycloak_api GET "/$REALM_NAME/users")
    local user_count
    user_count=$(echo "$users" | grep -o '"username"' | wc -l)
    if [[ $user_count -gt 0 ]]; then
        log_success "Found $user_count users"
    else
        log_warn "No users found"
    fi
    
    # Verify OIDC endpoints
    verify_oidc
    errors=$((errors + $?))
    
    echo ""
    if [[ $errors -eq 0 ]]; then
        log_success "All Keycloak components verified successfully!"
        return 0
    else
        log_error "Verification failed with $errors errors"
        return 1
    fi
}

# Clean up test configuration
clean_setup() {
    log_info "Cleaning up Keycloak test configuration..."
    
    # Delete realm (this will delete all clients, users, roles, etc.)
    local response
    response=$(curl -s -X DELETE "$KEYCLOAK_URL/admin/realms/$REALM_NAME" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -w "\n%{http_code}")
    
    local http_code
    http_code=$(echo "$response" | tail -1)
    
    if [[ "$http_code" == "204" ]] || [[ "$http_code" == "404" ]]; then
        log_success "Realm '$REALM_NAME' deleted"
    else
        log_warn "Failed to delete realm: HTTP $http_code"
    fi
    
    log_success "Cleanup completed"
}

# Print configuration summary
print_summary() {
    echo ""
    echo "============================================"
    echo "  Keycloak Configuration Summary"
    echo "============================================"
    echo ""
    echo "Keycloak URL:    $KEYCLOAK_URL"
    echo "Realm:           $REALM_NAME"
    echo "Client ID:       $CLIENT_ID"
    echo "Client Secret:   $CLIENT_SECRET"
    echo ""
    echo "OIDC Endpoints:"
    echo "  Discovery:     $KEYCLOAK_URL/realms/$REALM_NAME/.well-known/openid-configuration"
    echo "  Token:         $KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token"
    echo "  JWKS:          $KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/certs"
    echo "  Userinfo:      $KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/userinfo"
    echo ""
    echo "Test Users:"
    echo "  perftest-user-1 / perftest123"
    echo "  perftest-user-2 / perftest123"
    echo "  perftest-admin  / adminpass123"
    echo "  perftest-readonly / readonly123"
    echo ""
    echo "Environment variables for testing:"
    echo "  export KEYCLOAK_URL=$KEYCLOAK_URL"
    echo "  export KEYCLOAK_REALM=$REALM_NAME"
    echo "  export KEYCLOAK_CLIENT_ID=$CLIENT_ID"
    echo "  export KEYCLOAK_CLIENT_SECRET=$CLIENT_SECRET"
    echo ""
    echo "Get access token:"
    echo "  curl -X POST '$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token' \\"
    echo "    -d 'grant_type=client_credentials' \\"
    echo "    -d 'client_id=$CLIENT_ID' \\"
    echo "    -d 'client_secret=$CLIENT_SECRET'"
    echo "============================================"
}

# Main
main() {
    echo ""
    echo "============================================"
    echo "  Keycloak Setup for Performance Testing"
    echo "============================================"
    echo ""
    echo "Keycloak URL: $KEYCLOAK_URL"
    echo "Realm: $REALM_NAME"
    echo ""
    
    # Check Keycloak connectivity
    if ! check_keycloak; then
        log_error "Cannot connect to Keycloak. Please ensure Keycloak is running."
        exit 1
    fi
    
    # Disable SSL requirement (Keycloak 26.x compatibility)
    if ! disable_ssl_requirement; then
        log_warn "Could not disable SSL requirement, trying to continue..."
    fi
    
    # Get admin token
    if ! get_admin_token; then
        log_error "Failed to authenticate with Keycloak"
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
    create_realm
    create_client
    create_roles
    create_users
    assign_roles
    
    echo ""
    log_info "Running verification..."
    verify_setup
    
    print_summary
    
    log_success "Keycloak setup completed successfully!"
}

main
