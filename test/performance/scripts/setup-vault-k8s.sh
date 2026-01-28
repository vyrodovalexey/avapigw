#!/bin/bash
# setup-vault-k8s.sh - Configure Vault Kubernetes auth for avapigw
# Usage: ./setup-vault-k8s.sh [options]
#
# Configures Vault with:
#   - avapigw policy (PKI, KV, Transit access)
#   - Kubernetes auth method configuration
#   - Kubernetes auth role for avapigw service account
#   - PKI test-role for certificate issuance
#
# Prerequisites:
#   - Vault running (docker-compose)
#   - Kubernetes cluster running (Docker Desktop)
#   - kubectl configured
#   - vault CLI installed
#
# Options:
#   --vault-addr=<addr>   Vault address (default: http://127.0.0.1:8200)
#   --vault-token=<token> Vault root token (default: myroot)
#   --namespace=<ns>      K8s namespace (default: avapigw-test)
#   --sa-name=<name>      Service account name (default: avapigw)
#   --verify              Only verify setup, don't configure
#   --clean               Remove configuration
#   --setup-pki           Also configure PKI engine with test-role

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Retry configuration constants
MAX_RETRIES=30
INITIAL_DELAY=1
MAX_DELAY=30
BACKOFF_FACTOR=2

# Default values - avapigw-test is the standard test namespace
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-myroot}"
K8S_NAMESPACE="${K8S_NAMESPACE:-avapigw-test}"
SA_NAME="${SA_NAME:-avapigw}"
VERIFY_ONLY=false
CLEAN=false
SETUP_PKI=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --vault-addr=*) VAULT_ADDR="${1#*=}"; shift ;;
        --vault-token=*) VAULT_TOKEN="${1#*=}"; shift ;;
        --namespace=*) K8S_NAMESPACE="${1#*=}"; shift ;;
        --sa-name=*) SA_NAME="${1#*=}"; shift ;;
        --verify) VERIFY_ONLY=true; shift ;;
        --clean) CLEAN=true; shift ;;
        --setup-pki) SETUP_PKI=true; shift ;;
        *)
            echo -e "${RED}[ERROR] Unknown option: $1${NC}"
            echo "Usage: $0 [--vault-addr=<addr>] [--vault-token=<token>] [--namespace=<ns>] [--sa-name=<name>] [--verify] [--clean] [--setup-pki]"
            exit 1
            ;;
    esac
done

export VAULT_ADDR VAULT_TOKEN

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Exponential backoff retry function
# Usage: retry_with_backoff <command>
retry_with_backoff() {
    local cmd="$1"
    local attempt=1
    local delay=$INITIAL_DELAY
    
    while [[ $attempt -le $MAX_RETRIES ]]; do
        if eval "$cmd"; then
            return 0
        fi
        
        if [[ $attempt -eq $MAX_RETRIES ]]; then
            log_error "Command failed after $MAX_RETRIES attempts"
            return 1
        fi
        
        log_info "Attempt $attempt failed, retrying in ${delay}s..."
        sleep $delay
        
        # Calculate next delay with exponential backoff
        delay=$((delay * BACKOFF_FACTOR))
        if [[ $delay -gt $MAX_DELAY ]]; then
            delay=$MAX_DELAY
        fi
        
        ((attempt++))
    done
    
    return 1
}

# ==============================================================================
# Prerequisites
# ==============================================================================

check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v vault &> /dev/null; then
        log_error "vault CLI not found. Install: brew install vault"
        exit 1
    fi

    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found. Install: brew install kubectl"
        exit 1
    fi

    # Check Vault connectivity
    if ! vault status &> /dev/null; then
        log_error "Cannot connect to Vault at $VAULT_ADDR"
        exit 1
    fi

    # Check K8s connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi

    # Check service account exists
    if ! kubectl get sa "$SA_NAME" -n "$K8S_NAMESPACE" &> /dev/null; then
        log_warn "Service account '$SA_NAME' not found in namespace '$K8S_NAMESPACE'"
        log_warn "Deploy the Helm chart first to create the service account"
    fi

    log_success "Prerequisites check passed"
}

# ==============================================================================
# Verify
# ==============================================================================

verify_setup() {
    log_info "Verifying Vault Kubernetes auth setup..."
    local errors=0

    # Check policy
    if vault policy read avapigw &> /dev/null; then
        log_success "Policy 'avapigw' exists"
    else
        log_error "Policy 'avapigw' not found"
        ((errors++))
    fi

    # Check K8s auth is enabled
    if vault auth list 2>/dev/null | grep -q "kubernetes/"; then
        log_success "Kubernetes auth method enabled"
    else
        log_error "Kubernetes auth method not enabled"
        ((errors++))
    fi

    # Check K8s auth config
    if vault read auth/kubernetes/config &> /dev/null; then
        log_success "Kubernetes auth configured"
    else
        log_error "Kubernetes auth not configured"
        ((errors++))
    fi

    # Check K8s auth role
    if vault read auth/kubernetes/role/avapigw &> /dev/null; then
        log_success "Kubernetes auth role 'avapigw' exists"
        # Show role details
        vault read -format=json auth/kubernetes/role/avapigw 2>/dev/null | \
            jq -r '.data | "  SA: \(.bound_service_account_names[0]), NS: \(.bound_service_account_namespaces[0]), TTL: \(.token_ttl)s, Policies: \(.token_policies | join(", "))"' 2>/dev/null || true
    else
        log_error "Kubernetes auth role 'avapigw' not found"
        ((errors++))
    fi

    # Check PKI engine
    if vault secrets list 2>/dev/null | grep -q "pki/"; then
        log_success "PKI secrets engine enabled"
        # Check test-role
        if vault read pki/roles/test-role &> /dev/null; then
            log_success "PKI role 'test-role' exists"
        else
            log_warn "PKI role 'test-role' not found (run setup-vault.sh first)"
        fi
    else
        log_error "PKI secrets engine not enabled"
        ((errors++))
    fi

    # Test issuing a certificate (if PKI is set up)
    if vault write -format=json pki/issue/test-role \
        common_name="test.avapigw.local" \
        ttl="5m" &> /dev/null; then
        log_success "PKI certificate issuance works"
    else
        log_warn "PKI certificate issuance failed (may need Root CA setup)"
    fi

    echo ""
    if [[ $errors -eq 0 ]]; then
        log_success "All Vault K8s auth checks passed!"
    else
        log_error "$errors check(s) failed"
        return 1
    fi
}

# ==============================================================================
# Clean
# ==============================================================================

clean_setup() {
    log_info "Cleaning Vault Kubernetes auth setup..."

    # Delete role
    if vault delete auth/kubernetes/role/avapigw &> /dev/null; then
        log_success "Deleted K8s auth role 'avapigw'"
    else
        log_warn "K8s auth role 'avapigw' not found or already deleted"
    fi

    # Delete policy
    if vault policy delete avapigw &> /dev/null; then
        log_success "Deleted policy 'avapigw'"
    else
        log_warn "Policy 'avapigw' not found or already deleted"
    fi

    # Note: We don't disable K8s auth or delete PKI as other services may use them
    log_info "K8s auth method and PKI engine left intact (may be shared)"
    log_success "Cleanup completed"
}

# ==============================================================================
# Configure
# ==============================================================================

configure_policy() {
    log_info "Creating Vault policy 'avapigw'..."

    vault policy write avapigw - <<'POLICY'
# avapigw - API Gateway Vault Policy
# Grants access to PKI, KV, Transit, and token management

# PKI certificate issuance
path "pki/issue/*" {
  capabilities = ["create", "update"]
}
path "pki/sign/*" {
  capabilities = ["create", "update"]
}

# PKI CA certificate reading
path "pki/cert/ca" {
  capabilities = ["read"]
}
path "pki/ca/pem" {
  capabilities = ["read"]
}
path "pki/ca" {
  capabilities = ["read"]
}

# KV secrets reading
path "secret/data/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/*" {
  capabilities = ["read", "list"]
}

# Transit encryption/signing
path "transit/encrypt/*" {
  capabilities = ["create", "update"]
}
path "transit/decrypt/*" {
  capabilities = ["create", "update"]
}
path "transit/sign/*" {
  capabilities = ["create", "update"]
}
path "transit/verify/*" {
  capabilities = ["create", "update"]
}

# Token self-management
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
POLICY

    log_success "Policy 'avapigw' created"
}

configure_k8s_auth() {
    log_info "Configuring Kubernetes auth method..."

    # Enable K8s auth if not already enabled
    if ! vault auth list 2>/dev/null | grep -q "kubernetes/"; then
        log_info "Enabling Kubernetes auth method..."
        vault auth enable kubernetes
        log_success "Kubernetes auth method enabled"
    else
        log_info "Kubernetes auth method already enabled"
    fi

    # Use kubernetes.docker.internal for Docker Desktop K8s
    # The K8s API TLS certificate includes kubernetes.docker.internal in SANs
    # but NOT host.docker.internal, so Vault TLS verification requires this hostname
    local k8s_host="https://kubernetes.docker.internal:6443"
    log_info "K8s API server: $k8s_host"

    # Get K8s CA certificate
    local k8s_ca_cert
    k8s_ca_cert=$(kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d)

    if [[ -z "$k8s_ca_cert" ]]; then
        log_error "Could not extract K8s CA certificate"
        exit 1
    fi

    # Create vault-auth service account for token review
    # Vault needs a K8s SA token to call the TokenReview API
    log_info "Creating vault-auth service account for token review..."
    kubectl create sa vault-auth -n "$K8S_NAMESPACE" 2>/dev/null || \
        log_info "Service account vault-auth already exists"

    kubectl create clusterrolebinding vault-auth-tokenreview \
        --clusterrole=system:auth-delegator \
        --serviceaccount="$K8S_NAMESPACE:vault-auth" 2>/dev/null || \
        log_info "ClusterRoleBinding vault-auth-tokenreview already exists"

    # Create a long-lived token secret for the vault-auth SA
    kubectl apply -f - <<'K8S_SECRET'
apiVersion: v1
kind: Secret
metadata:
  name: vault-auth-token
  annotations:
    kubernetes.io/service-account.name: vault-auth
type: kubernetes.io/service-account-token
K8S_SECRET

    # Wait for token to be populated
    sleep 2

    local reviewer_jwt
    reviewer_jwt=$(kubectl get secret vault-auth-token -n "$K8S_NAMESPACE" -o jsonpath='{.data.token}' | base64 -d)

    if [[ -z "$reviewer_jwt" ]]; then
        log_error "Could not extract vault-auth token reviewer JWT"
        exit 1
    fi
    log_success "Token reviewer JWT obtained from vault-auth SA"

    # Configure K8s auth with token reviewer JWT and ISS validation disabled
    vault write auth/kubernetes/config \
        kubernetes_host="$k8s_host" \
        kubernetes_ca_cert="$k8s_ca_cert" \
        token_reviewer_jwt="$reviewer_jwt" \
        disable_local_ca_jwt=true \
        disable_iss_validation=true

    log_success "Kubernetes auth configured with host: $k8s_host"
}

configure_k8s_role() {
    log_info "Creating Kubernetes auth role 'avapigw'..."

    vault write auth/kubernetes/role/avapigw \
        bound_service_account_names="$SA_NAME" \
        bound_service_account_namespaces="$K8S_NAMESPACE" \
        policies=avapigw \
        ttl=1h \
        max_ttl=24h

    log_success "K8s auth role 'avapigw' created (SA: $SA_NAME, NS: $K8S_NAMESPACE)"
}

# ==============================================================================
# PKI Setup (for test-role)
# ==============================================================================

configure_pki() {
    log_info "Configuring PKI secrets engine with test-role..."

    # Enable PKI engine if not already enabled
    if ! vault secrets list 2>/dev/null | grep -q "pki/"; then
        log_info "Enabling PKI secrets engine..."
        vault secrets enable pki
        log_success "PKI secrets engine enabled"
    else
        log_info "PKI secrets engine already enabled"
    fi

    # Configure PKI max lease TTL
    vault secrets tune -max-lease-ttl=87600h pki

    # Generate root CA if not exists
    if ! vault read pki/cert/ca &>/dev/null; then
        log_info "Generating root CA certificate..."
        vault write pki/root/generate/internal \
            common_name="avapigw-test-ca" \
            ttl="87600h" \
            key_type="rsa" \
            key_bits=4096
        log_success "Root CA generated"
    else
        log_info "Root CA already exists"
    fi

    # Configure CA and CRL URLs
    vault write pki/config/urls \
        issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
        crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

    # Create test-role for avapigw-test namespace
    # Allows certificates for localhost, *.local, *.test, avapigw.local
    # Also allows IP SANs for 127.0.0.1
    log_info "Creating PKI role 'test-role' for $K8S_NAMESPACE namespace..."
    vault write pki/roles/test-role \
        allowed_domains="localhost,local,test,avapigw.local,avapigw-test.local" \
        allow_subdomains=true \
        allow_localhost=true \
        allow_ip_sans=true \
        allowed_uri_sans="spiffe://*" \
        max_ttl="720h" \
        key_type="rsa" \
        key_bits=2048 \
        require_cn=false \
        allow_any_name=false \
        enforce_hostnames=false

    log_success "PKI role 'test-role' created with allowed domains: localhost, *.local, *.test, avapigw.local"
    log_info "  IP SANs allowed: 127.0.0.1"
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    echo ""
    echo "=========================================="
    echo "  Vault Kubernetes Auth Setup"
    echo "  avapigw API Gateway"
    echo "=========================================="
    echo ""
    echo "  Vault:     $VAULT_ADDR"
    echo "  Namespace: $K8S_NAMESPACE"
    echo "  SA:        $SA_NAME"
    echo ""

    check_prerequisites

    if [[ "$CLEAN" == "true" ]]; then
        clean_setup
        exit 0
    fi

    if [[ "$VERIFY_ONLY" == "true" ]]; then
        verify_setup
        exit $?
    fi

    # Configure
    configure_policy
    configure_k8s_auth
    configure_k8s_role

    # Optionally configure PKI
    if [[ "$SETUP_PKI" == "true" ]]; then
        configure_pki
    fi

    echo ""
    log_success "Vault Kubernetes auth setup completed!"
    echo ""
    log_info "Next steps:"
    log_info "  1. Deploy gateway: helm upgrade --install avapigw helm/avapigw/ -f helm/avapigw/values-local.yaml -n $K8S_NAMESPACE --create-namespace"
    log_info "  2. Verify: ./setup-vault-k8s.sh --verify"
    log_info "  3. Test HTTPS: curl -k https://127.0.0.1:<HTTPS_NODEPORT>/health"
    if [[ "$SETUP_PKI" != "true" ]]; then
        log_info ""
        log_info "To also configure PKI with test-role, run:"
        log_info "  ./setup-vault-k8s.sh --setup-pki"
    fi
    echo ""
}

main
