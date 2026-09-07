#!/usr/bin/env bash
# =============================================================================
# setup-vault-k8s.sh - Configure Vault Kubernetes auth for the local cluster
# =============================================================================
# This script configures the Vault (running in docker-compose) Kubernetes auth
# method so that pods in the local Docker-Desktop / kind cluster can authenticate
# to Vault with their ServiceAccount token. It mirrors the style of
# setup-vault.sh (same repo dir) and reuses the PKI + KV mounts that script sets
# up.
#
# It:
#   1. Enables the 'kubernetes' auth method (idempotent).
#   2. Configures it to talk to the cluster's API server. Vault (in compose) is
#      NOT in the cluster, so disable_local_ca_jwt=true is set and a reviewer JWT
#      (SA 'vault-auth' bound to system:auth-delegator) is passed so Vault can
#      call the TokenReview API. kubernetes_host is auto-detected as the node
#      InternalIP:6443 (present in the API server cert SANs AND reachable from the
#      Vault container).
#   3. Creates the 'avapigw-policy' policy (PKI issue, KV read, Transit).
#   4. Binds gateway + operator ServiceAccounts to K8s auth roles:
#        role 'avapigw'          -> SAs avapigw, avapigw-gateway
#        role 'avapigw-operator' -> SA  avapigw-operator
#   5. Syncs the PKI CA into the 'avapigw-vault-pki-ca' Secret (gateway verifies
#      the operator gRPC serving cert against it).
#
# Usage:
#   ./scripts/setup-vault-k8s.sh            # configure
#   ./scripts/setup-vault-k8s.sh --verify   # verify only
#   ./scripts/setup-vault-k8s.sh --login-test  # configure + run k8s->Vault login test
#
# Environment overrides:
#   VAULT_ADDR    (default http://127.0.0.1:8200)
#   VAULT_TOKEN   (default myroot)
#   KUBE_CONTEXT  (default docker-desktop)
#   K8S_NAMESPACE (default avapigw-test)
#   K8S_HOST      (override the auto-detected kubernetes_host)
# =============================================================================

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-myroot}"
KUBE_CONTEXT="${KUBE_CONTEXT:-docker-desktop}"
K8S_NAMESPACE="${K8S_NAMESPACE:-avapigw-test}"
POLICY_NAME="${POLICY_NAME:-avapigw-policy}"
GATEWAY_ROLE="${GATEWAY_ROLE:-avapigw}"
OPERATOR_ROLE="${OPERATOR_ROLE:-avapigw-operator}"
GATEWAY_SAS="${GATEWAY_SAS:-avapigw,avapigw-gateway}"
OPERATOR_SA="${OPERATOR_SA:-avapigw-operator}"
PKI_MOUNT="${PKI_MOUNT:-pki}"
KV_MOUNT="${KV_MOUNT:-secret}"
PKI_CA_SECRET="${PKI_CA_SECRET:-avapigw-vault-pki-ca}"

export VAULT_ADDR VAULT_TOKEN

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

kc() { kubectl --context="${KUBE_CONTEXT}" "$@"; }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
check_prerequisites() {
    log_info "Checking prerequisites..."
    command -v vault >/dev/null 2>&1   || { log_error "vault CLI not found (brew install vault)"; exit 1; }
    command -v kubectl >/dev/null 2>&1 || { log_error "kubectl not found"; exit 1; }
    vault status >/dev/null 2>&1       || { log_error "Cannot reach Vault at ${VAULT_ADDR}"; exit 1; }
    kc cluster-info >/dev/null 2>&1    || { log_error "Cannot reach cluster (context ${KUBE_CONTEXT})"; exit 1; }
    log_info "Prerequisites OK"
}

# ---------------------------------------------------------------------------
# Determine the kubernetes_host Vault must use.
#
# Vault runs in docker-compose (NOT in the cluster). It must reach an API-server
# address that is BOTH routable from the Vault container AND present in the API
# server certificate SANs (so Vault's TLS verification of the TokenReview call
# passes). On this kind-based Docker-Desktop cluster the node InternalIP:6443
# (e.g. 172.19.0.2:6443) satisfies both — kubernetes.docker.internal / 127.0.0.1
# on the host point at a DIFFERENT (Rancher k3s) API server and MUST NOT be used.
# ---------------------------------------------------------------------------
detect_k8s_host() {
    if [[ -n "${K8S_HOST:-}" ]]; then
        echo "${K8S_HOST}"
        return 0
    fi
    local node_ip
    node_ip=$(kc get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null | awk '{print $1}')
    if [[ -n "${node_ip}" ]]; then
        echo "https://${node_ip}:6443"
    else
        echo "https://kubernetes.docker.internal:6443"
    fi
}

# ---------------------------------------------------------------------------
# Policy: PKI issuance + KV read + Transit + token self-management
# ---------------------------------------------------------------------------
configure_policy() {
    log_info "Writing Vault policy '${POLICY_NAME}'..."
    vault policy write "${POLICY_NAME}" - <<POLICY
# avapigw - API Gateway + Operator Vault policy
path "${PKI_MOUNT}/issue/*"   { capabilities = ["create", "update"] }
path "${PKI_MOUNT}/sign/*"    { capabilities = ["create", "update"] }
path "${PKI_MOUNT}/cert/ca"   { capabilities = ["read"] }
path "${PKI_MOUNT}/ca/pem"    { capabilities = ["read"] }
path "${PKI_MOUNT}/ca"        { capabilities = ["read"] }
path "${KV_MOUNT}/data/*"     { capabilities = ["read", "list"] }
path "${KV_MOUNT}/metadata/*" { capabilities = ["read", "list"] }
path "transit/encrypt/*"      { capabilities = ["create", "update"] }
path "transit/decrypt/*"      { capabilities = ["create", "update"] }
path "transit/sign/*"         { capabilities = ["create", "update"] }
path "transit/verify/*"       { capabilities = ["create", "update"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
POLICY
    log_info "Policy '${POLICY_NAME}' written"
}

# ---------------------------------------------------------------------------
# Kubernetes auth method: enable + configure with reviewer JWT
# ---------------------------------------------------------------------------
configure_k8s_auth() {
    log_info "Enabling 'kubernetes' auth method (idempotent)..."
    if ! vault auth list 2>/dev/null | grep -q '^kubernetes/'; then
        vault auth enable kubernetes
        log_info "kubernetes auth enabled"
    else
        log_info "kubernetes auth already enabled"
    fi

    local k8s_host
    k8s_host=$(detect_k8s_host)
    log_info "kubernetes_host = ${k8s_host}"

    local k8s_ca_cert
    k8s_ca_cert=$(kc config view --raw --minify --flatten \
        -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d)
    [[ -n "${k8s_ca_cert}" ]] || { log_error "Could not extract cluster CA"; exit 1; }

    # Reviewer SA 'vault-auth' bound to system:auth-delegator so Vault can call
    # the TokenReview API from outside the cluster.
    log_info "Ensuring reviewer SA 'vault-auth' + ClusterRoleBinding..."
    kc create sa vault-auth -n "${K8S_NAMESPACE}" 2>/dev/null || true
    kc apply -f - <<CRB
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vault-auth-tokenreview-${K8S_NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
  - kind: ServiceAccount
    name: vault-auth
    namespace: ${K8S_NAMESPACE}
CRB

    kc apply -f - <<SECRET
apiVersion: v1
kind: Secret
metadata:
  name: vault-auth-token
  namespace: ${K8S_NAMESPACE}
  annotations:
    kubernetes.io/service-account.name: vault-auth
type: kubernetes.io/service-account-token
SECRET

    local reviewer_jwt=""
    for _ in $(seq 1 15); do
        reviewer_jwt=$(kc get secret vault-auth-token -n "${K8S_NAMESPACE}" \
            -o jsonpath='{.data.token}' 2>/dev/null | base64 -d 2>/dev/null || true)
        [[ -n "${reviewer_jwt}" ]] && break
        sleep 1
    done
    [[ -n "${reviewer_jwt}" ]] || { log_error "Could not obtain vault-auth reviewer JWT"; exit 1; }
    log_info "Reviewer JWT obtained"

    vault write auth/kubernetes/config \
        kubernetes_host="${k8s_host}" \
        kubernetes_ca_cert="${k8s_ca_cert}" \
        token_reviewer_jwt="${reviewer_jwt}" \
        disable_local_ca_jwt=true \
        disable_iss_validation=true
    log_info "kubernetes auth configured (host ${k8s_host})"
}

# ---------------------------------------------------------------------------
# Roles: gateway + operator
# ---------------------------------------------------------------------------
configure_k8s_roles() {
    log_info "Creating K8s auth role '${GATEWAY_ROLE}' (SAs: ${GATEWAY_SAS})..."
    vault write "auth/kubernetes/role/${GATEWAY_ROLE}" \
        bound_service_account_names="${GATEWAY_SAS}" \
        bound_service_account_namespaces="${K8S_NAMESPACE}" \
        policies="${POLICY_NAME}" \
        ttl=1h max_ttl=24h

    log_info "Creating K8s auth role '${OPERATOR_ROLE}' (SA: ${OPERATOR_SA})..."
    vault write "auth/kubernetes/role/${OPERATOR_ROLE}" \
        bound_service_account_names="${OPERATOR_SA}" \
        bound_service_account_namespaces="${K8S_NAMESPACE}" \
        policies="${POLICY_NAME}" \
        ttl=1h max_ttl=24h
    log_info "Roles created"
}

# ---------------------------------------------------------------------------
# Sync the PKI CA into a K8s Secret (gateway verifies operator gRPC cert)
# ---------------------------------------------------------------------------
sync_pki_ca_secret() {
    log_info "Syncing PKI CA into Secret '${PKI_CA_SECRET}' (ns ${K8S_NAMESPACE})..."
    local ca_pem
    ca_pem=$(vault read -field=certificate "${PKI_MOUNT}/cert/ca" 2>/dev/null || true)
    if [[ -z "${ca_pem}" ]]; then
        log_warn "Could not read ${PKI_MOUNT}/cert/ca (run setup-vault.sh first); skipping CA secret sync"
        return 0
    fi
    kc get ns "${K8S_NAMESPACE}" >/dev/null 2>&1 || kc create ns "${K8S_NAMESPACE}"
    kc create secret generic "${PKI_CA_SECRET}" \
        --namespace "${K8S_NAMESPACE}" \
        --from-literal=ca.crt="${ca_pem}" \
        --dry-run=client -o yaml | kc apply -f -
    log_info "Secret '${PKI_CA_SECRET}' synced"
}

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
verify_setup() {
    log_info "Verifying Vault Kubernetes auth setup..."
    local errors=0

    vault policy read "${POLICY_NAME}" >/dev/null 2>&1 \
        && log_info "  ✓ policy '${POLICY_NAME}'" || { log_error "  ✗ policy '${POLICY_NAME}'"; errors=$((errors+1)); }
    vault auth list 2>/dev/null | grep -q '^kubernetes/' \
        && log_info "  ✓ kubernetes auth enabled" || { log_error "  ✗ kubernetes auth"; errors=$((errors+1)); }
    vault read auth/kubernetes/config >/dev/null 2>&1 \
        && log_info "  ✓ kubernetes auth configured" || { log_error "  ✗ kubernetes auth config"; errors=$((errors+1)); }
    vault read "auth/kubernetes/role/${GATEWAY_ROLE}" >/dev/null 2>&1 \
        && log_info "  ✓ role '${GATEWAY_ROLE}'" || { log_error "  ✗ role '${GATEWAY_ROLE}'"; errors=$((errors+1)); }
    vault read "auth/kubernetes/role/${OPERATOR_ROLE}" >/dev/null 2>&1 \
        && log_info "  ✓ role '${OPERATOR_ROLE}'" || { log_error "  ✗ role '${OPERATOR_ROLE}'"; errors=$((errors+1)); }

    if [[ ${errors} -gt 0 ]]; then
        log_error "Verification failed with ${errors} error(s)"
        return 1
    fi
    log_info "Vault K8s auth verified"
}

# ---------------------------------------------------------------------------
# Login test: run a throwaway pod in-cluster, project its SA token, and log in
# to Vault with role avapigw. Proves the whole chain works.
# ---------------------------------------------------------------------------
login_test() {
    log_info "Running in-cluster k8s->Vault login test (role ${GATEWAY_ROLE})..."
    # Ensure the gateway SA exists so the bound_service_account_names matches.
    kc get sa avapigw -n "${K8S_NAMESPACE}" >/dev/null 2>&1 || kc create sa avapigw -n "${K8S_NAMESPACE}"

    local pod="vault-login-test"
    kc delete pod "${pod}" -n "${K8S_NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true

    # Reach Vault from the pod: host.docker.internal:8200 (Vault dev port on host).
    kc run "${pod}" -n "${K8S_NAMESPACE}" \
        --image=curlimages/curl:8.11.1 \
        --restart=Never \
        --overrides='{"spec":{"serviceAccountName":"avapigw"}}' \
        --command -- sleep 120 >/dev/null 2>&1

    kc wait --for=condition=Ready "pod/${pod}" -n "${K8S_NAMESPACE}" --timeout=60s >/dev/null 2>&1 || true

    # Build the login script with the role substituted at generation time so the
    # in-pod shell only has to interpolate the JWT. curl reads the JSON body from
    # a file written with a shell here-doc to avoid nested-quote breakage.
    local out
    out=$(kc exec -n "${K8S_NAMESPACE}" "${pod}" -- sh -c "
        JWT=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
        printf '{\"jwt\":\"%s\",\"role\":\"${GATEWAY_ROLE}\"}' \"\$JWT\" > /tmp/login.json
        curl -s --request POST --data @/tmp/login.json \
          http://host.docker.internal:8200/v1/auth/kubernetes/login
    " 2>&1 || true)

    kc delete pod "${pod}" -n "${K8S_NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true

    if echo "${out}" | grep -q '"client_token"'; then
        log_info "  ✓ k8s->Vault login SUCCEEDED. Response (truncated):"
        echo "${out}" | python3 -m json.tool 2>/dev/null | head -30 || echo "${out}"
        return 0
    fi
    log_error "  ✗ k8s->Vault login FAILED. Response:"
    echo "${out}"
    return 1
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    local mode="${1:-configure}"
    check_prerequisites

    case "${mode}" in
        --verify)
            verify_setup
            ;;
        --login-test)
            configure_policy
            configure_k8s_auth
            configure_k8s_roles
            sync_pki_ca_secret
            verify_setup
            login_test
            ;;
        configure|*)
            configure_policy
            configure_k8s_auth
            configure_k8s_roles
            sync_pki_ca_secret
            verify_setup
            log_info ""
            log_info "=== Vault Kubernetes auth setup complete ==="
            log_info "Run './scripts/setup-vault-k8s.sh --login-test' to prove k8s->Vault login."
            ;;
    esac
}

main "$@"
