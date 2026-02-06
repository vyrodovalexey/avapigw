# AVAPIGW Operator Installation Guide

This guide provides detailed instructions for installing and configuring the AVAPIGW Operator in various environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
- [Configuration Options](#configuration-options)
- [Vault PKI Setup](#vault-pki-setup)
- [Verification](#verification)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Kubernetes Cluster

- **Kubernetes Version**: 1.23 or later
- **Helm Version**: 3.0 or later
- **kubectl**: Configured to access your cluster

### Required Permissions

The installer needs cluster-admin permissions to:
- Create Custom Resource Definitions (CRDs)
- Create ClusterRoles and ClusterRoleBindings
- Create ValidatingWebhookConfigurations

### Gateway Requirements

- AVAPIGW gateway instances running in the cluster
- Gateway instances configured to accept gRPC connections from the operator
- Network connectivity between operator and gateway pods

## Installation Methods

### Method 1: Helm Installation (Recommended)

#### Quick Installation

The operator is now part of the main Helm chart and can be enabled optionally. The chart supports 3 deployment modes:

1. **Gateway-only mode** (default) - Just the API Gateway
2. **With-operator mode** - Gateway + Operator for CRD-based configuration
3. **With-ingress mode** - Gateway + Operator + Ingress Controller for standard Ingress support

```bash
# Mode 1: Gateway-only (default)
helm install avapigw ./helm/avapigw \
  --namespace avapigw \
  --create-namespace

# Mode 2: Gateway with operator enabled
helm install avapigw ./helm/avapigw \
  --set operator.enabled=true \
  --namespace avapigw \
  --create-namespace

# Mode 3: Gateway with operator and ingress controller
helm install avapigw ./helm/avapigw \
  --set operator.enabled=true \
  --set operator.ingressController.enabled=true \
  --namespace avapigw \
  --create-namespace

# Verify installation
kubectl get pods -n avapigw
kubectl get crd | grep avapigw.io
```

#### Production Installation

```bash
# Create values file for production
cat > production-values.yaml <<EOF
# Enable operator with ingress controller
operator:
  enabled: true
  replicaCount: 2
  
  image:
    repository: ghcr.io/vyrodovalexey/avapigw-operator
    tag: "v1.0.0"
    pullPolicy: IfNotPresent

  resources:
    limits:
      cpu: 1000m
      memory: 512Mi
    requests:
      cpu: 200m
      memory: 256Mi

  podDisruptionBudget:
    enabled: true
    minAvailable: 1

  serviceMonitor:
    enabled: true
    interval: 30s

  grpc:
    tls:
      mode: vault

  # Enable ingress controller for standard Ingress support
  ingressController:
    enabled: true
    className: avapigw
    isDefaultClass: false
    lbAddress: "192.168.1.100"  # LoadBalancer IP for status updates

# Gateway configuration
gateway:
  replicaCount: 3
  
vault:
  enabled: true
  address: "https://vault.example.com:8200"
  authMethod: kubernetes
  role: avapigw
  pki:
    enabled: true
    pkiMount: pki
    role: operator-server
    commonName: avapigw-operator.avapigw-system.svc
    ttl: 24h

# Webhook configuration with Vault PKI
operator:
  webhook:
    tls:
      mode: vault
      vault:
        pkiMount: pki
        role: webhook
        commonName: avapigw-operator-webhook.avapigw-system.svc
        ttl: 24h
EOF

# Install with production values
helm install avapigw ./helm/avapigw \
  --namespace avapigw-system \
  --create-namespace \
  --values production-values.yaml
```

#### Development Installation

```bash
# Use local development values
helm install avapigw-operator ./helm/avapigw-operator \
  --namespace avapigw-test \
  --create-namespace \
  --values ./helm/avapigw-operator/values-local.yaml

# Enable debug logging
kubectl patch deployment avapigw-operator \
  -n avapigw-test \
  --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--log-level=debug"}]'
```

### Method 2: Manual Installation

#### 1. Install CRDs

```bash
# Apply CRDs manually
kubectl apply -f helm/avapigw-operator/crds/

# Verify CRDs are installed
kubectl get crd | grep avapigw
```

#### 2. Create Namespace and RBAC

```bash
# Create namespace
kubectl create namespace avapigw-system

# Create service account
kubectl create serviceaccount avapigw-operator -n avapigw-system

# Apply RBAC (extract from Helm templates)
helm template avapigw-operator ./helm/avapigw-operator \
  --namespace avapigw-system \
  --show-only templates/clusterrole.yaml \
  --show-only templates/clusterrolebinding.yaml \
  --show-only templates/role.yaml \
  --show-only templates/rolebinding.yaml | kubectl apply -f -
```

#### 3. Deploy Operator

```bash
# Generate deployment manifest
helm template avapigw-operator ./helm/avapigw-operator \
  --namespace avapigw-system \
  --show-only templates/deployment.yaml \
  --show-only templates/service.yaml | kubectl apply -f -
```

### Method 3: Kustomize Installation

```bash
# Create kustomization.yaml
cat > kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: avapigw-system

resources:
  - helm/avapigw-operator/crds/
  - https://github.com/vyrodovalexey/avapigw/releases/download/v1.0.0/operator.yaml

patchesStrategicMerge:
  - operator-config.yaml
EOF

# Create configuration patch
cat > operator-config.yaml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: avapigw-operator
spec:
  template:
    spec:
      containers:
      - name: manager
        env:
        - name: VAULT_ADDR
          value: "https://vault.example.com:8200"
        - name: VAULT_AUTH_METHOD
          value: "kubernetes"
EOF

# Apply with kustomize
kubectl apply -k .
```

## Configuration Options

### Core Configuration

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `replicaCount` | Number of operator replicas | `1` | No |
| `image.repository` | Container image repository | `ghcr.io/vyrodovalexey/avapigw-operator` | No |
| `image.tag` | Container image tag | Chart appVersion | No |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` | No |

### Leader Election

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `leaderElection.enabled` | Enable leader election | `true` | No |
| `leaderElection.leaseDuration` | Lease duration | `15s` | No |
| `leaderElection.renewDeadline` | Renew deadline | `10s` | No |
| `leaderElection.retryPeriod` | Retry period | `2s` | No |
| `leaderElection.resourceName` | Lease resource name | `some_id.avapigw.io` | No |

### gRPC Server

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `grpc.port` | gRPC server port | `9444` | No |
| `grpc.tls.mode` | TLS mode (`selfsigned`, `vault`) | `selfsigned` | No |
| `grpc.tls.vault.pkiMount` | Vault PKI mount path | `pki` | If vault mode |
| `grpc.tls.vault.role` | Vault PKI role | `""` | If vault mode |
| `grpc.tls.vault.commonName` | Certificate common name | `""` | If vault mode |
| `grpc.tls.vault.ttl` | Certificate TTL | `24h` | No |

### Webhook Configuration

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `webhook.enabled` | Enable admission webhooks | `true` | No |
| `webhook.port` | Webhook server port | `9443` | No |
| `webhook.tls.mode` | TLS mode (`selfsigned`, `vault`, `cert-manager`) | `selfsigned` | No |
| `webhook.tls.vault.*` | Vault PKI configuration | See gRPC config | If vault mode |
| `webhook.tls.certManager.issuerRef.name` | cert-manager issuer name | `""` | If cert-manager mode |
| `webhook.tls.certManager.issuerRef.kind` | cert-manager issuer kind | `ClusterIssuer` | If cert-manager mode |

### Vault Integration

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `vault.enabled` | Enable Vault integration | `false` | No |
| `vault.address` | Vault server address | `""` | If enabled |
| `vault.authMethod` | Auth method (`kubernetes`, `token`, `approle`) | `kubernetes` | No |
| `vault.role` | Kubernetes auth role | `""` | If kubernetes auth |
| `vault.kubernetesMountPath` | Kubernetes auth mount path | `kubernetes` | No |
| `vault.token` | Vault token (dev only) | `""` | If token auth |

### Resource Configuration

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `resources.limits.cpu` | CPU limit | `500m` | No |
| `resources.limits.memory` | Memory limit | `256Mi` | No |
| `resources.requests.cpu` | CPU request | `100m` | No |
| `resources.requests.memory` | Memory request | `128Mi` | No |

### Security Configuration

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `podSecurityContext.runAsNonRoot` | Run as non-root | `true` | No |
| `podSecurityContext.runAsUser` | User ID | `65532` | No |
| `securityContext.readOnlyRootFilesystem` | Read-only filesystem | `true` | No |
| `securityContext.allowPrivilegeEscalation` | Allow privilege escalation | `false` | No |

### Monitoring Configuration

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `metrics.enabled` | Enable metrics | `true` | No |
| `metrics.port` | Metrics port | `8080` | No |
| `serviceMonitor.enabled` | Enable ServiceMonitor | `false` | No |
| `serviceMonitor.interval` | Scrape interval | `30s` | No |

## Vault PKI Setup

### Prerequisites

- HashiCorp Vault running and accessible
- PKI secrets engine enabled
- Root CA generated
- Kubernetes auth method configured

### 1. Configure Vault PKI

```bash
# Enable PKI engine
vault secrets enable pki

# Configure max lease TTL
vault secrets tune -max-lease-ttl=87600h pki

# Generate root CA
vault write pki/root/generate/internal \
    common_name="AVAPIGW Root CA" \
    ttl=87600h

# Configure PKI URLs
vault write pki/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki/crl"
```

### 2. Create PKI Roles

```bash
# Create role for operator server certificates
vault write pki/roles/operator-server \
    allowed_domains="avapigw-system.svc,avapigw-system.svc.cluster.local" \
    allow_subdomains=true \
    allow_localhost=true \
    allow_ip_sans=true \
    max_ttl=72h \
    ttl=24h

# Create role for webhook certificates
vault write pki/roles/webhook \
    allowed_domains="avapigw-system.svc,avapigw-system.svc.cluster.local" \
    allow_subdomains=true \
    allow_localhost=true \
    allow_ip_sans=true \
    max_ttl=72h \
    ttl=24h
```

### 3. Configure Kubernetes Auth

```bash
# Enable Kubernetes auth
vault auth enable kubernetes

# Configure Kubernetes auth
vault write auth/kubernetes/config \
    token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Create policy for operator
vault policy write avapigw-operator - <<EOF
path "pki/issue/operator-server" {
  capabilities = ["create", "update"]
}
path "pki/issue/webhook" {
  capabilities = ["create", "update"]
}
EOF

# Create Kubernetes auth role
vault write auth/kubernetes/role/avapigw-operator \
    bound_service_account_names=avapigw-operator \
    bound_service_account_namespaces=avapigw-system \
    policies=avapigw-operator \
    ttl=24h
```

### 4. Install Operator with Vault

```bash
# Install with Vault configuration
helm install avapigw-operator ./helm/avapigw-operator \
  --namespace avapigw-system \
  --create-namespace \
  --set vault.enabled=true \
  --set vault.address="https://vault.example.com:8200" \
  --set vault.authMethod=kubernetes \
  --set vault.role=avapigw-operator \
  --set grpc.tls.mode=vault \
  --set grpc.tls.vault.pkiMount=pki \
  --set grpc.tls.vault.role=operator-server \
  --set grpc.tls.vault.commonName=avapigw-operator.avapigw-system.svc \
  --set webhook.tls.mode=vault \
  --set webhook.tls.vault.pkiMount=pki \
  --set webhook.tls.vault.role=webhook \
  --set webhook.tls.vault.commonName=avapigw-operator-webhook.avapigw-system.svc
```

## Verification

### 1. Check Pod Status

```bash
# Check operator pod
kubectl get pods -n avapigw-system
kubectl describe pod -l app.kubernetes.io/name=avapigw-operator -n avapigw-system

# Check logs
kubectl logs -l app.kubernetes.io/name=avapigw-operator -n avapigw-system -f
```

### 2. Verify CRDs

```bash
# List CRDs
kubectl get crd | grep avapigw

# Check CRD details
kubectl describe crd apiroutes.avapigw.io
```

### 3. Test Webhooks

```bash
# Check webhook configuration
kubectl get validatingwebhookconfigurations -l app.kubernetes.io/name=avapigw-operator

# Test webhook validation
kubectl apply -f - <<EOF
apiVersion: avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: test-route
spec:
  match:
    - uri:
        prefix: /test
  route:
    - destination:
        host: test-service
        port: 8080
EOF
```

### 4. Check Metrics

```bash
# Port forward to metrics endpoint
kubectl port-forward -n avapigw-system svc/avapigw-operator-metrics 8080:8080

# Check metrics
curl http://localhost:8080/metrics | grep controller_runtime
```

### 5. Verify gRPC Communication

```bash
# Check gRPC server logs
kubectl logs -l app.kubernetes.io/name=avapigw-operator -n avapigw-system | grep grpc

# Test gRPC connectivity (if grpcurl is available)
kubectl port-forward -n avapigw-system svc/avapigw-operator 9444:9444
grpcurl -insecure localhost:9444 list
```

## Upgrading

### Helm Upgrade

```bash
# Upgrade to new version
helm upgrade avapigw-operator ./helm/avapigw-operator \
  --namespace avapigw-system \
  --values production-values.yaml

# Check upgrade status
helm status avapigw-operator -n avapigw-system
kubectl rollout status deployment/avapigw-operator -n avapigw-system
```

### CRD Upgrades

```bash
# CRDs are not automatically upgraded by Helm
# Manually apply new CRD versions
kubectl apply -f helm/avapigw-operator/crds/

# Verify CRD versions
kubectl get crd apiroutes.avapigw.io -o yaml | grep version
```

### Rolling Back

```bash
# Roll back to previous version
helm rollback avapigw-operator -n avapigw-system

# Check rollback status
kubectl get pods -n avapigw-system
```

## Uninstalling

### Remove Operator

```bash
# Uninstall Helm release
helm uninstall avapigw-operator -n avapigw-system

# Remove namespace (optional)
kubectl delete namespace avapigw-system
```

### Remove CRDs

**Warning**: This will delete all APIRoute, GRPCRoute, Backend, and GRPCBackend resources.

```bash
# List all CRD instances
kubectl get apiroutes,grpcroutes,backends,grpcbackends --all-namespaces

# Delete CRD instances (optional)
kubectl delete apiroutes --all --all-namespaces
kubectl delete grpcroutes --all --all-namespaces
kubectl delete backends --all --all-namespaces
kubectl delete grpcbackends --all --all-namespaces

# Remove CRDs
kubectl delete crd apiroutes.avapigw.io
kubectl delete crd grpcroutes.avapigw.io
kubectl delete crd backends.avapigw.io
kubectl delete crd grpcbackends.avapigw.io
```

### Clean Up Webhooks

```bash
# Remove webhook configurations
kubectl delete validatingwebhookconfigurations -l app.kubernetes.io/name=avapigw-operator
```

## Troubleshooting

### Common Issues

#### 1. Operator Pod Not Starting

```bash
# Check pod events
kubectl describe pod -l app.kubernetes.io/name=avapigw-operator -n avapigw-system

# Check logs
kubectl logs -l app.kubernetes.io/name=avapigw-operator -n avapigw-system

# Common causes:
# - Image pull errors
# - RBAC permissions
# - Resource constraints
```

#### 2. Webhook Failures

```bash
# Check webhook configuration
kubectl get validatingwebhookconfigurations -l app.kubernetes.io/name=avapigw-operator -o yaml

# Check webhook service
kubectl get svc -n avapigw-system avapigw-operator-webhook

# Test webhook connectivity
kubectl port-forward -n avapigw-system svc/avapigw-operator-webhook 9443:9443
curl -k https://localhost:9443/validate-apiroute
```

#### 3. Vault Authentication Issues

```bash
# Check Vault configuration
kubectl logs -l app.kubernetes.io/name=avapigw-operator -n avapigw-system | grep vault

# Verify service account token
kubectl get serviceaccount avapigw-operator -n avapigw-system -o yaml

# Test Vault authentication manually
kubectl exec -it deployment/avapigw-operator -n avapigw-system -- sh
# Inside pod:
# vault auth -method=kubernetes role=avapigw-operator jwt=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
```

#### 4. CRD Validation Errors

```bash
# Check CRD schema
kubectl get crd apiroutes.avapigw.io -o yaml

# Validate CRD instance
kubectl apply --dry-run=server -f your-apiroute.yaml

# Check operator logs for validation details
kubectl logs -l app.kubernetes.io/name=avapigw-operator -n avapigw-system | grep validation
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Update deployment with debug logging
kubectl patch deployment avapigw-operator -n avapigw-system \
  --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--log-level=debug"}]'

# Watch debug logs
kubectl logs -l app.kubernetes.io/name=avapigw-operator -n avapigw-system -f
```

### Support

For additional support:

- **Documentation**: [docs/operator/](.)
- **Issues**: [GitHub Issues](https://github.com/vyrodovalexey/avapigw/issues)
- **Discussions**: [GitHub Discussions](https://github.com/vyrodovalexey/avapigw/discussions)