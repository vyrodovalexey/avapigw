# E2E Test Cases for AVAPIGW

This document describes the E2E test cases for the AVAPIGW Kubernetes operator with Vault integration.

## Test Environment

- **Kubernetes**: Real cluster accessible via kubectl
- **Vault Server**: http://192.168.0.61:8200
- **Vault Role**: all
- **Test Namespace**: avapigw-e2e-test

## Test Categories

### 1. Vault Setup Tests (`vault_setup_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TC-VS-001 | Verify Vault is accessible and unsealed | Vault health check passes |
| TC-VS-002 | Verify token is valid | Token lookup succeeds |
| TC-VS-003 | Verify KV v2 secrets engine is enabled | KV v2 mount exists at secret/ |
| TC-VS-004 | Create test secrets in Vault | Secrets created at avapigw/test/* |
| TC-VS-005 | Verify Kubernetes auth method is enabled | kubernetes/ auth mount exists |
| TC-VS-006 | Verify Vault role exists | Role 'all' is configured |
| TC-VS-007 | Enable PKI secrets engine for root CA | PKI mount at pki/ |
| TC-VS-008 | Generate root CA certificate | Root CA created |
| TC-VS-009 | Enable intermediate PKI secrets engine | PKI mount at pki_int/ |
| TC-VS-010 | Generate and sign intermediate CA | Intermediate CA signed by root |
| TC-VS-011 | Create PKI role for certificate issuance | Role 'e2e-test-role' created |
| TC-VS-012 | Issue a test certificate | Certificate issued successfully |
| TC-VS-013 | Create test policy for avapigw | Policy 'avapigw-e2e-test' created |

### 2. VaultSecret E2E Tests (`vaultsecret_e2e_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TC-VSE-001 | VaultSecret with token auth syncs to K8s Secret | Target secret created with correct data |
| TC-VSE-002 | VaultSecret handles key mappings correctly | Only mapped keys appear in target |
| TC-VSE-003 | VaultSecret handles Base64 encoding | Encoded values are decoded |
| TC-VSE-004 | VaultSecret applies target secret labels/annotations | Labels and annotations present |
| TC-VSE-005 | VaultSecret with Kubernetes auth | Authentication via K8s service account |
| TC-VSE-006 | Secret refresh on Vault update | Target secret updated after Vault change |
| TC-VSE-007 | VaultSecret deletion with Delete policy | Target secret deleted |
| TC-VSE-008 | VaultSecret deletion with Retain policy | Target secret retained |
| TC-VSE-009 | Handle non-existent Vault path | Error status with message |
| TC-VSE-010 | Handle invalid Vault address | Error status with connection error |
| TC-VSE-011 | Multiple VaultSecrets concurrently | All secrets synced correctly |

### 3. TLS Certificate Tests (`tls_certificate_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TC-TLS-001 | Issue certificate from Vault PKI | Valid TLS certificate created |
| TC-TLS-002 | Create TLSConfig with Secret source | TLSConfig ready with cert info |
| TC-TLS-003 | Create TLSConfig with Vault source | TLSConfig ready with Vault cert |
| TC-TLS-004 | Certificate rotation on Vault update | New certificate synced |
| TC-TLS-005 | TLSConfig with client validation (mTLS) | Client validation configured |
| TC-TLS-006 | TLSConfig with SAN matching | SAN rules configured |

### 4. Gateway Deployment Tests (`gateway_deployment_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TC-GW-001 | Create Gateway with HTTP listener | Gateway created with listener |
| TC-GW-002 | Create Gateway with HTTPS listener | Gateway with TLS configured |
| TC-GW-003 | Create Gateway with multiple listeners | All listeners configured |
| TC-GW-004 | Create Gateway with hostname filter | Hostname filter applied |
| TC-GW-005 | Gateway status update | ListenersCount updated |
| TC-GW-006 | Complete Gateway with Backend and HTTPRoute | All resources created |
| TC-GW-007 | Gateway service verification | Service created with correct ports |
| TC-GW-008 | Gateway deployment verification | Deployment created |
| TC-GW-009 | Health endpoint configuration | Health endpoint accessible |
| TC-GW-010 | Metrics endpoint configuration | Metrics endpoint accessible |

### 5. Traffic Flow Tests (`traffic_flow_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TC-TF-001 | Route HTTP requests based on path | Requests routed to correct backend |
| TC-TF-002 | Route HTTP requests based on headers | Header matching works |
| TC-TF-003 | Route HTTP requests based on method | Method matching works |
| TC-TF-004 | HTTPS with TLS termination | TLS terminated at gateway |
| TC-TF-005 | TLS passthrough | TLS passed to backend |
| TC-TF-006 | Round-robin load balancing | Requests distributed evenly |
| TC-TF-007 | Weighted load balancing | Requests distributed by weight |
| TC-TF-008 | Consistent hash load balancing | Same client goes to same backend |
| TC-TF-009 | Rate limiting policy | Requests limited per policy |
| TC-TF-010 | JWT authentication policy | JWT validation enforced |
| TC-TF-011 | API key authentication policy | API key validation enforced |

### 6. Resilience Tests (`resilience_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TC-RS-001 | Gateway state recovery after pod restart | Configuration preserved |
| TC-RS-002 | Configuration maintained after multiple updates | No data loss |
| TC-RS-003 | Handle backend with no healthy endpoints | Graceful degradation |
| TC-RS-004 | Circuit breaker configuration | Circuit breaker active |
| TC-RS-005 | Outlier detection configuration | Outlier detection active |
| TC-RS-006 | Handle Vault connection errors | Error status, no crash |
| TC-RS-007 | Recover when Vault becomes available | Sync resumes |
| TC-RS-008 | Preserve secret during Vault outage | Existing secret retained |
| TC-RS-009 | Update Gateway listeners without downtime | Zero downtime update |
| TC-RS-010 | Update HTTPRoute rules without downtime | Zero downtime update |
| TC-RS-011 | Handle rapid configuration changes | System stable |
| TC-RS-012 | Clean up orphaned resources | Resources deleted |
| TC-RS-013 | Handle finalizers correctly | Proper cleanup on deletion |

## Running Tests

### Prerequisites

1. Kubernetes cluster accessible via kubectl
2. Vault server running at http://192.168.0.61:8200
3. CRDs installed (`make install`)
4. Controller running (optional, for full E2E)

### Environment Variables

```bash
export VAULT_ADDR=http://192.168.0.61:8200
export VAULT_TOKEN=myroot
export VAULT_ROLE=all
export E2E_NAMESPACE=avapigw-e2e-test
export KUBECONFIG=~/.kube/config
```

### Run All E2E Tests

```bash
go test ./test/e2e/... -tags=e2e -v -timeout 30m
```

### Run Specific Test Suite

```bash
# Vault Setup Tests
go test ./test/e2e/... -tags=e2e -v -run "Vault Setup"

# VaultSecret Tests
go test ./test/e2e/... -tags=e2e -v -run "VaultSecret E2E"

# TLS Certificate Tests
go test ./test/e2e/... -tags=e2e -v -run "TLS Certificate"

# Gateway Deployment Tests
go test ./test/e2e/... -tags=e2e -v -run "Gateway Deployment"

# Traffic Flow Tests
go test ./test/e2e/... -tags=e2e -v -run "Traffic Flow"

# Resilience Tests
go test ./test/e2e/... -tags=e2e -v -run "Resilience"
```

### Skip E2E Tests

```bash
export SKIP_E2E=true
go test ./test/e2e/... -tags=e2e
```

## Test Data

### Vault Secrets Created During Tests

| Path | Keys | Purpose |
|------|------|---------|
| secret/data/avapigw/test/basic | username, password | Basic auth test |
| secret/data/avapigw/test/database | host, port, database, username, password | Database config test |
| secret/data/avapigw/test/api-keys | api_key, api_secret | API key test |
| secret/data/avapigw/test/multikey | key1, key2, key3 | Multi-key mapping test |
| secret/data/avapigw/e2e/* | Various | E2E test data |

### PKI Configuration

| Component | Path | Purpose |
|-----------|------|---------|
| Root CA | pki/ | Root certificate authority |
| Intermediate CA | pki_int/ | Intermediate CA for issuing certs |
| Role | pki_int/roles/e2e-test-role | Certificate issuance role |

## Cleanup

Tests automatically clean up resources after each test. If cleanup fails, manually delete:

```bash
kubectl delete namespace avapigw-e2e-test
```

## Troubleshooting

### Vault Connection Issues

1. Verify Vault is running: `vault status`
2. Check Vault address is accessible
3. Verify token is valid: `vault token lookup`

### Kubernetes Issues

1. Verify cluster access: `kubectl cluster-info`
2. Check CRDs installed: `kubectl get crd | grep avapigw`
3. Verify namespace exists: `kubectl get ns avapigw-e2e-test`

### Test Failures

1. Check test logs for specific errors
2. Verify prerequisites are met
3. Check resource status: `kubectl describe <resource> -n avapigw-e2e-test`
