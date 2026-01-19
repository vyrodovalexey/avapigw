# Testing Guide

This document provides comprehensive information about the test suite structure, configuration, and execution for the AVAPIGW (API Gateway Kubernetes Operator) project.

## Overview

The AVAPIGW project uses a multi-layered testing strategy to ensure code quality and reliability:

- **Unit Tests**: Fast, isolated tests for individual functions and methods
- **Functional Tests**: Tests for business logic and component behavior
- **Integration Tests**: Tests for controller reconciliation with envtest
- **E2E Tests**: End-to-end tests against real infrastructure (Vault, Keycloak, Kubernetes)

All tests are written using Go's standard testing package with [Ginkgo](https://onsi.github.io/ginkgo/) and [Gomega](https://onsi.github.io/gomega/) for BDD-style testing.

## Test Types

### Unit Tests

Unit tests are located alongside the source code and test individual functions in isolation.

```bash
# Run unit tests
make test-unit

# Run with coverage
make test
```

**Location**: `*_test.go` files in source directories (e.g., `internal/config/config_test.go`)

### Functional Tests

Functional tests verify business logic and component behavior without external dependencies.

```bash
# Run functional tests
make test-functional
```

**Location**: `test/functional/`

### Integration Tests

Integration tests use [envtest](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest) to test Kubernetes controllers against a local API server.

```bash
# Run integration tests
make test-integration
```

**Location**: `test/integration/`

### E2E Tests

End-to-end tests run against real infrastructure including Vault, Keycloak, and a Kubernetes cluster.

```bash
# Run all E2E tests
make test-e2e

# Run specific E2E test categories
make test-e2e-auth        # All authentication tests
make test-e2e-basic-auth  # Basic Auth tests
make test-e2e-oauth       # OAuth2/JWT tests
make test-e2e-vault       # Vault integration tests
make test-e2e-setup       # Environment setup tests
```

**Location**: `test/e2e/`

## Environment Variables

The test suite uses environment variables for configuration. All variables have sensible defaults for local development.

### Vault Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TEST_VAULT_ADDR` | Vault server address | `http://localhost:8200` |
| `TEST_VAULT_TOKEN` | Vault root token (required for Vault tests) | - |
| `TEST_VAULT_ROLE` | Vault Kubernetes auth role | `avapigw-test` |

### Kubernetes Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TEST_K8S_API_SERVER` | Kubernetes API server address | `https://127.0.0.1:6443` |
| `TEST_K8S_CA_CERT` | Kubernetes CA certificate (PEM format) | - |

### Keycloak Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TEST_KEYCLOAK_URL` | Keycloak server URL | `http://localhost:8080` |
| `TEST_KEYCLOAK_ADMIN` | Keycloak admin username | `admin` |
| `TEST_KEYCLOAK_PASSWORD` | Keycloak admin password | `admin` |
| `TEST_KEYCLOAK_REALM` | Test realm name | `avapigw-test` |
| `TEST_KEYCLOAK_CLIENT_ID` | OAuth2 client ID | `avapigw-test-client` |
| `TEST_KEYCLOAK_CLIENT_SECRET` | OAuth2 client secret (required for OAuth tests) | - |

### Test Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TEST_NAMESPACE` | Kubernetes namespace for tests | `avapigw-e2e-test` |

### Skip Flags

| Variable | Description | Default |
|----------|-------------|---------|
| `SKIP_E2E` | Skip all E2E tests | `false` |
| `SKIP_VAULT_TESTS` | Skip Vault-related tests | `false` |
| `SKIP_KEYCLOAK_TESTS` | Skip Keycloak-related tests | `false` |

## Test Environment Setup

### Prerequisites

Before running E2E tests, ensure you have the following infrastructure available:

1. **Kubernetes Cluster**: A running Kubernetes cluster (kind, minikube, or remote)
2. **HashiCorp Vault**: A Vault server with Kubernetes authentication enabled
3. **Keycloak**: A Keycloak server for OAuth2/OIDC testing

### Quick Setup with Docker Compose

For local development, you can use Docker Compose to start Vault and Keycloak:

```bash
# Start Vault (dev mode)
docker run -d --name vault \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=myroot \
  hashicorp/vault:latest

# Start Keycloak
docker run -d --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

### Configuration Steps

1. **Export environment variables**:

   ```bash
   # Generate template
   make test-env-export > .env.local
   
   # Edit with your values
   vim .env.local
   
   # Source the file
   source .env.local
   ```

2. **Verify connectivity**:

   ```bash
   make test-env-check
   ```

   Expected output:
   ```
   Checking test environment...
   TEST_VAULT_ADDR: http://localhost:8200
   TEST_KEYCLOAK_URL: http://localhost:8080
   TEST_K8S_API_SERVER: https://127.0.0.1:6443
   TEST_NAMESPACE: avapigw-e2e-test
   
   Checking connectivity...
   Vault: 200
   Keycloak: 200
   Kubernetes: connected
   ```

3. **Run setup tests** (creates test resources in Vault and Keycloak):

   ```bash
   make test-env-setup
   ```

### Vault Setup

The E2E tests require Vault to be configured with:

1. **KV Secrets Engine** (v2) mounted at `secret/`
2. **Kubernetes Authentication** enabled and configured
3. **Policy** allowing read/write access to test paths

Example Vault setup:

```bash
# Enable KV v2 secrets engine
vault secrets enable -path=secret kv-v2

# Enable Kubernetes auth
vault auth enable kubernetes

# Configure Kubernetes auth
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443"

# Create policy
vault policy write avapigw-test - <<EOF
path "secret/data/avapigw/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# Create role
vault write auth/kubernetes/role/avapigw-test \
  bound_service_account_names=avapigw-test \
  bound_service_account_namespaces=avapigw-e2e-test \
  policies=avapigw-test \
  ttl=1h
```

### Keycloak Setup

The E2E tests require Keycloak to be configured with:

1. **Test Realm**: `avapigw-test`
2. **Client**: `avapigw-test-client` with client credentials grant enabled
3. **Test Users**: For authentication testing

The setup tests (`make test-e2e-setup`) will automatically create these resources.

## Running Tests

### Run All Tests

```bash
# Run all tests (unit + functional + integration)
make test-all

# Run with E2E tests (requires infrastructure)
make test-all && make test-e2e
```

### Run Specific Test Categories

```bash
# Unit tests only
make test-unit

# Functional tests
make test-functional

# Integration tests (requires envtest)
make test-integration

# E2E tests (requires infrastructure)
make test-e2e
```

### Run with Verbose Output

```bash
# Using go test directly
go test -v ./...

# Using Ginkgo for E2E
./bin/ginkgo -v -tags=e2e ./test/e2e/...
```

### Run Specific Test Files

```bash
# Run specific test file
go test -v ./internal/config/config_test.go ./internal/config/config.go

# Run tests matching pattern
go test -v -run "TestConfig" ./...
```

### Generate Coverage Report

```bash
make test-coverage
# Opens coverage.html in bin/
```

## Authentication Testing

### Basic Auth Tests

Basic authentication tests verify username/password authentication flows.

```bash
make test-e2e-basic-auth
```

Test scenarios:
- Valid credentials authentication
- Invalid credentials rejection
- Credential rotation handling
- Vault-stored credentials retrieval

### OAuth2/JWT Tests

OAuth2 tests verify token-based authentication with Keycloak.

```bash
make test-e2e-oauth
```

Test scenarios:
- Client credentials grant flow
- JWT token validation
- Token refresh handling
- Invalid token rejection
- Scope-based authorization

### Vault Integration Tests

Vault tests verify secret management and Kubernetes authentication.

```bash
make test-e2e-vault
```

Test scenarios:
- Kubernetes service account authentication
- Secret read/write operations
- Secret rotation
- VaultSecret CRD reconciliation
- Dynamic credential generation

## Troubleshooting

### Common Issues

#### Vault Connection Refused

**Symptom**: `connection refused` when connecting to Vault

**Solution**:
1. Verify Vault is running: `curl http://localhost:8200/v1/sys/health`
2. Check `TEST_VAULT_ADDR` is correct
3. Ensure no firewall blocking the port

#### Keycloak Not Ready

**Symptom**: `Keycloak: unreachable` in connectivity check

**Solution**:
1. Wait for Keycloak to fully start (can take 30-60 seconds)
2. Check health endpoint: `curl http://localhost:8080/health/ready`
3. Verify `TEST_KEYCLOAK_URL` is correct

#### Kubernetes Authentication Failed

**Symptom**: `unauthorized` errors in Vault Kubernetes auth

**Solution**:
1. Verify service account exists in test namespace
2. Check Vault Kubernetes auth configuration
3. Ensure cluster CA certificate is correct

#### Missing Environment Variables

**Symptom**: `missing required environment variables` error

**Solution**:
1. Run `make test-env-export` to see required variables
2. Set missing variables or use skip flags:
   ```bash
   export SKIP_VAULT_TESTS=true
   export SKIP_KEYCLOAK_TESTS=true
   ```

#### Envtest Binary Not Found

**Symptom**: `setup-envtest: command not found`

**Solution**:
```bash
make envtest
```

### Debug Mode

Enable verbose logging for debugging:

```bash
# For Ginkgo tests
$(GINKGO) -v -trace ./test/e2e/...

# For go test
go test -v -count=1 ./...
```

### Cleanup Test Resources

If tests fail and leave resources behind:

```bash
# Delete test namespace
kubectl delete namespace avapigw-e2e-test --ignore-not-found

# Clean Vault test data (if using dev mode, restart Vault)
docker restart vault
```

## CI/CD Integration

### GitHub Actions

The project includes GitHub Actions workflows for automated testing:

- **ci.yaml**: Runs on every PR - unit, functional, and integration tests
- **e2e.yaml**: Runs E2E tests against real infrastructure

### Environment Variables in CI

Set these secrets in your CI environment:

```yaml
env:
  TEST_VAULT_ADDR: ${{ secrets.TEST_VAULT_ADDR }}
  TEST_VAULT_TOKEN: ${{ secrets.TEST_VAULT_TOKEN }}
  TEST_KEYCLOAK_URL: ${{ secrets.TEST_KEYCLOAK_URL }}
  TEST_KEYCLOAK_CLIENT_SECRET: ${{ secrets.TEST_KEYCLOAK_CLIENT_SECRET }}
```

### Running Tests in CI

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      
      - name: Run unit tests
        run: make test-unit
      
      - name: Run integration tests
        run: make test-integration
      
      - name: Run E2E tests
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        run: make test-e2e
        env:
          TEST_VAULT_ADDR: ${{ secrets.TEST_VAULT_ADDR }}
          TEST_VAULT_TOKEN: ${{ secrets.TEST_VAULT_TOKEN }}
```

### Parallel Test Execution

For faster CI runs, tests can be parallelized:

```bash
# Run unit tests in parallel
go test -parallel 4 ./...

# Run Ginkgo tests in parallel
$(GINKGO) -p -tags=e2e ./test/e2e/...
```

### Test Artifacts

Configure CI to upload test artifacts:

```yaml
- name: Upload coverage
  uses: actions/upload-artifact@v4
  with:
    name: coverage
    path: bin/cover*.out

- name: Upload test results
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: test-results
    path: bin/test-results/
```

## Best Practices

1. **Run tests locally before pushing**: `make test-all`
2. **Use skip flags for missing infrastructure**: `SKIP_VAULT_TESTS=true`
3. **Keep test data isolated**: Use unique namespaces and prefixes
4. **Clean up after tests**: Implement proper teardown in test suites
5. **Use table-driven tests**: For comprehensive coverage with less code
6. **Mock external dependencies**: In unit tests, mock Vault and Keycloak clients
