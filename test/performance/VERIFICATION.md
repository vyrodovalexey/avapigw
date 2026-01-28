# Performance Testing Configuration Verification

**Date:** 2026-01-28  
**Verified by:** Performance Testing Agent  
**Status:** VERIFIED

## Executive Summary

The avapigw API Gateway performance testing infrastructure has been verified and is properly configured for:
- HTTP/HTTPS throughput testing using Yandex Tank
- gRPC/gRPC-TLS testing using ghz
- WebSocket testing using k6
- Local and Kubernetes deployment testing
- Vault PKI integration for TLS certificates
- Keycloak OIDC integration for authentication testing

## 1. Infrastructure Setup Scripts

### 1.1 setup-vault.sh
**Status:** VERIFIED  
**Location:** `test/performance/scripts/setup-vault.sh`

**Features:**
- Configures PKI secrets engine with root CA
- Creates `perftest` role for certificate issuance
- Creates `test-role` for avapigw-test namespace (K8s testing)
- Configures KV secrets engine for API keys
- Configures Transit secrets engine for encryption
- Creates `perftest` policy with appropriate permissions
- Supports `--verify`, `--clean` options

**PKI Role Configuration (test-role):**
```yaml
allowed_domains: ["localhost", "local", "test", "avapigw.local", "avapigw-test.local"]
allow_subdomains: true
allow_localhost: true
allow_ip_sans: true
allowed_uri_sans: ["spiffe://*"]
max_ttl: "720h"
```

### 1.2 setup-keycloak.sh
**Status:** VERIFIED  
**Location:** `test/performance/scripts/setup-keycloak.sh`

**Features:**
- Creates `gateway-test` realm
- Creates `gateway` client with client credentials
- Creates test users: perftest-user-1, perftest-user-2, perftest-admin, testuser, adminuser
- Creates roles: perftest-user, perftest-admin, perftest-readonly
- Verifies OIDC endpoints (discovery, JWKS, token)
- Supports `--verify`, `--clean` options

**Test Users:**
| Username | Password | Purpose |
|----------|----------|---------|
| perftest-user-1 | perftest123 | Performance testing |
| perftest-user-2 | perftest123 | Performance testing |
| perftest-admin | adminpass123 | Admin testing |
| testuser | testpass123 | General testing |

### 1.3 setup-test-env.sh
**Status:** VERIFIED  
**Location:** `test/performance/scripts/setup-test-env.sh`

**Features:**
- Combined setup script for complete test environment
- Starts docker-compose services
- Configures Vault and Keycloak
- Supports `--namespace=avapigw-test` option
- Exponential backoff for service health checks
- Supports `--skip-docker`, `--skip-vault`, `--skip-keycloak` options

### 1.4 setup-vault-k8s.sh
**Status:** VERIFIED  
**Location:** `test/performance/scripts/setup-vault-k8s.sh`

**Features:**
- Configures Vault Kubernetes auth method
- Creates `avapigw` policy for PKI, KV, Transit access
- Creates K8s auth role bound to `avapigw` service account
- Supports `--namespace=avapigw-test` (default)
- Supports `--setup-pki` for PKI configuration
- Uses `kubernetes.docker.internal:6443` for Docker Desktop K8s

## 2. Performance Test Configurations

### 2.1 HTTP Throughput Test
**Status:** VERIFIED  
**File:** `test/performance/configs/http-throughput.yaml`

**Configuration:**
- Target: `host.docker.internal:8080`
- Load Profile: `line(100, 2000, 1m) const(2000, 3m) line(2000, 100, 1m)`
- Duration: 5 minutes (1m warmup + 3m sustain + 1m cooldown)
- Instances: 2000
- Threads: 8
- Autostop: 5xx > 10%, latency > 5000ms for 50%, net errors > 5%

### 2.2 HTTPS Throughput Test
**Status:** VERIFIED  
**File:** `test/performance/configs/https-throughput.yaml`

**Configuration:**
- Target: `host.docker.internal:8443`
- SSL: enabled
- Load Profile: Same as HTTP throughput
- Timeout: 15s (higher for TLS handshake)
- Designed for Vault PKI certificates

### 2.3 HTTP TLS Throughput Test
**Status:** VERIFIED  
**File:** `test/performance/configs/http-tls-throughput.yaml`

**Configuration:**
- Target: `host.docker.internal:8443`
- SSL: enabled
- Load Profile: `line(100, 2000, 1m) const(2000, 3m) line(2000, 100, 1m)`
- Autostop: 4xx > 10%, 5xx > 5%, latency > 5000ms, net > 5%

### 2.4 gRPC TLS Throughput Test
**Status:** VERIFIED  
**File:** `test/performance/configs/grpc/grpc-tls-throughput.yaml`

**Configuration:**
- Target: `127.0.0.1:9443` (gRPC TLS port)
- Service: `api.v1.TestService/Echo`
- TLS: enabled with skipVerify for self-signed certs
- Load: 600,000 total, 100 concurrency, 2000 RPS, 5m duration
- Connections: 20

### 2.5 gRPC TLS Unary Test
**Status:** VERIFIED  
**File:** `test/performance/configs/grpc/grpc-tls-unary.yaml`

**Configuration:**
- Target: `127.0.0.1:9443`
- Service: `api.v1.TestService/Echo`
- TLS: enabled with skipVerify
- Load: 600,000 total, 100 concurrency, 2000 RPS, 5m duration

### 2.6 K8s HTTP Throughput Test
**Status:** VERIFIED  
**File:** `test/performance/configs/k8s-http-throughput.yaml`

**Configuration:**
- Target: `host.docker.internal:8080` (port replaced dynamically)
- Load Profile: `line(1, 50, 30s)` (conservative for local K8s)
- Instances: 100
- Threads: 4
- Autostop: 5xx > 15%, latency > 5000ms, net > 10%

## 3. Performance Test Scripts

### 3.1 run-test.sh
**Status:** VERIFIED  
**Location:** `test/performance/scripts/run-test.sh`

**Supported Tests:**
| Test Name | Description |
|-----------|-------------|
| http-throughput | HTTP GET throughput (default) |
| http-tls-throughput | HTTPS GET with TLS |
| https-throughput | HTTPS GET with Vault PKI |
| http-auth-throughput | HTTP with JWT auth |
| http-post | HTTP POST with payload |
| load-balancing | Load balancer verification |
| rate-limiting | Rate limiter stress test |
| circuit-breaker | Circuit breaker test |
| mixed-workload | Mixed HTTP workload |
| vault-tls-handshake | TLS handshake with Vault certs |
| vault-cert-renewal | Certificate renewal under load |
| vault-backend-mtls | Backend mTLS with Vault certs |
| vault-multi-route-sni | Multi-route SNI with Vault certs |

**Options:**
- `--dry-run` - Validate without running
- `--duration=<time>` - Override duration
- `--rps=<number>` - Override RPS
- `--no-gateway` - Skip gateway start
- `--secure` - Use secure gateway config
- `--features` - Use features gateway config
- `--token=<token>` - JWT token for auth tests

### 3.2 run-grpc-test.sh
**Status:** VERIFIED  
**Location:** `test/performance/scripts/run-grpc-test.sh`

**Supported Tests:**
| Test Name | Description |
|-----------|-------------|
| unary | Unary RPC throughput (default) |
| tls-unary | Unary RPC with TLS |
| auth-unary | Unary RPC with JWT auth |
| server-stream | Server streaming test |
| client-stream | Client streaming test |
| bidi-stream | Bidirectional streaming test |

**Options:**
- `--host=<host>` - Target host (default: 127.0.0.1)
- `--port=<port>` - Target port (default: 9000, 9443 for TLS)
- `--duration=<time>` - Test duration
- `--rps=<number>` - Requests per second
- `--concurrency=<n>` - Concurrent workers
- `--dry-run` - Show command without running
- `--direct` - Test backend directly (port 8803)
- `--token=<token>` - JWT token for auth tests

### 3.3 run-k8s-test.sh
**Status:** VERIFIED  
**Location:** `test/performance/scripts/run-k8s-test.sh`

**Supported Tests:**
| Test Type | Description |
|-----------|-------------|
| http | HTTP throughput via Yandex Tank (default) |
| https | HTTPS throughput via Yandex Tank |
| grpc | gRPC unary test via ghz |
| grpc-tls | gRPC TLS unary test via ghz |
| websocket | WebSocket message test via k6 |
| all | Run all available tests |

**Features:**
- Auto-discovers K8s NodePort services
- Uses `avapigw-test` namespace by default
- Exponential backoff for health checks
- Graceful shutdown handling
- Supports `--namespace=<ns>`, `--service=<name>` options

**NodePort Discovery:**
- HTTP: port named 'http'
- HTTPS: port named 'https'
- gRPC: port named 'grpc'
- gRPC TLS: port named 'grpcs'
- Metrics: port named 'metrics'

## 4. Gateway Configurations

### 4.1 gateway-perftest.yaml
**Status:** VERIFIED  
**Location:** `test/performance/configs/gateway-perftest.yaml`

**Listeners:**
- HTTP: port 8080
- gRPC: port 9000 (reflection enabled, health check enabled)

**Routes:**
- `/health` - Direct response
- `/api/v1/items` - Load balanced (50/50) to backends 8801, 8802
- `/backend/health` - Rewrite to backend health
- `/` - Catch-all to backend 8801

**gRPC Routes:**
- `api.v1.TestService` - Load balanced (50/50) to backends 8803, 8804
- Catch-all to backend 8803

### 4.2 gateway-perftest-secure.yaml
**Status:** VERIFIED  
**Location:** `test/performance/configs/gateway-perftest-secure.yaml`

**Listeners:**
- HTTP: port 8080
- HTTPS: port 8443 (TLS enabled)
- gRPC: port 9000
- gRPC-TLS: port 9443 (TLS enabled)

**TLS Configuration:**
- Mode: SIMPLE
- Min Version: TLS12
- Max Version: TLS13
- Cipher Suites: ECDHE-RSA/ECDSA with AES-GCM

**Authentication:**
- JWT/OIDC via Keycloak
- Issuer: `http://127.0.0.1:8090/realms/gateway-test`
- JWKS Cache: 5m
- Clock Skew: 30s

**Protected Routes:**
- `/api/v1/protected/items` - JWT required
- `/api/v1/protected/users` - JWT required
- `/ws/protected` - WebSocket with JWT

## 5. Helm Values for K8s Testing

### 5.1 values-local.yaml
**Status:** VERIFIED  
**Location:** `helm/avapigw/values-local.yaml`

**Configuration:**
- Namespace: `avapigw-test`
- Service Type: NodePort
- Ports: HTTP (8080), HTTPS (8443), gRPC (9000), gRPC-TLS (9443), Metrics (9090)
- Image: `avapigw:test` (pullPolicy: Never)

**Vault Integration:**
- Address: `http://host.docker.internal:8200`
- Auth Method: kubernetes
- Role: avapigw
- PKI Mount: pki
- PKI Role: test-role
- Common Name: avapigw.local
- Alt Names: localhost, avapigw.local, *.avapigw.local
- gRPC TLS: enabled

## 6. Test Environment (docker-compose)

**Status:** VERIFIED  
**Location:** `test/docker-compose/docker-compose.yml`

**Services:**
| Service | Port | Image |
|---------|------|-------|
| Vault | 8200 | hashicorp/vault:1.17 |
| REST API 1 | 8801 | ghcr.io/vyrodovalexey/restapi-example:e9416f5 |
| REST API 2 | 8802 | ghcr.io/vyrodovalexey/restapi-example:e9416f5 |
| gRPC 1 | 8803 | ghcr.io/vyrodovalexey/grpc-example:21f4570 |
| gRPC 2 | 8804 | ghcr.io/vyrodovalexey/grpc-example:21f4570 |
| Redis | 6379 | bitnami/redis:latest |
| Keycloak | 8090 | quay.io/keycloak/keycloak:26.5 |

**Backend Capabilities:**
- WebSocket at `/ws` endpoint
- gRPC streaming (ServerStream, ClientStream, BidiStream)

## 7. Test Execution Procedures

### 7.1 Local Testing

#### Prerequisites
```bash
# Start test infrastructure
cd test/docker-compose
docker compose up -d

# Setup Vault
./test/performance/scripts/setup-vault.sh

# Setup Keycloak
./test/performance/scripts/setup-keycloak.sh

# Or use combined setup
./test/performance/scripts/setup-test-env.sh
```

#### HTTP Tests
```bash
# Basic HTTP throughput
./test/performance/scripts/run-test.sh http-throughput

# HTTPS with TLS
./test/performance/scripts/run-test.sh https-throughput --secure

# HTTP with JWT auth
./test/performance/scripts/run-test.sh http-auth-throughput --secure
```

#### gRPC Tests
```bash
# Basic gRPC unary
./test/performance/scripts/run-grpc-test.sh unary

# gRPC with TLS
./test/performance/scripts/run-grpc-test.sh tls-unary

# gRPC with JWT auth
./test/performance/scripts/run-grpc-test.sh auth-unary
```

### 7.2 Kubernetes Testing

#### Prerequisites
```bash
# Build gateway image
make docker-build

# Setup Vault K8s auth
./test/performance/scripts/setup-vault-k8s.sh --namespace=avapigw-test --setup-pki

# Deploy gateway
helm upgrade --install avapigw helm/avapigw/ \
  -f helm/avapigw/values-local.yaml \
  -n avapigw-test --create-namespace
```

#### K8s Tests
```bash
# HTTP test
./test/performance/scripts/run-k8s-test.sh http --namespace=avapigw-test

# HTTPS test (requires TLS NodePort)
./test/performance/scripts/run-k8s-test.sh https --namespace=avapigw-test

# gRPC test
./test/performance/scripts/run-k8s-test.sh grpc --namespace=avapigw-test

# gRPC TLS test
./test/performance/scripts/run-k8s-test.sh grpc-tls --namespace=avapigw-test

# All tests
./test/performance/scripts/run-k8s-test.sh all --namespace=avapigw-test
```

## 8. Expected Results and Thresholds

### 8.1 HTTP Tests
| Metric | Target | Acceptable |
|--------|--------|------------|
| Max RPS | > 2000 | > 1500 |
| Avg Latency | < 50ms | < 100ms |
| P95 Latency | < 200ms | < 500ms |
| P99 Latency | < 500ms | < 1000ms |
| Error Rate | < 0.1% | < 1% |

### 8.2 HTTPS/TLS Tests
| Metric | Target | Acceptable |
|--------|--------|------------|
| Max RPS | > 1500 | > 1000 |
| Avg Latency | < 75ms | < 150ms |
| P95 Latency | < 300ms | < 600ms |
| Error Rate | < 0.1% | < 1% |

### 8.3 gRPC Tests
| Metric | Target | Acceptable |
|--------|--------|------------|
| Max RPS | > 2000 | > 1500 |
| Avg Latency | < 10ms | < 50ms |
| P95 Latency | < 50ms | < 100ms |
| P99 Latency | < 100ms | < 200ms |
| Error Rate | < 0.1% | < 0.5% |

### 8.4 K8s Tests (Conservative)
| Metric | Target | Acceptable |
|--------|--------|------------|
| Max RPS | > 50 | > 30 |
| Avg Latency | < 100ms | < 200ms |
| P95 Latency | < 500ms | < 1000ms |
| Error Rate | < 1% | < 5% |

## 9. Issues Found and Recommendations

### 9.1 No Issues Found
All configurations are properly set up and verified.

### 9.2 Recommendations

1. **TLS Certificate Management**
   - For production testing, use proper CA certificates instead of skipVerify
   - Consider adding CA certificate mounting in test configurations

2. **K8s Test Load**
   - K8s tests use conservative load (50 RPS) for Docker Desktop
   - Increase load for dedicated K8s clusters

3. **Monitoring**
   - Enable Telegraf plugin for detailed resource monitoring during tests
   - Consider adding Prometheus metrics scraping

4. **Results Storage**
   - Results are stored in `test/performance/.yandextank/` and `test/performance/results/`
   - Consider archiving results for trend analysis

## 10. Verification Checklist

- [x] setup-vault.sh configures PKI with test-role for avapigw-test namespace
- [x] setup-keycloak.sh creates gateway-test realm with test users
- [x] setup-test-env.sh orchestrates complete environment setup
- [x] setup-vault-k8s.sh configures K8s auth for avapigw-test namespace
- [x] http-throughput.yaml properly configured for HTTP testing
- [x] https-throughput.yaml properly configured for HTTPS testing
- [x] grpc-tls-throughput.yaml properly configured for gRPC TLS testing
- [x] k8s-http-throughput.yaml properly configured for K8s testing
- [x] run-test.sh supports HTTPS and auth testing
- [x] run-grpc-test.sh supports gRPC TLS testing
- [x] run-k8s-test.sh supports both local and K8s gateway testing
- [x] values-local.yaml uses avapigw-test namespace
- [x] All scripts are executable
- [x] Documentation is comprehensive (README.md)

## Conclusion

The performance testing infrastructure for avapigw API Gateway is fully verified and ready for use. All configurations support:
- HTTP/HTTPS testing with Vault PKI TLS
- gRPC/gRPC-TLS testing
- Local gateway testing
- Kubernetes deployed gateway testing
- JWT authentication testing via Keycloak

The `avapigw-test` namespace is consistently used across all K8s-related configurations.
