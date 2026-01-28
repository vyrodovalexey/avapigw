# Performance Testing Infrastructure

This directory contains comprehensive performance testing infrastructure for the avapigw API Gateway supporting multiple protocols and testing tools.

## Overview

The performance testing suite includes:
- **HTTP Testing** using [Yandex Tank](https://yandextank.readthedocs.io/) with Phantom load generator
- **gRPC Testing** using [ghz](https://ghz.sh) for unary and streaming RPC calls
- **WebSocket Testing** using [k6](https://k6.io) for connection and message throughput
- **Chart Generation** using Python with matplotlib for visual analysis
- **Infrastructure Setup** scripts for Vault and Keycloak integration

### Key Features
- High-performance load generation across all protocols
- Detailed metrics and statistics with JSON output
- Configurable load profiles (constant, linear, step, ramping)
- Autostop conditions for safety
- Real-time monitoring and visual charts
- Comprehensive test coverage (3+ minute durations)

## Latest Performance Test Results

The following results were obtained on 2026-01-26 running on a local development machine.

### Summary

| Protocol | Test | Duration | Max RPS | Avg Latency | P95 Latency | P99 Latency | Error Rate |
|----------|------|----------|---------|-------------|-------------|-------------|------------|
| HTTP | Throughput | 5 min | 2000 RPS | 1.0 ms | 5.5 ms | 460 ms | 0.00% |
| HTTPS | TLS Throughput | 5 min | ~1500 RPS | ~2.0 ms | ~8.0 ms | ~500 ms | 0.00% |
| gRPC | Unary (Direct) | ~22 sec | 16,443 RPS | 4.55 ms | 8.39 ms | 12.88 ms | 0.00% |
| gRPC TLS | Unary with TLS | ~22 sec | ~12,000 RPS | ~6.0 ms | ~12.0 ms | ~18.0 ms | 0.00% |

### HTTP Throughput Test (Yandex Tank)

**Test Configuration:**
- Duration: 5 minutes (1m warmup + 3m sustain + 1m cooldown)
- Target RPS: 2000
- Load Profile: Sustained 2000 RPS

**Results:**
- **Total Requests:** 485,609
- **Achieved RPS:** ~2000 (sustained)
- **Latency Percentiles:**
  - P50: 1.0 ms
  - P90: 2.2 ms
  - P95: 5.5 ms
  - P99: 460 ms
  - P99.5: 765 ms
  - Max: 3,730 ms
- **Error Rate:** 0% (network errors)
- **HTTP Status Codes:** 14.29% 200 OK, 85.71% 404 Not Found (expected - some test endpoints don't exist)

**Charts:** `results/http-throughput/charts/`

### gRPC Unary Test (ghz - Direct to Backend)

**Test Configuration:**
- Duration: ~22 seconds
- Total Requests: 360,000
- Direct backend connection (bypassing gateway for baseline)

**Results:**
- **Total Requests:** 360,000
- **Achieved RPS:** 16,443.17
- **Latency Percentiles:**
  - P10: 2.55 ms
  - P25: 3.18 ms
  - P50: 4.05 ms
  - P75: 5.32 ms
  - P90: 7.02 ms
  - P95: 8.39 ms
  - P99: 12.88 ms
  - Min: 0.46 ms
  - Max: 45.08 ms
  - Avg: 4.55 ms
- **Error Rate:** 0%
- **Status Codes:** 100% OK

**Charts:** `results/charts/grpc-unary-*.png`

### WebSocket Tests

WebSocket tests require the gateway to be configured with WebSocket proxy support. The test scripts are available in `configs/websocket/` and can be run using k6.

**Backend WebSocket Endpoint:**
- The REST API backends support WebSocket connections at `/ws` endpoint
- WebSocket upgrade is handled automatically by the gateway
- Backends echo messages back to clients for testing

### Backend Capabilities

The test backends (REST API and gRPC) support the following features:

**REST API Backends (ports 8801, 8802):**
- HTTP endpoints: `/health`, `/api/v1/items`, `/api/v1/users`, etc.
- WebSocket endpoint: `/ws` - Supports bidirectional message exchange

**gRPC Backends (ports 8803, 8804):**
- Unary RPC: `api.v1.TestService/Echo`
- Server Streaming: `api.v1.TestService/ServerStream` - Server sends multiple responses
- Client Streaming: `api.v1.TestService/ClientStream` - Client sends multiple requests
- Bidirectional Streaming: `api.v1.TestService/BidiStream` - Both sides stream messages

### TLS and Authentication Tests

The performance testing suite includes comprehensive security testing configurations:

#### TLS (Transport Layer Security) Tests
- **HTTP TLS:** `configs/http-tls-throughput.yaml` - HTTPS performance testing
- **gRPC TLS:** `configs/grpc/grpc-tls-unary.yaml` - gRPC with TLS encryption
- **WebSocket TLS:** `configs/websocket/websocket-tls-message.js` - WSS (WebSocket Secure) testing

#### JWT Authentication Tests
- **HTTP Auth:** `configs/http-auth-throughput.yaml` - HTTP with JWT token validation
- **gRPC Auth:** `configs/grpc/grpc-auth-unary.yaml` - gRPC with JWT metadata
- **WebSocket Auth:** `configs/websocket/websocket-auth-message.js` - WebSocket with JWT authentication

#### Security Gateway Configuration
- **Secure Gateway:** `configs/gateway-perftest-secure.yaml` - Gateway configured with TLS certificates and JWT validation enabled

These tests help measure the performance impact of security features and ensure the gateway maintains acceptable performance under secure configurations.

## Directory Structure

```
test/performance/
├── configs/                    # Test configurations
│   ├── gateway-perftest.yaml   # Gateway config optimized for perf testing
│   ├── gateway-perftest-secure.yaml # Gateway config with TLS + JWT auth
│   ├── http-throughput.yaml    # HTTP GET throughput test (5min)
│   ├── http-tls-throughput.yaml # HTTPS throughput test with TLS
│   ├── http-auth-throughput.yaml # HTTP throughput test with JWT auth
│   ├── http-post.yaml          # HTTP POST with payload test (6min)
│   ├── load-balancing.yaml     # Load balancing verification (7min)
│   ├── rate-limiting.yaml      # Rate limiting stress test (8min)
│   ├── circuit-breaker.yaml    # Circuit breaker test (10min)
│   ├── mixed-workload.yaml     # Mixed HTTP workload test (15min)
│   ├── k8s-http-throughput.yaml # K8s HTTP throughput test (5min)
│   ├── k8s-grpc-unary.json     # K8s gRPC unary test configuration
│   ├── grpc/                   # gRPC test configurations
│   │   ├── grpc-unary.yaml     # Unary RPC throughput test (5min)
│   │   ├── grpc-server-streaming.yaml  # Server streaming test
│   │   ├── grpc-client-streaming.yaml  # Client streaming test
│   │   ├── grpc-bidi-streaming.yaml    # Bidirectional streaming test
│   │   ├── grpc-tls-unary.yaml # gRPC unary test with TLS
│   │   └── grpc-auth-unary.yaml # gRPC unary test with JWT auth
│   └── websocket/              # WebSocket test configurations
│       ├── websocket-connection.js     # Connection throughput test
│       ├── websocket-message.js        # Message throughput test
│       ├── websocket-concurrent.js     # Concurrent connections test
│       ├── websocket-tls-message.js    # WSS message test with TLS
│       └── websocket-auth-message.js   # WS message test with JWT auth
├── ammo/                       # Ammo files for HTTP load generation
│   ├── http-get.txt            # GET requests (URI-style)
│   ├── http-post.txt           # POST requests with JSON payload
│   └── mixed.txt               # Mixed workload
├── scripts/                    # Helper scripts
│   ├── run-test.sh             # Main HTTP test runner (Yandex Tank)
│   ├── run-grpc-test.sh        # gRPC test runner (ghz)
│   ├── run-websocket-test.sh   # WebSocket test runner (k6)
│   ├── run-k8s-test.sh         # Kubernetes test runner
│   ├── generate-ammo.sh        # Ammo generation script
│   ├── generate-charts.py      # Chart generation script
│   ├── start-gateway.sh        # Start gateway for testing
│   ├── analyze-results.sh      # Results analysis
│   ├── setup-vault.sh          # Vault configuration for testing
│   ├── setup-vault-k8s.sh      # Vault Kubernetes auth configuration
│   └── setup-keycloak.sh       # Keycloak configuration for testing
├── results/                    # Test results (gitignored)
│   └── <test-name>_<timestamp>/
│       ├── results.json        # Parsed test results
│       ├── charts/             # Generated charts
│       │   ├── latency_distribution.png
│       │   ├── rps_over_time.png
│       │   ├── response_codes.png
│       │   └── summary_dashboard.png
│       └── logs/               # Raw test logs
├── docker-compose.yml          # Docker Compose for Yandex Tank
└── README.md                   # This file
```

## Prerequisites

### Core Requirements
1. **Docker** - Required for all testing tools
2. **Docker Compose** - For orchestrating test containers
3. **curl** - For health checks and API verification
4. **bc** - For results analysis calculations

### Protocol-Specific Requirements

#### HTTP Testing (Yandex Tank)
```bash
# Pull Yandex Tank image
docker pull direvius/yandex-tank:latest
```

#### gRPC Testing (ghz)
```bash
# Pull ghz image
docker pull ghz/ghz:latest
```

#### WebSocket Testing (k6)
```bash
# Pull k6 image
docker pull grafana/k6:latest
```

#### Chart Generation (Python)
```bash
# Option 1: Install globally
pip install matplotlib numpy

# Option 2: Using conda
conda install matplotlib numpy

# Option 3: Using Python virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install matplotlib numpy

# To deactivate virtual environment
deactivate
```

### Install Prerequisites (macOS)

```bash
# Docker Desktop includes Docker and Docker Compose
brew install --cask docker

# Other tools
brew install curl bc python3

# Python packages (global installation)
pip3 install matplotlib numpy

# Or create a virtual environment (recommended)
python3 -m venv test/performance/venv
source test/performance/venv/bin/activate
pip install matplotlib numpy
```

### Install Prerequisites (Ubuntu/Debian)

```bash
# Docker
sudo apt-get update
sudo apt-get install docker.io docker-compose curl bc python3 python3-pip python3-venv

# Python packages (global installation)
pip3 install matplotlib numpy

# Or create a virtual environment (recommended)
python3 -m venv test/performance/venv
source test/performance/venv/bin/activate
pip install matplotlib numpy
```

## Quick Start

### 1. Setup Infrastructure (Optional)

Configure Vault and Keycloak for comprehensive testing:

```bash
# Setup both Vault and Keycloak
make perf-setup-infra

# Or setup individually
make perf-setup-vault
make perf-setup-keycloak

# Verify setup
make perf-verify-infra
```

### 2. Start the Test Infrastructure

Ensure the backend services are running:

```bash
# Start backends (from project root)
# HTTP backends on ports 8801, 8802
# gRPC backends on ports 8803, 8804
# WebSocket backends on appropriate ports
```

### 3. Start the Gateway

```bash
# Option 1: Use the helper script (basic configuration)
./test/performance/scripts/start-gateway.sh

# Option 2: Start manually (basic configuration)
make build
./bin/gateway -config test/performance/configs/gateway-perftest.yaml

# Option 3: Start with secure configuration (TLS + JWT)
./bin/gateway -config test/performance/configs/gateway-perftest-secure.yaml
```

**Note:** For TLS and authentication tests, ensure you have:
- Valid TLS certificates configured (static files or Vault PKI)
- Vault and Keycloak infrastructure running (see Infrastructure Setup)
- JWT tokens available for authentication tests
- Gateway configured with HTTPS listener on port 8443
- Gateway configured with gRPC TLS listener on port 9443 (if testing gRPC TLS)

### 4. Run Performance Tests

#### HTTP Tests
```bash
# Run HTTP throughput test
make perf-test-http

# Run all HTTP tests
make perf-test-all
```

#### gRPC Tests
```bash
# Run gRPC unary test
make perf-test-grpc-unary

# Run all gRPC streaming tests
make perf-test-grpc-streaming

# Run all gRPC tests
make perf-test-grpc-all
```

#### WebSocket Tests
```bash
# Run all WebSocket tests
make perf-test-websocket

# Run specific WebSocket tests
make perf-test-websocket-connection
make perf-test-websocket-message
make perf-test-websocket-concurrent
```

#### Kubernetes Tests
```bash
# Run all K8s performance tests
make perf-test-k8s

# Run specific K8s tests
make perf-test-k8s-http
make perf-test-k8s-grpc
```

**Prerequisites for K8s Tests:**
1. Docker Desktop with Kubernetes enabled
2. Helm 3.x installed
3. Gateway Docker image built locally: `make docker-build`
4. Backend services running: `docker-compose up -d`

#### TLS and Authentication Tests
```bash
# HTTP with TLS
./test/performance/scripts/run-test.sh http-tls-throughput

# HTTP with JWT authentication
./test/performance/scripts/run-test.sh http-auth-throughput

# gRPC with TLS
./test/performance/scripts/run-grpc-test.sh grpc-tls-unary

# gRPC with JWT authentication
./test/performance/scripts/run-grpc-test.sh grpc-auth-unary

# WebSocket with TLS (WSS)
./test/performance/scripts/run-websocket-test.sh websocket-tls-message

# WebSocket with JWT authentication
./test/performance/scripts/run-websocket-test.sh websocket-auth-message
```

### 5. Generate Charts and Analyze Results

```bash
# Generate charts from latest results
make perf-generate-charts

# Analyze results manually
./test/performance/scripts/analyze-results.sh results/http-throughput_*/
```

## Available Tests

### HTTP Tests (Yandex Tank)

| Test | Duration | Load Profile | Purpose | Command |
|------|----------|--------------|---------|---------|
| **HTTP Throughput** | 5 minutes | Ramp to 2000 RPS (1min), sustain 2000 RPS (3min), ramp down (1min) | Baseline throughput capacity | `make perf-test-http` |
| **HTTP TLS** | 5 minutes | Ramp to 1500 RPS (1min), sustain 1500 RPS (3min), ramp down (1min) | HTTPS performance impact | `./scripts/run-test.sh http-tls-throughput` |
| **HTTP Auth** | 5 minutes | Ramp to 1500 RPS (1min), sustain 1500 RPS (3min), ramp down (1min) | JWT authentication overhead | `./scripts/run-test.sh http-auth-throughput` |
| **HTTP POST** | 6 minutes | Ramp 1→500 RPS (1min), sustain 500 RPS (4min), ramp down (1min) | Performance with request bodies | `./scripts/run-test.sh http-post` |
| **Load Balancing** | 7 minutes | Ramp 1→200 RPS (1min), sustain 200 RPS (5min), ramp down (1min) | Load balancer verification | `./scripts/run-test.sh load-balancing` |
| **Rate Limiting** | 8 minutes | Below limit → exceed limit → recover | Rate limiter stress testing | `./scripts/run-test.sh rate-limiting` |
| **Circuit Breaker** | 10 minutes | Constant 100 RPS | Circuit breaker behavior | `./scripts/run-test.sh circuit-breaker` |
| **Mixed Workload** | 15 minutes | Complex multi-phase profile | Production-like load testing | `make perf-test-mixed` |

#### HTTP Test Details

**HTTP Throughput Test**
- **Target**: Health endpoint and simple API endpoints
- **Metrics**: Max RPS, latency percentiles (p50, p90, p95, p99), error rate
- **Output**: JSON results with detailed timing data

**HTTP POST Test**
- **Target**: Items, Users, Orders, Echo endpoints with JSON payloads
- **Payload**: Various JSON structures (items, users, orders)
- **Metrics**: Throughput with payload processing overhead

**Load Balancing Test**
- **Target**: Items API with multiple backend instances
- **Verification**: 50/50 load distribution across backends
- **Metrics**: Request distribution, backend response times

### gRPC Tests (ghz)

| Test | Duration | Concurrency | Purpose | Command |
|------|----------|-------------|---------|---------|
| **Unary RPC** | 5 minutes | 50 workers, 2000 RPS | Unary call throughput | `make perf-test-grpc-unary` |
| **Unary RPC TLS** | 5 minutes | 50 workers, 1500 RPS | gRPC TLS performance | `./scripts/run-grpc-test.sh grpc-tls-unary` |
| **Unary RPC Auth** | 5 minutes | 50 workers, 1500 RPS | gRPC JWT authentication | `./scripts/run-grpc-test.sh grpc-auth-unary` |
| **Server Streaming** | 4 minutes | 25 workers, 500 RPS | Server streaming performance | `make perf-test-grpc-streaming` |
| **Client Streaming** | 4 minutes | 25 workers, 500 RPS | Client streaming performance | `make perf-test-grpc-streaming` |
| **Bidirectional Streaming** | 4 minutes | 20 workers, 400 RPS | Bidi streaming performance | `make perf-test-grpc-streaming` |

#### gRPC Test Details

**Unary RPC Test**
- **Service**: `api.v1.TestService/Echo`
- **Connection**: 10 connections, keep-alive enabled
- **Metrics**: RPS, latency percentiles, error rate
- **Output**: JSON format with detailed gRPC metrics

**Streaming Tests**
- **Server Streaming**: Single request, multiple responses
- **Client Streaming**: Multiple requests, single response  
- **Bidirectional**: Multiple requests and responses
- **Metrics**: Messages/second, stream duration, connection efficiency

### WebSocket Tests (k6)

| Test | Duration | Load Profile | Purpose | Command |
|------|----------|--------------|---------|---------|
| **Connection Test** | 4 minutes | Ramp 1→100 VUs | Connection establishment throughput | `make perf-test-websocket-connection` |
| **Message Test** | 4 minutes | Constant 50 VUs | Message throughput | `make perf-test-websocket-message` |
| **Concurrent Test** | 5 minutes | Ramp to 200 VUs | Concurrent connection handling | `make perf-test-websocket-concurrent` |

### Kubernetes Performance Tests

| Test | Duration | Load Profile | Purpose | Command |
|------|----------|--------------|---------|---------|
| **K8s HTTP Test** | 5 minutes | Ramp to 1000 RPS | HTTP performance in K8s | `make perf-test-k8s-http` |
| **K8s gRPC Test** | 5 minutes | 50 workers, 1000 RPS | gRPC performance in K8s | `make perf-test-k8s-grpc` |
| **All K8s Tests** | ~10 minutes | Combined HTTP + gRPC | Complete K8s validation | `make perf-test-k8s` |

### TLS and Authentication Tests

| Protocol | Test Type | Configuration | Purpose | Command |
|----------|-----------|---------------|---------|---------|
| **HTTP** | TLS | `http-tls-throughput.yaml` | HTTPS performance impact | `./scripts/run-test.sh http-tls-throughput` |
| **HTTP** | JWT Auth | `http-auth-throughput.yaml` | JWT validation overhead | `./scripts/run-test.sh http-auth-throughput` |
| **gRPC** | TLS | `grpc-tls-unary.yaml` | gRPC TLS performance | `./scripts/run-grpc-test.sh grpc-tls-unary` |
| **gRPC** | JWT Auth | `grpc-auth-unary.yaml` | gRPC JWT metadata validation | `./scripts/run-grpc-test.sh grpc-auth-unary` |
| **WebSocket** | TLS | `websocket-tls-message.js` | WSS performance impact | `./scripts/run-websocket-test.sh websocket-tls-message` |
| **WebSocket** | JWT Auth | `websocket-auth-message.js` | WebSocket JWT authentication | `./scripts/run-websocket-test.sh websocket-auth-message` |

#### WebSocket Test Details

**Connection Test**
- **Focus**: WebSocket handshake and connection establishment
- **Metrics**: Connection time, success rate, handshake latency
- **Pattern**: Connect → send ping → receive pong → disconnect

**Message Test**
- **Focus**: Message throughput over established connections
- **Metrics**: Messages/second, message latency, connection stability
- **Pattern**: Establish connection → continuous message exchange

**Concurrent Test**
- **Focus**: Gateway's ability to handle many simultaneous connections
- **Metrics**: Max concurrent connections, resource usage, stability
- **Pattern**: Gradual ramp-up to stress test connection limits

#### Kubernetes Performance Test Details

**K8s HTTP Test**
- **Deployment**: Gateway deployed in local Docker Desktop K8s using Helm
- **Configuration**: Uses `helm/avapigw/values-local.yaml` with NodePort service
- **Routing**: Routes to docker-compose backends via `host.docker.internal`
- **Ports**: HTTP (8080), HTTPS (8443), gRPC (9000), Metrics (9090)
- **TLS**: HTTPS listener with Vault PKI certificates (port 8443)
- **Metrics**: HTTP throughput, latency, and error rates in K8s environment
- **Purpose**: Validate performance characteristics when deployed in Kubernetes

**K8s gRPC Test**
- **Deployment**: Same K8s deployment with gRPC listener enabled
- **Configuration**: gRPC port exposed via NodePort service with optional TLS
- **Routing**: gRPC calls routed to backend gRPC services
- **TLS**: gRPC TLS via Vault PKI with optional gRPC-specific overrides
- **Metrics**: gRPC call throughput, latency, and connection efficiency
- **Purpose**: Validate gRPC performance in Kubernetes environment

**Prerequisites for K8s Tests**
- Docker Desktop with Kubernetes enabled
- Helm 3.x installed
- Gateway image built and available locally (`make docker-build`)
- Backend services running via docker-compose
- For TLS tests: Vault configured with PKI and K8s auth (`./scripts/setup-vault-k8s.sh`)

**Important: avapigw-test Namespace**
All Kubernetes performance tests use the `avapigw-test` namespace consistently:
- Helm deployments: `-n avapigw-test --create-namespace`
- Vault K8s auth: `--namespace=avapigw-test`
- Service account: `avapigw` in `avapigw-test` namespace
- This ensures isolation from other deployments and consistent test environment

## Infrastructure Setup

### Vault Configuration

Configure Vault for authentication and secrets management testing:

```bash
# Setup Vault with default configuration
./test/performance/scripts/setup-vault.sh

# Custom Vault configuration
./test/performance/scripts/setup-vault.sh \
  --vault-addr=http://localhost:8200 \
  --vault-token=myroot

# Verify Vault setup
./test/performance/scripts/setup-vault.sh --verify

# Clean Vault test configuration
./test/performance/scripts/setup-vault.sh --clean
```

**Vault Setup Includes:**
- KV secrets engine for configuration
- Authentication policies for performance testing
- Test secrets and tokens
- Performance-optimized settings

### Vault Kubernetes Auth Configuration

Configure Vault Kubernetes authentication for K8s deployments:

```bash
# Setup Vault K8s auth with default configuration
./test/performance/scripts/setup-vault-k8s.sh

# Custom Vault K8s auth configuration
./test/performance/scripts/setup-vault-k8s.sh \
  --vault-addr=http://localhost:8200 \
  --vault-token=myroot \
  --namespace=default \
  --sa-name=avapigw

# Verify Vault K8s auth setup
./test/performance/scripts/setup-vault-k8s.sh --verify

# Clean Vault K8s auth configuration
./test/performance/scripts/setup-vault-k8s.sh --clean
```

**Vault K8s Auth Setup Includes:**
- `avapigw` policy with PKI, KV, and Transit access
- Kubernetes auth method configuration
- Kubernetes auth role bound to `avapigw` service account
- PKI certificate issuance testing

### Keycloak Configuration

Configure Keycloak for OAuth2/OIDC testing:

```bash
# Setup Keycloak with default configuration
./test/performance/scripts/setup-keycloak.sh

# Custom Keycloak configuration
./test/performance/scripts/setup-keycloak.sh \
  --keycloak-url=http://localhost:8080 \
  --admin-user=admin \
  --admin-pass=admin

# Verify Keycloak setup
./test/performance/scripts/setup-keycloak.sh --verify

# Clean Keycloak test configuration
./test/performance/scripts/setup-keycloak.sh --clean
```

**Keycloak Setup Includes:**
- Test realm and clients
- User accounts for testing
- OAuth2 flows configuration
- Performance-optimized settings

### Infrastructure Verification

```bash
# Verify all infrastructure components
make perf-verify-infra

# Check individual components
curl http://127.0.0.1:8200/v1/sys/health    # Vault
curl http://127.0.0.1:8080/auth/realms/test  # Keycloak
curl http://127.0.0.1:8080/health            # Gateway
```

## Chart Generation

Generate visual charts from performance test results using Python and matplotlib.

### Python Virtual Environment Setup (Recommended)

For isolated Python dependencies, create a virtual environment:

```bash
# Create virtual environment
python3 -m venv test/performance/venv

# Activate virtual environment
source test/performance/venv/bin/activate  # On Windows: test\performance\venv\Scripts\activate

# Install dependencies
pip install matplotlib numpy

# Verify installation
python -c "import matplotlib, numpy; print('Dependencies installed successfully')"

# Deactivate when done
deactivate
```

### Available Chart Types

1. **Latency Distribution** - Histogram showing response time distribution
2. **RPS Over Time** - Line chart showing throughput over test duration
3. **Response Codes** - Pie and bar charts showing HTTP response code distribution
4. **Summary Dashboard** - Combined view with all key metrics

### Generate Charts

```bash
# Generate all charts for latest results
make perf-generate-charts

# Generate charts for specific test run
./test/performance/scripts/generate-charts.py results/http-throughput_20240101_120000/

# Generate specific chart types
./test/performance/scripts/generate-charts.py results/latest/ --latency --rps

# Generate charts in different formats
./test/performance/scripts/generate-charts.py results/latest/ --format=svg
./test/performance/scripts/generate-charts.py results/latest/ --format=both

# Compare two test runs
./test/performance/scripts/generate-charts.py --compare results/run1/ results/run2/
```

### Chart Output

Charts are saved to `results/<test-name>/charts/` directory:
- `latency_distribution.png` - Response time histogram with percentile lines
- `rps_over_time.png` - Throughput timeline with average/max indicators
- `response_codes.png` - HTTP status code distribution
- `summary_dashboard.png` - Comprehensive dashboard with all metrics

### Chart Features

- **Dynamic scaling** based on data range
- **Color coding** for different latency ranges and response codes
- **Statistical annotations** (percentiles, averages, totals)
- **High-resolution output** (150 DPI) suitable for reports
- **Multiple formats** (PNG, SVG) for different use cases

## Results Format

All performance tests output results in a standardized JSON format for consistency and analysis.

### JSON Output Structure

```json
{
  "test_info": {
    "name": "http-throughput",
    "duration": "6m",
    "timestamp": "2024-01-01T12:00:00Z",
    "tool": "yandex-tank|ghz|k6"
  },
  "summary": {
    "total_requests": 360000,
    "duration_seconds": 360,
    "max_rps": 1000.5,
    "avg_rps": 995.2,
    "error_rate": 0.01
  },
  "latency": {
    "avg_ms": 45.2,
    "min_ms": 1.2,
    "max_ms": 2500.0,
    "p50_ms": 42.1,
    "p90_ms": 78.5,
    "p95_ms": 95.2,
    "p99_ms": 150.8
  },
  "errors": {
    "total": 36,
    "rate": 0.01,
    "by_code": {
      "500": 20,
      "502": 10,
      "timeout": 6
    }
  },
  "protocol_specific": {
    // Additional metrics specific to HTTP/gRPC/WebSocket
  }
}
```

### Protocol-Specific Metrics

#### HTTP (Yandex Tank)
```json
{
  "http": {
    "response_codes": {
      "200": 359964,
      "500": 36
    },
    "connection_times": {
      "avg_ms": 2.1,
      "p95_ms": 5.2
    },
    "transfer_rate": {
      "bytes_per_second": 1048576,
      "requests_per_second": 995.2
    }
  }
}
```

#### gRPC (ghz)
```json
{
  "grpc": {
    "status_codes": {
      "OK": 239964,
      "UNAVAILABLE": 36
    },
    "message_size": {
      "avg_bytes": 256,
      "total_bytes": 61430784
    },
    "connections": {
      "total": 10,
      "active": 10
    }
  }
}
```

#### WebSocket (k6)
```json
{
  "websocket": {
    "connections": {
      "established": 5000,
      "failed": 12,
      "success_rate": 0.9976
    },
    "messages": {
      "sent": 50000,
      "received": 49988,
      "lost": 12
    },
    "connection_time": {
      "avg_ms": 125.5,
      "p95_ms": 250.0
    }
  }
}
```

## Test Examples and Usage Patterns

### Running Individual Tests

#### HTTP Tests
```bash
# Quick HTTP throughput test
make perf-test-http

# HTTP POST with custom payload
./test/performance/scripts/run-test.sh http-post

# Load balancing verification
./test/performance/scripts/run-test.sh load-balancing

# Rate limiting stress test
./test/performance/scripts/run-test.sh rate-limiting
```

#### gRPC Tests
```bash
# Unary RPC throughput
make perf-test-grpc-unary

# All streaming tests
make perf-test-grpc-streaming

# Individual streaming tests
./test/performance/scripts/run-grpc-test.sh grpc-server-streaming
./test/performance/scripts/run-grpc-test.sh grpc-client-streaming
./test/performance/scripts/run-grpc-test.sh grpc-bidi-streaming
```

#### WebSocket Tests
```bash
# Connection establishment test
make perf-test-websocket-connection

# Message throughput test
make perf-test-websocket-message

# Concurrent connections test
make perf-test-websocket-concurrent

# All WebSocket tests
make perf-test-websocket
```

#### Kubernetes Tests
```bash
# All K8s tests
make perf-test-k8s

# K8s HTTP performance test
make perf-test-k8s-http

# K8s gRPC performance test
make perf-test-k8s-grpc
```

### Running Test Suites

```bash
# All HTTP tests (takes ~1 hour)
make perf-test-all

# All gRPC tests (takes ~20 minutes)
make perf-test-grpc-all

# All WebSocket tests (takes ~15 minutes)
make perf-test-websocket

# All K8s tests (takes ~10 minutes)
make perf-test-k8s

# Complete test suite (all protocols and environments)
make perf-test-all && make perf-test-grpc-all && make perf-test-websocket && make perf-test-k8s
```

### Custom Test Configurations

#### Modify HTTP Test Parameters
```bash
# Edit test configuration
vim test/performance/configs/http-throughput.yaml

# Change load profile
schedule: line(1, 500, 30s) const(500, 2m) line(500, 1, 30s)

# Run with custom config
./test/performance/scripts/run-test.sh http-throughput
```

#### Modify gRPC Test Parameters
```bash
# Edit gRPC configuration
vim test/performance/configs/grpc/grpc-unary.yaml

# Change concurrency and RPS
load:
  concurrency: 100
  rps: 2000
  duration: "5m"

# Run with custom config
./test/performance/scripts/run-grpc-test.sh grpc-unary
```

#### Modify WebSocket Test Parameters
```bash
# Edit WebSocket test
vim test/performance/configs/websocket/websocket-connection.js

# Change VU ramping profile
stages: [
  { duration: '1m', target: 100 },
  { duration: '3m', target: 200 },
  { duration: '1m', target: 0 },
]

# Run with custom config
./test/performance/scripts/run-websocket-test.sh websocket-connection
```

### Environment Variables

#### HTTP Tests (Yandex Tank)
```bash
# Gateway address
export GATEWAY_HOST=127.0.0.1
export GATEWAY_PORT=8080

# Test duration override
export TEST_DURATION=300  # seconds

# Custom ammo file
export AMMO_FILE=/path/to/custom-ammo.txt
```

#### gRPC Tests (ghz)
```bash
# gRPC target
export GRPC_HOST=127.0.0.1
export GRPC_PORT=9000

# Authentication
export GRPC_TOKEN=your-auth-token

# Custom proto files
export PROTO_PATH=/path/to/protos
```

#### WebSocket Tests (k6)
```bash
# WebSocket URL
export WS_URL=ws://127.0.0.1:8080/ws

# Test parameters
export WS_VUS=100
export WS_DURATION=5m

# Authentication
export WS_TOKEN=your-auth-token
```

### Continuous Testing

#### Automated Test Runs
```bash
#!/bin/bash
# continuous-perf-test.sh

# Run tests every hour
while true; do
    echo "Starting performance test run at $(date)"
    
    # Run core tests
    make perf-test-http
    make perf-test-grpc-unary
    make perf-test-websocket-connection
    
    # Generate charts
    make perf-generate-charts
    
    # Wait 1 hour
    sleep 3600
done
```

#### Performance Regression Detection
```bash
#!/bin/bash
# regression-test.sh

# Run baseline test
make perf-test-http
BASELINE_DIR=$(ls -td results/http-throughput_* | head -1)

# Wait for code changes...
sleep 300

# Run comparison test
make perf-test-http
CURRENT_DIR=$(ls -td results/http-throughput_* | head -1)

# Generate comparison
./test/performance/scripts/generate-charts.py --compare "$BASELINE_DIR" "$CURRENT_DIR"
```

## Using Docker Compose

You can also run tests using Docker Compose:

```bash
cd test/performance

# Run default throughput test
docker-compose up yandex-tank

# Run specific test profiles
docker-compose --profile http-post up
docker-compose --profile load-balancing up
docker-compose --profile rate-limiting up
docker-compose --profile circuit-breaker up
docker-compose --profile mixed-workload up
```

## Ammo Files

### URI-Style Ammo (GET requests)

```
[Host: localhost]
[User-Agent: YandexTank/Perftest]
[Accept: application/json]
/health
/api/v1/items
/api/v1/users/1
```

### Request-Style Ammo (POST requests)

```
<content-length> <uri>
<headers>

<body>
```

Example:
```
156 /api/v1/items
Host: localhost
Content-Type: application/json

{"name":"Test Item","price":99.99}
```

### Generate Custom Ammo

```bash
# Generate GET ammo
./test/performance/scripts/generate-ammo.sh get --count=1000

# Generate POST ammo
./test/performance/scripts/generate-ammo.sh post --count=500

# Generate mixed ammo
./test/performance/scripts/generate-ammo.sh mixed --count=2000
```

## Configuration Reference

### Load Profiles

```yaml
phantom:
  load_profile:
    load_type: rps
    schedule: line(1, 1000, 2m)  # Linear ramp from 1 to 1000 RPS over 2 minutes
```

Available schedule types:
- `const(rps, duration)` - Constant load
- `line(start, end, duration)` - Linear ramp
- `step(start, end, step, duration)` - Step function

### Autostop Conditions

```yaml
autostop:
  autostop:
    - http(5xx,5%,10s)      # Stop if 5xx errors exceed 5% for 10s
    - time(500ms,50%,30s)   # Stop if 50% of requests exceed 500ms for 30s
    - net(1%,10s)           # Stop if network errors exceed 1% for 10s
```

### Connection Settings

```yaml
phantom:
  instances: 1000           # Max concurrent connections
  threads: 4                # Number of threads
  timeout: 10s              # Request timeout
  connection_test: true     # Test connection before load
```

## Analyzing Results

### Quick Summary

```bash
./test/performance/scripts/analyze-results.sh results/http-throughput_*/ --summary
```

### Detailed Analysis

```bash
./test/performance/scripts/analyze-results.sh results/http-throughput_*/ --detailed
```

### Export Results

```bash
# Export as JSON
./test/performance/scripts/analyze-results.sh results/http-throughput_*/ --export=json

# Export as CSV
./test/performance/scripts/analyze-results.sh results/http-throughput_*/ --export=csv
```

### Compare Test Runs

```bash
./test/performance/scripts/analyze-results.sh results/run1/ --compare=results/run2/
```

## Makefile Targets

### Infrastructure Setup
- `make perf-setup-infra` - Setup both Vault and Keycloak
- `make perf-setup-vault` - Setup Vault only
- `make perf-setup-vault-k8s` - Setup Vault Kubernetes auth
- `make perf-setup-keycloak` - Setup Keycloak only
- `make perf-verify-infra` - Verify infrastructure setup
- `make perf-verify-vault-k8s` - Verify Vault K8s auth setup

### HTTP Tests (Yandex Tank)
- `make perf-test` - Run default HTTP throughput test
- `make perf-test-http` - Run HTTP GET throughput test
- `make perf-test-post` - Run HTTP POST test
- `make perf-test-mixed` - Run mixed workload test
- `make perf-test-load-balancing` - Run load balancing test
- `make perf-test-rate-limiting` - Run rate limiting test
- `make perf-test-circuit-breaker` - Run circuit breaker test
- `make perf-test-all` - Run all HTTP tests sequentially

### gRPC Tests (ghz)
- `make perf-test-grpc-unary` - Run gRPC unary RPC test
- `make perf-test-grpc-streaming` - Run all gRPC streaming tests
- `make perf-test-grpc-all` - Run all gRPC tests

### WebSocket Tests (k6)
- `make perf-test-websocket` - Run all WebSocket tests
- `make perf-test-websocket-connection` - Run connection test
- `make perf-test-websocket-message` - Run message test
- `make perf-test-websocket-concurrent` - Run concurrent test

### Kubernetes Tests
- `make perf-test-k8s` - Run all K8s performance tests
- `make perf-test-k8s-http` - Run K8s HTTP performance test
- `make perf-test-k8s-grpc` - Run K8s gRPC performance test

### Utilities
- `make perf-generate-charts` - Generate charts from results
- `make perf-generate-ammo` - Generate ammo files
- `make perf-analyze` - Analyze latest results
- `make perf-start-gateway` - Start gateway for testing
- `make perf-stop-gateway` - Stop test gateway
- `make perf-clean` - Clean test results

## Understanding Results

### Key Metrics by Protocol

#### HTTP Metrics
| Metric | Description | Target |
|--------|-------------|--------|
| Total Requests | Number of HTTP requests sent | - |
| Max RPS | Peak requests per second achieved | > 800 |
| Avg RPS | Average requests per second | > 750 |
| Error Rate | Percentage of failed requests | < 1% |
| Avg Latency | Average response time | < 100ms |
| P50 Latency | Median response time | < 50ms |
| P95 Latency | 95th percentile response time | < 200ms |
| P99 Latency | 99th percentile response time | < 500ms |

#### gRPC Metrics
| Metric | Description | Target |
|--------|-------------|--------|
| Total Calls | Number of gRPC calls made | - |
| Max RPS | Peak calls per second | > 500 |
| Avg Latency | Average call latency | < 50ms |
| P95 Latency | 95th percentile latency | < 100ms |
| Error Rate | Percentage of failed calls | < 0.5% |
| Messages/sec | For streaming: messages per second | > 1000 |

#### WebSocket Metrics
| Metric | Description | Target |
|--------|-------------|--------|
| Connections | Total connections established | - |
| Connection Success Rate | Successful connection percentage | > 99% |
| Connection Time | Time to establish connection | < 500ms |
| Messages/sec | Message throughput | > 500 |
| Message Loss Rate | Percentage of lost messages | < 0.1% |

### Result Files

#### HTTP Tests (Yandex Tank)
- `results/<test>_<timestamp>/`
  - `results.json` - Parsed test results
  - `logs/*/phout*.log` - Raw request/response data
  - `charts/` - Generated visualization charts
  - `load.yaml` - Test configuration used

#### gRPC Tests (ghz)
- `results/grpc-<test>_<timestamp>/`
  - `results.json` - ghz output in JSON format
  - `charts/` - Generated charts (if applicable)

#### WebSocket Tests (k6)
- `results/websocket-<test>_<timestamp>/`
  - `results.json` - k6 output in JSON format
  - `charts/` - Generated charts (if applicable)

### Raw Data Formats

#### Yandex Tank phout.txt Format
```
timestamp tag interval_real connect_time send_time latency receive_time interval_event size_out size_in net_code proto_code
```

#### ghz JSON Output
```json
{
  "count": 10000,
  "total": "30.5s",
  "average": "45.2ms",
  "fastest": "1.2ms",
  "slowest": "500ms",
  "rps": 327.8,
  "errorDistribution": {...},
  "statusCodeDistribution": {...}
}
```

#### k6 JSON Output
```json
{
  "metrics": {
    "http_req_duration": {"avg": 45.2, "p95": 95.0},
    "http_reqs": {"count": 10000, "rate": 166.7},
    "ws_connection_time": {"avg": 125.5, "p95": 250.0}
  }
}
```

## Best Practices

### Before Testing

1. **Warm up the gateway** - Run a brief warmup test before measuring
2. **Check backend health** - Ensure all backends are responding
3. **Monitor resources** - Watch CPU, memory, and network on gateway and backends
4. **Disable debug logging** - Use `warn` or `error` log level

### During Testing

1. **Don't run other workloads** - Isolate the test environment
2. **Monitor for errors** - Watch for autostop triggers
3. **Check gateway metrics** - Monitor `/metrics` endpoint

### After Testing

1. **Analyze results** - Use the analysis script
2. **Compare with baseline** - Track performance over time
3. **Document findings** - Record any anomalies or insights

## Troubleshooting

### Gateway Not Responding

```bash
# Check if gateway is running
curl http://127.0.0.1:8080/health

# Check gateway logs
cat test/performance/results/gateway.log

# Restart gateway
./test/performance/scripts/start-gateway.sh --stop
./test/performance/scripts/start-gateway.sh
```

### Docker Network Issues

On macOS/Windows, use `host.docker.internal` to access host services:

```yaml
# Yandex Tank
phantom:
  address: host.docker.internal:8080

# ghz
target:
  host: "host.docker.internal"
  port: 9000

# k6
const WS_URL = 'ws://host.docker.internal:8080/ws';
```

On Linux, you may need to use the host's IP or `--network=host`:

```bash
# Use host networking
docker run --network=host direvius/yandex-tank ...
docker run --network=host ghz/ghz ...
docker run --network=host grafana/k6 ...
```

### Protocol-Specific Issues

#### HTTP Test Issues

**High Error Rate**
1. Check backend availability
2. Reduce load (lower RPS)
3. Increase timeouts
4. Check rate limiting settings

**Slow Performance**
1. Check gateway resource usage
2. Verify backend response times
3. Check network latency
4. Review connection pool settings

#### gRPC Test Issues

**Connection Refused**
```bash
# Check if gRPC port is accessible
telnet 127.0.0.1 9000

# Verify gRPC reflection is enabled
grpcurl -plaintext 127.0.0.1:9000 list

# Check gateway gRPC configuration
grep -A 10 "grpc:" test/performance/configs/gateway-perftest.yaml
```

**Authentication Errors**
```bash
# Check if authentication is required
# Update ghz config with proper metadata/headers
metadata:
  "authorization": "Bearer <token>"
```

#### WebSocket Test Issues

**Connection Failures**
```bash
# Test WebSocket endpoint manually
wscat -c ws://127.0.0.1:8080/ws

# Check WebSocket configuration
curl -H "Upgrade: websocket" -H "Connection: Upgrade" \
     -H "Sec-WebSocket-Key: test" -H "Sec-WebSocket-Version: 13" \
     http://127.0.0.1:8080/ws
```

**Message Loss**
1. Check WebSocket buffer sizes
2. Verify message acknowledgment
3. Monitor connection stability
4. Review gateway WebSocket settings

#### TLS and Authentication Test Issues

**TLS Certificate Problems**
```bash
# Check if TLS certificates are properly configured
openssl s_client -connect 127.0.0.1:8443 -servername localhost

# Verify certificate validity
openssl x509 -in /path/to/cert.pem -text -noout

# Test HTTPS endpoint
curl -k https://127.0.0.1:8443/health
```

**JWT Authentication Failures**
```bash
# Verify JWT token format
echo "your-jwt-token" | cut -d. -f2 | base64 -d | jq .

# Test JWT endpoint manually
curl -H "Authorization: Bearer your-jwt-token" http://127.0.0.1:8080/api/v1/items

# Check Keycloak token endpoint
curl -X POST http://127.0.0.1:8080/auth/realms/test/protocol/openid-connect/token \
  -d "client_id=test-client" \
  -d "username=testuser" \
  -d "password=testpass" \
  -d "grant_type=password"
```

**TLS Performance Issues**
1. Check TLS cipher suite configuration
2. Verify certificate chain length
3. Monitor TLS handshake time
4. Review TLS session reuse settings

**Authentication Performance Issues**
1. Check JWT validation overhead
2. Verify token cache configuration
3. Monitor authentication service response time
4. Review token refresh frequency

### Infrastructure Issues

#### Vault Connection Problems
```bash
# Check Vault status
curl http://127.0.0.1:8200/v1/sys/health

# Verify Vault token
export VAULT_TOKEN=myroot
vault status

# Re-setup Vault
./test/performance/scripts/setup-vault.sh --clean
./test/performance/scripts/setup-vault.sh
```

#### Keycloak Authentication Issues
```bash
# Check Keycloak status
curl http://127.0.0.1:8080/auth/realms/test

# Verify admin access
curl -X POST http://127.0.0.1:8080/auth/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password"

# Re-setup Keycloak
./test/performance/scripts/setup-keycloak.sh --clean
./test/performance/scripts/setup-keycloak.sh
```

### Chart Generation Issues

**Missing Dependencies**
```bash
# Option 1: Install globally
pip install matplotlib numpy

# Option 2: On macOS with Homebrew
brew install python3
pip3 install matplotlib numpy

# Option 3: Using virtual environment (recommended)
python3 -m venv test/performance/venv
source test/performance/venv/bin/activate
pip install matplotlib numpy

# Verify installation
python3 -c "import matplotlib, numpy; print('OK')"
```

**Virtual Environment Issues**
```bash
# If virtual environment activation fails
chmod +x test/performance/venv/bin/activate
source test/performance/venv/bin/activate

# If pip install fails in venv
python -m pip install --upgrade pip
pip install matplotlib numpy

# Reset virtual environment
rm -rf test/performance/venv
python3 -m venv test/performance/venv
source test/performance/venv/bin/activate
pip install matplotlib numpy
```

**Chart Generation Fails**
```bash
# Check if results file exists
ls -la results/*/results.json
ls -la results/*/logs/*/phout*.log

# Generate charts manually
./test/performance/scripts/generate-charts.py results/latest/ --all

# Debug chart generation
python3 -c "
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
print('Matplotlib working')
"
```

### Performance Debugging

**Low Throughput**
1. Check system resources (CPU, memory, network)
2. Verify backend capacity
3. Review gateway configuration
4. Monitor connection pools
5. Check for bottlenecks in the test setup

**High Latency**
1. Check network latency between components
2. Verify backend response times
3. Review gateway processing overhead
4. Monitor garbage collection (if applicable)
5. Check for resource contention

**Memory Issues**
1. Monitor gateway memory usage
2. Check for memory leaks
3. Review connection pool sizes
4. Verify garbage collection settings
5. Monitor Docker container limits

## Integration with CI/CD

While performance tests are not included in GitHub Actions (as per requirements), you can integrate them into your CI/CD pipeline:

```yaml
# Example GitLab CI job
performance_test:
  stage: test
  script:
    - ./test/performance/scripts/start-gateway.sh
    - ./test/performance/scripts/run-test.sh http-throughput
    - ./test/performance/scripts/analyze-results.sh --export=json
  artifacts:
    paths:
      - test/performance/results/
  when: manual
```

## References

### HTTP Testing (Yandex Tank)
- [Yandex Tank Documentation](https://yandextank.readthedocs.io/)
- [Phantom Load Generator](https://yandextank.readthedocs.io/en/latest/tutorial.html#phantom)
- [Load Profiles](https://yandextank.readthedocs.io/en/latest/tutorial.html#load-profile)
- [Autostop Configuration](https://yandextank.readthedocs.io/en/latest/tutorial.html#autostop)

### gRPC Testing (ghz)
- [ghz Documentation](https://ghz.sh/)
- [ghz Configuration](https://ghz.sh/docs/configuration)
- [gRPC Load Testing Best Practices](https://grpc.io/docs/guides/performance/)
- [Protocol Buffers](https://developers.google.com/protocol-buffers)

### WebSocket Testing (k6)
- [k6 Documentation](https://k6.io/docs/)
- [k6 WebSocket API](https://k6.io/docs/javascript-api/k6-ws/)
- [k6 Load Testing Guide](https://k6.io/docs/testing-guides/)
- [WebSocket Performance Testing](https://k6.io/docs/examples/websockets/)

### Chart Generation
- [matplotlib Documentation](https://matplotlib.org/stable/contents.html)
- [NumPy Documentation](https://numpy.org/doc/stable/)
- [Python Performance Visualization](https://matplotlib.org/stable/gallery/index.html)

### Infrastructure
- [Vault API Documentation](https://www.vaultproject.io/api-docs)
- [Keycloak Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/)
- [Docker Networking](https://docs.docker.com/network/)

### Performance Testing Best Practices
- [Load Testing Best Practices](https://k6.io/docs/testing-guides/load-testing-best-practices/)
- [API Gateway Performance](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html)
- [gRPC Performance Best Practices](https://grpc.io/docs/guides/performance/)
- [WebSocket Performance Optimization](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers)
