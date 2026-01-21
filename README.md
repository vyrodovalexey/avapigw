# Ava API Gateway

[![CI](https://github.com/vyrodovalexey/avapigw/actions/workflows/ci.yml/badge.svg)](https://github.com/vyrodovalexey/avapigw/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/vyrodovalexey/avapigw)](https://goreportcard.com/report/github.com/vyrodovalexey/avapigw)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/go-1.24+-blue.svg)](https://golang.org/dl/)

A high-performance, production-ready API Gateway built with Go and gin-gonic. Designed for cloud-native environments with comprehensive traffic management, observability, and reliability features.

## 🚀 Features

### Core Gateway Features
- **Declarative YAML Configuration** - Kubernetes-style configuration with hot-reload support
- **JSON Schema Validation** - Comprehensive configuration validation
- **HTTP Routing** - Support for exact, prefix, regex, and wildcard path matching
- **Method & Header Matching** - Advanced request matching capabilities
- **Query Parameter Matching** - Route based on query parameters
- **Path Parameters** - Extract and use path parameters in routing

### Traffic Management
- **Load Balancing** - Round-robin and weighted load balancing algorithms
- **Backend Health Checking** - Automatic health monitoring with configurable thresholds
- **Rate Limiting** - Token bucket rate limiting with per-client support
- **Circuit Breaker** - Automatic failure detection and recovery
- **Retry Policies** - Exponential backoff with configurable retry conditions
- **Timeouts** - Request and per-try timeout configuration
- **Traffic Mirroring** - Mirror traffic to multiple backends for testing
- **Fault Injection** - Inject delays and errors for chaos engineering

### Request/Response Processing
- **URL Rewriting** - Modify request paths before forwarding
- **HTTP Redirects** - Return redirect responses
- **Direct Responses** - Return static responses without backend calls
- **Header Manipulation** - Add, modify, or remove request/response headers
- **CORS Support** - Comprehensive Cross-Origin Resource Sharing configuration

### Observability
- **Prometheus Metrics** - Comprehensive metrics collection
- **OpenTelemetry Tracing** - Distributed tracing support
- **Structured Logging** - JSON and console logging formats
- **Health Endpoints** - Health, readiness, and liveness probes
- **Access Logs** - Detailed request/response logging

### Operations
- **Hot Configuration Reload** - Update configuration without restart
- **Graceful Shutdown** - Clean shutdown with connection draining
- **Docker Support** - Production-ready container images
- **Multi-platform Builds** - Support for Linux, macOS, and Windows

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [API Endpoints](#-api-endpoints)
- [Routing](#-routing)
- [Traffic Management](#-traffic-management)
- [Observability](#-observability)
- [Development](#-development)
- [Docker](#-docker)
- [CI/CD](#-cicd)
- [Contributing](#-contributing)
- [License](#-license)

## 🏃 Quick Start

### Prerequisites
- Go 1.24+ (for building from source)
- Docker (for containerized deployment)

### Running with Docker

```bash
# Pull the latest image
docker pull ghcr.io/avapigw/avapigw:latest

# Run with default configuration
docker run -p 8080:8080 -p 9090:9090 ghcr.io/avapigw/avapigw:latest

# Run with custom configuration
docker run -p 8080:8080 -p 9090:9090 \
  -v $(pwd)/configs:/app/configs:ro \
  ghcr.io/avapigw/avapigw:latest
```

### Running from Source

```bash
# Clone the repository
git clone https://github.com/vyrodovalexey/avapigw.git
cd avapigw

# Install dependencies
make deps

# Build and run
make run

# Or run with debug logging
make run-debug
```

The gateway will start on port 8080 (HTTP traffic) and 9090 (metrics/health).

### Test the Gateway

```bash
# Health check
curl http://localhost:9090/health

# Metrics
curl http://localhost:9090/metrics

# Test routing (requires backend services)
curl http://localhost:8080/api/v1/items
```

## 📦 Installation

### From Source

```bash
# Clone repository
git clone https://github.com/vyrodovalexey/avapigw.git
cd avapigw

# Install dependencies
make deps

# Build binary
make build

# Install to system (optional)
sudo cp bin/gateway /usr/local/bin/avapigw
```

### Pre-built Binaries

Download pre-built binaries from the [releases page](https://github.com/vyrodovalexey/avapigw/releases).

### Docker

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/avapigw/avapigw:latest

# Or build locally
make docker-build
```

## ⚙️ Configuration

The gateway uses a declarative YAML configuration format inspired by Kubernetes.

### Basic Configuration Structure

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: my-gateway
  labels:
    app: avapigw
    environment: production
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
      hosts: ["*"]
      bind: 0.0.0.0
  
  routes:
    - name: api-route
      match:
        - uri:
            prefix: /api/v1
          methods: [GET, POST]
      route:
        - destination:
            host: backend.example.com
            port: 8080
  
  backends:
    - name: backend-service
      hosts:
        - address: backend.example.com
          port: 8080
          weight: 1
      healthCheck:
        path: /health
        interval: 10s
        timeout: 5s
```

### Listeners Configuration

Configure network listeners for incoming traffic:

```yaml
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
      hosts: ["*"]           # Host matching
      bind: 0.0.0.0         # Bind address
    
    - name: admin
      port: 9090
      protocol: HTTP
      hosts: ["admin.local"]
      bind: 127.0.0.1       # Admin interface
```

### Routes Configuration

Define routing rules with advanced matching:

```yaml
spec:
  routes:
    # Exact path matching
    - name: health-check
      match:
        - uri:
            exact: /health
          methods: [GET]
      directResponse:
        status: 200
        body: '{"status":"healthy"}'
        headers:
          Content-Type: application/json
    
    # Prefix matching with load balancing
    - name: api-service
      match:
        - uri:
            prefix: /api/v1
          methods: [GET, POST, PUT, DELETE]
          headers:
            - name: Authorization
              present: true
      route:
        - destination:
            host: api-backend-1
            port: 8080
          weight: 70
        - destination:
            host: api-backend-2
            port: 8080
          weight: 30
      timeout: 30s
      retries:
        attempts: 3
        perTryTimeout: 10s
        retryOn: "5xx,reset,connect-failure"
    
    # Regex matching with rewriting
    - name: user-service
      match:
        - uri:
            regex: "^/users/([0-9]+)$"
          methods: [GET]
      rewrite:
        uri: /user/{id}
      route:
        - destination:
            host: user-service
            port: 8080
    
    # Header-based routing
    - name: mobile-api
      match:
        - uri:
            prefix: /api
          headers:
            - name: User-Agent
              regex: "Mobile|Android|iPhone"
      route:
        - destination:
            host: mobile-backend
            port: 8080
```

### Backends Configuration

Configure backend services with health checking:

```yaml
spec:
  backends:
    - name: api-backend
      hosts:
        - address: 10.0.1.10
          port: 8080
          weight: 1
        - address: 10.0.1.11
          port: 8080
          weight: 2
      healthCheck:
        path: /health
        interval: 10s
        timeout: 5s
        healthyThreshold: 2
        unhealthyThreshold: 3
        headers:
          Authorization: "Bearer health-token"
      loadBalancer:
        algorithm: roundRobin  # or weighted
```

### Rate Limiting Configuration

Configure rate limiting with token bucket algorithm:

```yaml
spec:
  rateLimit:
    enabled: true
    requestsPerSecond: 100
    burst: 200
    perClient: true          # Rate limit per client IP
    skipSuccessfulRequests: false
    skipFailedRequests: false
    headers:
      - X-RateLimit-Limit
      - X-RateLimit-Remaining
      - X-RateLimit-Reset
```

### Circuit Breaker Configuration

Configure circuit breaker for fault tolerance:

```yaml
spec:
  circuitBreaker:
    enabled: true
    threshold: 5             # Failure threshold
    timeout: 30s             # Open state timeout
    halfOpenRequests: 3      # Requests in half-open state
    successThreshold: 2      # Success threshold to close
```

### CORS Configuration

Configure Cross-Origin Resource Sharing:

```yaml
spec:
  cors:
    allowOrigins:
      - "https://example.com"
      - "https://*.example.com"
    allowMethods:
      - GET
      - POST
      - PUT
      - DELETE
      - PATCH
      - OPTIONS
    allowHeaders:
      - Content-Type
      - Authorization
      - X-Request-ID
    exposeHeaders:
      - X-Request-ID
      - X-Response-Time
    maxAge: 86400
    allowCredentials: true
```

### Observability Configuration

Configure metrics, tracing, and logging:

```yaml
spec:
  observability:
    metrics:
      enabled: true
      path: /metrics
      port: 9090
    
    tracing:
      enabled: true
      samplingRate: 0.1
      otlpEndpoint: "http://jaeger:14268/api/traces"
      serviceName: avapigw
    
    logging:
      level: info              # debug, info, warn, error
      format: json             # json, console
      accessLog: true
```

### Complete Example Configuration

See [configs/gateway.yaml](configs/gateway.yaml) for a complete example configuration demonstrating all features.

## 🔌 API Endpoints

The gateway exposes several built-in endpoints:

### Health Endpoints

| Endpoint | Description | Response |
|----------|-------------|----------|
| `GET /health` | Overall health status | `{"status":"healthy"}` |
| `GET /ready` | Readiness probe | `{"status":"ready"}` |
| `GET /live` | Liveness probe | `{"status":"alive"}` |

### Metrics Endpoint

| Endpoint | Description | Format |
|----------|-------------|---------|
| `GET /metrics` | Prometheus metrics | Prometheus text format |

### Debug Endpoints

Debug endpoints are available when running with debug logging:

| Endpoint | Description |
|----------|-------------|
| `GET /debug/config` | Current configuration |
| `GET /debug/routes` | Route table |
| `GET /debug/backends` | Backend status |

## 🛣️ Routing

The gateway supports sophisticated routing capabilities:

### Path Matching Types

1. **Exact Match**: Matches the exact path
   ```yaml
   uri:
     exact: /api/v1/users
   ```

2. **Prefix Match**: Matches path prefix
   ```yaml
   uri:
     prefix: /api/v1
   ```

3. **Regex Match**: Matches using regular expressions
   ```yaml
   uri:
     regex: "^/users/([0-9]+)$"
   ```

### Method Matching

Restrict routes to specific HTTP methods:

```yaml
match:
  - uri:
      prefix: /api
    methods: [GET, POST]
```

### Header Matching

Route based on request headers:

```yaml
match:
  - uri:
      prefix: /api
    headers:
      - name: Authorization
        present: true
      - name: Content-Type
        exact: application/json
      - name: User-Agent
        regex: "Chrome|Firefox"
```

### Query Parameter Matching

Route based on query parameters:

```yaml
match:
  - uri:
      prefix: /search
    queryParams:
      - name: version
        exact: "v2"
      - name: format
        regex: "json|xml"
```

### Route Priority

Routes are evaluated in the order they appear in the configuration. More specific routes should be placed before general ones.

### Path Parameters

Extract path parameters for use in backends:

```yaml
match:
  - uri:
      regex: "^/users/([0-9]+)$"
rewrite:
  uri: "/user/{1}"  # Use captured group
```

## 🚦 Traffic Management

### Load Balancing

The gateway supports multiple load balancing algorithms:

#### Round Robin
```yaml
loadBalancer:
  algorithm: roundRobin
```

#### Weighted Round Robin
```yaml
hosts:
  - address: backend1.com
    port: 8080
    weight: 70
  - address: backend2.com
    port: 8080
    weight: 30
loadBalancer:
  algorithm: weighted
```

### Health Checking

Automatic backend health monitoring:

```yaml
healthCheck:
  path: /health
  interval: 10s
  timeout: 5s
  healthyThreshold: 2
  unhealthyThreshold: 3
  expectedStatus: [200, 204]
  headers:
    Authorization: "Bearer token"
```

### Rate Limiting

Token bucket rate limiting with configurable parameters:

```yaml
rateLimit:
  enabled: true
  requestsPerSecond: 100
  burst: 200
  perClient: true
  keyExtractor: "ip"  # ip, header, query
```

### Circuit Breaker

Automatic failure detection and recovery:

```yaml
circuitBreaker:
  enabled: true
  threshold: 5
  timeout: 30s
  halfOpenRequests: 3
  successThreshold: 2
```

### Retry Policies

Configurable retry with exponential backoff:

```yaml
retries:
  attempts: 3
  perTryTimeout: 10s
  retryOn: "5xx,reset,connect-failure,refused-stream"
  backoffStrategy: exponential
  baseInterval: 100ms
  maxInterval: 10s
```

### Traffic Mirroring

Mirror traffic to multiple backends:

```yaml
mirror:
  destination:
    host: test-backend
    port: 8080
  percentage: 10
```

### Fault Injection

Inject faults for chaos engineering:

```yaml
fault:
  delay:
    percentage: 1
    fixedDelay: 5s
  abort:
    percentage: 0.1
    httpStatus: 503
```

## 📊 Observability

### Prometheus Metrics

The gateway exposes comprehensive metrics:

#### Request Metrics
- `gateway_requests_total` - Total HTTP requests
- `gateway_request_duration_seconds` - Request duration histogram
- `gateway_request_size_bytes` - Request size histogram
- `gateway_response_size_bytes` - Response size histogram
- `gateway_active_requests` - Active requests gauge

#### Backend Metrics
- `gateway_backend_health` - Backend health status
- `gateway_backend_requests_total` - Backend request count
- `gateway_backend_request_duration_seconds` - Backend request duration

#### Circuit Breaker Metrics
- `gateway_circuit_breaker_state` - Circuit breaker state
- `gateway_circuit_breaker_requests_total` - Circuit breaker requests

#### Rate Limiting Metrics
- `gateway_rate_limit_hits_total` - Rate limit hits

### OpenTelemetry Tracing

Distributed tracing with OpenTelemetry:

```yaml
observability:
  tracing:
    enabled: true
    samplingRate: 0.1
    otlpEndpoint: "http://jaeger:14268/api/traces"
    serviceName: avapigw
```

### Structured Logging

JSON and console logging formats:

```yaml
observability:
  logging:
    level: info
    format: json
    accessLog: true
```

Log fields include:
- `timestamp` - Request timestamp
- `method` - HTTP method
- `path` - Request path
- `status` - Response status
- `duration` - Request duration
- `size` - Response size
- `user_agent` - User agent
- `remote_addr` - Client IP
- `request_id` - Unique request ID

### Health Probes

Kubernetes-compatible health endpoints:

- `/health` - Overall health
- `/ready` - Readiness probe
- `/live` - Liveness probe

## 🛠️ Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/vyrodovalexey/avapigw.git
cd avapigw

# Install dependencies
make deps

# Install development tools
make tools

# Build
make build
```

### Running Tests

```bash
# Unit tests
make test

# All tests with coverage
make test-coverage

# Functional tests
make test-functional

# Integration tests (requires backends)
make test-integration

# End-to-end tests (requires backends)
make test-e2e

# All tests
make test-all
```

### Code Quality

```bash
# Lint code
make lint

# Format code
make fmt

# Run security scan
make vuln

# All quality checks
make ci
```

### Development Server

```bash
# Run with hot reload (requires air)
make dev

# Run with debug logging
make run-debug
```

### Project Structure

```
avapigw/
├── cmd/gateway/          # Main application entry point
├── internal/             # Internal packages
│   ├── backend/         # Backend management
│   ├── config/          # Configuration handling
│   ├── gateway/         # Core gateway logic
│   ├── health/          # Health checking
│   ├── middleware/      # HTTP middleware
│   ├── observability/   # Metrics, tracing, logging
│   ├── proxy/           # Reverse proxy
│   ├── router/          # Request routing
│   └── util/            # Utilities
├── pkg/                 # Public packages
├── configs/             # Configuration files
├── test/                # Test suites
│   ├── functional/      # Functional tests
│   ├── integration/     # Integration tests
│   ├── e2e/            # End-to-end tests
│   └── helpers/        # Test helpers
└── docs/               # Documentation
```

### Contributing Guidelines

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the full test suite
6. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 🐳 Docker

### Building Docker Image

```bash
# Build with make
make docker-build

# Or build directly
docker build -t avapigw:latest .
```

### Running Container

```bash
# Basic run
docker run -p 8080:8080 -p 9090:9090 avapigw:latest

# With custom configuration
docker run -p 8080:8080 -p 9090:9090 \
  -v $(pwd)/configs:/app/configs:ro \
  avapigw:latest

# With environment variables
docker run -p 8080:8080 -p 9090:9090 \
  -e GATEWAY_LOG_LEVEL=debug \
  -e GATEWAY_LOG_FORMAT=console \
  avapigw:latest
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GATEWAY_CONFIG_PATH` | Configuration file path | `/app/configs/gateway.yaml` |
| `GATEWAY_LOG_LEVEL` | Log level | `info` |
| `GATEWAY_LOG_FORMAT` | Log format | `json` |
| `GATEWAY_PORT` | HTTP port | `8080` |
| `GATEWAY_ENV` | Environment name | `development` |

### Docker Compose

```yaml
version: '3.8'
services:
  gateway:
    image: ghcr.io/avapigw/avapigw:latest
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ./configs:/app/configs:ro
    environment:
      - GATEWAY_LOG_LEVEL=info
      - GATEWAY_ENV=production
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9090/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

## 🔄 CI/CD

### GitHub Actions

The project includes a comprehensive CI/CD pipeline:

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v4
        with:
          go-version: '1.24'
      - run: make ci
  
  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make docker-build
```

### Pipeline Stages

1. **Lint** - Code quality checks
2. **Test** - Unit and functional tests
3. **Security** - Vulnerability scanning
4. **Build** - Multi-platform builds
5. **Docker** - Container image build
6. **Deploy** - Automated deployment (on release)

### Running Integration Tests

Integration tests require backend services:

```bash
# Start test backends
docker run -d -p 8801:8080 --name backend1 nginx
docker run -d -p 8802:8080 --name backend2 nginx

# Run integration tests
make test-integration

# Cleanup
docker stop backend1 backend2
docker rm backend1 backend2
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Run tests: `make test-all`
6. Run quality checks: `make lint`
7. Commit your changes: `git commit -m 'Add amazing feature'`
8. Push to the branch: `git push origin feature/amazing-feature`
9. Open a Pull Request

### Code Style

- Follow Go conventions and best practices
- Use `gofmt` for formatting
- Add comprehensive tests for new features
- Update documentation for user-facing changes
- Keep commits atomic and well-described

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [gin-gonic](https://github.com/gin-gonic/gin) - HTTP web framework
- [Prometheus](https://prometheus.io/) - Monitoring and alerting
- [OpenTelemetry](https://opentelemetry.io/) - Observability framework
- [Go](https://golang.org/) - Programming language

## 📞 Support

- 📖 [Documentation](https://github.com/vyrodovalexey/avapigw/wiki)
- 🐛 [Issue Tracker](https://github.com/vyrodovalexey/avapigw/issues)
- 💬 [Discussions](https://github.com/vyrodovalexey/avapigw/discussions)
- 📧 [Email Support](mailto:support@avapigw.io)

---

**Ava API Gateway** - Built with ❤️ for cloud-native applications