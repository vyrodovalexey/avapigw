# AV API Gateway

[![CI](https://github.com/vyrodovalexey/avapigw/actions/workflows/ci.yml/badge.svg)](https://github.com/vyrodovalexey/avapigw/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/vyrodovalexey/avapigw)](https://goreportcard.com/report/github.com/vyrodovalexey/avapigw)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/go-1.25-blue.svg)](https://golang.org/dl/)

A high-performance, production-ready API Gateway built with Go and gin-gonic. Designed for cloud-native environments with comprehensive traffic management, observability, and reliability features.

## 🚀 Features

### Core Gateway Features
- **Declarative YAML Configuration** - Kubernetes-style configuration with hot-reload support
- **JSON Schema Validation** - Comprehensive configuration validation
- **HTTP Routing** - Support for exact, prefix, regex, and wildcard path matching
- **Method & Header Matching** - Advanced request matching capabilities
- **Query Parameter Matching** - Route based on query parameters
- **Path Parameters** - Extract and use path parameters in routing
- **Native gRPC Support** - Full gRPC over HTTP/2 with dedicated port
- **gRPC Streaming** - Support for unary, server streaming, client streaming, and bidirectional streaming
- **gRPC Routing** - Service and method-based routing with metadata matching
- **gRPC Health Service** - Built-in grpc.health.v1.Health implementation
- **gRPC Reflection** - Optional gRPC reflection service for service discovery
- **gRPC TLS via Vault PKI** - Automated gRPC listener TLS certificates from Vault PKI with optional gRPC-specific overrides
- **Streaming Support** - HTTP Flusher interface support for SSE, WebSocket, and streaming responses
- **WebSocket Proxy** - Full WebSocket proxying with connection management, message routing, and load balancing

### Security & TLS
- **Comprehensive TLS Support** - TLS 1.2/1.3 with multiple modes (SIMPLE, MUTUAL, OPTIONAL_MUTUAL)
- **Certificate Management** - Static and dynamic certificate provisioning with auto-rotation
- **Mutual TLS (mTLS)** - Client certificate authentication and validation
- **HSTS Support** - HTTP Strict Transport Security with configurable policies
- **Cipher Suite Control** - Modern, secure cipher suite configuration
- **ALPN Support** - Application-Layer Protocol Negotiation for HTTP/2 and gRPC
- **HashiCorp Vault Integration** - Dynamic secrets, PKI certificates, and secure credential management
- **Multiple Auth Methods** - Kubernetes, AppRole, Token, AWS, and GCP authentication for Vault
- **Secret Injection** - Dynamic secret injection into configuration and backends
- **Vault PKI Integration** - Automated certificate management for listener, route, and backend TLS
- **Certificate Auto-Renewal** - Automatic certificate renewal with Vault PKI and hot-reload
- **SNI Certificate Management** - Per-route certificates with Vault PKI for multi-tenant deployments
- **Backend Authentication** - JWT, Basic Auth, and mTLS authentication for backend connections
- **X-Forwarded-For Security** - TrustedProxies configuration for secure client IP handling
- **Open Redirect Protection** - Automatic validation and blocking of unsafe redirect URLs (javascript:, data:, vbscript: schemes)

### Authentication & Authorization
- **Global Authentication Middleware** - Applied to all requests in the global middleware chain
- **JWT Authentication** - Multiple algorithms (RS256, ES256, HS256, etc.) with JWK URL support
- **API Key Authentication** - Header/query/metadata extraction with hashing and rate limiting
- **mTLS Authentication** - Client certificate validation with identity extraction
- **OIDC Integration** - Keycloak, Auth0, Okta, Azure AD support with discovery
- **RBAC Authorization** - Role-based access control from JWT claims
- **ABAC Authorization** - Attribute-based with CEL expressions
- **External Authorization** - OPA integration for complex policies
- **Policy Caching** - Configurable TTL for authorization decisions
- **Security Headers** - HSTS, CSP, X-Frame-Options, and more (per-route middleware)
- **Audit Logging** - Comprehensive authentication and authorization logging with stdout as default output
- **gRPC Audit Support** - Built-in audit interceptor for gRPC requests and responses with trace context integration

### Traffic Management
- **Load Balancing** - Round-robin, weighted, least connections, and capacity-aware load balancing algorithms
- **Backend Health Checking** - Automatic health monitoring with configurable thresholds
- **Rate Limiting** - Token bucket rate limiting with per-client support (global, route-level, and backend-level)
- **Max Sessions** - Concurrent connection limiting with queueing support (global, route-level, and backend-level)
- **Circuit Breaker** - Automatic failure detection and recovery (global and backend-level)
- **Retry Policies** - Exponential backoff with configurable retry conditions
- **Timeouts** - Request and per-try timeout configuration
- **Traffic Mirroring** - Mirror traffic to multiple backends for testing
- **Fault Injection** - Inject delays and errors for chaos engineering

### Request/Response Processing
- **URL Rewriting** - Modify request paths before forwarding
- **HTTP Redirects** - Return redirect responses
- **Direct Responses** - Return static responses without backend calls
- **Header Manipulation** - Add, modify, or remove request/response headers
- **CORS Support** - Comprehensive Cross-Origin Resource Sharing configuration (global and route-level)
- **Request Limits** - Configurable request body and header size limits (global and route-level)
- **Security Headers** - Automatic security header injection (global and route-level)

### Data Transformation
- **Per-Route Transform Middleware** - Request/response transformation applied per route
- **Field Filtering** - Filter response fields using allow/deny lists
- **Field Mapping** - Rename and remap response fields
- **Field Grouping** - Group fields into nested objects
- **Field Flattening** - Extract and flatten nested objects
- **Array Operations** - Append, prepend, filter, sort, limit, deduplicate arrays
- **Request Templating** - Use Go templates for custom request transformation
- **Response Templating** - Use Go templates for custom response formatting
- **Response Merging** - Merge responses from multiple backends (deep, shallow, replace strategies)
- **Body Size Limits** - 10MB maximum request/response body size for transformation
- **JSON Optimization** - Optimized JSON request/response transformation
- **gRPC FieldMask** - Filter gRPC responses using Protocol Buffer FieldMask
- **Metadata Transformation** - Transform gRPC metadata (static and dynamic)
- **Streaming Transformation** - Transform streaming messages with rate limiting

### Caching
- **Per-Route Caching** - Isolated cache instances per route with dedicated middleware
- **In-Memory Cache** - Fast local caching with TTL and max entries
- **Redis Cache** - Distributed caching with Redis standalone or Sentinel
- **Redis Sentinel Support** - High availability Redis with automatic failover
- **TTL Jitter** - Random jitter added to TTL values to prevent thundering herd
- **Hash Keys** - SHA256 hashing of cache keys for privacy/length control
- **Vault Password Integration** - Redis passwords resolved from HashiCorp Vault KV secrets
- **Cache Key Generation** - Configurable cache key components
- **Cache Control** - Honor Cache-Control headers (no-store, no-cache)
- **Stale-While-Revalidate** - Serve stale data while revalidating
- **Body Size Limits** - 10MB maximum response body size for caching
- **GET-Only Caching** - Only GET requests are cached by default

### Encoding Support
- **Per-Route Encoding Middleware** - Content negotiation and encoding applied per route
- **JSON** - Full JSON encoding/decoding with configurable options
- **XML** - XML encoding/decoding
- **YAML** - YAML encoding/decoding
- **Content Negotiation** - Automatic content type negotiation based on Accept header
- **Encoding Metrics** - Track negotiation results and content type usage

### Observability
- **Comprehensive Prometheus Metrics** - 130+ metrics across gateway and operator components with route-based labels for cardinality control
- **Core Gateway Metrics** - Request throughput, latency, active connections, build info, and uptime tracking
- **Middleware Metrics** - Rate limiting, circuit breaker, timeout, retry, body limit, max sessions, recovery, and CORS metrics
- **Cache Metrics** - Cache hits, misses, evictions, size, duration, and error tracking for both memory and Redis caches
- **Authentication & Authorization Metrics** - JWT, API Key, OIDC, mTLS, RBAC, ABAC, and external authorization metrics
- **TLS & Security Metrics** - Certificate lifecycle, handshake performance, and security event tracking
- **Backend & Proxy Metrics** - Backend health, proxy errors, duration, and authentication metrics
- **WebSocket Metrics** - Dedicated metrics for WebSocket connections (total, active, errors, message throughput)
- **gRPC Metrics** - Comprehensive gRPC request tracking, streaming metrics, method-level observability, and proxy metrics
- **Operator Metrics** - Controller reconciliation, webhook validation, certificate management, and gRPC communication metrics
- **Config Reload Metrics** - Hot configuration reload success/failure tracking with atomic updates
- **Health Check Metrics** - Backend health monitoring and probe success/failure rates
- **OpenTelemetry Tracing** - Comprehensive distributed tracing with spans for proxy, transform, auth, authz, and circuit breaker operations
- **4 Grafana Dashboards** - Complete monitoring coverage with 100% metrics visualization
- **Production Monitoring Stack** - vmagent and otel-collector integration for enterprise observability
- **Structured Logging** - JSON and console logging formats
- **Health Endpoints** - Health, readiness, and liveness probes
- **Access Logs** - Detailed request/response logging

### Operations
- **Hot Configuration Reload** - Update configuration without restart with atomic config updates and hash-based change detection
- **Graceful Shutdown** - Clean shutdown with connection draining and configurable timeouts
- **Docker Support** - Production-ready container images with security optimizations
- **Kubernetes & Helm** - Production-ready Helm charts with local K8s deployment support via values-local.yaml
- **Multi-platform Builds** - Support for Linux, macOS, and Windows
- **AVAPIGW Operator** - Kubernetes-native configuration management with CRDs and admission webhooks
- **Ingress Controller Mode** - Standard Kubernetes Ingress support with rich annotation processing
- **Certificate Management** - Automated TLS certificate management with Vault PKI integration
- **Memory Leak Prevention** - Robust timer and resource cleanup in configuration watcher
- **Production-Ready Quality** - 94.1% test coverage with 2,986 tests and zero vulnerabilities
- **Performance Validated** - Comprehensive performance testing across deployment scenarios
- **Enterprise Monitoring** - 130+ metrics, 4 Grafana dashboards, and OTEL tracing integration

### Recent Improvements (Latest Release)

#### Metrics Fixes and Middleware Architecture Enhancements
- **Issue 1**: Fixed config reload timestamp metrics - corrected Grafana dashboard query for millisecond compatibility
- **Issue 2**: Integrated authentication metrics - wired auth middleware into global HTTP middleware chain with proper config conversion
- **Issue 3**: Implemented cache metrics - added per-route cache middleware with 10MB body limit, GET-only caching, and Cache-Control support
- **Issue 4**: Added transform/encoding metrics - implemented request/response transformation and content negotiation middleware

#### Two-Tier Middleware Architecture
- **Global Middleware Chain**: Recovery → RequestID → Logging → Tracing → Audit → Metrics → CORS → MaxSessions → CircuitBreaker → RateLimit → Auth → [proxy]
- **Per-Route Middleware Chain**: Security Headers → CORS → Body Limit → Headers → Cache → Transform → Encoding → [proxy to backend]
- **RouteMiddlewareApplier Interface**: Decoupled proxy from gateway package to avoid import cycles while enabling per-route middleware
- **Thread-Safe Cache Factory**: Per-route cache instances with lazy initialization and double-check locking

#### Core Reliability and Performance (DEV-001 to DEV-009)
- **DEV-001**: Fixed reload metrics registry mismatch - reload metrics now use custom registry for consistency
- **DEV-002**: Optimized config change detection with hash-based comparison for efficient hot-reload
- **DEV-003**: Fixed gRPC proxy context timeout on unmatched routes to prevent resource leaks
- **DEV-004**: Added security headers to metrics server endpoint for enhanced security posture
- **DEV-005**: Added missing gRPC proxy metrics (request/response sizes, stream messages, backend selections, timeouts)
- **DEV-006**: Added OTEL tracing spans for transform operations with comprehensive span attributes
- **DEV-007**: Added OTEL tracing spans for auth/authz decisions with detailed context propagation
- **DEV-008**: Added OTEL span events for circuit breaker state changes for better observability
- **DEV-009**: Fixed audit metrics to use custom registry for consistent metric collection

#### Comprehensive Test Coverage and Quality Assurance
- **Unit Test Coverage**: 94.1% across all 41 packages (all packages ≥90% coverage)
- **Functional Tests**: 1,843 tests passed with comprehensive scenario coverage
- **Integration Tests**: 671 tests run (667 passed, 4 expected skips for environment-specific features)
- **E2E Tests**: 472 tests run (454 passed, 18 expected skips for WIP features)
- **Total Test Suite**: 2,986 tests with 100% pass rate for production readiness
- **Zero Vulnerabilities**: Complete security scan with no identified vulnerabilities
- **Lint Clean**: Zero linting issues across the entire codebase

#### Performance Validation
- **Local Performance**: HTTP 763 RPS, gRPC 12,353 RPS with excellent latency characteristics
- **Kubernetes Config-based**: HTTP 763 RPS, gRPC 2,594 RPS with CRD management overhead
- **Kubernetes CRD-based**: HTTP 763 RPS, gRPC 2,816 RPS with operator integration
- **Kubernetes Ingress**: HTTP 763 RPS, gRPC 3,367 RPS with best P99 latency performance

#### Enhanced Observability
- **130+ Prometheus Metrics**: Comprehensive metrics across gateway and operator components
- **4 Grafana Dashboards**: Complete monitoring coverage with 100% metrics visualization
- **OTEL Tracing**: Distributed tracing with spans for proxy, transform, auth, authz, circuit breaker operations
- **Production Monitoring**: vmagent and otel-collector deployed in Kubernetes for enterprise observability

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [TLS & Transport Security](#-tls--transport-security)
- [Vault Integration](#-vault-integration)
- [Vault PKI Integration](#-vault-pki-integration)
- [Authentication](#-authentication)
- [Authorization](#-authorization)
- [Data Transformation](#-data-transformation)
- [API Endpoints](#-api-endpoints)
- [Routing](#-routing)
- [gRPC Gateway](#-grpc-gateway)
- [Traffic Management](#-traffic-management)
- [Observability](#-observability)
- [Middleware Architecture](#-middleware-architecture)
- [Performance](#-performance)
- [Development](#-development)
- [Kubernetes & Helm](#️-kubernetes--helm)
- [AVAPIGW Operator](#️-avapigw-operator)
- [Ingress Controller](#-ingress-controller)
- [Docker](#-docker)
- [CI/CD](#-cicd)
- [Performance Testing](#-performance-testing)
- [Contributing](#-contributing)
- [License](#-license)

## 🏃 Quick Start

### Prerequisites
- Go 1.25.7 (for building from source)
- Docker (for containerized deployment)
- Kubernetes 1.23+ (for operator deployment)
- Helm 3.0+ (for Kubernetes deployment)
- HashiCorp Vault (optional, for TLS certificate management)
- Keycloak (optional, for OIDC authentication)

### Running with Docker

```bash
# Pull the latest image
docker pull ghcr.io/vyrodovalexey/avapigw:latest

# Run with default configuration (HTTP + gRPC + metrics)
docker run -p 8080:8080 -p 9000:9000 -p 9090:9090 ghcr.io/vyrodovalexey/avapigw:latest

# Run with TLS support (HTTPS + gRPC TLS + metrics)
docker run -p 8080:8080 -p 8443:8443 -p 9000:9000 -p 9443:9443 -p 9090:9090 \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/certs:/app/certs:ro \
  ghcr.io/vyrodovalexey/avapigw:latest

# Run with custom configuration
docker run -p 8080:8080 -p 9000:9000 -p 9090:9090 \
  -v $(pwd)/configs:/app/configs:ro \
  ghcr.io/vyrodovalexey/avapigw:latest
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

The gateway will start on port 8080 (HTTP traffic) and 9090 (metrics/health). gRPC traffic on port 9000 is optional and can be enabled in the configuration. When TLS is enabled, HTTPS traffic uses port 8443 and gRPC TLS traffic uses port 9443.

### Test the Gateway

```bash
# Health check
curl http://localhost:9090/health

# Metrics
curl http://localhost:9090/metrics

# Test HTTP routing (requires backend services)
curl http://localhost:8080/api/v1/items

# Test gRPC endpoint (requires grpcurl)
grpcurl -plaintext localhost:9000 list

# Check gRPC health
grpcurl -plaintext localhost:9000 grpc.health.v1.Health/Check

# Test gRPC TLS endpoint (if TLS is enabled)
grpcurl -insecure localhost:9443 list

# Test HTTPS endpoint (if TLS is enabled)
curl -k https://localhost:8443/health
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
docker pull ghcr.io/vyrodovalexey/avapigw:latest

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
    - name: grpc
      port: 9000
      protocol: GRPC
      grpc:
        maxConcurrentStreams: 100
        reflection: true
        healthCheck: true
  
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
    
    - name: grpc
      port: 9000
      protocol: GRPC
      grpc:
        maxConcurrentStreams: 100
        maxRecvMsgSize: 4194304    # 4MB
        maxSendMsgSize: 4194304    # 4MB
        keepalive:
          time: 30s
          timeout: 10s
          permitWithoutStream: false
        reflection: true
        healthCheck: true
    
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
     
     # Route with custom request limits, CORS, and security headers
     - name: api-route-with-overrides
       match:
         - uri:
             prefix: /api/v1/upload
           methods: [POST]
       route:
         - destination:
             host: upload-backend
             port: 8080
       # Route-level request limits (overrides global)
       requestLimits:
         maxBodySize: 52428800    # 50MB for file uploads
         maxHeaderSize: 1048576   # 1MB for headers
       # Route-level CORS (overrides global)
       cors:
         allowOrigins: ["https://app.example.com", "https://admin.example.com"]
         allowMethods: ["POST", "OPTIONS"]
         allowHeaders: ["Content-Type", "Authorization", "X-Upload-Token"]
         maxAge: 3600
         allowCredentials: true
      # Route-level security headers (overrides global)
      security:
        enabled: true
        headers:
          enabled: true
          xFrameOptions: "SAMEORIGIN"
          customHeaders:
            X-Upload-Policy: "strict"
      # Route-level max sessions (overrides global)
      maxSessions:
        enabled: true
        maxConcurrent: 1000
        queueSize: 100
        queueTimeout: 10s
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
          algorithm: roundRobin  # or weighted, leastConn, random
        # Backend-level max sessions
        maxSessions:
          enabled: true
          maxConcurrent: 500
        # Backend-level rate limiting
        rateLimit:
          enabled: true
          requestsPerSecond: 100
          burst: 200
     
     # Backend with circuit breaker and JWT authentication
     - name: secure-api-backend
       hosts:
         - address: secure-api.example.com
           port: 443
           weight: 1
       # Backend-level circuit breaker
       circuitBreaker:
         enabled: true
         threshold: 5
         timeout: 30s
         halfOpenRequests: 3
       # Backend authentication with JWT from OIDC
       authentication:
         type: jwt
         jwt:
           enabled: true
           tokenSource: oidc
           oidc:
             issuerUrl: https://keycloak.example.com/realms/myrealm
             clientId: gateway-client
             clientSecret: secret-key
             scopes: ["openid", "profile"]
           headerName: Authorization
           headerPrefix: Bearer
       # TLS configuration for backend
       tls:
         enabled: true
         mode: SIMPLE
         caFile: /etc/ssl/certs/ca.crt
         serverName: secure-api.example.com
     
     # Backend with Basic authentication from Vault
     - name: legacy-backend
       hosts:
         - address: legacy.internal.com
           port: 8080
           weight: 1
       # Backend authentication with Basic auth from Vault
       authentication:
         type: basic
         basic:
           enabled: true
           vaultPath: secret/legacy-backend
           usernameKey: username
           passwordKey: password
     
     # Backend with mTLS authentication
     - name: mtls-backend
       hosts:
         - address: mtls.example.com
           port: 443
           weight: 1
       # Backend authentication with mTLS
       authentication:
         type: mtls
         mtls:
           enabled: true
           certFile: /etc/ssl/certs/client.crt
           keyFile: /etc/ssl/private/client.key
           caFile: /etc/ssl/certs/backend-ca.crt
        # TLS configuration for mTLS
        tls:
          enabled: true
          mode: MUTUAL
          caFile: /etc/ssl/certs/backend-ca.crt
          certFile: /etc/ssl/certs/client.crt
          keyFile: /etc/ssl/private/client.key
      
      # Backend with max sessions and rate limiting
      - name: high-traffic-backend
        hosts:
          - address: 10.0.1.20
            port: 8080
          - address: 10.0.1.21
            port: 8080
        # Backend-level max sessions
        maxSessions:
          enabled: true
          maxConcurrent: 500
        # Backend-level rate limiting
        rateLimit:
          enabled: true
          requestsPerSecond: 100
          burst: 200
        # Capacity-aware load balancing
        loadBalancer:
          algorithm: leastConn
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

### Max Sessions Configuration

Configure concurrent connection limiting with queueing support:

```yaml
spec:
  maxSessions:
    enabled: true
    maxConcurrent: 10000     # Maximum concurrent connections
    queueSize: 1000          # Queue size for waiting connections
    queueTimeout: 30s        # Timeout for queued connections
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
      
      # OTLP TLS Configuration (DEV-003)
      otlpInsecure: false              # Use secure gRPC connection (default: true for backward compatibility)
      otlpTLSCertFile: "/certs/client.crt"  # Client certificate for mTLS
      otlpTLSKeyFile: "/certs/client.key"   # Client private key for mTLS
      otlpTLSCAFile: "/certs/ca.crt"        # CA certificate for server verification
    
    logging:
      level: info              # debug, info, warn, error
      format: json             # json, console
      accessLog: true
```

### Comprehensive Metrics Collection

The gateway provides 130+ Prometheus metrics across all components for comprehensive observability:

#### Core Gateway Metrics
```bash
# Request metrics with route-based cardinality control
gateway_requests_total{method="GET",route="api-v1",status="200"} 1500
gateway_request_duration_seconds{method="GET",route="api-v1",status="200"} 0.002
gateway_active_requests{method="GET",route="api-v1"} 25
gateway_build_info{version="v1.0.0",commit="abc123",build_time="2026-02-14"} 1
gateway_start_time_seconds 1708000000
```

#### Middleware Metrics
```bash
# Rate limiting and circuit breaker metrics
gateway_middleware_rate_limit_allowed_total{route="api-v1"} 1450
gateway_middleware_rate_limit_rejected_total{route="api-v1"} 50
gateway_middleware_circuit_breaker_requests_total{name="backend-1",state="closed"} 1200
gateway_middleware_circuit_breaker_transitions_total{name="backend-1",from="closed",to="open"} 1
gateway_middleware_request_timeouts_total{route="api-v1"} 5
gateway_middleware_retry_attempts_total{route="api-v1"} 25
gateway_middleware_max_sessions_current 150
gateway_middleware_panics_recovered_total 0
gateway_middleware_cors_requests_total{type="preflight"} 100
```

#### Cache Metrics
```bash
# Cache performance metrics for memory and Redis
gateway_cache_hits_total{backend="api-backend",cache_type="memory"} 850
gateway_cache_misses_total{backend="api-backend",cache_type="memory"} 150
gateway_cache_evictions_total{backend="api-backend",cache_type="memory"} 25
gateway_cache_size_bytes{backend="api-backend",cache_type="memory"} 1048576
gateway_cache_operation_duration_seconds{backend="api-backend",operation="get"} 0.001
gateway_cache_errors_total{backend="api-backend",error_type="connection_failed"} 2
```

#### WebSocket Metrics
```bash
# WebSocket connection and message metrics
gateway_websocket_connections_total{backend="websocket-backend"} 150
gateway_websocket_connections_active{backend="websocket-backend"} 25
gateway_websocket_errors_total{backend="websocket-backend",error_type="connection_failed"} 3
gateway_websocket_message_rate{backend="websocket-backend"} 1000
```

#### Authentication & Authorization Metrics
```bash
# Auth metrics across all providers
gateway_auth_requests_total{provider="jwt",status="success"} 1200
gateway_auth_requests_total{provider="apikey",status="failed"} 15
gateway_authz_requests_total{provider="rbac",status="allowed"} 1100
gateway_authz_requests_total{provider="abac",status="denied"} 50
gateway_auth_oidc_token_requests_total{provider="keycloak",status="success"} 800
gateway_auth_mtls_verifications_total{status="success"} 300
```

#### Operator Metrics
```bash
# Operator controller and webhook metrics
avapigw_operator_reconcile_total{controller="apiroute",result="success"} 42
avapigw_operator_webhook_requests_total{webhook="apiroute",status="allowed"} 100
avapigw_operator_cert_renewals_total{mode="vault",status="success"} 5
avapigw_operator_config_push_total{status="success"} 156
```

Query all metrics:
```bash
curl http://localhost:9090/metrics | grep -E "(gateway_|avapigw_)"
```

These metrics provide comprehensive observability across all gateway components, enabling detailed monitoring, alerting, and performance analysis.

## 🔧 Middleware Architecture

The AV API Gateway implements a sophisticated two-tier middleware architecture that provides both global and per-route middleware capabilities.

### Two-Tier Middleware System

#### Global Middleware Chain
Applied to all requests in the following order:
```
Recovery → RequestID → Logging → Tracing → Audit → Metrics → 
CORS → MaxSessions → CircuitBreaker → RateLimit → Auth → [proxy]
```

#### Per-Route Middleware Chain
Applied to specific routes based on configuration:
```
Security Headers → CORS → Body Limit → Headers → Cache → 
Transform → Encoding → [proxy to backend]
```

### Key Architectural Features

- **Import Cycle Avoidance** - RouteMiddlewareApplier interface pattern decouples proxy from gateway package
- **Thread-Safe Caching** - Middleware chains cached with double-check locking for performance
- **Per-Route Isolation** - Each route gets its own cache namespace and middleware configuration
- **Graceful Degradation** - Middleware failures don't crash requests, they pass through
- **Comprehensive Metrics** - All middleware operations tracked with Prometheus metrics

### Middleware Components

#### Cache Middleware (`internal/middleware/cache.go`)
- **10MB Body Limit** - Maximum response body size for caching
- **GET-Only Caching** - Only GET requests are cached by default
- **Cache-Control Support** - Respects `no-store` and `no-cache` directives
- **Per-Route Cache Factory** - Thread-safe lazy cache creation per route

#### Transform Middleware (`internal/middleware/transform.go`)
- **10MB Body Limit** - Maximum request/response body size for transformation
- **Go Templates** - Request transformation using Go template engine
- **Field Operations** - Allow/deny lists and field mappings for responses
- **JSON Optimization** - Optimized for JSON request/response transformation

#### Encoding Middleware (`internal/middleware/encoding.go`)
- **Content Negotiation** - Automatic content type negotiation based on Accept header
- **Format Support** - JSON, XML, YAML encoding support
- **Metrics Recording** - Tracks negotiation results and content types

### Configuration Example

```yaml
spec:
  # Global middleware configuration
  authentication:
    enabled: true
    jwt:
      enabled: true
      issuer: "https://auth.example.com"
  
  routes:
    - name: api-route
      # Per-route middleware configuration
      cache:
        enabled: true
        ttl: "10m"
        type: "memory"
      transform:
        request:
          template: |
            {
              "data": {{.Body}},
              "metadata": {
                "timestamp": "{{.Timestamp}}"
              }
            }
      encoding:
        enableContentNegotiation: true
```

For detailed middleware architecture documentation, see [Middleware Architecture Guide](docs/middleware-architecture.md).

## 🚀 Performance

The AV API Gateway delivers high performance across multiple deployment scenarios with comprehensive testing validation.

### Performance Test Results

The gateway has been extensively validated across multiple deployment scenarios with comprehensive performance testing:

#### Local Gateway Performance
**Configuration:** Gateway with static YAML configuration
- **HTTP Throughput:** 763 RPS sustained
- **gRPC Throughput:** 12,353 RPS sustained
- **Latency Characteristics:** Excellent P95/P99 performance
- **Resource Efficiency:** Minimal CPU and memory overhead

#### Kubernetes Config-based Deployment
**Configuration:** Gateway with file-based configuration in Kubernetes
- **HTTP Throughput:** 763 RPS sustained
- **gRPC Throughput:** 2,594 RPS sustained
- **Configuration Management:** File-based hot-reload support
- **Deployment Overhead:** Minimal impact on performance

#### Kubernetes CRD-based Deployment
**Configuration:** Gateway + Operator with CRD-based configuration management
- **HTTP Throughput:** 763 RPS sustained
- **gRPC Throughput:** 2,816 RPS sustained
- **CRD Reconciliation:** < 100ms for route changes
- **Hot Configuration Updates:** Real-time configuration push via gRPC

#### Kubernetes Ingress Controller Mode
**Configuration:** Gateway + Operator + Ingress Controller with standard Kubernetes Ingress resources
- **HTTP Throughput:** 763 RPS sustained
- **gRPC Throughput:** 3,367 RPS sustained (best performance)
- **P99 Latency:** Best latency characteristics across all deployment modes
- **Ingress Processing:** < 10ms per Ingress resource conversion
- **Annotation Processing:** < 5ms overhead per annotation group

### Performance Characteristics

#### HTTP Performance
- **Maximum Throughput:** 2,000+ RPS sustained (static config)
- **Average Latency:** < 2ms at 1,000 RPS
- **P95 Latency:** < 10ms at 1,000 RPS
- **TLS Overhead:** ~25% throughput reduction, ~2x latency increase
- **Authentication Overhead:** ~10% throughput reduction (JWT), ~5% (API Key)

#### gRPC Performance
- **Unary Calls:** 15,000+ RPS direct, 12,000+ RPS via gateway
- **Streaming:** 1,000+ messages/second per stream
- **Connection Efficiency:** 10+ concurrent streams per connection
- **TLS Overhead:** ~20% throughput reduction

#### WebSocket Performance
- **Connection Rate:** 100+ connections/second
- **Message Rate:** 1,000+ messages/second per connection
- **Concurrent Connections:** 1,000+ simultaneous connections
- **Connection Success Rate:** > 99.5%

#### Resource Efficiency
- **Memory Usage:** < 100MB baseline, scales linearly with connections
- **CPU Usage:** < 5% at 1,000 RPS on modern hardware
- **Network Efficiency:** Minimal overhead with connection pooling
- **Hot Configuration Reload:** Zero-downtime updates in < 100ms

### Performance Testing

Comprehensive performance testing infrastructure supports:
- **HTTP Load Testing:** Yandex Tank with realistic traffic patterns
- **gRPC Load Testing:** ghz with unary and streaming scenarios
- **WebSocket Testing:** k6 with connection and message throughput tests
- **Kubernetes Testing:** Real cluster validation with CRD and Ingress modes

For detailed performance testing procedures, see [Performance Testing Guide](docs/performance-testing.md).

## 🔒 TLS & Transport Security

The AV API Gateway provides comprehensive TLS support for secure communication across all protocols.

### TLS Configuration Levels

The gateway supports TLS configuration at three levels:

1. **Listener-level TLS** - Gateway's own TLS certificates for incoming connections
2. **Route-level TLS** - Per-route certificates for SNI-based multi-tenant scenarios  
3. **Backend TLS** - Client certificates for secure backend connections

### Basic TLS Configuration

```yaml
spec:
  listeners:
    - name: https
      port: 8443
      protocol: HTTPS
      hosts: ["*"]
      tls:
        mode: SIMPLE
        minVersion: "1.2"
        certFile: /app/certs/tls.crt
        keyFile: /app/certs/tls.key
        hsts:
          enabled: true
          maxAge: 31536000
          includeSubDomains: true

    - name: grpc-tls
      port: 9443
      protocol: GRPC
      hosts: ["*"]
      grpc:
        maxConcurrentStreams: 100
        reflection: true
        healthCheck: true
        tls:
          enabled: true
          mode: SIMPLE
          minVersion: "1.3"
          certFile: /app/certs/grpc/tls.crt
          keyFile: /app/certs/grpc/tls.key
```

### Vault PKI Integration

For automated certificate management, the gateway integrates with HashiCorp Vault's PKI secrets engine:

```yaml
spec:
  vault:
    address: "https://vault.example.com:8200"
    authMethod: kubernetes
    role: gateway-role

  listeners:
    - name: https
      port: 8443
      protocol: HTTPS
      tls:
        mode: SIMPLE
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-server
          commonName: gateway.example.com
          altNames:
            - api.example.com
            - "*.api.example.com"
          ttl: 24h
          renewBefore: 1h

    - name: grpc-tls
      port: 9443
      protocol: GRPC
      grpc:
        tls:
          enabled: true
          vault:
            enabled: true
            pkiMount: pki-grpc
            role: grpc-server
            commonName: grpc.example.com
            ttl: 24h
```

### TLS Features

- **Multiple TLS Modes**: SIMPLE, MUTUAL, OPTIONAL_MUTUAL, INSECURE
- **Modern TLS Versions**: TLS 1.2 and 1.3 support with deprecation warnings for older versions
- **Cipher Suite Control**: Configurable cipher suites for security compliance
- **ALPN Support**: Application-Layer Protocol Negotiation for HTTP/2 and gRPC
- **HSTS Support**: HTTP Strict Transport Security with configurable policies
- **Certificate Auto-Renewal**: Automatic certificate renewal with Vault PKI
- **SNI Certificate Management**: Per-route certificates for multi-tenant deployments
- **Hot Certificate Reload**: Certificate updates without service restart

### Mutual TLS (mTLS)

Configure client certificate authentication:

```yaml
spec:
  listeners:
    - name: mtls
      port: 8443
      protocol: HTTPS
      tls:
        mode: MUTUAL
        certFile: /app/certs/server.crt
        keyFile: /app/certs/server.key
        caFile: /app/certs/client-ca.crt
        requireClientCert: true
        clientValidation:
          enabled: true
          allowedCNs:
            - "client.example.com"
          allowedSANs:
            - "*.client.example.com"
```

For detailed TLS configuration, see [Vault PKI Integration Guide](docs/vault-pki-integration.md).

## 📋 Configuration Levels Reference

The AV API Gateway supports configuration at three levels: **Global**, **Route**, and **Backend**. This section provides a comprehensive reference for all configuration options and their applicable levels.

### Configuration Level Hierarchy

Configuration options follow a hierarchical inheritance model:

1. **Global Level** - Applied to all routes and backends unless overridden
2. **Route Level** - Applied to specific routes, overrides global settings
3. **Backend Level** - Applied to specific backends, overrides global settings

When the same option is configured at multiple levels, the more specific level takes precedence.

### Listeners Configuration

| Option | Global | Route | Backend | Description |
|--------|:------:|:-----:|:-------:|-------------|
| `listeners[].name` | ✅ | - | - | Unique listener name |
| `listeners[].port` | ✅ | - | - | Port number to listen on |
| `listeners[].protocol` | ✅ | - | - | Protocol (HTTP, HTTPS, GRPC) |
| `listeners[].hosts` | ✅ | - | - | Host matching patterns |
| `listeners[].bind` | ✅ | - | - | Bind address |
| `listeners[].timeouts.readTimeout` | ✅ | - | - | Maximum duration for reading request |
| `listeners[].timeouts.readHeaderTimeout` | ✅ | - | - | Maximum duration for reading headers |
| `listeners[].timeouts.writeTimeout` | ✅ | - | - | Maximum duration for writing response |
| `listeners[].timeouts.idleTimeout` | ✅ | - | - | Maximum idle connection duration |

### Listener TLS Configuration

| Option | Global | Route | Backend | Description |
|--------|:------:|:-----:|:-------:|-------------|
| `listeners[].tls.mode` | ✅ | - | - | TLS mode (SIMPLE, MUTUAL, OPTIONAL_MUTUAL, INSECURE) |
| `listeners[].tls.minVersion` | ✅ | - | - | Minimum TLS version (TLS12, TLS13) |
| `listeners[].tls.maxVersion` | ✅ | - | - | Maximum TLS version |
| `listeners[].tls.certFile` | ✅ | - | - | Path to server certificate |
| `listeners[].tls.keyFile` | ✅ | - | - | Path to server private key |
| `listeners[].tls.caFile` | ✅ | - | - | Path to CA certificate for client validation |
| `listeners[].tls.cipherSuites` | ✅ | - | - | Allowed cipher suites |
| `listeners[].tls.requireClientCert` | ✅ | - | - | Require client certificate |
| `listeners[].tls.insecureSkipVerify` | ✅ | - | - | Skip certificate verification (dev only) |
| `listeners[].tls.alpn` | ✅ | - | - | ALPN protocols for negotiation |
| `listeners[].tls.httpsRedirect` | ✅ | - | - | Enable HTTP to HTTPS redirect |
| `listeners[].tls.hsts.enabled` | ✅ | - | - | Enable HSTS header |
| `listeners[].tls.hsts.maxAge` | ✅ | - | - | HSTS max-age in seconds |
| `listeners[].tls.hsts.includeSubDomains` | ✅ | - | - | Include subdomains in HSTS |
| `listeners[].tls.hsts.preload` | ✅ | - | - | Enable HSTS preload |
| `listeners[].tls.vault.enabled` | ✅ | - | - | Enable Vault certificate management |
| `listeners[].tls.vault.pkiMount` | ✅ | - | - | Vault PKI mount path |
| `listeners[].tls.vault.role` | ✅ | - | - | Vault PKI role name |
| `listeners[].tls.vault.commonName` | ✅ | - | - | Certificate common name |
| `listeners[].tls.vault.altNames` | ✅ | - | - | Certificate alternative names |
| `listeners[].tls.vault.ttl` | ✅ | - | - | Certificate TTL |

### gRPC Listener Configuration

| Option | Global | Route | Backend | Description |
|--------|:------:|:-----:|:-------:|-------------|
| `listeners[].grpc.maxConcurrentStreams` | ✅ | - | - | Max concurrent streams per connection |
| `listeners[].grpc.maxRecvMsgSize` | ✅ | - | - | Max receive message size in bytes |
| `listeners[].grpc.maxSendMsgSize` | ✅ | - | - | Max send message size in bytes |
| `listeners[].grpc.reflection` | ✅ | - | - | Enable gRPC reflection service |
| `listeners[].grpc.healthCheck` | ✅ | - | - | Enable gRPC health check service |
| `listeners[].grpc.keepalive.time` | ✅ | - | - | Keepalive ping interval |
| `listeners[].grpc.keepalive.timeout` | ✅ | - | - | Keepalive ping timeout |
| `listeners[].grpc.keepalive.permitWithoutStream` | ✅ | - | - | Allow keepalive without active streams |
| `listeners[].grpc.keepalive.maxConnectionIdle` | ✅ | - | - | Max connection idle time |
| `listeners[].grpc.keepalive.maxConnectionAge` | ✅ | - | - | Max connection age |
| `listeners[].grpc.keepalive.maxConnectionAgeGrace` | ✅ | - | - | Grace period after max age |
| `listeners[].grpc.tls.*` | ✅ | - | - | gRPC TLS configuration (same as listener TLS) |

### HTTP Routes Configuration

| Option | Global | Route | Backend | CRD Route | Description |
|--------|:------:|:-----:|:-------:|:---------:|-------------|
| `routes[].name` | - | ✅ | - | ✅ | Unique route name |
| `routes[].match[].uri.exact` | - | ✅ | - | ✅ | Exact URI match |
| `routes[].match[].uri.prefix` | - | ✅ | - | ✅ | URI prefix match |
| `routes[].match[].uri.regex` | - | ✅ | - | ✅ | URI regex match |
| `routes[].match[].methods` | - | ✅ | - | ✅ | HTTP methods to match |
| `routes[].match[].headers[].name` | - | ✅ | - | ✅ | Header name to match |
| `routes[].match[].headers[].exact` | - | ✅ | - | ✅ | Exact header value match |
| `routes[].match[].headers[].prefix` | - | ✅ | - | ✅ | Header value prefix match |
| `routes[].match[].headers[].regex` | - | ✅ | - | ✅ | Header value regex match |
| `routes[].match[].headers[].present` | - | ✅ | - | ✅ | Header must be present |
| `routes[].match[].headers[].absent` | - | ✅ | - | ✅ | Header must be absent |
| `routes[].match[].queryParams[].name` | - | ✅ | - | ✅ | Query parameter name |
| `routes[].match[].queryParams[].exact` | - | ✅ | - | ✅ | Exact query parameter value |
| `routes[].match[].queryParams[].regex` | - | ✅ | - | ✅ | Query parameter regex match |
| `routes[].match[].queryParams[].present` | - | ✅ | - | ✅ | Query parameter must be present |
| `routes[].route[].destination.host` | - | ✅ | - | ✅ | Backend host |
| `routes[].route[].destination.port` | - | ✅ | - | ✅ | Backend port |
| `routes[].route[].weight` | - | ✅ | - | ✅ | Traffic weight for load balancing |
| `routes[].timeout` | ✅ | ✅ | - | ✅ | Request timeout |
| `routes[].retries.attempts` | ✅ | ✅ | - | ✅ | Max retry attempts |
| `routes[].retries.perTryTimeout` | ✅ | ✅ | - | ✅ | Timeout per retry attempt |
| `routes[].retries.retryOn` | ✅ | ✅ | - | ✅ | Conditions to retry on |
| `routes[].redirect.uri` | - | ✅ | - | ✅ | Redirect URI |
| `routes[].redirect.code` | - | ✅ | - | ✅ | Redirect HTTP status code |
| `routes[].redirect.scheme` | - | ✅ | - | ✅ | Redirect scheme (http/https) |
| `routes[].redirect.host` | - | ✅ | - | ✅ | Redirect host |
| `routes[].redirect.port` | - | ✅ | - | ✅ | Redirect port |
| `routes[].redirect.stripQuery` | - | ✅ | - | ✅ | Strip query string on redirect |
| `routes[].rewrite.uri` | - | ✅ | - | ✅ | Rewrite URI |
| `routes[].rewrite.authority` | - | ✅ | - | ✅ | Rewrite authority/host |
| `routes[].directResponse.status` | - | ✅ | - | ✅ | Direct response status code |
| `routes[].directResponse.body` | - | ✅ | - | ✅ | Direct response body |
| `routes[].directResponse.headers` | - | ✅ | - | ✅ | Direct response headers |
| `routes[].headers.request.set` | - | ✅ | - | ✅ | Set request headers |
| `routes[].headers.request.add` | - | ✅ | - | ✅ | Add request headers |
| `routes[].headers.request.remove` | - | ✅ | - | ✅ | Remove request headers |
| `routes[].headers.response.set` | - | ✅ | - | ✅ | Set response headers |
| `routes[].headers.response.add` | - | ✅ | - | ✅ | Add response headers |
| `routes[].headers.response.remove` | - | ✅ | - | ✅ | Remove response headers |
| `routes[].mirror.destination` | - | ✅ | - | ✅ | Mirror traffic destination |
| `routes[].mirror.percentage` | - | ✅ | - | ✅ | Percentage of traffic to mirror |
| `routes[].fault.delay.fixedDelay` | - | ✅ | - | ✅ | Fixed delay duration |
| `routes[].fault.delay.percentage` | - | ✅ | - | ✅ | Percentage of requests to delay |
| `routes[].fault.abort.httpStatus` | - | ✅ | - | ✅ | HTTP status for abort |
| `routes[].fault.abort.percentage` | - | ✅ | - | ✅ | Percentage of requests to abort |
| `routes[].requestLimits.maxBodySize` | ✅ | ✅ | - | ✅ | Maximum request body size in bytes |
| `routes[].requestLimits.maxHeaderSize` | ✅ | ✅ | - | ✅ | Maximum total header size in bytes |
| `routes[].cors.allowOrigins` | ✅ | ✅ | - | ✅ | Allowed origins for CORS |
| `routes[].cors.allowMethods` | ✅ | ✅ | - | ✅ | Allowed HTTP methods for CORS |
| `routes[].cors.allowHeaders` | ✅ | ✅ | - | ✅ | Allowed request headers for CORS |
| `routes[].cors.exposeHeaders` | ✅ | ✅ | - | ✅ | Headers exposed to browser |
| `routes[].cors.maxAge` | ✅ | ✅ | - | ✅ | Preflight cache duration in seconds |
| `routes[].cors.allowCredentials` | ✅ | ✅ | - | ✅ | Allow credentials in CORS requests |
| `routes[].security.enabled` | ✅ | ✅ | - | ✅ | Enable security headers |
| `routes[].security.headers.enabled` | ✅ | ✅ | - | ✅ | Enable security headers injection |
| `routes[].security.headers.xFrameOptions` | ✅ | ✅ | - | ✅ | X-Frame-Options header value |
| `routes[].security.headers.xContentTypeOptions` | ✅ | ✅ | - | ✅ | X-Content-Type-Options header value |
| `routes[].security.headers.xXSSProtection` | ✅ | ✅ | - | ✅ | X-XSS-Protection header value |
| `routes[].security.headers.customHeaders` | ✅ | ✅ | - | ✅ | Custom security headers |
| `routes[].rateLimit.enabled` | ✅ | ✅ | - | ✅ | Enable route-level rate limiting |
| `routes[].rateLimit.requestsPerSecond` | ✅ | ✅ | - | ✅ | Requests per second limit |
| `routes[].rateLimit.burst` | ✅ | ✅ | - | ✅ | Burst size for rate limiting |
| `routes[].rateLimit.perClient` | ✅ | ✅ | - | ✅ | Apply rate limit per client IP |
| `routes[].transform.request.template` | - | ✅ | - | ✅ | Go template for request transformation |
| `routes[].transform.response.allowFields` | - | ✅ | - | ✅ | Fields to allow in response |
| `routes[].transform.response.denyFields` | - | ✅ | - | ✅ | Fields to deny in response |
| `routes[].transform.response.fieldMappings` | - | ✅ | - | ✅ | Field name mappings |
| `routes[].cache.enabled` | - | ✅ | - | ✅ | Enable caching |
| `routes[].cache.ttl` | - | ✅ | - | ✅ | Cache time-to-live |
| `routes[].cache.keyComponents` | - | ✅ | - | ✅ | Components for cache key generation |
| `routes[].cache.staleWhileRevalidate` | - | ✅ | - | ✅ | Serve stale while revalidating |
| `routes[].encoding.request.contentType` | - | ✅ | - | ✅ | Request content type |
| `routes[].encoding.response.contentType` | - | ✅ | - | ✅ | Response content type |
| `routes[].maxSessions.enabled` | ✅ | ✅ | - | ✅ | Enable max sessions limiting |
| `routes[].maxSessions.maxConcurrent` | ✅ | ✅ | - | ✅ | Maximum concurrent sessions |
| `routes[].maxSessions.queueSize` | ✅ | ✅ | - | ✅ | Queue size for waiting connections |
| `routes[].maxSessions.queueTimeout` | ✅ | ✅ | - | ✅ | Timeout for queued connections |
| `routes[].tls.certFile` | - | ✅ | - | ✅ | Route-specific certificate file |
| `routes[].tls.keyFile` | - | ✅ | - | ✅ | Route-specific private key file |
| `routes[].tls.sniHosts` | - | ✅ | - | ✅ | SNI hostnames for certificate |
| `routes[].tls.minVersion` | - | ✅ | - | ✅ | Minimum TLS version |
| `routes[].tls.maxVersion` | - | ✅ | - | ✅ | Maximum TLS version |
| `routes[].tls.cipherSuites` | - | ✅ | - | ✅ | Allowed cipher suites |
| `routes[].tls.clientValidation.enabled` | - | ✅ | - | ✅ | Enable client certificate validation |
| `routes[].tls.clientValidation.caFile` | - | ✅ | - | ✅ | CA certificate for client validation |
| `routes[].tls.clientValidation.requireClientCert` | - | ✅ | - | ✅ | Require client certificate |
| `routes[].tls.clientValidation.allowedCNs` | - | ✅ | - | ✅ | Allowed common names |
| `routes[].tls.clientValidation.allowedSANs` | - | ✅ | - | ✅ | Allowed subject alternative names |
| `routes[].tls.vault.enabled` | - | ✅ | - | ✅ | Enable Vault certificate management |
| `routes[].tls.vault.pkiMount` | - | ✅ | - | ✅ | Vault PKI mount path |
| `routes[].tls.vault.role` | - | ✅ | - | ✅ | Vault PKI role name |
| `routes[].tls.vault.commonName` | - | ✅ | - | ✅ | Certificate common name |
| `routes[].tls.vault.altNames` | - | ✅ | - | ✅ | Certificate alternative names |
| `routes[].tls.vault.ttl` | - | ✅ | - | ✅ | Certificate TTL |
| `routes[].authentication.enabled` | ✅ | ✅ | - | ✅ | Enable route-level authentication |
| `routes[].authorization.enabled` | ✅ | ✅ | - | ✅ | Enable route-level authorization |

### gRPC Routes Configuration

| Option | Global | Route | Backend | CRD Route | Description |
|--------|:------:|:-----:|:-------:|:---------:|-------------|
| `grpcRoutes[].name` | - | ✅ | - | ✅ | Unique gRPC route name |
| `grpcRoutes[].match[].service.exact` | - | ✅ | - | ✅ | Exact service name match |
| `grpcRoutes[].match[].service.prefix` | - | ✅ | - | ✅ | Service name prefix match |
| `grpcRoutes[].match[].service.regex` | - | ✅ | - | ✅ | Service name regex match |
| `grpcRoutes[].match[].method.exact` | - | ✅ | - | ✅ | Exact method name match |
| `grpcRoutes[].match[].method.prefix` | - | ✅ | - | ✅ | Method name prefix match |
| `grpcRoutes[].match[].method.regex` | - | ✅ | - | ✅ | Method name regex match |
| `grpcRoutes[].match[].metadata[].name` | - | ✅ | - | ✅ | Metadata key name |
| `grpcRoutes[].match[].metadata[].exact` | - | ✅ | - | ✅ | Exact metadata value match |
| `grpcRoutes[].match[].metadata[].prefix` | - | ✅ | - | ✅ | Metadata value prefix match |
| `grpcRoutes[].match[].metadata[].regex` | - | ✅ | - | ✅ | Metadata value regex match |
| `grpcRoutes[].match[].metadata[].present` | - | ✅ | - | ✅ | Metadata must be present |
| `grpcRoutes[].match[].metadata[].absent` | - | ✅ | - | ✅ | Metadata must be absent |
| `grpcRoutes[].match[].authority.exact` | - | ✅ | - | ✅ | Exact authority match |
| `grpcRoutes[].match[].authority.prefix` | - | ✅ | - | ✅ | Authority prefix match |
| `grpcRoutes[].match[].authority.regex` | - | ✅ | - | ✅ | Authority regex match |
| `grpcRoutes[].match[].withoutHeaders` | - | ✅ | - | ✅ | Headers that must NOT be present |
| `grpcRoutes[].route[].destination.host` | - | ✅ | - | ✅ | Backend host |
| `grpcRoutes[].route[].destination.port` | - | ✅ | - | ✅ | Backend port |
| `grpcRoutes[].route[].weight` | - | ✅ | - | ✅ | Traffic weight |
| `grpcRoutes[].timeout` | ✅ | ✅ | - | ✅ | Request timeout |
| `grpcRoutes[].retries.attempts` | ✅ | ✅ | - | ✅ | Max retry attempts |
| `grpcRoutes[].retries.perTryTimeout` | ✅ | ✅ | - | ✅ | Timeout per retry |
| `grpcRoutes[].retries.retryOn` | ✅ | ✅ | - | ✅ | gRPC status codes to retry on |
| `grpcRoutes[].retries.backoffBaseInterval` | ✅ | ✅ | - | ✅ | Base interval for exponential backoff |
| `grpcRoutes[].retries.backoffMaxInterval` | ✅ | ✅ | - | ✅ | Max interval for exponential backoff |
| `grpcRoutes[].headers.request.set` | - | ✅ | - | ✅ | Set request headers |
| `grpcRoutes[].headers.request.add` | - | ✅ | - | ✅ | Add request headers |
| `grpcRoutes[].headers.request.remove` | - | ✅ | - | ✅ | Remove request headers |
| `grpcRoutes[].headers.response.set` | - | ✅ | - | ✅ | Set response headers |
| `grpcRoutes[].headers.response.add` | - | ✅ | - | ✅ | Add response headers |
| `grpcRoutes[].headers.response.remove` | - | ✅ | - | ✅ | Remove response headers |
| `grpcRoutes[].mirror.destination` | - | ✅ | - | ✅ | Mirror traffic destination |
| `grpcRoutes[].mirror.percentage` | - | ✅ | - | ✅ | Percentage of traffic to mirror |
| `grpcRoutes[].rateLimit.enabled` | ✅ | ✅ | - | ✅ | Enable route-level rate limiting |
| `grpcRoutes[].rateLimit.requestsPerSecond` | ✅ | ✅ | - | ✅ | Requests per second limit |
| `grpcRoutes[].rateLimit.burst` | ✅ | ✅ | - | ✅ | Burst size for rate limiting |
| `grpcRoutes[].rateLimit.perClient` | ✅ | ✅ | - | ✅ | Apply rate limit per client IP |
| `grpcRoutes[].transform.fieldMask.paths` | - | ✅ | - | ✅ | Field paths to include |
| `grpcRoutes[].transform.metadata.static` | - | ✅ | - | ✅ | Static metadata values |
| `grpcRoutes[].transform.metadata.dynamic` | - | ✅ | - | ✅ | Dynamic metadata templates |
| `grpcRoutes[].cache.enabled` | - | ✅ | - | ✅ | Enable caching |
| `grpcRoutes[].cache.ttl` | - | ✅ | - | ✅ | Cache time-to-live |
| `grpcRoutes[].cache.keyComponents` | - | ✅ | - | ✅ | Components for cache key generation |
| `grpcRoutes[].cache.staleWhileRevalidate` | - | ✅ | - | ✅ | Serve stale while revalidating |
| `grpcRoutes[].encoding.request.contentType` | - | ✅ | - | ✅ | Request content type |
| `grpcRoutes[].encoding.response.contentType` | - | ✅ | - | ✅ | Response content type |
| `grpcRoutes[].cors.allowOrigins` | ✅ | ✅ | - | ✅ | Allowed origins for CORS |
| `grpcRoutes[].cors.allowMethods` | ✅ | ✅ | - | ✅ | Allowed HTTP methods for CORS |
| `grpcRoutes[].cors.allowHeaders` | ✅ | ✅ | - | ✅ | Allowed request headers for CORS |
| `grpcRoutes[].cors.exposeHeaders` | ✅ | ✅ | - | ✅ | Headers exposed to browser |
| `grpcRoutes[].cors.maxAge` | ✅ | ✅ | - | ✅ | Preflight cache duration in seconds |
| `grpcRoutes[].cors.allowCredentials` | ✅ | ✅ | - | ✅ | Allow credentials in CORS requests |
| `grpcRoutes[].security.enabled` | ✅ | ✅ | - | ✅ | Enable security headers |
| `grpcRoutes[].security.headers.enabled` | ✅ | ✅ | - | ✅ | Enable security headers injection |
| `grpcRoutes[].tls.certFile` | - | ✅ | - | ✅ | Route-specific certificate file |
| `grpcRoutes[].tls.keyFile` | - | ✅ | - | ✅ | Route-specific private key file |
| `grpcRoutes[].tls.sniHosts` | - | ✅ | - | ✅ | SNI hostnames for certificate |
| `grpcRoutes[].tls.minVersion` | - | ✅ | - | ✅ | Minimum TLS version |
| `grpcRoutes[].tls.maxVersion` | - | ✅ | - | ✅ | Maximum TLS version |
| `grpcRoutes[].tls.cipherSuites` | - | ✅ | - | ✅ | Allowed cipher suites |
| `grpcRoutes[].tls.clientValidation.enabled` | - | ✅ | - | ✅ | Enable client certificate validation |
| `grpcRoutes[].tls.vault.enabled` | - | ✅ | - | ✅ | Enable Vault certificate management |
| `grpcRoutes[].authentication.enabled` | ✅ | ✅ | - | ✅ | Enable route-level authentication |
| `grpcRoutes[].authorization.enabled` | ✅ | ✅ | - | ✅ | Enable route-level authorization |
| `grpcRoutes[].maxSessions.enabled` | ✅ | ✅ | - | ✅ | Enable max sessions limiting |
| `grpcRoutes[].maxSessions.maxConcurrent` | ✅ | ✅ | - | ✅ | Maximum concurrent sessions |
| `grpcRoutes[].maxSessions.queueSize` | ✅ | ✅ | - | ✅ | Queue size for waiting connections |
| `grpcRoutes[].maxSessions.queueTimeout` | ✅ | ✅ | - | ✅ | Timeout for queued connections |
| `grpcRoutes[].requestLimits.maxBodySize` | ✅ | ✅ | - | ✅ | Maximum request body size in bytes |
| `grpcRoutes[].requestLimits.maxHeaderSize` | ✅ | ✅ | - | ✅ | Maximum total header size in bytes |

### HTTP Backends Configuration

| Option | Global | Route | Backend | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:-----------:|-------------|
| `backends[].name` | - | - | ✅ | ✅ | Unique backend name |
| `backends[].hosts[].address` | - | - | ✅ | ✅ | Backend host address |
| `backends[].hosts[].port` | - | - | ✅ | ✅ | Backend port |
| `backends[].hosts[].weight` | - | - | ✅ | ✅ | Host weight for load balancing |
| `backends[].healthCheck.path` | - | - | ✅ | ✅ | Health check endpoint path |
| `backends[].healthCheck.interval` | - | - | ✅ | ✅ | Health check interval |
| `backends[].healthCheck.timeout` | - | - | ✅ | ✅ | Health check timeout |
| `backends[].healthCheck.healthyThreshold` | - | - | ✅ | ✅ | Consecutive successes to mark healthy |
| `backends[].healthCheck.unhealthyThreshold` | - | - | ✅ | ✅ | Consecutive failures to mark unhealthy |
| `backends[].loadBalancer.algorithm` | - | - | ✅ | ✅ | Load balancing algorithm (roundRobin, weighted, leastConn, random) |
| `backends[].maxSessions.enabled` | - | - | ✅ | ✅ | Enable max sessions for backend hosts |
| `backends[].maxSessions.maxConcurrent` | - | - | ✅ | ✅ | Max concurrent connections per host |
| `backends[].maxSessions.queueSize` | - | - | ✅ | ✅ | Queue size for waiting connections |
| `backends[].maxSessions.queueTimeout` | - | - | ✅ | ✅ | Timeout for queued connections |
| `backends[].rateLimit.enabled` | - | - | ✅ | ✅ | Enable rate limiting for backend hosts |
| `backends[].rateLimit.requestsPerSecond` | - | - | ✅ | ✅ | Requests per second limit per host |
| `backends[].rateLimit.burst` | - | - | ✅ | ✅ | Burst size per host |
| `backends[].rateLimit.perClient` | - | - | ✅ | ✅ | Apply rate limit per client IP |
| `backends[].tls.enabled` | - | - | ✅ | ✅ | Enable TLS for backend connections |
| `backends[].tls.mode` | - | - | ✅ | ✅ | TLS mode (SIMPLE, MUTUAL, INSECURE) |
| `backends[].tls.caFile` | - | - | ✅ | ✅ | CA certificate for server verification |
| `backends[].tls.certFile` | - | - | ✅ | ✅ | Client certificate (for mTLS) |
| `backends[].tls.keyFile` | - | - | ✅ | ✅ | Client private key (for mTLS) |
| `backends[].tls.serverName` | - | - | ✅ | ✅ | Server name for TLS verification (SNI) |
| `backends[].tls.insecureSkipVerify` | - | - | ✅ | ✅ | Skip server certificate verification |
| `backends[].tls.minVersion` | - | - | ✅ | ✅ | Minimum TLS version |
| `backends[].tls.maxVersion` | - | - | ✅ | ✅ | Maximum TLS version |
| `backends[].tls.cipherSuites` | - | - | ✅ | ✅ | Allowed cipher suites |
| `backends[].tls.alpn` | - | - | ✅ | ✅ | ALPN protocols |
| `backends[].tls.vault.enabled` | - | - | ✅ | ✅ | Enable Vault-based client certificate management |
| `backends[].tls.vault.pkiMount` | - | - | ✅ | ✅ | Vault PKI mount path |
| `backends[].tls.vault.role` | - | - | ✅ | ✅ | Vault PKI role name |
| `backends[].tls.vault.commonName` | - | - | ✅ | ✅ | Certificate common name |
| `backends[].tls.vault.altNames` | - | - | ✅ | ✅ | Certificate alternative names |
| `backends[].tls.vault.ttl` | - | - | ✅ | ✅ | Certificate TTL |
| `backends[].circuitBreaker.enabled` | - | - | ✅ | ✅ | Enable circuit breaker for this backend |
| `backends[].circuitBreaker.threshold` | - | - | ✅ | ✅ | Failure threshold to open circuit |
| `backends[].circuitBreaker.timeout` | - | - | ✅ | ✅ | Time to wait before half-open |
| `backends[].circuitBreaker.halfOpenRequests` | - | - | ✅ | ✅ | Requests allowed in half-open state |
| `backends[].authentication.type` | - | - | ✅ | ✅ | Authentication type (jwt, basic, mtls) |
| `backends[].authentication.jwt.enabled` | - | - | ✅ | ✅ | Enable JWT authentication |
| `backends[].authentication.jwt.tokenSource` | - | - | ✅ | ✅ | Token source (static, vault, oidc) |
| `backends[].authentication.jwt.staticToken` | - | - | ✅ | ✅ | Static JWT token (dev only) |
| `backends[].authentication.jwt.vaultPath` | - | - | ✅ | ✅ | Vault path for JWT token |
| `backends[].authentication.jwt.oidc.issuerUrl` | - | - | ✅ | ✅ | OIDC issuer URL |
| `backends[].authentication.jwt.oidc.clientId` | - | - | ✅ | ✅ | OIDC client ID |
| `backends[].authentication.jwt.oidc.clientSecret` | - | - | ✅ | ✅ | OIDC client secret |
| `backends[].authentication.jwt.oidc.clientSecretRef.name` | - | - | ✅ | ✅ | Kubernetes secret name for client secret |
| `backends[].authentication.jwt.oidc.clientSecretRef.key` | - | - | ✅ | ✅ | Kubernetes secret key for client secret |
| `backends[].authentication.jwt.oidc.scopes` | - | - | ✅ | ✅ | OIDC scopes to request |
| `backends[].authentication.jwt.oidc.tokenCacheTTL` | - | - | ✅ | ✅ | TTL for cached tokens |
| `backends[].authentication.jwt.headerName` | - | - | ✅ | ✅ | Header name for JWT token |
| `backends[].authentication.jwt.headerPrefix` | - | - | ✅ | ✅ | Header prefix for JWT token |
| `backends[].authentication.basic.enabled` | - | - | ✅ | ✅ | Enable Basic authentication |
| `backends[].authentication.basic.username` | - | - | ✅ | ✅ | Username for Basic auth |
| `backends[].authentication.basic.password` | - | - | ✅ | ✅ | Password for Basic auth |
| `backends[].authentication.basic.vaultPath` | - | - | ✅ | ✅ | Vault path for credentials |
| `backends[].authentication.basic.usernameKey` | - | - | ✅ | ✅ | Vault key for username |
| `backends[].authentication.basic.passwordKey` | - | - | ✅ | ✅ | Vault key for password |
| `backends[].authentication.mtls.enabled` | - | - | ✅ | ✅ | Enable mTLS authentication |
| `backends[].authentication.mtls.certFile` | - | - | ✅ | ✅ | Client certificate file |
| `backends[].authentication.mtls.keyFile` | - | - | ✅ | ✅ | Client private key file |
| `backends[].authentication.mtls.caFile` | - | - | ✅ | ✅ | CA certificate for server verification |
| `backends[].authentication.mtls.vault.enabled` | - | - | ✅ | ✅ | Enable Vault-based certificate management |
| `backends[].authentication.mtls.vault.pkiMount` | - | - | ✅ | ✅ | Vault PKI mount path |
| `backends[].authentication.mtls.vault.role` | - | - | ✅ | ✅ | Vault PKI role name |
| `backends[].authentication.mtls.vault.commonName` | - | - | ✅ | ✅ | Certificate common name |
| `backends[].authentication.mtls.vault.altNames` | - | - | ✅ | ✅ | Certificate alternative names |
| `backends[].authentication.mtls.vault.ttl` | - | - | ✅ | ✅ | Certificate TTL |
| `backends[].requestLimits.maxBodySize` | - | - | ✅ | ✅ | Maximum request body size in bytes |
| `backends[].requestLimits.maxHeaderSize` | - | - | ✅ | ✅ | Maximum total header size in bytes |
| `backends[].transform.request.template` | - | - | ✅ | ✅ | Go template for request transformation |
| `backends[].transform.request.headers.set` | - | - | ✅ | ✅ | Set request headers |
| `backends[].transform.request.headers.add` | - | - | ✅ | ✅ | Add request headers |
| `backends[].transform.request.headers.remove` | - | - | ✅ | ✅ | Remove request headers |
| `backends[].transform.response.allowFields` | - | - | ✅ | ✅ | Fields to allow in response |
| `backends[].transform.response.denyFields` | - | - | ✅ | ✅ | Fields to deny in response |
| `backends[].transform.response.fieldMappings` | - | - | ✅ | ✅ | Field name mappings |
| `backends[].transform.response.headers.set` | - | - | ✅ | ✅ | Set response headers |
| `backends[].transform.response.headers.add` | - | - | ✅ | ✅ | Add response headers |
| `backends[].transform.response.headers.remove` | - | - | ✅ | ✅ | Remove response headers |
| `backends[].cache.enabled` | - | - | ✅ | ✅ | Enable caching |
| `backends[].cache.ttl` | - | - | ✅ | ✅ | Cache time-to-live |
| `backends[].cache.keyComponents` | - | - | ✅ | ✅ | Components for cache key generation |
| `backends[].cache.staleWhileRevalidate` | - | - | ✅ | ✅ | Serve stale while revalidating |
| `backends[].cache.type` | - | - | ✅ | ✅ | Cache type (memory, redis) |
| `backends[].encoding.request.contentType` | - | - | ✅ | ✅ | Request content type |
| `backends[].encoding.request.compression` | - | - | ✅ | ✅ | Request compression algorithm |
| `backends[].encoding.response.contentType` | - | - | ✅ | ✅ | Response content type |
| `backends[].encoding.response.compression` | - | - | ✅ | ✅ | Response compression algorithm |

### gRPC Backends Configuration

| Option | Global | Route | Backend | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:-----------:|-------------|
| `grpcBackends[].name` | - | - | ✅ | ✅ | Unique gRPC backend name |
| `grpcBackends[].hosts[].address` | - | - | ✅ | ✅ | Backend host address |
| `grpcBackends[].hosts[].port` | - | - | ✅ | ✅ | Backend port |
| `grpcBackends[].hosts[].weight` | - | - | ✅ | ✅ | Host weight for load balancing |
| `grpcBackends[].healthCheck.enabled` | - | - | ✅ | ✅ | Enable gRPC health checking |
| `grpcBackends[].healthCheck.service` | - | - | ✅ | ✅ | Service name to check (empty for overall) |
| `grpcBackends[].healthCheck.interval` | - | - | ✅ | ✅ | Health check interval |
| `grpcBackends[].healthCheck.timeout` | - | - | ✅ | ✅ | Health check timeout |
| `grpcBackends[].healthCheck.healthyThreshold` | - | - | ✅ | ✅ | Consecutive successes to mark healthy |
| `grpcBackends[].healthCheck.unhealthyThreshold` | - | - | ✅ | ✅ | Consecutive failures to mark unhealthy |
| `grpcBackends[].loadBalancer.algorithm` | - | - | ✅ | ✅ | Load balancing algorithm |
| `grpcBackends[].tls.enabled` | - | - | ✅ | ✅ | Enable TLS for backend connections |
| `grpcBackends[].tls.mode` | - | - | ✅ | ✅ | TLS mode (SIMPLE, MUTUAL, INSECURE) |
| `grpcBackends[].tls.caFile` | - | - | ✅ | ✅ | CA certificate for server verification |
| `grpcBackends[].tls.certFile` | - | - | ✅ | ✅ | Client certificate (for mTLS) |
| `grpcBackends[].tls.keyFile` | - | - | ✅ | ✅ | Client private key (for mTLS) |
| `grpcBackends[].tls.serverName` | - | - | ✅ | ✅ | Server name for TLS verification (SNI) |
| `grpcBackends[].tls.insecureSkipVerify` | - | - | ✅ | ✅ | Skip server certificate verification |
| `grpcBackends[].tls.minVersion` | - | - | ✅ | ✅ | Minimum TLS version |
| `grpcBackends[].tls.maxVersion` | - | - | ✅ | ✅ | Maximum TLS version |
| `grpcBackends[].tls.cipherSuites` | - | - | ✅ | ✅ | Allowed cipher suites |
| `grpcBackends[].tls.alpn` | - | - | ✅ | ✅ | ALPN protocols |
| `grpcBackends[].tls.vault.enabled` | - | - | ✅ | ✅ | Enable Vault-based client certificate management |
| `grpcBackends[].tls.vault.pkiMount` | - | - | ✅ | ✅ | Vault PKI mount path |
| `grpcBackends[].tls.vault.role` | - | - | ✅ | ✅ | Vault PKI role name |
| `grpcBackends[].tls.vault.commonName` | - | - | ✅ | ✅ | Certificate common name |
| `grpcBackends[].tls.vault.altNames` | - | - | ✅ | ✅ | Certificate alternative names |
| `grpcBackends[].tls.vault.ttl` | - | - | ✅ | ✅ | Certificate TTL |
| `grpcBackends[].connectionPool.maxIdleConns` | - | - | ✅ | ✅ | Max idle connections per host |
| `grpcBackends[].connectionPool.maxConnsPerHost` | - | - | ✅ | ✅ | Max connections per host |
| `grpcBackends[].connectionPool.idleConnTimeout` | - | - | ✅ | ✅ | Idle connection timeout |
| `grpcBackends[].circuitBreaker.enabled` | - | - | ✅ | ✅ | Enable circuit breaker for this backend |
| `grpcBackends[].circuitBreaker.threshold` | - | - | ✅ | ✅ | Failure threshold to open circuit |
| `grpcBackends[].circuitBreaker.timeout` | - | - | ✅ | ✅ | Time to wait before half-open |
| `grpcBackends[].circuitBreaker.halfOpenRequests` | - | - | ✅ | ✅ | Requests allowed in half-open state |
| `grpcBackends[].authentication.type` | - | - | ✅ | ✅ | Authentication type (jwt, basic, mtls) |
| `grpcBackends[].authentication.jwt.enabled` | - | - | ✅ | ✅ | Enable JWT authentication |
| `grpcBackends[].authentication.jwt.tokenSource` | - | - | ✅ | ✅ | Token source (static, vault, oidc) |
| `grpcBackends[].authentication.jwt.staticToken` | - | - | ✅ | ✅ | Static JWT token (dev only) |
| `grpcBackends[].authentication.jwt.vaultPath` | - | - | ✅ | ✅ | Vault path for JWT token |
| `grpcBackends[].authentication.jwt.oidc.issuerUrl` | - | - | ✅ | ✅ | OIDC issuer URL |
| `grpcBackends[].authentication.jwt.oidc.clientId` | - | - | ✅ | ✅ | OIDC client ID |
| `grpcBackends[].authentication.jwt.oidc.clientSecret` | - | - | ✅ | ✅ | OIDC client secret |
| `grpcBackends[].authentication.jwt.oidc.clientSecretRef.name` | - | - | ✅ | ✅ | Kubernetes secret name for client secret |
| `grpcBackends[].authentication.jwt.oidc.clientSecretRef.key` | - | - | ✅ | ✅ | Kubernetes secret key for client secret |
| `grpcBackends[].authentication.jwt.oidc.scopes` | - | - | ✅ | ✅ | OIDC scopes to request |
| `grpcBackends[].authentication.jwt.oidc.tokenCacheTTL` | - | - | ✅ | ✅ | TTL for cached tokens |
| `grpcBackends[].authentication.jwt.headerName` | - | - | ✅ | ✅ | Header name for JWT token |
| `grpcBackends[].authentication.jwt.headerPrefix` | - | - | ✅ | ✅ | Header prefix for JWT token |
| `grpcBackends[].authentication.basic.enabled` | - | - | ✅ | ✅ | Enable Basic authentication |
| `grpcBackends[].authentication.basic.username` | - | - | ✅ | ✅ | Username for Basic auth |
| `grpcBackends[].authentication.basic.password` | - | - | ✅ | ✅ | Password for Basic auth |
| `grpcBackends[].authentication.basic.vaultPath` | - | - | ✅ | ✅ | Vault path for credentials |
| `grpcBackends[].authentication.basic.usernameKey` | - | - | ✅ | ✅ | Vault key for username |
| `grpcBackends[].authentication.basic.passwordKey` | - | - | ✅ | ✅ | Vault key for password |
| `grpcBackends[].authentication.mtls.enabled` | - | - | ✅ | ✅ | Enable mTLS authentication |
| `grpcBackends[].authentication.mtls.certFile` | - | - | ✅ | ✅ | Client certificate file |
| `grpcBackends[].authentication.mtls.keyFile` | - | - | ✅ | ✅ | Client private key file |
| `grpcBackends[].authentication.mtls.caFile` | - | - | ✅ | ✅ | CA certificate for server verification |
| `grpcBackends[].authentication.mtls.vault.enabled` | - | - | ✅ | ✅ | Enable Vault-based certificate management |
| `grpcBackends[].authentication.mtls.vault.pkiMount` | - | - | ✅ | ✅ | Vault PKI mount path |
| `grpcBackends[].authentication.mtls.vault.role` | - | - | ✅ | ✅ | Vault PKI role name |
| `grpcBackends[].authentication.mtls.vault.commonName` | - | - | ✅ | ✅ | Certificate common name |
| `grpcBackends[].authentication.mtls.vault.altNames` | - | - | ✅ | ✅ | Certificate alternative names |
| `grpcBackends[].authentication.mtls.vault.ttl` | - | - | ✅ | ✅ | Certificate TTL |
| `grpcBackends[].maxSessions.enabled` | - | - | ✅ | ✅ | Enable max sessions for backend hosts |
| `grpcBackends[].maxSessions.maxConcurrent` | - | - | ✅ | ✅ | Max concurrent connections per host |
| `grpcBackends[].maxSessions.queueSize` | - | - | ✅ | ✅ | Queue size for waiting connections |
| `grpcBackends[].maxSessions.queueTimeout` | - | - | ✅ | ✅ | Timeout for queued connections |
| `grpcBackends[].rateLimit.enabled` | - | - | ✅ | ✅ | Enable rate limiting for backend hosts |
| `grpcBackends[].rateLimit.requestsPerSecond` | - | - | ✅ | ✅ | Requests per second limit per host |
| `grpcBackends[].rateLimit.burst` | - | - | ✅ | ✅ | Burst size per host |
| `grpcBackends[].rateLimit.perClient` | - | - | ✅ | ✅ | Apply rate limit per client IP |
| `grpcBackends[].transform.fieldMask.paths` | - | - | ✅ | ✅ | Field paths to include |
| `grpcBackends[].transform.metadata.static` | - | - | ✅ | ✅ | Static metadata values |
| `grpcBackends[].transform.metadata.dynamic` | - | - | ✅ | ✅ | Dynamic metadata templates |
| `grpcBackends[].cache.enabled` | - | - | ✅ | ✅ | Enable caching |
| `grpcBackends[].cache.ttl` | - | - | ✅ | ✅ | Cache time-to-live |
| `grpcBackends[].cache.keyComponents` | - | - | ✅ | ✅ | Components for cache key generation |
| `grpcBackends[].cache.staleWhileRevalidate` | - | - | ✅ | ✅ | Serve stale while revalidating |
| `grpcBackends[].cache.type` | - | - | ✅ | ✅ | Cache type (memory, redis) |
| `grpcBackends[].encoding.request.contentType` | - | - | ✅ | ✅ | Request content type |
| `grpcBackends[].encoding.request.compression` | - | - | ✅ | ✅ | Request compression algorithm |
| `grpcBackends[].encoding.response.contentType` | - | - | ✅ | ✅ | Response content type |
| `grpcBackends[].encoding.response.compression` | - | - | ✅ | ✅ | Response compression algorithm |

### Rate Limiting Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `rateLimit.enabled` | ✅ | ✅ | ✅ | ✅ | ✅ | Enable rate limiting |
| `rateLimit.requestsPerSecond` | ✅ | ✅ | ✅ | ✅ | ✅ | Requests per second limit |
| `rateLimit.burst` | ✅ | ✅ | ✅ | ✅ | ✅ | Burst size (token bucket) |
| `rateLimit.perClient` | ✅ | ✅ | ✅ | ✅ | ✅ | Apply rate limit per client IP |

### Max Sessions Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `maxSessions.enabled` | ✅ | ✅ | ✅ | ✅ | ✅ | Enable max sessions limiting |
| `maxSessions.maxConcurrent` | ✅ | ✅ | ✅ | ✅ | ✅ | Maximum concurrent connections |
| `maxSessions.queueSize` | ✅ | ✅ | ✅ | ✅ | ✅ | Queue size for waiting connections |
| `maxSessions.queueTimeout` | ✅ | ✅ | ✅ | ✅ | ✅ | Timeout for queued connections |

### Circuit Breaker Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `circuitBreaker.enabled` | ✅ | - | ✅ | - | ✅ | Enable circuit breaker |
| `circuitBreaker.threshold` | ✅ | - | ✅ | - | ✅ | Failure threshold to open circuit |
| `circuitBreaker.timeout` | ✅ | - | ✅ | - | ✅ | Time to wait before half-open |
| `circuitBreaker.halfOpenRequests` | ✅ | - | ✅ | - | ✅ | Requests allowed in half-open state |

### Request Limits Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `requestLimits.maxBodySize` | ✅ | ✅ | ✅ | ✅ | ✅ | Maximum request body size in bytes |
| `requestLimits.maxHeaderSize` | ✅ | ✅ | ✅ | ✅ | ✅ | Maximum total header size in bytes |

### CORS Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `cors.allowOrigins` | ✅ | ✅ | - | ✅ | - | Allowed origins |
| `cors.allowMethods` | ✅ | ✅ | - | ✅ | - | Allowed HTTP methods |
| `cors.allowHeaders` | ✅ | ✅ | - | ✅ | - | Allowed request headers |
| `cors.exposeHeaders` | ✅ | ✅ | - | ✅ | - | Headers exposed to browser |
| `cors.maxAge` | ✅ | ✅ | - | ✅ | - | Preflight cache duration in seconds |
| `cors.allowCredentials` | ✅ | ✅ | - | ✅ | - | Allow credentials |

### Observability Configuration

| Option | Global | Route | Backend | Description |
|--------|:------:|:-----:|:-------:|-------------|
| `observability.metrics.enabled` | ✅ | - | - | Enable Prometheus metrics |
| `observability.metrics.path` | ✅ | - | - | Metrics endpoint path |
| `observability.metrics.port` | ✅ | - | - | Metrics endpoint port |
| `observability.tracing.enabled` | ✅ | - | - | Enable distributed tracing |
| `observability.tracing.samplingRate` | ✅ | - | - | Trace sampling rate (0.0-1.0) |
| `observability.tracing.otlpEndpoint` | ✅ | - | - | OTLP collector endpoint |
| `observability.tracing.serviceName` | ✅ | - | - | Service name for traces |
| `observability.logging.level` | ✅ | - | - | Log level (debug, info, warn, error) |
| `observability.logging.format` | ✅ | - | - | Log format (json, console) |
| `observability.logging.output` | ✅ | - | - | Log output destination |

### Authentication Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `authentication.enabled` | ✅ | ✅ | - | ✅ | - | Enable authentication |
| `authentication.allowAnonymous` | ✅ | ✅ | - | ✅ | - | Allow anonymous access |
| `authentication.skipPaths` | ✅ | ✅ | - | ✅ | - | Paths to skip authentication |
| `authentication.jwt.enabled` | ✅ | ✅ | - | ✅ | - | Enable JWT authentication |
| `authentication.jwt.issuer` | ✅ | ✅ | - | ✅ | - | Expected token issuer |
| `authentication.jwt.audience` | ✅ | ✅ | - | ✅ | - | Expected token audience |
| `authentication.jwt.jwksUrl` | ✅ | ✅ | - | ✅ | - | JWKS URL for key retrieval |
| `authentication.jwt.secret` | ✅ | ✅ | - | ✅ | - | Secret for HMAC algorithms |
| `authentication.jwt.publicKey` | ✅ | ✅ | - | ✅ | - | Public key for RSA/ECDSA |
| `authentication.jwt.algorithm` | ✅ | ✅ | - | ✅ | - | Expected signing algorithm |
| `authentication.jwt.claimMapping.roles` | ✅ | ✅ | - | ✅ | - | Claim containing roles |
| `authentication.jwt.claimMapping.permissions` | ✅ | ✅ | - | ✅ | - | Claim containing permissions |
| `authentication.jwt.claimMapping.groups` | ✅ | ✅ | - | ✅ | - | Claim containing groups |
| `authentication.jwt.claimMapping.scopes` | ✅ | ✅ | - | ✅ | - | Claim containing scopes |
| `authentication.jwt.claimMapping.email` | ✅ | ✅ | - | ✅ | - | Claim containing email |
| `authentication.jwt.claimMapping.name` | ✅ | ✅ | - | ✅ | - | Claim containing name |
| `authentication.apiKey.enabled` | ✅ | ✅ | - | ✅ | - | Enable API key authentication |
| `authentication.apiKey.header` | ✅ | ✅ | - | ✅ | - | Header name for API key |
| `authentication.apiKey.query` | ✅ | ✅ | - | ✅ | - | Query parameter for API key |
| `authentication.apiKey.hashAlgorithm` | ✅ | ✅ | - | ✅ | - | Hash algorithm for stored keys |
| `authentication.apiKey.vaultPath` | ✅ | ✅ | - | ✅ | - | Vault path for API keys |
| `authentication.mtls.enabled` | ✅ | ✅ | - | ✅ | - | Enable mTLS authentication |
| `authentication.mtls.caFile` | ✅ | ✅ | - | ✅ | - | CA certificate path |
| `authentication.mtls.extractIdentity` | ✅ | ✅ | - | ✅ | - | How to extract identity from cert |
| `authentication.mtls.allowedCNs` | ✅ | ✅ | - | ✅ | - | Allowed common names |
| `authentication.mtls.allowedOUs` | ✅ | ✅ | - | ✅ | - | Allowed organizational units |
| `authentication.oidc.enabled` | ✅ | ✅ | - | ✅ | - | Enable OIDC authentication |
| `authentication.oidc.providers[].name` | ✅ | ✅ | - | ✅ | - | Provider name |
| `authentication.oidc.providers[].issuerUrl` | ✅ | ✅ | - | ✅ | - | OIDC issuer URL |
| `authentication.oidc.providers[].clientId` | ✅ | ✅ | - | ✅ | - | OIDC client ID |
| `authentication.oidc.providers[].clientSecret` | ✅ | ✅ | - | ✅ | - | OIDC client secret |
| `authentication.oidc.providers[].clientSecretRef.name` | ✅ | ✅ | - | ✅ | - | Kubernetes secret name for client secret |
| `authentication.oidc.providers[].clientSecretRef.key` | ✅ | ✅ | - | ✅ | - | Kubernetes secret key for client secret |
| `authentication.oidc.providers[].scopes` | ✅ | ✅ | - | ✅ | - | Scopes to request |
| `backends[].authentication.type` | - | - | ✅ | - | ✅ | Backend authentication type (jwt, basic, mtls) |
| `backends[].authentication.jwt.enabled` | - | - | ✅ | - | ✅ | Enable JWT authentication for backend |
| `backends[].authentication.jwt.tokenSource` | - | - | ✅ | - | ✅ | Token source (static, vault, oidc) |
| `backends[].authentication.jwt.staticToken` | - | - | ✅ | - | ✅ | Static JWT token (dev only) |
| `backends[].authentication.jwt.vaultPath` | - | - | ✅ | - | ✅ | Vault path for JWT token |
| `backends[].authentication.jwt.oidc.issuerUrl` | - | - | ✅ | - | ✅ | OIDC issuer URL for backend auth |
| `backends[].authentication.jwt.oidc.clientId` | - | - | ✅ | - | ✅ | OIDC client ID for backend auth |
| `backends[].authentication.jwt.oidc.clientSecret` | - | - | ✅ | - | ✅ | OIDC client secret for backend auth |
| `backends[].authentication.jwt.oidc.clientSecretRef.name` | - | - | ✅ | - | ✅ | Kubernetes secret name for backend OIDC client secret |
| `backends[].authentication.jwt.oidc.clientSecretRef.key` | - | - | ✅ | - | ✅ | Kubernetes secret key for backend OIDC client secret |
| `backends[].authentication.jwt.oidc.scopes` | - | - | ✅ | - | ✅ | OIDC scopes for backend auth |
| `backends[].authentication.jwt.oidc.tokenCacheTTL` | - | - | ✅ | - | ✅ | TTL for cached backend tokens |
| `backends[].authentication.jwt.headerName` | - | - | ✅ | - | ✅ | Header name for backend JWT token |
| `backends[].authentication.jwt.headerPrefix` | - | - | ✅ | - | ✅ | Header prefix for backend JWT token |
| `backends[].authentication.basic.enabled` | - | - | ✅ | - | ✅ | Enable Basic authentication for backend |
| `backends[].authentication.basic.username` | - | - | ✅ | - | ✅ | Username for backend Basic auth |
| `backends[].authentication.basic.password` | - | - | ✅ | - | ✅ | Password for backend Basic auth |
| `backends[].authentication.basic.vaultPath` | - | - | ✅ | - | ✅ | Vault path for backend credentials |
| `backends[].authentication.basic.usernameKey` | - | - | ✅ | - | ✅ | Vault key for backend username |
| `backends[].authentication.basic.passwordKey` | - | - | ✅ | - | ✅ | Vault key for backend password |
| `backends[].authentication.mtls.enabled` | - | - | ✅ | - | ✅ | Enable mTLS authentication for backend |
| `backends[].authentication.mtls.certFile` | - | - | ✅ | - | ✅ | Client certificate file for backend |
| `backends[].authentication.mtls.keyFile` | - | - | ✅ | - | ✅ | Client private key file for backend |
| `backends[].authentication.mtls.caFile` | - | - | ✅ | - | ✅ | CA certificate for backend server verification |
| `backends[].authentication.mtls.vault.enabled` | - | - | ✅ | - | ✅ | Enable Vault-based certificate management for backend |
| `backends[].authentication.mtls.vault.pkiMount` | - | - | ✅ | - | ✅ | Vault PKI mount path for backend |
| `backends[].authentication.mtls.vault.role` | - | - | ✅ | - | ✅ | Vault PKI role name for backend |
| `backends[].authentication.mtls.vault.commonName` | - | - | ✅ | - | ✅ | Certificate common name for backend |
| `backends[].authentication.mtls.vault.altNames` | - | - | ✅ | - | ✅ | Certificate alternative names for backend |
| `backends[].authentication.mtls.vault.ttl` | - | - | ✅ | - | ✅ | Certificate TTL for backend |

### Authorization Configuration

| Option | Global | Route | Backend | CRD Route | Description |
|--------|:------:|:-----:|:-------:|:---------:|-------------|
| `authorization.enabled` | ✅ | ✅ | - | ✅ | Enable authorization |
| `authorization.defaultPolicy` | ✅ | ✅ | - | ✅ | Default policy (allow/deny) |
| `authorization.skipPaths` | ✅ | ✅ | - | ✅ | Paths to skip authorization |
| `authorization.cache.enabled` | ✅ | ✅ | - | ✅ | Enable authorization caching |
| `authorization.cache.ttl` | ✅ | ✅ | - | ✅ | Cache TTL |
| `authorization.cache.maxSize` | ✅ | ✅ | - | ✅ | Maximum cache entries |
| `authorization.cache.type` | ✅ | ✅ | - | ✅ | Cache type (memory, redis) |
| `authorization.rbac.enabled` | ✅ | ✅ | - | ✅ | Enable RBAC |
| `authorization.rbac.policies[].name` | ✅ | ✅ | - | ✅ | Policy name |
| `authorization.rbac.policies[].roles` | ✅ | ✅ | - | ✅ | Roles that match policy |
| `authorization.rbac.policies[].resources` | ✅ | ✅ | - | ✅ | Resources policy applies to |
| `authorization.rbac.policies[].actions` | ✅ | ✅ | - | ✅ | Actions policy allows |
| `authorization.rbac.policies[].effect` | ✅ | ✅ | - | ✅ | Policy effect (allow/deny) |
| `authorization.rbac.policies[].priority` | ✅ | ✅ | - | ✅ | Policy priority |
| `authorization.rbac.roleHierarchy` | ✅ | - | - | ✅ | Role inheritance definitions |
| `authorization.abac.enabled` | ✅ | ✅ | - | ✅ | Enable ABAC |
| `authorization.abac.policies[].name` | ✅ | ✅ | - | ✅ | Policy name |
| `authorization.abac.policies[].expression` | ✅ | ✅ | - | ✅ | CEL expression for policy |
| `authorization.abac.policies[].resources` | ✅ | ✅ | - | ✅ | Resources policy applies to |
| `authorization.abac.policies[].actions` | ✅ | ✅ | - | ✅ | Actions policy applies to |
| `authorization.abac.policies[].effect` | ✅ | ✅ | - | ✅ | Policy effect (allow/deny) |
| `authorization.abac.policies[].priority` | ✅ | ✅ | - | ✅ | Policy priority |
| `authorization.external.enabled` | ✅ | ✅ | - | ✅ | Enable external authorization |
| `authorization.external.opa.url` | ✅ | ✅ | - | ✅ | OPA server URL |
| `authorization.external.opa.policy` | ✅ | ✅ | - | ✅ | OPA policy path |
| `authorization.external.opa.headers` | ✅ | ✅ | - | ✅ | Additional headers for OPA |
| `authorization.external.timeout` | ✅ | ✅ | - | ✅ | External authz timeout |
| `authorization.external.failOpen` | ✅ | ✅ | - | ✅ | Allow on external authz failure |

### Security Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `security.enabled` | ✅ | ✅ | - | ✅ | - | Enable security features |
| `security.headers.enabled` | ✅ | ✅ | - | ✅ | - | Enable security headers |
| `security.headers.xFrameOptions` | ✅ | ✅ | - | ✅ | - | X-Frame-Options header value |
| `security.headers.xContentTypeOptions` | ✅ | ✅ | - | ✅ | - | X-Content-Type-Options header |
| `security.headers.xXSSProtection` | ✅ | ✅ | - | ✅ | - | X-XSS-Protection header |
| `security.headers.customHeaders` | ✅ | ✅ | - | ✅ | - | Custom security headers |
| `security.hsts.enabled` | ✅ | ✅ | - | ✅ | - | Enable HSTS |
| `security.hsts.maxAge` | ✅ | ✅ | - | ✅ | - | HSTS max-age in seconds |
| `security.hsts.includeSubDomains` | ✅ | ✅ | - | ✅ | - | Include subdomains |
| `security.hsts.preload` | ✅ | ✅ | - | ✅ | - | Enable preload |
| `security.csp.enabled` | ✅ | ✅ | - | ✅ | - | Enable CSP |
| `security.csp.policy` | ✅ | ✅ | - | ✅ | - | CSP policy string |
| `security.csp.reportOnly` | ✅ | ✅ | - | ✅ | - | Report-only mode |
| `security.csp.reportUri` | ✅ | ✅ | - | ✅ | - | CSP violation report URI |
| `security.referrerPolicy` | ✅ | ✅ | - | ✅ | - | Referrer-Policy header value |

### Audit Configuration

| Option | Global | Route | Backend | Description |
|--------|:------:|:-----:|:-------:|-------------|
| `audit.enabled` | ✅ | - | - | Enable audit logging |
| `audit.level` | ✅ | - | - | Minimum audit level |
| `audit.output` | ✅ | - | - | Output destination |
| `audit.format` | ✅ | - | - | Output format (json, text) |
| `audit.skipPaths` | ✅ | - | - | Paths to skip auditing |
| `audit.redactFields` | ✅ | - | - | Fields to redact from logs |
| `audit.events.authentication` | ✅ | - | - | Audit authentication events |
| `audit.events.authorization` | ✅ | - | - | Audit authorization events |
| `audit.events.request` | ✅ | - | - | Audit request events |
| `audit.events.response` | ✅ | - | - | Audit response events |
| `audit.events.configuration` | ✅ | - | - | Audit configuration changes |
| `audit.events.security` | ✅ | - | - | Audit security events |

### Backend Authentication Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `backends[].authentication.type` | - | - | ✅ | - | ✅ | Authentication type (jwt, basic, mtls) |
| `backends[].authentication.jwt.enabled` | - | - | ✅ | - | ✅ | Enable JWT authentication |
| `backends[].authentication.jwt.tokenSource` | - | - | ✅ | - | ✅ | Token source (static, vault, oidc) |
| `backends[].authentication.jwt.staticToken` | - | - | ✅ | - | ✅ | Static JWT token (development only) |
| `backends[].authentication.jwt.vaultPath` | - | - | ✅ | - | ✅ | Vault path for JWT token |
| `backends[].authentication.jwt.oidc.issuerUrl` | - | - | ✅ | - | ✅ | OIDC issuer URL |
| `backends[].authentication.jwt.oidc.clientId` | - | - | ✅ | - | ✅ | OIDC client ID |
| `backends[].authentication.jwt.oidc.clientSecret` | - | - | ✅ | - | ✅ | OIDC client secret |
| `backends[].authentication.jwt.oidc.clientSecretVaultPath` | - | - | ✅ | - | ✅ | Vault path for OIDC client secret |
| `backends[].authentication.jwt.oidc.scopes` | - | - | ✅ | - | ✅ | OIDC scopes to request |
| `backends[].authentication.jwt.oidc.tokenCacheTTL` | - | - | ✅ | - | ✅ | TTL for cached tokens |
| `backends[].authentication.jwt.headerName` | - | - | ✅ | - | ✅ | Header name for JWT token (default: Authorization) |
| `backends[].authentication.jwt.headerPrefix` | - | - | ✅ | - | ✅ | Header prefix for JWT token (default: Bearer) |
| `backends[].authentication.basic.enabled` | - | - | ✅ | - | ✅ | Enable Basic authentication |
| `backends[].authentication.basic.username` | - | - | ✅ | - | ✅ | Username for Basic auth |
| `backends[].authentication.basic.password` | - | - | ✅ | - | ✅ | Password for Basic auth |
| `backends[].authentication.basic.vaultPath` | - | - | ✅ | - | ✅ | Vault path for credentials |
| `backends[].authentication.basic.usernameKey` | - | - | ✅ | - | ✅ | Vault key for username (default: username) |
| `backends[].authentication.basic.passwordKey` | - | - | ✅ | - | ✅ | Vault key for password (default: password) |
| `backends[].authentication.mtls.enabled` | - | - | ✅ | - | ✅ | Enable mTLS authentication |
| `backends[].authentication.mtls.certFile` | - | - | ✅ | - | ✅ | Client certificate file path |
| `backends[].authentication.mtls.keyFile` | - | - | ✅ | - | ✅ | Client private key file path |
| `backends[].authentication.mtls.caFile` | - | - | ✅ | - | ✅ | CA certificate for server verification |
| `backends[].authentication.mtls.vault.enabled` | - | - | ✅ | - | ✅ | Enable Vault-based certificate management |
| `backends[].authentication.mtls.vault.pkiMount` | - | - | ✅ | - | ✅ | Vault PKI mount path |
| `backends[].authentication.mtls.vault.role` | - | - | ✅ | - | ✅ | Vault PKI role name |
| `backends[].authentication.mtls.vault.commonName` | - | - | ✅ | - | ✅ | Certificate common name |
| `backends[].authentication.mtls.vault.altNames` | - | - | ✅ | - | ✅ | Certificate alternative names |
| `backends[].authentication.mtls.vault.ttl` | - | - | ✅ | - | ✅ | Certificate TTL |

### HTTP Transform Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `routes[].transform.request.passthroughBody` | - | ✅ | - | ✅ | - | Pass request body unchanged |
| `routes[].transform.request.bodyTemplate` | - | ✅ | - | ✅ | - | Go template for request body |
| `routes[].transform.request.staticHeaders` | - | ✅ | - | ✅ | - | Static headers to add |
| `routes[].transform.request.dynamicHeaders` | - | ✅ | - | ✅ | - | Dynamic headers from context |
| `routes[].transform.request.injectFields` | - | ✅ | - | ✅ | - | Fields to inject into body |
| `routes[].transform.request.removeFields` | - | ✅ | - | ✅ | - | Fields to remove from body |
| `routes[].transform.request.defaultValues` | - | ✅ | - | ✅ | - | Default values for missing fields |
| `routes[].transform.request.validateBeforeTransform` | - | ✅ | - | ✅ | - | Validate before transformation |
| `routes[].transform.response.allowFields` | - | ✅ | - | ✅ | - | Fields to include (whitelist) |
| `routes[].transform.response.denyFields` | - | ✅ | - | ✅ | - | Fields to exclude (blacklist) |
| `routes[].transform.response.fieldMappings` | - | ✅ | - | ✅ | - | Field rename mappings |
| `routes[].transform.response.groupFields` | - | ✅ | - | ✅ | - | Group fields into objects |
| `routes[].transform.response.flattenFields` | - | ✅ | - | ✅ | - | Flatten nested objects |
| `routes[].transform.response.arrayOperations` | - | ✅ | - | ✅ | - | Array manipulation operations |
| `routes[].transform.response.template` | - | ✅ | - | ✅ | - | Go template for response |
| `routes[].transform.response.mergeStrategy` | - | ✅ | - | ✅ | - | Merge strategy (deep, shallow, replace) |
| `backends[].transform.request.template` | - | - | ✅ | - | ✅ | Go template for request transformation |
| `backends[].transform.request.headers.set` | - | - | ✅ | - | ✅ | Set request headers |
| `backends[].transform.request.headers.add` | - | - | ✅ | - | ✅ | Add request headers |
| `backends[].transform.request.headers.remove` | - | - | ✅ | - | ✅ | Remove request headers |
| `backends[].transform.response.allowFields` | - | - | ✅ | - | ✅ | Fields to allow in response |
| `backends[].transform.response.denyFields` | - | - | ✅ | - | ✅ | Fields to deny in response |
| `backends[].transform.response.fieldMappings` | - | - | ✅ | - | ✅ | Field name mappings |
| `backends[].transform.response.headers.set` | - | - | ✅ | - | ✅ | Set response headers |
| `backends[].transform.response.headers.add` | - | - | ✅ | - | ✅ | Add response headers |
| `backends[].transform.response.headers.remove` | - | - | ✅ | - | ✅ | Remove response headers |

### gRPC Transform Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `grpcRoutes[].transform.request.injectFieldMask` | - | ✅ | - | ✅ | - | FieldMask to inject |
| `grpcRoutes[].transform.request.staticMetadata` | - | ✅ | - | ✅ | - | Static metadata to add |
| `grpcRoutes[].transform.request.dynamicMetadata` | - | ✅ | - | ✅ | - | Dynamic metadata from context |
| `grpcRoutes[].transform.request.injectFields` | - | ✅ | - | ✅ | - | Fields to inject |
| `grpcRoutes[].transform.request.removeFields` | - | ✅ | - | ✅ | - | Fields to remove |
| `grpcRoutes[].transform.request.defaultValues` | - | ✅ | - | ✅ | - | Default values |
| `grpcRoutes[].transform.request.validateBeforeTransform` | - | ✅ | - | ✅ | - | Validate before transformation |
| `grpcRoutes[].transform.request.injectDeadline` | - | ✅ | - | ✅ | - | Deadline to inject |
| `grpcRoutes[].transform.request.authorityOverride` | - | ✅ | - | ✅ | - | Override :authority header |
| `grpcRoutes[].transform.response.fieldMask` | - | ✅ | - | ✅ | - | FieldMask for filtering |
| `grpcRoutes[].transform.response.fieldMappings` | - | ✅ | - | ✅ | - | Field rename mappings |
| `grpcRoutes[].transform.response.repeatedFieldOps` | - | ✅ | - | ✅ | - | Operations on repeated fields |
| `grpcRoutes[].transform.response.mapFieldOps` | - | ✅ | - | ✅ | - | Operations on map fields |
| `grpcRoutes[].transform.response.preserveUnknownFields` | - | ✅ | - | ✅ | - | Preserve unknown fields |
| `grpcRoutes[].transform.response.trailerMetadata` | - | ✅ | - | ✅ | - | Metadata for response trailers |
| `grpcRoutes[].transform.response.streaming.perMessageTransform` | - | ✅ | - | ✅ | - | Transform each message |
| `grpcRoutes[].transform.response.streaming.aggregate` | - | ✅ | - | ✅ | - | Aggregate messages |
| `grpcRoutes[].transform.response.streaming.filterCondition` | - | ✅ | - | ✅ | - | CEL filter for messages |
| `grpcRoutes[].transform.response.streaming.bufferSize` | - | ✅ | - | ✅ | - | Message buffer size |
| `grpcRoutes[].transform.response.streaming.rateLimit` | - | ✅ | - | ✅ | - | Max messages per second |
| `grpcRoutes[].transform.response.streaming.messageTimeout` | - | ✅ | - | ✅ | - | Per-message timeout |
| `grpcRoutes[].transform.response.streaming.totalTimeout` | - | ✅ | - | ✅ | - | Total streaming timeout |
| `grpcBackends[].transform.fieldMask.paths` | - | - | ✅ | - | ✅ | Field paths to include |
| `grpcBackends[].transform.metadata.static` | - | - | ✅ | - | ✅ | Static metadata values |
| `grpcBackends[].transform.metadata.dynamic` | - | - | ✅ | - | ✅ | Dynamic metadata templates |

### Cache Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `routes[].cache.enabled` | - | ✅ | - | ✅ | - | Enable caching |
| `routes[].cache.type` | - | ✅ | - | ✅ | - | Cache type (memory, redis) |
| `routes[].cache.ttl` | - | ✅ | - | ✅ | - | Cache TTL |
| `routes[].cache.maxEntries` | - | ✅ | - | ✅ | - | Max entries (memory cache) |
| `routes[].cache.honorCacheControl` | - | ✅ | - | ✅ | - | Honor Cache-Control headers |
| `routes[].cache.staleWhileRevalidate` | - | ✅ | - | ✅ | - | Stale-while-revalidate duration |
| `routes[].cache.negativeCacheTTL` | - | ✅ | - | ✅ | - | TTL for error responses |
| `routes[].cache.redis.url` | - | ✅ | - | ✅ | - | Redis connection URL |
| `routes[].cache.redis.poolSize` | - | ✅ | - | ✅ | - | Redis connection pool size |
| `routes[].cache.redis.connectTimeout` | - | ✅ | - | ✅ | - | Redis connect timeout |
| `routes[].cache.redis.readTimeout` | - | ✅ | - | ✅ | - | Redis read timeout |
| `routes[].cache.redis.writeTimeout` | - | ✅ | - | ✅ | - | Redis write timeout |
| `routes[].cache.redis.keyPrefix` | - | ✅ | - | ✅ | - | Redis key prefix |
| `routes[].cache.redis.tls.*` | - | ✅ | - | ✅ | - | Redis TLS configuration |
| `routes[].cache.redis.retry.maxRetries` | - | ✅ | - | ✅ | - | Max connection retries |
| `routes[].cache.redis.retry.initialBackoff` | - | ✅ | - | ✅ | - | Initial retry backoff |
| `routes[].cache.redis.retry.maxBackoff` | - | ✅ | - | ✅ | - | Max retry backoff |
| `routes[].cache.keyConfig.includeMethod` | - | ✅ | - | ✅ | - | Include method in cache key |
| `routes[].cache.keyConfig.includePath` | - | ✅ | - | ✅ | - | Include path in cache key |
| `routes[].cache.keyConfig.includeQueryParams` | - | ✅ | - | ✅ | - | Query params to include |
| `routes[].cache.keyConfig.includeHeaders` | - | ✅ | - | ✅ | - | Headers to include |
| `routes[].cache.keyConfig.includeBodyHash` | - | ✅ | - | ✅ | - | Include body hash |
| `routes[].cache.keyConfig.keyTemplate` | - | ✅ | - | ✅ | - | Custom key template |
| `grpcRoutes[].cache.*` | - | ✅ | - | ✅ | - | Same as HTTP routes cache |
| `backends[].cache.enabled` | - | - | ✅ | - | ✅ | Enable caching |
| `backends[].cache.ttl` | - | - | ✅ | - | ✅ | Cache time-to-live |
| `backends[].cache.keyComponents` | - | - | ✅ | - | ✅ | Components for cache key generation |
| `backends[].cache.staleWhileRevalidate` | - | - | ✅ | - | ✅ | Serve stale while revalidating |
| `backends[].cache.type` | - | - | ✅ | - | ✅ | Cache type (memory, redis) |
| `grpcBackends[].cache.enabled` | - | - | ✅ | - | ✅ | Enable caching |
| `grpcBackends[].cache.ttl` | - | - | ✅ | - | ✅ | Cache time-to-live |
| `grpcBackends[].cache.keyComponents` | - | - | ✅ | - | ✅ | Components for cache key generation |
| `grpcBackends[].cache.staleWhileRevalidate` | - | - | ✅ | - | ✅ | Serve stale while revalidating |
| `grpcBackends[].cache.type` | - | - | ✅ | - | ✅ | Cache type (memory, redis) |

### Encoding Configuration

| Option | Global | Route | Backend | CRD Route | CRD Backend | Description |
|--------|:------:|:-----:|:-------:|:---------:|:-----------:|-------------|
| `routes[].encoding.requestEncoding` | - | ✅ | - | ✅ | - | Request encoding (json, xml, yaml, protobuf) |
| `routes[].encoding.responseEncoding` | - | ✅ | - | ✅ | - | Response encoding |
| `routes[].encoding.enableContentNegotiation` | - | ✅ | - | ✅ | - | Enable content negotiation |
| `routes[].encoding.supportedContentTypes` | - | ✅ | - | ✅ | - | Supported content types |
| `routes[].encoding.passthrough` | - | ✅ | - | ✅ | - | Pass content unchanged |
| `routes[].encoding.json.emitDefaults` | - | ✅ | - | ✅ | - | Include default values |
| `routes[].encoding.json.useProtoNames` | - | ✅ | - | ✅ | - | Use proto field names |
| `routes[].encoding.json.enumAsIntegers` | - | ✅ | - | ✅ | - | Encode enums as integers |
| `routes[].encoding.json.int64AsStrings` | - | ✅ | - | ✅ | - | Encode int64 as strings |
| `routes[].encoding.json.prettyPrint` | - | ✅ | - | ✅ | - | Pretty print JSON |
| `routes[].encoding.protobuf.useJSONEncoding` | - | ✅ | - | ✅ | - | Use JSON for protobuf |
| `routes[].encoding.protobuf.descriptorSource` | - | ✅ | - | ✅ | - | Descriptor source (reflection, file) |
| `routes[].encoding.protobuf.descriptorFile` | - | ✅ | - | ✅ | - | Path to descriptor file |
| `routes[].encoding.compression.enabled` | - | ✅ | - | ✅ | - | Enable compression |
| `routes[].encoding.compression.algorithms` | - | ✅ | - | ✅ | - | Compression algorithms |
| `routes[].encoding.compression.minSize` | - | ✅ | - | ✅ | - | Min size to compress |
| `routes[].encoding.compression.level` | - | ✅ | - | ✅ | - | Compression level |
| `grpcRoutes[].encoding.*` | - | ✅ | - | ✅ | - | Same as HTTP routes encoding |
| `backends[].encoding.request.contentType` | - | - | ✅ | - | ✅ | Request content type |
| `backends[].encoding.request.compression` | - | - | ✅ | - | ✅ | Request compression algorithm |
| `backends[].encoding.response.contentType` | - | - | ✅ | - | ✅ | Response content type |
| `backends[].encoding.response.compression` | - | - | ✅ | - | ✅ | Response compression algorithm |
| `grpcBackends[].encoding.request.contentType` | - | - | ✅ | - | ✅ | Request content type |
| `grpcBackends[].encoding.request.compression` | - | - | ✅ | - | ✅ | Request compression algorithm |
| `grpcBackends[].encoding.response.contentType` | - | - | ✅ | - | ✅ | Response content type |
| `grpcBackends[].encoding.response.compression` | - | - | ✅ | - | ✅ | Response compression algorithm |

### Configuration Level Examples

#### Global Level Configuration

```yaml
spec:
  # Global rate limiting - applies to all routes
  rateLimit:
    enabled: true
    requestsPerSecond: 100
    burst: 200
    perClient: true
  
  # Global max sessions - applies to all routes
  maxSessions:
    enabled: true
    maxConcurrent: 10000
    queueSize: 1000
    queueTimeout: 30s
  
  # Global circuit breaker
  circuitBreaker:
    enabled: true
    threshold: 5
    timeout: 30s
  
  # Global authentication
  authentication:
    enabled: true
    jwt:
      enabled: true
      issuer: "https://auth.example.com"
  
  # Global request limits
  requestLimits:
    maxBodySize: 10485760    # 10MB
    maxHeaderSize: 1048576   # 1MB
  
  # Global CORS configuration
  cors:
    allowOrigins: ["*"]
    allowMethods: ["GET", "POST", "PUT", "DELETE"]
    allowHeaders: ["Content-Type", "Authorization"]
  
  # Global security headers
  security:
    enabled: true
    headers:
      enabled: true
      xFrameOptions: "DENY"
      xContentTypeOptions: "nosniff"
```

#### Route Level Override

```yaml
spec:
  routes:
    - name: high-traffic-api
      match:
        - uri:
            prefix: /api/v1/public
      route:
        - destination:
            host: backend
            port: 8080
      # Route-level rate limit overrides global
      rateLimit:
        enabled: true
        requestsPerSecond: 1000  # Higher limit for this route
        burst: 2000
      # Route-level authentication override
      authentication:
        enabled: false  # Disable auth for public API
    
    - name: upload-api
      match:
        - uri:
            prefix: /api/v1/upload
      route:
        - destination:
            host: upload-backend
            port: 8080
      # Route-level request limits override global
      requestLimits:
        maxBodySize: 104857600   # 100MB for file uploads
        maxHeaderSize: 2097152   # 2MB for headers
      # Route-level CORS override global
      cors:
        allowOrigins: ["https://app.example.com"]
        allowMethods: ["POST", "OPTIONS"]
        allowCredentials: true
      # Route-level security headers override global
      security:
        enabled: true
        headers:
          enabled: true
          xFrameOptions: "SAMEORIGIN"
          customHeaders:
            X-Upload-Policy: "strict"
```

#### Backend Level Configuration

```yaml
spec:
  backends:
    - name: secure-backend
      hosts:
        - address: secure.example.com
          port: 443
      # Backend-specific TLS
      tls:
        enabled: true
        mode: MUTUAL
        caFile: /etc/ssl/certs/backend-ca.crt
        certFile: /etc/ssl/certs/client.crt
        keyFile: /etc/ssl/private/client.key
      # Backend-specific health check
      healthCheck:
        path: /health
        interval: 5s
        timeout: 2s
      # Backend-specific circuit breaker
      circuitBreaker:
        enabled: true
        threshold: 3
        timeout: 15s
        halfOpenRequests: 2
      # Backend authentication with JWT from OIDC
      authentication:
        type: jwt
        jwt:
          enabled: true
          tokenSource: oidc
          oidc:
            issuerUrl: https://auth.example.com/realms/backend
            clientId: gateway-backend-client
            clientSecret: backend-secret
            scopes: ["backend-access"]
          headerName: Authorization
          headerPrefix: Bearer
    
    - name: legacy-backend
      hosts:
        - address: legacy.internal.com
          port: 8080
      # Backend authentication with Basic auth from Vault
      authentication:
        type: basic
        basic:
          enabled: true
          vaultPath: secret/legacy-backend
          usernameKey: username
          passwordKey: password
    
    - name: mtls-backend
      hosts:
        - address: mtls.example.com
          port: 443
      # Backend authentication with mTLS using Vault PKI
      authentication:
        type: mtls
        mtls:
          enabled: true
          vault:
            enabled: true
            pkiMount: pki
            role: backend-client
            commonName: gateway.example.com
    
    - name: capacity-aware-backend
      hosts:
        - address: 10.0.1.30
          port: 8080
        - address: 10.0.1.31
          port: 8080
      # Backend-level max sessions
      maxSessions:
        enabled: true
        maxConcurrent: 500
      # Backend-level rate limiting
      rateLimit:
        enabled: true
        requestsPerSecond: 100
        burst: 200
      # Capacity-aware load balancing
      loadBalancer:
        algorithm: leastConn
      # Health check
      healthCheck:
        path: /health
        interval: 10s
        timeout: 5s
            ttl: 24h
      # TLS configuration for mTLS
      tls:
        enabled: true
        mode: MUTUAL
        vault:
          enabled: true
          pkiMount: pki
          role: backend-client
          commonName: gateway.example.com
```

## 🚦 Traffic Management

The AV API Gateway provides comprehensive traffic management capabilities including rate limiting, max sessions control, circuit breaking, and intelligent load balancing.

### Max Sessions Control

Max sessions control limits the number of concurrent connections to prevent resource exhaustion and ensure fair resource allocation. It can be configured at global, route, and backend levels.

#### Global Max Sessions

Configure global max sessions that apply to all routes:

```yaml
spec:
  maxSessions:
    enabled: true
    maxConcurrent: 10000     # Maximum concurrent connections
    queueSize: 1000          # Queue size for waiting connections
    queueTimeout: 30s        # Timeout for queued connections
```

#### Route-Level Max Sessions

Override global settings for specific routes:

```yaml
spec:
  routes:
    - name: high-traffic-api
      match:
        - uri:
            prefix: /api/v1/public
      maxSessions:
        enabled: true
        maxConcurrent: 1000    # Lower limit for this route
        queueSize: 100
        queueTimeout: 10s
      route:
        - destination:
            host: backend
            port: 8080
```

#### Backend-Level Max Sessions

Control concurrent connections to backend hosts:

```yaml
spec:
  backends:
    - name: api-backend
      hosts:
        - address: 10.0.1.10
          port: 8080
        - address: 10.0.1.11
          port: 8080
      maxSessions:
        enabled: true
        maxConcurrent: 500     # Per host limit
      loadBalancer:
        algorithm: leastConn   # Capacity-aware load balancing
```

### Backend Rate Limiting

Backend rate limiting controls the rate of requests sent to individual backend hosts, preventing backend overload and ensuring fair distribution of load.

#### Backend Rate Limit Configuration

```yaml
spec:
  backends:
    - name: rate-limited-backend
      hosts:
        - address: 10.0.1.20
          port: 8080
        - address: 10.0.1.21
          port: 8080
      rateLimit:
        enabled: true
        requestsPerSecond: 100   # Requests per second per host
        burst: 200               # Burst capacity per host
      loadBalancer:
        algorithm: roundRobin
```

### Load Balancer Integration

The load balancer integrates with max sessions and rate limiting to make intelligent routing decisions:

#### Capacity-Aware Load Balancing

```yaml
spec:
  backends:
    - name: smart-backend
      hosts:
        - address: host1.example.com
          port: 8080
          weight: 1
        - address: host2.example.com
          port: 8080
          weight: 2
      maxSessions:
        enabled: true
        maxConcurrent: 500
      rateLimit:
        enabled: true
        requestsPerSecond: 100
        burst: 200
      loadBalancer:
        algorithm: leastConn     # Considers both load and capacity
```

#### Load Balancing Algorithms

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| `roundRobin` | Distributes requests evenly across hosts | Uniform backend capacity |
| `weighted` | Distributes based on host weights | Different backend capacities |
| `leastConn` | Routes to host with fewest active connections | Capacity-aware routing |
| `random` | Random selection with optional weights | Simple load distribution |

### Behavior When Limits Are Exceeded

#### Max Sessions Exceeded

When max sessions limit is reached:

1. **Queue Available**: New connections are queued up to `queueSize`
2. **Queue Full**: New connections are rejected with HTTP 503 (Service Unavailable)
3. **Queue Timeout**: Queued connections timeout after `queueTimeout`

#### Rate Limit Exceeded

When rate limit is exceeded:

1. **Backend Level**: Load balancer tries next available host
2. **Global/Route Level**: Request is rejected with HTTP 429 (Too Many Requests)
3. **Recovery**: Limits reset based on token bucket algorithm

#### Circuit Breaker Integration

Max sessions and rate limiting work with circuit breakers:

```yaml
spec:
  backends:
    - name: resilient-backend
      hosts:
        - address: backend.example.com
          port: 8080
      maxSessions:
        enabled: true
        maxConcurrent: 500
      rateLimit:
        enabled: true
        requestsPerSecond: 100
        burst: 200
      circuitBreaker:
        enabled: true
        threshold: 5
        timeout: 30s
        halfOpenRequests: 3
```

### Monitoring and Metrics

Traffic management features expose comprehensive metrics:

```
# Max sessions metrics
gateway_max_sessions_active{level, name}
gateway_max_sessions_queued{level, name}
gateway_max_sessions_rejected_total{level, name}
gateway_max_sessions_queue_timeout_total{level, name}

# Backend rate limit metrics
gateway_backend_rate_limit_requests_total{backend, host, status}
gateway_backend_rate_limit_tokens_available{backend, host}

# Load balancer metrics
gateway_load_balancer_requests_total{backend, host, algorithm}
gateway_load_balancer_host_capacity{backend, host}
gateway_load_balancer_host_active_connections{backend, host}
```

### Configuration Inheritance

Configuration follows a hierarchical inheritance model:

1. **Global** → **Route** → **Backend**
2. More specific levels override general levels
3. Disabled at any level stops inheritance

Example inheritance:

```yaml
spec:
  # Global: 10000 max sessions
  maxSessions:
    enabled: true
    maxConcurrent: 10000
  
  routes:
    - name: api-route
      # Route: Inherits global (10000)
      route:
        - destination:
            host: backend1
    
    - name: upload-route
      # Route: Overrides global (1000)
      maxSessions:
        enabled: true
        maxConcurrent: 1000
      route:
        - destination:
            host: backend2
  
  backends:
    - name: backend1
      # Backend: Inherits from route (10000)
      hosts:
        - address: host1.example.com
          port: 8080
    
    - name: backend2
      # Backend: Overrides route (500)
      maxSessions:
        enabled: true
        maxConcurrent: 500
      hosts:
        - address: host2.example.com
          port: 8080
```

## 🔐 TLS & Transport Security

The AV API Gateway provides comprehensive TLS support for secure communication between clients and the gateway, as well as between the gateway and backend services. The gateway supports multiple TLS modes, modern TLS versions, and flexible certificate management.

### TLS Modes

The gateway supports the following TLS modes:

- **SIMPLE** - Standard TLS with server certificate validation
- **MUTUAL** - Mutual TLS (mTLS) requiring client certificates
- **OPTIONAL_MUTUAL** - Optional client certificate validation
- **PASSTHROUGH** - TLS passthrough without termination
- **INSECURE** - No TLS (development only)

### TLS Versions and Cipher Suites

- **TLS 1.2** - Minimum supported version for production
- **TLS 1.3** - Recommended for enhanced security and performance
- **Configurable cipher suites** - Support for modern, secure cipher suites
- **ALPN support** - Application-Layer Protocol Negotiation for HTTP/2 and gRPC

### HTTP TLS Configuration

Configure HTTPS listeners with comprehensive TLS settings:

```yaml
spec:
  listeners:
    - name: https
      port: 8443
      protocol: HTTPS
      tls:
        mode: SIMPLE              # SIMPLE, MUTUAL, OPTIONAL_MUTUAL, INSECURE
        minVersion: TLS12         # TLS12, TLS13
        maxVersion: TLS13
        certFile: /path/to/server.crt
        keyFile: /path/to/server.key
        caFile: /path/to/ca.crt   # For client validation (MUTUAL mode)
        cipherSuites:
          - TLS_AES_128_GCM_SHA256
          - TLS_AES_256_GCM_SHA384
          - TLS_CHACHA20_POLY1305_SHA256
          - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
          - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        hsts:
          enabled: true
          maxAge: 31536000        # 1 year
          includeSubDomains: true
          preload: true
        httpsRedirect: true       # Redirect HTTP to HTTPS
        clientAuth:
          required: false         # For OPTIONAL_MUTUAL mode
          verifyClientCert: true
```

### gRPC TLS Configuration

Configure secure gRPC listeners with HTTP/2 and ALPN:

```yaml
spec:
  listeners:
    - name: grpc-secure
      port: 9443
      protocol: GRPC
      grpc:
        tls:
          enabled: true
          mode: MUTUAL
          certFile: /path/to/server.crt
          keyFile: /path/to/server.key
          caFile: /path/to/ca.crt
          requireClientCert: true
          alpn:
            - h2                  # HTTP/2 for gRPC
          clientAuth:
            verifyClientCert: true
            allowedClientCNs:
              - "client.example.com"
              - "*.clients.example.com"
        maxConcurrentStreams: 100
        keepalive:
          time: 30s
          timeout: 10s
```

### Backend TLS Configuration

Configure TLS for upstream backend connections:

```yaml
spec:
  backends:
    - name: secure-backend
      hosts:
        - address: backend.example.com
          port: 443
      tls:
        enabled: true
        mode: SIMPLE
        caFile: /path/to/backend-ca.crt
        serverName: backend.example.com  # SNI
        skipVerify: false               # Never skip in production
        clientCert:
          certFile: /path/to/client.crt
          keyFile: /path/to/client.key
        alpn:
          - h2
          - http/1.1
```

### TLS Certificate Management

#### Static Certificate Configuration

```yaml
spec:
  tls:
    certificates:
      - name: default-cert
        certFile: /etc/ssl/certs/server.crt
        keyFile: /etc/ssl/private/server.key
        domains:
          - "*.example.com"
          - "api.example.com"
      - name: client-cert
        certFile: /etc/ssl/certs/client.crt
        keyFile: /etc/ssl/private/client.key
        usage: client
```

#### Certificate Rotation

```yaml
spec:
  tls:
    certificateRotation:
      enabled: true
      checkInterval: 1h
      gracePeriod: 24h          # Grace period before expiration
      autoReload: true
```

### Security Best Practices

#### Production TLS Configuration

```yaml
spec:
  listeners:
    - name: https-production
      port: 443
      protocol: HTTPS
      tls:
        mode: SIMPLE
        minVersion: TLS12         # Minimum TLS 1.2
        maxVersion: TLS13         # Prefer TLS 1.3
        certFile: /etc/ssl/certs/server.crt
        keyFile: /etc/ssl/private/server.key
        cipherSuites:
          # TLS 1.3 cipher suites (preferred)
          - TLS_AES_256_GCM_SHA384
          - TLS_CHACHA20_POLY1305_SHA256
          - TLS_AES_128_GCM_SHA256
          # TLS 1.2 cipher suites (fallback)
          - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
          - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        hsts:
          enabled: true
          maxAge: 31536000
          includeSubDomains: true
          preload: true
        httpsRedirect: true
```

#### Security Headers

```yaml
spec:
  security:
    headers:
      - name: Strict-Transport-Security
        value: "max-age=31536000; includeSubDomains; preload"
      - name: X-Content-Type-Options
        value: "nosniff"
      - name: X-Frame-Options
        value: "DENY"
      - name: X-XSS-Protection
        value: "1; mode=block"
      - name: Referrer-Policy
        value: "strict-origin-when-cross-origin"
```

## 🔐 Vault PKI Integration

The AV API Gateway provides comprehensive integration with HashiCorp Vault's PKI (Public Key Infrastructure) secrets engine for automated certificate management. This integration enables dynamic certificate issuance, automatic renewal, and hot-reload across three key areas:

### Key Features

- **Listener-level TLS** - Gateway's own TLS certificates with automatic renewal
- **Route-level TLS** - Per-route certificates for SNI-based selection and multi-tenant deployments
- **Backend mTLS** - Client certificates for mutual TLS authentication to backends
- **Automatic Renewal** - Proactive certificate renewal before expiration
- **Hot-Reload** - Certificate updates without service restart
- **Prometheus Metrics** - Certificate expiry monitoring and renewal tracking

### Listener TLS with Vault PKI

Configure the gateway's main TLS certificate from Vault:

```yaml
spec:
  listeners:
    - name: https
      port: 8443
      protocol: HTTPS
      hosts: ["*"]
      tls:
        mode: SIMPLE
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-server
          commonName: gateway.example.com
          altNames:
            - api.example.com
            - "*.api.example.com"
          ttl: 24h
          renewBefore: 1h
        minVersion: "1.2"
        hsts:
          enabled: true
          maxAge: 31536000
```

### Route-Level TLS with Vault PKI

Configure per-route certificates for multi-tenant scenarios:

```yaml
spec:
  routes:
    - name: tenant-a-api
      match:
        - uri:
            prefix: /api/tenant-a
      route:
        - destination:
            host: backend-a
            port: 8080
      tls:
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-server
          commonName: tenant-a.example.com
          altNames:
            - api.tenant-a.example.com
          ttl: 24h
        sniHosts:
          - tenant-a.example.com
          - api.tenant-a.example.com
        minVersion: "1.2"
```

### Backend mTLS with Vault PKI

Configure client certificates for backend authentication:

```yaml
spec:
  backends:
    - name: secure-backend
      hosts:
        - address: secure-api.example.com
          port: 8443
      tls:
        enabled: true
        mode: MUTUAL
        vault:
          enabled: true
          pkiMount: pki-client
          role: gateway-client
          commonName: gateway-client.example.com
          ttl: 24h
        serverName: secure-api.example.com
```

### Certificate Monitoring

Monitor certificate expiry and renewal with Prometheus metrics:

```prometheus
# Certificate expiry timestamps
gateway_tls_certificate_expiry_seconds{type="listener",name="https"}
gateway_tls_certificate_expiry_seconds{type="route",name="tenant-a"}
gateway_tls_certificate_expiry_seconds{type="backend",name="secure-backend"}

# Certificate renewal operations
gateway_tls_certificate_renewals_total{type="listener",status="success"}
gateway_vault_pki_operations_total{operation="issue",status="success"}
```

For detailed configuration and troubleshooting, see:
- [Vault PKI Integration Guide](docs/vault-pki-integration.md)
- [Configuration Reference](docs/configuration-reference.md)
- [Troubleshooting Guide](docs/troubleshooting-vault-pki.md)

## 🔐 Vault Integration

The AV API Gateway integrates with HashiCorp Vault for secure secret management, including dynamic certificate provisioning, secret storage, and authentication token management.

### Vault Configuration

Enable and configure Vault integration:

```yaml
spec:
  vault:
    enabled: true
    address: https://vault.example.com:8200
    authMethod: kubernetes        # token, kubernetes, approle, aws, gcp
    namespace: "admin/gateway"    # Vault namespace (Vault Enterprise)
    
    # Kubernetes authentication
    kubernetes:
      role: gateway
      mountPath: kubernetes
      tokenPath: /var/run/secrets/kubernetes.io/serviceaccount/token
    
    # Token authentication (for development)
    token:
      value: "hvs.CAESIJ..."      # Direct token (not recommended for production)
      file: /etc/vault/token      # Token from file
    
    # AppRole authentication
    approle:
      roleId: "role-id-here"
      secretId: "secret-id-here"
      mountPath: approle
    
    # Connection settings
    timeout: 30s
    maxRetries: 3
    retryWaitMin: 1s
    retryWaitMax: 30s
    
    # Caching
    cache:
      enabled: true
      ttl: 5m
      maxEntries: 1000
    
    # TLS settings for Vault connection
    tls:
      caFile: /etc/ssl/certs/vault-ca.crt
      certFile: /etc/ssl/certs/vault-client.crt
      keyFile: /etc/ssl/private/vault-client.key
      skipVerify: false
```

### PKI Secrets Engine for Certificates

Configure dynamic certificate generation using Vault's PKI secrets engine:

```yaml
spec:
  vault:
    pki:
      enabled: true
      mountPath: pki
      role: gateway-certs
      
      # Certificate configuration
      certificates:
        - name: server-cert
          commonName: "gateway.example.com"
          altNames:
            - "api.example.com"
            - "*.api.example.com"
          ipSans:
            - "10.0.1.100"
          ttl: 720h                # 30 days
          renewBefore: 168h        # Renew 7 days before expiration
          keyType: rsa
          keyBits: 2048
          
        - name: client-cert
          commonName: "gateway-client"
          ttl: 168h                # 7 days
          renewBefore: 24h         # Renew 1 day before expiration
          keyType: ec
          keyBits: 256
          usage: client
      
      # Auto-renewal settings
      autoRenew:
        enabled: true
        checkInterval: 1h
        renewThreshold: 0.3       # Renew when 30% of TTL remains
```

### KV Secrets Engine

Store and retrieve secrets using Vault's KV secrets engine:

```yaml
spec:
  vault:
    kv:
      enabled: true
      mountPath: secret
      version: 2                  # KV version 1 or 2
      
      # Secret mappings
      secrets:
        - name: database-credentials
          path: database/postgres
          keys:
            - username
            - password
          refreshInterval: 1h
          
        - name: api-keys
          path: api/external
          keys:
            - stripe_key
            - sendgrid_key
          refreshInterval: 24h
        
        - name: jwt-signing-key
          path: auth/jwt
          keys:
            - private_key
            - public_key
          refreshInterval: 168h     # Weekly refresh
```

### Dynamic Secrets

Configure dynamic secrets for databases and other services:

```yaml
spec:
  vault:
    dynamic:
      enabled: true
      
      # Database dynamic secrets
      database:
        - name: postgres-creds
          mountPath: database
          role: gateway-readonly
          ttl: 1h
          maxTTL: 24h
          renewBefore: 10m
          
        - name: redis-creds
          mountPath: database
          role: gateway-cache
          ttl: 2h
          maxTTL: 12h
          renewBefore: 15m
      
      # AWS dynamic secrets
      aws:
        - name: s3-access
          mountPath: aws
          role: s3-readonly
          ttl: 1h
          maxTTL: 6h
          renewBefore: 10m
```

### Vault Authentication Methods

#### Kubernetes Authentication

```yaml
spec:
  vault:
    authMethod: kubernetes
    kubernetes:
      role: gateway
      mountPath: kubernetes
      tokenPath: /var/run/secrets/kubernetes.io/serviceaccount/token
      # Optional: custom service account
      serviceAccount: vault-auth
```

#### AppRole Authentication

```yaml
spec:
  vault:
    authMethod: approle
    approle:
      roleId: "{{ .Env.VAULT_ROLE_ID }}"
      secretId: "{{ .Env.VAULT_SECRET_ID }}"
      mountPath: approle
      wrapTTL: 300s               # Secret ID wrapping
```

#### Token Authentication

```yaml
spec:
  vault:
    authMethod: token
    token:
      # From environment variable
      value: "{{ .Env.VAULT_TOKEN }}"
      # Or from file
      file: /etc/vault/token
      # Token renewal
      renewable: true
      renewThreshold: 0.9         # Renew when 90% of TTL used
```

### Vault Secret Injection

Inject Vault secrets into gateway configuration:

```yaml
spec:
  backends:
    - name: database-backend
      hosts:
        - address: db.example.com
          port: 5432
      auth:
        type: basic
        username: "{{ vault.secret.database-credentials.username }}"
        password: "{{ vault.secret.database-credentials.password }}"
  
  # TLS certificates from Vault PKI
  listeners:
    - name: https
      port: 8443
      protocol: HTTPS
      tls:
        mode: SIMPLE
        certFile: "{{ vault.pki.server-cert.cert }}"
        keyFile: "{{ vault.pki.server-cert.key }}"
```

### Development/Testing Mode

For development and testing environments:

```yaml
# Development configuration (NOT for production)
spec:
  listeners:
    - name: http-dev
      port: 8080
      protocol: HTTP
      # No TLS for development
    
    - name: grpc-dev
      port: 9090
      protocol: GRPC
      grpc:
        tls:
          enabled: false          # Insecure mode for development
        reflection: true
        healthCheck: true
  
  # Disable Vault in development
  vault:
    enabled: false
  
  # Use static secrets for development
  secrets:
    static:
      database_url: "postgres://user:pass@localhost:5432/db"
      api_key: "dev-api-key-12345"
```

### Vault Setup for Testing

Set up Vault for local development and testing:

```bash
# Start Vault in dev mode
docker run -d --name vault-test \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=myroot \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  vault:latest

# Set environment variables
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=myroot

# Enable PKI secrets engine
vault secrets enable pki

# Configure PKI root CA
vault write pki/root/generate/internal \
  common_name="Test CA" \
  ttl=87600h \
  key_type=rsa \
  key_bits=2048

# Configure PKI role for gateway certificates
vault write pki/roles/gateway \
  allowed_domains="localhost,example.com" \
  allow_subdomains=true \
  allow_localhost=true \
  allow_ip_sans=true \
  max_ttl=720h \
  ttl=168h \
  key_type=rsa \
  key_bits=2048

# Enable KV secrets engine
vault secrets enable -path=secret kv-v2

# Store test secrets
vault kv put secret/database username=testuser password=testpass
vault kv put secret/api stripe_key=sk_test_123 sendgrid_key=SG.test.456

# Enable Kubernetes auth (for K8s environments)
vault auth enable kubernetes

# Configure Kubernetes auth
vault write auth/kubernetes/config \
  token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  kubernetes_host="https://kubernetes.default.svc:443" \
  kubernetes_ca_cert="$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)"

# Create policy for gateway
vault policy write gateway-policy - <<EOF
# PKI permissions
path "pki/issue/gateway" {
  capabilities = ["create", "update"]
}

# KV permissions
path "secret/data/database" {
  capabilities = ["read"]
}

path "secret/data/api" {
  capabilities = ["read"]
}
EOF

# Create Kubernetes role
vault write auth/kubernetes/role/gateway \
  bound_service_account_names=gateway \
  bound_service_account_namespaces=default \
  policies=gateway-policy \
  ttl=1h
```

### Vault Production Setup

For production environments:

```bash
# Initialize Vault (one-time setup)
vault operator init -key-shares=5 -key-threshold=3

# Unseal Vault (required after restart)
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Enable audit logging
vault audit enable file file_path=/vault/logs/audit.log

# Configure PKI with intermediate CA
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int

# Generate intermediate CSR
vault write -format=json pki_int/intermediate/generate/internal \
  common_name="Gateway Intermediate CA" \
  ttl=43800h | jq -r '.data.csr' > pki_intermediate.csr

# Sign intermediate certificate with root CA
vault write -format=json pki/root/sign-intermediate \
  csr=@pki_intermediate.csr \
  format=pem_bundle ttl=43800h | jq -r '.data.certificate' > intermediate.cert.pem

# Set intermediate certificate
vault write pki_int/intermediate/set-signed certificate=@intermediate.cert.pem

# Configure role for production certificates
vault write pki_int/roles/gateway \
  allowed_domains="example.com" \
  allow_subdomains=true \
  max_ttl=720h \
  ttl=168h \
  key_type=rsa \
  key_bits=2048 \
  require_cn=true
```

### TLS and Vault Endpoints

The gateway exposes additional endpoints when TLS and Vault are enabled:

| Endpoint | Port | Description | Response |
|----------|------|-------------|----------|
| `GET /tls/certificates` | 9090 | List active certificates | JSON certificate info |
| `GET /tls/certificates/{name}` | 9090 | Get certificate details | Certificate metadata |
| `POST /tls/certificates/{name}/renew` | 9090 | Force certificate renewal | Renewal status |
| `GET /vault/status` | 9090 | Vault connection status | Connection health |
| `GET /vault/secrets` | 9090 | List configured secrets | Secret metadata |
| `POST /vault/secrets/refresh` | 9090 | Force secret refresh | Refresh status |

### Security Considerations

#### Production Security Checklist

- [ ] Use TLS 1.2 minimum, prefer TLS 1.3
- [ ] Configure strong cipher suites
- [ ] Enable HSTS with appropriate max-age
- [ ] Use mutual TLS for sensitive services
- [ ] Implement certificate rotation
- [ ] Store Vault tokens securely
- [ ] Use Vault authentication methods (not direct tokens)
- [ ] Enable Vault audit logging
- [ ] Regularly rotate secrets
- [ ] Monitor certificate expiration
- [ ] Implement proper secret injection
- [ ] Use Vault namespaces for isolation
- [ ] Configure appropriate Vault policies
- [ ] Enable Vault seal/unseal procedures
- [ ] Implement backup and disaster recovery

#### Common Security Pitfalls

❌ **Don't do this:**
```yaml
# Insecure configuration
tls:
  skipVerify: true              # Never skip verification in production
  minVersion: TLS10             # Use TLS 1.2 minimum
vault:
  token:
    value: "hardcoded-token"    # Never hardcode tokens
```

✅ **Do this instead:**
```yaml
# Secure configuration
tls:
  skipVerify: false
  minVersion: TLS12
  maxVersion: TLS13
vault:
  authMethod: kubernetes
  kubernetes:
    role: gateway
```

## ⚙️ Environment Variable Configuration

The AV API Gateway supports comprehensive environment variable configuration with enhanced boolean value handling.

### Boolean Environment Variables

All boolean configuration options support symmetric true/false handling with multiple formats (case-insensitive):

**Supported Boolean Values:**
- **True values**: `true`, `yes`, `1`, `on`, `enable`, `enabled`
- **False values**: `false`, `no`, `0`, `off`, `disable`, `disabled`

```bash
# All of these are equivalent for enabling features
export VAULT_ENABLED=true
export VAULT_ENABLED=yes
export VAULT_ENABLED=1
export VAULT_ENABLED=on

# All of these are equivalent for disabling features
export VAULT_ENABLED=false
export VAULT_ENABLED=no
export VAULT_ENABLED=0
export VAULT_ENABLED=off
```

### Common Environment Variables

```bash
# Core gateway settings
export GATEWAY_PORT=8080
export GATEWAY_HOST=0.0.0.0
export GATEWAY_LOG_LEVEL=info
export GATEWAY_LOG_FORMAT=json

# TLS configuration
export TLS_ENABLED=true
export TLS_CERT_FILE=/app/certs/tls.crt
export TLS_KEY_FILE=/app/certs/tls.key
export TLS_MIN_VERSION=1.2

# Vault integration
export VAULT_ENABLED=true
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_AUTH_METHOD=kubernetes
export VAULT_ROLE=gateway-role

# Metrics and observability
export METRICS_ENABLED=true
export METRICS_PORT=9090
export TRACING_ENABLED=true
export TRACING_ENDPOINT=http://jaeger:14268/api/traces

# Security settings
export CORS_ENABLED=true
export RATE_LIMIT_ENABLED=true
export CIRCUIT_BREAKER_ENABLED=true
```

### Environment Variable Precedence

Configuration values are resolved in the following order (highest to lowest precedence):

1. **Command line flags** - Direct CLI arguments
2. **Environment variables** - OS environment variables
3. **Configuration file** - YAML configuration file
4. **Default values** - Built-in defaults

```bash
# Example: Override config file settings with environment variables
export GATEWAY_PORT=9080              # Overrides config file port
export VAULT_ENABLED=false            # Disables Vault regardless of config file
./bin/gateway -config gateway.yaml    # Config file provides base configuration
```

### Docker Environment Configuration

```bash
# Run with environment variables
docker run -d \
  -p 8080:8080 \
  -p 9090:9090 \
  -e GATEWAY_LOG_LEVEL=debug \
  -e VAULT_ENABLED=true \
  -e VAULT_ADDR=https://vault.example.com:8200 \
  -e METRICS_ENABLED=true \
  ghcr.io/vyrodovalexey/avapigw:latest
```

### Kubernetes Environment Configuration

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: avapigw
spec:
  template:
    spec:
      containers:
      - name: gateway
        image: ghcr.io/vyrodovalexey/avapigw:latest
        env:
        - name: GATEWAY_LOG_LEVEL
          value: "info"
        - name: VAULT_ENABLED
          value: "true"
        - name: VAULT_ADDR
          value: "https://vault.vault.svc.cluster.local:8200"
        - name: VAULT_AUTH_METHOD
          value: "kubernetes"
        - name: VAULT_ROLE
          value: "gateway-role"
        - name: METRICS_ENABLED
          value: "yes"                    # Alternative boolean format
        - name: TRACING_ENABLED
          value: "1"                      # Alternative boolean format
```

## 🔐 Authentication

The AV API Gateway provides comprehensive authentication capabilities supporting multiple authentication methods for both HTTP and gRPC protocols. Authentication can be configured globally or per-route, with support for multiple authentication providers and token extraction methods.

### Authentication Overview

The gateway supports the following authentication methods:

- **JWT Authentication** - JSON Web Token validation with multiple algorithms
- **API Key Authentication** - API key validation with hashing and rate limiting
- **mTLS Authentication** - Mutual TLS client certificate validation
- **OIDC Integration** - OpenID Connect with popular providers

### Global Authentication Configuration

Enable authentication globally for all routes:

```yaml
spec:
  authentication:
    enabled: true
    defaultPolicy: deny          # deny, allow
    skipPaths:                   # Paths to skip authentication
      - /health
      - /metrics
      - /public/*
    
    # Multiple authentication methods can be enabled
    jwt:
      enabled: true
    apiKey:
      enabled: true
    mtls:
      enabled: true
    oidc:
      enabled: true
```

### JWT Authentication

Configure JWT authentication with support for multiple algorithms and key sources:

```yaml
spec:
  authentication:
    jwt:
      enabled: true
      algorithms: [RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384, HS512, Ed25519]
      
      # JWK URL for dynamic key retrieval
      jwksUrl: "https://auth.example.com/.well-known/jwks.json"
      jwksCacheTTL: 1h
      jwksRefreshInterval: 15m
      
      # Token validation settings
      issuer: "https://auth.example.com"
      audience: ["api.example.com", "gateway.example.com"]
      clockSkew: 5m
      
      # Token extraction configuration
      extraction:
        # HTTP: Extract from Authorization header
        - type: header
          name: Authorization
          prefix: "Bearer "
        # HTTP: Extract from cookie
        - type: cookie
          name: access_token
        # HTTP: Extract from query parameter
        - type: query
          name: token
        # gRPC: Extract from metadata
        - type: metadata
          name: authorization
          prefix: "Bearer "
      
      # Token revocation checking
      revocation:
        enabled: true
        checkUrl: "https://auth.example.com/revoke/check"
        cacheTTL: 5m
      
      # Vault Transit integration for signing keys
      vault:
        enabled: true
        transitMount: transit
        keyName: jwt-signing-key
        algorithm: RS256
```

#### JWT Algorithm Support

| Algorithm | Type | Description |
|-----------|------|-------------|
| RS256, RS384, RS512 | RSA | RSA signatures with SHA-256/384/512 |
| ES256, ES384, ES512 | ECDSA | ECDSA signatures with P-256/384/521 curves |
| HS256, HS384, HS512 | HMAC | HMAC signatures with SHA-256/384/512 |
| Ed25519 | EdDSA | EdDSA signatures with Ed25519 |

#### JWT Claims Validation

```yaml
spec:
  authentication:
    jwt:
      claims:
        required:
          - sub
          - iat
          - exp
        validation:
          - claim: role
            values: [admin, user, guest]
          - claim: scope
            contains: [read, write]
          - claim: tenant_id
            regex: "^[a-zA-Z0-9-]+$"
```

### API Key Authentication

Configure API key authentication with flexible extraction and validation:

```yaml
spec:
  authentication:
    apiKey:
      enabled: true
      
      # Key extraction methods
      extraction:
        # HTTP: Extract from header
        - type: header
          name: X-API-Key
        # HTTP: Extract from query parameter
        - type: query
          name: api_key
        # gRPC: Extract from metadata
        - type: metadata
          name: x-api-key
      
      # Key hashing for secure storage
      hashAlgorithm: sha256        # sha256, bcrypt, none
      
      # Rate limiting per API key
      rateLimit:
        enabled: true
        requestsPerSecond: 100
        burst: 200
        window: 1h
      
      # Vault KV integration for key storage
      vault:
        enabled: true
        kvMount: secret
        path: api-keys
        keyField: key
        metadataFields:
          - name
          - permissions
          - rate_limit
      
      # Static keys (for development/testing)
      staticKeys:
        - key: "dev-key-12345"
          name: "Development Key"
          permissions: [read, write]
        - key: "test-key-67890"
          name: "Test Key"
          permissions: [read]
```

#### API Key Hashing

For security, API keys can be hashed before storage:

```yaml
# SHA-256 hashing
hashAlgorithm: sha256

# bcrypt hashing (more secure, slower)
hashAlgorithm: bcrypt
bcryptCost: 12

# No hashing (not recommended for production)
hashAlgorithm: none
```

### mTLS Authentication

Configure mutual TLS authentication with client certificate validation:

```yaml
spec:
  authentication:
    mtls:
      enabled: true
      
      # Client certificate validation
      clientAuth:
        required: true
        verifyClientCert: true
        
        # Allowed client certificate authorities
        caFiles:
          - /etc/ssl/certs/client-ca.crt
          - /etc/ssl/certs/partner-ca.crt
        
        # Certificate revocation checking
        crl:
          enabled: true
          urls:
            - "http://crl.example.com/client.crl"
          cacheTTL: 1h
      
      # Identity extraction from certificate
      identityExtraction:
        # Extract from Subject Distinguished Name
        - type: subject_dn
          field: CN                # CN, O, OU, C, ST, L
        # Extract from Subject Alternative Name
        - type: san
          field: dns               # dns, email, ip, uri
        # Extract SPIFFE URI
        - type: spiffe_uri
      
      # Vault PKI integration
      vault:
        enabled: true
        pkiMount: pki
        role: client-certs
        
        # Certificate validation against Vault
        validateWithVault: true
        allowedRoles:
          - client-role
          - partner-role
```

#### mTLS Identity Extraction

Extract client identity from certificates:

```yaml
identityExtraction:
  # Subject DN extraction
  - type: subject_dn
    field: CN                    # Common Name
    regex: "^client-(.+)$"       # Extract client ID
  
  # SAN extraction
  - type: san
    field: uri                   # URI SAN
    regex: "spiffe://trust-domain/(.+)"
  
  # Custom OID extraction
  - type: oid
    oid: "1.3.6.1.4.1.12345.1"  # Custom OID
```

### OIDC Integration

Configure OpenID Connect integration with popular providers:

```yaml
spec:
  authentication:
    oidc:
      enabled: true
      
      # Multiple OIDC providers
      providers:
        - name: keycloak
          issuer: "http://localhost:8090/realms/gateway-test"
          clientId: "gateway"
          clientSecret: "${OIDC_CLIENT_SECRET}"
          scopes: [openid, profile, email]
          
          # OIDC discovery
          discovery:
            enabled: true
            cacheTTL: 1h
            endpoint: "/.well-known/openid_configuration"
          
          # Token validation
          validation:
            audience: ["gateway", "api"]
            clockSkew: 5m
            
        - name: auth0
          issuer: "https://dev-12345.us.auth0.com/"
          clientId: "auth0-client-id"
          clientSecret: "${AUTH0_CLIENT_SECRET}"
          scopes: [openid, profile, email]
          
        - name: okta
          issuer: "https://dev-12345.okta.com/oauth2/default"
          clientId: "okta-client-id"
          clientSecret: "${OKTA_CLIENT_SECRET}"
          scopes: [openid, profile, email]
          
        - name: azure
          issuer: "https://login.microsoftonline.com/tenant-id/v2.0"
          clientId: "azure-client-id"
          clientSecret: "${AZURE_CLIENT_SECRET}"
          scopes: [openid, profile, email]
      
      # Token extraction (same as JWT)
      extraction:
        - type: header
          name: Authorization
          prefix: "Bearer "
        - type: cookie
          name: oidc_token
```

#### OIDC Provider Configuration

| Provider | Issuer URL | Notes |
|----------|------------|-------|
| Keycloak | `http://keycloak:8080/realms/{realm}` | Self-hosted |
| Auth0 | `https://{domain}.auth0.com/` | SaaS |
| Okta | `https://{domain}.okta.com/oauth2/default` | SaaS |
| Azure AD | `https://login.microsoftonline.com/{tenant}/v2.0` | Microsoft |
| Google | `https://accounts.google.com` | Google |

### Route-Level Authentication

Override global authentication settings per route:

```yaml
spec:
  routes:
    - name: public-api
      match:
        - uri:
            prefix: /public
      authentication:
        enabled: false             # Disable auth for public routes
    
    - name: admin-api
      match:
        - uri:
            prefix: /admin
      authentication:
        enabled: true
        methods: [jwt, mtls]       # Require JWT AND mTLS
        jwt:
          requiredClaims:
            role: admin
        mtls:
          requiredIdentity: "admin-client"
    
    - name: api-key-only
      match:
        - uri:
            prefix: /api/v1
      authentication:
        enabled: true
        methods: [apiKey]          # Only API key auth
        apiKey:
          rateLimit:
            requestsPerSecond: 1000
```

### Authentication Context

Authenticated requests include context information:

```yaml
# Available in request context
auth:
  method: jwt                    # Authentication method used
  principal: user@example.com    # Principal/subject
  claims:                        # JWT claims or API key metadata
    sub: user@example.com
    role: admin
    permissions: [read, write]
  identity:                      # mTLS identity
    subject_dn: "CN=client.example.com"
    san_dns: ["client.example.com"]
  metadata:                      # Additional metadata
    api_key_name: "Production Key"
    rate_limit: 1000
```

### Authentication Metrics

The gateway exposes authentication-related Prometheus metrics:

```
# Authentication attempts
gateway_auth_requests_total{method, status, auth_type}

# Authentication duration
gateway_auth_request_duration_seconds{method, auth_type}

# JWT validation
gateway_jwt_validation_total{status, issuer}
gateway_jwt_cache_hits_total
gateway_jwt_cache_misses_total

# API key validation
gateway_apikey_validation_total{status}

# mTLS validation
gateway_mtls_validation_total{status}

# OIDC token validation
gateway_oidc_token_validation_total{provider, status}
```

### Authentication Testing

Test authentication with curl and grpcurl:

```bash
# JWT Authentication
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  http://localhost:8080/api/v1/users

# API Key Authentication
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/v1/data

# mTLS Authentication
curl --cert client.crt --key client.key --cacert ca.crt \
  https://localhost:8443/api/v1/secure

# gRPC with JWT
grpcurl -H "authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -plaintext localhost:9000 api.v1.UserService/GetUser

# gRPC with API Key
grpcurl -H "x-api-key: your-api-key" \
  -plaintext localhost:9000 api.v1.DataService/GetData
```

## 🛡️ Authorization

The AV API Gateway provides flexible authorization capabilities including Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC), and integration with external authorization services like Open Policy Agent (OPA).

### Authorization Overview

Authorization in the gateway supports:

- **RBAC** - Role-based access control using JWT claims
- **ABAC** - Attribute-based access control with CEL expressions
- **External Authorization** - Integration with OPA and custom authorization services
- **Policy Caching** - Configurable TTL for authorization decisions
- **Fine-grained Permissions** - Resource and action-based authorization

### Global Authorization Configuration

Configure authorization globally:

```yaml
spec:
  authorization:
    enabled: true
    defaultPolicy: deny          # deny, allow
    
    # Skip authorization for specific paths
    skipPaths:
      - /health
      - /metrics
      - /public/*
    
    # Policy caching
    cache:
      enabled: true
      ttl: 5m
      maxEntries: 10000
    
    # Enable specific authorization methods
    rbac:
      enabled: true
    abac:
      enabled: true
    external:
      enabled: true
```

### Role-Based Access Control (RBAC)

Configure RBAC using JWT claims:

```yaml
spec:
  authorization:
    rbac:
      enabled: true
      
      # Role claim mapping from JWT
      claimMapping:
        roles: "realm_access.roles"     # Keycloak format
        # roles: "roles"                # Simple format
        # roles: "https://example.com/roles"  # Namespaced format
      
      # RBAC policies
      policies:
        - name: admin-access
          description: "Full admin access"
          roles: [admin, super-admin]
          resources: ["*"]
          actions: ["*"]
          
        - name: user-read-access
          description: "User read access to API"
          roles: [user, premium-user]
          resources: ["/api/v1/*"]
          actions: [GET]
          
        - name: user-write-access
          description: "User write access to own data"
          roles: [user, premium-user]
          resources: ["/api/v1/users/{user_id}/*"]
          actions: [GET, POST, PUT, PATCH]
          conditions:
            - "request.user_id == auth.claims.sub"
          
        - name: service-access
          description: "Service-to-service access"
          roles: [service]
          resources: ["/api/internal/*"]
          actions: [GET, POST]
          
        - name: read-only-access
          description: "Read-only access to public APIs"
          roles: [readonly, guest]
          resources: ["/api/v1/public/*", "/api/v1/catalog/*"]
          actions: [GET]
```

#### RBAC Resource Patterns

| Pattern | Description | Example |
|---------|-------------|---------|
| `*` | Match all resources | All endpoints |
| `/api/v1/*` | Prefix match | All v1 API endpoints |
| `/users/{user_id}` | Path parameter | User-specific endpoints |
| `/api/v1/users/{user_id}/orders/{order_id}` | Multiple parameters | Nested resources |
| `regex:^/api/v[0-9]+/.*` | Regex pattern | Version-specific APIs |

#### RBAC Conditions

Add conditions to RBAC policies for fine-grained control:

```yaml
policies:
  - name: user-own-data
    roles: [user]
    resources: ["/api/v1/users/{user_id}/*"]
    actions: [GET, PUT, PATCH]
    conditions:
      # User can only access their own data
      - "request.path_params.user_id == auth.claims.sub"
      
  - name: tenant-isolation
    roles: [tenant-admin]
    resources: ["/api/v1/tenants/{tenant_id}/*"]
    actions: ["*"]
    conditions:
      # Admin can only access their tenant
      - "request.path_params.tenant_id == auth.claims.tenant_id"
      
  - name: time-based-access
    roles: [employee]
    resources: ["/api/v1/internal/*"]
    actions: ["*"]
    conditions:
      # Only during business hours
      - "request.time.getHours() >= 9 && request.time.getHours() <= 17"
      - "request.time.getDayOfWeek() >= 1 && request.time.getDayOfWeek() <= 5"
```

### Attribute-Based Access Control (ABAC)

Configure ABAC using CEL (Common Expression Language):

```yaml
spec:
  authorization:
    abac:
      enabled: true
      engine: cel                # cel, rego (for OPA)
      
      # ABAC policies using CEL expressions
      policies:
        - name: time-based-access
          description: "Allow access only during business hours"
          expression: |
            request.time.getHours() >= 9 && 
            request.time.getHours() <= 17 &&
            request.time.getDayOfWeek() >= 1 && 
            request.time.getDayOfWeek() <= 5
          
        - name: geo-restriction
          description: "Block access from certain countries"
          expression: |
            !has(request.headers['cf-ipcountry']) ||
            request.headers['cf-ipcountry'] != 'CN'
          
        - name: rate-limit-by-plan
          description: "Different rate limits based on user plan"
          expression: |
            (auth.claims.plan == 'premium' && request.rate_limit <= 1000) ||
            (auth.claims.plan == 'basic' && request.rate_limit <= 100) ||
            (auth.claims.plan == 'free' && request.rate_limit <= 10)
          
        - name: resource-ownership
          description: "Users can only access their own resources"
          expression: |
            request.path.startsWith('/api/v1/users/' + auth.claims.sub + '/') ||
            request.path.startsWith('/api/v1/public/')
          
        - name: admin-override
          description: "Admins can access everything"
          expression: |
            'admin' in auth.claims.roles ||
            'super-admin' in auth.claims.roles
          
        - name: api-version-access
          description: "Beta users can access beta APIs"
          expression: |
            !request.path.contains('/beta/') ||
            'beta-tester' in auth.claims.roles
```

#### CEL Expression Context

Available variables in CEL expressions:

```yaml
# Request context
request:
  method: "GET"                  # HTTP method
  path: "/api/v1/users/123"      # Request path
  headers:                       # Request headers
    authorization: "Bearer ..."
    user-agent: "curl/7.68.0"
  query_params:                  # Query parameters
    limit: "10"
    offset: "0"
  path_params:                   # Path parameters
    user_id: "123"
  body: {...}                    # Request body (parsed)
  remote_addr: "192.168.1.100"   # Client IP
  time: timestamp                # Request timestamp
  rate_limit: 100                # Current rate limit

# Authentication context
auth:
  method: "jwt"                  # Auth method
  principal: "user@example.com"  # Principal
  claims:                        # JWT claims
    sub: "user@example.com"
    roles: ["user", "premium"]
    tenant_id: "tenant-123"
    plan: "premium"
  identity: {...}                # mTLS identity

# Environment context
env:
  gateway_version: "1.0.0"
  environment: "production"
  region: "us-west-2"
```

### External Authorization

Integrate with external authorization services like OPA:

```yaml
spec:
  authorization:
    external:
      enabled: true
      
      # OPA integration
      opa:
        enabled: true
        endpoint: "http://opa:8181/v1/data/gateway/authz"
        timeout: 1s
        
        # Request payload to OPA
        requestPayload:
          input:
            method: "{{ .Request.Method }}"
            path: "{{ .Request.Path }}"
            headers: "{{ .Request.Headers }}"
            user: "{{ .Auth.Principal }}"
            roles: "{{ .Auth.Claims.roles }}"
            claims: "{{ .Auth.Claims }}"
        
        # Expected response format
        responseFormat:
          allowField: "result.allow"
          reasonField: "result.reason"
          
        # Caching
        cache:
          enabled: true
          ttl: 30s
          keyTemplate: "{{ .Auth.Principal }}:{{ .Request.Method }}:{{ .Request.Path }}"
      
      # Custom authorization service
      custom:
        enabled: true
        endpoint: "http://authz-service:8080/authorize"
        method: POST
        timeout: 2s
        
        headers:
          Content-Type: "application/json"
          Authorization: "Bearer {{ .Env.AUTHZ_TOKEN }}"
        
        requestPayload:
          user_id: "{{ .Auth.Claims.sub }}"
          resource: "{{ .Request.Path }}"
          action: "{{ .Request.Method }}"
          context:
            ip: "{{ .Request.RemoteAddr }}"
            user_agent: "{{ .Request.Headers.user_agent }}"
        
        # Response evaluation
        responseEvaluation:
          allowCondition: "response.allowed == true"
          denyReason: "response.reason"
```

#### OPA Policy Example

Example OPA policy for the gateway:

```rego
# gateway/authz.rego
package gateway.authz

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Allow if user has admin role
allow if {
    "admin" in input.roles
}

# Allow read access to public APIs
allow if {
    input.method == "GET"
    startswith(input.path, "/api/v1/public/")
}

# Allow users to access their own data
allow if {
    input.method in ["GET", "PUT", "PATCH"]
    startswith(input.path, sprintf("/api/v1/users/%s/", [input.user]))
}

# Allow during business hours only
allow if {
    business_hours
    input.method == "GET"
    startswith(input.path, "/api/v1/")
}

business_hours if {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour <= 17
}

# Provide reason for denial
reason := "Access denied: insufficient permissions" if {
    not allow
    not "admin" in input.roles
}

reason := "Access denied: outside business hours" if {
    not allow
    not business_hours
}
```

### Route-Level Authorization

Override global authorization per route:

```yaml
spec:
  routes:
    - name: admin-api
      match:
        - uri:
            prefix: /admin
      authorization:
        enabled: true
        rbac:
          requiredRoles: [admin, super-admin]
        
    - name: user-api
      match:
        - uri:
            prefix: /api/v1/users
      authorization:
        enabled: true
        abac:
          policies:
            - name: user-data-access
              expression: |
                request.path.startsWith('/api/v1/users/' + auth.claims.sub + '/') ||
                'admin' in auth.claims.roles
        
    - name: public-api
      match:
        - uri:
            prefix: /public
      authorization:
        enabled: false             # No authorization required
```

### Authorization Metrics

Authorization-related Prometheus metrics:

```
# Authorization decisions
gateway_authz_decisions_total{decision, policy}

# Authorization decision duration
gateway_authz_decision_duration_seconds{policy_type}

# RBAC evaluations
gateway_rbac_evaluations_total{role, decision}

# ABAC evaluations
gateway_abac_evaluations_total{policy, decision}

# External authorization requests
gateway_external_authz_requests_total{endpoint, status}
gateway_external_authz_latency_seconds{endpoint}
```

### Security Headers

Configure security headers automatically:

```yaml
spec:
  security:
    headers:
      enabled: true
      
      # HSTS (HTTP Strict Transport Security)
      hsts:
        enabled: true
        maxAge: 31536000          # 1 year
        includeSubDomains: true
        preload: true
      
      # Content Security Policy
      csp:
        enabled: true
        policy: "default-src 'self'; script-src 'self' 'unsafe-inline'"
        reportOnly: false
      
      # Additional security headers
      additionalHeaders:
        X-Content-Type-Options: "nosniff"
        X-Frame-Options: "DENY"
        X-XSS-Protection: "1; mode=block"
        Referrer-Policy: "strict-origin-when-cross-origin"
        Permissions-Policy: "geolocation=(), microphone=(), camera=()"
```

### Audit Logging

Configure comprehensive audit logging:

```yaml
spec:
  audit:
    enabled: true
    
    # Log authentication events
    authentication:
      enabled: true
      logSuccessful: true
      logFailed: true
      includeTokenClaims: false   # For privacy
    
    # Log authorization events
    authorization:
      enabled: true
      logAllowed: false           # Only log denials by default
      logDenied: true
      includePolicyDetails: true
    
    # Audit log format
    format: json
    fields:
      - timestamp
      - request_id
      - method
      - path
      - user_id
      - auth_method
      - authz_decision
      - policy_name
      - remote_addr
      - user_agent
    
    # Output destinations
    outputs:
      - type: file
        path: /var/log/gateway/audit.log
        rotation:
          maxSize: 100MB
          maxAge: 30d
          maxBackups: 10
      - type: syslog
        network: udp
        address: "syslog.example.com:514"
        facility: local0
```

### Authorization Testing

Test authorization with different scenarios:

```bash
# Test with admin role
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/admin/users

# Test with user role
curl -H "Authorization: Bearer $USER_TOKEN" \
  http://localhost:8080/api/v1/users/123

# Test unauthorized access
curl -H "Authorization: Bearer $USER_TOKEN" \
  http://localhost:8080/admin/settings

# Test with API key
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8080/api/v1/data

# Test gRPC authorization
grpcurl -H "authorization: Bearer $TOKEN" \
  -plaintext localhost:9000 api.v1.UserService/GetUser
```

## 🔄 Data Transformation

The AV API Gateway provides comprehensive data transformation capabilities for both HTTP and gRPC protocols.

### Response Manipulation

- **Field Filtering**: Filter response fields using allow/deny lists
- **Field Mapping**: Rename and remap response fields
- **Field Grouping**: Group fields into nested objects
- **Field Flattening**: Extract and flatten nested objects
- **Array Operations**: Append, prepend, filter, sort, limit, deduplicate arrays
- **Response Templating**: Use Go templates for custom response formatting
- **Response Merging**: Merge responses from multiple backends (deep, shallow, replace strategies)

### Request Manipulation

- **Body Passthrough**: Forward request body to backends
- **Body Templating**: Transform request body using templates
- **Header Injection**: Inject static and dynamic headers
- **Field Injection**: Add fields to request body
- **Field Removal**: Remove fields from request body
- **Default Values**: Set default values for missing fields

### gRPC-Specific Features

- **FieldMask Filtering**: Filter responses using Protocol Buffer FieldMask
- **Metadata Transformation**: Transform gRPC metadata (static and dynamic)
- **Streaming Transformation**: Transform streaming messages with rate limiting
- **Repeated Field Operations**: Filter, sort, limit, deduplicate repeated fields
- **Map Field Operations**: Filter keys, merge map fields

### Caching

- **In-Memory Cache**: Fast local caching with TTL and max entries
- **Redis Cache**: Distributed caching with Redis
- **Cache Key Generation**: Configurable cache key components
- **Cache Control**: Honor Cache-Control headers
- **Stale-While-Revalidate**: Serve stale data while revalidating
- **Negative Caching**: Cache error responses

### Encoding Support

- **JSON**: Full JSON encoding/decoding with configurable options
- **XML**: XML encoding/decoding
- **YAML**: YAML encoding/decoding
- **Content Negotiation**: Automatic content type negotiation based on Accept header

### Configuration Examples

#### HTTP Route with Transformation

```yaml
routes:
  - name: api-route
    match:
      - uri:
          prefix: /api/v1/
    route:
      - destination:
          host: backend.example.com
          port: 8080
    transform:
      response:
        allowFields:
          - id
          - name
          - status
        fieldMappings:
          - source: created_at
            target: createdAt
        mergeStrategy: deep
      request:
        staticHeaders:
          X-Gateway: avapigw
        defaultValues:
          version: "1.0"
    cache:
      enabled: true
      type: redis
      ttl: 5m
      redis:
        url: redis://localhost:6379
        keyPrefix: "api:"
```

#### gRPC Route with Transformation

```yaml
grpcRoutes:
  - name: grpc-service
    match:
      - service:
          exact: "api.v1.UserService"
    route:
      - destination:
          host: grpc-backend.example.com
          port: 50051
    transform:
      response:
        fieldMask:
          - id
          - name
          - email
      request:
        staticMetadata:
          x-gateway: avapigw
        dynamicMetadata:
          - key: x-request-id
            source: context.request_id
    cache:
      enabled: true
      type: redis
      ttl: 10m
```

### API Reference

#### Transformation Configuration

| Field | Type | Description |
|-------|------|-------------|
| `transform.response.allowFields` | `[]string` | Fields to include in response |
| `transform.response.denyFields` | `[]string` | Fields to exclude from response |
| `transform.response.fieldMappings` | `[]FieldMapping` | Field rename mappings |
| `transform.response.groupFields` | `[]FieldGroup` | Fields to group into objects |
| `transform.response.flattenFields` | `[]string` | Nested fields to flatten |
| `transform.response.arrayOperations` | `[]ArrayOperation` | Array manipulation operations |
| `transform.response.template` | `string` | Go template for response |
| `transform.response.mergeStrategy` | `string` | Merge strategy: deep, shallow, replace |
| `transform.request.passthroughBody` | `bool` | Pass request body unchanged |
| `transform.request.bodyTemplate` | `string` | Go template for request body |
| `transform.request.staticHeaders` | `map[string]string` | Static headers to inject |
| `transform.request.dynamicHeaders` | `[]DynamicHeader` | Dynamic headers from context |
| `transform.request.injectFields` | `[]FieldInjection` | Fields to inject |
| `transform.request.removeFields` | `[]string` | Fields to remove |
| `transform.request.defaultValues` | `map[string]interface{}` | Default values for missing fields |

#### Cache Configuration

| Field | Type | Description |
|-------|------|-------------|
| `cache.enabled` | `bool` | Enable caching |
| `cache.type` | `string` | Cache type: memory, redis |
| `cache.ttl` | `duration` | Cache TTL |
| `cache.maxEntries` | `int` | Max entries (memory cache) |
| `cache.redis.url` | `string` | Redis connection URL |
| `cache.redis.keyPrefix` | `string` | Key prefix for Redis |
| `cache.honorCacheControl` | `bool` | Honor Cache-Control headers |
| `cache.staleWhileRevalidate` | `duration` | Stale-while-revalidate duration |
| `cache.negativeCacheTTL` | `duration` | TTL for error responses |

#### Encoding Configuration

| Field | Type | Description |
|-------|------|-------------|
| `encoding.requestEncoding` | `string` | Request encoding: json, xml, yaml |
| `encoding.responseEncoding` | `string` | Response encoding |
| `encoding.enableContentNegotiation` | `bool` | Enable content negotiation |
| `encoding.json.emitDefaults` | `bool` | Emit default values in JSON |
| `encoding.json.prettyPrint` | `bool` | Pretty print JSON |
| `encoding.compression.enabled` | `bool` | Enable compression |
| `encoding.compression.algorithms` | `[]string` | Compression algorithms |

## 🔌 API Endpoints

The gateway exposes several built-in endpoints:

### HTTP Endpoints

| Endpoint | Port | Description | Response |
|----------|------|-------------|----------|
| `GET /health` | 9090 | Overall health status | `{"status":"healthy"}` |
| `GET /ready` | 9090 | Readiness probe | `{"status":"ready"}` |
| `GET /live` | 9090 | Liveness probe | `{"status":"alive"}` |
| `GET /metrics` | 9090 | Prometheus metrics | Prometheus text format |

### Authentication & Authorization Endpoints

| Endpoint | Port | Description | Response |
|----------|------|-------------|----------|
| `GET /auth/status` | 9090 | Authentication status | Auth configuration info |
| `GET /auth/jwks` | 9090 | JSON Web Key Set | JWKS for token validation |
| `POST /auth/validate` | 9090 | Validate token | Token validation result |
| `GET /authz/policies` | 9090 | List authorization policies | Policy metadata |
| `POST /authz/evaluate` | 9090 | Evaluate authorization | Authorization decision |
| `GET /audit/logs` | 9090 | Audit log entries | Audit log data |

### gRPC Endpoints

| Endpoint | Port | Description |
|----------|------|-------------|
| gRPC Services | 9000 | Native gRPC traffic |
| grpc.health.v1.Health | 9000 | gRPC health checking |
| gRPC Reflection | 9000 | Service discovery (optional) |

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

## 🔌 gRPC Gateway

The gateway provides comprehensive gRPC support with native HTTP/2 handling, streaming capabilities, and advanced routing features.

### gRPC Listener Configuration

Configure gRPC listeners with HTTP/2 settings:

```yaml
spec:
  listeners:
    - name: grpc
      port: 9000
      protocol: GRPC
      grpc:
        maxConcurrentStreams: 100
        maxRecvMsgSize: 4194304    # 4MB
        maxSendMsgSize: 4194304    # 4MB
        keepalive:
          time: 30s
          timeout: 10s
          permitWithoutStream: false
        reflection: true
        healthCheck: true
```

### gRPC Routes Configuration

Define gRPC routing rules with service and method matching:

```yaml
spec:
  grpcRoutes:
    - name: user-service
      match:
        - service: "user.v1.UserService"
          method: "GetUser"
          metadata:
            - name: "authorization"
              present: true
      route:
        - destination:
            host: user-backend.example.com
            port: 50051
          weight: 100
      timeout: 30s
      retries:
        attempts: 3
        retryOn: "unavailable,resource-exhausted"
    
    - name: order-service
      match:
        - service: "order.v1.OrderService"
          method: "*"  # All methods
          authority: "orders.example.com"
      route:
        - destination:
            host: order-backend-1
            port: 50051
          weight: 70
        - destination:
            host: order-backend-2
            port: 50051
          weight: 30
      timeout: 60s
    
    - name: streaming-service
      match:
        - service: "stream.v1.StreamService"
          method: "StreamData"
      route:
        - destination:
            host: stream-backend
            port: 50051
      timeout: 300s  # Longer timeout for streaming
```

### gRPC Backends Configuration

Configure gRPC backend services with health checking:

```yaml
spec:
  grpcBackends:
    - name: user-backend
      hosts:
        - address: user-backend.example.com
          port: 50051
          weight: 1
      healthCheck:
        enabled: true
        service: "user.v1.UserService"  # Service-specific health check
        interval: 10s
        timeout: 5s
        healthyThreshold: 2
        unhealthyThreshold: 3
      connectionPool:
        maxConnections: 100
        connectTimeout: 5s
        idleTimeout: 60s
    
    - name: order-backend
      hosts:
        - address: order-backend-1.example.com
          port: 50051
          weight: 2
        - address: order-backend-2.example.com
          port: 50051
          weight: 1
      healthCheck:
        enabled: true
        service: ""  # Overall health check
        interval: 15s
        timeout: 5s
      loadBalancer:
        algorithm: roundRobin
```

### gRPC Routing Features

#### Service Name Matching
```yaml
match:
  - service: "user.v1.UserService"        # Exact match
  - service: "user.v1.*"                  # Prefix match
  - service: "^user\\.v[0-9]+\\..*"       # Regex match
```

#### Method Name Matching
```yaml
match:
  - method: "GetUser"                     # Exact match
  - method: "Get*"                        # Prefix match
  - method: "^(Get|List).*"               # Regex match
  - method: "*"                           # Wildcard (all methods)
```

#### Metadata Matching
```yaml
match:
  - metadata:
      - name: "authorization"
        present: true                     # Header must be present
      - name: "user-id"
        exact: "12345"                    # Exact value match
      - name: "user-agent"
        regex: "grpc-go.*"                # Regex match
      - name: "x-trace-id"
        prefix: "trace-"                  # Prefix match
```

#### Authority/Host Matching
```yaml
match:
  - authority: "api.example.com"          # Exact authority match
  - authority: "*.example.com"            # Wildcard authority match
```

### gRPC Traffic Management

#### Timeouts and Deadlines
```yaml
grpcRoutes:
  - name: quick-service
    timeout: 5s                           # Route-level timeout
    route:
      - destination:
          host: backend
          port: 50051
        timeout: 3s                       # Per-destination timeout
```

#### Retry Policies
```yaml
retries:
  attempts: 3
  retryOn: "unavailable,resource-exhausted,deadline-exceeded"
  backoffStrategy: exponential
  baseInterval: 100ms
  maxInterval: 5s
  perTryTimeout: 10s
```

#### Rate Limiting
```yaml
rateLimit:
  enabled: true
  requestsPerSecond: 1000
  burst: 2000
  perClient: true
  keyExtractor: "metadata:user-id"        # Extract from gRPC metadata
```

#### Circuit Breaker
```yaml
circuitBreaker:
  enabled: true
  threshold: 10
  timeout: 30s
  halfOpenRequests: 5
  successThreshold: 3
```

### gRPC Streaming Support

The gateway supports all gRPC streaming patterns:

#### Unary RPC
```protobuf
rpc GetUser(GetUserRequest) returns (GetUserResponse);
```

#### Server Streaming
```protobuf
rpc ListUsers(ListUsersRequest) returns (stream User);
```

#### Client Streaming
```protobuf
rpc CreateUsers(stream CreateUserRequest) returns (CreateUsersResponse);
```

#### Bidirectional Streaming
```protobuf
rpc ChatStream(stream ChatMessage) returns (stream ChatMessage);
```

### gRPC Health Service

Built-in gRPC health checking following the [gRPC Health Checking Protocol](https://github.com/grpc/grpc/blob/master/doc/health-checking.md):

```bash
# Check overall health
grpcurl -plaintext localhost:9000 grpc.health.v1.Health/Check

# Check specific service health
grpcurl -plaintext -d '{"service":"user.v1.UserService"}' \
  localhost:9000 grpc.health.v1.Health/Check

# Watch health status
grpcurl -plaintext -d '{"service":"user.v1.UserService"}' \
  localhost:9000 grpc.health.v1.Health/Watch
```

### gRPC Reflection

Optional gRPC reflection service for service discovery:

```bash
# List all services
grpcurl -plaintext localhost:9000 list

# List methods for a service
grpcurl -plaintext localhost:9000 list user.v1.UserService

# Describe a method
grpcurl -plaintext localhost:9000 describe user.v1.UserService.GetUser
```

### gRPC Observability

#### Prometheus Metrics
- `gateway_grpc_requests_total` - Total gRPC requests by service/method
- `gateway_grpc_request_duration_seconds` - Request duration histogram
- `gateway_grpc_request_message_size_bytes` - Request message size
- `gateway_grpc_response_message_size_bytes` - Response message size
- `gateway_grpc_active_streams` - Active streaming connections

#### OpenTelemetry Tracing
Automatic trace propagation with gRPC metadata:
- `grpc-trace-bin` - Binary trace context
- `grpc-tags-bin` - Binary baggage context

#### Structured Logging
gRPC-specific log fields:
- `grpc_service` - gRPC service name
- `grpc_method` - gRPC method name
- `grpc_status` - gRPC status code
- `grpc_status_message` - gRPC status message
- `stream_id` - HTTP/2 stream ID

### gRPC Configuration Examples

#### Complete gRPC Gateway Example
```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: grpc-gateway
spec:
  listeners:
    - name: grpc
      port: 9000
      protocol: GRPC
      grpc:
        maxConcurrentStreams: 1000
        maxRecvMsgSize: 16777216  # 16MB
        maxSendMsgSize: 16777216  # 16MB
        keepalive:
          time: 30s
          timeout: 10s
        reflection: true
        healthCheck: true
  
  grpcRoutes:
    - name: user-service
      match:
        - service: "user.v1.UserService"
      route:
        - destination:
            host: user-service
            port: 50051
      timeout: 30s
      retries:
        attempts: 3
        retryOn: "unavailable"
    
    - name: order-service
      match:
        - service: "order.v1.OrderService"
          metadata:
            - name: "tenant-id"
              present: true
      route:
        - destination:
            host: order-service
            port: 50051
      rateLimit:
        requestsPerSecond: 100
        keyExtractor: "metadata:tenant-id"
  
  grpcBackends:
    - name: user-service
      hosts:
        - address: user-service.default.svc.cluster.local
          port: 50051
      healthCheck:
        enabled: true
        service: "user.v1.UserService"
        interval: 10s
    
    - name: order-service
      hosts:
        - address: order-service.default.svc.cluster.local
          port: 50051
      healthCheck:
        enabled: true
        interval: 10s
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

#### HTTP Request Metrics
- `gateway_requests_total{route, method, status}` - Total HTTP requests (uses route label for cardinality control)
- `gateway_request_duration_seconds{route, method}` - Request duration histogram
- `gateway_request_size_bytes{route}` - Request size histogram
- `gateway_response_size_bytes{route}` - Response size histogram
- `gateway_active_requests` - Active requests gauge

#### gRPC Request Metrics
- `gateway_grpc_requests_total` - Total gRPC requests by service/method
- `gateway_grpc_request_duration_seconds` - gRPC request duration histogram
- `gateway_grpc_request_message_size_bytes` - gRPC request message size
- `gateway_grpc_response_message_size_bytes` - gRPC response message size
- `gateway_grpc_active_streams` - Active gRPC streaming connections

#### Backend Metrics
- `gateway_backend_health` - Backend health status
- `gateway_backend_requests_total` - Backend request count
- `gateway_backend_request_duration_seconds` - Backend request duration
- `gateway_grpc_backend_health` - gRPC backend health status

#### Circuit Breaker Metrics
- `gateway_circuit_breaker_state` - Circuit breaker state
- `gateway_circuit_breaker_requests_total` - Circuit breaker requests

#### Rate Limiting Metrics
- `gateway_rate_limit_hits_total{route}` - Rate limit hits (no client_ip label for cardinality control)

#### Authentication Metrics
- `gateway_auth_requests_total{method, status, auth_type}` - Authentication attempts
- `gateway_auth_request_duration_seconds{method, auth_type}` - Authentication duration
- `gateway_jwt_validation_total{status, issuer}` - JWT validation results
- `gateway_jwt_cache_hits_total` - JWT cache hits
- `gateway_jwt_cache_misses_total` - JWT cache misses
- `gateway_apikey_validation_total{status}` - API key validation results
- `gateway_mtls_validation_total{status}` - mTLS validation results
- `gateway_oidc_token_validation_total{provider, status}` - OIDC token validation

#### Authorization Metrics
- `gateway_authz_decisions_total{decision, policy}` - Authorization decisions
- `gateway_authz_decision_duration_seconds{policy_type}` - Authorization decision duration
- `gateway_rbac_evaluations_total{role, decision}` - RBAC evaluations
- `gateway_abac_evaluations_total{policy, decision}` - ABAC evaluations
- `gateway_external_authz_requests_total{endpoint, status}` - External authorization requests
- `gateway_external_authz_latency_seconds{endpoint}` - External authorization latency

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

## 📊 Performance Testing

The gateway includes comprehensive performance testing infrastructure supporting multiple protocols and testing tools.

### Quick Performance Test

```bash
# Start backend services
docker-compose up -d

# Run HTTP throughput test (5 minutes)
make perf-test-http

# Run gRPC unary test (5 minutes)
make perf-test-grpc-unary

# Run WebSocket connection test (4 minutes)
make perf-test-websocket-connection

# Generate performance charts
make perf-generate-charts
```

### Performance Test Types

| Protocol | Test Type | Tool | Duration | Purpose |
|----------|-----------|------|----------|---------|
| **HTTP** | Throughput | Yandex Tank | 5 min | Baseline HTTP performance |
| **HTTP** | TLS | Yandex Tank | 5 min | HTTPS performance impact |
| **HTTP** | Auth | Yandex Tank | 5 min | JWT authentication overhead |
| **gRPC** | Unary | ghz | 5 min | gRPC call throughput |
| **gRPC** | Streaming | ghz | 4 min | gRPC streaming performance |
| **gRPC** | TLS | ghz | 5 min | gRPC TLS performance |
| **WebSocket** | Connection | k6 | 4 min | WebSocket handshake performance |
| **WebSocket** | Message | k6 | 4 min | WebSocket message throughput |
| **K8s** | HTTP | Yandex Tank | 5 min | Kubernetes deployment performance |
| **K8s** | gRPC | ghz | 5 min | Kubernetes gRPC performance |

### TLS and Authentication Performance

Test the performance impact of security features:

```bash
# HTTPS performance test
./test/performance/scripts/run-test.sh http-tls-throughput

# HTTP with JWT authentication
./test/performance/scripts/run-test.sh http-auth-throughput

# gRPC with TLS
./test/performance/scripts/run-grpc-test.sh grpc-tls-unary

# gRPC with JWT authentication
./test/performance/scripts/run-grpc-test.sh grpc-auth-unary

# WebSocket with TLS (WSS)
./test/performance/scripts/run-websocket-test.sh websocket-tls-message
```

### Kubernetes Performance Testing

Test performance in Kubernetes environment using the `avapigw-test` namespace:

```bash
# Setup Vault for K8s testing
./test/performance/scripts/setup-vault-k8s.sh --namespace=avapigw-test

# Deploy gateway to K8s
helm upgrade --install avapigw helm/avapigw/ \
  -f helm/avapigw/values-local.yaml \
  -n avapigw-test --create-namespace

# Run K8s performance tests
make perf-test-k8s-http
make perf-test-k8s-grpc

# Run all K8s tests
make perf-test-k8s
```

### Performance Results

Recent performance test results on local development machine:

| Protocol | Max RPS | Avg Latency | P95 Latency | P99 Latency | Error Rate |
|----------|---------|-------------|-------------|-------------|------------|
| HTTP | 2,000 | 1.0 ms | 5.5 ms | 460 ms | 0.00% |
| gRPC Unary | 16,443 | 4.55 ms | 8.39 ms | 12.88 ms | 0.00% |

For detailed performance testing documentation, see [Performance Testing Guide](test/performance/README.md).

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
make test-unit

# Functional tests
make test-functional

# Integration tests (requires Redis and backends, includes WebSocket tests)
make test-integration

# E2E tests (requires Redis and backends, includes WebSocket tests)
make test-e2e

# All tests
make test-all

# All tests with coverage
make test-coverage
```

### Test Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TEST_REDIS_URL` | `redis://default:password@127.0.0.1:6379` | Redis connection URL |
| `TEST_BACKEND1_URL` | `http://127.0.0.1:8801` | HTTP backend 1 URL |
| `TEST_BACKEND2_URL` | `http://127.0.0.1:8802` | HTTP backend 2 URL |
| `TEST_GRPC_BACKEND1_URL` | `127.0.0.1:8803` | gRPC backend 1 URL |
| `TEST_GRPC_BACKEND2_URL` | `127.0.0.1:8804` | gRPC backend 2 URL |
| `TEST_KEYCLOAK_URL` | `http://127.0.0.1:8090` | Keycloak server URL |
| `TEST_KEYCLOAK_REALM` | `gateway-test` | Keycloak realm name |
| `TEST_KEYCLOAK_CLIENT_ID` | `gateway` | Keycloak client ID |
| `TEST_KEYCLOAK_CLIENT_SECRET` | `gateway-secret` | Keycloak client secret |
| `TEST_VAULT_URL` | `http://127.0.0.1:8200` | Vault server URL |
| `TEST_VAULT_TOKEN` | `myroot` | Vault root token |
| `TEST_OPA_URL` | `http://127.0.0.1:8181` | OPA server URL |

### Authentication Testing Commands

```bash
# Test JWT authentication
make test-auth-jwt

# Test API key authentication
make test-auth-apikey

# Test mTLS authentication
make test-auth-mtls

# Test OIDC authentication
make test-auth-oidc

# Test RBAC authorization
make test-authz-rbac

# Test ABAC authorization
make test-authz-abac

# Test external authorization (OPA)
make test-authz-external

# All authentication and authorization tests
make test-auth-all
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
│   ├── grpc/            # gRPC-specific packages
│   │   ├── server/      # gRPC server implementation
│   │   ├── proxy/       # gRPC reverse proxy
│   │   ├── router/      # gRPC routing
│   │   ├── middleware/  # gRPC interceptors
│   │   └── health/      # gRPC health service
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

### Test Environment Setup

#### Keycloak Setup for Authentication Testing

Set up Keycloak for OIDC and JWT testing:

```bash
# Start PostgreSQL for Keycloak
docker run -d --name keycloak-db \
  -e POSTGRES_DB=keycloak \
  -e POSTGRES_USER=keycloak \
  -e POSTGRES_PASSWORD=keycloak \
  -p 5432:5432 \
  postgres:15

# Start Keycloak
docker run -d --name keycloak \
  -p 8090:8080 \
  -e KC_DB=postgres \
  -e KC_DB_URL=jdbc:postgresql://host.docker.internal:5432/keycloak \
  -e KC_DB_USERNAME=keycloak \
  -e KC_DB_PASSWORD=keycloak \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.5 start-dev

# Wait for Keycloak to start
sleep 30

# Configure Keycloak realm and client
make setup-keycloak-test
```

#### OPA Setup for Authorization Testing

Set up Open Policy Agent for external authorization testing:

```bash
# Start OPA server
docker run -d --name opa \
  -p 8181:8181 \
  -v $(pwd)/test/policies:/policies \
  openpolicyagent/opa:latest \
  run --server --addr localhost:8181 /policies

# Load test policies
make setup-opa-policies
```

#### Vault Setup for Secret Management Testing

Set up Vault for authentication and secret management testing:

```bash
# Start Vault in dev mode
docker run -d --name vault-test \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=myroot \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  vault:latest

# Configure Vault for testing
make setup-vault-test
```

### Contributing Guidelines

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the full test suite
6. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## ☸️ Kubernetes & Helm

The AV API Gateway provides production-ready Helm charts for easy deployment to Kubernetes clusters. The chart supports both standalone gateway deployment and optional operator mode for CRD-based configuration management.

### Helm Installation

#### Gateway Only (Default)

```bash
# Install the gateway only
helm install avapigw ./helm/avapigw \
  -n avapigw \
  --create-namespace

# Install with custom values
helm install avapigw ./helm/avapigw \
  -f values-production.yaml \
  -n avapigw \
  --create-namespace
```

#### Gateway with Operator

```bash
# Install gateway with operator for CRD-based configuration
helm install avapigw ./helm/avapigw \
  --set operator.enabled=true \
  -n avapigw \
  --create-namespace

# Install with custom values and operator
helm install avapigw ./helm/avapigw \
  -f values-production.yaml \
  --set operator.enabled=true \
  -n avapigw \
  --create-namespace
```

#### Upgrade Existing Installation

```bash
# Upgrade gateway only
helm upgrade avapigw ./helm/avapigw \
  -n avapigw

# Upgrade and enable operator
helm upgrade avapigw ./helm/avapigw \
  --set operator.enabled=true \
  -n avapigw
```

#### Vault TLS with Kubernetes Auth Deployment

For secure deployments with Vault PKI TLS certificates and Kubernetes authentication:

**Prerequisites:**
- Vault running with PKI engine enabled
- PKI role configured (e.g., `test-role`)
- Root CA generated
- Kubernetes auth method enabled and configured
- `avapigw` policy created
- `avapigw` K8s auth role bound to the service account

**Setup Steps:**

```bash
# 1. Start infrastructure (Vault, backends)
docker-compose -f test/docker-compose/docker-compose.yml up -d

# 2. Configure Vault K8s auth
./test/performance/scripts/setup-vault-k8s.sh

# 3. Build and load Docker image
docker build -t avapigw:test .

# 4. Deploy with Vault TLS enabled
helm upgrade --install avapigw helm/avapigw/ -f helm/avapigw/values-local.yaml

# 5. Verify deployment
kubectl get pods
kubectl get svc avapigw

# 6. Test HTTPS (self-signed cert, use -k)
HTTPS_PORT=$(kubectl get svc avapigw -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
curl -k https://127.0.0.1:$HTTPS_PORT/health
```

**Environment Variables for Vault:**

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_ADDR` | Vault server address | (required) |
| `VAULT_AUTH_METHOD` | Auth method: token, kubernetes, approle | `token` |
| `VAULT_TOKEN` | Vault token (token auth only) | - |
| `VAULT_K8S_ROLE` | Vault K8s auth role | - |
| `VAULT_K8S_MOUNT_PATH` | K8s auth mount path | `kubernetes` |
| `VAULT_K8S_TOKEN_PATH` | SA token path | `/var/run/secrets/kubernetes.io/serviceaccount/token` |

**Ports:**

| Port | Protocol | Description |
|------|----------|-------------|
| 8080 | HTTP | Plain HTTP traffic |
| 8443 | HTTPS | TLS-encrypted HTTP traffic (Vault PKI or static certs) |
| 9000 | gRPC | gRPC traffic |
| 9090 | HTTP | Metrics and health endpoints |

**Vault Prerequisites:**
- Vault running with PKI engine enabled
- PKI role configured (e.g., `test-role`)
- Root CA generated
- Kubernetes auth method enabled and configured
- `avapigw` policy created
- `avapigw` K8s auth role bound to the service account

#### Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `ghcr.io/vyrodovalexey/avapigw` |
| `image.tag` | Image tag | `""` (uses appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `service.type` | Service type | `ClusterIP` |
| `service.httpPort` | HTTP port | `8080` |
| `service.httpsPort` | HTTPS port | `8443` |
| `service.grpcPort` | gRPC port | `9000` |
| `service.metricsPort` | Metrics port | `9090` |
| `redis.enabled` | Enable Redis subchart | `false` |
| `vault.enabled` | Enable Vault integration | `false` |
| `keycloak.enabled` | Enable Keycloak integration | `false` |
| `autoscaling.enabled` | Enable HPA | `false` |
| `ingress.enabled` | Enable Ingress | `false` |
| `podDisruptionBudget.enabled` | Enable PDB | `false` |

#### Enable Redis Caching

```bash
helm install my-gateway ./helm/avapigw \
  --set redis.enabled=true \
  --set redis.auth.password=mypassword
```

#### Enable Autoscaling

```bash
helm install my-gateway ./helm/avapigw \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=2 \
  --set autoscaling.maxReplicas=10 \
  --set autoscaling.targetCPUUtilizationPercentage=80
```

#### Enable Ingress

```bash
helm install my-gateway ./helm/avapigw \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set ingress.hosts[0].host=api.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix
```

#### Production Configuration Example

```yaml
# production-values.yaml
replicaCount: 3

resources:
  limits:
    cpu: 1000m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70

podDisruptionBudget:
  enabled: true
  minAvailable: 2

redis:
  enabled: true
  auth:
    password: "secure-password"
  replica:
    replicaCount: 3

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: api.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: api-tls
      hosts:
        - api.example.com

gateway:
  logLevel: info
  rateLimit:
    enabled: true
    requestsPerSecond: 1000
    burst: 2000
  circuitBreaker:
    enabled: true
    threshold: 10
```

```bash
helm install my-gateway ./helm/avapigw -f production-values.yaml
```

#### Upgrading

```bash
# Upgrade with new values
helm upgrade my-gateway ./helm/avapigw -f my-values.yaml

# Rollback if needed
helm rollback my-gateway 1
```

#### Uninstalling

```bash
helm uninstall my-gateway
```

### Helm Chart Testing

```bash
# Lint the chart
helm lint ./helm/avapigw

# Template validation
helm template my-gateway ./helm/avapigw

# Dry-run install
helm install --dry-run --debug my-gateway ./helm/avapigw

# Run chart tests (after installation)
helm test my-gateway
```

### Makefile Targets

The project includes convenient Makefile targets for Helm operations:

```bash
# Helm operations (gateway only)
make helm-lint                    # Lint Helm chart
make helm-template                # Template gateway only
make helm-install                 # Install gateway only to local K8s
make helm-uninstall              # Uninstall from local K8s

# Helm operations (with operator)
make helm-template-with-operator  # Template with operator enabled
make helm-install-with-operator   # Install with operator to local K8s

# Legacy aliases (still supported for backward compatibility)
make helm-template-operator       # Alias for helm-template-with-operator
make helm-install-operator        # Alias for helm-install-with-operator
```

## 🎛️ AVAPIGW Operator

The AVAPIGW Operator is a Kubernetes operator that manages API Gateway configuration through Custom Resource Definitions (CRDs). It enables declarative configuration of routes and backends using Kubernetes-native resources and is now integrated into the main Helm chart.

### Key Features

- **Declarative Configuration** - Manage routes and backends using Kubernetes CRDs
- **Hot Configuration Updates** - Apply configuration changes without gateway restarts
- **Base Reconciler Pattern** - Extracted common reconciliation logic to reduce code duplication
- **Efficient Status Updates** - Status updates now use Patch instead of Update for better performance
- **Generation-based Reconciliation** - Skip unnecessary reconciliation when resources haven't changed
- **Thread-safe StatusUpdater** - Improved initialization and concurrent access handling
- **gRPC ConfigurationService** - Modern streaming-based configuration management with RegisterGateway, GetConfiguration, Heartbeat, AcknowledgeConfiguration, and StreamConfiguration RPCs using secure mTLS communication
- **Automated Certificate Management** - Webhook certificate provisioning supporting self-signed, Vault PKI, and cert-manager modes
- **Enhanced Admission Webhooks** - Cross-CRD duplicate detection, ingress validation, and cross-reference validation
- **Comprehensive RBAC** - Least-privilege RBAC permissions for Ingress, IngressClass, Leases, Secrets, Services, ConfigMaps, and ValidatingWebhookConfigurations
- **WebhookCAInjector** - Fully implemented automated CA bundle injection into ValidatingWebhookConfigurations with retry logic, metrics, and OpenTelemetry tracing
- **Ingress Controller Support** - Convert standard Kubernetes Ingress to gateway configuration
- **Status Reporting** - Real-time status updates and condition reporting
- **Multi-Gateway Support** - Manage multiple gateway instances from a single operator
- **Consolidated Deployment** - Single Helm chart with optional operator mode

### Quick Start

#### Prerequisites

- Kubernetes 1.23+
- Helm 3.0+
- AVAPIGW gateway instances running in the cluster

#### Install the Operator

The operator is now part of the main Helm chart and can be enabled optionally:

```bash
# Install gateway with operator enabled
helm install avapigw ./helm/avapigw \
  --set operator.enabled=true \
  -n avapigw \
  --create-namespace

# Verify installation
kubectl get pods -n avapigw
kubectl get crd | grep avapigw.io
```

#### Create Your First Route

```bash
# Create an APIRoute (note the new API group)
cat <<EOF | kubectl apply -f -
apiVersion: avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: hello-world
  namespace: default
spec:
  match:
    - uri:
        prefix: /hello
      methods:
        - GET
  route:
    - destination:
        host: hello-service
        port: 8080
  timeout: 30s
EOF

# Check route status
kubectl get apiroutes hello-world -o yaml
```

#### Create a Backend

```bash
# Create a Backend (note the new API group)
cat <<EOF | kubectl apply -f -
apiVersion: avapigw.io/v1alpha1
kind: Backend
metadata:
  name: hello-backend
  namespace: default
spec:
  hosts:
    - address: hello-service.default.svc.cluster.local
      port: 8080
      weight: 1
  healthCheck:
    path: /health
    interval: 10s
    timeout: 5s
    healthyThreshold: 2
    unhealthyThreshold: 3
  loadBalancer:
    algorithm: roundRobin
EOF

# Check backend status
kubectl get backends hello-backend -o yaml
```

### Available CRDs

The operator manages four types of Custom Resource Definitions:

| CRD | Kind | Description |
|-----|------|-------------|
| `apiroutes` | `APIRoute` | HTTP route configuration |
| `grpcroutes` | `GRPCRoute` | gRPC route configuration |
| `backends` | `Backend` | HTTP backend configuration |
| `grpcbackends` | `GRPCBackend` | gRPC backend configuration |

### RBAC Permissions

The operator requires comprehensive RBAC permissions for full functionality:

#### Core Resources
- **Events** - Recording reconciliation events and status changes
- **Secrets** - TLS certificates and sensitive data access (read-only)
- **ConfigMaps** - Configuration storage and management
- **Services/Endpoints** - Backend service discovery and health checking

#### CRD Management
- **APIRoute, GRPCRoute, Backend, GRPCBackend** - Full CRUD operations and status updates
- **Cross-reference validation** - Ensuring referenced backends exist

#### Ingress Support (when ingress controller enabled)
- **Ingress** - Reading and converting standard Kubernetes Ingress resources
- **IngressClass** - Managing IngressClass resources for opt-in behavior

#### Coordination and Security
- **Leases** - Leader election for high availability deployments
- **ValidatingWebhookConfigurations** - Webhook CA injection for certificate rotation

### Certificate Management

The operator supports three certificate management modes for webhook validation:

#### Self-Signed Mode (Default)
```yaml
operator:
  webhook:
    tls:
      mode: selfsigned
```
- Automatically generates self-signed certificates
- Handles certificate rotation and CA injection
- No external dependencies required

#### Vault PKI Mode
```yaml
operator:
  webhook:
    tls:
      mode: vault
vault:
  enabled: true
  address: "https://vault.example.com:8200"
  authMethod: kubernetes
  role: avapigw-operator
```
- Integrates with HashiCorp Vault PKI
- Automatic certificate issuance and renewal
- Enterprise-grade certificate management

#### Cert-Manager Mode
```yaml
operator:
  webhook:
    tls:
      mode: cert-manager
```
- Integrates with cert-manager for certificate lifecycle
- Supports various certificate issuers
- Kubernetes-native certificate management

### Documentation

For comprehensive operator documentation, see:

- **[Operator Overview](docs/operator/README.md)** - Architecture and key concepts
- **[Installation Guide](docs/operator/installation.md)** - Detailed installation instructions
- **[CRD Reference](docs/operator/crd-reference.md)** - Complete CRD specification
- **[Configuration Guide](docs/operator/configuration.md)** - Operator configuration options
- **[Vault PKI Integration](docs/operator/vault-pki.md)** - Certificate management setup
- **[Troubleshooting](docs/operator/troubleshooting.md)** - Common issues and solutions

### Makefile Targets

The project includes convenient Makefile targets for Helm and operator operations:

```bash
# Helm operations (gateway only)
make helm-lint                    # Lint Helm chart
make helm-template                # Template gateway only
make helm-install                 # Install gateway only
make helm-uninstall              # Uninstall from cluster

# Helm operations (with operator)
make helm-template-with-operator  # Template with operator
make helm-install-with-operator   # Install with operator

# Legacy aliases (still supported for backward compatibility)
make helm-template-operator       # Alias for helm-template-with-operator
make helm-install-operator        # Alias for helm-install-with-operator
```

### Monitoring

The operator exposes Prometheus metrics for monitoring:

```bash
# Check operator metrics (when operator is enabled)
kubectl port-forward -n avapigw svc/avapigw-operator-metrics 8080:8080
curl http://localhost:8080/metrics
```

Key metrics include:
- `controller_runtime_reconcile_total` - Total reconciliations
- `controller_runtime_reconcile_errors_total` - Reconciliation errors
- `controller_runtime_reconcile_time_seconds` - Reconciliation duration

### Examples

Complete examples are available in the [test/crd-samples/](test/crd-samples/) directory:

- [Basic APIRoute](test/crd-samples/apiroute-basic.yaml)
- [Advanced APIRoute with all features](test/crd-samples/apiroute-full.yaml)
- [GRPCRoute example](test/crd-samples/grpcroute-basic.yaml)
- [Backend with health checks](test/crd-samples/backend-basic.yaml)
- [GRPCBackend example](test/crd-samples/grpcbackend-basic.yaml)

## 🌐 Ingress Controller

The AVAPIGW Ingress Controller enables the operator to watch standard Kubernetes `networking.k8s.io/v1` Ingress resources and automatically translate them into internal APIRoute/Backend configuration. This provides a familiar Kubernetes-native way to configure the gateway using standard Ingress resources.

### Key Features

- **Standard Ingress Support** - Works with standard `networking.k8s.io/v1` Ingress resources
- **IngressClass Integration** - Uses `avapigw` IngressClass for opt-in behavior
- **Rich Annotations** - Extensive annotation support for advanced gateway features
- **Path Type Support** - Supports Exact, Prefix, and ImplementationSpecific path types
- **TLS Termination** - Automatic TLS configuration from Ingress TLS section
- **Default Backend** - Support for catch-all routing via default backend
- **Status Updates** - Updates Ingress status with LoadBalancer IP/hostname
- **Hot Configuration** - Changes are applied immediately without restart

### Quick Start

#### Prerequisites

- Kubernetes 1.23+
- AVAPIGW operator deployed with ingress controller enabled
- Standard Kubernetes Ingress resources

#### Enable Ingress Controller

The ingress controller is an optional feature that must be explicitly enabled:

```bash
# Enable via Helm values
helm install avapigw ./helm/avapigw \
  --set operator.enabled=true \
  --set operator.ingressController.enabled=true \
  -n avapigw \
  --create-namespace

# Or enable via environment variable
kubectl set env deployment/avapigw-operator \
  ENABLE_INGRESS_CONTROLLER=true \
  -n avapigw

# Or enable via command line flag
kubectl patch deployment avapigw-operator \
  --patch '{"spec":{"template":{"spec":{"containers":[{"name":"manager","args":["--enable-ingress-controller"]}]}}}}' \
  -n avapigw
```

#### Create Your First Ingress

```yaml
# Create IngressClass (automatically created by Helm chart)
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: avapigw
spec:
  controller: avapigw.io/ingress-controller

---
# Create Ingress resource
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
  annotations:
    avapigw.io/timeout: "30s"
    avapigw.io/retries: "3"
    avapigw.io/rate-limit-rps: "100"
spec:
  ingressClassName: avapigw
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /api/v1
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 8080
  tls:
  - hosts:
    - api.example.com
    secretName: api-tls
```

### Supported Annotations

The ingress controller supports a comprehensive set of annotations for configuring advanced gateway features:

| Annotation | Description | Example |
|------------|-------------|---------|
| `avapigw.io/timeout` | Request timeout | `30s` |
| `avapigw.io/retries` | Number of retries | `3` |
| `avapigw.io/retry-on` | Retry conditions | `5xx,reset` |
| `avapigw.io/rate-limit-rps` | Rate limit requests/sec | `100` |
| `avapigw.io/rate-limit-burst` | Rate limit burst | `200` |
| `avapigw.io/cors-allow-origins` | CORS allowed origins | `https://example.com` |
| `avapigw.io/cors-allow-methods` | CORS allowed methods | `GET,POST,PUT` |
| `avapigw.io/cors-allow-headers` | CORS allowed headers | `Content-Type,Authorization` |
| `avapigw.io/circuit-breaker-threshold` | Circuit breaker threshold | `5` |
| `avapigw.io/circuit-breaker-timeout` | Circuit breaker timeout | `30s` |
| `avapigw.io/load-balancer` | Load balancing algorithm | `round-robin` |
| `avapigw.io/health-check-path` | Health check path | `/health` |
| `avapigw.io/health-check-interval` | Health check interval | `10s` |
| `avapigw.io/strip-prefix` | Strip path prefix | `true` |
| `avapigw.io/rewrite-path` | Rewrite path | `/new-path` |
| `avapigw.io/websocket` | Enable WebSocket | `true` |
| `avapigw.io/max-body-size` | Max request body size | `10485760` |
| `avapigw.io/request-headers-add` | Add request headers | `X-Gateway:avapigw` |
| `avapigw.io/response-headers-add` | Add response headers | `X-Served-By:avapigw` |
| `avapigw.io/request-headers-remove` | Remove request headers | `X-Internal-Token` |
| `avapigw.io/response-headers-remove` | Remove response headers | `X-Debug` |

### Path Type Support

The ingress controller supports all standard Kubernetes path types:

#### Exact Path Matching
```yaml
spec:
  rules:
  - http:
      paths:
      - path: /api/v1/users
        pathType: Exact
        backend:
          service:
            name: user-service
            port:
              number: 8080
```

#### Prefix Path Matching
```yaml
spec:
  rules:
  - http:
      paths:
      - path: /api/v1
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 8080
```

#### Implementation Specific (Regex)
```yaml
spec:
  rules:
  - http:
      paths:
      - path: /users/[0-9]+
        pathType: ImplementationSpecific
        backend:
          service:
            name: user-service
            port:
              number: 8080
```

### TLS Configuration

The ingress controller automatically configures TLS based on the Ingress TLS section:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-example
spec:
  ingressClassName: avapigw
  tls:
  - hosts:
    - secure.example.com
    - api.example.com
    secretName: example-tls
  rules:
  - host: secure.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: secure-service
            port:
              number: 8080
```

### Default Backend

Configure a default backend for catch-all routing:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: default-backend-example
spec:
  ingressClassName: avapigw
  defaultBackend:
    service:
      name: default-service
      port:
        number: 8080
  rules:
  - host: example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 8080
```

### Advanced Configuration Examples

#### Rate Limiting and Circuit Breaker
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rate-limited-api
  annotations:
    avapigw.io/rate-limit-rps: "100"
    avapigw.io/rate-limit-burst: "200"
    avapigw.io/circuit-breaker-threshold: "5"
    avapigw.io/circuit-breaker-timeout: "30s"
spec:
  ingressClassName: avapigw
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /api/v1
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 8080
```

#### CORS Configuration
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cors-enabled-api
  annotations:
    avapigw.io/cors-allow-origins: "https://app.example.com,https://admin.example.com"
    avapigw.io/cors-allow-methods: "GET,POST,PUT,DELETE,OPTIONS"
    avapigw.io/cors-allow-headers: "Content-Type,Authorization,X-Requested-With"
spec:
  ingressClassName: avapigw
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /api/v1
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 8080
```

#### Header Manipulation
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: header-manipulation
  annotations:
    avapigw.io/request-headers-add: "X-Gateway:avapigw,X-Version:v1"
    avapigw.io/response-headers-add: "X-Served-By:avapigw"
    avapigw.io/request-headers-remove: "X-Internal-Token"
    avapigw.io/response-headers-remove: "X-Debug-Info"
spec:
  ingressClassName: avapigw
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /api/v1
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 8080
```

### Helm Chart Configuration

Configure the ingress controller through Helm values:

```yaml
operator:
  enabled: true
  ingressController:
    enabled: true              # Enable ingress controller
    className: "avapigw"       # IngressClass name
    isDefaultClass: false      # Set as default IngressClass
    lbAddress: ""              # LoadBalancer address for status updates
```

### Monitoring

Monitor ingress controller operations through metrics and logs:

```bash
# Check ingress controller logs
kubectl logs -n avapigw deployment/avapigw-operator -c manager

# Monitor ingress resources
kubectl get ingress --all-namespaces
kubectl describe ingress example-ingress

# Check generated APIRoutes and Backends
kubectl get apiroutes
kubectl get backends
```

### Troubleshooting

#### Common Issues

1. **Ingress not processed**
   - Verify IngressClass is set to `avapigw`
   - Check that ingress controller is enabled
   - Verify operator is running

2. **Annotations not applied**
   - Ensure annotations use `avapigw.io/` prefix
   - Check annotation syntax and values
   - Review operator logs for validation errors

3. **TLS not working**
   - Verify TLS secret exists and is valid
   - Check certificate format and content
   - Ensure hosts match certificate SANs

#### Debug Commands

```bash
# Check IngressClass
kubectl get ingressclass avapigw -o yaml

# Verify operator configuration
kubectl get deployment avapigw-operator -o yaml | grep -A5 -B5 ingress

# Check generated resources
kubectl get apiroutes,backends -o wide

# Monitor events
kubectl get events --field-selector involvedObject.kind=Ingress
```

For more detailed troubleshooting, see the [operator documentation](docs/operator/troubleshooting.md).

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
docker run -p 8080:8080 -p 9000:9000 -p 9090:9090 avapigw:latest

# With custom configuration
docker run -p 8080:8080 -p 9000:9000 -p 9090:9090 \
  -v $(pwd)/configs:/app/configs:ro \
  avapigw:latest

# With environment variables
docker run -p 8080:8080 -p 9000:9000 -p 9090:9090 \
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
| `GATEWAY_HTTP_PORT` | HTTP port | `8080` |
| `GATEWAY_GRPC_PORT` | gRPC port | `9000` |
| `GATEWAY_ADMIN_PORT` | Admin/metrics port | `9090` |
| `GATEWAY_ENV` | Environment name | `development` |

#### Authentication & Authorization Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GATEWAY_AUTH_ENABLED` | Enable authentication | `false` |
| `GATEWAY_AUTHZ_ENABLED` | Enable authorization | `false` |
| `GATEWAY_JWT_JWKS_URL` | JWT JWKS URL | - |
| `GATEWAY_JWT_ISSUER` | JWT issuer | - |
| `GATEWAY_JWT_AUDIENCE` | JWT audience | - |
| `OIDC_CLIENT_SECRET` | OIDC client secret | - |
| `AUTH0_CLIENT_SECRET` | Auth0 client secret | - |
| `OKTA_CLIENT_SECRET` | Okta client secret | - |
| `AZURE_CLIENT_SECRET` | Azure AD client secret | - |
| `VAULT_TOKEN` | Vault authentication token | - |
| `VAULT_ROLE_ID` | Vault AppRole role ID | - |
| `VAULT_SECRET_ID` | Vault AppRole secret ID | - |
| `OPA_ENDPOINT` | OPA authorization endpoint | - |
| `AUTHZ_TOKEN` | External authz service token | - |

### Docker Compose

```yaml
version: '3.8'
services:
  gateway:
    image: ghcr.io/vyrodovalexey/avapigw:latest
    ports:
      - "8080:8080"
      - "9000:9000"
      - "9090:9090"
    volumes:
      - ./configs:/app/configs:ro
    environment:
      - GATEWAY_LOG_LEVEL=info
      - GATEWAY_ENV=production
      - GATEWAY_AUTH_ENABLED=true
      - GATEWAY_AUTHZ_ENABLED=true
      - OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}
      - VAULT_TOKEN=${VAULT_TOKEN}
    depends_on:
      - keycloak
      - vault
      - opa
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9090/health"]
      interval: 30s
      timeout: 5s
      retries: 3

  # Keycloak for OIDC authentication
  keycloak-db:
    image: postgres:15
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: keycloak
    volumes:
      - keycloak_data:/var/lib/postgresql/data

  keycloak:
    image: quay.io/keycloak/keycloak:26.5
    ports:
      - "8090:8090"
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://keycloak-db:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: keycloak
      KC_HOSTNAME: 127.0.0.1
      KC_HTTP_PORT: 8090
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    command: start-dev
    depends_on:
      - keycloak-db

  # Vault for secret management
  vault:
    image: vault:latest
    ports:
      - "8200:8200"
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: myroot
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    cap_add:
      - IPC_LOCK

  # OPA for external authorization
  opa:
    image: openpolicyagent/opa:latest
    ports:
      - "8181:8181"
    volumes:
      - ./policies:/policies
    command: run --server --addr localhost:8181 /policies

  # Redis for caching
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --requirepass password

volumes:
  keycloak_data:
```

## 🔄 CI/CD

### GitHub Actions

The project includes a comprehensive CI/CD pipeline with enhanced security features including image signing and SBOM generation:

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

env:
  GO_VERSION: '1.25.6'
  GOLANGCI_LINT_VERSION: 'v2.8.0'

jobs:
  # Parallel quality checks
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
      - uses: golangci/golangci-lint-action@v9.2.0
        with:
          version: ${{ env.GOLANGCI_LINT_VERSION }}

  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
      - run: go test -race -coverprofile=coverage.out ./internal/... ./cmd/...
      - uses: codecov/codecov-action@v5
        with:
          files: ./coverage.out
          flags: unit

  # Enhanced build and security
  build:
    needs: [lint, unit-tests]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: make build-all
      - uses: actions/upload-artifact@v4
        with:
          name: binaries
          path: bin/

  docker:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/build-push-action@v5
        with:
          platforms: linux/amd64,linux/arm64
          push: false
          tags: ghcr.io/${{ github.repository }}:latest
```

### Enhanced Pipeline Stages

1. **Parallel Quality Checks**
   - **Lint** - Code quality checks with golangci-lint v2.8.0
   - **Vulnerability Check** - Security scanning with govulncheck
   - **Unit Tests** - Comprehensive test suite with 90%+ coverage
   - **Functional Tests** - End-to-end testing with enhanced coverage

2. **Build & Security**
   - **Build Binaries** - Multi-platform builds (Linux, macOS, Windows)
   - **Docker Images** - Multi-architecture containers (amd64, arm64)
   - **Security Scan** - Container vulnerability scanning
   - **Image Signing** - Cosign-based image signing for supply chain security
   - **SBOM Generation** - Software Bill of Materials for transparency

3. **Enhanced Validation**
   - **Operator Validation** - CRD validation, webhook testing, certificate management
   - **Ingress Controller Validation** - Standard Kubernetes Ingress support testing
   - **Helm Chart Validation** - Chart linting and template validation

4. **Release & Publish**
   - **Create Release** - Automated GitHub releases with artifacts
   - **Publish Images** - Signed container images to GitHub Container Registry

### Security Features

#### Image Signing with Cosign
All container images are signed using Cosign for supply chain security:

```bash
# Verify signed images
cosign verify ghcr.io/vyrodovalexey/avapigw:latest \
  --certificate-identity-regexp="https://github.com/vyrodovalexey/avapigw" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

#### SBOM Generation
Software Bill of Materials (SBOM) is generated for all releases:

```bash
# Download SBOM from release
gh release download --pattern="*sbom*" --repo vyrodovalexey/avapigw
```

#### Enhanced Security Scanning
- Multi-layer vulnerability scanning
- Critical vulnerability blocking
- Continuous security monitoring
- Compliance reporting

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

## 🚀 Performance Testing

The AV API Gateway includes comprehensive performance testing infrastructure using [Yandex Tank](https://yandextank.readthedocs.io/), a powerful load testing tool that provides high-performance load generation and detailed metrics.

### Overview

The performance testing infrastructure provides:
- **High-performance load generation** using Phantom engine
- **Detailed metrics and statistics** with real-time monitoring
- **Configurable load profiles** (constant, linear, step)
- **Autostop conditions** for safety during testing
- **Multiple test scenarios** covering different use cases

### Prerequisites

- **Docker** - Required to run Yandex Tank
- **Docker Compose** - For orchestrating test containers

```bash
# Install Docker Desktop (includes Docker Compose)
brew install --cask docker

# Pull Yandex Tank image
docker pull direvius/yandex-tank:latest
```

### Quick Start

#### 1. Start the Gateway for Testing

```bash
# Start gateway with performance-optimized configuration
make perf-start-gateway

# Or manually
./bin/gateway -config test/performance/configs/gateway-perftest.yaml
```

#### 2. Run a Basic Performance Test

```bash
# Run HTTP throughput test (default)
make perf-test

# Or run specific test
make perf-test-http
```

#### 3. Analyze Results

```bash
# Analyze latest test results
make perf-analyze

# Or manually
./test/performance/scripts/analyze-results.sh test/performance/results/http-throughput_*/
```

### Available Test Scenarios

#### HTTP Throughput Test
Tests maximum throughput for GET requests with simple payloads.

```bash
make perf-test-http
```

- **Load Profile**: Ramp 1→1000 RPS (2min), sustain 1000 RPS (3min)
- **Target**: Health and API endpoints
- **Purpose**: Measure baseline throughput capacity

#### HTTP POST Test
Tests throughput and latency for POST requests with JSON payloads.

```bash
make perf-test-post
```

- **Load Profile**: Ramp 1→500 RPS (2min), sustain 500 RPS (3min)
- **Target**: Items, Users, Orders endpoints
- **Purpose**: Measure performance with request bodies

#### Load Balancing Test
Verifies load distribution across multiple backends.

```bash
make perf-test-load-balancing
```

- **Load Profile**: Ramp 1→200 RPS (1min), sustain 200 RPS (5min)
- **Purpose**: Verify load balancer behavior and distribution

#### Rate Limiting Test
Stress tests the rate limiting functionality.

```bash
make perf-test-rate-limiting
```

- **Load Profile**: Below limit → exceed limit → recover
- **Purpose**: Verify rate limiter behavior under stress

#### Circuit Breaker Test
Tests circuit breaker behavior during backend failures.

```bash
make perf-test-circuit-breaker
```

- **Load Profile**: Constant 100 RPS for 8 minutes
- **Purpose**: Verify circuit breaker opens and recovers properly

#### Mixed Workload Test
Simulates realistic mixed traffic patterns.

```bash
make perf-test-mixed
```

- **Load Profile**: Complex multi-phase load with GET and POST requests
- **Purpose**: Realistic production-like load testing

#### Kubernetes Performance Tests
Tests the gateway deployed in Kubernetes with NodePort service routing to docker-compose backends.

```bash
# Run all K8s performance tests
make perf-test-k8s

# Run K8s HTTP performance test
make perf-test-k8s-http

# Run K8s gRPC performance test
make perf-test-k8s-grpc
```

- **Deployment**: Uses `helm/avapigw/values-local.yaml` for local Docker Desktop K8s
- **Routing**: NodePort service routes to `host.docker.internal` backends
- **Purpose**: Validate performance in Kubernetes environment

### Make Targets

| Target | Description |
|--------|-------------|
| `make perf-test` | Run HTTP throughput test (default) |
| `make perf-test-http` | Run HTTP GET throughput test |
| `make perf-test-post` | Run HTTP POST performance test |
| `make perf-test-mixed` | Run mixed workload test |
| `make perf-test-load-balancing` | Run load balancing verification |
| `make perf-test-rate-limiting` | Run rate limiting stress test |
| `make perf-test-circuit-breaker` | Run circuit breaker test |
| `make perf-test-all` | Run all performance tests sequentially |
| `make perf-test-k8s` | Run all K8s performance tests |
| `make perf-test-k8s-http` | Run K8s HTTP performance test |
| `make perf-test-k8s-grpc` | Run K8s gRPC performance test |
| `make perf-generate-ammo` | Generate ammo files for tests |
| `make perf-analyze` | Analyze latest test results |
| `make perf-start-gateway` | Start gateway for performance testing |
| `make perf-stop-gateway` | Stop performance test gateway |
| `make perf-clean` | Clean performance test results |

### Results and Analysis

#### Key Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| Total Requests | Number of requests sent | - |
| Error Rate | Percentage of failed requests | < 1% |
| Avg Latency | Average response time | < 100ms |
| P50 Latency | Median response time | < 50ms |
| P95 Latency | 95th percentile response time | < 200ms |
| P99 Latency | 99th percentile response time | < 500ms |

#### Analyzing Results

```bash
# Quick summary
./test/performance/scripts/analyze-results.sh results/http-throughput_*/ --summary

# Detailed analysis
./test/performance/scripts/analyze-results.sh results/http-throughput_*/ --detailed

# Export as JSON/CSV
./test/performance/scripts/analyze-results.sh results/http-throughput_*/ --export=json

# Compare test runs
./test/performance/scripts/analyze-results.sh results/run1/ --compare=results/run2/
```

#### Result Files

Test results are stored in `test/performance/results/` with the following structure:

```
results/
├── http-throughput_20240126_113619/
│   ├── load.yaml              # Test configuration
│   ├── tank_errors.log        # Error log
│   └── logs/
│       ├── phout.log          # Raw request/response data
│       ├── monitoring.log     # System monitoring data
│       └── validated_conf.yaml # Validated configuration
└── gateway.log                # Gateway logs during test
```

### Detailed Documentation

For comprehensive documentation including:
- Configuration reference
- Custom ammo generation
- Advanced load profiles
- Troubleshooting guide
- Integration with CI/CD

See: [test/performance/README.md](test/performance/README.md)

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

## 📞 Contact

- 📖 [Documentation](https://github.com/vyrodovalexey/avapigw/wiki)
- 🐛 [Issue Tracker](https://github.com/vyrodovalexey/avapigw/issues)
- 💬 [Discussions](https://github.com/vyrodovalexey/avapigw/discussions)
- 📧 [Email](mailto:vyrodov.alexey@gmail.com)
- 📧 [LinkedIN] (https://www.linkedin.com/in/
alexey-vyrodov-16b97659)

---

**AV API Gateway** - Built with ❤️ for cloud-native applications