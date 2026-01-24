# Ava API Gateway

[![CI](https://github.com/vyrodovalexey/avapigw/actions/workflows/ci.yml/badge.svg)](https://github.com/vyrodovalexey/avapigw/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/vyrodovalexey/avapigw)](https://goreportcard.com/report/github.com/vyrodovalexey/avapigw)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/go-1.25+-blue.svg)](https://golang.org/dl/)

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
- **Certificate Auto-Renewal** - Automatic certificate renewal with Vault PKI

### Authentication & Authorization
- **JWT Authentication** - Multiple algorithms (RS256, ES256, HS256, etc.) with JWK URL support
- **API Key Authentication** - Header/query/metadata extraction with hashing and rate limiting
- **mTLS Authentication** - Client certificate validation with identity extraction
- **OIDC Integration** - Keycloak, Auth0, Okta, Azure AD support with discovery
- **RBAC Authorization** - Role-based access control from JWT claims
- **ABAC Authorization** - Attribute-based with CEL expressions
- **External Authorization** - OPA integration for complex policies
- **Policy Caching** - Configurable TTL for authorization decisions
- **Security Headers** - HSTS, CSP, X-Frame-Options, and more
- **Audit Logging** - Comprehensive authentication and authorization logging

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

### Data Transformation
- **Field Filtering** - Filter response fields using allow/deny lists
- **Field Mapping** - Rename and remap response fields
- **Field Grouping** - Group fields into nested objects
- **Field Flattening** - Extract and flatten nested objects
- **Array Operations** - Append, prepend, filter, sort, limit, deduplicate arrays
- **Response Templating** - Use Go templates for custom response formatting
- **Response Merging** - Merge responses from multiple backends (deep, shallow, replace strategies)
- **Request Manipulation** - Transform request body using templates and field operations
- **gRPC FieldMask** - Filter gRPC responses using Protocol Buffer FieldMask
- **Metadata Transformation** - Transform gRPC metadata (static and dynamic)
- **Streaming Transformation** - Transform streaming messages with rate limiting

### Caching
- **In-Memory Cache** - Fast local caching with TTL and max entries
- **Redis Cache** - Distributed caching with Redis
- **Cache Key Generation** - Configurable cache key components
- **Cache Control** - Honor Cache-Control headers
- **Stale-While-Revalidate** - Serve stale data while revalidating
- **Negative Caching** - Cache error responses

### Encoding Support
- **JSON** - Full JSON encoding/decoding with configurable options
- **XML** - XML encoding/decoding
- **YAML** - YAML encoding/decoding
- **Content Negotiation** - Automatic content type negotiation based on Accept header

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
- [TLS & Transport Security](#-tls--transport-security)
- [Vault Integration](#-vault-integration)
- [Authentication](#-authentication)
- [Authorization](#-authorization)
- [Data Transformation](#-data-transformation)
- [API Endpoints](#-api-endpoints)
- [Routing](#-routing)
- [gRPC Gateway](#-grpc-gateway)
- [Traffic Management](#-traffic-management)
- [Observability](#-observability)
- [Development](#-development)
- [Docker](#-docker)
- [CI/CD](#-cicd)
- [Contributing](#-contributing)
- [License](#-license)

## 🏃 Quick Start

### Prerequisites
- Go 1.25+ (for building from source)
- Docker (for containerized deployment)

### Running with Docker

```bash
# Pull the latest image
docker pull ghcr.io/vyrodovalexey/avapigw:latest

# Run with default configuration
docker run -p 8080:8080 -p 9000:9000 -p 9090:9090 ghcr.io/vyrodovalexey/avapigw:latest

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

The gateway will start on port 8080 (HTTP traffic) and 9090 (metrics/health). gRPC traffic on port 9000 is optional and can be enabled in the configuration.

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

## 🔐 TLS & Transport Security

The Ava API Gateway provides comprehensive TLS support for secure communication between clients and the gateway, as well as between the gateway and backend services. The gateway supports multiple TLS modes, modern TLS versions, and flexible certificate management.

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

## 🔐 Vault Integration

The Ava API Gateway integrates with HashiCorp Vault for secure secret management, including dynamic certificate provisioning, secret storage, and authentication token management.

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

## 🔐 Authentication

The Ava API Gateway provides comprehensive authentication capabilities supporting multiple authentication methods for both HTTP and gRPC protocols. Authentication can be configured globally or per-route, with support for multiple authentication providers and token extraction methods.

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

The Ava API Gateway provides flexible authorization capabilities including Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC), and integration with external authorization services like Open Policy Agent (OPA).

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

The Ava API Gateway provides comprehensive data transformation capabilities for both HTTP and gRPC protocols.

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
- `gateway_requests_total` - Total HTTP requests
- `gateway_request_duration_seconds` - Request duration histogram
- `gateway_request_size_bytes` - Request size histogram
- `gateway_response_size_bytes` - Response size histogram
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
- `gateway_rate_limit_hits_total` - Rate limit hits

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

# Integration tests (requires Redis)
make test-integration

# E2E tests (requires Redis and backends)
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