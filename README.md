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
- **Native gRPC Support** - Full gRPC over HTTP/2 with dedicated port
- **gRPC Streaming** - Support for unary, server streaming, client streaming, and bidirectional streaming
- **gRPC Routing** - Service and method-based routing with metadata matching
- **gRPC Health Service** - Built-in grpc.health.v1.Health implementation
- **gRPC Reflection** - Optional gRPC reflection service for service discovery

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
- Go 1.24+ (for building from source)
- Docker (for containerized deployment)

### Running with Docker

```bash
# Pull the latest image
docker pull ghcr.io/avapigw/avapigw:latest

# Run with default configuration
docker run -p 8080:8080 -p 9000:9000 -p 9090:9090 ghcr.io/avapigw/avapigw:latest

# Run with custom configuration
docker run -p 8080:8080 -p 9000:9000 -p 9090:9090 \
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

The gateway will start on port 8080 (HTTP traffic), 9000 (gRPC traffic), and 9090 (metrics/health).

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

### Docker Compose

```yaml
version: '3.8'
services:
  gateway:
    image: ghcr.io/avapigw/avapigw:latest
    ports:
      - "8080:8080"
      - "9000:9000"
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