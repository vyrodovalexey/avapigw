# CRD Reference Guide

This document provides a comprehensive reference for all Custom Resource Definitions (CRDs) managed by the AVAPIGW Operator.

## Table of Contents

- [Overview](#overview)
- [Ingress Support](#ingress-support)
  - [gRPC Ingress Support](#grpc-ingress-support)
- [APIRoute CRD](#apiroute-crd)
- [GRPCRoute CRD](#grpcroute-crd)
- [Backend CRD](#backend-crd)
- [GRPCBackend CRD](#grpcbackend-crd)
- [Status Conditions](#status-conditions)
- [Examples](#examples)

## Overview

The AVAPIGW Operator manages four types of Custom Resource Definitions:

| CRD | Kind | API Group | Description |
|-----|------|-----------|-------------|
| `apiroutes` | `APIRoute` | `avapigw.io/v1alpha1` | HTTP route configuration |
| `grpcroutes` | `GRPCRoute` | `avapigw.io/v1alpha1` | gRPC route configuration |
| `backends` | `Backend` | `avapigw.io/v1alpha1` | HTTP backend configuration |
| `grpcbackends` | `GRPCBackend` | `avapigw.io/v1alpha1` | gRPC backend configuration |

All CRDs are namespaced and support the following common features:
- **Status reporting** with conditions
- **Finalizers** for cleanup
- **Labels and annotations** for organization
- **Admission webhook validation**
- **Cross-CRD duplicate detection** to prevent conflicts

**Important**: CRDs configure route and backend level settings only. Main gateway configuration (listeners, global settings) must still be configured through the gateway's YAML configuration file.

## Ingress Support

The AVAPIGW Operator supports standard Kubernetes `networking.k8s.io/v1` Ingress resources. Ingress resources assigned to the `avapigw` IngressClass are automatically converted to internal gateway configuration (routes and backends).

### Ingress Protocol Support

| Protocol | Ingress Support | Recommended CRD |
|----------|-----------------|-----------------|
| HTTP/1.1 | Full support | Ingress or APIRoute |
| HTTP/2 | Full support | Ingress or APIRoute |
| gRPC | Full support via annotations | Ingress (with gRPC annotations) or GRPCRoute + GRPCBackend |
| gRPC-Web | Full support via annotations | Ingress (with gRPC annotations) or GRPCRoute + GRPCBackend |

**gRPC Support Options**:
- **gRPC Ingress**: Use standard Kubernetes Ingress with `avapigw.io/protocol: "grpc"` annotation for gRPC traffic. This provides gRPC-specific features through annotations and automatically creates GRPCRoute/GRPCBackend resources internally.
- **Native gRPC CRDs**: Use [GRPCRoute CRD](#grpcroute-crd) and [GRPCBackend CRD](#grpcbackend-crd) for advanced gRPC features and fine-grained control.

Both approaches provide:
- gRPC service and method matching
- gRPC health checking
- gRPC-specific retry conditions (e.g., `unavailable`, `resource-exhausted`)
- gRPC metadata manipulation
- Field mask transformations
- Connection pooling optimized for gRPC

### IngressClass Configuration

To use AVAPIGW as your Ingress controller, create an IngressClass resource:

```yaml
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: avapigw
  annotations:
    ingressclass.kubernetes.io/is-default-class: "false"
spec:
  controller: avapigw.io/ingress-controller
```

### Ingress Resource Assignment

Assign an Ingress to AVAPIGW using either:

**Option 1: spec.ingressClassName (Recommended)**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
spec:
  ingressClassName: avapigw
  rules:
    - host: api.example.com
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

**Option 2: Legacy Annotation**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  annotations:
    kubernetes.io/ingress.class: avapigw
spec:
  rules:
    - host: api.example.com
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

### Ingress Annotations Reference

AVAPIGW extends standard Ingress functionality through annotations. All AVAPIGW-specific annotations use the `avapigw.io/` prefix.

#### Timeout and Retry Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/timeout` | duration | Request timeout for routes | `30s`, `1m`, `500ms` |
| `avapigw.io/retry-attempts` | integer | Number of retry attempts | `3` |
| `avapigw.io/retry-per-try-timeout` | duration | Timeout per retry attempt | `10s` |
| `avapigw.io/retry-on` | string | Comma-separated retry conditions | `5xx,reset,connect-failure` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/timeout: "30s"
    avapigw.io/retry-attempts: "3"
    avapigw.io/retry-per-try-timeout: "10s"
    avapigw.io/retry-on: "5xx,reset,connect-failure"
```

#### Rate Limiting Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/rate-limit-enabled` | boolean | Enable rate limiting | `true` |
| `avapigw.io/rate-limit-rps` | integer | Requests per second limit | `100` |
| `avapigw.io/rate-limit-burst` | integer | Burst capacity | `200` |
| `avapigw.io/rate-limit-per-client` | boolean | Enable per-client rate limiting | `true` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/rate-limit-enabled: "true"
    avapigw.io/rate-limit-rps: "100"
    avapigw.io/rate-limit-burst: "200"
    avapigw.io/rate-limit-per-client: "true"
```

#### CORS Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/cors-allow-origins` | CSV | Allowed origins (comma-separated) | `https://example.com,https://app.example.com` |
| `avapigw.io/cors-allow-methods` | CSV | Allowed HTTP methods | `GET,POST,PUT,DELETE` |
| `avapigw.io/cors-allow-headers` | CSV | Allowed request headers | `Content-Type,Authorization` |
| `avapigw.io/cors-expose-headers` | CSV | Headers exposed to browser | `X-Request-ID,X-Response-Time` |
| `avapigw.io/cors-max-age` | integer | Preflight cache duration (seconds) | `86400` |
| `avapigw.io/cors-allow-credentials` | boolean | Allow credentials in CORS | `true` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/cors-allow-origins: "https://example.com,https://app.example.com"
    avapigw.io/cors-allow-methods: "GET,POST,PUT,DELETE"
    avapigw.io/cors-allow-headers: "Content-Type,Authorization"
    avapigw.io/cors-expose-headers: "X-Request-ID"
    avapigw.io/cors-max-age: "86400"
    avapigw.io/cors-allow-credentials: "true"
```

#### Rewrite and Redirect Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/rewrite-uri` | string | URI rewrite target | `/internal/api` |
| `avapigw.io/rewrite-authority` | string | Host header rewrite | `internal.example.com` |
| `avapigw.io/redirect-uri` | string | Redirect URI | `/new-path` |
| `avapigw.io/redirect-code` | integer | Redirect HTTP status code | `301`, `302`, `307`, `308` |
| `avapigw.io/redirect-scheme` | string | Redirect scheme | `https` |

**Example (Rewrite):**
```yaml
metadata:
  annotations:
    avapigw.io/rewrite-uri: "/internal/api"
    avapigw.io/rewrite-authority: "internal.example.com"
```

**Example (Redirect):**
```yaml
metadata:
  annotations:
    avapigw.io/redirect-uri: "/new-location"
    avapigw.io/redirect-code: "301"
    avapigw.io/redirect-scheme: "https"
```

#### Health Check Annotations (Backend)

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/health-check-path` | string | Health check endpoint path | `/health` |
| `avapigw.io/health-check-interval` | duration | Health check interval | `10s` |
| `avapigw.io/health-check-timeout` | duration | Health check timeout | `5s` |
| `avapigw.io/health-check-healthy-threshold` | integer | Successes to mark healthy | `2` |
| `avapigw.io/health-check-unhealthy-threshold` | integer | Failures to mark unhealthy | `3` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/health-check-path: "/health"
    avapigw.io/health-check-interval: "10s"
    avapigw.io/health-check-timeout: "5s"
    avapigw.io/health-check-healthy-threshold: "2"
    avapigw.io/health-check-unhealthy-threshold: "3"
```

#### Load Balancer Annotations (Backend)

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/load-balancer-algorithm` | string | Load balancing algorithm | `roundRobin`, `weighted`, `leastConn`, `random` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/load-balancer-algorithm: "roundRobin"
```

#### Circuit Breaker Annotations (Backend)

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/circuit-breaker-enabled` | boolean | Enable circuit breaker | `true` |
| `avapigw.io/circuit-breaker-threshold` | integer | Failure threshold to open circuit | `5` |
| `avapigw.io/circuit-breaker-timeout` | duration | Time in open state before half-open | `30s` |
| `avapigw.io/circuit-breaker-half-open` | integer | Requests allowed in half-open state | `3` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/circuit-breaker-enabled: "true"
    avapigw.io/circuit-breaker-threshold: "5"
    avapigw.io/circuit-breaker-timeout: "30s"
    avapigw.io/circuit-breaker-half-open: "3"
```

#### TLS Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/tls-min-version` | string | Minimum TLS version | `TLS12`, `TLS13` |
| `avapigw.io/tls-max-version` | string | Maximum TLS version | `TLS12`, `TLS13` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/tls-min-version: "TLS12"
    avapigw.io/tls-max-version: "TLS13"
```

#### Security Headers Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/security-enabled` | boolean | Enable security headers | `true` |
| `avapigw.io/security-x-frame-options` | string | X-Frame-Options header value | `DENY`, `SAMEORIGIN` |
| `avapigw.io/security-x-content-type-options` | string | X-Content-Type-Options header | `nosniff` |
| `avapigw.io/security-x-xss-protection` | string | X-XSS-Protection header | `1; mode=block` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/security-enabled: "true"
    avapigw.io/security-x-frame-options: "DENY"
    avapigw.io/security-x-content-type-options: "nosniff"
    avapigw.io/security-x-xss-protection: "1; mode=block"
```

#### Encoding Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/encoding-request-content-type` | string | Request content type | `application/json` |
| `avapigw.io/encoding-response-content-type` | string | Response content type | `application/json` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/encoding-request-content-type: "application/json"
    avapigw.io/encoding-response-content-type: "application/json"
```

#### Cache Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/cache-enabled` | boolean | Enable response caching | `true` |
| `avapigw.io/cache-ttl` | duration | Cache time-to-live | `5m`, `1h` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/cache-enabled: "true"
    avapigw.io/cache-ttl: "5m"
```

#### Session Limiting Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/max-sessions-enabled` | boolean | Enable session limiting | `true` |
| `avapigw.io/max-sessions-max-concurrent` | integer | Maximum concurrent sessions | `1000` |
| `avapigw.io/max-sessions-queue-size` | integer | Queue size for waiting requests | `100` |
| `avapigw.io/max-sessions-queue-timeout` | duration | Queue timeout | `10s` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/max-sessions-enabled: "true"
    avapigw.io/max-sessions-max-concurrent: "1000"
    avapigw.io/max-sessions-queue-size: "100"
    avapigw.io/max-sessions-queue-timeout: "10s"
```

#### Request Limits Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/max-body-size` | integer | Maximum request body size (bytes) | `10485760` (10MB) |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/max-body-size: "10485760"
```

#### Authentication Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/auth-enabled` | boolean | Enable authentication | `true` |
| `avapigw.io/auth-type` | string | Authentication type | `jwt`, `apiKey`, `mtls` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/auth-enabled: "true"
    avapigw.io/auth-type: "jwt"
```

#### Protocol Selection Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/protocol` | string | Protocol type for the Ingress | `http`, `grpc`, `h2c` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/protocol: "grpc"
```

#### gRPC Service/Method Matching Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/grpc-service` | string | gRPC service name to match | `mypackage.MyService` |
| `avapigw.io/grpc-service-match-type` | string | Service match type | `exact`, `prefix`, `regex` (default: `prefix`) |
| `avapigw.io/grpc-method` | string | gRPC method name to match | `MyMethod` |
| `avapigw.io/grpc-method-match-type` | string | Method match type | `exact`, `prefix`, `regex` (default: `prefix`) |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/grpc-service: "mypackage.MyService"
    avapigw.io/grpc-service-match-type: "exact"
    avapigw.io/grpc-method: "MyMethod"
    avapigw.io/grpc-method-match-type: "exact"
```

#### gRPC Retry Configuration Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/grpc-retry-on` | CSV | gRPC status codes to retry on | `unavailable,resource-exhausted` |
| `avapigw.io/grpc-backoff-base-interval` | duration | Base interval for exponential backoff | `100ms` |
| `avapigw.io/grpc-backoff-max-interval` | duration | Maximum backoff interval | `10s` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/grpc-retry-on: "unavailable,resource-exhausted"
    avapigw.io/grpc-backoff-base-interval: "100ms"
    avapigw.io/grpc-backoff-max-interval: "10s"
```

#### gRPC Health Check Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/grpc-health-check-enabled` | boolean | Enable gRPC health checking | `true` |
| `avapigw.io/grpc-health-check-service` | string | Service name for gRPC health check | `mypackage.MyService` |
| `avapigw.io/grpc-health-check-interval` | duration | Health check interval | `10s` |
| `avapigw.io/grpc-health-check-timeout` | duration | Health check timeout | `5s` |
| `avapigw.io/grpc-health-check-healthy-threshold` | integer | Healthy threshold count | `2` |
| `avapigw.io/grpc-health-check-unhealthy-threshold` | integer | Unhealthy threshold count | `3` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/grpc-health-check-enabled: "true"
    avapigw.io/grpc-health-check-service: "mypackage.MyService"
    avapigw.io/grpc-health-check-interval: "10s"
    avapigw.io/grpc-health-check-timeout: "5s"
    avapigw.io/grpc-health-check-healthy-threshold: "2"
    avapigw.io/grpc-health-check-unhealthy-threshold: "3"
```

#### gRPC Connection Pool Annotations

| Annotation | Type | Description | Example |
|------------|------|-------------|---------|
| `avapigw.io/grpc-max-idle-conns` | integer | Maximum idle connections | `100` |
| `avapigw.io/grpc-max-conns-per-host` | integer | Maximum connections per host | `50` |
| `avapigw.io/grpc-idle-conn-timeout` | duration | Idle connection timeout | `90s` |

**Example:**
```yaml
metadata:
  annotations:
    avapigw.io/grpc-max-idle-conns: "100"
    avapigw.io/grpc-max-conns-per-host: "50"
    avapigw.io/grpc-idle-conn-timeout: "90s"
```

#### Internal Annotations (Managed by Controller)

| Annotation | Description |
|------------|-------------|
| `avapigw.io/applied-routes` | Tracks applied routes and backends for cleanup (managed automatically) |

### Complete Ingress Example

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  namespace: production
  annotations:
    # Timeout and retries
    avapigw.io/timeout: "30s"
    avapigw.io/retry-attempts: "3"
    avapigw.io/retry-per-try-timeout: "10s"
    avapigw.io/retry-on: "5xx,reset,connect-failure"
    
    # Rate limiting
    avapigw.io/rate-limit-enabled: "true"
    avapigw.io/rate-limit-rps: "100"
    avapigw.io/rate-limit-burst: "200"
    avapigw.io/rate-limit-per-client: "true"
    
    # CORS
    avapigw.io/cors-allow-origins: "https://app.example.com"
    avapigw.io/cors-allow-methods: "GET,POST,PUT,DELETE"
    avapigw.io/cors-allow-headers: "Content-Type,Authorization"
    avapigw.io/cors-allow-credentials: "true"
    
    # Health check
    avapigw.io/health-check-path: "/health"
    avapigw.io/health-check-interval: "10s"
    avapigw.io/health-check-timeout: "5s"
    
    # Circuit breaker
    avapigw.io/circuit-breaker-enabled: "true"
    avapigw.io/circuit-breaker-threshold: "5"
    avapigw.io/circuit-breaker-timeout: "30s"
    
    # Security headers
    avapigw.io/security-enabled: "true"
    avapigw.io/security-x-frame-options: "DENY"
    avapigw.io/security-x-content-type-options: "nosniff"
    
    # TLS
    avapigw.io/tls-min-version: "TLS12"
    
    # Session limiting
    avapigw.io/max-sessions-enabled: "true"
    avapigw.io/max-sessions-max-concurrent: "1000"
    
    # Request limits
    avapigw.io/max-body-size: "10485760"
    
    # Caching
    avapigw.io/cache-enabled: "true"
    avapigw.io/cache-ttl: "5m"
spec:
  ingressClassName: avapigw
  tls:
    - hosts:
        - api.example.com
      secretName: api-tls-secret
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
          - path: /api/v2
            pathType: Prefix
            backend:
              service:
                name: api-service-v2
                port:
                  number: 8080
  defaultBackend:
    service:
      name: default-backend
      port:
        number: 80
```

### Ingress Validation Rules

The AVAPIGW operator validates Ingress resources through admission webhooks:

#### Host Validation
- Hostnames must be valid DNS names
- Wildcard hosts (e.g., `*.example.com`) are supported
- Host labels cannot exceed 63 characters
- Hosts cannot start or end with a dot

#### Path Validation
- Paths must start with `/`
- PathType must be `Prefix`, `Exact`, or `ImplementationSpecific`
- Duplicate host/path combinations within the same Ingress are rejected

#### Backend Validation
- Either `service` or `resource` must be specified
- Service name is required
- Port number must be between 1 and 65535, or port name must be specified

#### TLS Validation
- Secret name is required for TLS configuration
- TLS hosts must be valid DNS names

#### Conflict Detection
- Ingress paths are checked against existing APIRoute CRDs
- Overlapping paths between Ingress and APIRoute resources are rejected
- This prevents configuration conflicts in the gateway

### Ingress to Gateway Conversion

When an Ingress is reconciled, the operator converts it to internal gateway configuration:

| Ingress Component | Gateway Configuration |
|-------------------|----------------------|
| `spec.rules[].host` | Route SNI hosts (if TLS enabled) |
| `spec.rules[].http.paths[].path` | Route URI match |
| `spec.rules[].http.paths[].pathType` | Route URI match type (prefix/exact) |
| `spec.rules[].http.paths[].backend` | Backend host and port |
| `spec.tls` | Route TLS configuration |
| `spec.defaultBackend` | Catch-all route with `/` prefix |
| Annotations | Route and backend configuration |

### Ingress Lifecycle

1. **Creation**: Ingress is validated, converted to routes/backends, and applied to the gateway
2. **Update**: Changes are validated, routes/backends are updated
3. **Deletion**: Finalizer ensures all routes/backends are cleaned up before removal

The operator tracks applied routes using the `avapigw.io/applied-routes` annotation for reliable cleanup.

## gRPC Ingress Support

AVAPIGW now supports gRPC protocol through standard Kubernetes Ingress resources using the `avapigw.io/protocol: "grpc"` annotation. This provides a familiar Kubernetes-native way to configure gRPC routing while leveraging the full power of gRPC-specific features.

### How gRPC Ingress Works

When you set `avapigw.io/protocol: "grpc"` on an Ingress resource, the AVAPIGW operator:

1. **Validates** the Ingress configuration for gRPC compatibility
2. **Creates** internal GRPCRoute and GRPCBackend resources automatically
3. **Applies** gRPC-specific configurations from annotations
4. **Manages** the lifecycle of the generated gRPC resources

This approach provides the simplicity of Ingress with the advanced features of native gRPC CRDs.

### gRPC vs HTTP Ingress Differences

| Aspect | HTTP Ingress | gRPC Ingress |
|--------|--------------|--------------|
| **Protocol** | HTTP/1.1, HTTP/2 | gRPC over HTTP/2 |
| **Path Matching** | URI paths (e.g., `/api/v1`) | gRPC service/method names |
| **Routing Logic** | Path-based routing | Service and method matching |
| **Health Checks** | HTTP endpoint checks | gRPC health protocol |
| **Retry Logic** | HTTP status codes | gRPC status codes |
| **Load Balancing** | Standard HTTP | gRPC-aware connection pooling |
| **TLS** | Standard TLS termination | gRPC-compatible TLS |

### Basic gRPC Ingress Configuration

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-basic
  namespace: default
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
spec:
  ingressClassName: avapigw
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /mypackage.MyService
            pathType: Prefix
            backend:
              service:
                name: grpc-backend
                port:
                  number: 50051
```

### gRPC Ingress with Service/Method Matching

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-service-method
  namespace: default
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
    
    # gRPC service/method matching
    avapigw.io/grpc-service: "mypackage.MyService"
    avapigw.io/grpc-service-match-type: "exact"
    avapigw.io/grpc-method: "GetUser"
    avapigw.io/grpc-method-match-type: "exact"
spec:
  ingressClassName: avapigw
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /mypackage.MyService/GetUser
            pathType: Exact
            backend:
              service:
                name: user-service
                port:
                  number: 50051
```

### gRPC Ingress with Retry Configuration

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-retry
  namespace: default
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
    
    # Standard retry configuration
    avapigw.io/retry-attempts: "3"
    avapigw.io/retry-per-try-timeout: "5s"
    
    # gRPC-specific retry configuration
    avapigw.io/grpc-retry-on: "unavailable,resource-exhausted,deadline-exceeded"
    avapigw.io/grpc-backoff-base-interval: "100ms"
    avapigw.io/grpc-backoff-max-interval: "10s"
spec:
  ingressClassName: avapigw
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /api.v1.OrderService
            pathType: Prefix
            backend:
              service:
                name: order-service
                port:
                  number: 50051
```

### gRPC Ingress with Health Check

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-health-check
  namespace: default
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
    
    # gRPC health check configuration
    avapigw.io/grpc-health-check-enabled: "true"
    avapigw.io/grpc-health-check-service: "api.v1.OrderService"
    avapigw.io/grpc-health-check-interval: "10s"
    avapigw.io/grpc-health-check-timeout: "5s"
    avapigw.io/grpc-health-check-healthy-threshold: "2"
    avapigw.io/grpc-health-check-unhealthy-threshold: "3"
spec:
  ingressClassName: avapigw
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /api.v1.OrderService
            pathType: Prefix
            backend:
              service:
                name: order-service
                port:
                  number: 50051
```

### gRPC Ingress with Connection Pool

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-connection-pool
  namespace: default
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
    
    # gRPC connection pool configuration
    avapigw.io/grpc-max-idle-conns: "100"
    avapigw.io/grpc-max-conns-per-host: "50"
    avapigw.io/grpc-idle-conn-timeout: "90s"
spec:
  ingressClassName: avapigw
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /api.v1.UserService
            pathType: Prefix
            backend:
              service:
                name: user-service
                port:
                  number: 50051
```

### gRPC Ingress with TLS

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-tls
  namespace: default
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
    
    # TLS configuration
    avapigw.io/tls-min-version: "TLS12"
    avapigw.io/tls-max-version: "TLS13"
    
    # gRPC service matching
    avapigw.io/grpc-service: "api.v1.PaymentService"
    avapigw.io/grpc-service-match-type: "exact"
spec:
  ingressClassName: avapigw
  tls:
    - hosts:
        - grpc.example.com
      secretName: grpc-tls-secret
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /api.v1.PaymentService
            pathType: Prefix
            backend:
              service:
                name: payment-service
                port:
                  number: 50051
```

### Complete gRPC Ingress Example

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-complete
  namespace: production
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
    
    # gRPC service/method matching
    avapigw.io/grpc-service: "mypackage.MyService"
    avapigw.io/grpc-service-match-type: "exact"
    avapigw.io/grpc-method: "MyMethod"
    avapigw.io/grpc-method-match-type: "exact"
    
    # Timeout and retry configuration
    avapigw.io/timeout: "30s"
    avapigw.io/retry-attempts: "3"
    avapigw.io/retry-per-try-timeout: "5s"
    avapigw.io/grpc-retry-on: "unavailable,resource-exhausted"
    avapigw.io/grpc-backoff-base-interval: "100ms"
    avapigw.io/grpc-backoff-max-interval: "10s"
    
    # gRPC health check
    avapigw.io/grpc-health-check-enabled: "true"
    avapigw.io/grpc-health-check-service: "mypackage.MyService"
    avapigw.io/grpc-health-check-interval: "10s"
    avapigw.io/grpc-health-check-timeout: "5s"
    avapigw.io/grpc-health-check-healthy-threshold: "2"
    avapigw.io/grpc-health-check-unhealthy-threshold: "3"
    
    # Connection pool
    avapigw.io/grpc-max-idle-conns: "100"
    avapigw.io/grpc-max-conns-per-host: "50"
    avapigw.io/grpc-idle-conn-timeout: "90s"
    
    # Rate limiting
    avapigw.io/rate-limit-enabled: "true"
    avapigw.io/rate-limit-rps: "100"
    avapigw.io/rate-limit-burst: "200"
    
    # Circuit breaker
    avapigw.io/circuit-breaker-enabled: "true"
    avapigw.io/circuit-breaker-threshold: "5"
    avapigw.io/circuit-breaker-timeout: "30s"
    
    # TLS
    avapigw.io/tls-min-version: "TLS12"
    
    # Authentication
    avapigw.io/auth-enabled: "true"
    avapigw.io/auth-type: "jwt"
spec:
  ingressClassName: avapigw
  tls:
    - hosts:
        - grpc.example.com
      secretName: grpc-tls-secret
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /mypackage.MyService
            pathType: Prefix
            backend:
              service:
                name: grpc-backend
                port:
                  number: 50051
```

### When to Use gRPC Ingress vs GRPCRoute CRD

| Use Case | Recommended Approach | Reason |
|----------|---------------------|---------|
| **Simple gRPC routing** | gRPC Ingress | Familiar Kubernetes Ingress pattern |
| **Standard gRPC features** | gRPC Ingress | Annotations provide most common features |
| **Team familiar with Ingress** | gRPC Ingress | Lower learning curve |
| **Advanced gRPC features** | GRPCRoute CRD | Full control over gRPC-specific settings |
| **Complex routing logic** | GRPCRoute CRD | More flexible matching and routing |
| **Field mask transformations** | GRPCRoute CRD | Advanced data transformation |
| **Multiple gRPC backends** | GRPCRoute CRD | Better backend management |
| **Custom metadata manipulation** | GRPCRoute CRD | Fine-grained control |

### Protocol Comparison Table

| Protocol | Use Case | Ingress Resource | Recommended For |
|----------|----------|------------------|-----------------|
| **HTTP** | REST APIs, web applications | Standard Ingress | Web traffic, REST APIs |
| **gRPC** | gRPC services via Ingress | Ingress with `avapigw.io/protocol: "grpc"` | Teams familiar with Ingress |
| **gRPC** | Advanced gRPC features | GRPCRoute + GRPCBackend CRDs | Complex gRPC routing, advanced features |

### gRPC Services with Ingress (Legacy - Deprecated)

**Note**: This section describes the legacy approach before gRPC Ingress support was added. For new deployments, use [gRPC Ingress Support](#grpc-ingress-support) instead.

Previously, standard Kubernetes Ingress did not support gRPC traffic natively. The recommended approach was to use AVAPIGW native CRDs instead.

#### Migration from Legacy Approach to gRPC Ingress

If you have existing GRPCRoute/GRPCBackend CRDs and want to migrate to the simpler gRPC Ingress approach:

**Legacy GRPCRoute approach:**
```yaml
apiVersion: avapigw.io/v1alpha1
kind: GRPCRoute
metadata:
  name: grpc-service-route
  namespace: production
spec:
  match:
    - service:
        prefix: "api.v1"           # Match gRPC services starting with api.v1
      authority:
        exact: "grpc.example.com"  # Match the host/authority
  route:
    - destination:
        host: "grpc-service"
        port: 9000
  timeout: "30s"
  retries:
    attempts: 3
    retryOn: "unavailable,resource-exhausted,deadline-exceeded"
---
apiVersion: avapigw.io/v1alpha1
kind: GRPCBackend
metadata:
  name: grpc-service-backend
  namespace: production
spec:
  hosts:
    - address: "grpc-service.production.svc.cluster.local"
      port: 9000
  healthCheck:
    enabled: true
    service: ""  # Empty for overall health check
    interval: "10s"
    timeout: "5s"
  connectionPool:
    maxIdleConns: 10
    maxConnsPerHost: 100
    idleConnTimeout: "5m"
```

**Modern gRPC Ingress approach (recommended):**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-service-ingress
  namespace: production
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
    
    # gRPC service matching
    avapigw.io/grpc-service: "api.v1"
    avapigw.io/grpc-service-match-type: "prefix"
    
    # Timeout and retry
    avapigw.io/timeout: "30s"
    avapigw.io/retry-attempts: "3"
    avapigw.io/grpc-retry-on: "unavailable,resource-exhausted,deadline-exceeded"
    
    # Health check
    avapigw.io/grpc-health-check-enabled: "true"
    avapigw.io/grpc-health-check-interval: "10s"
    avapigw.io/grpc-health-check-timeout: "5s"
    
    # Connection pool
    avapigw.io/grpc-max-idle-conns: "10"
    avapigw.io/grpc-max-conns-per-host: "100"
    avapigw.io/grpc-idle-conn-timeout: "5m"
spec:
  ingressClassName: avapigw
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /api.v1
            pathType: Prefix
            backend:
              service:
                name: grpc-service
                port:
                  number: 9000
```

#### Feature Comparison: HTTP Ingress vs gRPC Ingress vs GRPCRoute

| Feature | HTTP Ingress | gRPC Ingress | GRPCRoute CRD |
|---------|--------------|--------------|---------------|
| HTTP/1.1 routing | Yes | No | No |
| HTTP/2 routing | Yes | No | No |
| gRPC routing | No | Yes | Yes |
| Path-based routing | Yes | Yes (mapped to service/method) | N/A (uses service/method) |
| Service/method matching | No | Yes (via annotations) | Yes |
| gRPC metadata matching | No | Limited | Yes |
| Authority (host) matching | Via `host` field | Via `host` field | Yes |
| gRPC health checking | No | Yes (via annotations) | Yes |
| gRPC retry conditions | No | Yes (via annotations) | Yes |
| Field mask transformations | No | No | Yes |
| Connection pooling | Basic | gRPC-optimized (via annotations) | gRPC-optimized |
| Streaming support | No | Yes | Yes |
| Configuration complexity | Low | Medium | High |
| Kubernetes native | Yes | Yes | No (CRD) |

#### When to Use Each Resource Type

| Use Case | Recommended Resource |
|----------|---------------------|
| REST API (HTTP/1.1) | Ingress or APIRoute |
| REST API (HTTP/2) | Ingress or APIRoute |
| Simple gRPC services | gRPC Ingress (with annotations) |
| gRPC unary calls | gRPC Ingress or GRPCRoute + GRPCBackend |
| gRPC streaming | gRPC Ingress or GRPCRoute + GRPCBackend |
| gRPC-Web | gRPC Ingress or GRPCRoute + GRPCBackend |
| Advanced gRPC features | GRPCRoute + GRPCBackend |
| Field mask transformations | GRPCRoute + GRPCBackend |
| Complex gRPC routing | GRPCRoute + GRPCBackend |
| Mixed HTTP + gRPC | Ingress + gRPC Ingress (separate resources) |
| Simple HTTP routing | Ingress |
| Advanced HTTP routing | APIRoute |

## APIRoute CRD

The `APIRoute` CRD configures HTTP routing rules for the API Gateway.

### APIRoute Specification

```yaml
apiVersion: avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: example-route
  namespace: default
spec:
  # Route matching conditions
  match:
    - uri:
        exact: "/api/v1/users"     # Exact path match
        # OR prefix: "/api/v1"     # Prefix match
        # OR regex: "^/api/v[0-9]+/.*"  # Regex match
      methods:
        - GET
        - POST
      headers:
        - name: "Authorization"
          present: true            # Header must be present
          # OR exact: "Bearer token"     # Exact value match
          # OR prefix: "Bearer"          # Prefix match
          # OR regex: "Bearer .*"        # Regex match
          # OR absent: true              # Header must be absent
      queryParams:
        - name: "version"
          exact: "v1"              # Exact parameter value
          # OR regex: "v[0-9]+"          # Regex match
          # OR present: true             # Parameter must be present
  
  # Route destinations
  route:
    - destination:
        host: "backend-service"
        port: 8080
      weight: 70                   # Traffic weight (0-100)
    - destination:
        host: "backend-service-canary"
        port: 8080
      weight: 30
  
  # Timeout and retry configuration
  timeout: "30s"                   # Request timeout
  retries:
    attempts: 3                    # Max retry attempts
    perTryTimeout: "10s"           # Timeout per attempt
    retryOn: "5xx,reset,connect-failure"  # Retry conditions
  
  # URL manipulation
  rewrite:
    uri: "/internal/users"         # Rewrite request URI
    authority: "internal.example.com"  # Rewrite Host header
  
  redirect:
    uri: "/new-path"               # Redirect URI
    code: 301                      # HTTP status code
    scheme: "https"                # Redirect scheme
    host: "new.example.com"        # Redirect host
    port: 443                      # Redirect port
    stripQuery: false              # Strip query parameters
  
  # Direct response (no backend call)
  directResponse:
    status: 200
    body: '{"status":"healthy"}'
    headers:
      Content-Type: "application/json"
      X-Custom-Header: "value"
  
  # Header manipulation
  headers:
    request:
      set:
        X-Gateway: "avapigw"       # Set header value
        X-Request-ID: "{{.RequestID}}"  # Template variables
      add:
        X-Forwarded-By: "gateway"  # Add header (preserves existing)
      remove:
        - "X-Internal-Header"      # Remove headers
    response:
      set:
        X-Response-Time: "{{.ResponseTime}}"
      add:
        X-Served-By: "avapigw"
      remove:
        - "Server"
  
  # Traffic management
  rateLimit:
    enabled: true
    requestsPerSecond: 100         # Requests per second
    burst: 200                     # Burst capacity
    perClient: true                # Per-client rate limiting
  
  maxSessions:
    enabled: true
    maxConcurrent: 1000            # Max concurrent requests
    queueSize: 100                 # Queue size for waiting requests
    queueTimeout: "10s"            # Queue timeout
  
  # Request limits
  requestLimits:
    maxBodySize: 10485760          # 10MB max body size
    maxHeaderSize: 1048576         # 1MB max header size
  
  # CORS configuration
  cors:
    allowOrigins:
      - "https://example.com"
      - "https://*.example.com"
    allowMethods:
      - "GET"
      - "POST"
      - "PUT"
      - "DELETE"
    allowHeaders:
      - "Content-Type"
      - "Authorization"
    exposeHeaders:
      - "X-Request-ID"
    maxAge: 86400                  # Preflight cache duration
    allowCredentials: true
  
  # Security headers
  security:
    enabled: true
    headers:
      enabled: true
      xFrameOptions: "DENY"
      xContentTypeOptions: "nosniff"
      xXSSProtection: "1; mode=block"
      customHeaders:
        X-Custom-Security: "enabled"
  
  # TLS configuration (route-level)
  tls:
    certFile: "/certs/route/tls.crt"
    keyFile: "/certs/route/tls.key"
    sniHosts:
      - "api.example.com"
    minVersion: "TLS12"
    vault:
      enabled: true
      pkiMount: "pki"
      role: "api-route"
      commonName: "api.example.com"
      altNames:
        - "*.api.example.com"
      ttl: "24h"
  
  # Data transformation
  transform:
    request:
      template: |
        {"wrapped": {{.Body}}}
    response:
      allowFields:
        - "id"
        - "name"
        - "email"
      denyFields:
        - "password"
        - "secret"
      fieldMappings:
        created_at: "createdAt"
        updated_at: "updatedAt"
  
  # Caching
  cache:
    enabled: true
    ttl: "5m"                      # Cache TTL
    keyComponents:
      - "path"
      - "query"
      - "headers.Authorization"
    staleWhileRevalidate: "1m"     # Serve stale while revalidating
  
  # Content encoding
  encoding:
    request:
      contentType: "application/json"
    response:
      contentType: "application/json"
  
  # Fault injection (testing)
  fault:
    delay:
      fixedDelay: "100ms"
      percentage: 10               # 10% of requests
    abort:
      httpStatus: 503
      percentage: 5                # 5% of requests
  
  # Traffic mirroring
  mirror:
    destination:
      host: "mirror-service"
      port: 8080
    percentage: 10                 # Mirror 10% of traffic
  
  # Authentication configuration
  authentication:
    enabled: true
    jwt:
      enabled: true
      issuer: "https://auth.example.com"
      audience: ["api.example.com"]
      jwksUrl: "https://auth.example.com/.well-known/jwks.json"
      algorithm: "RS256"
      claimMapping:
        roles: "roles"
        permissions: "permissions"
        email: "email"
    apiKey:
      enabled: false
      header: "X-API-Key"
      hashAlgorithm: "sha256"
      vaultPath: "secret/api-keys"
    mtls:
      enabled: false
      caFile: "/certs/client-ca.crt"
      extractIdentity: "cn"
      allowedCNs:
        - "client.example.com"
    oidc:
      enabled: false
      providers:
        - name: "keycloak"
          issuerUrl: "https://keycloak.example.com/realms/myrealm"
          clientId: "api-client"
          clientSecretRef:
            name: "oidc-secret"
            key: "client-secret"
          scopes: ["openid", "profile", "email"]
    allowAnonymous: false
    skipPaths:
      - "/health"
      - "/metrics"
  
  # Authorization configuration
  authorization:
    enabled: true
    defaultPolicy: "deny"
    rbac:
      enabled: true
      policies:
        - name: "admin-policy"
          roles: ["admin"]
          resources: ["*"]
          actions: ["*"]
          effect: "allow"
          priority: 100
        - name: "user-policy"
          roles: ["user"]
          resources: ["/api/v1/users/*"]
          actions: ["GET", "POST"]
          effect: "allow"
          priority: 50
      roleHierarchy:
        admin: ["user", "viewer"]
        user: ["viewer"]
    abac:
      enabled: false
      policies:
        - name: "time-based-access"
          expression: "request.time.getHours() >= 9 && request.time.getHours() <= 17"
          resources: ["/api/v1/sensitive/*"]
          effect: "allow"
    external:
      enabled: false
      opa:
        url: "http://opa.example.com:8181/v1/data/authz/allow"
        policy: "authz"
        headers:
          Authorization: "Bearer opa-token"
      timeout: "5s"
      failOpen: false
    skipPaths:
      - "/health"
      - "/metrics"
    cache:
      enabled: true
      ttl: "5m"
      maxSize: 1000
      type: "memory"
```

### APIRoute Fields Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `spec.match` | `[]RouteMatch` | Yes | Route matching conditions |
| `spec.match[].uri.exact` | `string` | No | Exact URI match |
| `spec.match[].uri.prefix` | `string` | No | URI prefix match |
| `spec.match[].uri.regex` | `string` | No | URI regex match |
| `spec.match[].methods` | `[]string` | No | HTTP methods to match |
| `spec.match[].headers` | `[]HeaderMatch` | No | Header matching conditions |
| `spec.match[].queryParams` | `[]QueryParamMatch` | No | Query parameter matching |
| `spec.route` | `[]RouteDestination` | No | Route destinations |
| `spec.route[].destination.host` | `string` | Yes | Backend host |
| `spec.route[].destination.port` | `int` | Yes | Backend port |
| `spec.route[].weight` | `int` | No | Traffic weight (0-100) |
| `spec.timeout` | `string` | No | Request timeout (duration) |
| `spec.retries.attempts` | `int` | No | Max retry attempts |
| `spec.retries.perTryTimeout` | `string` | No | Per-attempt timeout |
| `spec.retries.retryOn` | `string` | No | Retry conditions |
| `spec.rewrite.uri` | `string` | No | URI rewrite pattern |
| `spec.redirect.uri` | `string` | No | Redirect URI |
| `spec.redirect.code` | `int` | No | Redirect status code |
| `spec.directResponse.status` | `int` | No | Direct response status |
| `spec.directResponse.body` | `string` | No | Direct response body |
| `spec.headers.request.set` | `map[string]string` | No | Request headers to set |
| `spec.headers.request.add` | `map[string]string` | No | Request headers to add |
| `spec.headers.request.remove` | `[]string` | No | Request headers to remove |
| `spec.rateLimit.enabled` | `bool` | No | Enable rate limiting |
| `spec.rateLimit.requestsPerSecond` | `int` | No | Requests per second limit |
| `spec.rateLimit.burst` | `int` | No | Burst capacity |
| `spec.maxSessions.enabled` | `bool` | No | Enable session limiting |
| `spec.maxSessions.maxConcurrent` | `int` | No | Max concurrent sessions |
| `spec.cors.allowOrigins` | `[]string` | No | Allowed CORS origins |
| `spec.tls.vault.enabled` | `bool` | No | Enable Vault PKI |
| `spec.tls.vault.pkiMount` | `string` | No | Vault PKI mount path |
| `spec.tls.vault.role` | `string` | No | Vault PKI role |
| `spec.transform.response.allowFields` | `[]string` | No | Fields to include in response |
| `spec.cache.enabled` | `bool` | No | Enable caching |
| `spec.cache.ttl` | `string` | No | Cache TTL |
| `spec.authentication.enabled` | `bool` | No | Enable route authentication |
| `spec.authentication.jwt.enabled` | `bool` | No | Enable JWT authentication |
| `spec.authentication.apiKey.enabled` | `bool` | No | Enable API key authentication |
| `spec.authentication.mtls.enabled` | `bool` | No | Enable mTLS authentication |
| `spec.authentication.oidc.enabled` | `bool` | No | Enable OIDC authentication |
| `spec.authorization.enabled` | `bool` | No | Enable route authorization |
| `spec.authorization.rbac.enabled` | `bool` | No | Enable RBAC authorization |
| `spec.authorization.abac.enabled` | `bool` | No | Enable ABAC authorization |
| `spec.authorization.external.enabled` | `bool` | No | Enable external authorization |

## GRPCRoute CRD

The `GRPCRoute` CRD configures gRPC routing rules for the API Gateway.

### GRPCRoute Specification

```yaml
apiVersion: avapigw.io/v1alpha1
kind: GRPCRoute
metadata:
  name: example-grpc-route
  namespace: default
spec:
  # gRPC matching conditions
  match:
    - service:
        exact: "api.v1.UserService"    # Exact service name
        # OR prefix: "api.v1"          # Service prefix
        # OR regex: "api\\.v[0-9]+\\..*"  # Service regex
      method:
        exact: "GetUser"               # Exact method name
        # OR prefix: "Get"             # Method prefix
        # OR regex: "Get.*"            # Method regex
      metadata:
        - name: "x-tenant-id"
          present: true                # Metadata must be present
          # OR exact: "tenant-123"     # Exact value match
          # OR prefix: "tenant-"       # Prefix match
          # OR regex: "tenant-[0-9]+"  # Regex match
          # OR absent: true            # Metadata must be absent
      authority:
        exact: "grpc.example.com"      # Authority (Host) match
        # OR prefix: "grpc"            # Authority prefix
        # OR regex: "grpc\\..*"        # Authority regex
      withoutHeaders:
        - "x-debug"                    # Headers that must NOT be present
  
  # Route destinations
  route:
    - destination:
        host: "grpc-backend"
        port: 9000
      weight: 100
  
  # Timeout and retry configuration
  timeout: "30s"
  retries:
    attempts: 3
    perTryTimeout: "10s"
    retryOn: "unavailable,resource-exhausted,deadline-exceeded"
    backoffBaseInterval: "100ms"     # Exponential backoff base
    backoffMaxInterval: "1s"         # Exponential backoff max
  
  # Header/metadata manipulation
  headers:
    request:
      set:
        x-gateway: "avapigw"
        x-request-id: "{{.RequestID}}"
      add:
        x-forwarded-by: "gateway"
      remove:
        - "x-internal"
    response:
      set:
        x-response-time: "{{.ResponseTime}}"
  
  # Rate limiting
  rateLimit:
    enabled: true
    requestsPerSecond: 100
    burst: 200
  
  # Data transformation
  transform:
    fieldMask:
      paths:
        - "user.id"
        - "user.name"
        - "user.email"
    metadata:
      static:
        x-source: "gateway"
        x-version: "v1"
      dynamic:
        x-request-id: "{{.RequestID}}"
        x-timestamp: "{{.Timestamp}}"
  
  # TLS configuration
  tls:
    vault:
      enabled: true
      pkiMount: "pki"
      role: "grpc-route"
      commonName: "grpc.example.com"
      ttl: "24h"
  
  # Traffic mirroring
  mirror:
    destination:
      host: "grpc-mirror"
      port: 9000
    percentage: 10
  
  # Authentication configuration
  authentication:
    enabled: true
    jwt:
      enabled: true
      issuer: "https://auth.example.com"
      audience: ["grpc.example.com"]
      jwksUrl: "https://auth.example.com/.well-known/jwks.json"
      algorithm: "RS256"
      claimMapping:
        roles: "roles"
        permissions: "permissions"
    allowAnonymous: false
  
  # Authorization configuration
  authorization:
    enabled: true
    defaultPolicy: "deny"
    rbac:
      enabled: true
      policies:
        - name: "grpc-admin-policy"
          roles: ["admin"]
          resources: ["api.v1.UserService/*"]
          actions: ["*"]
          effect: "allow"
    skipPaths:
      - "grpc.health.v1.Health/Check"
  
  # Session limiting
  maxSessions:
    enabled: true
    maxConcurrent: 1000
    queueSize: 100
    queueTimeout: "10s"
  
  # Request limits
  requestLimits:
    maxBodySize: 10485760          # 10MB max body size
    maxHeaderSize: 1048576         # 1MB max header size
```

### GRPCRoute Fields Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `spec.match` | `[]GRPCRouteMatch` | Yes | gRPC matching conditions |
| `spec.match[].service.exact` | `string` | No | Exact service name match |
| `spec.match[].service.prefix` | `string` | No | Service name prefix match |
| `spec.match[].service.regex` | `string` | No | Service name regex match |
| `spec.match[].method.exact` | `string` | No | Exact method name match |
| `spec.match[].metadata` | `[]MetadataMatch` | No | Metadata matching conditions |
| `spec.match[].authority` | `StringMatch` | No | Authority matching |
| `spec.route` | `[]RouteDestination` | No | Route destinations |
| `spec.timeout` | `string` | No | Request timeout |
| `spec.retries.attempts` | `int` | No | Max retry attempts |
| `spec.retries.retryOn` | `string` | No | gRPC status codes to retry |
| `spec.retries.backoffBaseInterval` | `string` | No | Backoff base interval |
| `spec.transform.fieldMask.paths` | `[]string` | No | Field mask paths |
| `spec.transform.metadata.static` | `map[string]string` | No | Static metadata values |
| `spec.authentication.enabled` | `bool` | No | Enable route authentication |
| `spec.authentication.jwt.enabled` | `bool` | No | Enable JWT authentication |
| `spec.authorization.enabled` | `bool` | No | Enable route authorization |
| `spec.authorization.rbac.enabled` | `bool` | No | Enable RBAC authorization |
| `spec.maxSessions.enabled` | `bool` | No | Enable session limiting |
| `spec.maxSessions.maxConcurrent` | `int` | No | Max concurrent sessions |
| `spec.requestLimits.maxBodySize` | `int64` | No | Max request body size |
| `spec.requestLimits.maxHeaderSize` | `int64` | No | Max header size |

## Backend CRD

The `Backend` CRD configures HTTP backend services with health checking and load balancing.

### Backend Specification

```yaml
apiVersion: avapigw.io/v1alpha1
kind: Backend
metadata:
  name: example-backend
  namespace: default
spec:
  # Backend hosts
  hosts:
    - address: "10.0.1.10"         # IP address or hostname
      port: 8080
      weight: 1                    # Load balancing weight
    - address: "backend.example.com"
      port: 8080
      weight: 2
  
  # Health check configuration
  healthCheck:
    path: "/health"                # Health check endpoint
    interval: "10s"                # Check interval
    timeout: "5s"                  # Check timeout
    healthyThreshold: 2            # Successes to mark healthy
    unhealthyThreshold: 3          # Failures to mark unhealthy
    headers:
      Authorization: "Bearer health-token"
      User-Agent: "avapigw-health-checker"
  
  # Load balancer configuration
  loadBalancer:
    algorithm: "roundRobin"        # roundRobin, weighted, leastConn, random
  
  # TLS configuration for backend connections
  tls:
    enabled: true
    mode: "MUTUAL"                 # SIMPLE, MUTUAL
    caFile: "/certs/backend/ca.crt"
    certFile: "/certs/backend/client.crt"
    keyFile: "/certs/backend/client.key"
    serverName: "backend.internal"  # SNI server name
    minVersion: "TLS12"
    insecureSkipVerify: false      # Skip certificate verification (dev only)
    vault:
      enabled: true
      pkiMount: "pki"
      role: "backend-client"
      commonName: "gateway-client"
      ttl: "24h"
  
  # Circuit breaker configuration
  circuitBreaker:
    enabled: true
    threshold: 5                   # Failure threshold
    timeout: "30s"                 # Open state timeout
    halfOpenRequests: 3            # Requests in half-open state
    successThreshold: 2            # Successes to close circuit
  
  # Session limiting
  maxSessions:
    enabled: true
    maxConcurrent: 500             # Max concurrent connections
    queueSize: 50                  # Queue size for waiting connections
    queueTimeout: "10s"            # Queue timeout
  
  # Rate limiting
  rateLimit:
    enabled: true
    requestsPerSecond: 100
    burst: 200
  
  # Authentication configuration
  authentication:
    type: "jwt"                    # jwt, basic, mtls
    
    # JWT authentication
    jwt:
      enabled: true
      tokenSource: "oidc"          # static, vault, oidc
      
      # OIDC token source
      oidc:
        issuerUrl: "https://keycloak.example.com/realms/myrealm"
        clientId: "gateway-client"
        clientSecretRef:
          name: "keycloak-secret"
          key: "client-secret"
        scopes:
          - "openid"
          - "profile"
        tokenCacheTTL: "5m"
      
      # Static token (development only)
      staticToken: "eyJhbGciOiJIUzI1NiIs..."
      
      # Vault token source
      vaultPath: "secret/jwt-tokens"
      vaultKey: "backend-token"
      
      headerName: "Authorization"
      headerPrefix: "Bearer"
  
  # Request limits
  requestLimits:
    maxBodySize: 10485760          # 10MB max body size
    maxHeaderSize: 1048576         # 1MB max header size
  
  # Backend transformation
  transform:
    request:
      template: |
        {
          "wrapped": {{.Body}},
          "timestamp": "{{.Timestamp}}",
          "source": "gateway"
        }
      headers:
        set:
          X-Gateway-Transform: "enabled"
        remove:
          - "X-Internal-Header"
    response:
      allowFields:
        - "id"
        - "name"
        - "email"
        - "created_at"
      denyFields:
        - "password"
        - "secret"
        - "internal_id"
      fieldMappings:
        created_at: "createdAt"
        updated_at: "updatedAt"
      headers:
        set:
          X-Response-Transform: "applied"
  
  # Backend caching
  cache:
    enabled: true
    ttl: "5m"                      # Cache TTL
    keyComponents:
      - "path"
      - "query"
      - "headers.Authorization"
    staleWhileRevalidate: "1m"     # Serve stale while revalidating
    type: "redis"                  # Cache type (memory, redis)
    
    # Redis cache configuration
    redis:
      # Redis Sentinel configuration (high availability)
      sentinel:
        masterName: "mymaster"
        sentinelAddrs:
          - "sentinel1.cache.svc.cluster.local:26379"
          - "sentinel2.cache.svc.cluster.local:26379"
          - "sentinel3.cache.svc.cluster.local:26379"
        sentinelPassword: "sentinel-password"
        password: "redis-master-password"
        # Vault password integration for sentinel
        sentinelPasswordVaultPath: "secret/redis-sentinel"
        passwordVaultPath: "secret/redis-master"
        db: 0
      
      # OR Redis standalone configuration (fallback)
      address: "redis.cache.svc.cluster.local:6379"
      password: "redis-password"
      # Vault password integration for standalone
      passwordVaultPath: "secret/redis"
      db: 0
      
      # Connection pool settings
      maxRetries: 3
      poolSize: 10
      minIdleConns: 5
      maxConnAge: "30m"
      poolTimeout: "5s"
      idleTimeout: "10m"
      keyPrefix: "avapigw:cache:"
      
      # TTL jitter to prevent thundering herd
      ttlJitter: 0.1  # ±10% jitter on TTL values
      
      # Hash cache keys for privacy and length control
      hashKeys: true
      
      # TLS configuration
      tls:
        enabled: true
        caFile: "/etc/ssl/certs/redis-ca.crt"
        certFile: "/etc/ssl/certs/redis-client.crt"
        keyFile: "/etc/ssl/private/redis-client.key"
        insecureSkipVerify: false
  
  # Backend encoding
  encoding:
    request:
      contentType: "application/json"
      compression: "gzip"
    response:
      contentType: "application/json"
      compression: "gzip"
    
    # Basic authentication
    basic:
      enabled: false
      username: "gateway"
      password: "secret"
      # OR from Vault
      vaultPath: "secret/backend/credentials"
      usernameKey: "username"
      passwordKey: "password"
    
    # mTLS authentication
    mtls:
      enabled: false
      certFile: "/certs/client.crt"
      keyFile: "/certs/client.key"
      caFile: "/certs/ca.crt"
      vault:
        enabled: true
        pkiMount: "pki"
        role: "client-cert"
        commonName: "gateway-client"
```

### Backend Fields Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `spec.hosts` | `[]BackendHost` | Yes | Backend host configuration |
| `spec.hosts[].address` | `string` | Yes | Host address (IP or hostname) |
| `spec.hosts[].port` | `int` | Yes | Host port |
| `spec.hosts[].weight` | `int` | No | Load balancing weight |
| `spec.healthCheck.path` | `string` | No | Health check path |
| `spec.healthCheck.interval` | `string` | No | Health check interval |
| `spec.healthCheck.timeout` | `string` | No | Health check timeout |
| `spec.healthCheck.healthyThreshold` | `int` | No | Healthy threshold |
| `spec.healthCheck.unhealthyThreshold` | `int` | No | Unhealthy threshold |
| `spec.loadBalancer.algorithm` | `string` | No | Load balancing algorithm |
| `spec.tls.enabled` | `bool` | No | Enable TLS |
| `spec.tls.mode` | `string` | No | TLS mode (SIMPLE, MUTUAL) |
| `spec.tls.vault.enabled` | `bool` | No | Enable Vault PKI |
| `spec.circuitBreaker.enabled` | `bool` | No | Enable circuit breaker |
| `spec.circuitBreaker.threshold` | `int` | No | Failure threshold |
| `spec.authentication.type` | `string` | No | Authentication type |
| `spec.authentication.jwt.enabled` | `bool` | No | Enable JWT auth |
| `spec.authentication.jwt.tokenSource` | `string` | No | Token source (static, vault, oidc) |
| `spec.requestLimits.maxBodySize` | `int64` | No | Max request body size |
| `spec.requestLimits.maxHeaderSize` | `int64` | No | Max header size |
| `spec.transform.enabled` | `bool` | No | Enable transformation |
| `spec.transform.request.template` | `string` | No | Request transformation template |
| `spec.transform.response.allowFields` | `[]string` | No | Response fields to allow |
| `spec.cache.enabled` | `bool` | No | Enable caching |
| `spec.cache.ttl` | `string` | No | Cache TTL |
| `spec.cache.type` | `string` | No | Cache type (memory, redis) |
| `spec.cache.redis.sentinel.masterName` | `string` | No | Redis Sentinel master name |
| `spec.cache.redis.sentinel.sentinelAddrs` | `[]string` | No | Redis Sentinel addresses |
| `spec.cache.redis.sentinel.sentinelPassword` | `string` | No | Redis Sentinel password |
| `spec.cache.redis.sentinel.password` | `string` | No | Redis master password |
| `spec.cache.redis.sentinel.sentinelPasswordVaultPath` | `string` | No | Vault path for sentinel password |
| `spec.cache.redis.sentinel.passwordVaultPath` | `string` | No | Vault path for master password |
| `spec.cache.redis.sentinel.db` | `int` | No | Redis database number |
| `spec.cache.redis.address` | `string` | No | Redis standalone address |
| `spec.cache.redis.password` | `string` | No | Redis standalone password |
| `spec.cache.redis.passwordVaultPath` | `string` | No | Vault path for Redis password |
| `spec.cache.redis.db` | `int` | No | Redis standalone database |
| `spec.cache.redis.poolSize` | `int` | No | Redis connection pool size |
| `spec.cache.redis.keyPrefix` | `string` | No | Redis key prefix |
| `spec.cache.redis.ttlJitter` | `float64` | No | TTL jitter percentage (0.0-1.0) |
| `spec.cache.redis.hashKeys` | `bool` | No | Enable SHA256 key hashing |
| `spec.cache.redis.tls.enabled` | `bool` | No | Enable Redis TLS |
| `spec.encoding.request.contentType` | `string` | No | Request content type |
| `spec.encoding.response.contentType` | `string` | No | Response content type |
| `spec.encoding.response.compression` | `string` | No | Response compression (gzip, deflate, br) |

## GRPCBackend CRD

The `GRPCBackend` CRD configures gRPC backend services with gRPC-specific features.

### GRPCBackend Specification

```yaml
apiVersion: avapigw.io/v1alpha1
kind: GRPCBackend
metadata:
  name: example-grpc-backend
  namespace: default
spec:
  # Backend hosts
  hosts:
    - address: "grpc-service.default.svc.cluster.local"
      port: 9000
      weight: 1
    - address: "grpc-service-2.default.svc.cluster.local"
      port: 9000
      weight: 1
  
  # gRPC health check configuration
  healthCheck:
    enabled: true
    service: ""                    # Empty for overall health, or specific service
    interval: "10s"
    timeout: "5s"
    healthyThreshold: 2
    unhealthyThreshold: 3
  
  # Load balancer configuration
  loadBalancer:
    algorithm: "roundRobin"
  
  # TLS configuration
  tls:
    enabled: true
    mode: "MUTUAL"
    vault:
      enabled: true
      pkiMount: "pki"
      role: "grpc-client"
      commonName: "gateway-grpc-client"
      ttl: "24h"
  
  # Connection pool configuration
  connectionPool:
    maxIdleConns: 10               # Max idle connections per host
    maxConnsPerHost: 100           # Max connections per host
    idleConnTimeout: "5m"          # Idle connection timeout
  
  # Circuit breaker configuration
  circuitBreaker:
    enabled: true
    threshold: 5
    timeout: "30s"
    halfOpenRequests: 3
  
  # Authentication configuration
  authentication:
    type: "jwt"
    jwt:
      enabled: true
      tokenSource: "oidc"
      oidc:
        issuerUrl: "https://keycloak.example.com/realms/myrealm"
        clientId: "grpc-client"
        clientSecretRef:
          name: "keycloak-secret"
          key: "client-secret"
        scopes:
          - "openid"
          - "profile"
      headerName: "authorization"   # gRPC metadata key
      headerPrefix: "bearer"
  
  # Session limiting
  maxSessions:
    enabled: true
    maxConcurrent: 500             # Max concurrent connections
    queueSize: 50                  # Queue size for waiting connections
    queueTimeout: "10s"            # Queue timeout
  
  # Rate limiting
  rateLimit:
    enabled: true
    requestsPerSecond: 100
    burst: 200
  
  # gRPC transformation
  transform:
    fieldMask:
      paths:
        - "user.id"
        - "user.name"
        - "user.email"
        - "user.profile"
    metadata:
      static:
        x-source: "gateway"
        x-version: "v1"
      dynamic:
        x-request-id: "{{.RequestID}}"
        x-timestamp: "{{.Timestamp}}"
  
  # Backend caching
  cache:
    enabled: true
    ttl: "5m"
    keyComponents:
      - "service"
      - "method"
      - "metadata.x-tenant-id"
    staleWhileRevalidate: "1m"
    type: "memory"
  
  # Backend encoding
  encoding:
    request:
      contentType: "application/grpc"
    response:
      contentType: "application/grpc"
```

### GRPCBackend Fields Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `spec.hosts` | `[]BackendHost` | Yes | Backend host configuration |
| `spec.healthCheck.enabled` | `bool` | No | Enable gRPC health checking |
| `spec.healthCheck.service` | `string` | No | Service name for health check |
| `spec.connectionPool.maxIdleConns` | `int` | No | Max idle connections |
| `spec.connectionPool.maxConnsPerHost` | `int` | No | Max connections per host |
| `spec.connectionPool.idleConnTimeout` | `string` | No | Idle connection timeout |
| `spec.maxSessions.enabled` | `bool` | No | Enable session limiting |
| `spec.maxSessions.maxConcurrent` | `int` | No | Max concurrent sessions |
| `spec.rateLimit.enabled` | `bool` | No | Enable rate limiting |
| `spec.rateLimit.requestsPerSecond` | `int` | No | Requests per second limit |
| `spec.transform.fieldMask.paths` | `[]string` | No | Field mask paths |
| `spec.transform.metadata.static` | `map[string]string` | No | Static metadata values |
| `spec.cache.enabled` | `bool` | No | Enable caching |
| `spec.cache.ttl` | `string` | No | Cache TTL |
| `spec.encoding.request.contentType` | `string` | No | Request content type |
| `spec.encoding.response.contentType` | `string` | No | Response content type |

## Status Conditions

All CRDs support status reporting with standardized conditions.

### Common Status Fields

```yaml
status:
  # Observed generation for optimistic concurrency
  observedGeneration: 1
  
  # Status conditions
  conditions:
    - type: "Ready"                # Condition type
      status: "True"               # True, False, Unknown
      reason: "Reconciled"         # Machine-readable reason
      message: "Resource successfully applied to 2 gateways"
      lastTransitionTime: "2026-02-02T19:00:00Z"
    
    - type: "Valid"
      status: "True"
      reason: "ValidationPassed"
      message: "Configuration is valid"
      lastTransitionTime: "2026-02-02T19:00:00Z"
  
  # Applied gateways (for routes)
  appliedGateways:
    - name: "gateway-1"
      namespace: "avapigw-system"
      lastApplied: "2026-02-02T19:00:00Z"
    - name: "gateway-2"
      namespace: "avapigw-system"
      lastApplied: "2026-02-02T19:00:00Z"
  
  # Health status (for backends)
  healthyHosts: 2
  totalHosts: 2
  lastHealthCheck: "2026-02-02T19:00:00Z"
```

### Condition Types

| Type | Description | Applies To |
|------|-------------|------------|
| `Ready` | Resource is ready and applied | All CRDs |
| `Valid` | Configuration is valid | All CRDs |
| `Healthy` | Backend hosts are healthy | Backend, GRPCBackend |
| `Synced` | Configuration is synced to gateways | All CRDs |

### Condition Reasons

| Reason | Description |
|--------|-------------|
| `Reconciled` | Resource successfully reconciled |
| `ValidationPassed` | Configuration validation passed |
| `ValidationFailed` | Configuration validation failed |
| `HealthCheckPassed` | Health check passed |
| `HealthCheckFailed` | Health check failed |
| `SyncFailed` | Failed to sync to gateways |
| `DuplicateFound` | Duplicate configuration detected |

## Redis Sentinel Configuration

The AVAPIGW Operator supports Redis Sentinel for high-availability caching in both Backend and GRPCBackend CRDs. Redis Sentinel provides automatic failover and service discovery for Redis master-replica setups.

### RedisSentinelSpec Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `masterName` | `string` | Yes | Redis Sentinel master name |
| `sentinelAddrs` | `[]string` | Yes | List of Sentinel addresses (host:port) |
| `sentinelPassword` | `string` | No | Password for Sentinel authentication |
| `password` | `string` | No | Password for Redis master authentication |
| `db` | `int` | No | Redis database number (default: 0) |

### Configuration Precedence

When both Sentinel and standalone Redis configurations are provided:

1. **Sentinel configuration takes precedence** - If `sentinel` is configured, it will be used
2. **Standalone fallback** - If Sentinel is not configured or fails, standalone Redis is used
3. **Environment variable override** - Environment variables override YAML configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `REDIS_SENTINEL_MASTER_NAME` | Sentinel master name | `mymaster` |
| `REDIS_SENTINEL_ADDRS` | Comma-separated sentinel addresses | `sentinel1:26379,sentinel2:26379` |
| `REDIS_SENTINEL_PASSWORD` | Sentinel authentication password | `sentinel-password` |
| `REDIS_MASTER_PASSWORD` | Redis master password | `redis-master-password` |
| `REDIS_SENTINEL_DB` | Redis database number | `0` |

### Example Backend with Redis Sentinel Cache

```yaml
apiVersion: avapigw.io/v1alpha1
kind: Backend
metadata:
  name: redis-sentinel-backend
  namespace: production
spec:
  hosts:
    - address: "api.example.com"
      port: 8080
  cache:
    enabled: true
    ttl: "10m"
    type: "redis"
    keyComponents:
      - "path"
      - "query"
      - "headers.Authorization"
    staleWhileRevalidate: "2m"
    redis:
      # Redis Sentinel configuration (high availability)
      sentinel:
        masterName: "mymaster"
        sentinelAddrs:
          - "sentinel1.cache.svc.cluster.local:26379"
          - "sentinel2.cache.svc.cluster.local:26379"
          - "sentinel3.cache.svc.cluster.local:26379"
        sentinelPassword: "sentinel-password"
        password: "redis-master-password"
        db: 0
      # Connection pool settings
      poolSize: 10
      maxRetries: 3
      keyPrefix: "avapigw:cache:"
      # TLS configuration
      tls:
        enabled: true
        caFile: "/etc/ssl/certs/redis-ca.crt"
        insecureSkipVerify: false
```

### Validation Rules

The operator validates Redis Sentinel configuration through admission webhooks:

#### Sentinel Address Validation
- Sentinel addresses must be in `host:port` format
- Port numbers must be between 1 and 65535
- At least one sentinel address is required
- Duplicate sentinel addresses are rejected

#### Master Name Validation
- Master name is required when Sentinel is configured
- Master name must be a valid identifier (alphanumeric, hyphens, underscores)
- Master name cannot be empty or whitespace-only

#### Database Validation
- Database number must be non-negative integer
- Database number must be within Redis limits (typically 0-15)

#### Password Validation
- Passwords are optional but recommended for production
- Empty passwords are allowed for development environments
- Passwords should be stored in Kubernetes secrets for production

### High Availability Features

Redis Sentinel provides the following high availability features:

- **Automatic Failover**: When the master becomes unavailable, Sentinel promotes a replica to master
- **Service Discovery**: Gateway automatically discovers the current master through Sentinel
- **Connection Pooling**: Optimized connection pooling with exponential backoff retry
- **Health Monitoring**: Continuous monitoring of Redis master and replica health
- **Split-brain Protection**: Sentinel quorum prevents split-brain scenarios

## Examples

### Basic APIRoute

```yaml
apiVersion: avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: api-v1
  namespace: production
spec:
  match:
    - uri:
        prefix: "/api/v1"
      methods: ["GET", "POST"]
  route:
    - destination:
        host: "api-backend"
        port: 8080
  timeout: "30s"
```

### Advanced APIRoute with All Features

```yaml
apiVersion: avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: advanced-api
  namespace: production
  labels:
    app: "my-app"
    version: "v1"
spec:
  match:
    - uri:
        prefix: "/api/v1"
      methods: ["GET", "POST", "PUT", "DELETE"]
      headers:
        - name: "Authorization"
          present: true
        - name: "Content-Type"
          exact: "application/json"
  route:
    - destination:
        host: "api-backend-primary"
        port: 8080
      weight: 80
    - destination:
        host: "api-backend-canary"
        port: 8080
      weight: 20
  timeout: "60s"
  retries:
    attempts: 3
    perTryTimeout: "20s"
    retryOn: "5xx,reset,connect-failure"
  headers:
    request:
      set:
        X-Gateway: "avapigw"
        X-Request-ID: "{{.RequestID}}"
      remove:
        - "X-Internal-Header"
    response:
      set:
        X-Response-Time: "{{.ResponseTime}}"
  rateLimit:
    enabled: true
    requestsPerSecond: 1000
    burst: 2000
    perClient: true
  cors:
    allowOrigins:
      - "https://app.example.com"
      - "https://admin.example.com"
    allowMethods:
      - "GET"
      - "POST"
      - "PUT"
      - "DELETE"
    allowHeaders:
      - "Content-Type"
      - "Authorization"
    allowCredentials: true
  transform:
    response:
      allowFields:
        - "id"
        - "name"
        - "email"
      denyFields:
        - "password"
        - "secret"
  cache:
    enabled: true
    ttl: "5m"
    keyComponents:
      - "path"
      - "query"
```

### GRPCRoute Example

```yaml
apiVersion: avapigw.io/v1alpha1
kind: GRPCRoute
metadata:
  name: user-service
  namespace: production
spec:
  match:
    - service:
        exact: "api.v1.UserService"
      method:
        prefix: "Get"
      metadata:
        - name: "x-tenant-id"
          present: true
  route:
    - destination:
        host: "user-service"
        port: 9000
  timeout: "30s"
  retries:
    attempts: 3
    retryOn: "unavailable,resource-exhausted"
  transform:
    fieldMask:
      paths:
        - "user.id"
        - "user.name"
        - "user.email"
```

### Backend with Health Checks

```yaml
apiVersion: avapigw.io/v1alpha1
kind: Backend
metadata:
  name: api-backend
  namespace: production
spec:
  hosts:
    - address: "api-1.internal"
      port: 8080
      weight: 1
    - address: "api-2.internal"
      port: 8080
      weight: 1
  healthCheck:
    path: "/health"
    interval: "10s"
    timeout: "5s"
    healthyThreshold: 2
    unhealthyThreshold: 3
  loadBalancer:
    algorithm: "roundRobin"
  circuitBreaker:
    enabled: true
    threshold: 5
    timeout: "30s"
```

### GRPCBackend Example

```yaml
apiVersion: avapigw.io/v1alpha1
kind: GRPCBackend
metadata:
  name: user-service-backend
  namespace: production
spec:
  hosts:
    - address: "user-service.default.svc.cluster.local"
      port: 9000
      weight: 1
  healthCheck:
    enabled: true
    service: "api.v1.UserService"
    interval: "10s"
    timeout: "5s"
  connectionPool:
    maxIdleConns: 10
    maxConnsPerHost: 100
    idleConnTimeout: "5m"
  tls:
    enabled: true
    mode: "SIMPLE"
    vault:
      enabled: true
      pkiMount: "pki"
      role: "grpc-client"
      commonName: "gateway-grpc-client"
```

## Configuration Level Hierarchy

The following tables show which configuration options are available at each level:

### Route Level Configuration (APIRoute/GRPCRoute)

| Configuration | APIRoute | GRPCRoute | Description |
|--------------|----------|-----------|-------------|
| RateLimit | Yes | Yes | Request rate limiting |
| MaxSessions | Yes | Yes | Concurrent session limits |
| RequestLimits | Yes | Yes | Request size limits |
| CORS | Yes | Yes | Cross-origin resource sharing |
| Authentication | Yes | Yes | Route authentication |
| Authorization | Yes | Yes | Route authorization |
| Security | Yes | Yes | Security headers |
| Transform | Yes | Yes | Request/response transformation |
| Cache | Yes | Yes | Response caching |
| Encoding | Yes | Yes | Content encoding |
| TLS | Yes | Yes | Route-level TLS override |
| Headers | Yes | Yes | Header manipulation |
| Mirror | Yes | Yes | Traffic mirroring |
| Fault | Yes | No | Fault injection (HTTP only) |
| Redirect | Yes | No | HTTP redirects (HTTP only) |
| Rewrite | Yes | No | URL rewriting (HTTP only) |
| DirectResponse | Yes | No | Direct responses (HTTP only) |
| Retries | Yes | Yes | Retry policies |
| Timeout | Yes | Yes | Request timeouts |

### Backend Level Configuration (Backend/GRPCBackend)

| Configuration | Backend | GRPCBackend | Description |
|--------------|---------|-------------|-------------|
| RateLimit | Yes | Yes | Backend rate limiting |
| MaxSessions | Yes | Yes | Backend session limits |
| CircuitBreaker | Yes | Yes | Circuit breaker |
| RequestLimits | Yes | No | Request size limits (HTTP only) |
| Authentication | Yes | Yes | Backend authentication |
| Transform | Yes | Yes | Backend transformation |
| Cache | Yes | Yes | Backend caching |
| Encoding | Yes | Yes | Content encoding |
| TLS | Yes | Yes | Backend TLS |
| HealthCheck | Yes | Yes | Health checking |
| LoadBalancer | Yes | Yes | Load balancing |
| ConnectionPool | No | Yes | Connection pooling (gRPC only) |

### Configuration Priority Order

When the same configuration option is available at multiple levels, the following priority order applies (highest to lowest):

1. **Route Level** - Configuration specified in APIRoute/GRPCRoute
2. **Backend Level** - Configuration specified in Backend/GRPCBackend
3. **Gateway Level** - Default configuration from Gateway resource
4. **Operator Default** - Built-in default values

**Example Priority Resolution:**
```yaml
# Gateway default rate limit: 1000 RPS
# Backend rate limit: 500 RPS  
# Route rate limit: 100 RPS
# Effective rate limit: 100 RPS (route level wins)
```

## Validation Rules

The operator enforces validation rules through admission webhooks:

### Common Validations

- **Required fields** must be present
- **Duration fields** must be valid Go duration strings
- **Port numbers** must be in range 1-65535
- **Weight values** must be 0-100 and sum to 100 for multiple destinations
- **Enum fields** must have valid values

### Route-Specific Validations

- **URI matching** - exactly one of exact, prefix, or regex must be specified
- **Duplicate routes** - no two routes can have identical match conditions
- **Backend references** - referenced backends must exist in the same namespace
- **Weight distribution** - weights across destinations must sum to 100

### Backend-Specific Validations

- **Host addresses** - must be valid IP addresses or hostnames
- **Health check paths** - must start with '/' for HTTP backends
- **TLS configuration** - certificate files must exist when specified
- **Authentication** - required fields must be present for each auth type

### APIRoute with Full Authentication and Authorization

```yaml
apiVersion: avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: secure-api
  namespace: production
  labels:
    app: "secure-app"
    security: "high"
spec:
  match:
    - uri:
        prefix: "/api/v1/secure"
      methods: ["GET", "POST", "PUT", "DELETE"]
      headers:
        - name: "Authorization"
          present: true
  route:
    - destination:
        host: "secure-backend"
        port: 8080
  timeout: "30s"
  
  # Authentication configuration
  authentication:
    enabled: true
    jwt:
      enabled: true
      issuer: "https://auth.example.com"
      audience: ["api.example.com"]
      jwksUrl: "https://auth.example.com/.well-known/jwks.json"
      algorithm: "RS256"
      claimMapping:
        roles: "roles"
        permissions: "permissions"
        email: "email"
        name: "name"
    allowAnonymous: false
    skipPaths:
      - "/api/v1/secure/health"
  
  # Authorization configuration
  authorization:
    enabled: true
    defaultPolicy: "deny"
    rbac:
      enabled: true
      policies:
        - name: "admin-full-access"
          roles: ["admin", "super-admin"]
          resources: ["*"]
          actions: ["*"]
          effect: "allow"
          priority: 100
        - name: "user-read-access"
          roles: ["user"]
          resources: ["/api/v1/secure/users/*"]
          actions: ["GET"]
          effect: "allow"
          priority: 50
        - name: "user-write-own"
          roles: ["user"]
          resources: ["/api/v1/secure/users/{{.user.id}}/*"]
          actions: ["PUT", "PATCH"]
          effect: "allow"
          priority: 60
      roleHierarchy:
        super-admin: ["admin", "user", "viewer"]
        admin: ["user", "viewer"]
        user: ["viewer"]
    abac:
      enabled: true
      policies:
        - name: "business-hours-only"
          expression: "request.time.getHours() >= 9 && request.time.getHours() <= 17"
          resources: ["/api/v1/secure/admin/*"]
          effect: "allow"
          priority: 80
        - name: "ip-whitelist"
          expression: "request.remote_addr in ['10.0.0.0/8', '192.168.0.0/16']"
          resources: ["/api/v1/secure/internal/*"]
          effect: "allow"
          priority: 90
    cache:
      enabled: true
      ttl: "5m"
      maxSize: 1000
      type: "memory"
  
  # Rate limiting
  rateLimit:
    enabled: true
    requestsPerSecond: 100
    burst: 200
    perClient: true
  
  # Session limiting
  maxSessions:
    enabled: true
    maxConcurrent: 500
    queueSize: 50
    queueTimeout: "10s"
  
  # Request limits
  requestLimits:
    maxBodySize: 5242880          # 5MB
    maxHeaderSize: 524288         # 512KB
  
  # Response transformation
  transform:
    response:
      allowFields:
        - "id"
        - "name"
        - "email"
        - "created_at"
        - "updated_at"
      denyFields:
        - "password"
        - "secret"
        - "internal_id"
        - "ssn"
      fieldMappings:
        created_at: "createdAt"
        updated_at: "updatedAt"
  
  # Caching
  cache:
    enabled: true
    ttl: "5m"
    keyComponents:
      - "path"
      - "query"
      - "headers.Authorization"
    staleWhileRevalidate: "1m"
  
  # Security headers
  security:
    enabled: true
    headers:
      enabled: true
      xFrameOptions: "DENY"
      xContentTypeOptions: "nosniff"
      xXSSProtection: "1; mode=block"
      contentSecurityPolicy: "default-src 'self'"
      strictTransportSecurity: "max-age=31536000; includeSubDomains"
```

### GRPCRoute with All New Fields

```yaml
apiVersion: avapigw.io/v1alpha1
kind: GRPCRoute
metadata:
  name: user-service-secure
  namespace: production
spec:
  match:
    - service:
        exact: "api.v1.UserService"
      method:
        prefix: "Get"
      metadata:
        - name: "x-tenant-id"
          present: true
        - name: "authorization"
          prefix: "Bearer"
      authority:
        exact: "grpc.example.com"
  route:
    - destination:
        host: "user-service"
        port: 9000
  timeout: "30s"
  
  # Authentication
  authentication:
    enabled: true
    jwt:
      enabled: true
      issuer: "https://auth.example.com"
      audience: ["grpc.example.com"]
      jwksUrl: "https://auth.example.com/.well-known/jwks.json"
      algorithm: "RS256"
      claimMapping:
        roles: "roles"
        permissions: "permissions"
  
  # Authorization
  authorization:
    enabled: true
    defaultPolicy: "deny"
    rbac:
      enabled: true
      policies:
        - name: "grpc-user-access"
          roles: ["user", "admin"]
          resources: ["api.v1.UserService/GetUser", "api.v1.UserService/ListUsers"]
          actions: ["*"]
          effect: "allow"
  
  # Session limiting
  maxSessions:
    enabled: true
    maxConcurrent: 1000
    queueSize: 100
    queueTimeout: "10s"
  
  # Request limits
  requestLimits:
    maxBodySize: 10485760         # 10MB
    maxHeaderSize: 1048576        # 1MB
  
  # Rate limiting
  rateLimit:
    enabled: true
    requestsPerSecond: 500
    burst: 1000
  
  # gRPC transformation
  transform:
    fieldMask:
      paths:
        - "user.id"
        - "user.name"
        - "user.email"
        - "user.profile.avatar"
    metadata:
      static:
        x-source: "gateway"
        x-version: "v1"
      dynamic:
        x-request-id: "{{.RequestID}}"
        x-timestamp: "{{.Timestamp}}"
        x-user-id: "{{.user.id}}"
  
  # Caching
  cache:
    enabled: true
    ttl: "5m"
    keyComponents:
      - "service"
      - "method"
      - "metadata.x-tenant-id"
      - "metadata.authorization"
    staleWhileRevalidate: "1m"
  
  # Encoding
  encoding:
    request:
      contentType: "application/grpc"
    response:
      contentType: "application/grpc"
  
  # Retries
  retries:
    attempts: 3
    perTryTimeout: "10s"
    retryOn: "unavailable,resource-exhausted,deadline-exceeded"
    backoffBaseInterval: "100ms"
    backoffMaxInterval: "1s"
```

### Backend with Transform, Cache, and Encoding

```yaml
apiVersion: avapigw.io/v1alpha1
kind: Backend
metadata:
  name: api-backend-enhanced
  namespace: production
spec:
  hosts:
    - address: "api-1.internal"
      port: 8080
      weight: 1
    - address: "api-2.internal"
      port: 8080
      weight: 1
  
  # Health checking
  healthCheck:
    path: "/health"
    interval: "10s"
    timeout: "5s"
    healthyThreshold: 2
    unhealthyThreshold: 3
  
  # Load balancing
  loadBalancer:
    algorithm: "roundRobin"
  
  # Circuit breaker
  circuitBreaker:
    enabled: true
    threshold: 5
    timeout: "30s"
    halfOpenRequests: 3
  
  # Session limiting
  maxSessions:
    enabled: true
    maxConcurrent: 500
    queueSize: 50
    queueTimeout: "10s"
  
  # Rate limiting
  rateLimit:
    enabled: true
    requestsPerSecond: 1000
    burst: 2000
  
  # Request limits
  requestLimits:
    maxBodySize: 10485760         # 10MB
    maxHeaderSize: 1048576        # 1MB
  
  # Backend authentication
  authentication:
    type: "jwt"
    jwt:
      enabled: true
      tokenSource: "oidc"
      oidc:
        issuerUrl: "https://keycloak.example.com/realms/backend"
        clientId: "gateway-client"
        clientSecretRef:
          name: "keycloak-secret"
          key: "client-secret"
        scopes: ["openid", "profile"]
        tokenCacheTTL: "5m"
      headerName: "Authorization"
      headerPrefix: "Bearer"
  
  # Backend transformation
  transform:
    request:
      template: |
        {
          "data": {{.Body}},
          "metadata": {
            "timestamp": "{{.Timestamp}}",
            "requestId": "{{.RequestID}}",
            "source": "gateway",
            "version": "v1"
          }
        }
      headers:
        set:
          X-Gateway-Transform: "enabled"
          X-Request-ID: "{{.RequestID}}"
        remove:
          - "X-Internal-Header"
    response:
      allowFields:
        - "id"
        - "name"
        - "email"
        - "created_at"
        - "updated_at"
        - "status"
      denyFields:
        - "password"
        - "secret"
        - "internal_id"
        - "private_key"
      fieldMappings:
        created_at: "createdAt"
        updated_at: "updatedAt"
        user_id: "userId"
      headers:
        set:
          X-Response-Transform: "applied"
          X-Response-Time: "{{.ResponseTime}}"
  
  # Backend caching
  cache:
    enabled: true
    ttl: "10m"
    keyComponents:
      - "path"
      - "query"
      - "headers.Authorization"
      - "headers.X-Tenant-ID"
    staleWhileRevalidate: "2m"
    type: "memory"
  
  # Backend encoding
  encoding:
    request:
      contentType: "application/json"
      compression: "gzip"
    response:
      contentType: "application/json"
      compression: "gzip"
  
  # TLS configuration
  tls:
    enabled: true
    mode: "MUTUAL"
    vault:
      enabled: true
      pkiMount: "pki-client"
      role: "gateway-client"
      commonName: "gateway-client.example.com"
      ttl: "24h"
    serverName: "api.internal"
    minVersion: "TLS12"
```

### GRPCBackend with All New Fields

```yaml
apiVersion: avapigw.io/v1alpha1
kind: GRPCBackend
metadata:
  name: user-service-backend-enhanced
  namespace: production
spec:
  hosts:
    - address: "user-service.default.svc.cluster.local"
      port: 9000
      weight: 1
    - address: "user-service-2.default.svc.cluster.local"
      port: 9000
      weight: 1
  
  # gRPC health checking
  healthCheck:
    enabled: true
    service: "api.v1.UserService"
    interval: "10s"
    timeout: "5s"
    healthyThreshold: 2
    unhealthyThreshold: 3
  
  # Load balancing
  loadBalancer:
    algorithm: "roundRobin"
  
  # Connection pool
  connectionPool:
    maxIdleConns: 10
    maxConnsPerHost: 100
    idleConnTimeout: "5m"
  
  # Circuit breaker
  circuitBreaker:
    enabled: true
    threshold: 5
    timeout: "30s"
    halfOpenRequests: 3
  
  # Session limiting
  maxSessions:
    enabled: true
    maxConcurrent: 500
    queueSize: 50
    queueTimeout: "10s"
  
  # Rate limiting
  rateLimit:
    enabled: true
    requestsPerSecond: 500
    burst: 1000
  
  # Backend authentication
  authentication:
    type: "jwt"
    jwt:
      enabled: true
      tokenSource: "oidc"
      oidc:
        issuerUrl: "https://keycloak.example.com/realms/grpc"
        clientId: "grpc-client"
        clientSecretRef:
          name: "keycloak-secret"
          key: "client-secret"
        scopes: ["openid", "profile"]
      headerName: "authorization"
      headerPrefix: "bearer"
  
  # gRPC transformation
  transform:
    fieldMask:
      paths:
        - "user.id"
        - "user.name"
        - "user.email"
        - "user.profile"
        - "user.created_at"
    metadata:
      static:
        x-source: "gateway"
        x-version: "v1"
        x-backend: "user-service"
      dynamic:
        x-request-id: "{{.RequestID}}"
        x-timestamp: "{{.Timestamp}}"
        x-gateway-id: "{{.GatewayID}}"
  
  # Backend caching
  cache:
    enabled: true
    ttl: "5m"
    keyComponents:
      - "service"
      - "method"
      - "metadata.x-tenant-id"
      - "metadata.authorization"
    staleWhileRevalidate: "1m"
    type: "memory"
  
  # Backend encoding
  encoding:
    request:
      contentType: "application/grpc"
    response:
      contentType: "application/grpc"
  
  # TLS configuration
  tls:
    enabled: true
    mode: "MUTUAL"
    vault:
      enabled: true
      pkiMount: "pki-grpc"
      role: "grpc-client"
      commonName: "gateway-grpc-client"
      ttl: "24h"
    serverName: "user-service.default.svc.cluster.local"
    minVersion: "TLS13"
```

### Basic Ingress Example

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: basic-api
  namespace: production
spec:
  ingressClassName: avapigw
  rules:
    - host: api.example.com
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

### Ingress with TLS

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-api
  namespace: production
  annotations:
    avapigw.io/tls-min-version: "TLS12"
spec:
  ingressClassName: avapigw
  tls:
    - hosts:
        - api.example.com
        - www.example.com
      secretName: api-tls-secret
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: api-service
                port:
                  number: 8080
    - host: www.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web-service
                port:
                  number: 80
```

### Ingress with Rate Limiting and CORS

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rate-limited-api
  namespace: production
  annotations:
    # Rate limiting
    avapigw.io/rate-limit-enabled: "true"
    avapigw.io/rate-limit-rps: "100"
    avapigw.io/rate-limit-burst: "200"
    avapigw.io/rate-limit-per-client: "true"
    # CORS
    avapigw.io/cors-allow-origins: "https://app.example.com,https://admin.example.com"
    avapigw.io/cors-allow-methods: "GET,POST,PUT,DELETE,OPTIONS"
    avapigw.io/cors-allow-headers: "Content-Type,Authorization,X-Request-ID"
    avapigw.io/cors-allow-credentials: "true"
    avapigw.io/cors-max-age: "86400"
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
                name: api-v1-service
                port:
                  number: 8080
```

### Ingress with Retry and Circuit Breaker

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: resilient-api
  namespace: production
  annotations:
    # Timeout and retries
    avapigw.io/timeout: "30s"
    avapigw.io/retry-attempts: "3"
    avapigw.io/retry-per-try-timeout: "10s"
    avapigw.io/retry-on: "5xx,reset,connect-failure"
    # Circuit breaker
    avapigw.io/circuit-breaker-enabled: "true"
    avapigw.io/circuit-breaker-threshold: "5"
    avapigw.io/circuit-breaker-timeout: "30s"
    avapigw.io/circuit-breaker-half-open: "3"
    # Health check
    avapigw.io/health-check-path: "/health"
    avapigw.io/health-check-interval: "10s"
    avapigw.io/health-check-timeout: "5s"
    avapigw.io/health-check-healthy-threshold: "2"
    avapigw.io/health-check-unhealthy-threshold: "3"
spec:
  ingressClassName: avapigw
  rules:
    - host: api.example.com
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

### Ingress with URL Rewrite

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rewrite-api
  namespace: production
  annotations:
    avapigw.io/rewrite-uri: "/internal/api"
    avapigw.io/rewrite-authority: "internal.example.com"
spec:
  ingressClassName: avapigw
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /external/api
            pathType: Prefix
            backend:
              service:
                name: internal-api-service
                port:
                  number: 8080
```

### Ingress with HTTP to HTTPS Redirect

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: redirect-to-https
  namespace: production
  annotations:
    avapigw.io/redirect-scheme: "https"
    avapigw.io/redirect-code: "301"
spec:
  ingressClassName: avapigw
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: redirect-service
                port:
                  number: 80
```

### Ingress with Security Headers

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-headers-api
  namespace: production
  annotations:
    avapigw.io/security-enabled: "true"
    avapigw.io/security-x-frame-options: "DENY"
    avapigw.io/security-x-content-type-options: "nosniff"
    avapigw.io/security-x-xss-protection: "1; mode=block"
spec:
  ingressClassName: avapigw
  rules:
    - host: api.example.com
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

### Ingress with Session Limiting and Caching

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cached-api
  namespace: production
  annotations:
    # Session limiting
    avapigw.io/max-sessions-enabled: "true"
    avapigw.io/max-sessions-max-concurrent: "1000"
    avapigw.io/max-sessions-queue-size: "100"
    avapigw.io/max-sessions-queue-timeout: "10s"
    # Caching
    avapigw.io/cache-enabled: "true"
    avapigw.io/cache-ttl: "5m"
    # Request limits
    avapigw.io/max-body-size: "10485760"
spec:
  ingressClassName: avapigw
  rules:
    - host: api.example.com
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

### Ingress with Default Backend

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: with-default-backend
  namespace: production
  annotations:
    avapigw.io/timeout: "30s"
spec:
  ingressClassName: avapigw
  defaultBackend:
    service:
      name: default-backend
      port:
        number: 80
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /api/v1
            pathType: Prefix
            backend:
              service:
                name: api-v1-service
                port:
                  number: 8080
          - path: /api/v2
            pathType: Prefix
            backend:
              service:
                name: api-v2-service
                port:
                  number: 8080
```

### Basic gRPC Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: basic-grpc
  namespace: production
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
spec:
  ingressClassName: avapigw
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /api.v1.UserService
            pathType: Prefix
            backend:
              service:
                name: user-service
                port:
                  number: 50051
```

### gRPC Ingress with Service/Method Matching

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-service-method
  namespace: production
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
    
    # gRPC service/method matching
    avapigw.io/grpc-service: "api.v1.UserService"
    avapigw.io/grpc-service-match-type: "exact"
    avapigw.io/grpc-method: "GetUser"
    avapigw.io/grpc-method-match-type: "exact"
spec:
  ingressClassName: avapigw
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /api.v1.UserService/GetUser
            pathType: Exact
            backend:
              service:
                name: user-service
                port:
                  number: 50051
```

### gRPC Ingress with Health Check and Retry

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-health-retry
  namespace: production
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
    
    # Timeout and retry configuration
    avapigw.io/timeout: "30s"
    avapigw.io/retry-attempts: "3"
    avapigw.io/retry-per-try-timeout: "5s"
    avapigw.io/grpc-retry-on: "unavailable,resource-exhausted,deadline-exceeded"
    avapigw.io/grpc-backoff-base-interval: "100ms"
    avapigw.io/grpc-backoff-max-interval: "10s"
    
    # gRPC health check
    avapigw.io/grpc-health-check-enabled: "true"
    avapigw.io/grpc-health-check-service: "api.v1.OrderService"
    avapigw.io/grpc-health-check-interval: "10s"
    avapigw.io/grpc-health-check-timeout: "5s"
    avapigw.io/grpc-health-check-healthy-threshold: "2"
    avapigw.io/grpc-health-check-unhealthy-threshold: "3"
spec:
  ingressClassName: avapigw
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /api.v1.OrderService
            pathType: Prefix
            backend:
              service:
                name: order-service
                port:
                  number: 50051
```

### gRPC Ingress with TLS and Connection Pool

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-tls-pool
  namespace: production
  annotations:
    # Enable gRPC protocol
    avapigw.io/protocol: "grpc"
    
    # TLS configuration
    avapigw.io/tls-min-version: "TLS12"
    avapigw.io/tls-max-version: "TLS13"
    
    # gRPC connection pool
    avapigw.io/grpc-max-idle-conns: "100"
    avapigw.io/grpc-max-conns-per-host: "50"
    avapigw.io/grpc-idle-conn-timeout: "90s"
    
    # Rate limiting
    avapigw.io/rate-limit-enabled: "true"
    avapigw.io/rate-limit-rps: "100"
    avapigw.io/rate-limit-burst: "200"
spec:
  ingressClassName: avapigw
  tls:
    - hosts:
        - grpc.example.com
      secretName: grpc-tls-secret
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /api.v1.PaymentService
            pathType: Prefix
            backend:
              service:
                name: payment-service
                port:
                  number: 50051
```

For more examples and advanced configurations, see the [test/crd-samples/](../../test/crd-samples/) directory.