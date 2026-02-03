# CRD Reference Guide

This document provides a comprehensive reference for all Custom Resource Definitions (CRDs) managed by the AVAPIGW Operator.

## Table of Contents

- [Overview](#overview)
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
    type: "memory"                 # Cache type (memory, redis)
  
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

For more examples and advanced configurations, see the [test/crd-samples/](../../test/crd-samples/) directory.