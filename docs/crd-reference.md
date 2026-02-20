# CRD Reference

## Overview

The AVAPIGW Operator provides four Custom Resource Definitions (CRDs) for Kubernetes-native configuration management. This document provides a comprehensive reference for all CRD types, their fields, and usage examples.

## Table of Contents

- [APIRoute CRD](#apiroute-crd)
- [Backend CRD](#backend-crd)
- [GRPCRoute CRD](#grpcroute-crd)
- [GRPCBackend CRD](#grpcbackend-crd)
- [Status Fields](#status-fields)
- [Cross-Reference Validation](#cross-reference-validation)
- [Examples](#examples)

## APIRoute CRD

The `APIRoute` CRD defines HTTP routing rules and traffic management policies.

### APIVersion and Kind

```yaml
apiVersion: avapigw.io/v1
kind: APIRoute
```

### Metadata

```yaml
metadata:
  name: api-route-example
  namespace: default
  labels:
    app: my-app
    environment: production
  annotations:
    avapigw.io/description: "Main API route for user service"
```

### Spec Fields

#### Match Conditions

```yaml
spec:
  match:
    - uri:
        exact: "/api/v1/users"          # Exact path match
        # OR
        prefix: "/api/v1"               # Prefix match
        # OR  
        regex: "^/api/v[0-9]+/users$"   # Regex match
      
      methods:                          # HTTP methods (optional)
        - GET
        - POST
        - PUT
      
      headers:                          # Header matching (optional)
        - name: "Authorization"
          present: true                 # Header must be present
        - name: "Content-Type"
          exact: "application/json"     # Exact header value
        - name: "User-Agent"
          prefix: "Mozilla"             # Header value prefix
        - name: "X-API-Version"
          regex: "v[0-9]+"             # Header value regex
        - name: "X-Debug"
          absent: true                  # Header must be absent
      
      queryParams:                      # Query parameter matching (optional)
        - name: "version"
          exact: "v1"                   # Exact parameter value
        - name: "format"
          regex: "(json|xml)"           # Parameter value regex
        - name: "debug"
          present: true                 # Parameter must be present
```

#### Route Destinations

```yaml
spec:
  route:
    - destination:
        host: "user-service"            # Backend service name
        port: 8080                      # Backend port
      weight: 70                        # Traffic weight (0-100)
    
    - destination:
        host: "user-service-v2"
        port: 8080
      weight: 30                        # Weighted load balancing
```

#### Traffic Management

```yaml
spec:
  # Request timeout
  timeout: "30s"
  
  # Retry policy
  retries:
    attempts: 3                         # Max retry attempts
    perTryTimeout: "10s"               # Timeout per attempt
    retryOn: "5xx,reset,connect-failure" # Retry conditions
    backoffBaseInterval: "1s"          # Base backoff interval
    backoffMaxInterval: "10s"          # Max backoff interval
  
  # Traffic mirroring
  mirror:
    destination:
      host: "analytics-service"
      port: 8080
    percentage: 10                      # Mirror 10% of traffic
  
  # Fault injection
  fault:
    delay:
      fixedDelay: "100ms"              # Inject delay
      percentage: 5                     # 5% of requests
    abort:
      httpStatus: 503                   # Return error
      percentage: 1                     # 1% of requests
```

#### Request/Response Manipulation

```yaml
spec:
  # URL rewriting
  rewrite:
    uri: "/v2/users"                    # Rewrite path
    authority: "new-service.com"        # Rewrite host
  
  # HTTP redirects
  redirect:
    uri: "/new-path"                    # Redirect to new path
    code: 301                           # HTTP status code
    scheme: "https"                     # Redirect scheme
    host: "new-host.com"               # Redirect host
    port: 443                          # Redirect port
    stripQuery: false                   # Keep query parameters
  
  # Direct response (no backend)
  directResponse:
    status: 200                         # HTTP status
    body: '{"status":"ok"}'            # Response body
    headers:
      Content-Type: "application/json"
      X-Custom-Header: "value"
  
  # Header manipulation
  headers:
    request:
      set:
        X-Forwarded-Proto: "https"     # Set request header
      add:
        X-Request-ID: "{{.RequestID}}" # Add request header
      remove:
        - "X-Internal-Header"          # Remove request header
    response:
      set:
        X-Response-Time: "{{.Duration}}" # Set response header
      add:
        X-Server: "avapigw"            # Add response header
      remove:
        - "Server"                     # Remove response header
```

#### Data Transformation

```yaml
spec:
  # Request transformation
  transform:
    request:
      template: |                       # Go template for request
        {
          "user_id": "{{.user_id}}",
          "timestamp": "{{now}}"
        }
    
    # Response transformation
    response:
      allowFields:                      # Allow only these fields
        - "id"
        - "name"
        - "email"
      denyFields:                       # Deny these fields
        - "password"
        - "internal_id"
      fieldMappings:                    # Rename fields
        user_id: "id"
        full_name: "name"
      fieldGrouping:                    # Group fields
        profile:
          - "name"
          - "email"
          - "avatar"
      arrayOperations:
        sort:
          field: "created_at"
          order: "desc"
        limit: 10
        filter:
          field: "status"
          value: "active"
```

#### Caching

```yaml
spec:
  cache:
    enabled: true
    ttl: "300s"                         # Cache TTL
    keyComponents:                      # Cache key components
      - "uri"
      - "method"
      - "headers.Authorization"
    staleWhileRevalidate: "60s"        # Serve stale while revalidating
    negativeCaching:
      enabled: true
      ttl: "60s"                       # Cache error responses
```

#### Security and Rate Limiting

```yaml
spec:
  # Authentication
  authentication:
    enabled: true
    jwt:
      enabled: true
      issuer: "https://auth.example.com"
      audience: "api-service"
      jwksUrl: "https://auth.example.com/.well-known/jwks.json"
    apiKey:
      enabled: true
      headerName: "X-API-Key"
      sources:
        - header: "X-API-Key"
        - query: "api_key"
  
  # Authorization
  authorization:
    enabled: true
    rbac:
      enabled: true
      policies:
        - role: "admin"
          permissions: ["read", "write", "delete"]
        - role: "user"
          permissions: ["read"]
    abac:
      enabled: true
      policies:
        - name: "business-hours"
          expression: 'hour(now()) >= 9 && hour(now()) <= 17'
  
  # Rate limiting
  rateLimit:
    enabled: true
    requestsPerSecond: 100
    burst: 200
    perClient: true                     # Per client IP
  
  # Max sessions
  maxSessions:
    enabled: true
    maxConcurrent: 1000
    queueSize: 100
    queueTimeout: "30s"
  
  # CORS
  cors:
    allowOrigins:
      - "https://app.example.com"
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
    maxAge: 86400
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
```

#### TLS Configuration

```yaml
spec:
  tls:
    certFile: "/certs/route.crt"        # Route-specific certificate
    keyFile: "/certs/route.key"         # Route-specific private key
    sniHosts:                           # SNI hostnames
      - "api.example.com"
      - "*.api.example.com"
    minVersion: "1.2"                   # Minimum TLS version
    maxVersion: "1.3"                   # Maximum TLS version
    cipherSuites:                       # Allowed cipher suites
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    
    # Client certificate validation
    clientValidation:
      enabled: true
      caFile: "/certs/client-ca.crt"
      requireClientCert: true
      allowedCNs:
        - "client.example.com"
      allowedSANs:
        - "*.client.example.com"
    
    # Vault PKI integration
    vault:
      enabled: true
      pkiMount: "pki"
      role: "api-certs"
      commonName: "api.example.com"
      altNames:
        - "*.api.example.com"
      ttl: "24h"
      renewBefore: "1h"
```

## Backend CRD

The `Backend` CRD defines HTTP backend services and their configuration.

### APIVersion and Kind

```yaml
apiVersion: avapigw.io/v1
kind: Backend
```

### Spec Fields

#### Host Configuration

```yaml
spec:
  hosts:
    - address: "10.0.1.10"              # Backend IP address
      port: 8080                        # Backend port
      weight: 1                         # Load balancing weight
    - address: "backend.example.com"    # Backend hostname
      port: 8080
      weight: 2
    - address: "10.0.1.12"
      port: 8080
      weight: 1
      metadata:                         # Host-specific metadata
        zone: "us-west-1a"
        instance_type: "m5.large"
```

#### Health Checks

```yaml
spec:
  healthCheck:
    enabled: true
    path: "/health"                     # Health check path
    method: "GET"                       # Health check method
    interval: "10s"                     # Check interval
    timeout: "5s"                       # Check timeout
    healthyThreshold: 2                 # Healthy threshold
    unhealthyThreshold: 3               # Unhealthy threshold
    headers:                            # Health check headers
      Authorization: "Bearer health-token"
      User-Agent: "avapigw-health-checker"
    expectedStatus: [200, 204]          # Expected status codes
    expectedBody: "OK"                  # Expected response body
```

#### Load Balancing

```yaml
spec:
  loadBalancer:
    algorithm: "roundRobin"             # roundRobin, weighted, leastConn, random
    consistentHash:                     # For consistent hashing
      enabled: true
      hashKey: "source_ip"             # Hash key source
    sessionAffinity:                    # Session affinity
      enabled: true
      cookieName: "JSESSIONID"
      ttl: "3600s"
```

#### Backend Authentication

```yaml
spec:
  authentication:
    # JWT authentication
    jwt:
      enabled: true
      tokenSource: "oidc"              # oidc, static, vault
      oidc:
        issuerUrl: "https://keycloak.example.com/realms/backend"
        clientId: "backend-client"
        clientSecret: "secret-key"
        scopes: ["openid", "backend-access"]
      headerName: "Authorization"
      headerPrefix: "Bearer "
    
    # Basic authentication
    basic:
      enabled: true
      username: "backend-user"
      password: "backend-pass"
      # Or from Vault
      vaultPath: "secret/backend-auth"
      usernameKey: "username"
      passwordKey: "password"
    
    # mTLS authentication
    mtls:
      enabled: true
      certFile: "/certs/backend-client.crt"
      keyFile: "/certs/backend-client.key"
      caFile: "/certs/backend-ca.crt"
```

#### TLS Configuration

```yaml
spec:
  tls:
    enabled: true
    mode: "SIMPLE"                      # SIMPLE, MUTUAL, OPTIONAL_MUTUAL
    caFile: "/certs/backend-ca.crt"
    certFile: "/certs/backend-client.crt" # For mTLS
    keyFile: "/certs/backend-client.key"   # For mTLS
    serverName: "backend.example.com"   # SNI server name
    insecureSkipVerify: false           # Skip certificate verification
    minVersion: "1.2"
    maxVersion: "1.3"
```

#### Traffic Management

```yaml
spec:
  # Circuit breaker
  circuitBreaker:
    enabled: true
    threshold: 5                        # Failure threshold
    timeout: "30s"                      # Open state timeout
    halfOpenRequests: 3                 # Half-open requests
    successThreshold: 2                 # Success threshold to close
  
  # Rate limiting
  rateLimit:
    enabled: true
    requestsPerSecond: 100
    burst: 200
  
  # Max sessions
  maxSessions:
    enabled: true
    maxConcurrent: 500
    queueSize: 50
    queueTimeout: "10s"
  
  # Connection settings
  connection:
    maxIdleConns: 100                   # Max idle connections
    maxIdleConnsPerHost: 10             # Max idle per host
    idleConnTimeout: "90s"              # Idle connection timeout
    dialTimeout: "10s"                  # Dial timeout
    keepAlive: "30s"                    # Keep-alive duration
```

## GRPCRoute CRD

The `GRPCRoute` CRD defines gRPC routing rules and service-specific policies.

### APIVersion and Kind

```yaml
apiVersion: avapigw.io/v1
kind: GRPCRoute
```

### Spec Fields

#### Match Conditions

```yaml
spec:
  match:
    - service:
        exact: "api.v1.UserService"     # Exact service name
        # OR
        prefix: "api.v1"                # Service name prefix
        # OR
        regex: "api\\.v[0-9]+\\..*"     # Service name regex
      
      method:
        exact: "GetUser"                # Exact method name
        # OR
        prefix: "Get"                   # Method name prefix
        # OR
        regex: "(Get|List).*"           # Method name regex
      
      metadata:                         # gRPC metadata matching
        - name: "authorization"
          present: true                 # Metadata must be present
        - name: "content-type"
          exact: "application/grpc"     # Exact metadata value
        - name: "user-agent"
          prefix: "grpc-go"             # Metadata value prefix
        - name: "x-trace-id"
          regex: "[a-f0-9-]{36}"        # Metadata value regex
        - name: "x-debug"
          absent: true                  # Metadata must be absent
      
      authority:                        # Authority/host matching
        exact: "api.example.com"        # Exact authority
        # OR
        prefix: "api"                   # Authority prefix
        # OR
        regex: ".*\\.example\\.com"     # Authority regex
      
      withoutHeaders:                   # Headers that must NOT be present
        - "x-internal-only"
        - "x-debug-mode"
```

#### Route Destinations

```yaml
spec:
  route:
    - destination:
        host: "user-grpc-service"       # Backend gRPC service
        port: 9000                      # gRPC port
      weight: 80                        # Traffic weight
    
    - destination:
        host: "user-grpc-service-v2"
        port: 9000
      weight: 20                        # Weighted routing
```

#### gRPC-Specific Configuration

```yaml
spec:
  # Request timeout
  timeout: "30s"
  
  # Retry policy
  retries:
    attempts: 3
    perTryTimeout: "10s"
    retryOn: ["UNAVAILABLE", "DEADLINE_EXCEEDED", "RESOURCE_EXHAUSTED"]
    backoffBaseInterval: "1s"
    backoffMaxInterval: "10s"
  
  # Metadata manipulation
  headers:
    request:
      set:
        x-forwarded-proto: "grpc"
      add:
        x-request-id: "{{.RequestID}}"
      remove:
        - "x-internal-header"
    response:
      set:
        x-response-time: "{{.Duration}}"
      add:
        x-server: "avapigw"
      remove:
        - "x-debug-info"
```

#### Data Transformation

```yaml
spec:
  transform:
    # Request transformation
    request:
      metadata:                         # Transform gRPC metadata
        static:
          x-service-version: "v1"
        dynamic:
          x-client-ip: "{{.ClientIP}}"
    
    # Response transformation
    response:
      fieldMask:                        # Protocol Buffer FieldMask
        paths:
          - "user.id"
          - "user.name"
          - "user.email"
      streaming:                        # Streaming transformation
        enabled: true
        rateLimit:
          messagesPerSecond: 100
          burst: 200
```

## GRPCBackend CRD

The `GRPCBackend` CRD defines gRPC backend services and their configuration.

### APIVersion and Kind

```yaml
apiVersion: avapigw.io/v1
kind: GRPCBackend
```

### Spec Fields

#### Host Configuration

```yaml
spec:
  hosts:
    - address: "grpc-service-1.example.com"
      port: 9000
      weight: 1
    - address: "grpc-service-2.example.com"
      port: 9000
      weight: 2
    - address: "10.0.1.15"
      port: 9000
      weight: 1
      metadata:
        zone: "us-east-1a"
        version: "v1.2.0"
```

#### gRPC Health Checks

```yaml
spec:
  healthCheck:
    enabled: true
    service: "api.v1.UserService"       # gRPC health service name
    interval: "10s"
    timeout: "5s"
    healthyThreshold: 2
    unhealthyThreshold: 3
```

#### gRPC Connection Settings

```yaml
spec:
  grpc:
    maxRecvMsgSize: 4194304             # 4MB max receive message size
    maxSendMsgSize: 4194304             # 4MB max send message size
    keepalive:
      time: "30s"                       # Keepalive ping interval
      timeout: "10s"                    # Keepalive ping timeout
      permitWithoutStream: false        # Allow keepalive without streams
      maxConnectionIdle: "300s"         # Max connection idle time
      maxConnectionAge: "3600s"         # Max connection age
      maxConnectionAgeGrace: "30s"      # Grace period after max age
    
    # Connection pool settings
    connectionPool:
      maxConnections: 100               # Max connections per backend
      maxConcurrentStreams: 100         # Max concurrent streams per connection
      idleTimeout: "300s"               # Idle connection timeout
```

#### TLS Configuration

```yaml
spec:
  tls:
    enabled: true
    mode: "SIMPLE"                      # SIMPLE, MUTUAL, OPTIONAL_MUTUAL
    caFile: "/certs/grpc-ca.crt"
    certFile: "/certs/grpc-client.crt"  # For mTLS
    keyFile: "/certs/grpc-client.key"   # For mTLS
    serverName: "grpc.example.com"      # SNI server name
    insecureSkipVerify: false
    alpn: ["h2"]                        # ALPN protocols
```

## Status Fields

All CRDs include comprehensive status reporting for observability and debugging.

### Common Status Structure

```yaml
status:
  # Overall condition
  conditions:
    - type: "Ready"
      status: "True"                    # True, False, Unknown
      reason: "ConfigurationApplied"
      message: "Route configuration successfully applied"
      lastTransitionTime: "2026-02-15T10:30:00Z"
    
    - type: "Validated"
      status: "True"
      reason: "ValidationPassed"
      message: "All validation checks passed"
      lastTransitionTime: "2026-02-15T10:29:45Z"
  
  # Resource state
  state: "Active"                       # Active, Pending, Error, Inactive
  
  # Applied configuration
  appliedSpec:
    hash: "sha256:abc123..."            # Configuration hash
    version: "v1.2.3"                   # Applied version
    timestamp: "2026-02-15T10:30:00Z"   # Application timestamp
  
  # Observability
  observedGeneration: 5                 # Last observed generation
  lastUpdated: "2026-02-15T10:30:00Z"   # Last status update
  
  # Metrics
  metrics:
    requestCount: 1500                  # Total requests processed
    errorCount: 5                       # Total errors
    lastRequestTime: "2026-02-15T10:29:55Z"
```

### APIRoute Status

```yaml
status:
  # Route-specific status
  routeStatus:
    matchedRequests: 1500               # Requests matched by this route
    upstreamConnections: 3              # Active upstream connections
    cacheHitRatio: 0.85                # Cache hit ratio
  
  # Backend references
  backendRefs:
    - name: "user-service"
      namespace: "default"
      status: "Ready"
      endpoints: 3
      healthyEndpoints: 3
```

### Backend Status

```yaml
status:
  # Backend health
  endpoints:
    - address: "10.0.1.10:8080"
      status: "Healthy"                 # Healthy, Unhealthy, Unknown
      lastCheck: "2026-02-15T10:29:50Z"
      consecutiveFailures: 0
    - address: "10.0.1.11:8080"
      status: "Healthy"
      lastCheck: "2026-02-15T10:29:52Z"
      consecutiveFailures: 0
  
  # Load balancing
  loadBalancer:
    algorithm: "roundRobin"
    totalRequests: 2000
    requestDistribution:
      "10.0.1.10:8080": 1000
      "10.0.1.11:8080": 1000
```

## Cross-Reference Validation

The operator performs comprehensive cross-reference validation to ensure configuration consistency.

### Validation Rules

1. **Backend References**: All route destinations must reference existing Backend or GRPCBackend resources
2. **Namespace Validation**: Cross-namespace references are validated based on RBAC permissions
3. **Duplicate Detection**: Prevents conflicting route configurations across different CRDs
4. **Resource Dependencies**: Ensures dependent resources exist before applying configuration

### Validation Examples

```yaml
# APIRoute referencing Backend
apiVersion: avapigw.io/v1
kind: APIRoute
metadata:
  name: api-route
  namespace: app
spec:
  route:
    - destination:
        host: "user-backend"            # Must reference existing Backend
        port: 8080
---
# Referenced Backend must exist
apiVersion: avapigw.io/v1
kind: Backend
metadata:
  name: user-backend                    # Matches route destination
  namespace: app                        # Same namespace or allowed cross-namespace
spec:
  hosts:
    - address: "user-service.app.svc.cluster.local"
      port: 8080
```

## Examples

### Complete APIRoute Example

```yaml
apiVersion: avapigw.io/v1
kind: APIRoute
metadata:
  name: user-api
  namespace: production
  labels:
    app: user-service
    version: v1
spec:
  match:
    - uri:
        prefix: "/api/v1/users"
      methods: ["GET", "POST", "PUT", "DELETE"]
      headers:
        - name: "Authorization"
          present: true
  
  route:
    - destination:
        host: "user-backend"
        port: 8080
      weight: 100
  
  timeout: "30s"
  retries:
    attempts: 3
    perTryTimeout: "10s"
    retryOn: "5xx,reset,connect-failure"
  
  authentication:
    enabled: true
    jwt:
      enabled: true
      issuer: "https://auth.example.com"
      jwksUrl: "https://auth.example.com/.well-known/jwks.json"
  
  authorization:
    enabled: true
    rbac:
      enabled: true
      policies:
        - role: "user"
          permissions: ["read"]
        - role: "admin"
          permissions: ["read", "write", "delete"]
  
  rateLimit:
    enabled: true
    requestsPerSecond: 100
    burst: 200
    perClient: true
  
  cors:
    allowOrigins: ["https://app.example.com"]
    allowMethods: ["GET", "POST", "PUT", "DELETE"]
    allowHeaders: ["Content-Type", "Authorization"]
    allowCredentials: true
  
  cache:
    enabled: true
    ttl: "300s"
    keyComponents: ["uri", "method", "headers.Authorization"]
```

### Complete Backend Example

```yaml
apiVersion: avapigw.io/v1
kind: Backend
metadata:
  name: user-backend
  namespace: production
spec:
  hosts:
    - address: "user-service-1.production.svc.cluster.local"
      port: 8080
      weight: 1
    - address: "user-service-2.production.svc.cluster.local"
      port: 8080
      weight: 1
  
  healthCheck:
    enabled: true
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
    halfOpenRequests: 3
  
  tls:
    enabled: true
    mode: "SIMPLE"
    caFile: "/certs/ca.crt"
    serverName: "user-service.production.svc.cluster.local"
  
  authentication:
    jwt:
      enabled: true
      tokenSource: "oidc"
      oidc:
        issuerUrl: "https://keycloak.example.com/realms/backend"
        clientId: "user-service"
        clientSecret: "secret-key"
        scopes: ["openid", "user-service"]
```

### Complete GRPCRoute Example

```yaml
apiVersion: avapigw.io/v1
kind: GRPCRoute
metadata:
  name: user-grpc-api
  namespace: production
spec:
  match:
    - service:
        exact: "api.v1.UserService"
      method:
        prefix: "Get"
      metadata:
        - name: "authorization"
          present: true
  
  route:
    - destination:
        host: "user-grpc-backend"
        port: 9000
      weight: 100
  
  timeout: "30s"
  retries:
    attempts: 3
    perTryTimeout: "10s"
    retryOn: ["UNAVAILABLE", "DEADLINE_EXCEEDED"]
  
  transform:
    response:
      fieldMask:
        paths:
          - "user.id"
          - "user.name"
          - "user.email"
```

### Complete GRPCBackend Example

```yaml
apiVersion: avapigw.io/v1
kind: GRPCBackend
metadata:
  name: user-grpc-backend
  namespace: production
spec:
  hosts:
    - address: "user-grpc-service.production.svc.cluster.local"
      port: 9000
      weight: 1
  
  healthCheck:
    enabled: true
    service: "api.v1.UserService"
    interval: "10s"
    timeout: "5s"
  
  grpc:
    maxRecvMsgSize: 4194304
    maxSendMsgSize: 4194304
    keepalive:
      time: "30s"
      timeout: "10s"
  
  tls:
    enabled: true
    mode: "SIMPLE"
    caFile: "/certs/grpc-ca.crt"
    serverName: "user-grpc-service.production.svc.cluster.local"
```

## Related Documentation

- **[Operator Documentation](operator.md)** - AVAPIGW Operator overview and deployment
- **[Webhook Configuration](webhook-configuration.md)** - Admission webhook setup and validation
- **[Configuration Reference](configuration-reference.md)** - Complete configuration options
- **[Installation Guide](../README.md#installation)** - Installation and deployment instructions