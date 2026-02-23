# GraphQL Support

## Overview

The AV API Gateway provides comprehensive GraphQL support with advanced features for query analysis, security, performance optimization, and observability. The gateway acts as a GraphQL proxy, routing requests to backend GraphQL services while providing middleware capabilities for query protection, authentication, caching, and more.

## Key Features

- **Query Analysis**: Depth limiting and complexity analysis to prevent resource exhaustion
- **Security**: Introspection control, operation type filtering, and comprehensive authentication/authorization
- **Performance**: Intelligent caching, connection pooling, and load balancing
- **WebSocket Subscriptions**: Full support for GraphQL subscriptions over WebSocket
- **Observability**: Detailed metrics, tracing, and logging for GraphQL operations
- **Kubernetes Native**: CRD-based configuration with operator support

## Architecture

### GraphQL Proxy Architecture

```
┌─────────────┐    ┌─────────────────────────────────────┐    ┌─────────────────┐
│   Client    │    │           AV API Gateway            │    │  GraphQL Backend│
│             │    │                                     │    │                 │
│ ┌─────────┐ │    │ ┌─────────┐ ┌─────────┐ ┌─────────┐ │    │ ┌─────────────┐ │
│ │GraphQL  │ │───▶│ │ Router  │ │Middleware│ │  Proxy  │ │───▶│ │GraphQL      │ │
│ │Query    │ │    │ │         │ │ Chain   │ │         │ │    │ │Service      │ │
│ └─────────┘ │    │ └─────────┘ └─────────┘ └─────────┘ │    │ └─────────────┘ │
│             │    │                                     │    │                 │
│ ┌─────────┐ │    │ ┌─────────────────────────────────┐ │    │                 │
│ │WebSocket│ │◄──▶│ │    Subscription Proxy           │ │◄──▶│                 │
│ │         │ │    │ │    (graphql-ws protocol)        │ │    │                 │
│ └─────────┘ │    │ └─────────────────────────────────┘ │    │                 │
└─────────────┘    └─────────────────────────────────────┘    └─────────────────┘
```

### Request Flow

1. **Routing**: GraphQL requests are matched against configured routes based on path, operation type, operation name, and headers
2. **Middleware Chain**: Requests pass through middleware for authentication, authorization, rate limiting, and query analysis
3. **Query Analysis**: GraphQL queries are parsed and analyzed for depth, complexity, and introspection
4. **Caching**: Cache lookup for previously processed queries (optional)
5. **Load Balancing**: Requests are distributed across healthy backend instances
6. **Proxying**: Requests are forwarded to the selected backend with optional transformation
7. **Response Processing**: Responses are processed through middleware chain and returned to client

## Configuration Guide

### Basic GraphQL Configuration

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: graphql-gateway
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
  
  graphqlRoutes:
    - name: main-graphql
      match:
        - path:
            exact: "/graphql"
      route:
        - destination:
            host: graphql-backend
            port: 4000
      depthLimit: 10
      complexityLimit: 100
      introspectionEnabled: true
  
  graphqlBackends:
    - name: graphql-backend
      hosts:
        - address: "graphql-service.default.svc.cluster.local"
          port: 4000
      healthCheck:
        enabled: true
        path: "/health"
```

### Advanced Routing Configuration

#### Route by Operation Type

```yaml
spec:
  graphqlRoutes:
    # Route queries to read-optimized backend
    - name: graphql-queries
      match:
        - path:
            exact: "/graphql"
          operationType: query
      route:
        - destination:
            host: graphql-read-backend
            port: 4000
      depthLimit: 15
      complexityLimit: 500
    
    # Route mutations to write-optimized backend
    - name: graphql-mutations
      match:
        - path:
            exact: "/graphql"
          operationType: mutation
      route:
        - destination:
            host: graphql-write-backend
            port: 4000
      depthLimit: 5
      complexityLimit: 200
      timeout: 60s
    
    # Route subscriptions to subscription backend
    - name: graphql-subscriptions
      match:
        - path:
            exact: "/graphql"
          operationType: subscription
      route:
        - destination:
            host: graphql-subscription-backend
            port: 4000
      allowedOperations:
        - subscription
```

#### Route by Operation Name

```yaml
spec:
  graphqlRoutes:
    # Route user operations to user service
    - name: user-operations
      match:
        - path:
            exact: "/graphql"
          operationName:
            prefix: "User"
      route:
        - destination:
            host: user-graphql-service
            port: 4000
    
    # Route admin operations to admin service
    - name: admin-operations
      match:
        - path:
            exact: "/graphql"
          operationName:
            regex: "^(Admin|Manage).*"
      route:
        - destination:
            host: admin-graphql-service
            port: 4000
      authentication:
        enabled: true
        jwt:
          enabled: true
          issuer: "https://auth.example.com"
      authorization:
        enabled: true
        rbac:
          enabled: true
          policies:
            - role: "admin"
              permissions: ["read", "write", "delete"]
```

#### Route by Headers

```yaml
spec:
  graphqlRoutes:
    # Route API v2 requests
    - name: graphql-v2
      match:
        - path:
            exact: "/graphql"
          headers:
            - name: "X-API-Version"
              exact: "v2"
      route:
        - destination:
            host: graphql-v2-backend
            port: 4000
    
    # Route tenant-specific requests
    - name: tenant-graphql
      match:
        - path:
            exact: "/graphql"
          headers:
            - name: "X-Tenant-ID"
              present: true
      route:
        - destination:
            host: tenant-graphql-backend
            port: 4000
      headers:
        request:
          add:
            X-Tenant-ID: "{{.headers.X-Tenant-ID}}"
```

## Middleware Features

### Query Depth Limiting

Prevents deeply nested queries that could cause performance issues or denial of service attacks.

```yaml
spec:
  graphqlRoutes:
    - name: depth-limited-graphql
      depthLimit: 10  # Maximum nesting depth
```

**Example**: With `depthLimit: 3`, this query would be rejected:

```graphql
query DeepQuery {
  user {           # Depth 1
    posts {        # Depth 2
      comments {   # Depth 3
        replies {  # Depth 4 - EXCEEDS LIMIT
          author {
            name
          }
        }
      }
    }
  }
}
```

**Error Response**:
```json
{
  "errors": [
    {
      "message": "Query depth limit exceeded: 4 > 3",
      "extensions": {
        "code": "DEPTH_LIMIT_EXCEEDED",
        "depth": 4,
        "maxDepth": 3
      }
    }
  ]
}
```

### Query Complexity Analysis

Prevents complex queries that could consume excessive computational resources.

```yaml
spec:
  graphqlRoutes:
    - name: complexity-limited-graphql
      complexityLimit: 1000  # Maximum complexity score
```

**Complexity Calculation**:
- Each field adds 1 to the complexity score
- Nested fields contribute multiplicatively based on depth
- List fields may have higher complexity weights

**Example**: A query with complexity score exceeding the limit:

```graphql
query ComplexQuery {
  users {          # Base complexity: 1
    posts {        # Nested complexity: users * posts
      comments {   # Nested complexity: users * posts * comments
        author {   # Further nesting increases complexity
          profile {
            details
          }
        }
      }
    }
  }
}
```

### Introspection Control

Controls whether GraphQL schema introspection is allowed, important for production security.

```yaml
spec:
  graphqlRoutes:
    - name: production-graphql
      introspectionEnabled: false  # Disable in production
    
    - name: development-graphql
      introspectionEnabled: true   # Allow in development
```

**Blocked Introspection Query**:
```graphql
query IntrospectionQuery {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

**Error Response**:
```json
{
  "errors": [
    {
      "message": "GraphQL introspection is not allowed",
      "extensions": {
        "code": "INTROSPECTION_DISABLED"
      }
    }
  ]
}
```

### Operation Type Filtering

Restricts which GraphQL operation types are allowed on specific routes.

```yaml
spec:
  graphqlRoutes:
    - name: read-only-graphql
      allowedOperations:
        - query  # Only allow queries
    
    - name: full-access-graphql
      allowedOperations:
        - query
        - mutation
        - subscription
```

## WebSocket Subscriptions

The gateway provides full support for GraphQL subscriptions over WebSocket using the `graphql-ws` protocol.

### Subscription Configuration

```yaml
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP  # WebSocket upgrades over HTTP
  
  graphqlRoutes:
    - name: subscription-route
      match:
        - path:
            exact: "/graphql"
          operationType: subscription
      route:
        - destination:
            host: subscription-backend
            port: 4000
      allowedOperations:
        - subscription
```

### WebSocket Protocol Support

- **Protocol**: `graphql-ws` (GraphQL over WebSocket Protocol)
- **Subprotocol**: `graphql-ws` in WebSocket handshake
- **Connection Lifecycle**: Automatic connection management and cleanup
- **Message Types**: Support for all `graphql-ws` message types:
  - `connection_init` - Initialize connection
  - `connection_ack` - Acknowledge connection
  - `start` - Start subscription
  - `data` - Subscription data
  - `error` - Error message
  - `complete` - Subscription complete
  - `stop` - Stop subscription
  - `connection_terminate` - Terminate connection

### Subscription Example

**Client Connection**:
```javascript
const client = new WebSocket('ws://gateway.example.com:8080/graphql', 'graphql-ws');

// Initialize connection
client.send(JSON.stringify({
  type: 'connection_init',
  payload: {
    Authorization: 'Bearer token123'
  }
}));

// Start subscription
client.send(JSON.stringify({
  id: 'sub1',
  type: 'start',
  payload: {
    query: `
      subscription {
        messageAdded {
          id
          content
          user {
            name
          }
        }
      }
    `
  }
}));
```

**Gateway Proxying**:
The gateway maintains bidirectional communication between client and backend, forwarding all messages while applying middleware for authentication, rate limiting, and logging.

## Metrics and Observability

### GraphQL-Specific Metrics

The gateway provides comprehensive metrics for GraphQL operations:

```yaml
spec:
  observability:
    metrics:
      enabled: true
      graphql:
        enabled: true
        operations: true      # Track operation types and names
        complexity: true      # Track query complexity scores
        depth: true          # Track query depth
        introspection: true  # Track introspection attempts
        subscriptions: true  # Track WebSocket subscription metrics
```

### Available Metrics

#### Request Metrics
- `graphql_requests_total{operation_type, operation_name, route, status}` - Total GraphQL requests
- `graphql_request_duration_seconds{operation_type, operation_name, route}` - Request duration histogram
- `graphql_errors_total{operation_type, error_type, route}` - GraphQL error count

#### Query Analysis Metrics
- `graphql_query_depth{route}` - Query depth distribution
- `graphql_query_complexity{route}` - Query complexity distribution
- `graphql_depth_limit_exceeded_total{route}` - Depth limit violations
- `graphql_complexity_limit_exceeded_total{route}` - Complexity limit violations

#### Security Metrics
- `graphql_introspection_requests_total{route, allowed}` - Introspection request count
- `graphql_operation_type_blocked_total{operation_type, route}` - Blocked operation types

#### Subscription Metrics
- `graphql_subscription_connections_active{route}` - Active WebSocket connections
- `graphql_subscription_connections_total{route, status}` - Total WebSocket connections
- `graphql_subscription_messages_total{route, type}` - WebSocket message count
- `graphql_subscription_duration_seconds{route}` - Subscription duration

#### Backend Metrics
- `graphql_backend_requests_total{backend, operation_type, status}` - Backend request count
- `graphql_backend_request_duration_seconds{backend, operation_type}` - Backend request duration
- `graphql_backend_errors_total{backend, error_type}` - Backend error count

### Tracing

GraphQL operations are fully traced with OpenTelemetry:

```yaml
spec:
  observability:
    tracing:
      enabled: true
      otlpEndpoint: "https://jaeger-collector:14250"
      serviceName: "avapigw-graphql"
```

**Trace Spans**:
- `graphql.request` - Overall request span
- `graphql.parse` - Query parsing
- `graphql.validate` - Query validation (depth, complexity, introspection)
- `graphql.route` - Route matching
- `graphql.proxy` - Backend proxying
- `graphql.subscription` - WebSocket subscription handling

### Logging

Structured logging for GraphQL operations:

```yaml
spec:
  observability:
    logging:
      level: info
      format: json
      graphql:
        enabled: true
        logQueries: false      # Set to true for debugging (security risk)
        logVariables: false    # Set to true for debugging (security risk)
        logErrors: true
        logMetrics: true
```

**Log Fields**:
- `operation_type` - GraphQL operation type
- `operation_name` - GraphQL operation name
- `query_depth` - Calculated query depth
- `query_complexity` - Calculated query complexity
- `route_name` - Matched route name
- `backend_name` - Selected backend name
- `duration_ms` - Request duration
- `status_code` - HTTP status code

## Operator/CRD Usage

### GraphQLRoute CRD

```yaml
apiVersion: avapigw.io/v1
kind: GraphQLRoute
metadata:
  name: user-api-graphql
  namespace: production
spec:
  match:
    - path:
        exact: "/graphql"
      headers:
        - name: "Authorization"
          present: true
  
  route:
    - destination:
        host: "user-graphql-backend"
        port: 4000
  
  depthLimit: 15
  complexityLimit: 1000
  introspectionEnabled: false
  allowedOperations:
    - query
    - mutation
  
  authentication:
    enabled: true
    jwt:
      enabled: true
      issuer: "https://auth.example.com"
      audience: "user-api"
  
  rateLimit:
    enabled: true
    requestsPerSecond: 100
    burst: 200
```

### GraphQLBackend CRD

```yaml
apiVersion: avapigw.io/v1
kind: GraphQLBackend
metadata:
  name: user-graphql-backend
  namespace: production
spec:
  hosts:
    - address: "user-graphql-1.prod.svc.cluster.local"
      port: 4000
      weight: 1
    - address: "user-graphql-2.prod.svc.cluster.local"
      port: 4000
      weight: 1
  
  healthCheck:
    enabled: true
    path: "/health"
    interval: 10s
    timeout: 5s
  
  loadBalancer:
    algorithm: roundRobin
  
  circuitBreaker:
    enabled: true
    threshold: 5
    timeout: 30s
  
  tls:
    enabled: true
    mode: SIMPLE
    caFile: "/certs/ca.crt"
```

### Operator Features

- **Automatic Configuration**: CRDs are automatically converted to gateway configuration
- **Validation**: Comprehensive validation of GraphQL-specific fields
- **Status Reporting**: Real-time status updates for routes and backends
- **Cross-Reference Validation**: Ensures referenced backends exist
- **Hot Reload**: Configuration changes are applied without restart

## Examples

### Multi-Tenant GraphQL Gateway

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: multi-tenant-graphql
spec:
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      tls:
        certFile: "/certs/tls.crt"
        keyFile: "/certs/tls.key"
  
  graphqlRoutes:
    # Tenant A - Full access
    - name: tenant-a-graphql
      match:
        - path:
            exact: "/graphql"
          headers:
            - name: "X-Tenant-ID"
              exact: "tenant-a"
      route:
        - destination:
            host: tenant-a-graphql
            port: 4000
      depthLimit: 20
      complexityLimit: 2000
      introspectionEnabled: true
      allowedOperations:
        - query
        - mutation
        - subscription
    
    # Tenant B - Restricted access
    - name: tenant-b-graphql
      match:
        - path:
            exact: "/graphql"
          headers:
            - name: "X-Tenant-ID"
              exact: "tenant-b"
      route:
        - destination:
            host: tenant-b-graphql
            port: 4000
      depthLimit: 10
      complexityLimit: 500
      introspectionEnabled: false
      allowedOperations:
        - query
      rateLimit:
        enabled: true
        requestsPerSecond: 50
        burst: 100
  
  graphqlBackends:
    - name: tenant-a-graphql
      hosts:
        - address: "tenant-a-graphql.prod.svc.cluster.local"
          port: 4000
      healthCheck:
        enabled: true
        path: "/health"
    
    - name: tenant-b-graphql
      hosts:
        - address: "tenant-b-graphql.prod.svc.cluster.local"
          port: 4000
      healthCheck:
        enabled: true
        path: "/health"
```

### Development vs Production Configuration

#### Development Environment

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: graphql-dev
spec:
  graphqlRoutes:
    - name: dev-graphql
      match:
        - path:
            exact: "/graphql"
      route:
        - destination:
            host: graphql-dev
            port: 4000
      
      # Relaxed limits for development
      depthLimit: 50
      complexityLimit: 10000
      introspectionEnabled: true
      allowedOperations:
        - query
        - mutation
        - subscription
      
      # No authentication in dev
      authentication:
        enabled: false
      
      # Detailed logging
      observability:
        logging:
          level: debug
          graphql:
            logQueries: true
            logVariables: true
```

#### Production Environment

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: graphql-prod
spec:
  graphqlRoutes:
    - name: prod-graphql
      match:
        - path:
            exact: "/graphql"
      route:
        - destination:
            host: graphql-prod
            port: 4000
      
      # Strict limits for production
      depthLimit: 15
      complexityLimit: 1000
      introspectionEnabled: false
      allowedOperations:
        - query
        - mutation
      
      # Required authentication
      authentication:
        enabled: true
        jwt:
          enabled: true
          issuer: "https://auth.company.com"
          audience: "api.company.com"
      
      # Rate limiting
      rateLimit:
        enabled: true
        requestsPerSecond: 100
        burst: 200
        perClient: true
      
      # Caching
      cache:
        enabled: true
        ttl: "5m"
        type: "redis"
        redis:
          address: "redis.prod.svc.cluster.local:6379"
          keyPrefix: "graphql:prod:"
      
      # Security headers
      security:
        enabled: true
        headers:
          enabled: true
          xFrameOptions: "DENY"
          xContentTypeOptions: "nosniff"
```

### GraphQL Federation Gateway

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: graphql-federation
spec:
  graphqlRoutes:
    # User service operations
    - name: user-service-graphql
      match:
        - path:
            exact: "/graphql"
          operationName:
            regex: "^(User|Profile|Account).*"
      route:
        - destination:
            host: user-graphql-service
            port: 4000
    
    # Product service operations
    - name: product-service-graphql
      match:
        - path:
            exact: "/graphql"
          operationName:
            regex: "^(Product|Catalog|Inventory).*"
      route:
        - destination:
            host: product-graphql-service
            port: 4000
    
    # Order service operations
    - name: order-service-graphql
      match:
        - path:
            exact: "/graphql"
          operationName:
            regex: "^(Order|Cart|Payment).*"
      route:
        - destination:
            host: order-graphql-service
            port: 4000
    
    # Fallback to gateway service for federated queries
    - name: federated-graphql
      match:
        - path:
            exact: "/graphql"
      route:
        - destination:
            host: graphql-federation-gateway
            port: 4000
      depthLimit: 20
      complexityLimit: 5000
```

## Best Practices

### Security

1. **Disable Introspection in Production**
   ```yaml
   introspectionEnabled: false
   ```

2. **Set Appropriate Limits**
   ```yaml
   depthLimit: 15          # Reasonable depth limit
   complexityLimit: 1000   # Prevent resource exhaustion
   ```

3. **Use Authentication and Authorization**
   ```yaml
   authentication:
     enabled: true
   authorization:
     enabled: true
   ```

4. **Implement Rate Limiting**
   ```yaml
   rateLimit:
     enabled: true
     requestsPerSecond: 100
     perClient: true
   ```

### Performance

1. **Enable Caching**
   ```yaml
   cache:
     enabled: true
     ttl: "5m"
     type: "redis"
   ```

2. **Use Load Balancing**
   ```yaml
   loadBalancer:
     algorithm: roundRobin
   ```

3. **Configure Circuit Breakers**
   ```yaml
   circuitBreaker:
     enabled: true
     threshold: 5
   ```

4. **Set Appropriate Timeouts**
   ```yaml
   timeout: "30s"
   ```

### Monitoring

1. **Enable Comprehensive Metrics**
   ```yaml
   observability:
     metrics:
       enabled: true
       graphql:
         enabled: true
   ```

2. **Use Structured Logging**
   ```yaml
   observability:
     logging:
       format: json
       level: info
   ```

3. **Enable Tracing**
   ```yaml
   observability:
     tracing:
       enabled: true
   ```

### Development

1. **Use Relaxed Limits in Development**
   ```yaml
   depthLimit: 50
   complexityLimit: 10000
   introspectionEnabled: true
   ```

2. **Enable Query Logging for Debugging**
   ```yaml
   observability:
     logging:
       graphql:
         logQueries: true  # Only in development
   ```

3. **Separate Development and Production Configurations**

## Troubleshooting

### Common Issues

#### Query Depth Limit Exceeded

**Error**: `Query depth limit exceeded: 12 > 10`

**Solution**: Either increase the depth limit or optimize the query structure:
```yaml
depthLimit: 15  # Increase limit
```

#### Query Complexity Limit Exceeded

**Error**: `Query complexity limit exceeded: 1500 > 1000`

**Solution**: Increase complexity limit or optimize query:
```yaml
complexityLimit: 2000  # Increase limit
```

#### Introspection Disabled

**Error**: `GraphQL introspection is not allowed`

**Solution**: Enable introspection for development:
```yaml
introspectionEnabled: true
```

#### Operation Type Not Allowed

**Error**: `Operation type 'subscription' is not allowed`

**Solution**: Add subscription to allowed operations:
```yaml
allowedOperations:
  - query
  - mutation
  - subscription
```

#### WebSocket Connection Failed

**Issue**: WebSocket subscriptions not working

**Solution**: Ensure proper protocol configuration:
```yaml
listeners:
  - name: http
    port: 8080
    protocol: HTTP  # Required for WebSocket upgrades
```

### Debugging

1. **Enable Debug Logging**
   ```yaml
   observability:
     logging:
       level: debug
   ```

2. **Check Metrics**
   ```bash
   curl http://gateway:9090/metrics | grep graphql
   ```

3. **Verify Route Matching**
   ```bash
   kubectl logs -l app=avapigw | grep "route matched"
   ```

4. **Check Backend Health**
   ```bash
   kubectl get graphqlbackends -o wide
   ```

## Related Documentation

- **[Configuration Reference](configuration-reference.md)** - Complete configuration options
- **[CRD Reference](crd-reference.md)** - Kubernetes CRD documentation
- **[Operator Documentation](operator.md)** - AVAPIGW Operator overview
- **[Metrics Documentation](metrics.md)** - Observability and monitoring
- **[Performance Tuning](performance-tuning.md)** - Performance optimization guide