# OpenAPI Request Validation

## Overview

The AV API Gateway provides comprehensive OpenAPI 3.x request validation capabilities for all gateway modes (HTTP, gRPC, GraphQL). This feature validates incoming requests against OpenAPI specifications to ensure API contract compliance and improve security.

OpenAPI validation operates as middleware in the request processing chain, positioned strategically after authentication and authorization but before caching and transformation:

```
Auth → Authz → Security → CORS → BodyLimit → **OpenAPI Validation** → Headers → Cache → Transform → Encoding
```

## Key Features

- **OpenAPI 3.x Support** - Full support for OpenAPI 3.0+ specifications
- **Multiple Spec Sources** - Load specs from files, URLs, or Kubernetes ConfigMaps
- **Configurable Validation** - Enable/disable validation of request bodies, parameters, headers, and security
- **Fail-Safe Modes** - Reject invalid requests or log-only mode for monitoring
- **Hot Reload** - Dynamic spec reloading without gateway restart
- **Comprehensive Metrics** - Prometheus metrics for validation results and performance
- **Multi-Protocol Support** - HTTP, gRPC (proto descriptors), and GraphQL (schema validation)

## Configuration Reference

### Global Configuration

Configure OpenAPI validation at the gateway level to apply to all routes:

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: my-gateway
spec:
  # Global OpenAPI validation configuration
  openAPIValidation:
    enabled: true
    specFile: "/path/to/openapi.yaml"
    specURL: "https://api.example.com/openapi.yaml"
    failOnError: true
    validateRequestBody: true
    validateRequestParams: true
    validateRequestHeaders: false
    validateSecurity: false
```

### Route-Level Configuration

Override global settings for specific routes:

```yaml
spec:
  routes:
    - name: items-api
      match:
        - uri:
            prefix: /api/v1/items
      route:
        - destination:
            host: items-service
            port: 8080
      # Route-level OpenAPI validation (overrides global)
      openAPIValidation:
        enabled: true
        specFile: "/path/to/items-openapi.yaml"
        failOnError: true
        validateRequestBody: true
        validateRequestParams: true
        validateRequestHeaders: true
        validateSecurity: false
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable OpenAPI request validation |
| `specFile` | string | - | Path to OpenAPI specification file |
| `specURL` | string | - | URL to fetch OpenAPI specification from |
| `failOnError` | boolean | `true` | Reject requests that fail validation |
| `validateRequestBody` | boolean | `true` | Validate request body against schema |
| `validateRequestParams` | boolean | `true` | Validate path, query, and header parameters |
| `validateRequestHeaders` | boolean | `false` | Validate request headers |
| `validateSecurity` | boolean | `false` | Validate security requirements |

**Note**: Only one of `specFile` or `specURL` should be specified. If both are provided, `specFile` takes precedence.

#### Spec Loading Safeguards

- **Fetch timeout**: `specURL` fetches are bounded to 30 seconds.
- **External `$ref` denied (SSRF guard)**: references to locations other than
  the spec's own root URI are rejected unless the loader is explicitly
  configured to allow external references, protecting against SSRF and
  local-file reads via `$ref` in untrusted documents. A denied reference
  fails the load with `encountered disallowed external reference`.
- **Per-load byte cache**: fetched spec bytes are cached only for the
  duration of one load, so invalidating/reloading a spec genuinely refetches
  it instead of serving stale bytes.

## gRPC Proto Validation

For gRPC routes, use proto descriptor-based validation:

```yaml
spec:
  grpcRoutes:
    - name: test-service
      match:
        - service:
            exact: TestService
      route:
        - destination:
            host: grpc-backend
            port: 9000
      # Proto validation configuration
      protoValidation:
        enabled: true
        descriptorFile: "/path/to/descriptor.pb"
        failOnError: true
        validateRequestMessage: true
```

### gRPC Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable proto descriptor validation |
| `descriptorConfigMapRef.name` | string | - | Name of ConfigMap (in the route's namespace) containing the proto descriptor. Resolved and inlined (base64) by the operator. |
| `descriptorConfigMapRef.key` | string | - | Key in ConfigMap (optional; if empty the ConfigMap must have exactly one key) |
| `descriptorFile` | string | - | Path to proto descriptor file (file/URL modes) |
| `failOnError` | boolean | `true` | Reject requests that fail validation |
| `validateRequestMessage` | boolean | `true` | Validate request message structure |

## GraphQL Schema Validation

For GraphQL routes, use schema-based validation:

```yaml
spec:
  graphqlRoutes:
    - name: items-graphql
      match:
        - path:
            exact: /graphql
      route:
        - destination:
            host: graphql-backend
            port: 8080
      # GraphQL schema validation
      schemaValidation:
        enabled: true
        schemaFile: "/path/to/schema.graphql"
        failOnError: true
        validateVariables: true
```

### GraphQL Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable GraphQL schema validation |
| `schemaConfigMapRef.name` | string | - | Name of ConfigMap (in the route's namespace) containing the GraphQL schema. Resolved and inlined by the operator. |
| `schemaConfigMapRef.key` | string | - | Key in ConfigMap (optional; if empty the ConfigMap must have exactly one key) |
| `schemaFile` | string | - | Path to GraphQL schema file (file/URL modes) |
| `failOnError` | boolean | `true` | Reject requests that fail validation |
| `validateVariables` | boolean | `true` | Validate GraphQL variables |

## Kubernetes CRD Support

When using the AVAPIGW Operator, configure OpenAPI validation through Custom Resource Definitions:

### How ConfigMap-referenced specs are resolved (operator mode)

In operator mode, the gateway receives its configuration from the operator rather than
reading files or ConfigMaps directly. Because of this, `specConfigMapRef` (and the gRPC
`descriptorConfigMapRef` and GraphQL `schemaConfigMapRef` equivalents) are **fully
supported and resolved by the operator** before the configuration is pushed to the gateway:

1. When an `APIRoute` sets `openAPIValidation.specConfigMapRef`, the operator reads the
   referenced ConfigMap and inlines the spec content into the configuration it delivers to
   the gateway. The gateway then loads the spec from that inline content — it never needs
   cluster access to the ConfigMap.
2. The referenced ConfigMap **must live in the same namespace as the route**. Cross-namespace
   references are rejected; the operator always resolves the ConfigMap from the route's own
   namespace as a defense against privilege escalation.
3. If `specConfigMapRef.key` is omitted, the ConfigMap must contain exactly one key, which
   the operator uses automatically. If the ConfigMap has multiple keys, you must specify
   `key` explicitly.
4. gRPC (`protoValidation.descriptorConfigMapRef`) and GraphQL
   (`schemaValidation.schemaConfigMapRef`) references are resolved the same way. Because a
   proto descriptor is binary, the operator base64-encodes it during resolution.
5. **Referenced ConfigMaps are watched**: editing a ConfigMap referenced by an
   APIRoute/GRPCRoute/GraphQLRoute automatically **re-reconciles the referencing routes**
   (field-indexed ConfigMap watch, namespace-local), so an updated OpenAPI spec, proto
   descriptor, or GraphQL schema propagates to the gateway without touching the route or
   restarting the operator. Re-reconciles triggered this way are counted by
   `avapigw_operator_configmap_watch_enqueues_total{kind}`.

> **Note:** Earlier releases required `specFile`/`specURL` in gateway configuration and the
> gateway rejected routes that used `specConfigMapRef`. The operator now resolves these
> references itself, so `specConfigMapRef` is the recommended way to supply specs in
> operator mode.
>
> The resolved content is carried on internal `specInline` / `descriptorInline` /
> `schemaInline` fields that the operator populates automatically. These fields are an
> internal transport and are **not** intended to be set directly by users.

To read the referenced ConfigMaps, the operator's ClusterRole grants `configmaps`
`get`, `list`, and `watch` (see [RBAC for ConfigMaps](#rbac-for-configmaps)). This is
already included in the generated `config/rbac/role.yaml` and the Helm chart.

### APIRoute with OpenAPI Validation

```yaml
apiVersion: gateway.avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: items-api
  namespace: default
spec:
  match:
    - uri:
        prefix: /api/v1/items
  route:
    - destination:
        host: items-service
        port: 8080
  # OpenAPI validation configuration
  openAPIValidation:
    enabled: true
    specConfigMapRef:
      name: items-openapi-spec
      key: openapi.yaml
    failOnError: true
    validateRequestBody: true
    validateRequestParams: true
    validateRequestHeaders: false
    validateSecurity: false
```

### ConfigMap with OpenAPI Spec

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: items-openapi-spec
  namespace: default
data:
  openapi.yaml: |
    openapi: "3.0.3"
    info:
      title: Items API
      version: "1.0.0"
    paths:
      /api/v1/items:
        get:
          operationId: listItems
          parameters:
            - name: limit
              in: query
              schema:
                type: integer
                minimum: 1
                maximum: 100
          responses:
            "200":
              description: A list of items
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      items:
                        type: array
                        items:
                          $ref: "#/components/schemas/Item"
        post:
          operationId: createItem
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  $ref: "#/components/schemas/CreateItemRequest"
          responses:
            "201":
              description: Item created
    components:
      schemas:
        Item:
          type: object
          required:
            - id
            - name
          properties:
            id:
              type: string
              format: uuid
            name:
              type: string
              minLength: 1
              maxLength: 255
        CreateItemRequest:
          type: object
          required:
            - name
          properties:
            name:
              type: string
              minLength: 1
              maxLength: 255
```

### CRD Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable OpenAPI request validation |
| `specConfigMapRef.name` | string | - | Name of ConfigMap (in the route's namespace) containing the spec. Resolved and inlined by the operator. |
| `specConfigMapRef.key` | string | - | Key in ConfigMap (optional; if empty the ConfigMap must have exactly one key) |
| `specFile` | string | - | Path to OpenAPI specification file |
| `specURL` | string | - | URL to fetch OpenAPI specification from |
| `failOnError` | boolean | `true` | Reject requests that fail validation |
| `validateRequestBody` | boolean | `true` | Validate request body against schema |
| `validateRequestParams` | boolean | `true` | Validate path, query, and header parameters |
| `validateRequestHeaders` | boolean | `false` | Validate request headers |
| `validateSecurity` | boolean | `false` | Validate security requirements |

## Usage Examples

### Basic HTTP API Validation

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: api-gateway
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
      hosts: ["*"]
  
  # Global OpenAPI validation
  openAPIValidation:
    enabled: true
    specFile: "/etc/gateway/specs/api.yaml"
    failOnError: true
    validateRequestBody: true
    validateRequestParams: true
  
  routes:
    - name: users-api
      match:
        - uri:
            prefix: /api/v1/users
      route:
        - destination:
            host: users-service
            port: 8080
    
    - name: orders-api
      match:
        - uri:
            prefix: /api/v1/orders
      route:
        - destination:
            host: orders-service
            port: 8080
      # Override global validation for orders
      openAPIValidation:
        enabled: true
        specFile: "/etc/gateway/specs/orders.yaml"
        failOnError: false  # Log-only mode for orders
```

### Multi-Protocol Validation

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: multi-protocol-gateway
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
      hosts: ["*"]
    - name: grpc
      port: 9000
      protocol: GRPC
      grpc:
        reflection: true
        healthCheck: true
  
  # HTTP routes with OpenAPI validation
  routes:
    - name: rest-api
      match:
        - uri:
            prefix: /api/v1
      route:
        - destination:
            host: rest-service
            port: 8080
      openAPIValidation:
        enabled: true
        specFile: "/etc/specs/rest-api.yaml"
        failOnError: true
  
  # gRPC routes with proto validation
  grpcRoutes:
    - name: grpc-service
      match:
        - service:
            exact: UserService
      route:
        - destination:
            host: grpc-service
            port: 9000
      protoValidation:
        enabled: true
        descriptorFile: "/etc/specs/user-service.pb"
        failOnError: true
  
  # GraphQL routes with schema validation
  graphqlRoutes:
    - name: graphql-api
      match:
        - path:
            exact: /graphql
      route:
        - destination:
            host: graphql-service
            port: 8080
      schemaValidation:
        enabled: true
        schemaFile: "/etc/specs/schema.graphql"
        failOnError: true
```

### Kubernetes Deployment with ConfigMaps

```yaml
# ConfigMap with OpenAPI specs
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-specs
  namespace: gateway-system
data:
  users-api.yaml: |
    openapi: "3.0.3"
    info:
      title: Users API
      version: "1.0.0"
    # ... OpenAPI specification
  
  orders-api.yaml: |
    openapi: "3.0.3"
    info:
      title: Orders API
      version: "1.0.0"
    # ... OpenAPI specification

---
# APIRoute with ConfigMap reference
apiVersion: gateway.avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: users-api
  namespace: gateway-system
spec:
  match:
    - uri:
        prefix: /api/v1/users
  route:
    - destination:
        host: users-service.default.svc.cluster.local
        port: 8080
  openAPIValidation:
    enabled: true
    specConfigMapRef:
      name: api-specs
      key: users-api.yaml
    failOnError: true
    validateRequestBody: true
    validateRequestParams: true

---
apiVersion: gateway.avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: orders-api
  namespace: gateway-system
spec:
  match:
    - uri:
        prefix: /api/v1/orders
  route:
    - destination:
        host: orders-service.default.svc.cluster.local
        port: 8080
  openAPIValidation:
    enabled: true
    specConfigMapRef:
      name: api-specs
      key: orders-api.yaml
    failOnError: false  # Log-only mode
    validateRequestBody: true
    validateRequestParams: true
```

## Middleware Chain Position

OpenAPI validation is positioned strategically in the middleware chain to ensure proper request processing:

### Global Middleware Chain
```
Recovery → RequestID → Logging → Tracing → Audit → Metrics → 
CORS → MaxSessions → CircuitBreaker → RateLimit → Auth → [proxy]
```

### Per-Route Middleware Chain
```
Auth → Authz → RateLimit → Security Headers → CORS → Body Limit → 
**OpenAPI Validation** → Headers → Cache → Transform → Encoding → [proxy to backend]
```

This positioning ensures that:
1. **Authentication/Authorization** happens before validation
2. **Rate limiting** sheds load before body/validation work (401 before 429 for unauthenticated requests)
3. **Request limits** are enforced before processing large payloads
4. **Validation** occurs before expensive operations like caching and transformation
5. **Header manipulation** can modify requests after validation

## Prometheus Metrics

OpenAPI validation provides comprehensive metrics for monitoring and alerting:

### Core Metrics

```prometheus
# Request validation results
gateway_openapi_validation_requests_total{route="items-api", result="success"} 1500
gateway_openapi_validation_requests_total{route="items-api", result="failure"} 25

# Validation duration
gateway_openapi_validation_duration_seconds{route="items-api"} 0.002

# Validation errors by type
gateway_openapi_validation_errors_total{route="items-api", error_type="body"} 15
gateway_openapi_validation_errors_total{route="items-api", error_type="params"} 8
gateway_openapi_validation_errors_total{route="items-api", error_type="headers"} 2
```

### Metric Labels

| Metric | Labels | Description |
|--------|--------|-------------|
| `gateway_openapi_validation_requests_total` | `route`, `result` | Total validation requests by result |
| `gateway_openapi_validation_duration_seconds` | `route` | Validation duration histogram |
| `gateway_openapi_validation_errors_total` | `route`, `error_type` | Validation errors by type |

### Error Types

- `body` - Request body validation failed
- `params` - Query or path parameter validation failed (missing or invalid)
- `headers` - Header parameter validation failed
- `security` - Security requirement validation failed
- `unknown` - Any other validation failure

### Monitoring Queries

```prometheus
# Validation success rate
rate(gateway_openapi_validation_requests_total{result="success"}[5m]) / 
rate(gateway_openapi_validation_requests_total[5m]) * 100

# Average validation latency
rate(gateway_openapi_validation_duration_seconds_sum[5m]) / 
rate(gateway_openapi_validation_duration_seconds_count[5m])

# Top validation error types
topk(5, sum by (error_type) (
  rate(gateway_openapi_validation_errors_total[5m])
))

# Routes with highest validation failure rate
topk(10, sum by (route) (
  rate(gateway_openapi_validation_requests_total{result="failure"}[5m])
))
```

## Testing

The OpenAPI validation feature includes comprehensive test coverage across multiple levels:

### Test Targets

```bash
# Run all OpenAPI validation tests
make test-openapi

# Run specific test suites
make test-openapi-unit        # Unit tests
make test-openapi-functional  # Functional tests
make test-openapi-integration # Integration tests
make test-openapi-e2e        # End-to-end tests
```

### Test Data

Test specifications are available in `test/testdata/openapi/`:

- `items-api.yaml` - Complete Items API specification
- `minimal.yaml` - Minimal OpenAPI spec for basic testing
- `invalid.yaml` - Invalid spec for error testing

### Example Test Scenarios

```bash
# Test valid request validation
curl -X POST http://localhost:8080/api/v1/items \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Item", "price": 19.99}'

# Test invalid request body (should return 400)
curl -X POST http://localhost:8080/api/v1/items \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}'

# Test invalid query parameters (should return 400)
curl "http://localhost:8080/api/v1/items?limit=invalid"

# Test with validation disabled (log-only mode)
curl -X POST http://localhost:8080/api/v1/items \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}' \
  # Should return 200 but log validation error
```

## Troubleshooting

### Common Issues

#### 1. Spec Loading Failures

**Symptoms**: Gateway fails to start or validation is disabled
**Causes**: 
- Invalid file path or URL
- Malformed OpenAPI specification
- Network connectivity issues (for URL specs)

**Solutions**:
```bash
# Check file exists and is readable
ls -la /path/to/openapi.yaml

# Validate OpenAPI spec
swagger-codegen validate -i /path/to/openapi.yaml

# Check gateway logs
kubectl logs -f deployment/gateway -n gateway-system
```

#### 2. High Validation Latency

**Symptoms**: Increased request latency, timeout errors
**Causes**:
- Large OpenAPI specifications
- Complex validation rules
- Frequent spec reloading

**Solutions**:
```yaml
# Optimize validation settings
openAPIValidation:
  enabled: true
  specFile: "/path/to/optimized-spec.yaml"
  validateRequestHeaders: false  # Disable if not needed
  validateSecurity: false        # Disable if not needed
```

#### 3. False Positive Validation Errors

**Symptoms**: Valid requests rejected by validation
**Causes**:
- Overly strict OpenAPI specification
- Missing optional parameters in spec
- Incorrect content-type handling

**Solutions**:
```yaml
# Use log-only mode for debugging
openAPIValidation:
  enabled: true
  failOnError: false  # Log errors but allow requests
  specFile: "/path/to/spec.yaml"
```

#### 4. ConfigMap Updates Not Reflected

**Symptoms**: Spec changes in ConfigMap not applied
**Causes**:
- ConfigMap not mounted correctly
- Operator not watching ConfigMap changes
- Cache not invalidated

**Solutions**:
```bash
# Check ConfigMap mount
kubectl describe pod gateway-xxx -n gateway-system

# Restart gateway to reload specs
kubectl rollout restart deployment/gateway -n gateway-system

# Check operator logs
kubectl logs -f deployment/avapigw-operator -n gateway-system
```

### Debug Configuration

Enable debug logging for detailed validation information:

```yaml
spec:
  observability:
    logging:
      level: debug  # Enable debug logging
      format: json
```

### Validation Error Response Format

When validation fails, the gateway returns a structured error response:

```json
{
  "error": "Request validation failed",
  "details": [
    {
      "field": "name",
      "message": "field is required",
      "type": "body_validation"
    },
    {
      "field": "limit",
      "message": "value must be between 1 and 100",
      "type": "parameter_validation"
    }
  ]
}
```

## Performance Considerations

### Optimization Tips

1. **Spec Size**: Keep OpenAPI specifications focused and minimal
2. **Validation Scope**: Disable unnecessary validation types
3. **Caching**: Specs are cached in memory for performance
4. **Hot Reload**: Minimize spec changes in production

### Performance Metrics

Monitor these metrics for performance optimization:

```prometheus
# Validation latency percentiles
histogram_quantile(0.95, 
  rate(gateway_openapi_validation_duration_seconds_bucket[5m])
)

# Validation throughput
rate(gateway_openapi_validation_requests_total[5m])

# Memory usage (spec caching)
process_resident_memory_bytes{job="gateway"}
```

### Recommended Limits

| Resource | Recommended Limit | Description |
|----------|------------------|-------------|
| Spec File Size | < 1MB | Larger specs increase memory usage |
| Validation Latency | < 5ms P95 | Target for production workloads |
| Cache Size | < 100MB | Total memory for spec caching |
| Concurrent Validations | < 1000/sec | Per gateway instance |

## Security Considerations

### Best Practices

1. **Spec Security**: Ensure OpenAPI specs don't expose sensitive information
2. **Access Control**: Restrict access to spec files and ConfigMaps
3. **Validation Coverage**: Enable comprehensive validation for security-critical APIs
4. **Error Handling**: Avoid exposing internal details in validation errors

### Security Configuration

```yaml
# Secure OpenAPI validation configuration
openAPIValidation:
  enabled: true
  specFile: "/etc/gateway/secure/api-spec.yaml"
  failOnError: true
  validateRequestBody: true
  validateRequestParams: true
  validateRequestHeaders: true
  validateSecurity: true  # Enable security validation
```

### RBAC for ConfigMaps

In operator mode the **operator** (not the gateway) reads the ConfigMaps referenced by
`specConfigMapRef` / `descriptorConfigMapRef` / `schemaConfigMapRef` and inlines their
content before delivering configuration to the gateway. The operator therefore needs
`configmaps` `get`, `list`, and `watch`. This is already included in the operator's
generated ClusterRole (`config/rbac/role.yaml`) and the Helm chart CRDs:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: avapigw-operator-role
rules:
- apiGroups: [""]
  resources:
  - configmaps
  - endpoints
  - services
  verbs: ["get", "list", "watch"]
```

If you instead mount specs into the gateway directly (file mode, without the operator),
scope a namespaced `Role` to the specific ConfigMaps the gateway consumes:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: gateway-system
  name: gateway-configmap-reader
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]
  resourceNames: ["api-specs"]  # Restrict to specific ConfigMaps
```

## Migration Guide

### From Manual Validation to OpenAPI

1. **Extract OpenAPI Spec**: Generate spec from existing API code
2. **Configure Validation**: Start with log-only mode
3. **Monitor Metrics**: Check for validation errors
4. **Enable Enforcement**: Switch to fail-on-error mode
5. **Optimize Performance**: Tune validation settings

### Version Compatibility

| Gateway Version | OpenAPI Support | Features |
|----------------|-----------------|----------|
| v1.0.0+ | OpenAPI 3.0+ | Basic validation |
| v1.1.0+ | OpenAPI 3.0+ | ConfigMap support |
| v1.2.0+ | OpenAPI 3.0+ | gRPC/GraphQL validation |

## Related Documentation

- [Configuration Reference](configuration-reference.md) - Complete configuration options
- [Middleware Architecture](middleware-architecture.md) - Middleware chain details
- [Metrics](metrics.md) - Comprehensive metrics documentation
- [CRD Reference](crd-reference.md) - Kubernetes CRD specifications
- [Performance Testing](performance-testing.md) - Performance validation procedures