# Metrics and Dashboards

## Overview

The AV API Gateway provides comprehensive observability through Prometheus metrics and Grafana dashboards. This document covers all available metrics, dashboard usage, and monitoring best practices.

## Quick Links

- **[Complete Metrics Reference](features/metrics.md)** - Detailed documentation of all 120+ metrics
- **[Performance Testing](performance-testing.md)** - Performance metrics and testing procedures
- **[Operator Documentation](operator.md)** - Operator-specific metrics and monitoring

## Metrics Summary

The gateway exposes **130+ Prometheus metrics** across all components:

### Gateway Metrics (70+ metrics)
- **Core Gateway**: Request processing, build info, uptime
- **Middleware**: Rate limiting, circuit breaker, timeouts, retries, CORS, authentication, cache, transform, encoding
- **Cache**: Memory and Redis cache performance with per-route isolation
- **Authentication**: JWT, API Key, OIDC, mTLS validation (global middleware chain)
- **Authorization**: RBAC, ABAC, external authorization
- **TLS**: Handshakes, certificate lifecycle
- **Vault**: API requests, authentication, secret retrieval
- **Backend Auth**: Backend authentication operations
- **Proxy**: Backend communication, errors, duration
- **WebSocket**: Connections, messages, errors
- **gRPC**: Requests, streaming, method-level tracking
- **Config Reload**: Hot reload operations with fixed timestamp metrics
- **Health Check**: Backend health monitoring
- **Transform**: Request/response transformation metrics
- **Encoding**: Content negotiation and encoding metrics

### Operator Metrics (60+ metrics)
- **Controller**: Reconciliation performance and errors
- **Webhook**: Admission webhook validation
- **Certificate**: Certificate management and rotation
- **gRPC**: ConfigurationService communication
- **CA Injection**: Webhook CA bundle management

## Dashboard Overview

The gateway includes **4 comprehensive Grafana dashboards**:

### 1. Gateway Dashboard (`gateway-dashboard.json`)
- **140+ panels** covering all gateway metrics
- **Recent Updates**: 47 new panels added in latest refactoring
- **Coverage**: Authentication, gRPC, config reload, cache, WebSocket, TLS, backend health, transform, encoding
- **Fixed Issues**: Config reload timestamp query corrected for Grafana compatibility

### 2. Gateway Operator Dashboard (`gateway-operator-dashboard.json`)
- **50+ panels** for operator monitoring
- **Recent Updates**: 7 new panels added
- **Coverage**: gRPC ConfigurationService, certificate management, webhook validation, CA injection

### 3. Telemetry Dashboard (`telemetry-dashboard.json`)
- **10+ panels** focused on OpenTelemetry metrics
- **Coverage**: OTEL collector performance, trace processing

### 4. Spans Dashboard (`spans-dashboard.json`)
- **5+ panels** for distributed tracing
- **Coverage**: Trace analysis, span metrics

## Key Metrics Examples

### Request Metrics
```prometheus
# Request rate by route
rate(gateway_requests_total[5m])

# Average request duration
rate(gateway_request_duration_seconds_sum[5m]) / rate(gateway_request_duration_seconds_count[5m])

# Error rate
rate(gateway_requests_total{status=~"5.."}[5m]) / rate(gateway_requests_total[5m])
```

### Cache Performance
```prometheus
# Cache hit ratio
rate(gateway_cache_hits_total[5m]) / (rate(gateway_cache_hits_total[5m]) + rate(gateway_cache_misses_total[5m]))

# Cache operation duration
histogram_quantile(0.95, rate(gateway_cache_operation_duration_seconds_bucket[5m]))
```

### Authentication Metrics
```prometheus
# Authentication success rate
sum(rate(gateway_auth_requests_total{status="success"}[5m])) / sum(rate(gateway_auth_requests_total[5m])) * 100

# JWT validation rate
rate(gateway_auth_jwt_verifications_total[5m])
```

### Operator Metrics
```prometheus
# Reconciliation rate
rate(avapigw_operator_reconcile_total[5m])

# Configuration push success rate
sum(rate(avapigw_operator_config_push_total{status="success"}[5m])) / sum(rate(avapigw_operator_config_push_total[5m])) * 100
```

## Dashboard Usage Guide

### Accessing Dashboards

1. **Import to Grafana**:
   ```bash
   # Import all dashboards
   kubectl apply -f monitoring/grafana/
   ```

2. **Port Forward to Grafana**:
   ```bash
   kubectl port-forward -n monitoring svc/grafana 3000:3000
   ```

3. **Access Dashboard URLs**:
   - Gateway: `http://localhost:3000/d/avapigw-gateway/avapigw-gateway-dashboard`
   - Operator: `http://localhost:3000/d/avapigw-operator/avapigw-operator-dashboard`
   - Telemetry: `http://localhost:3000/d/avapigw-telemetry/avapigw-telemetry-dashboard`
   - Spans: `http://localhost:3000/d/avapigw-spans/avapigw-spans-dashboard`

### Dashboard Features

- **Multi-Instance Support**: Metrics aggregated across replicas
- **Time Range Filtering**: Configurable time ranges for analysis
- **Alert Integration**: Visual indicators for alert conditions
- **Drill-Down Capability**: Links to detailed views and logs
- **Performance Baselines**: Historical performance comparison

## Alerting Rules

### Critical Alerts
```yaml
groups:
- name: avapigw.critical
  rules:
  - alert: GatewayDown
    expr: up{job="avapigw"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Gateway is down"

  - alert: HighErrorRate
    expr: rate(gateway_requests_total{status=~"5.."}[5m]) / rate(gateway_requests_total[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"

  - alert: CircuitBreakerOpen
    expr: gateway_circuit_breaker_state == 2
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Circuit breaker is open"
```

### Warning Alerts
```yaml
- name: avapigw.warning
  rules:
  - alert: HighLatency
    expr: histogram_quantile(0.95, rate(gateway_request_duration_seconds_bucket[5m])) > 1
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High request latency detected"

  - alert: LowCacheHitRatio
    expr: rate(gateway_cache_hits_total[5m]) / (rate(gateway_cache_hits_total[5m]) + rate(gateway_cache_misses_total[5m])) < 0.8
    for: 15m
    labels:
      severity: warning
    annotations:
      summary: "Low cache hit ratio"

  - alert: CertificateExpiringSoon
    expr: gateway_tls_certificate_expiry_seconds < 7 * 24 * 3600
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: "TLS certificate expiring soon"
```

## Monitoring Best Practices

### 1. Metric Collection
- **Scrape Interval**: 30s for production, 15s for development
- **Retention**: 15 days for high-resolution, 1 year for downsampled
- **Cardinality Control**: Use bounded labels (route names, not user IDs)

### 2. Dashboard Organization
- **Gateway Dashboard**: Focus on request processing and performance
- **Operator Dashboard**: Monitor CRD reconciliation and configuration
- **Telemetry Dashboard**: Track observability infrastructure health
- **Spans Dashboard**: Analyze distributed tracing patterns

### 3. Alerting Strategy
- **Critical Alerts**: Service down, high error rates, circuit breakers
- **Warning Alerts**: High latency, low cache hit ratios, certificate expiry
- **Info Alerts**: Configuration changes, scaling events

### 4. Performance Monitoring
- **SLIs**: Request success rate, latency percentiles, availability
- **SLOs**: 99.9% availability, P95 latency < 100ms, error rate < 0.1%
- **Error Budgets**: Track SLO compliance and error budget consumption

## Troubleshooting

### Common Issues

#### 1. Missing Metrics
```bash
# Check if metrics endpoint is accessible
curl http://localhost:9090/metrics

# Verify Prometheus scraping
kubectl logs -n monitoring prometheus-server-0 | grep avapigw

# Check ServiceMonitor configuration
kubectl get servicemonitor -n avapigw
```

#### 2. Dashboard Not Loading
```bash
# Verify Grafana data source
kubectl port-forward -n monitoring svc/grafana 3000:3000
# Check data source configuration in Grafana UI

# Verify dashboard import
kubectl get configmap -n monitoring | grep dashboard
```

#### 3. High Cardinality Metrics
```bash
# Check metric cardinality
curl http://localhost:9090/metrics | grep gateway_requests_total | wc -l

# Review label usage
curl http://localhost:9090/metrics | grep gateway_requests_total | head -10
```

### Debugging Commands

```bash
# Check all gateway metrics
curl http://localhost:9090/metrics | grep -E "^gateway_"

# Check operator metrics
curl http://localhost:9090/metrics | grep -E "^avapigw_operator_"

# Monitor specific metric families
watch 'curl -s http://localhost:9090/metrics | grep gateway_requests_total'

# Check Prometheus targets
curl http://prometheus:9090/api/v1/targets
```

## Performance Impact

### Metrics Collection Overhead
- **CPU Impact**: < 1% additional CPU usage
- **Memory Impact**: ~10MB for metric storage
- **Network Impact**: ~1KB/s per scrape interval

### Dashboard Rendering
- **Query Performance**: Optimized queries with appropriate time ranges
- **Refresh Rates**: 30s for real-time, 5m for historical analysis
- **Panel Limits**: Reasonable data point limits to prevent browser overload

## Middleware Architecture Updates

### Recent Metrics Fixes (Latest Release)

Four critical metrics issues were resolved to improve observability:

#### 1. Config Reload Timestamp Fix
- **Issue**: Grafana dashboard query incompatibility with `SetToCurrentTime()` seconds vs milliseconds
- **Solution**: Updated PromQL query to multiply by 1000 for millisecond conversion
- **Impact**: Fixed config reload timestamp visualization in Grafana dashboards

#### 2. Authentication Metrics Integration
- **Issue**: Auth middleware not wired into global HTTP middleware chain
- **Solution**: Created `internal/auth/config_converter.go` for config type conversion
- **Impact**: Auth middleware now applied when `GatewaySpec.Authentication` is enabled
- **Metrics**: Authentication success/failure rates now properly tracked

#### 3. Cache Metrics Implementation
- **Issue**: Cache middleware not integrated with per-route middleware chain
- **Solution**: 
  - Created `internal/middleware/cache.go` for HTTP cache middleware
  - Created `internal/gateway/cache_factory.go` for per-route cache management
  - Integrated via `RouteMiddlewareManager` with thread-safe lazy creation
- **Features**: 10MB body limit, GET-only caching, Cache-Control header support
- **Metrics**: Cache hits, misses, evictions, size, and duration tracking

#### 4. Transform/Encoding Metrics Implementation
- **Issue**: Transform and encoding operations not instrumented
- **Solution**:
  - Created `internal/middleware/transform.go` for request/response transformation
  - Created `internal/middleware/encoding.go` for content negotiation
  - Integrated into per-route middleware chain
- **Features**: 10MB body limit for transforms, content type negotiation
- **Metrics**: Transform operations and encoding negotiation tracking

### Middleware Chain Architecture

The gateway now implements a two-tier middleware architecture:

#### Global Middleware Chain (cmd/gateway/middleware.go)
```
Recovery → RequestID → Logging → Tracing → Audit → Metrics → 
CORS → MaxSessions → CircuitBreaker → RateLimit → Auth → [proxy]
```

#### Per-Route Middleware Chain (internal/gateway/route_middleware.go)
```
Security Headers → CORS → Body Limit → Headers → Cache → 
Transform → Encoding → [proxy to backend]
```

### RouteMiddlewareApplier Interface

To avoid import cycles, the proxy uses the `RouteMiddlewareApplier` interface:

```go
type RouteMiddlewareApplier interface {
    GetMiddleware(route *config.Route) []func(http.Handler) http.Handler
    ApplyMiddleware(handler http.Handler, route *config.Route) http.Handler
}
```

This pattern allows:
- **Decoupled Architecture**: Proxy package independent of gateway package
- **Per-Route Middleware**: Cache, transform, encoding applied per route
- **Thread-Safe Caching**: Middleware chains cached with double-check locking
- **Lazy Initialization**: Cache instances created on-demand per route

## Related Documentation

- **[Complete Metrics Reference](features/metrics.md)** - Detailed metrics documentation
- **[Performance Testing](performance-testing.md)** - Performance metrics and benchmarks
- **[Operator Documentation](operator.md)** - Operator monitoring and metrics
- **[Configuration Reference](configuration-reference.md)** - Observability configuration
- **[Troubleshooting Guide](troubleshooting-vault-pki.md)** - General troubleshooting