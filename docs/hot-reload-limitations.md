# Hot-Reload Limitations

## Overview

The AV API Gateway supports hot configuration reload through two distinct modes, each with different capabilities and limitations. Understanding these modes is crucial for proper deployment and configuration management.

### Two Hot-Reload Modes

1. **File-Based Config Mode**: Uses `fsnotify` file watcher to detect configuration file changes
2. **Operator/CRD Mode**: Receives configuration updates via gRPC stream from the Kubernetes operator

**Key Difference**: gRPC routes can be hot-reloaded in Operator/CRD mode but NOT in File-Based Config mode.

## Quick Reference

| Component | File-Based Mode | Operator/CRD Mode | Notes |
|---|---|---|---|
| HTTP routes | ✅ Reloaded | ✅ Reloaded | `router.LoadRoutes()` |
| HTTP backends | ✅ Reloaded | ✅ Reloaded | `backendRegistry.ReloadFromConfig()` |
| gRPC routes | ❌ Not reloaded | ✅ Reloaded | **Key difference between modes** |
| gRPC backends | ✅ Reloaded | ✅ Reloaded | `backendRegistry.ReloadFromConfig()` with copy-on-write |
| Rate limiter | ✅ Reloaded | ✅ Reloaded | `rateLimiter.UpdateConfig()` |
| Max sessions | ✅ Reloaded | ✅ Reloaded | `maxSessionsLimiter.UpdateConfig()` |
| Audit logger | ✅ Reloaded | ✅ Reloaded | `AtomicAuditLogger` atomic swap |
| HTTP middleware cache | ✅ Cleared | ✅ Cleared | `routeMiddlewareMgr.ClearCache()` |
| gRPC auth cache | ❌ Not cleared | ✅ Cleared | `gateway.ClearAllAuthCaches()` |
| CORS middleware | ❌ Restart required | ❌ Preserved from initial config | Static handler chain |
| Security headers | ❌ Restart required | ❌ Preserved from initial config | Static handler chain |
| Circuit breaker | ❌ Restart required | ❌ Preserved from initial config | sony/gobreaker limitation |
| Listener config (ports, TLS) | ❌ Restart required | ❌ Preserved from initial config | Bound at startup |
| Observability (tracing, metrics) | ❌ Restart required | ❌ Preserved from initial config | Initialized once |
| Global auth middleware | ❌ Restart required | ❌ Preserved from initial config | Static handler chain |
| Trusted proxies | ❌ Restart required | ❌ Preserved from initial config | `initClientIPExtractor()` once |

## File-Based Config Mode

**Trigger**: `fsnotify` file watcher detects config file change → 100ms debounce → `reloadComponents()` in `cmd/gateway/reload.go:181-287`

### What IS Reloaded

✅ **Gateway Configuration**
- Atomic pointer swap via `atomic.Pointer[config.GatewayConfig]` (reload.go:191)

✅ **HTTP Routes**
- Route definitions, path matching, HTTP methods, headers, query parameters
- Route-level timeouts, retry policies, traffic mirroring, fault injection
- Request/response header manipulation, URL rewriting, redirects
- Reloaded via `router.LoadRoutes()` (reload.go:226-235)

✅ **HTTP Backends**
- Backend host addresses, ports, weights, health checks
- Load balancing algorithms, backend-level timeouts
- Backend authentication settings (JWT, Basic Auth, mTLS)
- Reloaded via `backendRegistry.ReloadFromConfig()` with 30s timeout (reload.go:245-259)

✅ **gRPC Backends**
- Backend host addresses, ports, weights, health checks
- Load balancing algorithms, backend-level timeouts
- Backend authentication settings (JWT, Basic Auth, mTLS)
- Reloaded via `gateway.ReloadGRPCBackends()` with copy-on-write pattern (reload.go:301-313)

✅ **HTTP Route Middleware Cache**
- Cache cleared so next request rebuilds middleware chain (reload.go:239-242)
- Enables route-level auth/authz policy changes

✅ **Rate Limiter**
- Global, route-level, and backend-level rate limiting
- Thresholds, burst sizes, per-client configuration
- Updated via `rateLimiter.UpdateConfig()` (reload.go:214-217)

✅ **Max Sessions Limiter**
- Global, route-level, and backend-level max sessions
- Queue size and timeout settings
- Updated via `maxSessionsLimiter.UpdateConfig()` (reload.go:220-223)

✅ **Audit Logger**
- Logger configuration, output destinations, log format
- Audit event filtering, skip paths, redact fields
- Uses `AtomicAuditLogger` wrapper for lock-free hot-reload
- New logger atomically swapped in; old logger closed after swap (reload.go:330-370)
- Shared audit metrics instance preserved across reloads

### What is NOT Reloaded (Warning Logged)

❌ **gRPC Routes**
- Warning logged: "gRPC routes have changed but gRPC routes are NOT hot-reloaded in file-based mode; restart the gateway or use operator mode to apply gRPC route changes" (reload.go:324-328)

❌ **CORS Middleware**
- Warning logged: "CORS configuration has changed but CORS middleware is NOT hot-reloaded" (reload.go:266-269)

❌ **Security Headers Middleware**
- Warning logged: "security configuration has changed but security middleware is NOT hot-reloaded" (reload.go:273-276)

### What Requires Restart (Silently Ignored)

❌ **Circuit Breaker**
- Comment at reload.go:175: "Circuit breaker from sony/gobreaker does not support runtime reconfiguration"

❌ **HTTP/HTTPS Listener Configuration**
- Ports, addresses, TLS settings created once during `Start()` (gateway.go:349-376)

❌ **gRPC Listener Configuration**
- Ports, addresses, TLS, interceptors (same as HTTP listeners)

❌ **Observability Configuration**
- Tracer, metrics namespace initialized once (app.go:58-61)

❌ **Global Authentication/Authorization Middleware**
- Part of static handler chain built once (middleware.go:29-108)

❌ **Trusted Proxies**
- `initClientIPExtractor()` called once at startup

## Operator/CRD Mode

**Trigger**: Operator pushes CRD updates via gRPC stream → `ConfigHandler.HandleUpdate()` in `internal/gateway/operator/handler.go:103`

### What IS Reloaded

✅ **HTTP Routes**
- Applied via `ApplyRoutes()` (operator_mode.go:207-222)

✅ **HTTP Backends**
- Applied via `ApplyBackends()` (operator_mode.go:225-240)

✅ **gRPC Backends** ⭐ **New Feature**
- Applied via `ApplyGRPCBackends()` (operator_mode.go:269-289)
- Uses copy-on-write pattern for thread-safe hot-reload
- Stale connections to removed/changed backends are cleaned up

✅ **gRPC Routes** ⭐ **Key Advantage**
- Applied via `ApplyGRPCRoutes()` (operator_mode.go:244-263)
- Iterates all gRPC listeners, calls `listener.LoadRoutes(routes)` → `router.LoadRoutes()` (Clear + AddRoute under `sync.RWMutex`)

✅ **Rate Limiter**
- Via `ApplyFullConfig()` → `applyMergedComponents()` (operator_mode.go:353-355)

✅ **Max Sessions**
- Via `ApplyFullConfig()` → `applyMergedComponents()` (operator_mode.go:357-359)

✅ **Audit Logger** ⭐ **New Feature**
- Via `ApplyFullConfig()` → `applyMergedComponents()` → `reloadAuditLogger()` (operator_mode.go:369-372)
- Operator config merged via `mergeAuditConfig()` — operator audit config takes precedence when provided
- Uses `AtomicAuditLogger` atomic swap for lock-free hot-reload
- HTTP middleware and gRPC interceptors transparently use the new logger via the wrapper

✅ **HTTP Route Middleware Cache**
- Cleared via `CacheInvalidator` callback (operator_mode.go:77-79)

✅ **gRPC Auth Caches**
- Cleared via `CacheInvalidator` callback → `gateway.ClearAllAuthCaches()` → each listener's `ClearAuthCache()` → `proxy.ClearAuthCache()` → `director.ClearAuthCache()` (operator_mode.go:80-84)

### What is NOT Reloaded

❌ **CORS, Security Headers, Circuit Breaker, Listeners, Observability, Global Auth/Authz, Trusted Proxies**
- All preserved from initial config via `mergeOperatorConfig()` (operator_mode.go:282-311)

## Non-Reloadable Configuration (Both Modes)

The following configuration changes require a full gateway restart in both modes:

### ~~gRPC Backends~~ ✅ **Now Supported**
✅ **Hot-Reloadable as of Latest Release**
- gRPC backend configuration is now hot-reloadable in both file-based and operator modes
- Uses the same copy-on-write pattern as HTTP backends for thread-safe updates
- Stale connections to removed/changed backends are automatically cleaned up

**Technical Implementation**: gRPC backends are converted to the shared `Backend` format and reloaded via the `backend.Registry` infrastructure, enabling safe hot-reload without disrupting active connections.

### CORS Middleware
❌ **Always Requires Restart**
- Global CORS settings, allowed origins, methods, headers
- Route-level CORS configuration overrides

**Technical Reason**: CORS middleware is part of the static handler chain established during gateway initialization.

### Security Headers Middleware
❌ **Always Requires Restart**
- Global security headers configuration
- Route-level security headers overrides
- Custom security headers

**Technical Reason**: Security headers middleware is part of the core middleware chain that cannot be dynamically reconfigured.

### Circuit Breaker Configuration
❌ **Always Requires Restart**
- Circuit breaker thresholds, timeouts, failure ratios
- Circuit breaker state management settings

**Technical Reason**: Circuit breaker from sony/gobreaker does not support runtime reconfiguration and maintains internal state machines.

### Listener Configuration
❌ **Always Requires Restart**
- HTTP/HTTPS/gRPC listener ports and addresses
- TLS listener configuration and certificates
- Protocol-specific listener settings

**Technical Reason**: Network listeners are bound during startup and cannot be dynamically reconfigured without disrupting active connections.

### Observability Configuration
❌ **Always Requires Restart**
- Tracing configuration (Jaeger, OTLP endpoints)
- Metrics namespace and custom labels
- Logging configuration

**Technical Reason**: Observability components are initialized once during startup with global scope.

### Global Authentication/Authorization Middleware
❌ **Always Requires Restart**
- Global JWT authentication settings
- Global API key authentication
- Global OIDC configuration
- Global mTLS authentication settings

**Technical Reason**: Global auth middleware is part of the static handler chain. Note: Route-level auth policies ARE reloadable via middleware cache clearing.

### Trusted Proxies Configuration
❌ **Always Requires Restart**
- Trusted proxy IP ranges
- Client IP extraction settings

**Technical Reason**: Client IP extractor is initialized once at startup via `initClientIPExtractor()`.

## Technical Architecture

### Atomic Configuration Updates
- Gateway config uses `atomic.Pointer[config.GatewayConfig]` (gateway.go:27) for lock-free concurrent access
- Ensures consistent configuration state during updates

### Atomic Audit Logger
- `AtomicAuditLogger` wraps `audit.Logger` with `atomic.Pointer[Logger]` (audit/atomic.go)
- HTTP middleware and gRPC interceptors receive the wrapper at init time
- `Swap()` atomically replaces the inner logger; all subsequent calls use the new one
- Solves the stale-reference problem where closures captured the old logger
- Shared `*audit.Metrics` instance preserved across reloads to avoid Prometheus re-registration

### Change Detection
- SHA-256 hashing via `configSectionHash()` (reload.go:324-330) for O(n) change detection
- Only reloads components that have actually changed

### File Watcher Debounce
- 100ms debounce via `fsnotify` with proper timer drain logic (watcher.go:218-227)
- Prevents excessive reloads from rapid file changes

### gRPC Router Thread Safety
- `router.LoadRoutes()` uses `sync.RWMutex` for concurrent access protection
- **Known Issue**: Current implementation calls `Clear()` then `AddRoute()` in a loop, each acquiring/releasing the mutex independently
- This means concurrent `Match()` calls may briefly see a partial route table during reload

### Cache Invalidation in Operator Mode
- Every CRD update triggers cache invalidation for both HTTP middleware and gRPC auth caches
- Occurs even for HTTP-only changes (low overhead since it just replaces a map)

## Known Limitations

### Non-Atomic gRPC Route Reload Window
In operator mode, gRPC route reloads have a brief window where the route table is partially populated:
- `router.LoadRoutes()` calls `Clear()` then loops through `AddRoute()`
- Each operation acquires/releases the mutex independently
- Concurrent requests may see incomplete routing during this window

**Impact**: Minimal - window is typically microseconds, and failed route matches fall back to default behavior.

### Cache Invalidation Scope
In operator mode, all caches are invalidated on every CRD update:
- HTTP middleware cache cleared even for gRPC-only changes
- gRPC auth cache cleared even for HTTP-only changes

**Impact**: Low - cache rebuilding is fast and happens on-demand.

## Monitoring Hot-Reload

### Key Metrics

Monitor these metrics to track hot-reload performance:

```prometheus
# Reload success rate
rate(gateway_config_reload_total{result="success"}[5m]) / rate(gateway_config_reload_total[5m])

# Reload duration
histogram_quantile(0.95, rate(gateway_config_reload_duration_seconds_bucket[5m]))

# Configuration watcher status
gateway_config_watcher_running

# Component reload status
rate(gateway_config_reload_component_total[5m])

# Last successful reload timestamp
gateway_config_reload_last_success_timestamp
```

### Available Metrics

The gateway exposes these hot-reload metrics:

- `gateway_config_reload_total` with label `result` (values: "success", "error")
- `gateway_config_reload_duration_seconds` (histogram with buckets: .01, .05, .1, .25, .5, 1, 2.5, 5)
- `gateway_config_reload_last_success_timestamp` (gauge)
- `gateway_config_watcher_running` (gauge, 1=running, 0=stopped)
- `gateway_config_reload_component_total` with labels `component` and `result`
  - Components: "rate_limiter", "max_sessions", "routes", "backends", "audit", "grpc_routes", "grpc_backends"

### Grafana Dashboard Queries

```promql
# Reload success rate panel
sum(rate(gateway_config_reload_total{result="success"}[5m])) / sum(rate(gateway_config_reload_total[5m])) * 100

# Reload latency panel
histogram_quantile(0.50, rate(gateway_config_reload_duration_seconds_bucket[5m]))
histogram_quantile(0.95, rate(gateway_config_reload_duration_seconds_bucket[5m]))

# Component reload success rate
sum(rate(gateway_config_reload_component_total{result="success"}[5m])) by (component)
```

## Alerting Rules

```yaml
groups:
- name: avapigw.config-reload
  rules:
  - alert: ConfigReloadFailure
    expr: rate(gateway_config_reload_total{result="error"}[5m]) > 0
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "Configuration reload failed"
      description: "Gateway configuration reload has failed"

  - alert: ConfigReloadHighLatency
    expr: histogram_quantile(0.95, rate(gateway_config_reload_duration_seconds_bucket[5m])) > 5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Configuration reload taking too long"
      description: "Configuration reload latency is above 5 seconds"

  - alert: ConfigWatcherDown
    expr: gateway_config_watcher_running == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Configuration file watcher is not running"
      description: "The configuration file watcher has stopped"

  - alert: ComponentReloadFailure
    expr: rate(gateway_config_reload_component_total{result="error"}[5m]) > 0
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "Component reload failed"
      description: "Component {{ $labels.component }} reload has failed"
```

## Best Practices

### Planning Configuration Changes

1. **Identify Reload Mode**: Determine if you're using file-based or operator/CRD mode
2. **Categorize Changes**: Use the Quick Reference table to identify reloadable vs restart-required changes
3. **Batch Non-Reloadable Changes**: Group restart-required changes together to minimize disruption
4. **gRPC Route Strategy**: 
   - File-based mode: Plan gRPC route changes during maintenance windows
   - Operator mode: gRPC routes can be updated without restart

### Deployment Strategies

#### For Reloadable Changes (File-Based Mode)
```bash
# Update configuration file
kubectl apply -f updated-config.yaml

# Monitor reload success
kubectl logs -f deployment/avapigw-gateway | grep "config reload"
```

#### For Reloadable Changes (Operator Mode)
```bash
# Update CRD resources
kubectl apply -f updated-routes.yaml
kubectl apply -f updated-backends.yaml

# Monitor via operator logs
kubectl logs -f deployment/avapigw-operator
```

#### For Non-Reloadable Changes (Both Modes)
```bash
# Use rolling deployment
kubectl set image deployment/avapigw-gateway gateway=avapigw:new-version
kubectl rollout status deployment/avapigw-gateway

# Or restart pods with updated config
kubectl rollout restart deployment/avapigw-gateway
```

### Configuration Validation

Always validate configuration before applying:

```bash
# File-based mode validation
./gateway --config-file=new-config.yaml --validate-only

# Check YAML syntax
yamllint config.yaml

# Operator mode validation
kubectl apply --dry-run=server -f new-routes.yaml
```

## Troubleshooting

### Common Issues

#### 1. gRPC Routes Not Reloading (File-Based Mode)

**Symptoms:**
```
WARN gRPC routes have changed but gRPC routes are NOT hot-reloaded in file-based mode
```

**Solutions:**
- Expected behavior in file-based mode (gRPC routes only reload in operator mode)
- Switch to operator/CRD mode for gRPC route hot-reload
- Use rolling deployment for gRPC route changes
- Note: gRPC backends ARE hot-reloaded in both modes

#### 2. Partial Configuration Application

**Symptoms:**
```
WARN CORS configuration has changed but CORS middleware is NOT hot-reloaded
WARN security configuration has changed but security middleware is NOT hot-reloaded
```

**Solutions:**
- Expected behavior for non-reloadable components
- Plan restart for CORS and security header changes
- Check component reload metrics for specific failures

#### 3. High Reload Latency

**Symptoms:**
- `gateway_config_reload_duration_seconds` > 5 seconds
- Temporary request failures during reload

**Solutions:**
- Check backend health check timeouts (30s timeout for backend reload)
- Monitor system resources during reload
- Consider reducing configuration complexity

#### 4. Configuration Watcher Stopped

**Symptoms:**
```
gateway_config_watcher_running 0
```

**Solutions:**
- Check file system permissions on config file
- Verify configuration file path exists
- Review gateway logs for watcher errors
- Restart gateway if watcher cannot recover

#### 5. gRPC Route Table Inconsistency

**Symptoms:**
- Intermittent gRPC routing failures during operator updates
- Brief 404/UNIMPLEMENTED errors

**Solutions:**
- Expected during the brief reload window
- Monitor error rates - should be minimal
- Consider request retry policies for critical gRPC calls

### Debugging Commands

```bash
# Check current configuration metrics
curl http://localhost:9090/metrics | grep gateway_config_reload

# Monitor reload events (file-based mode)
kubectl logs -f deployment/avapigw-gateway | grep -E "(reload|config)"

# Monitor CRD updates (operator mode)
kubectl logs -f deployment/avapigw-operator | grep -E "(update|reload)"

# Check configuration validation
./gateway --config-file=config.yaml --validate-only

# Test CRD changes
kubectl apply --dry-run=server -f new-routes.yaml
```

### Log Analysis

Look for these log patterns during hot-reload:

**File-Based Mode:**
```
INFO  Configuration file changed, reloading...
INFO  Configuration validation successful
INFO  Configuration reload completed in 45ms
ERROR Configuration reload failed: validation error
WARN  gRPC routes have changed but gRPC routes are NOT hot-reloaded in file-based mode
WARN  CORS configuration has changed but CORS middleware is NOT hot-reloaded
```

**Operator Mode:**
```
INFO  Received CRD update: routes
INFO  Applied 5 HTTP routes successfully
INFO  Applied 3 gRPC routes successfully
INFO  Applied 2 gRPC backends successfully
INFO  Cache invalidation completed
```

## Related Documentation

- **[Configuration Reference](configuration-reference.md)** - Complete configuration options
- **[Operator](operator.md)** - Kubernetes operator documentation
- **[Metrics Reference](features/metrics.md)** - Hot-reload metrics documentation
- **[Performance Testing](performance-testing.md)** - Hot-reload performance characteristics
- **[Troubleshooting Guide](troubleshooting-vault-pki.md)** - General troubleshooting procedures