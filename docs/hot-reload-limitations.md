# Hot-Reload Limitations

## Overview

The AV API Gateway supports hot configuration reload for most configuration changes without requiring a service restart. However, certain configuration changes require a full restart due to architectural constraints and initialization requirements.

This document provides a comprehensive reference for what can and cannot be hot-reloaded, along with the technical reasons and recommended approaches for handling non-reloadable changes.

## Table of Contents

- [Reloadable Configuration](#reloadable-configuration)
- [Non-Reloadable Configuration](#non-reloadable-configuration)
- [Technical Background](#technical-background)
- [Best Practices](#best-practices)
- [Monitoring Hot-Reload](#monitoring-hot-reload)
- [Troubleshooting](#troubleshooting)

## Reloadable Configuration

The following configuration changes can be applied without restarting the gateway:

### HTTP Routes and Routing
✅ **Fully Reloadable**
- Route definitions (match conditions, destinations, weights)
- Path matching rules (exact, prefix, regex)
- HTTP method matching
- Header and query parameter matching
- Route-level timeouts and retry policies
- Traffic mirroring and fault injection
- Request/response header manipulation
- URL rewriting and redirects
- Direct responses

### Backend Configuration
✅ **Fully Reloadable**
- Backend host addresses and ports
- Backend weights for load balancing
- Health check configuration
- Load balancing algorithms
- Backend-level timeouts
- Backend authentication settings (JWT, Basic Auth, mTLS)
- Backend TLS configuration

### Rate Limiting
✅ **Fully Reloadable**
- Global rate limiting settings
- Route-level rate limiting
- Backend-level rate limiting
- Rate limit thresholds and burst sizes
- Per-client rate limiting configuration

### Max Sessions
✅ **Fully Reloadable**
- Global max sessions configuration
- Route-level max sessions
- Backend-level max sessions
- Queue size and timeout settings

### Audit Logging
✅ **Fully Reloadable**
- Audit logger configuration
- Log output destinations
- Log format and fields
- Audit event filtering

### Authentication and Authorization
✅ **Fully Reloadable**
- JWT authentication settings
- API key authentication
- OIDC configuration
- mTLS authentication settings
- RBAC policies and rules
- ABAC policies and expressions
- External authorization (OPA) settings

### Data Transformation
✅ **Fully Reloadable**
- Response field filtering and mapping
- Request transformation templates
- Field grouping and flattening
- Array operations
- Response merging strategies

### Caching
✅ **Fully Reloadable**
- Cache TTL settings
- Cache key generation rules
- Redis cache configuration
- Cache invalidation policies

### TLS and Security
✅ **Fully Reloadable**
- Route-level TLS certificates
- SNI certificate management
- Certificate rotation from Vault PKI
- Security headers configuration

## Non-Reloadable Configuration

The following configuration changes require a full gateway restart:

### gRPC Configuration
❌ **Requires Restart**
- gRPC listener configuration
- gRPC routes and backends
- gRPC-specific settings (max message size, keepalive, etc.)
- gRPC TLS configuration
- gRPC reflection and health check services

**Technical Reason:** gRPC server initialization requires specific setup during startup, and the gRPC routing infrastructure is initialized once during gateway startup.

**Workaround:** Use rolling deployments in Kubernetes to update gRPC configuration without service interruption.

### CORS Configuration
❌ **Requires Restart**
- Global CORS settings
- Route-level CORS configuration
- CORS allowed origins, methods, and headers

**Technical Reason:** CORS middleware is initialized during startup and cannot be dynamically reconfigured due to the middleware chain architecture.

**Workaround:** Plan CORS changes during maintenance windows or use rolling deployments.

### Security Headers Middleware
❌ **Requires Restart**
- Global security headers configuration
- Route-level security headers overrides
- Custom security headers

**Technical Reason:** Security headers middleware is part of the core middleware chain that is established during gateway initialization.

**Workaround:** Use rolling deployments to apply security header changes.

### Listener Configuration
❌ **Requires Restart**
- HTTP/HTTPS listener ports and addresses
- TLS listener configuration
- Listener-level TLS settings
- Protocol-specific listener settings

**Technical Reason:** Network listeners are bound during startup and cannot be dynamically reconfigured without disrupting active connections.

**Workaround:** Use load balancer configuration changes or rolling deployments.

### Circuit Breaker Configuration
❌ **Requires Restart**
- Circuit breaker thresholds and timeouts
- Circuit breaker state management settings

**Technical Reason:** Circuit breaker state machines are initialized during startup and maintain internal state that cannot be safely reset during runtime.

**Workaround:** Monitor circuit breaker metrics and plan changes during low-traffic periods.

## Technical Background

### Hot-Reload Architecture

The gateway implements hot-reload using a configuration watcher and atomic configuration updates:

1. **File Watcher**: Monitors configuration file changes using filesystem events
2. **Hash-Based Detection**: Uses SHA-256 hashing to detect actual configuration changes (DEV-002)
3. **Validation**: Validates new configuration before applying changes
4. **Atomic Updates**: Applies configuration changes atomically to prevent partial states
5. **Metrics Registry**: Uses custom metrics registry for reload operations (DEV-001, DEV-009)

### Configuration Components

The gateway configuration is divided into reloadable and non-reloadable components:

#### Reloadable Components
- HTTP routing engine
- Backend pool management
- Middleware configuration (rate limiting, max sessions, auth)
- Cache configuration
- Audit logging

#### Non-Reloadable Components
- gRPC server and routing
- Network listeners
- Core middleware chain (CORS, security headers)
- Circuit breaker state machines

### Memory Management

Hot-reload includes proper resource cleanup to prevent memory leaks:
- Timer cleanup in configuration watcher
- Goroutine lifecycle management
- Connection pool updates
- Cache invalidation

## Best Practices

### Planning Configuration Changes

1. **Categorize Changes**: Identify whether changes are reloadable or require restart
2. **Batch Non-Reloadable Changes**: Group restart-required changes together
3. **Use Rolling Deployments**: For non-reloadable changes in production
4. **Test in Staging**: Validate hot-reload behavior in non-production environments

### Monitoring Configuration Updates

1. **Watch Reload Metrics**: Monitor `gateway_config_reload_total` and `gateway_config_reload_duration_seconds`
2. **Set Up Alerts**: Alert on reload failures or excessive reload times
3. **Log Analysis**: Review logs for reload validation errors

### Deployment Strategies

#### For Reloadable Changes
```bash
# Simply update the configuration file
kubectl apply -f updated-config.yaml

# Monitor reload success
kubectl logs -f deployment/avapigw-gateway | grep "config reload"
```

#### For Non-Reloadable Changes
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
# Dry-run validation
./gateway --config-file=new-config.yaml --validate-only

# Check configuration syntax
yamllint config.yaml
```

## Monitoring Hot-Reload

### Key Metrics

Monitor these metrics to track hot-reload performance:

```prometheus
# Reload success rate
rate(gateway_config_reload_total{status="success"}[5m]) / rate(gateway_config_reload_total[5m])

# Reload duration
histogram_quantile(0.95, rate(gateway_config_reload_duration_seconds_bucket[5m]))

# Reload errors by type
rate(gateway_config_reload_errors_total[5m])

# Configuration watcher status
gateway_config_watcher_running

# Component reload status
rate(gateway_config_reload_component_total[5m])
```

### Grafana Dashboard Queries

```promql
# Reload success rate panel
sum(rate(gateway_config_reload_total{status="success"}[5m])) / sum(rate(gateway_config_reload_total[5m])) * 100

# Reload latency panel
histogram_quantile(0.50, rate(gateway_config_reload_duration_seconds_bucket[5m]))
histogram_quantile(0.95, rate(gateway_config_reload_duration_seconds_bucket[5m]))

# Reload error rate panel
sum(rate(gateway_config_reload_errors_total[5m])) by (error_type)
```

### Alerting Rules

```yaml
groups:
- name: avapigw.config-reload
  rules:
  - alert: ConfigReloadFailure
    expr: rate(gateway_config_reload_total{status="error"}[5m]) > 0
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
```

## Troubleshooting

### Common Issues

#### 1. Reload Validation Failures

**Symptoms:**
```
Error: configuration validation failed: invalid route configuration
```

**Solutions:**
- Check YAML syntax and structure
- Validate referenced backends exist
- Ensure route matching rules are valid
- Review authentication/authorization settings

#### 2. Partial Configuration Application

**Symptoms:**
```
Warning: some configuration changes could not be applied
```

**Solutions:**
- Check for non-reloadable configuration changes
- Review component-specific reload metrics
- Consider full restart for non-reloadable changes

#### 3. High Reload Latency

**Symptoms:**
- Reload duration > 5 seconds
- Temporary request failures during reload

**Solutions:**
- Optimize configuration size and complexity
- Check for resource contention
- Monitor system resources during reload

#### 4. Configuration Watcher Stopped

**Symptoms:**
```
gateway_config_watcher_running 0
```

**Solutions:**
- Check file system permissions
- Verify configuration file path
- Review gateway logs for watcher errors
- Restart gateway if watcher cannot recover

### Debugging Commands

```bash
# Check current configuration hash
curl http://localhost:9090/metrics | grep gateway_config_hash

# Monitor reload events
kubectl logs -f deployment/avapigw-gateway | grep -E "(reload|config)"

# Check configuration validation
./gateway --config-file=config.yaml --validate-only

# Test configuration changes
kubectl apply --dry-run=server -f new-config.yaml
```

### Log Analysis

Look for these log patterns during hot-reload:

```
INFO  Configuration file changed, reloading...
INFO  Configuration validation successful
INFO  Configuration reload completed in 45ms
ERROR Configuration reload failed: validation error
WARN  Some components require restart: [cors, security-headers]
```

## Related Documentation

- **[Configuration Reference](configuration-reference.md)** - Complete configuration options
- **[Metrics Reference](features/metrics.md)** - Hot-reload metrics documentation
- **[Performance Testing](performance-testing.md)** - Hot-reload performance characteristics
- **[Troubleshooting Guide](troubleshooting-vault-pki.md)** - General troubleshooting procedures