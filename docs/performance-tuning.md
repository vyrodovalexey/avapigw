# Performance Tuning Guide

## Overview

This guide provides comprehensive recommendations for optimizing the AV API Gateway performance based on extensive testing across multiple deployment scenarios. The recommendations are derived from real performance test results and production deployments.

## Table of Contents

- [Performance Baseline](#performance-baseline)
- [Resource Limits and Requests](#resource-limits-and-requests)
- [Connection Pool Tuning](#connection-pool-tuning)
- [Rate Limiter Configuration](#rate-limiter-configuration)
- [Circuit Breaker Tuning](#circuit-breaker-tuning)
- [Caching Best Practices](#caching-best-practices)
- [TLS Performance Optimization](#tls-performance-optimization)
- [gRPC Performance Tuning](#grpc-performance-tuning)
- [Monitoring and Observability](#monitoring-and-observability)
- [Deployment-Specific Tuning](#deployment-specific-tuning)

## Performance Baseline

Based on comprehensive performance testing in Kubernetes operator mode with full TLS and authentication features:

### K8s Operator Mode Performance (Production Configuration)
- **HTTPS with TLS**: 93 RPS sustained, 3.36ms P50 latency, 8.2ms P95 latency
- **gRPC with TLS**: 1933 RPS sustained, 5.02ms P50 latency, 12.1ms P95 latency  
- **WebSocket**: 100% connection success rate, persistent connections
- **JWT Authentication**: 248 RPS sustained, 4.1ms P50 latency, 9.8ms P95 latency

### Performance Impact Analysis
- **TLS Overhead**: ~25% throughput reduction for HTTPS, ~20% for gRPC TLS
- **Authentication Overhead**: ~10% latency increase for JWT validation
- **mTLS Communication**: < 5ms additional latency for operator-gateway communication
- **Redis Sentinel Cache**: Significant performance improvement for cacheable content

### Key Observations
- gRPC TLS performance significantly higher than HTTPS TLS
- Authentication adds minimal overhead when properly configured
- Redis Sentinel caching provides excellent hit ratios
- mTLS operator communication has negligible performance impact

## Resource Limits and Requests

### Recommended Resource Configuration

#### Gateway Container
```yaml
resources:
  requests:
    cpu: "500m"                         # 0.5 CPU cores
    memory: "256Mi"                     # 256MB memory
  limits:
    cpu: "2000m"                        # 2 CPU cores
    memory: "1Gi"                       # 1GB memory
```

#### Operator Container (when enabled)
```yaml
resources:
  requests:
    cpu: "100m"                         # 0.1 CPU cores
    memory: "128Mi"                     # 128MB memory
  limits:
    cpu: "500m"                         # 0.5 CPU cores
    memory: "256Mi"                     # 256MB memory
```

### Scaling Guidelines

#### Horizontal Scaling
- **Target CPU Utilization**: 70%
- **Target Memory Utilization**: 80%
- **Min Replicas**: 2 (for high availability)
- **Max Replicas**: 10 (adjust based on traffic patterns)

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

#### Vertical Scaling Indicators
- CPU usage consistently > 80%
- Memory usage > 85%
- Request latency P95 > 100ms
- High GC pressure (Go runtime metrics)

### Resource Monitoring

```prometheus
# CPU utilization
rate(container_cpu_usage_seconds_total{container="gateway"}[5m]) * 100

# Memory utilization  
container_memory_working_set_bytes{container="gateway"} / container_spec_memory_limit_bytes{container="gateway"} * 100

# Request rate per replica
rate(gateway_requests_total[5m]) / on() group_left() kube_deployment_status_replicas{deployment="avapigw-gateway"}
```

## Connection Pool Tuning

### HTTP Connection Pool Settings

```yaml
spec:
  backends:
    - name: high-traffic-backend
      connection:
        maxIdleConns: 100               # Total max idle connections
        maxIdleConnsPerHost: 20         # Max idle per backend host
        idleConnTimeout: "90s"          # Idle connection timeout
        dialTimeout: "10s"              # Connection establishment timeout
        keepAlive: "30s"                # TCP keep-alive duration
        disableKeepAlives: false        # Enable connection reuse
        maxConnsPerHost: 50             # Max connections per host
        responseHeaderTimeout: "30s"    # Response header timeout
        expectContinueTimeout: "1s"     # Expect: 100-continue timeout
```

### Connection Pool Sizing Guidelines

#### Low Traffic (< 100 RPS)
```yaml
connection:
  maxIdleConns: 50
  maxIdleConnsPerHost: 10
  maxConnsPerHost: 25
```

#### Medium Traffic (100-1000 RPS)
```yaml
connection:
  maxIdleConns: 100
  maxIdleConnsPerHost: 20
  maxConnsPerHost: 50
```

#### High Traffic (> 1000 RPS)
```yaml
connection:
  maxIdleConns: 200
  maxIdleConnsPerHost: 50
  maxConnsPerHost: 100
```

### Connection Pool Monitoring

```prometheus
# Connection pool utilization
gateway_backend_connections_active / gateway_backend_connections_max * 100

# Connection establishment rate
rate(gateway_backend_connections_created_total[5m])

# Connection errors
rate(gateway_backend_connection_errors_total[5m])
```

## Rate Limiter Configuration

### Token Bucket Algorithm Tuning

The gateway uses a token bucket algorithm for rate limiting. Proper configuration is crucial for performance:

#### Global Rate Limiting
```yaml
spec:
  rateLimit:
    enabled: true
    requestsPerSecond: 1000             # Base rate
    burst: 2000                         # Burst capacity (2x base rate)
    perClient: true                     # Enable per-client limiting
    skipSuccessfulRequests: false       # Count all requests
    skipFailedRequests: false           # Count failed requests
```

#### Route-Level Rate Limiting
```yaml
spec:
  routes:
    - name: api-route
      rateLimit:
        enabled: true
        requestsPerSecond: 100          # Lower limit for specific route
        burst: 200                      # 2x burst capacity
        perClient: true
```

#### Backend-Level Rate Limiting
```yaml
spec:
  backends:
    - name: protected-backend
      rateLimit:
        enabled: true
        requestsPerSecond: 50           # Protect backend capacity
        burst: 100
```

### Rate Limiting Best Practices

1. **Burst Sizing**: Set burst to 2-3x the base rate for handling traffic spikes
2. **Per-Client Limiting**: Enable for public APIs to prevent abuse
3. **Layered Limiting**: Use global, route, and backend limits together
4. **Monitoring**: Track rate limit hits and rejections

### Rate Limiting Performance Impact

Based on performance testing with various rate limiting configurations:

- **CPU Overhead**: ~2% additional CPU usage
- **Memory Overhead**: ~5MB per 10,000 unique clients (with per-client limiting)
- **Latency Impact**: < 1ms additional latency
- **Throughput Impact**: Minimal when limits are not exceeded

**Tested Configurations:**
- **50 RPS with burst 100**: Excellent performance for API protection
- **10 RPS with burst 20**: Effective for API key rate limiting
- **20 RPS with burst 40**: Good balance for session-limited endpoints

**Performance Recommendations:**
- Use per-client limiting for public APIs
- Set burst to 2x base rate for traffic spikes
- Monitor rate limit hit rates to optimize thresholds

## Max Sessions Performance

### Max Sessions Configuration

Max sessions provide connection and request limiting with queuing support:

```yaml
spec:
  routes:
    - name: limited-endpoint
      maxSessions:
        enabled: true
        maxConcurrent: 100              # Maximum concurrent sessions
        queueSize: 50                   # Queue size for waiting requests
        queueTimeout: 5s                # Maximum wait time in queue
```

### Performance Impact Analysis

Based on testing with WebSocket and HTTP endpoints:

**WebSocket Max Sessions:**
- **50 concurrent connections**: 100% success rate
- **Queue size 25**: Effective overflow handling
- **Queue timeout 5s**: Prevents indefinite waiting
- **Memory overhead**: ~1MB per 1000 concurrent sessions

**HTTP Max Sessions:**
- **100 concurrent requests**: Smooth request handling
- **Queue size 50**: Good balance for burst traffic
- **Latency impact**: < 2ms additional latency when not queued
- **Queue latency**: 1-5s when queued (configurable)

### Max Sessions Best Practices

1. **Size Appropriately**: Set maxConcurrent based on backend capacity
2. **Queue Sizing**: Set queue to 25-50% of maxConcurrent
3. **Timeout Configuration**: Use 5-10s queue timeout for user-facing APIs
4. **Monitoring**: Track queue depth and timeout rates

## Circuit Breaker Tuning

### Circuit Breaker Configuration

```yaml
spec:
  backends:
    - name: unreliable-backend
      circuitBreaker:
        enabled: true
        threshold: 5                    # Failure threshold
        timeout: "30s"                  # Open state duration
        halfOpenRequests: 3             # Requests in half-open state
        successThreshold: 2             # Successes needed to close
        failureTypes:                   # What constitutes a failure
          - "5xx"
          - "timeout"
          - "connection_error"
```

### Circuit Breaker Tuning Guidelines

#### Conservative Settings (High Reliability)
```yaml
circuitBreaker:
  threshold: 3                          # Fail fast
  timeout: "60s"                        # Longer recovery time
  halfOpenRequests: 1                   # Single test request
  successThreshold: 3                   # Multiple successes required
```

#### Aggressive Settings (High Performance)
```yaml
circuitBreaker:
  threshold: 10                         # Allow more failures
  timeout: "15s"                        # Quick recovery
  halfOpenRequests: 5                   # Multiple test requests
  successThreshold: 2                   # Quick recovery
```

### Circuit Breaker Monitoring

```prometheus
# Circuit breaker state (0=closed, 1=half-open, 2=open)
gateway_circuit_breaker_state

# Circuit breaker transitions
rate(gateway_middleware_circuit_breaker_transitions_total[5m])

# Requests by circuit breaker state
rate(gateway_middleware_circuit_breaker_requests_total[5m])
```

## Caching Best Practices

### Memory Cache Configuration

```yaml
spec:
  cache:
    type: "memory"
    memory:
      maxEntries: 10000                 # Max cache entries
      maxSizeBytes: 104857600           # 100MB max cache size
      ttl: "300s"                       # Default TTL
      cleanupInterval: "60s"            # Cleanup interval
      jitter: "30s"                     # TTL jitter to prevent thundering herd
```

### Redis Sentinel Cache Configuration

Based on performance testing results, Redis Sentinel provides excellent caching performance:

```yaml
spec:
  cache:
    type: "redis"
    redis:
      addresses:
        - "redis-master:6379"
        - "redis-replica-1:6379"
        - "redis-replica-2:6379"
      sentinel:
        enabled: true
        masterName: "mymaster"
        addresses:
          - "sentinel-1:26379"
          - "sentinel-2:26379"
          - "sentinel-3:26379"
      poolSize: 20                      # Connection pool size
      minIdleConns: 5                   # Minimum idle connections
      maxRetries: 3                     # Max retry attempts
      dialTimeout: "5s"                 # Connection timeout
      readTimeout: "3s"                 # Read timeout
      writeTimeout: "3s"                # Write timeout
      poolTimeout: "4s"                 # Pool timeout

# Performance-optimized cache settings
cache:
  ttl: "60s"                           # Optimal TTL for most use cases
  staleWhileRevalidate: "30s"          # Serve stale while updating
  keyComponents:                       # Optimize cache key generation
    - path
    - method
    - query
  # Avoid high-cardinality components for better hit ratios
```

**Performance Benefits:**
- **High Availability**: Automatic failover with Redis Sentinel
- **Excellent Hit Ratios**: 80-95% cache hit rates in testing
- **Low Latency**: < 2ms cache lookup times
- **Scalability**: Horizontal scaling with read replicas

### Cache Key Optimization

```yaml
spec:
  routes:
    - name: cacheable-route
      cache:
        enabled: true
        ttl: "300s"
        keyComponents:                  # Optimize cache key generation
          - "uri"                       # Include URI
          - "method"                    # Include HTTP method
          - "headers.Authorization"     # Include auth header
          # Avoid high-cardinality components like:
          # - "headers.X-Request-ID"   # Unique per request
          # - "query.timestamp"        # Time-based values
        hashKeys: true                  # Hash keys for privacy/length
```

### Cache Performance Tuning

#### High Hit Ratio Configuration
```yaml
cache:
  ttl: "600s"                          # Longer TTL
  staleWhileRevalidate: "60s"          # Serve stale while updating
  negativeCaching:
    enabled: true
    ttl: "60s"                         # Cache errors briefly
```

#### Low Latency Configuration
```yaml
cache:
  type: "memory"                       # Use memory cache
  ttl: "300s"                          # Moderate TTL
  maxEntries: 50000                    # Large cache size
```

### Cache Monitoring

```prometheus
# Cache hit ratio
rate(gateway_cache_hits_total[5m]) / (rate(gateway_cache_hits_total[5m]) + rate(gateway_cache_misses_total[5m])) * 100

# Cache operation latency
histogram_quantile(0.95, rate(gateway_cache_operation_duration_seconds_bucket[5m]))

# Cache size utilization
gateway_cache_size_bytes / gateway_cache_max_size_bytes * 100
```

## TLS Performance Optimization

### TLS Configuration for Performance

```yaml
spec:
  listeners:
    - name: https
      port: 8443
      protocol: HTTPS
      tls:
        mode: SIMPLE
        minVersion: "1.2"               # Balance security and compatibility
        maxVersion: "1.3"               # Use TLS 1.3 for better performance
        cipherSuites:                   # Optimized cipher suites
          - "TLS_AES_128_GCM_SHA256"    # TLS 1.3 - fastest
          - "TLS_AES_256_GCM_SHA384"    # TLS 1.3 - secure
          - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"  # TLS 1.2 fallback
        sessionTickets: true            # Enable session resumption
        sessionTimeout: "300s"          # Session cache timeout
```

### TLS Performance Impact

Based on testing results:
- **HTTP Throughput Impact**: ~25% reduction with TLS
- **Latency Impact**: ~2x increase in request latency
- **CPU Overhead**: ~15% additional CPU usage
- **Memory Overhead**: ~50MB for TLS session cache

### TLS Optimization Strategies

1. **Use TLS 1.3**: Faster handshake and better cipher suites
2. **Enable Session Resumption**: Reduce handshake overhead
3. **Optimize Cipher Suites**: Prefer AES-GCM for performance
4. **Certificate Management**: Use shorter certificate chains
5. **Hardware Acceleration**: Use AES-NI when available

## Authentication Performance Optimization

### Authentication Performance Impact

Based on comprehensive testing with various authentication methods:

**JWT Authentication (Keycloak OIDC):**
- **Throughput**: 248 RPS sustained (vs 300+ RPS without auth)
- **Latency Impact**: ~10% increase (4.1ms P50 vs 3.6ms)
- **Token Validation**: < 1ms JWKS lookup with caching
- **Memory Overhead**: ~10MB for token cache

**API Key Authentication (Vault KV):**
- **Throughput Impact**: ~5% reduction
- **Latency Impact**: ~0.5ms increase
- **Vault Lookup**: < 2ms with connection pooling
- **Cache Hit Rate**: 95%+ for repeated keys

**mTLS Authentication (Vault PKI):**
- **Throughput Impact**: ~15% reduction
- **Latency Impact**: ~2ms increase (TLS handshake)
- **Certificate Validation**: < 1ms with cached CA
- **Connection Reuse**: Significant performance improvement

### Authentication Optimization Strategies

1. **Enable Token Caching**: Cache JWT tokens and API keys to reduce validation overhead
2. **Connection Pooling**: Use connection pools for external auth services (Vault, Keycloak)
3. **Certificate Caching**: Cache CA certificates and validation results for mTLS
4. **Batch Validation**: Validate multiple tokens in batch when possible
5. **Monitor Cache Hit Rates**: Optimize cache TTL based on hit rate metrics

## gRPC Performance Tuning

### gRPC Server Configuration

```yaml
spec:
  listeners:
    - name: grpc
      port: 9000
      protocol: GRPC
      grpc:
        maxConcurrentStreams: 1000      # High concurrency
        maxRecvMsgSize: 4194304         # 4MB max message size
        maxSendMsgSize: 4194304         # 4MB max message size
        keepalive:
          time: "30s"                   # Keepalive ping interval
          timeout: "5s"                 # Keepalive timeout
          permitWithoutStream: true     # Allow keepalive without streams
          maxConnectionIdle: "300s"     # Max idle time
          maxConnectionAge: "3600s"     # Max connection age
          maxConnectionAgeGrace: "30s"  # Grace period
        connectionWindow: 65536         # Connection-level flow control
        streamWindow: 65536             # Stream-level flow control
```

### gRPC Backend Configuration

```yaml
spec:
  grpcBackends:
    - name: high-performance-grpc
      grpc:
        maxRecvMsgSize: 4194304
        maxSendMsgSize: 4194304
        keepalive:
          time: "30s"
          timeout: "5s"
        connectionPool:
          maxConnections: 50            # Connection pool size
          maxConcurrentStreams: 100     # Streams per connection
          idleTimeout: "300s"           # Idle connection timeout
```

### gRPC Performance Optimization

#### For High Throughput
```yaml
grpc:
  maxConcurrentStreams: 1000           # High concurrency
  connectionPool:
    maxConnections: 100                # Large connection pool
    maxConcurrentStreams: 50           # Moderate streams per connection
```

#### For Low Latency
```yaml
grpc:
  maxConcurrentStreams: 100            # Lower concurrency
  keepalive:
    time: "10s"                        # Frequent keepalives
    timeout: "2s"                      # Quick timeout
  connectionPool:
    maxConnections: 20                 # Smaller pool
    maxConcurrentStreams: 10           # Few streams per connection
```

### gRPC Performance Monitoring

```prometheus
# gRPC request rate
rate(gateway_grpc_requests_total[5m])

# gRPC request latency
histogram_quantile(0.95, rate(gateway_grpc_request_duration_seconds_bucket[5m]))

# Active gRPC connections
gateway_grpc_connections_active

# gRPC streaming messages
rate(gateway_grpc_streaming_messages_total[5m])
```

## Monitoring and Observability

### Key Performance Metrics

#### Request Metrics
```prometheus
# Request throughput
rate(gateway_requests_total[5m])

# Request latency percentiles
histogram_quantile(0.50, rate(gateway_request_duration_seconds_bucket[5m]))
histogram_quantile(0.95, rate(gateway_request_duration_seconds_bucket[5m]))
histogram_quantile(0.99, rate(gateway_request_duration_seconds_bucket[5m]))

# Error rate
rate(gateway_requests_total{status=~"5.."}[5m]) / rate(gateway_requests_total[5m]) * 100
```

#### Resource Metrics
```prometheus
# CPU utilization
rate(process_cpu_seconds_total[5m]) * 100

# Memory usage
process_resident_memory_bytes

# Goroutine count
go_goroutines

# GC metrics
rate(go_gc_duration_seconds_sum[5m])
```

### Performance Alerting

```yaml
groups:
- name: avapigw.performance
  rules:
  - alert: HighLatency
    expr: histogram_quantile(0.95, rate(gateway_request_duration_seconds_bucket[5m])) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High request latency detected"

  - alert: HighErrorRate
    expr: rate(gateway_requests_total{status=~"5.."}[5m]) / rate(gateway_requests_total[5m]) > 0.05
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"

  - alert: HighCPUUsage
    expr: rate(process_cpu_seconds_total[5m]) * 100 > 80
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage detected"

  - alert: HighMemoryUsage
    expr: process_resident_memory_bytes / 1024 / 1024 / 1024 > 0.8
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage detected"
```

## Deployment-Specific Tuning

### Local Deployment Optimization

For maximum performance in local/development environments:

```yaml
# Optimize for single-node performance
spec:
  # Disable unnecessary features
  observability:
    tracing:
      enabled: false                   # Disable tracing overhead
    metrics:
      enabled: true                    # Keep metrics for monitoring
  
  # Optimize connection pools
  backends:
    - connection:
        maxIdleConns: 200
        maxIdleConnsPerHost: 50
  
  # Use memory cache
  cache:
    type: "memory"
    memory:
      maxEntries: 50000
      maxSizeBytes: 209715200          # 200MB
```

### Kubernetes Config-based Optimization

For file-based configuration in Kubernetes:

```yaml
# Optimize for config reload performance
spec:
  # Enable efficient config watching
  configReload:
    enabled: true
    watchInterval: "5s"                # Frequent config checks
  
  # Optimize resource usage
  resources:
    requests:
      cpu: "500m"
      memory: "256Mi"
    limits:
      cpu: "1000m"
      memory: "512Mi"
```

### Kubernetes CRD-based Optimization

For operator-managed configuration:

```yaml
# Optimize for CRD reconciliation
operator:
  # Efficient reconciliation
  reconcileInterval: "30s"
  maxConcurrentReconciles: 5
  
  # gRPC optimization
  grpc:
    keepalive:
      time: "30s"
      timeout: "5s"
    maxConcurrentStreams: 100
  
gateway:
  # Optimize for dynamic config
  resources:
    requests:
      cpu: "500m"
      memory: "256Mi"
    limits:
      cpu: "1500m"                     # Higher CPU for config processing
      memory: "512Mi"
```

### Kubernetes Ingress Controller Optimization

For best gRPC performance (as shown in test results):

```yaml
# Optimize for ingress processing
operator:
  ingressController:
    enabled: true
    # Efficient ingress processing
    resyncPeriod: "60s"
    maxConcurrentReconciles: 10
  
  # Annotation processing optimization
  annotations:
    processingTimeout: "5s"
    batchSize: 50
  
gateway:
  # Optimized for ingress workload
  resources:
    requests:
      cpu: "750m"                      # Higher CPU for annotation processing
      memory: "512Mi"
    limits:
      cpu: "2000m"
      memory: "1Gi"
  
  # gRPC optimization for best performance
  listeners:
    - name: grpc
      protocol: GRPC
      grpc:
        maxConcurrentStreams: 1000
        keepalive:
          time: "15s"                  # More frequent keepalives
          timeout: "3s"
```

## Performance Testing and Validation

### Load Testing Setup

```bash
# HTTP load testing with Yandex Tank
yandex-tank -c load-test-config.yaml

# gRPC load testing with ghz
ghz --insecure \
    --proto api.proto \
    --call api.v1.UserService/GetUser \
    --data '{"id": "123"}' \
    --rps 1000 \
    --duration 5m \
    localhost:9000
```

### Performance Benchmarking

```bash
# Benchmark current configuration
./scripts/benchmark.sh --duration=5m --rps=1000

# Compare configurations
./scripts/compare-configs.sh config-a.yaml config-b.yaml

# Profile CPU and memory
go tool pprof http://localhost:9090/debug/pprof/profile
go tool pprof http://localhost:9090/debug/pprof/heap
```

### Continuous Performance Monitoring

```yaml
# Performance regression detection
- alert: PerformanceRegression
  expr: |
    (
      histogram_quantile(0.95, rate(gateway_request_duration_seconds_bucket[5m])) 
      / 
      histogram_quantile(0.95, rate(gateway_request_duration_seconds_bucket[5m] offset 1d))
    ) > 1.2
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Performance regression detected"
    description: "P95 latency is 20% higher than yesterday"
```

## Related Documentation

- **[Performance Testing Guide](performance-testing.md)** - Detailed performance testing procedures
- **[Metrics Reference](features/metrics.md)** - Complete metrics documentation
- **[Configuration Reference](configuration-reference.md)** - All configuration options
- **[Operator Documentation](operator.md)** - Kubernetes operator performance considerations