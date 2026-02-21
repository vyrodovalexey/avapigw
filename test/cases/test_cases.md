# API Gateway Test Cases

This document covers test cases for the AVAPIGW API Gateway, including the core gateway, operator, and ingress controller functionality.

## Functional Tests

### TestFunctional_Config_LoadAndValidate
- **Description**: Test configuration loading and validation
- **Preconditions**: Valid and invalid configuration files exist
- **Steps**:
  1. Load valid configuration file
  2. Validate configuration structure
  3. Load invalid configuration file
  4. Verify validation errors are returned
- **Expected Results**: Valid config loads successfully, invalid config returns errors

### TestFunctional_Router_RouteMatching
- **Description**: Test route matching logic
- **Preconditions**: Router with multiple routes configured
- **Steps**:
  1. Create router with exact, prefix, and regex routes
  2. Test exact match
  3. Test prefix match
  4. Test regex match
  5. Test method matching
  6. Test header matching
  7. Test query parameter matching
- **Expected Results**: Correct route is matched for each request

### TestFunctional_Middleware_Chain
- **Description**: Test middleware chain execution
- **Preconditions**: Multiple middlewares configured
- **Steps**:
  1. Create middleware chain with logging, rate limit, circuit breaker
  2. Send request through chain
  3. Verify each middleware is executed in order
- **Expected Results**: All middlewares execute in correct order

### TestFunctional_Health_Endpoints
- **Description**: Test health check endpoints
- **Preconditions**: Health checker configured
- **Steps**:
  1. Call /health endpoint
  2. Call /ready endpoint
  3. Call /live endpoint
- **Expected Results**: All endpoints return correct status

## Integration Tests

### TestIntegration_Proxy_ForwardToBackend
- **Description**: Test proxy forwarding to backend
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure proxy with backend
  2. Send request to proxy
  3. Verify request is forwarded to backend
  4. Verify response is returned correctly
- **Expected Results**: Request is proxied and response returned

### TestIntegration_LoadBalancer_Distribution
- **Description**: Test load balancer distributes requests
- **Preconditions**: Two backend services running
- **Steps**:
  1. Configure load balancer with two backends
  2. Send multiple requests
  3. Verify requests are distributed between backends
- **Expected Results**: Requests are distributed according to algorithm

### TestIntegration_HealthCheck_BackendStatus
- **Description**: Test backend health checking
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure health check for backend
  2. Verify backend is marked healthy
  3. Stop backend
  4. Verify backend is marked unhealthy
- **Expected Results**: Backend status reflects actual health

### TestIntegration_Headers_XForwarded
- **Description**: Test X-Forwarded headers
- **Preconditions**: Backend service running
- **Steps**:
  1. Send request through proxy
  2. Verify X-Forwarded-For header is set
  3. Verify X-Forwarded-Proto header is set
  4. Verify X-Forwarded-Host header is set
- **Expected Results**: All X-Forwarded headers are correctly set

### TestIntegration_Timeout_BackendSlow
- **Description**: Test timeout handling for slow backends
- **Preconditions**: Backend configured with delay
- **Steps**:
  1. Configure route with timeout
  2. Send request to slow backend
  3. Verify timeout error is returned
- **Expected Results**: Request times out and error is returned

## E2E Tests

### TestE2E_GatewayStartup
- **Description**: Test gateway startup and shutdown
- **Preconditions**: Valid configuration file
- **Steps**:
  1. Start gateway with configuration
  2. Verify gateway is running
  3. Verify listeners are active
  4. Stop gateway
  5. Verify gateway is stopped
- **Expected Results**: Gateway starts and stops cleanly

### TestE2E_CRUD_ThroughGateway
- **Description**: Test CRUD operations through gateway
- **Preconditions**: Gateway and backend running
- **Steps**:
  1. Create item through gateway
  2. Read item through gateway
  3. Update item through gateway
  4. Delete item through gateway
- **Expected Results**: All CRUD operations succeed

### TestE2E_LoadBalancing
- **Description**: Test load balancing across backends
- **Preconditions**: Gateway with two backends running
- **Steps**:
  1. Send multiple requests through gateway
  2. Track which backend handles each request
  3. Verify distribution matches configuration
- **Expected Results**: Requests are balanced across backends

### TestE2E_RateLimiting
- **Description**: Test rate limiting functionality
- **Preconditions**: Gateway with rate limiting enabled
- **Steps**:
  1. Send requests within rate limit
  2. Verify requests succeed
  3. Send requests exceeding rate limit
  4. Verify 429 response is returned
- **Expected Results**: Rate limiting is enforced

### TestE2E_CircuitBreaker
- **Description**: Test circuit breaker functionality
- **Preconditions**: Gateway with circuit breaker enabled
- **Steps**:
  1. Send requests to healthy backend
  2. Simulate backend failures
  3. Verify circuit breaker opens
  4. Verify 503 response is returned
  5. Wait for circuit breaker to half-open
  6. Verify recovery
- **Expected Results**: Circuit breaker protects against failures

### TestE2E_HotReload
- **Description**: Test hot-reload of configuration
- **Preconditions**: Gateway running with config watcher
- **Steps**:
  1. Start gateway with initial configuration
  2. Modify configuration file
  3. Verify configuration is reloaded
  4. Verify new routes are active
- **Expected Results**: Configuration is reloaded without restart

### TestE2E_GracefulShutdown
- **Description**: Test graceful shutdown
- **Preconditions**: Gateway running with active connections
- **Steps**:
  1. Start gateway
  2. Send long-running request
  3. Initiate shutdown
  4. Verify in-flight requests complete
  5. Verify new requests are rejected
- **Expected Results**: Graceful shutdown completes

## gRPC Functional Tests

### TestFunctional_GRPCRouter_ServiceMatching
- **Description**: Test gRPC service matching logic
- **Preconditions**: Router with gRPC routes configured
- **Steps**:
  1. Create router with exact, prefix, and regex service matchers
  2. Test exact service match
  3. Test prefix service match
  4. Test regex service match
  5. Test wildcard service match
- **Expected Results**: Correct route is matched for each service

### TestFunctional_GRPCRouter_MethodMatching
- **Description**: Test gRPC method matching logic
- **Preconditions**: Router with gRPC routes configured
- **Steps**:
  1. Create router with exact, prefix, and regex method matchers
  2. Test exact method match
  3. Test prefix method match
  4. Test regex method match
- **Expected Results**: Correct route is matched for each method

### TestFunctional_GRPCRouter_Priority
- **Description**: Test gRPC route priority ordering
- **Preconditions**: Router with multiple overlapping routes
- **Steps**:
  1. Add prefix route
  2. Add exact route
  3. Verify exact match has higher priority
  4. Verify more specific match has higher priority
  5. Verify metadata adds to priority
- **Expected Results**: Routes are matched in correct priority order

### TestFunctional_GRPCConfig_LoadAndValidate
- **Description**: Test gRPC configuration loading and validation
- **Preconditions**: Valid gRPC configuration file exists
- **Steps**:
  1. Load valid gRPC configuration file
  2. Validate gRPC listener configuration
  3. Validate gRPC routes configuration
  4. Validate gRPC backends configuration
  5. Validate keepalive configuration
- **Expected Results**: Configuration loads and validates correctly

### TestFunctional_GRPCConfig_Defaults
- **Description**: Test gRPC default configuration values
- **Preconditions**: None
- **Steps**:
  1. Get default gRPC listener config
  2. Get default gRPC health check config
  3. Get default gRPC retry policy
  4. Verify all default values are correct
- **Expected Results**: Default values match expected values

## gRPC Integration Tests

### TestIntegration_GRPCProxy_UnaryCall
- **Description**: Test gRPC unary call proxying
- **Preconditions**: gRPC backend service running
- **Steps**:
  1. Configure proxy with route to backend
  2. Create gRPC connection through proxy
  3. Make unary call
  4. Verify response is returned correctly
- **Expected Results**: Unary call is proxied successfully

### TestIntegration_GRPCProxy_ServerStreaming
- **Description**: Test gRPC server streaming proxying
- **Preconditions**: gRPC backend service running
- **Steps**:
  1. Configure proxy with streaming route
  2. Create gRPC connection through proxy
  3. Make server streaming call
  4. Verify all stream messages are received
- **Expected Results**: Server streaming is proxied successfully

### TestIntegration_GRPCProxy_LoadBalancing
- **Description**: Test gRPC load balancing
- **Preconditions**: Two gRPC backend services running
- **Steps**:
  1. Configure proxy with weighted destinations
  2. Make multiple requests
  3. Verify requests are distributed according to weights
- **Expected Results**: Requests are load balanced correctly

## gRPC E2E Tests

### TestE2E_GRPCGateway_Startup
- **Description**: Test gRPC gateway startup and shutdown
- **Preconditions**: Valid gRPC configuration
- **Steps**:
  1. Start gRPC gateway with configuration
  2. Verify gateway is running
  3. Verify gRPC listener is active
  4. Stop gateway
  5. Verify gateway is stopped cleanly
- **Expected Results**: Gateway starts and stops cleanly

### TestE2E_GRPCGateway_UnaryThroughGateway
- **Description**: Test unary gRPC calls through gateway
- **Preconditions**: Gateway and gRPC backend running
- **Steps**:
  1. Start gateway with gRPC listener
  2. Connect to gateway
  3. Make unary call through gateway
  4. Verify response is correct
- **Expected Results**: Unary calls work through gateway

### TestE2E_GRPCGateway_LoadBalancing
- **Description**: Test gRPC load balancing through gateway
- **Preconditions**: Gateway with two gRPC backends running
- **Steps**:
  1. Start gateway with multiple backends
  2. Send multiple requests through gateway
  3. Track which backend handles each request
  4. Verify distribution matches configuration
- **Expected Results**: Requests are balanced across backends

### TestE2E_GRPCGateway_HealthService
- **Description**: Test gRPC health service
- **Preconditions**: Gateway with health check enabled
- **Steps**:
  1. Start gateway with health check enabled
  2. Connect to gateway
  3. Call health check service
  4. Verify SERVING status is returned
- **Expected Results**: Health service responds correctly

## Redis Cache Integration Tests

### TestIntegration_Cache_Redis_BasicOperations
- **Description**: Test basic Redis cache operations (Get, Set, Delete, Exists)
- **Preconditions**: Redis server running at TEST_REDIS_URL
- **Steps**:
  1. Create Redis cache with configuration
  2. Test Set operation - store value with TTL
  3. Test Get operation - retrieve stored value
  4. Test Exists operation - check key existence
  5. Test Delete operation - remove key
  6. Verify cache miss for non-existing keys
- **Expected Results**: All basic operations work correctly

### TestIntegration_Cache_Redis_TTLExpiration
- **Description**: Test Redis cache TTL expiration
- **Preconditions**: Redis server running
- **Steps**:
  1. Set value with short TTL (1 second)
  2. Verify value is accessible immediately
  3. Wait for TTL to expire
  4. Verify cache miss after expiration
  5. Test zero TTL uses default
- **Expected Results**: Keys expire after TTL

### TestIntegration_Cache_Redis_ConcurrentAccess
- **Description**: Test Redis cache concurrent access
- **Preconditions**: Redis server running
- **Steps**:
  1. Spawn multiple goroutines writing to same key
  2. Spawn multiple goroutines reading and writing
  3. Spawn multiple goroutines operating on different keys
  4. Verify no errors occur
- **Expected Results**: Concurrent operations are thread-safe

### TestIntegration_Cache_Redis_ConnectionHandling
- **Description**: Test Redis cache connection handling
- **Preconditions**: Redis server running
- **Steps**:
  1. Test connection pool with multiple operations
  2. Test close and reopen cache
  3. Verify data persists across cache instances
  4. Test invalid Redis URL returns error
- **Expected Results**: Connection handling is robust

### TestIntegration_Cache_Redis_KeyPrefix
- **Description**: Test Redis cache key prefix functionality
- **Preconditions**: Redis server running
- **Steps**:
  1. Create two caches with different prefixes
  2. Set same key in both caches
  3. Verify keys are isolated by prefix
  4. Delete in one cache doesn't affect other
- **Expected Results**: Key prefixes provide isolation

### TestIntegration_Cache_Redis_LargeValues
- **Description**: Test Redis cache with large values
- **Preconditions**: Redis server running
- **Steps**:
  1. Store and retrieve 1KB value
  2. Store and retrieve 100KB value
  3. Store and retrieve 1MB value
  4. Store and retrieve empty value
- **Expected Results**: Large values are handled correctly

### TestIntegration_Cache_Redis_ErrorHandling
- **Description**: Test Redis cache error handling
- **Preconditions**: Redis server running
- **Steps**:
  1. Get non-existing key returns cache miss
  2. Context cancellation is handled
  3. Context timeout is handled
  4. Special characters in keys are handled
- **Expected Results**: Errors are handled gracefully

### TestIntegration_Cache_Redis_Statistics
- **Description**: Test Redis cache statistics
- **Preconditions**: Redis server running
- **Steps**:
  1. Get initial statistics
  2. Cause cache miss
  3. Cause cache hit
  4. Verify statistics are updated
- **Expected Results**: Statistics track hits and misses

## Transform with Redis Cache Integration Tests

### TestIntegration_Transform_WithRedisCache
- **Description**: Test transformation with Redis caching
- **Preconditions**: Redis server running
- **Steps**:
  1. Create transformer and Redis cache
  2. Transform data with field filtering
  3. Cache transformed result
  4. Retrieve from cache and verify
- **Expected Results**: Transformed data is cached correctly

### TestIntegration_Transform_CacheInvalidation
- **Description**: Test transformation cache invalidation
- **Preconditions**: Redis server running
- **Steps**:
  1. Cache transformed data
  2. Verify data exists
  3. Delete (invalidate) cache entry
  4. Verify cache miss
  5. Test cache update overwrites old data
- **Expected Results**: Cache invalidation works correctly

### TestIntegration_Transform_CacheMiss
- **Description**: Test transformation with cache miss
- **Preconditions**: Redis server running
- **Steps**:
  1. Try to get non-existing cache key
  2. On cache miss, perform transformation
  3. Cache the result
  4. Subsequent get should hit cache
  5. Simulate cache-aside pattern
- **Expected Results**: Cache miss triggers transformation

### TestIntegration_Transform_StaleWhileRevalidate
- **Description**: Test stale-while-revalidate pattern
- **Preconditions**: Redis server running
- **Steps**:
  1. Cache data with short TTL
  2. Verify data is available
  3. Wait for TTL to expire
  4. Verify cache miss
  5. Revalidate with fresh data
- **Expected Results**: Stale data expires and requires revalidation

### TestIntegration_Transform_FieldMappingWithCache
- **Description**: Test field mapping transformation with caching
- **Preconditions**: Redis server running
- **Steps**:
  1. Transform data with field mappings
  2. Cache transformed result
  3. Retrieve and verify field mappings are preserved
- **Expected Results**: Field mappings are cached correctly

### TestIntegration_Transform_ArrayOperationsWithCache
- **Description**: Test array operations with caching
- **Preconditions**: Redis server running
- **Steps**:
  1. Transform data with array operations (limit)
  2. Cache transformed result
  3. Retrieve and verify array operations are applied
- **Expected Results**: Array operations are cached correctly

## gRPC Transform with Redis Cache Integration Tests

### TestIntegration_GRPCTransform_WithRedisCache
- **Description**: Test gRPC transformation with Redis caching
- **Preconditions**: Redis server running
- **Steps**:
  1. Create gRPC transformer and Redis cache
  2. Create transform context with metadata
  3. Cache transform context data
  4. Retrieve and verify
- **Expected Results**: gRPC transform data is cached correctly

### TestIntegration_GRPCTransform_MetadataWithCache
- **Description**: Test gRPC metadata transformation with caching
- **Preconditions**: Redis server running
- **Steps**:
  1. Cache metadata transformation rules
  2. Cache transformed metadata
  3. Verify metadata key normalization
- **Expected Results**: Metadata transformations are cached correctly

### TestIntegration_GRPCTransform_StreamingWithCache
- **Description**: Test gRPC streaming transformation with cache
- **Preconditions**: Redis server running
- **Steps**:
  1. Cache streaming transformation config
  2. Cache streaming message batch
  3. Cache stream state for resumption
- **Expected Results**: Streaming data is cached correctly

### TestIntegration_GRPCTransform_FieldMaskWithCache
- **Description**: Test gRPC field mask transformation with cache
- **Preconditions**: Redis server running
- **Steps**:
  1. Cache field mask configuration
  2. Cache filtered response based on field mask
  3. Verify excluded fields are not present
- **Expected Results**: Field mask filtering is cached correctly

### TestIntegration_GRPCTransform_ErrorHandlingWithCache
- **Description**: Test gRPC error transformation with cache
- **Preconditions**: Redis server running
- **Steps**:
  1. Cache error transformation mapping
  2. Cache transformed error response
  3. Verify error codes and messages
- **Expected Results**: Error transformations are cached correctly

### TestIntegration_GRPCTransform_CustomDataWithCache
- **Description**: Test custom data in transform context with cache
- **Preconditions**: Redis server running
- **Steps**:
  1. Create transform context with custom data
  2. Set and get custom data values
  3. Cache custom transform data
  4. Retrieve and verify
- **Expected Results**: Custom data is cached correctly

## Data Transformation E2E Tests

### TestE2E_Transform_HTTPFlow
- **Description**: Test complete HTTP request/response transformation flow through gateway
- **Preconditions**: HTTP backend service running
- **Steps**:
  1. Start gateway with transformation configuration
  2. Make GET request through gateway
  3. Make POST request through gateway
  4. Verify responses are transformed correctly
- **Expected Results**: HTTP transformation flow works end-to-end

### TestE2E_Transform_FieldFiltering
- **Description**: Test transformation with field filtering
- **Preconditions**: HTTP backend service running
- **Steps**:
  1. Configure gateway with allowFields and denyFields
  2. Make request through gateway
  3. Verify allowed fields are present
  4. Verify denied fields are removed
- **Expected Results**: Field filtering is applied correctly

### TestE2E_Transform_FieldMapping
- **Description**: Test transformation with field mapping
- **Preconditions**: HTTP backend service running
- **Steps**:
  1. Configure gateway with field mappings (e.g., created_at -> createdAt)
  2. Make request through gateway
  3. Verify fields are renamed according to mappings
- **Expected Results**: Field mapping is applied correctly

### TestE2E_Transform_MultipleBackends
- **Description**: Test transformation with multiple backends
- **Preconditions**: Two HTTP backend services running
- **Steps**:
  1. Configure gateway with multiple weighted backends
  2. Make multiple requests through gateway
  3. Verify requests are distributed across backends
- **Expected Results**: Requests are distributed and transformed correctly

### TestE2E_Transform_LoadBalancing
- **Description**: Test transformation with load balancing
- **Preconditions**: Two HTTP backend services running
- **Steps**:
  1. Configure gateway with weighted backends (70/30)
  2. Make multiple requests through gateway
  3. Verify distribution matches weights
- **Expected Results**: Load balancing works with transformation

### TestE2E_Transform_ErrorHandling
- **Description**: Test transformation error handling
- **Preconditions**: HTTP backend service running
- **Steps**:
  1. Request non-existent endpoint
  2. Request with invalid method
  3. Request with malformed JSON body
  4. Verify proper error responses
- **Expected Results**: Errors are handled gracefully

### TestE2E_Transform_RequestTransformation
- **Description**: Test request transformation
- **Preconditions**: HTTP backend service running
- **Steps**:
  1. Configure gateway with request transformation (static headers, default values)
  2. Make request through gateway
  3. Verify backend receives transformed request
- **Expected Results**: Request transformation is applied

### TestE2E_Transform_ResponseHeaders
- **Description**: Test response header transformation
- **Preconditions**: HTTP backend service running
- **Steps**:
  1. Configure gateway with header manipulation
  2. Make request through gateway
  3. Verify response headers are modified
- **Expected Results**: Response headers are transformed

### TestE2E_Transform_CompleteJourney
- **Description**: Test complete user journey with transformations
- **Preconditions**: HTTP backend service running
- **Steps**:
  1. Create item through gateway
  2. Read items through gateway
  3. Update item through gateway
  4. Delete item through gateway
- **Expected Results**: Complete CRUD journey works with transformation

## Cache E2E Tests

### TestE2E_Cache_RedisGatewayFlow
- **Description**: Test caching with Redis in gateway flow
- **Preconditions**: Redis and HTTP backend running
- **Steps**:
  1. Start gateway with Redis caching
  2. Make request, cache response
  3. Verify data is cached
  4. Serve subsequent request from cache
- **Expected Results**: Caching works in gateway flow

### TestE2E_Cache_Invalidation
- **Description**: Test cache invalidation
- **Preconditions**: Redis running
- **Steps**:
  1. Cache data
  2. Verify data exists
  3. Invalidate (delete) cache entry
  4. Verify cache miss
  5. Test invalidation on update
- **Expected Results**: Cache invalidation works correctly

### TestE2E_Cache_TTL
- **Description**: Test cache TTL expiration
- **Preconditions**: Redis running
- **Steps**:
  1. Cache data with short TTL
  2. Verify data is accessible
  3. Wait for TTL to expire
  4. Verify cache miss after expiration
- **Expected Results**: Cache TTL is enforced

### TestE2E_Cache_Bypass
- **Description**: Test cache bypass functionality
- **Preconditions**: Redis and HTTP backend running
- **Steps**:
  1. Cache some data
  2. Make request with Cache-Control: no-cache header
  3. Verify request bypasses cache
  4. Verify POST requests bypass cache
- **Expected Results**: Cache bypass works correctly

### TestE2E_Cache_NegativeCaching
- **Description**: Test caching of error responses
- **Preconditions**: Redis running
- **Steps**:
  1. Cache 404 error response
  2. Cache 500 error response
  3. Verify error responses are cached with shorter TTL
- **Expected Results**: Negative caching works correctly

### TestE2E_Cache_ConcurrentAccess
- **Description**: Test concurrent cache access
- **Preconditions**: Redis running
- **Steps**:
  1. Spawn multiple goroutines reading and writing
  2. Verify no errors occur
  3. Verify data consistency
- **Expected Results**: Concurrent access is thread-safe

### TestE2E_Cache_CompleteJourney
- **Description**: Test complete caching journey
- **Preconditions**: Redis and HTTP backend running
- **Steps**:
  1. First request - cache miss, fetch from backend
  2. Second request - cache hit
  3. Update - invalidate cache
  4. Third request - cache miss after invalidation
- **Expected Results**: Complete caching journey works

## gRPC Transform E2E Tests

### TestE2E_GRPCTransform_UnaryFlow
- **Description**: Test complete gRPC transformation flow
- **Preconditions**: gRPC backend service running
- **Steps**:
  1. Start gateway with gRPC transformation
  2. Make unary call through gateway
  3. Verify response is transformed
  4. Test with metadata transformation
- **Expected Results**: gRPC unary transformation works

### TestE2E_GRPCTransform_StreamingFlow
- **Description**: Test gRPC streaming transformation flow
- **Preconditions**: gRPC backend service running
- **Steps**:
  1. Start gateway with streaming transformation
  2. Make streaming call through gateway
  3. Verify each message is transformed
- **Expected Results**: gRPC streaming transformation works

### TestE2E_GRPCTransform_WithCaching
- **Description**: Test gRPC transformation with caching
- **Preconditions**: Redis and gRPC backend running
- **Steps**:
  1. Start gateway with caching
  2. Make call, verify cached
  3. Make same call, verify served from cache
- **Expected Results**: gRPC caching works with transformation

### TestE2E_GRPCTransform_MultipleBackends
- **Description**: Test gRPC transformation with multiple backends
- **Preconditions**: Two gRPC backend services running
- **Steps**:
  1. Start gateway with multiple backends
  2. Make calls, verify load balancing
  3. Verify transformation on all backends
- **Expected Results**: Load balancing works with gRPC transformation

### TestE2E_GRPCTransform_Metadata
- **Description**: Test gRPC metadata transformation
- **Preconditions**: gRPC backend service running
- **Steps**:
  1. Start gateway with metadata transformation
  2. Make call with metadata
  3. Verify metadata is transformed (static and dynamic)
- **Expected Results**: gRPC metadata transformation works

### TestE2E_GRPCTransform_ErrorHandling
- **Description**: Test gRPC transformation error handling
- **Preconditions**: gRPC backend service running
- **Steps**:
  1. Test connection timeout handling
  2. Test invalid service handling
  3. Verify proper gRPC status codes
- **Expected Results**: Errors are handled gracefully

### TestE2E_GRPCTransform_HealthCheck
- **Description**: Test gRPC health check with transformation
- **Preconditions**: gRPC backend service running
- **Steps**:
  1. Start gateway with health check enabled
  2. Call health check service
  3. Verify SERVING status
  4. Test health watch
- **Expected Results**: Health check works with transformation

### TestE2E_GRPCTransform_CompleteJourney
- **Description**: Test complete gRPC transformation journey
- **Preconditions**: Redis and gRPC backend running
- **Steps**:
  1. Verify gateway is running
  2. Connect to gateway
  3. Health check passes
  4. Cache response data
  5. Invalidate cache
  6. Gateway stops cleanly
- **Expected Results**: Complete gRPC journey works

## Route-Level Configuration Tests

### TestFunctional_RouteConfig_RequestLimits
- **Description**: Test route-level request limits configuration
- **Preconditions**: None
- **Steps**:
  1. Create route with custom RequestLimits (smaller than global)
  2. Create route with custom RequestLimits (larger than global)
  3. Test route inheriting global configuration
  4. Test multiple routes with different configurations
  5. Verify request body size validation
  6. Verify header size validation
- **Expected Results**: Route-level limits override global limits

### TestFunctional_RouteConfig_CORS
- **Description**: Test route-level CORS configuration
- **Preconditions**: None
- **Steps**:
  1. Create route with custom CORS configuration
  2. Test CORS preflight with route-specific origins
  3. Test route inheriting global CORS
  4. Verify CORS headers in response
  5. Test allowCredentials override
  6. Test maxAge override
- **Expected Results**: Route-level CORS overrides global CORS

### TestFunctional_RouteConfig_Security
- **Description**: Test route-level security headers configuration
- **Preconditions**: None
- **Steps**:
  1. Create route with custom Security headers
  2. Test route inheriting global security headers
  3. Verify security headers present in response
  4. Test custom security headers
  5. Test X-Frame-Options override
  6. Test X-Content-Type-Options override
- **Expected Results**: Route-level security headers override global

### TestFunctional_RouteConfig_Inheritance
- **Description**: Test configuration inheritance from global to route level
- **Preconditions**: None
- **Steps**:
  1. Configure global RequestLimits, CORS, and Security
  2. Create route without overrides
  3. Create route with partial overrides
  4. Create route with complete overrides
  5. Verify inheritance behavior
- **Expected Results**: Routes inherit global config unless overridden

### TestFunctional_RouteConfig_Validation
- **Description**: Test validation of route-level configurations
- **Preconditions**: None
- **Steps**:
  1. Test invalid RequestLimits values
  2. Test invalid CORS origins
  3. Test invalid security header values
  4. Verify validation error messages
- **Expected Results**: Invalid configurations are rejected with clear errors

## Backend Circuit Breaker Tests

### TestFunctional_BackendCircuitBreaker_Enabled
- **Description**: Test backend with circuit breaker enabled
- **Preconditions**: None
- **Steps**:
  1. Create backend with circuit breaker enabled
  2. Verify requests pass when circuit breaker is closed
  3. Test disabled circuit breaker passes all requests
- **Expected Results**: Circuit breaker allows requests when closed

### TestFunctional_BackendCircuitBreaker_OpensAfterFailures
- **Description**: Test circuit breaker opens after failures
- **Preconditions**: None
- **Steps**:
  1. Configure circuit breaker with low threshold
  2. Send failing requests
  3. Verify circuit breaker opens
  4. Verify 503 response when open
- **Expected Results**: Circuit breaker opens after threshold failures

### TestFunctional_BackendCircuitBreaker_HalfOpenState
- **Description**: Test circuit breaker half-open state
- **Preconditions**: None
- **Steps**:
  1. Open circuit breaker with failures
  2. Wait for timeout
  3. Verify half-open state allows test requests
- **Expected Results**: Circuit breaker transitions to half-open

### TestFunctional_BackendCircuitBreaker_Recovery
- **Description**: Test circuit breaker recovery
- **Preconditions**: None
- **Steps**:
  1. Open circuit breaker
  2. Wait for timeout
  3. Send successful requests
  4. Verify circuit breaker closes
- **Expected Results**: Circuit breaker recovers after successful requests

### TestFunctional_BackendCircuitBreaker_MultipleBackends
- **Description**: Test multiple backends with different circuit breaker configs
- **Preconditions**: None
- **Steps**:
  1. Create backend with conservative circuit breaker
  2. Create backend with aggressive circuit breaker
  3. Send failures to both
  4. Verify independent circuit breaker behavior
- **Expected Results**: Each backend has independent circuit breaker

### TestFunctional_BackendCircuitBreaker_GlobalVsBackend
- **Description**: Test global vs backend-level circuit breaker configuration
- **Preconditions**: None
- **Steps**:
  1. Configure global circuit breaker
  2. Create backend without circuit breaker config
  3. Create backend with circuit breaker override
  4. Verify global config is inherited
  5. Verify backend config overrides global
- **Expected Results**: Backend-level config overrides global when present

### TestFunctional_BackendCircuitBreaker_Validation
- **Description**: Test validation of backend circuit breaker configuration
- **Preconditions**: None
- **Steps**:
  1. Test invalid threshold values
  2. Test invalid timeout values
  3. Test invalid halfOpenRequests values
  4. Verify validation error messages
- **Expected Results**: Invalid configurations are rejected with clear errors

## Backend Authentication Tests

### TestFunctional_BackendAuth_JWTConfig
- **Description**: Test backend JWT authentication configuration
- **Preconditions**: None
- **Steps**:
  1. Test JWT auth with static token
  2. Test JWT auth with OIDC token source
  3. Test JWT auth with Vault token source
  4. Test validation errors for invalid config
- **Expected Results**: JWT auth config validates correctly

### TestFunctional_BackendAuth_BasicConfig
- **Description**: Test backend Basic authentication configuration
- **Preconditions**: None
- **Steps**:
  1. Test Basic auth with static credentials
  2. Test Basic auth with Vault credentials
  3. Test validation errors for missing credentials
- **Expected Results**: Basic auth config validates correctly

### TestFunctional_BackendAuth_MTLSConfig
- **Description**: Test backend mTLS authentication configuration
- **Preconditions**: None
- **Steps**:
  1. Test mTLS auth with file-based certificates
  2. Test mTLS auth with Vault PKI
  3. Test validation errors for missing certificates
- **Expected Results**: mTLS auth config validates correctly

### TestFunctional_BackendAuth_HeaderVerification
- **Description**: Test backend authentication header verification
- **Preconditions**: None
- **Steps**:
  1. Test JWT auth header name and prefix
  2. Test Basic auth Vault key names
  3. Test custom header name configuration
  4. Test default header values
  5. Verify header injection into backend requests
- **Expected Results**: Auth headers are configured correctly

### TestFunctional_BackendAuth_TokenCaching
- **Description**: Test backend authentication token caching
- **Preconditions**: None
- **Steps**:
  1. Configure JWT auth with OIDC token source
  2. Make multiple requests
  3. Verify token is cached and reused
  4. Test token refresh on expiry
  5. Test cache TTL configuration
- **Expected Results**: Tokens are cached and refreshed appropriately

### TestFunctional_BackendAuth_VaultIntegration
- **Description**: Test backend authentication with Vault integration
- **Preconditions**: None
- **Steps**:
  1. Test JWT token retrieval from Vault
  2. Test Basic auth credentials from Vault
  3. Test mTLS certificates from Vault PKI
  4. Test Vault path validation
  5. Test Vault secret refresh
- **Expected Results**: Vault integration works for all auth types

### TestFunctional_BackendAuth_ErrorHandling
- **Description**: Test backend authentication error handling
- **Preconditions**: None
- **Steps**:
  1. Test invalid OIDC configuration
  2. Test unreachable Vault server
  3. Test missing certificates
  4. Test expired tokens
  5. Verify error propagation and logging
- **Expected Results**: Errors are handled gracefully with proper logging

## Backend Authentication Integration Tests

### TestIntegration_BackendAuth_JWT_OIDC
- **Description**: Test backend JWT auth with OIDC client credentials
- **Preconditions**: Keycloak running
- **Steps**:
  1. Create backend service client in Keycloak
  2. Get token using client credentials
  3. Test token refresh on expiry
  4. Test token caching behavior
  5. Test error handling for invalid OIDC config
- **Expected Results**: OIDC token acquisition works correctly

### TestIntegration_BackendAuth_Basic_Vault
- **Description**: Test backend Basic auth with Vault credentials
- **Preconditions**: Vault running
- **Steps**:
  1. Store credentials in Vault
  2. Read credentials from Vault
  3. Test credential refresh from Vault
  4. Test error handling for missing Vault path
- **Expected Results**: Vault credential retrieval works correctly

### TestIntegration_BackendAuth_MTLS_Vault
- **Description**: Test backend mTLS with Vault PKI certificates
- **Preconditions**: Vault running with PKI enabled
- **Steps**:
  1. Issue certificate from Vault PKI
  2. Test certificate rotation
  3. Test error handling for PKI errors
  4. Test mTLS connection with Vault-issued certificates
- **Expected Results**: Vault PKI certificate management works correctly

### TestIntegration_BackendCircuitBreaker_RealBackend
- **Description**: Test circuit breaker with real backend failures
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure circuit breaker with backend
  2. Simulate backend failures
  3. Verify circuit breaker opens
  4. Test state persistence across requests
  5. Test multiple backends with independent circuit breakers
- **Expected Results**: Circuit breaker works with real backends

### TestIntegration_RouteConfig_RequestLimits
- **Description**: Test route-level request limits with real requests
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure route with custom request limits
  2. Send request within limits
  3. Send request exceeding body size limit
  4. Send request exceeding header size limit
  5. Verify appropriate HTTP status codes
- **Expected Results**: Request limits are enforced correctly

### TestIntegration_RouteConfig_CORS
- **Description**: Test route-level CORS with real browser requests
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure route with custom CORS settings
  2. Send preflight OPTIONS request
  3. Send actual CORS request
  4. Verify CORS headers in response
  5. Test with different origins
- **Expected Results**: CORS is handled correctly per route

### TestIntegration_RouteConfig_Security
- **Description**: Test route-level security headers with real requests
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure route with custom security headers
  2. Send request to route
  3. Verify security headers in response
  4. Test custom headers injection
  5. Compare with global security headers
- **Expected Results**: Security headers are applied correctly per route

## Backend Configuration E2E Tests

### TestE2E_RouteConfig_RequestLimits
- **Description**: Test full gateway with route-level RequestLimits
- **Preconditions**: Backend service running
- **Steps**:
  1. Start gateway with route-level request limits
  2. Test request within limit succeeds
  3. Test request exceeding route body limit returns 413
- **Expected Results**: Route-level limits enforced end-to-end

### TestE2E_RouteConfig_CORS
- **Description**: Test full gateway with route-level CORS
- **Preconditions**: Backend service running
- **Steps**:
  1. Start gateway with route-level CORS
  2. Test CORS preflight with route-specific origins
  3. Verify CORS headers in response
- **Expected Results**: Route-level CORS works end-to-end

### TestE2E_RouteConfig_Security
- **Description**: Test full gateway with route-level Security headers
- **Preconditions**: Backend service running
- **Steps**:
  1. Start gateway with route-level security headers
  2. Verify security headers present in response
- **Expected Results**: Route-level security headers work end-to-end

### TestE2E_BackendAuth_JWT
- **Description**: Test gateway proxying to backend with JWT auth
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure backend with JWT authentication
  2. Start gateway
  3. Verify JWT token is injected into backend requests
- **Expected Results**: JWT auth works end-to-end

### TestE2E_BackendAuth_Basic
- **Description**: Test gateway proxying to backend with Basic auth
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure backend with Basic authentication
  2. Start gateway
  3. Verify Basic auth header is injected into backend requests
- **Expected Results**: Basic auth works end-to-end

### TestE2E_BackendAuth_MTLS
- **Description**: Test gateway proxying to backend with mTLS
- **Preconditions**: Backend service running with TLS
- **Steps**:
  1. Generate test certificates
  2. Configure backend with mTLS authentication
  3. Start gateway
  4. Verify mTLS connection to backend
- **Expected Results**: mTLS auth works end-to-end

### TestE2E_BackendAuth_Vault
- **Description**: Test backend auth with Vault integration
- **Preconditions**: Vault running
- **Steps**:
  1. Store credentials in Vault
  2. Configure backend with Vault-based authentication
  3. Start gateway
  4. Verify credentials are retrieved from Vault
- **Expected Results**: Vault integration works end-to-end

### TestE2E_BackendAuth_Keycloak
- **Description**: Test backend auth with Keycloak OIDC
- **Preconditions**: Keycloak running
- **Steps**:
  1. Create backend service client in Keycloak
  2. Configure backend with OIDC authentication
  3. Start gateway
  4. Verify token is acquired from Keycloak
- **Expected Results**: Keycloak OIDC works end-to-end

### TestE2E_BackendCircuitBreaker
- **Description**: Test gateway with backend circuit breaker
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure backend with circuit breaker
  2. Start gateway
  3. Verify circuit breaker allows requests when closed
  4. Simulate backend failures
  5. Verify circuit breaker opens on backend failures
  6. Verify circuit breaker returns 503 when open
  7. Test circuit breaker recovery after timeout
- **Expected Results**: Backend circuit breaker works end-to-end

### TestE2E_RouteConfig_CompleteFlow
- **Description**: Test complete flow with route-level configurations
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure multiple routes with different settings
  2. Start gateway
  3. Test route with custom request limits
  4. Test route with custom CORS settings
  5. Test route with custom security headers
  6. Verify each route behaves independently
- **Expected Results**: Route-level configurations work end-to-end

### TestE2E_BackendAuth_CompleteFlow
- **Description**: Test complete flow with backend authentication
- **Preconditions**: Backend service running, Vault/Keycloak available
- **Steps**:
  1. Configure backends with different auth types
  2. Start gateway
  3. Test JWT auth with OIDC token acquisition
  4. Test Basic auth with Vault credentials
  5. Test mTLS auth with certificate management
  6. Verify authentication headers are injected
- **Expected Results**: Backend authentication works end-to-end

### TestE2E_MixedConfiguration
- **Description**: Test gateway with mixed global and specific configurations
- **Preconditions**: Multiple backend services running
- **Steps**:
  1. Configure global settings (rate limit, CORS, security)
  2. Configure route-level overrides
  3. Configure backend-level circuit breakers and auth
  4. Start gateway
  5. Test inheritance and override behavior
  6. Verify independent operation of each component
- **Expected Results**: Mixed configuration levels work correctly together

### TestE2E_ConfigurationHotReload_NewFeatures
- **Description**: Test hot reload with new configuration features
- **Preconditions**: Gateway running
- **Steps**:
  1. Start gateway with basic configuration
  2. Add route-level request limits via hot reload
  3. Add backend authentication via hot reload
  4. Add backend circuit breaker via hot reload
  5. Verify new configurations are applied without restart
- **Expected Results**: New features support hot reload correctly

## Vault PKI Integration Tests

### TestFunctional_VaultPKI_ListenerTLS
- **Description**: Test Vault PKI integration for listener-level TLS
- **Preconditions**: Vault server running with PKI enabled
- **Steps**:
  1. Configure listener with Vault PKI certificate
  2. Verify certificate issuance from Vault
  3. Test TLS handshake with issued certificate
  4. Verify certificate expiry metrics
  5. Test certificate renewal before expiry
- **Expected Results**: Listener TLS works with Vault-issued certificates

### TestFunctional_VaultPKI_RouteTLS
- **Description**: Test Vault PKI integration for route-level TLS
- **Preconditions**: Vault server running with PKI enabled
- **Steps**:
  1. Configure route with Vault PKI certificate
  2. Verify certificate issuance for route
  3. Test SNI-based certificate selection
  4. Verify route-specific certificate metrics
  5. Test automatic certificate renewal
- **Expected Results**: Route TLS works with Vault-issued certificates

### TestFunctional_VaultPKI_BackendMTLS
- **Description**: Test Vault PKI integration for backend mTLS
- **Preconditions**: Vault server running with PKI enabled, backend with mTLS
- **Steps**:
  1. Configure backend with Vault PKI client certificate
  2. Verify client certificate issuance
  3. Test mTLS connection to backend
  4. Verify backend authentication metrics
  5. Test client certificate renewal
- **Expected Results**: Backend mTLS works with Vault-issued client certificates

### TestFunctional_VaultPKI_CertificateRenewal
- **Description**: Test automatic certificate renewal with Vault PKI
- **Preconditions**: Vault server running
- **Steps**:
  1. Issue certificate with short TTL (1 hour)
  2. Configure renewal before expiry (10 minutes)
  3. Wait for renewal trigger
  4. Verify new certificate issuance
  5. Verify hot-swap without service interruption
  6. Test renewal failure handling
- **Expected Results**: Certificates renew automatically without downtime

### TestFunctional_VaultPKI_MultiTenant
- **Description**: Test Vault PKI with multi-tenant configuration
- **Preconditions**: Vault server with multiple PKI mounts
- **Steps**:
  1. Configure multiple routes with different PKI mounts
  2. Verify certificate isolation between tenants
  3. Test SNI-based certificate selection
  4. Verify independent renewal schedules
  5. Test tenant-specific CA validation
- **Expected Results**: Multi-tenant PKI isolation works correctly

### TestIntegration_VaultPKI_Authentication
- **Description**: Test Vault authentication methods for PKI
- **Preconditions**: Vault server with auth methods configured
- **Steps**:
  1. Test Kubernetes authentication
  2. Test AppRole authentication
  3. Test token authentication
  4. Test AWS IAM authentication
  5. Test GCP authentication
  6. Verify token renewal and rotation
- **Expected Results**: All authentication methods work for PKI operations

### TestIntegration_VaultPKI_FailureHandling
- **Description**: Test Vault PKI failure scenarios
- **Preconditions**: Vault server running
- **Steps**:
  1. Test Vault server unavailability
  2. Test PKI role permission errors
  3. Test certificate issuance failures
  4. Test network connectivity issues
  5. Verify graceful degradation
  6. Test recovery after failures
- **Expected Results**: Failures are handled gracefully with proper fallbacks

### TestIntegration_VaultPKI_Metrics
- **Description**: Test Vault PKI metrics and monitoring
- **Preconditions**: Vault server running, Prometheus enabled
- **Steps**:
  1. Issue certificates and verify expiry metrics
  2. Trigger renewals and verify renewal metrics
  3. Cause failures and verify error metrics
  4. Test certificate validity duration metrics
  5. Verify Vault operation metrics
- **Expected Results**: All PKI operations are properly monitored

### TestE2E_VaultPKI_CompleteFlow
- **Description**: Test complete Vault PKI integration end-to-end
- **Preconditions**: Vault server, backend services, monitoring stack
- **Steps**:
  1. Start gateway with Vault PKI configuration
  2. Verify listener certificate from Vault
  3. Test route-level certificates with SNI
  4. Test backend mTLS with Vault client certificates
  5. Verify automatic renewal across all certificate types
  6. Test certificate metrics and alerting
  7. Simulate failure scenarios and recovery
- **Expected Results**: Complete Vault PKI integration works end-to-end

### TestE2E_VaultPKI_HotReload
- **Description**: Test Vault PKI configuration hot-reload
- **Preconditions**: Gateway running with Vault PKI
- **Steps**:
  1. Start gateway with initial Vault PKI config
  2. Update PKI configuration (new role, TTL, etc.)
  3. Verify configuration reload without restart
  4. Test new certificates with updated config
  5. Verify existing certificates continue working
- **Expected Results**: Vault PKI configuration supports hot-reload

### TestE2E_VaultPKI_HighAvailability
- **Description**: Test Vault PKI with high availability setup
- **Preconditions**: Vault HA cluster, multiple gateway instances
- **Steps**:
  1. Deploy multiple gateway instances with Vault PKI
  2. Test certificate issuance across instances
  3. Simulate Vault node failures
  4. Verify automatic failover
  5. Test certificate consistency across instances
- **Expected Results**: Vault PKI works correctly in HA setup

### TestE2E_VaultPKI_Security
- **Description**: Test Vault PKI security features
- **Preconditions**: Vault server with security policies
- **Steps**:
  1. Test least-privilege PKI policies
  2. Verify certificate validation and chains
  3. Test client certificate authentication
  4. Verify audit logging for PKI operations
  5. Test certificate revocation handling
- **Expected Results**: All security features work correctly

## New Features Comprehensive Tests

### TestComprehensive_RouteLevel_AllFeatures
- **Description**: Comprehensive test of all route-level features including Vault PKI
- **Preconditions**: Backend service running, Vault server available
- **Steps**:
  1. Configure route with all new features (RequestLimits, CORS, Security, Vault PKI)
  2. Test request limits enforcement
  3. Test CORS preflight and actual requests
  4. Test security headers injection
  5. Test Vault PKI certificate issuance and renewal
  6. Test feature interaction and precedence
  7. Test configuration validation
- **Expected Results**: All route-level features work together correctly

### TestComprehensive_BackendLevel_AllFeatures
- **Description**: Comprehensive test of all backend-level features
- **Preconditions**: Backend services running, Vault/Keycloak available
- **Steps**:
  1. Configure backend with circuit breaker and all auth types
  2. Test circuit breaker behavior under load
  3. Test JWT authentication with token refresh
  4. Test Basic authentication with Vault
  5. Test mTLS authentication with certificate rotation
  6. Test feature interaction and error handling
- **Expected Results**: All backend-level features work together correctly

### TestComprehensive_ConfigurationLevels_Precedence
- **Description**: Test configuration precedence across all levels
- **Preconditions**: Multiple backend services running
- **Steps**:
  1. Configure global settings for all features
  2. Configure route-level overrides
  3. Configure backend-level overrides
  4. Test precedence rules (route > global, backend > global)
  5. Test inheritance when overrides are not specified
  6. Test complex scenarios with mixed configurations
- **Expected Results**: Configuration precedence works correctly

### TestComprehensive_Performance_NewFeatures
- **Description**: Performance test with all new features enabled
- **Preconditions**: Load testing tools available
- **Steps**:
  1. Configure gateway with all new features enabled
  2. Run load test with concurrent requests
  3. Measure latency impact of route-level configs
  4. Measure latency impact of backend authentication
  5. Measure circuit breaker performance
  6. Test memory usage and resource consumption
- **Expected Results**: New features have minimal performance impact

### TestComprehensive_Security_NewFeatures
- **Description**: Security test of all new authentication features
- **Preconditions**: Security testing tools available
- **Steps**:
  1. Test JWT token validation and expiry
  2. Test Basic auth credential security
  3. Test mTLS certificate validation
  4. Test Vault integration security
  5. Test OIDC token acquisition security
  6. Test error handling without information leakage
- **Expected Results**: All authentication features are secure

### TestComprehensive_Monitoring_NewFeatures
- **Description**: Test monitoring and observability of new features
- **Preconditions**: Monitoring stack available
- **Steps**:
  1. Enable metrics for all new features
  2. Test circuit breaker metrics
  3. Test authentication metrics
  4. Test route-level configuration metrics
  5. Test error rate and latency metrics
  6. Verify alerting on feature failures
- **Expected Results**: All new features are properly monitored

## Max Sessions Tests

### TestFunctional_MaxSessions_GlobalLevel
- **Description**: Test global max sessions configuration
- **Preconditions**: None
- **Steps**:
  1. Create gateway config with global max sessions enabled
  2. Set maxConcurrent to 2
  3. Send 5 concurrent requests
  4. Verify at least 2 succeed and at least 1 is rejected
- **Expected Results**: Global max sessions limits concurrent requests

### TestFunctional_MaxSessions_RouteLevel
- **Description**: Test route-level max sessions configuration
- **Preconditions**: None
- **Steps**:
  1. Create route with custom max sessions config
  2. Verify route config overrides global config
  3. Test disabled route overrides enabled global
- **Expected Results**: Route-level max sessions overrides global

### TestFunctional_MaxSessions_BackendLevel
- **Description**: Test backend max sessions configuration
- **Preconditions**: None
- **Steps**:
  1. Create backend with max sessions config
  2. Verify hosts have max sessions enabled
  3. Test connection limiting per host
- **Expected Results**: Backend max sessions limits connections per host

### TestFunctional_MaxSessions_Inheritance
- **Description**: Test config inheritance from global to route level
- **Preconditions**: None
- **Steps**:
  1. Configure global max sessions
  2. Create route without max sessions config
  3. Verify route inherits global config
  4. Create route with override
  5. Verify route uses its own config
- **Expected Results**: Routes inherit global config unless overridden

### TestFunctional_MaxSessions_Validation
- **Description**: Test max sessions config validation
- **Preconditions**: None
- **Steps**:
  1. Test valid config with all fields
  2. Test default queue timeout when not specified
  3. Test zero queue size means reject immediately
- **Expected Results**: Config validation works correctly

### TestIntegration_MaxSessions_WithRealBackends
- **Description**: Test max sessions with real backend services
- **Preconditions**: Backend services running
- **Steps**:
  1. Create backend with max sessions enabled
  2. Get hosts up to max concurrent limit
  3. Verify additional requests fail
  4. Release host and verify new request succeeds
- **Expected Results**: Max sessions enforced with real backends

### TestIntegration_MaxSessions_ConcurrentRequests
- **Description**: Test max sessions under concurrent load
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure backend with max sessions
  2. Start many concurrent requests
  3. Track max concurrent connections
  4. Verify limit is not exceeded
- **Expected Results**: Concurrent requests respect max sessions

### TestIntegration_MaxSessions_QueueBehavior
- **Description**: Test queue functionality for max sessions
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure max sessions with queue
  2. Fill capacity
  3. Verify requests queue
  4. Release capacity
  5. Verify queued requests complete
- **Expected Results**: Queue behavior works correctly

### TestE2E_MaxSessions_GlobalLimit
- **Description**: Test full gateway with global max sessions
- **Preconditions**: Backend services running
- **Steps**:
  1. Start gateway with global max sessions config
  2. Make concurrent requests through gateway
  3. Verify max sessions is enforced
- **Expected Results**: Global max sessions works end-to-end

### TestE2E_MaxSessions_RouteOverride
- **Description**: Test route overrides global max sessions
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure global max sessions (permissive)
  2. Configure route max sessions (restrictive)
  3. Verify route uses its own config
- **Expected Results**: Route override works end-to-end

### TestE2E_MaxSessions_BackendLimit
- **Description**: Test backend-level max sessions
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure backend with max sessions
  2. Start gateway
  3. Verify backend hosts have max sessions enabled
- **Expected Results**: Backend max sessions works end-to-end

### TestE2E_MaxSessions_Recovery
- **Description**: Test recovery after sessions released
- **Preconditions**: Backend services running
- **Steps**:
  1. Fill max sessions capacity
  2. Complete requests (release sessions)
  3. Verify new requests succeed
  4. Test queue drains after capacity freed
- **Expected Results**: Sessions are properly released

## Backend Rate Limit Tests

### TestFunctional_BackendRateLimit_Config
- **Description**: Test backend rate limit configuration
- **Preconditions**: None
- **Steps**:
  1. Create backend with rate limit config
  2. Verify hosts have rate limiting enabled
  3. Test disabled rate limit does not limit hosts
  4. Test nil rate limit config
- **Expected Results**: Rate limit config applied correctly

### TestFunctional_BackendRateLimit_Validation
- **Description**: Test rate limit config validation
- **Preconditions**: None
- **Steps**:
  1. Test valid rate limit config
  2. Test burst defaults to RPS when zero
  3. Test per client flag
- **Expected Results**: Config validation works correctly

### TestFunctional_BackendRateLimit_HostBehavior
- **Description**: Test host rate limiter behavior
- **Preconditions**: None
- **Steps**:
  1. Create host with rate limiter
  2. Verify burst requests allowed
  3. Verify requests denied after burst exhausted
  4. Wait for token replenishment
  5. Verify requests allowed again
- **Expected Results**: Host rate limiter works correctly

### TestIntegration_BackendRateLimit_WithRealBackends
- **Description**: Test backend rate limit with real backends
- **Preconditions**: Backend services running
- **Steps**:
  1. Create backend with rate limit
  2. Make requests up to burst limit
  3. Verify additional requests are rate limited
  4. Wait for recovery
  5. Verify requests succeed again
- **Expected Results**: Rate limit enforced with real backends

### TestIntegration_BackendRateLimit_LoadBalancerIntegration
- **Description**: Test rate limit with load balancer
- **Preconditions**: Multiple backend services running
- **Steps**:
  1. Configure backend with multiple hosts and rate limit
  2. Make requests through load balancer
  3. Verify rate limit per host is independent
  4. Verify load balancer tries next host when rate limited
- **Expected Results**: Rate limit integrates with load balancer

### TestE2E_BackendRateLimit_Enforcement
- **Description**: Test rate limit enforcement end-to-end
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure backend with rate limit
  2. Start gateway
  3. Make requests up to burst limit
  4. Verify rate limiting kicks in
- **Expected Results**: Rate limit enforced end-to-end

### TestE2E_BackendRateLimit_Recovery
- **Description**: Test rate limit recovery
- **Preconditions**: Backend services running
- **Steps**:
  1. Exhaust rate limit burst
  2. Wait for token replenishment
  3. Verify requests succeed again
  4. Test sustained rate within limit
- **Expected Results**: Rate limit recovers correctly

## Load Balancer Capacity Tests

### TestIntegration_LoadBalancer_SkipsHostsAtCapacity
- **Description**: Test load balancer skips hosts at max sessions capacity
- **Preconditions**: None
- **Steps**:
  1. Create hosts with max sessions enabled
  2. Fill first host to capacity
  3. Verify load balancer selects second host
  4. Fill second host to capacity
  5. Verify load balancer returns nil
- **Expected Results**: Load balancer respects max sessions

### TestIntegration_LoadBalancer_ConsidersRateLimit
- **Description**: Test load balancer considers rate limit
- **Preconditions**: None
- **Steps**:
  1. Create hosts with rate limiting
  2. Exhaust rate limit on first host
  3. Verify load balancer still returns host (rate limit checked separately)
  4. Verify AllowRequest returns false for rate limited host
- **Expected Results**: Rate limit is checked separately from availability

## Max Sessions and Backend Rate Limit E2E Tests

### TestE2E_MaxSessions_GlobalEnforcement
- **Description**: Test global max sessions enforcement end-to-end
- **Preconditions**: Backend services running
- **Steps**:
  1. Start gateway with global max sessions (limit: 5)
  2. Make 10 concurrent requests
  3. Verify 5 succeed and 5 are queued or rejected
  4. Complete some requests
  5. Verify queued requests are processed
- **Expected Results**: Global max sessions enforced correctly

### TestE2E_MaxSessions_RouteOverride
- **Description**: Test route-level max sessions override
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure global max sessions (limit: 100)
  2. Configure route max sessions (limit: 5)
  3. Make requests to route
  4. Verify route limit is enforced, not global
- **Expected Results**: Route override works correctly

### TestE2E_MaxSessions_BackendLimit
- **Description**: Test backend-level max sessions
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure backend with max sessions (limit: 3)
  2. Make concurrent requests to backend
  3. Verify backend host limits are enforced
  4. Test with multiple hosts
- **Expected Results**: Backend max sessions enforced per host

### TestE2E_MaxSessions_QueueBehavior
- **Description**: Test max sessions queue functionality
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure max sessions with queue (limit: 2, queue: 3)
  2. Make 8 concurrent requests
  3. Verify 2 active, 3 queued, 3 rejected
  4. Complete active requests
  5. Verify queued requests are processed
- **Expected Results**: Queue behavior works correctly

### TestE2E_MaxSessions_QueueTimeout
- **Description**: Test max sessions queue timeout
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure max sessions with short queue timeout (1s)
  2. Fill capacity and queue
  3. Wait for queue timeout
  4. Verify queued requests timeout with 503
- **Expected Results**: Queue timeout works correctly

### TestE2E_BackendRateLimit_Enforcement
- **Description**: Test backend rate limit enforcement
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure backend with rate limit (5 RPS, burst 10)
  2. Send burst of 15 requests quickly
  3. Verify first 10 succeed, rest are rate limited
  4. Wait for token replenishment
  5. Verify requests succeed again
- **Expected Results**: Backend rate limit enforced correctly

### TestE2E_BackendRateLimit_LoadBalancerIntegration
- **Description**: Test backend rate limit with load balancer
- **Preconditions**: Multiple backend services running
- **Steps**:
  1. Configure backend with 2 hosts, rate limit per host
  2. Exhaust rate limit on first host
  3. Verify load balancer routes to second host
  4. Exhaust both hosts
  5. Verify requests are rejected
- **Expected Results**: Load balancer integrates with rate limiting

### TestE2E_BackendRateLimit_Recovery
- **Description**: Test backend rate limit recovery
- **Preconditions**: Backend services running
- **Steps**:
  1. Exhaust backend rate limit
  2. Wait for token bucket refill
  3. Verify requests succeed again
  4. Test sustained rate within limit
- **Expected Results**: Rate limit recovers correctly

### TestE2E_LoadBalancer_CapacityAware
- **Description**: Test capacity-aware load balancing
- **Preconditions**: Multiple backend services running
- **Steps**:
  1. Configure backends with max sessions and leastConn algorithm
  2. Fill first host to capacity
  3. Verify load balancer routes to second host
  4. Test with different capacity limits
- **Expected Results**: Load balancer considers host capacity

### TestE2E_LoadBalancer_RateLimitAware
- **Description**: Test rate limit aware load balancing
- **Preconditions**: Multiple backend services running
- **Steps**:
  1. Configure backends with rate limits
  2. Exhaust rate limit on first host
  3. Verify load balancer tries next host
  4. Test with all hosts rate limited
- **Expected Results**: Load balancer considers rate limits

### TestE2E_CombinedLimits_MaxSessionsAndRateLimit
- **Description**: Test combined max sessions and rate limiting
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure both max sessions and rate limiting
  2. Test max sessions limit reached first
  3. Test rate limit reached first
  4. Test both limits together
  5. Verify correct error responses
- **Expected Results**: Both limits work together correctly

### TestE2E_ConfigurationInheritance_MaxSessions
- **Description**: Test max sessions configuration inheritance
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure global max sessions (100)
  2. Configure route override (50)
  3. Configure backend override (25)
  4. Test inheritance chain
  5. Verify most specific config wins
- **Expected Results**: Configuration inheritance works correctly

### TestE2E_ConfigurationInheritance_RateLimit
- **Description**: Test rate limit configuration inheritance
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure global rate limit (100 RPS)
  2. Configure route override (50 RPS)
  3. Configure backend override (25 RPS)
  4. Test inheritance chain
  5. Verify most specific config wins
- **Expected Results**: Configuration inheritance works correctly

### TestE2E_HotReload_NewTrafficFeatures
- **Description**: Test hot reload with new traffic management features
- **Preconditions**: Gateway running
- **Steps**:
  1. Start gateway with basic config
  2. Add max sessions via hot reload
  3. Add backend rate limiting via hot reload
  4. Verify new limits are enforced
  5. Modify limits via hot reload
  6. Verify changes take effect
- **Expected Results**: Hot reload works with new features

### TestE2E_Metrics_TrafficManagement
- **Description**: Test metrics for traffic management features
- **Preconditions**: Gateway running with metrics enabled
- **Steps**:
  1. Configure max sessions and rate limiting
  2. Generate traffic to trigger limits
  3. Check max sessions metrics
  4. Check rate limit metrics
  5. Check load balancer metrics
- **Expected Results**: All metrics are properly exposed

### TestE2E_CircuitBreaker_WithTrafficLimits
- **Description**: Test circuit breaker with traffic limits
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure circuit breaker, max sessions, and rate limiting
  2. Trigger circuit breaker with failures
  3. Verify traffic limits still apply when circuit is open
  4. Test circuit breaker recovery with limits
- **Expected Results**: Circuit breaker works with traffic limits

### TestE2E_HealthCheck_WithTrafficLimits
- **Description**: Test health checking with traffic limits
- **Preconditions**: Backend services running
- **Steps**:
  1. Configure health checks with max sessions and rate limiting
  2. Verify health checks bypass traffic limits
  3. Test unhealthy backend with traffic limits
  4. Verify traffic is not routed to unhealthy backends
- **Expected Results**: Health checks work correctly with traffic limits

### TestE2E_GracefulShutdown_WithActiveSessions
- **Description**: Test graceful shutdown with active sessions
- **Preconditions**: Gateway running with active connections
- **Steps**:
  1. Fill max sessions capacity
  2. Initiate graceful shutdown
  3. Verify active sessions complete
  4. Verify new sessions are rejected
  5. Verify queued sessions are handled
- **Expected Results**: Graceful shutdown handles active sessions correctly

## Performance and Stress Tests

### TestPerformance_MaxSessions_HighConcurrency
- **Description**: Performance test with high concurrency and max sessions
- **Preconditions**: Load testing tools available
- **Steps**:
  1. Configure max sessions with high limits
  2. Generate high concurrent load
  3. Measure latency impact of max sessions
  4. Measure throughput with limits
  5. Test queue performance under load
- **Expected Results**: Max sessions has minimal performance impact

### TestPerformance_BackendRateLimit_HighThroughput
- **Description**: Performance test with backend rate limiting
- **Preconditions**: Load testing tools available
- **Steps**:
  1. Configure backend rate limiting
  2. Generate high throughput load
  3. Measure latency impact of rate limiting
  4. Test token bucket performance
  5. Measure load balancer performance
- **Expected Results**: Backend rate limiting has minimal performance impact

### TestStress_CombinedLimits_ExtremLoad
- **Description**: Stress test with all traffic limits under extreme load
- **Preconditions**: Load testing tools available
- **Steps**:
  1. Configure all traffic management features
  2. Generate extreme load (10x normal capacity)
  3. Verify system remains stable
  4. Verify limits are enforced correctly
  5. Measure resource usage
- **Expected Results**: System remains stable under extreme load

## Security Tests

### TestSecurity_MaxSessions_DenialOfService
- **Description**: Test max sessions protection against DoS attacks
- **Preconditions**: Attack simulation tools available
- **Steps**:
  1. Configure max sessions with reasonable limits
  2. Simulate connection flood attack
  3. Verify legitimate traffic still works
  4. Verify attack traffic is limited
  5. Test recovery after attack
- **Expected Results**: Max sessions protects against DoS attacks

### TestSecurity_RateLimit_BruteForce
- **Description**: Test rate limiting protection against brute force
- **Preconditions**: Attack simulation tools available
- **Steps**:
  1. Configure rate limiting
  2. Simulate brute force attack
  3. Verify rate limiting kicks in
  4. Verify legitimate traffic still works
  5. Test different attack patterns
- **Expected Results**: Rate limiting protects against brute force

### TestSecurity_CombinedProtection_MultiVector
- **Description**: Test combined protection against multi-vector attacks
- **Preconditions**: Attack simulation tools available
- **Steps**:
  1. Configure all traffic protection features
  2. Simulate combined attack (DoS + brute force)
  3. Verify all protections work together
  4. Verify legitimate traffic still works
  5. Test attack mitigation effectiveness
- **Expected Results**: Combined protections work effectively together

## Route-Level TLS Tests

### Functional Tests

#### TestFunctional_RouteTLS_ConfigParsing
- **Description**: Test route TLS configuration parsing and validation
- **Preconditions**: None
- **Steps**:
  1. Create route TLS config with valid file-based certificates
  2. Create route TLS config with multiple SNI hosts
  3. Create route TLS config with wildcard SNI
  4. Create route TLS config with TLS versions
  5. Create route TLS config with client validation
  6. Test invalid configurations (missing cert, missing key, invalid SNI)
- **Expected Results**: Valid configs pass validation, invalid configs return errors

#### TestFunctional_RouteTLS_SNIHostMatching
- **Description**: Test SNI host matching logic
- **Preconditions**: None
- **Steps**:
  1. Test exact SNI match
  2. Test case-insensitive matching
  3. Test wildcard single-level match
  4. Test wildcard multi-level no match
  5. Test wildcard root domain no match
- **Expected Results**: SNI matching works correctly for all patterns

#### TestFunctional_RouteTLS_CertificateSelection
- **Description**: Test certificate selection logic
- **Preconditions**: Test certificates generated
- **Steps**:
  1. Add multiple routes with different SNI hosts
  2. Test exact SNI match selects correct route
  3. Test wildcard SNI match selects correct route
  4. Test exact match takes precedence over wildcard
  5. Test no match falls back to listener
- **Expected Results**: Correct certificate is selected for each SNI

#### TestFunctional_RouteTLS_Validation
- **Description**: Test route TLS validation
- **Preconditions**: None
- **Steps**:
  1. Test valid config passes validation
  2. Test missing cert file fails validation
  3. Test missing key file fails validation
  4. Test no certificate source fails validation
- **Expected Results**: Validation correctly identifies invalid configs

#### TestFunctional_RouteTLS_RouteHasTLSOverride
- **Description**: Test HasTLSOverride method
- **Preconditions**: None
- **Steps**:
  1. Test route without TLS config returns false
  2. Test route with empty TLS config returns false
  3. Test route with cert files returns true
  4. Test route with Vault enabled returns true
- **Expected Results**: HasTLSOverride correctly identifies TLS overrides

#### TestFunctional_RouteTLS_GetEffectiveSNIHosts
- **Description**: Test GetEffectiveSNIHosts method
- **Preconditions**: None
- **Steps**:
  1. Test route without TLS config returns nil
  2. Test route with empty SNI hosts returns nil
  3. Test route with single SNI host returns correct list
  4. Test route with multiple SNI hosts returns correct list
- **Expected Results**: GetEffectiveSNIHosts returns correct SNI hosts

#### TestFunctional_RouteTLS_WildcardMatching
- **Description**: Test wildcard SNI matching edge cases
- **Preconditions**: None
- **Steps**:
  1. Test single label match
  2. Test multi-level subdomain no match
  3. Test root domain no match
  4. Test case insensitive match
  5. Test numeric and hyphenated subdomains
- **Expected Results**: Wildcard matching handles all edge cases correctly

### Integration Tests

#### TestIntegration_RouteTLS_SNIBasedCertificateSelection
- **Description**: Test SNI-based certificate selection with actual TLS connections
- **Preconditions**: Test certificates generated
- **Steps**:
  1. Generate certificates for different domains
  2. Create route TLS manager with multiple routes
  3. Start TLS server with SNI-based selection
  4. Connect with api.example.com SNI
  5. Connect with www.example.com SNI
- **Expected Results**: Correct certificate is served for each SNI

#### TestIntegration_RouteTLS_WildcardSNI
- **Description**: Test wildcard SNI certificate selection
- **Preconditions**: Wildcard certificate generated
- **Steps**:
  1. Generate wildcard certificate
  2. Add wildcard route
  3. Test various subdomains (api, www, admin, test)
- **Expected Results**: Wildcard certificate serves all matching subdomains

#### TestIntegration_RouteTLS_FallbackToListener
- **Description**: Test fallback to listener certificate
- **Preconditions**: Listener and route certificates generated
- **Steps**:
  1. Create base TLS manager (listener level)
  2. Create route TLS manager with base manager
  3. Add route for specific SNI
  4. Test route-specific SNI uses route certificate
  5. Test unknown SNI falls back to listener certificate
- **Expected Results**: Fallback works correctly for unknown SNI

#### TestIntegration_RouteTLS_MultipleRoutes
- **Description**: Test multiple routes with different certificates
- **Preconditions**: Multiple tenant certificates generated
- **Steps**:
  1. Generate certificates for multiple tenants
  2. Add routes for each tenant
  3. Test each tenant gets correct certificate
- **Expected Results**: Each tenant receives their specific certificate

#### TestIntegration_RouteTLS_CertificateHotReload
- **Description**: Test certificate hot-reload for routes
- **Preconditions**: Test certificates generated
- **Steps**:
  1. Add route with initial certificate
  2. Start manager
  3. Get initial certificate
  4. Overwrite certificate files
  5. Trigger reload
  6. Verify certificate changed
- **Expected Results**: Certificate is reloaded without restart

#### TestIntegration_RouteTLS_MTLSAtRouteLevel
- **Description**: Test mTLS at the route level
- **Preconditions**: Server and client certificates generated
- **Steps**:
  1. Add route with client validation
  2. Test with valid client certificate
  3. Test without client certificate fails
- **Expected Results**: mTLS works correctly at route level

#### TestIntegration_RouteTLS_ConcurrentAccess
- **Description**: Test concurrent access to route TLS manager
- **Preconditions**: Test certificates generated
- **Steps**:
  1. Add route
  2. Concurrent certificate requests (100 goroutines)
  3. Concurrent route queries (100 goroutines)
- **Expected Results**: No race conditions or errors

#### TestIntegration_RouteTLS_RouteAddRemove
- **Description**: Test adding and removing routes dynamically
- **Preconditions**: Test certificates generated
- **Steps**:
  1. Add first route
  2. Add second route
  3. Verify both routes work
  4. Remove first route
  5. Verify first route no longer works
  6. Verify second route still works
- **Expected Results**: Routes can be added and removed dynamically

### E2E Tests

#### TestE2E_RouteTLS_MultiTenantScenario
- **Description**: Test multi-tenant scenario with different certificates per tenant
- **Preconditions**: Tenant certificates generated
- **Steps**:
  1. Generate certificates for multiple tenants
  2. Add routes for each tenant
  3. Start TLS server
  4. Test each tenant receives correct certificate
  5. Verify tenant isolation
- **Expected Results**: Multi-tenant TLS works correctly

#### TestE2E_RouteTLS_MTLSWithClientCertificates
- **Description**: Test route-level mTLS with client certificates
- **Preconditions**: Server and client certificates generated
- **Steps**:
  1. Add route with mTLS
  2. Test with valid client certificate
  3. Test without client certificate fails
  4. Test with invalid client certificate fails
- **Expected Results**: mTLS authentication works correctly

#### TestE2E_RouteTLS_CertificateExpiryHandling
- **Description**: Test handling of certificate expiry
- **Preconditions**: Expired certificate generated
- **Steps**:
  1. Generate expired certificate
  2. Add route with expired certificate
  3. Start TLS server
  4. Client should reject expired certificate
- **Expected Results**: Expired certificates are rejected

#### TestE2E_RouteTLS_GatewayRoutingIntegration
- **Description**: Test route-level TLS with gateway routing
- **Preconditions**: API version certificates generated
- **Steps**:
  1. Generate certificates for different API versions
  2. Add routes for each version
  3. Start TLS server with routing
  4. Test API v1 route
  5. Test API v2 route
- **Expected Results**: Routing works correctly with route-level TLS

#### TestE2E_RouteTLS_WildcardCertificateScenario
- **Description**: Test wildcard certificate scenarios
- **Preconditions**: Wildcard certificate generated
- **Steps**:
  1. Generate wildcard certificate
  2. Add wildcard route
  3. Test various subdomains
- **Expected Results**: Wildcard certificate serves all matching subdomains

#### TestE2E_RouteTLS_CertificateHotReloadScenario
- **Description**: Test certificate hot-reload in realistic scenario
- **Preconditions**: Test certificates generated
- **Steps**:
  1. Add route with initial certificate
  2. Start manager and TLS server
  3. Make initial request
  4. Overwrite certificate files
  5. Trigger reload
  6. Make request with new certificate
- **Expected Results**: Certificate reload works without downtime

#### TestE2E_RouteTLS_MixedExactAndWildcard
- **Description**: Test mixed exact and wildcard SNI matching
- **Preconditions**: Exact and wildcard certificates generated
- **Steps**:
  1. Add exact match route
  2. Add wildcard route
  3. Test exact match takes precedence
  4. Test wildcard matches other subdomains
- **Expected Results**: Exact match takes precedence over wildcard

## Audit Stdout Feature Tests

### Functional Tests

#### TestFunctional_AuditConfig_StdoutOutput
- **Description**: Test audit config with stdout output validation
- **Preconditions**: None
- **Steps**:
  1. Create config with explicit stdout output
  2. Verify stdout output is valid
  3. Create config with empty output
  4. Verify empty output defaults to stdout
  5. Create config with stderr output
  6. Verify default config uses stdout
- **Expected Results**: Stdout is the default and valid output destination

#### TestFunctional_AuditConfig_EventsMapping
- **Description**: Test audit events config mapping
- **Preconditions**: None
- **Steps**:
  1. Create config with all events enabled
  2. Verify all ShouldAudit* methods return true
  3. Create config with all events disabled
  4. Verify all ShouldAudit* methods return false
  5. Test nil events config uses defaults
  6. Test disabled config disables all events
- **Expected Results**: Events mapping correctly reflects configuration

#### TestFunctional_AuditConfig_MiddlewareIntegration
- **Description**: Test audit config integration with middleware
- **Preconditions**: None
- **Steps**:
  1. Create config suitable for middleware use
  2. Verify all effective values are correct
  3. Verify skip paths work
  4. Test default config creates valid logger
  5. Test text format is valid
- **Expected Results**: Config integrates correctly with middleware

#### TestFunctional_AuditMiddleware_Enabled
- **Description**: Test audit middleware with enabled config
- **Preconditions**: None
- **Steps**:
  1. Create audit logger with buffer writer
  2. Wrap handler with audit middleware
  3. Send HTTP request
  4. Verify request and response events are logged
  5. Verify correct status code capture
  6. Verify request details (method, path, query, content-type)
- **Expected Results**: Audit middleware logs request and response events

#### TestFunctional_AuditMiddleware_Disabled
- **Description**: Test audit middleware with disabled config
- **Preconditions**: None
- **Steps**:
  1. Create disabled audit config
  2. Wrap handler with audit middleware
  3. Send HTTP request
  4. Verify no audit output is produced
  5. Test with noop logger
- **Expected Results**: Disabled audit produces no events

#### TestFunctional_AuditMiddleware_SkipPaths
- **Description**: Test audit middleware respects skip paths
- **Preconditions**: None
- **Steps**:
  1. Configure skip paths (/health, /metrics, /internal/*)
  2. Send requests to skip paths
  3. Verify no audit output for skipped paths
  4. Send requests to non-skip paths
  5. Verify audit output for non-skip paths
- **Expected Results**: Skip paths are respected

#### TestFunctional_AuditMiddleware_RedactFields
- **Description**: Test audit middleware redacts sensitive fields
- **Preconditions**: None
- **Steps**:
  1. Configure redact fields (password, secret, token, authorization)
  2. Send request with Authorization header
  3. Verify raw token does not appear in audit output
- **Expected Results**: Sensitive fields are redacted

#### TestFunctional_AuditMiddleware_EventTypes
- **Description**: Test audit middleware event type filtering
- **Preconditions**: None
- **Steps**:
  1. Enable only request events
  2. Verify only request events are logged
  3. Enable only response events
  4. Verify only response events are logged
  5. Disable both
  6. Verify no events are logged
- **Expected Results**: Event type filtering works correctly

#### TestFunctional_AuditMiddleware_RequestIDIntegration
- **Description**: Test audit middleware captures request ID
- **Preconditions**: None
- **Steps**:
  1. Chain RequestID middleware before Audit middleware
  2. Send request with X-Request-ID header
  3. Verify request_id appears in audit event metadata
- **Expected Results**: Request ID is captured in audit events

#### TestFunctional_AuditMiddleware_ResponseWriterCapture
- **Description**: Test audit middleware captures response details
- **Preconditions**: None
- **Steps**:
  1. Send request that produces response body
  2. Verify response body size is captured
  3. Send request without explicit WriteHeader
  4. Verify default 200 status is captured
- **Expected Results**: Response details are correctly captured

#### TestFunctional_AuditMiddleware_HTTPMethods
- **Description**: Test audit middleware handles all HTTP methods
- **Preconditions**: None
- **Steps**:
  1. Send GET, POST, PUT, DELETE, PATCH requests
  2. Verify each method is correctly captured in audit events
- **Expected Results**: All HTTP methods are handled

#### TestFunctional_AuditMiddleware_ResourceInfo
- **Description**: Test audit events contain resource information
- **Preconditions**: None
- **Steps**:
  1. Send request to specific path
  2. Verify resource type is "http"
  3. Verify resource path matches request path
  4. Verify resource method matches request method
- **Expected Results**: Resource information is correctly populated

#### TestFunctional_AuditMiddleware_DurationTracking
- **Description**: Test audit response event includes duration
- **Preconditions**: None
- **Steps**:
  1. Send request through audit middleware
  2. Parse response event
  3. Verify duration is positive
- **Expected Results**: Duration is tracked in response events

### Integration Tests

#### TestIntegration_Audit_WithRealBackend
- **Description**: Test audit with real backend service
- **Preconditions**: Backend service running on port 8801
- **Steps**:
  1. Configure proxy with audit middleware
  2. Send request to real backend
  3. Verify proxy still works correctly
  4. Verify audit events are logged
  5. Verify correct status code from backend
- **Expected Results**: Audit does not interfere with proxy operation

#### TestIntegration_Audit_SkipPaths_WithRealRequests
- **Description**: Test skip paths with real backend requests
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure skip paths and routes
  2. Send request to /health (skipped)
  3. Verify no audit output
  4. Send request to /api/v1/items (audited)
  5. Verify audit output
- **Expected Results**: Skip paths work with real requests

#### TestIntegration_Audit_HTTPMethods_WithRealBackend
- **Description**: Test audit with various HTTP methods to real backend
- **Preconditions**: Backend service running
- **Steps**:
  1. Send GET, POST, PUT, DELETE to real backend
  2. Verify audit events for each method
  3. Verify correct method in audit event
- **Expected Results**: All HTTP methods are audited correctly

#### TestIntegration_Audit_NormalProxyOperation
- **Description**: Test audit does not modify proxy behavior
- **Preconditions**: Backend service running
- **Steps**:
  1. Make direct request to backend
  2. Make request through proxy with audit
  3. Compare response bodies
  4. Verify response headers are preserved
- **Expected Results**: Audit is transparent to proxy operation

#### TestIntegration_Audit_DirectResponse
- **Description**: Test audit with direct response routes
- **Preconditions**: None
- **Steps**:
  1. Configure direct response route
  2. Send request through audit middleware
  3. Verify direct response works
  4. Verify audit events are logged
- **Expected Results**: Audit works with direct response routes

#### TestIntegration_Audit_RouteNotFound
- **Description**: Test audit captures 404 for unmatched routes
- **Preconditions**: None
- **Steps**:
  1. Configure specific route
  2. Send request to non-existent path
  3. Verify 404 response
  4. Verify audit captures 404 status
- **Expected Results**: 404 responses are audited

#### TestIntegration_Audit_TextFormat
- **Description**: Test audit with text format output
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure audit with text format
  2. Send request to real backend
  3. Verify text format output contains event info
- **Expected Results**: Text format audit works correctly

#### TestIntegration_Audit_FullMiddlewareChain
- **Description**: Test audit in full middleware chain
- **Preconditions**: Backend service running
- **Steps**:
  1. Chain RequestID -> Recovery -> Audit -> Proxy
  2. Send request to real backend
  3. Verify all middleware works together
  4. Verify request_id in audit metadata
- **Expected Results**: Audit works in full middleware chain

### E2E Tests

#### TestE2E_Audit_GatewayLifecycle
- **Description**: Test gateway lifecycle with audit enabled
- **Preconditions**: Backend service running
- **Steps**:
  1. Create gateway config with audit enabled
  2. Start gateway
  3. Verify gateway is running
  4. Stop gateway
  5. Verify gateway is stopped
  6. Test with audit disabled
- **Expected Results**: Gateway starts and stops cleanly with audit

#### TestE2E_Audit_RequestProcessing
- **Description**: Test audit does not affect request processing
- **Preconditions**: Gateway and backend running
- **Steps**:
  1. Start gateway
  2. Send GET request
  3. Send POST request
  4. Send health check request
  5. Verify all responses are correct
- **Expected Results**: Audit is transparent to request processing

#### TestE2E_Audit_ResponseTimes
- **Description**: Test audit does not significantly affect response times
- **Preconditions**: Gateway and backend running
- **Steps**:
  1. Start gateway
  2. Send multiple requests
  3. Measure response times
  4. Verify all within acceptable latency
- **Expected Results**: Response times are not significantly affected

#### TestE2E_Audit_LoadBalancing
- **Description**: Test audit works with load balancing
- **Preconditions**: Two backend services running
- **Steps**:
  1. Start gateway with load balancing
  2. Send multiple requests
  3. Verify requests are distributed
  4. Verify all succeed
- **Expected Results**: Audit works with load balanced requests

#### TestE2E_Audit_ConcurrentRequests
- **Description**: Test audit handles concurrent requests
- **Preconditions**: Gateway and backend running
- **Steps**:
  1. Start gateway
  2. Send concurrent requests (10 goroutines)
  3. Verify most requests succeed
  4. Verify no errors from audit
- **Expected Results**: Concurrent requests are handled correctly

#### TestE2E_Audit_CRUD_Journey
- **Description**: Test complete CRUD journey with audit
- **Preconditions**: Gateway and backend running
- **Steps**:
  1. Create item through gateway
  2. Read items through gateway
  3. Update item through gateway
  4. Delete item through gateway
- **Expected Results**: Complete CRUD journey works with audit

#### TestE2E_Audit_GatewayConfig
- **Description**: Test gateway config includes audit settings
- **Preconditions**: None
- **Steps**:
  1. Create gateway with audit config
  2. Start gateway
  3. Get config
  4. Verify audit config is present
- **Expected Results**: Audit config is accessible from gateway

#### TestE2E_Audit_MultipleHTTPMethods
- **Description**: Test audit with multiple HTTP methods through gateway
- **Preconditions**: Gateway and backend running
- **Steps**:
  1. Start gateway
  2. Send GET to /api/v1/items
  3. Send GET to /health
  4. Send GET to /backend/health
  5. Verify all succeed
- **Expected Results**: All HTTP methods work through gateway with audit

## WebSocket Tests

### Integration Tests

#### TestIntegration_WebSocket_DirectConnection
- **Description**: Test WebSocket connection directly to backend /ws endpoint
- **Preconditions**: Backend service running with /ws WebSocket endpoint
- **Steps**:
  1. Connect to backend WebSocket endpoint
  2. Verify HTTP 101 Switching Protocols response
  3. Read a message from the WebSocket stream
  4. Verify message is non-empty text
- **Expected Results**: Direct WebSocket connection works and receives messages

#### TestIntegration_WebSocket_MessageStreaming
- **Description**: Test WebSocket message streaming from backend
- **Preconditions**: Backend service running with /ws endpoint streaming random values every 1s
- **Steps**:
  1. Connect to backend WebSocket endpoint
  2. Read 3 consecutive messages
  3. Verify all messages are received
  4. Verify messages contain different random values
- **Expected Results**: Multiple streamed messages are received with different values

#### TestIntegration_WebSocket_CloseHandling
- **Description**: Test WebSocket connection close handling
- **Preconditions**: Backend service running
- **Steps**:
  1. Connect to WebSocket, read a message, send close frame
  2. Verify graceful close completes
  3. Connect to WebSocket and close immediately without reading
  4. Verify immediate close works
- **Expected Results**: Both graceful and immediate close work correctly

#### TestIntegration_WebSocket_ConcurrentConnections
- **Description**: Test multiple concurrent WebSocket connections to backend
- **Preconditions**: Backend service running
- **Steps**:
  1. Establish 5 concurrent WebSocket connections
  2. Read 2 messages per connection
  3. Verify at least 75% of connections succeed
  4. Verify at least one message per connection
- **Expected Results**: Concurrent WebSocket connections work independently

#### TestIntegration_WebSocket_ConnectionTimeout
- **Description**: Test WebSocket read deadline and timeout behavior
- **Preconditions**: Backend service running
- **Steps**:
  1. Connect to WebSocket endpoint
  2. Set very short read deadline (1ms)
  3. Attempt to read message
  4. Verify timeout error is returned
- **Expected Results**: Read deadline causes proper timeout error

#### TestIntegration_WebSocket_UpgradeHeaders
- **Description**: Test WebSocket upgrade handshake headers
- **Preconditions**: Backend service running
- **Steps**:
  1. Connect to WebSocket endpoint
  2. Inspect upgrade response
  3. Verify HTTP 101 status code
  4. Verify Upgrade: websocket header
- **Expected Results**: Upgrade response contains correct headers

#### TestIntegration_WebSocket_InvalidEndpoint
- **Description**: Test WebSocket connection to non-WebSocket endpoint
- **Preconditions**: Backend service running
- **Steps**:
  1. Attempt WebSocket connection to /health (non-WebSocket endpoint)
  2. Verify connection fails with error
- **Expected Results**: Non-WebSocket endpoint rejects upgrade

#### TestIntegration_WebSocket_SendAndReceive
- **Description**: Test bidirectional WebSocket communication
- **Preconditions**: Backend service running
- **Steps**:
  1. Connect to WebSocket endpoint
  2. Send a text message
  3. Read the next streamed message
  4. Verify message is received
- **Expected Results**: Bidirectional communication works

#### TestIntegration_WebSocket_MockBackend
- **Description**: Test WebSocket with local mock server (no external dependencies)
- **Preconditions**: None (uses in-process mock server)
- **Steps**:
  1. Start mock WebSocket echo server
  2. Test text message echo
  3. Test binary message echo
  4. Test 10 concurrent connections with echo verification
- **Expected Results**: Mock WebSocket server works for all message types and concurrency

### E2E Tests

#### TestE2E_WebSocket_ProxyConnection
- **Description**: Test WebSocket connection through gateway proxy
- **Preconditions**: Backend service running, gateway started with websocket-test.yaml
- **Steps**:
  1. Start gateway with WebSocket route configuration
  2. Connect to WebSocket through gateway (/ws)
  3. Verify upgrade succeeds through proxy
  4. Read 3 streamed messages through gateway
  5. Verify messages contain different random values
- **Expected Results**: WebSocket upgrade and streaming work through gateway proxy

#### TestE2E_WebSocket_SendReceive
- **Description**: Test bidirectional WebSocket through gateway
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Connect to WebSocket through gateway
  2. Send a text message through gateway
  3. Read response message through gateway
  4. Verify non-empty response
- **Expected Results**: Bidirectional WebSocket works through gateway

#### TestE2E_WebSocket_GracefulClose
- **Description**: Test WebSocket close handling through gateway
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Connect, read message, send close frame through gateway
  2. Verify graceful close through proxy
  3. Connect and close immediately through gateway
  4. Verify immediate close through proxy
- **Expected Results**: Close handling works correctly through gateway proxy

#### TestE2E_WebSocket_ConcurrentConnections
- **Description**: Test concurrent WebSocket connections through gateway
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Establish 5 concurrent WebSocket connections through gateway
  2. Read 2 messages per connection
  3. Verify at least 75% of connections succeed
  4. Verify message delivery through proxy
- **Expected Results**: Gateway handles concurrent WebSocket connections

#### TestE2E_WebSocket_LoadBalancing
- **Description**: Test WebSocket load balancing across backends
- **Preconditions**: Both backend services running, gateway started
- **Steps**:
  1. Establish 10 WebSocket connections to /ws-lb (50/50 weight)
  2. Read one message per connection
  3. Verify at least 75% of connections succeed
- **Expected Results**: WebSocket connections are distributed across backends

#### TestE2E_WebSocket_ConnectionResilience
- **Description**: Test gateway resilience with WebSocket connections
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Perform 10 rapid connect-disconnect cycles
  2. Verify at least 75% succeed
  3. Verify gateway is still healthy after cycles
  4. Test sequential connection after previous close
  5. Verify second connection works after first is closed
- **Expected Results**: Gateway remains stable through rapid WebSocket cycles

#### TestE2E_WebSocket_InvalidUpgrade
- **Description**: Test invalid WebSocket upgrade through gateway
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Attempt WebSocket upgrade to /health (direct response route)
  2. Verify upgrade fails with error
- **Expected Results**: Non-WebSocket routes reject upgrade through gateway

#### TestE2E_WebSocket_LongLivedConnection
- **Description**: Test long-lived WebSocket connection through gateway
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Connect to WebSocket through gateway
  2. Read 5 messages over ~5 seconds
  3. Verify most messages are received
  4. Log elapsed time and message count
- **Expected Results**: Long-lived WebSocket connection remains active through gateway

#### TestE2E_WebSocket_MixedTraffic
- **Description**: Test concurrent HTTP and WebSocket traffic through gateway
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Start 3 WebSocket connections reading 2 messages each
  2. Simultaneously make 10 HTTP requests to /health
  3. Verify most WebSocket connections succeed
  4. Verify most HTTP requests succeed
- **Expected Results**: Gateway handles mixed HTTP and WebSocket traffic simultaneously

#### TestE2E_WebSocket_SequentialConnections
- **Description**: Test sequential WebSocket connect-use-close cycles
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Perform 3 sequential cycles: connect, read message, close
  2. Verify each cycle succeeds independently
  3. Verify messages are received in each cycle
- **Expected Results**: Sequential WebSocket connections work reliably through gateway

## Operator Test Cases

### Unit Tests

#### TestOperator_BaseReconciler_Pattern
- **Description**: Test base reconciler pattern for code reuse
- **Preconditions**: Base reconciler implementation available
- **Steps**:
  1. Test common reconciliation logic
  2. Verify status update patterns
  3. Test generation-based reconciliation skip
  4. Verify error handling patterns
- **Expected Results**: Base reconciler provides consistent behavior across controllers

#### TestOperator_StatusUpdater_ThreadSafety
- **Description**: Test thread-safe StatusUpdater initialization
- **Preconditions**: StatusUpdater implementation
- **Steps**:
  1. Initialize StatusUpdater from multiple goroutines
  2. Verify no race conditions
  3. Test concurrent status updates
  4. Verify status updates use Patch instead of Update
- **Expected Results**: StatusUpdater is thread-safe and uses efficient Patch operations

#### TestOperator_CrossCRD_DuplicateDetection
- **Description**: Test cross-CRD duplicate detection between Backend and GRPCBackend
- **Preconditions**: Webhook validation enabled
- **Steps**:
  1. Create Backend with specific host/port
  2. Attempt to create GRPCBackend with same host/port
  3. Verify webhook rejects duplicate
  4. Test with different ports - should succeed
- **Expected Results**: Webhook prevents Backend vs GRPCBackend conflicts

### Functional Tests

#### TestOperator_IngressWebhook_Validation
- **Description**: Test ingress webhook validation when ingress controller is enabled
- **Preconditions**: Operator with ingress controller enabled
- **Steps**:
  1. Create valid Ingress resource
  2. Verify webhook allows creation
  3. Create invalid Ingress with bad annotations
  4. Verify webhook rejects invalid resource
  5. Test IngressClass validation
- **Expected Results**: Ingress webhook validates resources correctly

#### TestOperator_VaultPKI_CertificateIntegration
- **Description**: Test Vault PKI certificate integration for webhooks
- **Preconditions**: Vault PKI configured
- **Steps**:
  1. Configure operator with Vault PKI for webhook certificates
  2. Verify webhook certificates are issued by Vault
  3. Test certificate auto-renewal
  4. Verify webhook continues to work with new certificates
- **Expected Results**: Vault PKI integration works for webhook certificates

### Integration Tests

#### TestOperator_IngressController_ResourceConversion
- **Description**: Test conversion of Ingress resources to APIRoute/Backend
- **Preconditions**: Kubernetes cluster with ingress controller enabled
- **Steps**:
  1. Create Ingress resource with avapigw IngressClass
  2. Verify APIRoute is created automatically
  3. Verify Backend is created for service reference
  4. Test annotation mapping to route configuration
  5. Verify status updates on Ingress resource
- **Expected Results**: Ingress resources are converted to internal configuration

#### TestOperator_IngressController_StatusUpdates
- **Description**: Test LoadBalancer IP/hostname status updates on Ingress
- **Preconditions**: Ingress controller with LoadBalancer address configured
- **Steps**:
  1. Create Ingress resource
  2. Verify status is updated with LoadBalancer IP
  3. Test hostname-based status updates
  4. Verify status persists across reconciliation cycles
- **Expected Results**: Ingress status reflects LoadBalancer information

## Ingress Controller Test Cases

### Unit Tests

#### TestIngressController_PathTypeConversion
- **Description**: Test conversion of Kubernetes path types to gateway routes
- **Preconditions**: Ingress controller implementation
- **Steps**:
  1. Test Exact path type conversion
  2. Test Prefix path type conversion  
  3. Test ImplementationSpecific (regex) path type conversion
  4. Verify correct route matching configuration
- **Expected Results**: All path types convert to appropriate route matchers

#### TestIngressController_AnnotationParsing
- **Description**: Test parsing of avapigw-specific annotations
- **Preconditions**: Annotation parser implementation
- **Steps**:
  1. Test timeout annotation parsing
  2. Test rate limiting annotation parsing
  3. Test CORS annotation parsing
  4. Test invalid annotation handling
  5. Verify default values for missing annotations
- **Expected Results**: Annotations are parsed correctly with proper validation

#### TestIngressController_TLSConfiguration
- **Description**: Test TLS configuration from Ingress TLS section
- **Preconditions**: TLS configuration logic
- **Steps**:
  1. Test single host TLS configuration
  2. Test multiple hosts TLS configuration
  3. Test TLS secret reference validation
  4. Verify certificate configuration mapping
- **Expected Results**: TLS configuration is correctly mapped from Ingress

### Functional Tests

#### TestIngressController_DefaultBackend
- **Description**: Test default backend configuration for catch-all routing
- **Preconditions**: Ingress controller with default backend support
- **Steps**:
  1. Create Ingress with default backend
  2. Verify catch-all route is created
  3. Test request routing to default backend
  4. Verify specific routes take precedence
- **Expected Results**: Default backend provides catch-all functionality

#### TestIngressController_MultipleIngress
- **Description**: Test handling of multiple Ingress resources
- **Preconditions**: Multiple Ingress resources
- **Steps**:
  1. Create multiple Ingress resources with different hosts
  2. Verify separate APIRoute/Backend resources are created
  3. Test cross-Ingress conflict detection
  4. Verify independent lifecycle management
- **Expected Results**: Multiple Ingress resources are handled independently

#### TestIngressController_IngressClassFiltering
- **Description**: Test filtering by IngressClass
- **Preconditions**: Multiple IngressClass resources
- **Steps**:
  1. Create Ingress with avapigw IngressClass
  2. Verify resource is processed
  3. Create Ingress with different IngressClass
  4. Verify resource is ignored
  5. Test default IngressClass behavior
- **Expected Results**: Only Ingress resources with correct IngressClass are processed

### Performance Test Cases

#### TestPerformance_OperatorReconciliation
- **Description**: Test operator reconciliation performance with many CRDs
- **Preconditions**: Kubernetes cluster with operator
- **Steps**:
  1. Create 100 APIRoute resources
  2. Measure reconciliation time
  3. Create 100 Backend resources
  4. Measure total reconciliation time
  5. Verify memory usage remains stable
- **Expected Results**: Reconciliation scales linearly with resource count

#### TestPerformance_IngressController_Throughput
- **Description**: Test ingress controller throughput with many Ingress resources
- **Preconditions**: Ingress controller enabled
- **Steps**:
  1. Create 50 Ingress resources rapidly
  2. Measure conversion time to APIRoute/Backend
  3. Verify all resources are processed
  4. Test concurrent Ingress creation
- **Expected Results**: Ingress controller handles high throughput efficiently

#### TestPerformance_CrossCRD_ValidationScale
- **Description**: Test cross-CRD validation performance with many resources
- **Preconditions**: Webhook validation enabled
- **Steps**:
  1. Create 100 Backend resources
  2. Create 100 GRPCBackend resources
  3. Measure validation time for duplicate detection
  4. Verify validation remains fast
- **Expected Results**: Cross-CRD validation scales well with resource count

## gRPC Ingress Test Cases

### E2E Tests

#### TestE2E_GRPCIngress_BasicRouting
- **Description**: Test creating a gRPC Ingress and verifying gRPC routes are pushed to gRPC server
- **Preconditions**: gRPC server running, Kubernetes cluster available
- **Steps**:
  1. Create gRPC Ingress with protocol annotation set to "grpc"
  2. Verify reconciliation completes successfully
  3. Verify gRPC routes are stored under grpcRoutes key in config
  4. Verify gRPC backends are stored under grpcBackends key
  5. Verify Ingress has finalizer added
- **Expected Results**: gRPC Ingress creates GRPCRoute and GRPCBackend resources

#### TestE2E_GRPCIngress_ServiceMethodRouting
- **Description**: Test gRPC Ingress with service/method annotations
- **Preconditions**: gRPC server running
- **Steps**:
  1. Create gRPC Ingress with grpc-service and grpc-method annotations
  2. Set grpc-service-match-type and grpc-method-match-type to "exact"
  3. Verify reconciliation completes
  4. Verify applied-routes annotation contains grpcRoutes
  5. Verify service/method matching is configured correctly
- **Expected Results**: gRPC service/method matching is configured from annotations

#### TestE2E_GRPCIngress_TLSTermination
- **Description**: Test gRPC Ingress with TLS configuration
- **Preconditions**: gRPC server running, TLS secrets available
- **Steps**:
  1. Create gRPC Ingress with TLS section
  2. Add tls-min-version and tls-max-version annotations
  3. Verify reconciliation completes
  4. Verify TLS configuration is applied to gRPC route
  5. Verify SNI hosts are configured
- **Expected Results**: gRPC Ingress with TLS creates secure gRPC routes

#### TestE2E_GRPCIngress_AnnotationFeatures
- **Description**: Test gRPC Ingress with all gRPC-specific annotations
- **Preconditions**: gRPC server running
- **Steps**:
  1. Create gRPC Ingress with all gRPC annotations:
     - grpc-service, grpc-method, grpc-service-match-type, grpc-method-match-type
     - grpc-retry-on, grpc-backoff-base-interval, grpc-backoff-max-interval
     - grpc-health-check-enabled, grpc-health-check-service, grpc-health-check-interval
     - grpc-max-idle-conns, grpc-max-conns-per-host, grpc-idle-conn-timeout
  2. Add common annotations (timeout, rate-limit, cors, circuit-breaker)
  3. Verify reconciliation completes
  4. Verify all annotations are applied to gRPC route and backend
- **Expected Results**: All gRPC-specific annotations are correctly applied

#### TestE2E_GRPCIngress_DefaultBackend
- **Description**: Test gRPC Ingress with default backend
- **Preconditions**: gRPC server running
- **Steps**:
  1. Create gRPC Ingress with only defaultBackend (no rules)
  2. Verify reconciliation completes
  3. Verify default gRPC route is created with catch-all service match
  4. Verify default gRPC backend is created
- **Expected Results**: gRPC Ingress default backend creates catch-all gRPC route

#### TestE2E_GRPCIngress_UpdateAndDelete
- **Description**: Test full lifecycle of gRPC Ingress
- **Preconditions**: gRPC server running
- **Steps**:
  1. Create gRPC Ingress
  2. Verify gRPC route exists after create
  3. Update Ingress with new annotations (timeout, grpc-retry-on)
  4. Verify gRPC route is updated
  5. Delete gRPC route via cleanup
  6. Verify gRPC route is removed from config
- **Expected Results**: gRPC Ingress lifecycle (create, update, delete) works correctly

### Performance Tests

#### BenchmarkGRPCIngressConversion_Basic
- **Description**: Benchmark converting a basic gRPC Ingress to config.GRPCRoute/GRPCBackend
- **Preconditions**: IngressConverter available
- **Steps**:
  1. Create basic gRPC Ingress with single rule and path
  2. Run conversion benchmark
  3. Measure allocations and time per operation
- **Expected Results**: Basic gRPC Ingress conversion is fast with minimal allocations

#### BenchmarkGRPCIngressConversion_Complex
- **Description**: Benchmark converting a complex gRPC Ingress with all annotations
- **Preconditions**: IngressConverter available
- **Steps**:
  1. Create complex gRPC Ingress with multiple rules, paths, TLS, and all annotations
  2. Run conversion benchmark
  3. Measure allocations and time per operation
  4. Compare with HTTP Ingress conversion
- **Expected Results**: Complex gRPC Ingress conversion scales linearly with complexity

#### BenchmarkGRPCIngressConversion_WithAnnotations
- **Description**: Benchmark gRPC annotation parsing overhead
- **Preconditions**: IngressConverter available
- **Steps**:
  1. Create gRPC Ingress with all gRPC-specific annotations
  2. Run conversion benchmark
  3. Measure annotation parsing overhead
  4. Compare with HTTP annotation parsing
- **Expected Results**: gRPC annotation parsing has minimal overhead

#### BenchmarkGRPCIngressReconciliation_Create
- **Description**: Benchmark creating a gRPC Ingress resource
- **Preconditions**: IngressReconciler with fake client
- **Steps**:
  1. Create fresh gRPC Ingress for each iteration
  2. Run two reconciliation cycles (finalizer + apply)
  3. Measure total reconciliation time
- **Expected Results**: gRPC Ingress creation is performant

#### BenchmarkGRPCIngressReconciliation_Update
- **Description**: Benchmark updating a gRPC Ingress resource
- **Preconditions**: IngressReconciler with pre-created gRPC Ingress
- **Steps**:
  1. Pre-create and reconcile gRPC Ingress
  2. Run update reconciliation benchmark
  3. Measure re-apply time
- **Expected Results**: gRPC Ingress updates are efficient

#### BenchmarkGRPCIngressConversion_Parallel
- **Description**: Benchmark concurrent gRPC Ingress conversions
- **Preconditions**: IngressConverter available
- **Steps**:
  1. Pre-create 100 complex gRPC Ingress objects
  2. Run parallel conversion benchmark
  3. Measure throughput and contention
- **Expected Results**: gRPC Ingress conversion is thread-safe and scales with parallelism

#### BenchmarkGRPCvsHTTPIngressConversion
- **Description**: Compare gRPC vs HTTP Ingress conversion performance
- **Preconditions**: IngressConverter available
- **Steps**:
  1. Create equivalent HTTP and gRPC Ingress resources
  2. Run conversion benchmarks for both
  3. Compare allocations and time per operation
- **Expected Results**: gRPC and HTTP conversion have similar performance characteristics

## Redis Cache Features Tests

### Functional Tests

#### TestFunctional_Cache_Features_TTLJitter_ConfigDefaults
- **Description**: Test that TTLJitter defaults to 0 in RedisCacheConfig
- **Preconditions**: None (no external dependencies)
- **Steps**:
  1. Create empty RedisCacheConfig
  2. Verify TTLJitter is 0.0
  3. Verify DefaultRedisCacheConfig has zero TTLJitter
  4. Verify DefaultRedisTTLJitter constant is 0.0
- **Expected Results**: TTLJitter defaults to 0 (no jitter)

#### TestFunctional_Cache_Features_TTLJitter_AcceptsValidRange
- **Description**: Test that TTLJitter accepts values in [0.0, 1.0]
- **Preconditions**: None
- **Steps**:
  1. Set TTLJitter to 0.0, 0.05, 0.1, 0.5, 1.0
  2. Verify each value is stored correctly
- **Expected Results**: All valid jitter values are accepted

#### TestFunctional_Cache_Features_TTLJitter_CreateTestCacheConfig
- **Description**: Test TTLJitter in CacheConfig hierarchy
- **Preconditions**: None
- **Steps**:
  1. Create redis CacheConfig with TTLJitter set
  2. Create sentinel CacheConfig with TTLJitter set
  3. Verify TTLJitter is accessible in both
- **Expected Results**: TTLJitter works in both standalone and sentinel configs

#### TestFunctional_Cache_Features_TTLJitter_ApplyFunction
- **Description**: Test TTLJitter boundary values in config
- **Preconditions**: None
- **Steps**:
  1. Set TTLJitter > 1.0 (clamped at runtime, stored as-is in config)
  2. Set TTLJitter < 0.0 (no-op at runtime, stored as-is in config)
- **Expected Results**: Config stores values; runtime clamping is separate

#### TestFunctional_Cache_Features_HashKeys_ConfigDefaults
- **Description**: Test that HashKeys defaults to false
- **Preconditions**: None
- **Steps**:
  1. Create empty RedisCacheConfig
  2. Verify HashKeys is false
  3. Verify DefaultRedisCacheConfig has HashKeys false
- **Expected Results**: HashKeys defaults to false

#### TestFunctional_Cache_Features_HashKey_Consistency
- **Description**: Test HashKey produces consistent SHA256 hashes
- **Preconditions**: None
- **Steps**:
  1. Hash same input twice, verify identical output
  2. Verify hash is 64 hex characters
  3. Hash different inputs, verify different outputs
  4. Hash empty string, verify known SHA256 value
- **Expected Results**: HashKey is deterministic and produces valid SHA256

#### TestFunctional_Cache_Features_HashKey_DataDriven
- **Description**: Data-driven test for HashKey with various inputs
- **Preconditions**: None
- **Steps**:
  1. Test short, medium, long keys
  2. Test keys with special characters
  3. Test unicode keys
  4. Verify all hashes are unique
- **Expected Results**: HashKey handles all input types correctly

#### TestFunctional_Cache_Features_VaultPassword_ConfigFields
- **Description**: Test PasswordVaultPath fields in config structs
- **Preconditions**: None
- **Steps**:
  1. Set PasswordVaultPath in RedisCacheConfig
  2. Verify default is empty
  3. Set PasswordVaultPath in RedisSentinelConfig
  4. Set SentinelPasswordVaultPath in RedisSentinelConfig
  5. Set both vault paths in sentinel config
- **Expected Results**: Vault path fields store values correctly

#### TestFunctional_Cache_Features_VaultPassword_CacheConfigIntegration
- **Description**: Test vault paths in full CacheConfig hierarchy
- **Preconditions**: None
- **Steps**:
  1. Create standalone redis config with vault path
  2. Create sentinel config with vault paths
  3. Create combined config with all vault paths
- **Expected Results**: Vault paths work in all config levels

#### TestFunctional_Cache_Features_AllFeaturesCombined
- **Description**: Test all three features configured together
- **Preconditions**: None
- **Steps**:
  1. Create RedisCacheConfig with TTLJitter, HashKeys, and PasswordVaultPath
  2. Verify all fields are set correctly
- **Expected Results**: All features coexist in config

### Integration Tests

#### TestIntegration_Cache_Features_TTLJitter_WithRedis
- **Description**: Test TTL jitter with real Redis
- **Preconditions**: Redis server running
- **Steps**:
  1. Create cache with TTLJitter=0.1 and 10-minute TTL
  2. Store 20 keys and collect their TTLs via GetWithTTL
  3. Verify TTLs are not all identical (jitter applied)
  4. Verify all TTLs are within ±15% of base TTL
  5. Create cache with TTLJitter=0
  6. Store 10 keys and verify TTLs are within 2s of base TTL
- **Expected Results**: Jitter produces varied TTLs; no jitter produces exact TTLs

#### TestIntegration_Cache_Features_TTLJitter_WithSentinel
- **Description**: Test TTL jitter with Redis Sentinel
- **Preconditions**: Redis Sentinel running
- **Steps**:
  1. Create sentinel cache with TTLJitter=0.1
  2. Store 15 keys and collect TTLs
  3. Verify TTLs vary across keys
- **Expected Results**: TTL jitter works with sentinel cache

#### TestIntegration_Cache_Features_HashKeys_WithRedis
- **Description**: Test hash keys with real Redis
- **Preconditions**: Redis server running
- **Steps**:
  1. Create cache with HashKeys=true, store and retrieve values
  2. Verify hashed key exists in Redis via raw client
  3. Verify plain key does NOT exist when HashKeys=true
  4. Create cache with HashKeys=false, verify plain key exists
  5. Verify hashed key does NOT exist when HashKeys=false
  6. Test multiple keys with HashKeys=true
- **Expected Results**: Hash keys feature correctly hashes/unhashes keys in Redis

#### TestIntegration_Cache_Features_HashKeys_WithSentinel
- **Description**: Test hash keys with Redis Sentinel
- **Preconditions**: Redis Sentinel running
- **Steps**:
  1. Create sentinel cache with HashKeys=true
  2. Store and retrieve values
  3. Verify hashed key exists in Redis via raw sentinel client
- **Expected Results**: Hash keys work with sentinel cache

#### TestIntegration_Cache_Features_VaultPassword
- **Description**: Test Vault password integration with Redis cache
- **Preconditions**: Redis and Vault running
- **Steps**:
  1. Write Redis password to Vault KV
  2. Create cache with PasswordVaultPath pointing to Vault secret
  3. Verify cache connects and operations work
  4. Test invalid vault path returns error
- **Expected Results**: Cache resolves password from Vault and connects to Redis

### E2E Tests

#### TestE2E_Cache_Features_TTLJitter
- **Description**: Test gateway with TTL jitter end-to-end
- **Preconditions**: Redis and backend running
- **Steps**:
  1. Start gateway with TTL jitter configured
  2. Make request through gateway, verify it serves correctly
  3. Cache multiple entries with short TTL and jitter
  4. Verify TTLs are within expected jitter range
  5. Wait for entries to expire, verify all are gone
- **Expected Results**: TTL jitter works in gateway flow

#### TestE2E_Cache_Features_HashKeys
- **Description**: Test gateway with hash keys end-to-end
- **Preconditions**: Redis and backend running
- **Steps**:
  1. Start gateway with hash keys enabled
  2. Cache data and verify retrieval
  3. Verify keys in Redis are hashed (via raw client)
  4. Verify plain keys do NOT exist
  5. Make request through gateway
  6. Complete cache journey: miss → store → hit → invalidate → miss
- **Expected Results**: Hash keys work in gateway flow

#### TestE2E_Cache_Features_Combined
- **Description**: Test TTL jitter and hash keys together end-to-end
- **Preconditions**: Redis running
- **Steps**:
  1. Create cache with both TTLJitter=0.1 and HashKeys=true
  2. Store and retrieve values
  3. Verify keys are hashed in Redis
  4. Verify TTLs vary (jitter applied with hashed keys)
- **Expected Results**: Both features work together correctly

## gRPC Backend Hot-Reload Tests

### TestFunctional_GRPCBackend_ConfigConversion
- **Description**: Test GRPCBackendToBackend conversion preserves all fields
- **Preconditions**: None
- **Steps**:
  1. Create GRPCBackend with name and hosts
  2. Convert to Backend using GRPCBackendToBackend
  3. Verify name, hosts, weights preserved
  4. Test with health check enabled/disabled/nil
  5. Test with TLS simple mode
  6. Test with TLS and Vault config
  7. Test with Vault TLS disabled
  8. Test with circuit breaker
  9. Test with load balancer
  10. Test with authentication
  11. Test with nil TLS
- **Expected Results**: All fields correctly converted from GRPCBackend to Backend

### TestFunctional_GRPCBackend_BatchConversion
- **Description**: Test GRPCBackendsToBackends batch conversion
- **Preconditions**: None
- **Steps**:
  1. Convert empty slice
  2. Convert nil slice
  3. Convert multiple backends
  4. Convert single backend
- **Expected Results**: Batch conversion works correctly for all cases

### TestFunctional_GRPCConfig_BackendConversion
- **Description**: Test gRPC backend config conversion in functional context
- **Preconditions**: None
- **Steps**:
  1. Test full field preservation (name, hosts, health check, LB, TLS, Vault, CB, auth)
  2. Test batch conversion
  3. Test empty/nil handling
  4. Test health check disabled produces nil
  5. Test TLS with disabled/nil Vault
  6. Test cipher suites and insecure skip verify
- **Expected Results**: Config conversion works correctly for all edge cases

### TestIntegration_GRPCBackendReload_RegistryReload
- **Description**: Test backend registry reload with copy-on-write pattern
- **Preconditions**: gRPC backend services running
- **Steps**:
  1. Load initial backends into registry
  2. Reload with additional backend
  3. Verify new backend added
  4. Reload with removed backend
  5. Verify old backend removed
  6. Reload with updated weights
- **Expected Results**: Registry reload works correctly with add/remove/update

### TestIntegration_GRPCBackendReload_ConcurrentAccess
- **Description**: Test concurrent access during backend reload
- **Preconditions**: gRPC backend services running
- **Steps**:
  1. Load initial backends
  2. Spawn concurrent readers
  3. Spawn concurrent reloaders
  4. Verify no errors during concurrent operations
- **Expected Results**: Concurrent reads and reloads are thread-safe

### TestIntegration_GRPCBackendReload_ConnectionCleanup
- **Description**: Test stale connection cleanup after backend reload
- **Preconditions**: gRPC backend services running
- **Steps**:
  1. Create proxy with two backends
  2. Establish connections to both
  3. Clean up connections to removed backend
  4. Verify only valid connections remain
  5. Test cleanup with empty valid targets
- **Expected Results**: Stale connections are properly cleaned up

### TestIntegration_GRPCBackendReload_ListenerReload
- **Description**: Test GRPCListener.ReloadBackends method
- **Preconditions**: gRPC backend services running
- **Steps**:
  1. Create listener with backend registry
  2. Start listener
  3. Reload backends
  4. Verify listener still running
  5. Test reload without registry returns error
- **Expected Results**: Listener reload works correctly

### TestIntegration_GRPCBackendReload_GRPCBackendConversion
- **Description**: Test full conversion pipeline from GRPCBackend to Backend in reload
- **Preconditions**: gRPC backend services running
- **Steps**:
  1. Create GRPCBackend configs
  2. Convert to Backend configs
  3. Load into registry
  4. Reload with updated GRPCBackend configs
  5. Verify registry state
- **Expected Results**: Full conversion pipeline works with reload

### TestIntegration_GRPCBackendReload_ProxyDirectorAfterReload
- **Description**: Test proxy director routes correctly after reload
- **Preconditions**: gRPC backend services running
- **Steps**:
  1. Create proxy with route to backend1
  2. Verify routing to backend1
  3. Reload routes to point to backend2
  4. Clean up stale connections
  5. Verify routing to backend2
- **Expected Results**: Director routes to new backends after reload

### TestIntegration_GRPCBackendReload_EmptyBackends
- **Description**: Test reload with empty backends
- **Preconditions**: gRPC backend services running
- **Steps**:
  1. Load initial backends
  2. Reload with empty backends
  3. Verify registry is empty
- **Expected Results**: Empty reload clears registry

### TestE2E_GRPCGateway_BackendHotReload
- **Description**: Test gRPC backend hot-reload end-to-end
- **Preconditions**: gRPC backend services running
- **Steps**:
  1. Start gateway with single backend
  2. Verify initial routing
  3. Connect and verify health check
  4. Reload routes with two backends
  5. Verify updated routing
  6. Verify health check still works
  7. Test connection preservation during reload
  8. Test backend removal with connection cleanup
- **Expected Results**: Hot-reload works end-to-end without service interruption

### TestE2E_HotReload_GRPCBackendReload
- **Description**: Test gRPC backend config change detection via file watcher
- **Preconditions**: gRPC backend services running
- **Steps**:
  1. Create config file with gRPC backends
  2. Start config watcher
  3. Update config with additional backend
  4. Verify change detected
  5. Test backend removal detection
  6. Test weight change detection
- **Expected Results**: File watcher detects gRPC backend config changes
