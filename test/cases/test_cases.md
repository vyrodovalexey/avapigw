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

### TestReloadComponents_CORSChangeWithRouteMiddlewareMgr
- **Description**: Test that route-level CORS is hot-reloaded via UpdateGlobalConfig during config reload
- **Preconditions**: Gateway running with route middleware manager and global CORS config
- **Steps**:
  1. Create application with RouteMiddlewareManager and initial global CORS config
  2. Pre-populate middleware cache with a test route
  3. Trigger reloadComponents with new CORS config (different AllowOrigins)
  4. Verify route middleware manager reflects new global CORS via GetEffectiveCORS
  5. Verify middleware cache was cleared and rebuilt with new config
- **Expected Results**: Route middleware manager uses new global CORS after reload; cache is cleared

### TestCorsConfigChanged_WithRouteLevelCORS
- **Description**: Test that corsConfigChanged only detects global CORS changes, not route-level CORS changes
- **Preconditions**: None
- **Steps**:
  1. Test with same global CORS but different route-level CORS — should report no change
  2. Test with different global CORS and same route-level CORS — should report change
  3. Verify corsConfigChanged only compares Spec.CORS, not route-level CORS
- **Expected Results**: corsConfigChanged detects global CORS changes only

### TestReloadMetrics_Init_IncludesCorsComponent
- **Description**: Test that reload metrics Init() pre-populates "cors" component labels
- **Preconditions**: None
- **Steps**:
  1. Create new reload metrics
  2. Verify "cors" component labels are pre-populated with "success" and "error" results
  3. Verify incrementing cors metrics does not panic
  4. Verify all expected components are present (rate_limiter, max_sessions, routes, backends, audit, cors, grpc_routes, grpc_backends, graphql_routes, graphql_backends)
- **Expected Results**: "cors" component is included in pre-populated metrics labels

### TestReloadComponents_CORSChangeIncrementsMetrics
- **Description**: Test that CORS config change increments the cors component reload metric
- **Preconditions**: None
- **Steps**:
  1. Create application with initial CORS config and reload metrics
  2. Trigger reloadComponents with different CORS config
  3. Verify cors component success metric is incremented
- **Expected Results**: CORS reload success metric is incremented on CORS config change

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

## Gateway-wide Vault Client (spec.vault) Tests

These tests cover the gateway-wide `spec.vault` section
(`internal/config.VaultConfig`), which configures the Vault CLIENT CONNECTION
used by the whole gateway (distinct from the per-listener/route `tls.vault` PKI
issuance blocks above). The section is overlaid per-field by the environment
(`ENV > file > defaults`), supports file-referenced secrets (`tokenFile`,
`appRole.secretIdFile`), surfaces inline-secret WARNINGs at validation, and is
intentionally NOT hot-reloaded (the config watcher warns and skips vault
changes while still validating the effective, env-overlaid config).

Field mapping (`convertVaultClientConfig`), the full ENV overlay matrix
(`applyVaultEnv`), the no-hot-reload warn+skip (`warnVaultConfigChanged`), and
the watcher pre-validate transform (`vaultEnvPreValidateTransform`) are
exhaustively UNIT covered in `cmd/gateway` and `internal/config`. The
integration cases below cover the SUITE seam: a real config FILE driving a real
Vault client against LIVE Vault, plus the file-loaded validation behavior.

### TestIntegration_SpecVault_ConfigFile_TokenFile_ResolvesSecret
- **Description**: A gateway config FILE with `spec.vault{enabled, address, authMethod: token, tokenFile}` and NO `VAULT_*` environment in the process builds a working Vault client that resolves a real KV secret.
- **Preconditions**: Live Vault reachable; `secret/backend-auth/basic` provisioned (compose `setup-vault.sh`); token written to a temp `tokenFile` (with trailing newline to exercise trimming); all `VAULT_*` env cleared for the process.
- **Steps**:
  1. Write the Vault token to a temp `tokenFile` (`myroot\n`).
  2. Write a gateway config file referencing that `tokenFile` in `spec.vault` (no inline token).
  3. `config.LoadConfig` the file and assert `spec.vault` parsed.
  4. Apply the production per-field ENV overlay (no `VAULT_*` set → file wins).
  5. Map the effective section to a `vault.Config` (resolving `tokenFile` from disk).
  6. Construct + authenticate the Vault client against live Vault.
  7. `KV().Read("secret", "backend-auth/basic")`.
- **Expected Results**: Client authenticates; secret resolves to `username=backend-user`, `password=backend-pass`.

### TestIntegration_SpecVault_EnvAddressWins
- **Description**: Per-field precedence — the config FILE carries a WRONG Vault address, but a correct `VAULT_ADDR` in the environment wins, so the gateway boots and Vault works.
- **Preconditions**: Live Vault reachable; correct address available for `VAULT_ADDR`.
- **Steps**:
  1. Write a config file with a deliberately black-holed address (`http://127.0.0.1:1`) and a valid `tokenFile`.
  2. Set `VAULT_ADDR` to the correct live Vault address.
  3. Load the file, apply the ENV overlay (env address wins, forces `enabled=true`).
  4. Build + authenticate the client and read the secret.
- **Expected Results**: The env address is used (not the wrong file value); secret resolves successfully, proving `ENV > file` per-field.

### TestIntegration_SpecVault_EnvTokenClearsTokenFile
- **Description**: Per-field precedence for the token — the file references a `tokenFile` (with a BOGUS token), but `VAULT_TOKEN` in the environment wins and CLEARS the `tokenFile` reference (keeping the exactly-one(token|tokenFile) invariant), and the client still works.
- **Preconditions**: Live Vault reachable; correct token available for `VAULT_TOKEN`.
- **Steps**:
  1. Write a config file whose `tokenFile` contains a bogus token.
  2. Set `VAULT_TOKEN` to the correct token.
  3. Load + overlay; assert effective `tokenFile` is EMPTY and effective `token` equals the env token.
  4. Build + authenticate the client and read the secret.
- **Expected Results**: Env token wins, `tokenFile` cleared; secret resolves successfully.

### TestIntegration_SpecVault_Validation_FileSeam
- **Description**: Validation behavior on FILE-loaded `spec.vault`: an inline token surfaces a WARNING (not an error), and an AppRole config missing `roleId` is REJECTED at load-time validation.
- **Preconditions**: None (pure config-time validation; runs in the integration suite alongside the live cases).
- **Steps**:
  1. Load a config file with `spec.vault.token` inline; call `ValidateConfigWithWarnings`.
  2. Assert no error and a warning at path `spec.vault.token` containing "discouraged".
  3. Load a config file with `authMethod: approle` and `appRole.secretId` but no `roleId`; call `ValidateConfig`.
  4. Assert an error mentioning `roleId`.
- **Expected Results**: Inline token → warning (accepted); AppRole without `roleId` → validation error (rejected).

### TestIntegration_SpecVault_Kubernetes (Phase 7 — deferred)
- **Description**: `spec.vault.authMethod: kubernetes` (ServiceAccount JWT) end-to-end requires an in-cluster ServiceAccount token and a Vault `kubernetes` auth mount; it is exercised in-cluster in Phase 7 and intentionally NOT covered here.
- **Status**: Deferred to Phase 7 (in-cluster). No local docker-compose coverage.

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

#### TestE2E_WebSocket_OriginAllowlist
- **Description**: Test Cross-Site WebSocket Hijacking protection via spec.websocket.allowedOrigins
- **Preconditions**: Backend service running, gateway started with websocket-origin-test.yaml (allowedOrigins: "https://app.example.com", "trusted.example.com")
- **Steps**:
  1. Connect with Origin "https://app.example.com" (scheme+host entry) and verify handshake succeeds and stream works
  2. Connect with Origin "http://trusted.example.com" and verify the bare-host entry matches any scheme
  3. Connect without an Origin header (non-browser client) and verify handshake succeeds
  4. Connect with a same-origin Origin (gateway host:port) and verify handshake succeeds
  5. Connect with Origin "https://evil.example.com" and verify the handshake is rejected with HTTP 403 before any backend dial
  6. Connect with Origin "http://app.example.com" and verify a scheme-qualified entry does not match other schemes (403)
  7. Verify the gateway stays healthy after rejected handshakes
- **Expected Results**: Only allowlisted, same-origin, and origin-less handshakes are upgraded; other origins get 403 Forbidden

#### TestE2E_WebSocket_OriginPermissiveDefault
- **Description**: Test backward-compatible permissive default when no WebSocket origin allowlist is configured
- **Preconditions**: Backend service running, gateway started with websocket-test.yaml (no websocket.allowedOrigins; a startup warning is logged)
- **Steps**:
  1. Connect with an arbitrary cross-site Origin header
  2. Verify the handshake succeeds and messages stream through the gateway
- **Expected Results**: Empty allowedOrigins preserves the legacy allow-all behavior (warning logged at startup)

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

#### TestIntegration_Cache_Redis_OperationMetricsParity
- **Description**: Test that Redis-only operations record operation metrics with their own labels (metric parity with base operations)
- **Preconditions**: Redis running
- **Steps**:
  1. Create Redis cache and snapshot gateway_cache_operation_duration_seconds sample counts for operations get_with_ttl, setnx, expire
  2. Drive GetWithTTL (after Set), SetNX on a fresh key, and Expire on an existing key
  3. Verify the duration histogram gains samples for each of the get_with_ttl, setnx, and expire operation labels
  4. Verify gateway_cache_errors_total pre-initializes the redis-only operation label combinations via Init()
- **Expected Results**: GetWithTTL/SetNX/Expire are observable with the same metrics as Get/Set/Delete/Exists, using operation labels get_with_ttl, setnx, expire

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

## Audit Logger Hot-Reload Tests

### TestFunctional_AuditLogger_AtomicSwap
- **Description**: Test AtomicAuditLogger atomic swap functionality
- **Preconditions**: None
- **Steps**:
  1. Create AtomicAuditLogger with initial logger
  2. Verify initial logger is loaded
  3. Swap with new logger configuration
  4. Verify new logger is active
  5. Test concurrent access during swap
- **Expected Results**: Logger swap is atomic and thread-safe

### TestIntegration_AuditLogger_HotReload
- **Description**: Test audit logger hot-reload in gateway
- **Preconditions**: Gateway running with audit logging
- **Steps**:
  1. Start gateway with initial audit configuration
  2. Generate audit events
  3. Update audit configuration (output, format, level)
  4. Trigger configuration reload
  5. Verify new audit configuration is active
  6. Verify audit metrics are preserved
- **Expected Results**: Audit logger reloads without losing events

### TestE2E_AuditLogger_OperatorMode
- **Description**: Test audit logger hot-reload in operator mode
- **Preconditions**: Operator and gateway running
- **Steps**:
  1. Configure audit logging via operator
  2. Generate audit events
  3. Update audit configuration via CRD
  4. Verify operator merges audit config
  5. Verify gateway receives updated config
  6. Test audit event filtering changes
- **Expected Results**: Operator mode audit hot-reload works end-to-end

### TestE2E_AuditLogger_ConfigMerge
- **Description**: Test audit configuration merging in operator mode
- **Preconditions**: Operator running with audit config
- **Steps**:
  1. Configure global audit settings
  2. Configure operator-specific audit settings
  3. Verify operator config takes precedence
  4. Test partial operator config (inherits global)
  5. Test audit metrics preservation across merges
- **Expected Results**: Audit configuration merging works correctly

## gRPC Backend Hot-Reload Tests

### TestFunctional_GRPCBackend_CopyOnWrite
- **Description**: Test gRPC backend copy-on-write pattern
- **Preconditions**: None
- **Steps**:
  1. Create gRPC backend registry
  2. Add initial backends
  3. Trigger copy-on-write update
  4. Verify old connections preserved
  5. Verify new connections use new backends
  6. Test concurrent access during update
- **Expected Results**: Copy-on-write pattern works correctly

### TestIntegration_GRPCBackend_HotReload_FileMode
- **Description**: Test gRPC backend hot-reload in file-based mode
- **Preconditions**: gRPC backend services running
- **Steps**:
  1. Start gateway with gRPC backend configuration
  2. Establish gRPC connections
  3. Update backend configuration file
  4. Verify configuration reload
  5. Test existing connections preserved
  6. Test new connections use updated backends
- **Expected Results**: gRPC backend hot-reload works in file mode

### TestIntegration_GRPCBackend_HotReload_OperatorMode
- **Description**: Test gRPC backend hot-reload in operator mode
- **Preconditions**: Operator and gRPC backends running
- **Steps**:
  1. Create GRPCBackend CRDs
  2. Establish gRPC connections
  3. Update GRPCBackend CRDs
  4. Verify operator pushes updates
  5. Test connection preservation
  6. Test backend health check updates
- **Expected Results**: gRPC backend hot-reload works in operator mode

### TestE2E_GRPCBackend_LoadBalancing_HotReload
- **Description**: Test gRPC backend load balancing during hot-reload
- **Preconditions**: Multiple gRPC backend services
- **Steps**:
  1. Configure weighted gRPC backends
  2. Generate load across backends
  3. Update backend weights via hot-reload
  4. Verify new weight distribution
  5. Test backend addition/removal
  6. Verify load balancing algorithm changes
- **Expected Results**: Load balancing updates correctly during hot-reload

### TestE2E_GRPCBackend_HealthCheck_HotReload
- **Description**: Test gRPC backend health check updates during hot-reload
- **Preconditions**: gRPC backends with health checks
- **Steps**:
  1. Configure backends with health checks
  2. Verify initial health status
  3. Update health check configuration
  4. Trigger hot-reload
  5. Verify new health check behavior
  6. Test health check interval changes
- **Expected Results**: Health check configuration updates correctly

## Combined Hot-Reload Feature Tests

### TestE2E_HotReload_AllFeatures
- **Description**: Test all hot-reload features together
- **Preconditions**: Full gateway setup with all features
- **Steps**:
  1. Configure HTTP routes, gRPC backends, audit logging
  2. Generate traffic and audit events
  3. Update all configurations simultaneously
  4. Verify all components reload correctly
  5. Test feature interaction during reload
  6. Verify metrics and monitoring
- **Expected Results**: All hot-reload features work together

### TestE2E_HotReload_Performance_Impact
- **Description**: Test performance impact of hot-reload operations
- **Preconditions**: Load testing setup
- **Steps**:
  1. Generate baseline load
  2. Trigger hot-reload during load
  3. Measure latency impact
  4. Measure throughput impact
  5. Test reload frequency limits
  6. Verify resource usage
- **Expected Results**: Hot-reload has minimal performance impact

### TestE2E_HotReload_Failure_Recovery
- **Description**: Test hot-reload failure scenarios and recovery
- **Preconditions**: Gateway with invalid configurations
- **Steps**:
  1. Start with valid configuration
  2. Attempt reload with invalid config
  3. Verify rollback to previous config
  4. Test partial reload failures
  5. Verify error reporting and metrics
  6. Test recovery after failures
- **Expected Results**: Hot-reload failures are handled gracefully

## REST/GraphQL Cross-Route Intersection Prevention Tests

### TC-CROSS-001: APIRoute with identical-specificity path as GraphQLRoute → rejected by webhook
- **Description**: Test that creating an APIRoute whose match has the SAME specificity as an existing GraphQLRoute (identical exact path or identical prefix) is rejected as a genuine cross-kind duplicate. Cross-kind combinations of different specificity (exact vs prefix, catch-all vs specific) coexist deterministically — the GraphQL pipeline exclusively owns its endpoint path — and must be admitted
- **Preconditions**: A GraphQLRoute with exact path `/graphql` (or prefix `/graphql`) exists in the cluster
- **Steps**:
  1. Create a GraphQLRoute with exact path `/graphql`
  2. Create an APIRoute with the identical exact path `/graphql` (or identical prefix when the GraphQLRoute uses a prefix)
  3. Submit the APIRoute to the webhook validator
  4. Additionally create an APIRoute with prefix `/graphql` (different specificity) and verify it is admitted
- **Expected Results**: Webhook rejects the identical-specificity APIRoute with a path conflict error mentioning the GraphQLRoute; the different-specificity APIRoute is admitted

### TC-CROSS-002: GraphQLRoute with identical-specificity path as APIRoute → rejected by webhook
- **Description**: Test that creating a GraphQLRoute whose match has the SAME specificity as an existing APIRoute (identical prefix or identical exact path) is rejected; a GraphQL exact path nested under an APIRoute prefix has different specificity and must be admitted
- **Preconditions**: An APIRoute with prefix `/api` exists in the cluster
- **Steps**:
  1. Create an APIRoute with prefix `/api`
  2. Create a GraphQLRoute with the identical prefix `/api`
  3. Submit the GraphQLRoute to the webhook validator
  4. Additionally create a GraphQLRoute with exact path `/api/graphql` (nested, different specificity) and verify it is admitted
- **Expected Results**: Webhook rejects the identical-prefix GraphQLRoute with a path conflict error mentioning the APIRoute; the nested exact-path GraphQLRoute is admitted

### TC-CROSS-003: APIRoute and GraphQLRoute with non-overlapping paths → allowed
- **Description**: Test that non-overlapping REST and GraphQL routes are allowed
- **Preconditions**: None
- **Steps**:
  1. Create an APIRoute with prefix `/api/v1`
  2. Create a GraphQLRoute with exact path `/graphql`
  3. Submit both to the webhook validator
- **Expected Results**: Both routes are accepted without errors

### TC-CROSS-004: Cross-namespace conflict detection (cluster-scoped)
- **Description**: Test that identical-specificity cross-CRD route duplicates are detected across namespaces when cluster-scoped, and NOT detected when namespace-scoped
- **Preconditions**: DuplicateChecker configured with cluster-wide scope
- **Steps**:
  1. Create a GraphQLRoute with exact path `/graphql` in namespace `ns-a`
  2. Create an APIRoute with the identical exact path `/graphql` in namespace `ns-b`
  3. Submit the APIRoute to the webhook validator with cluster-scoped DuplicateChecker
  4. Repeat with a namespace-scoped DuplicateChecker and verify the APIRoute is admitted
- **Expected Results**: Cluster-scoped checker rejects the APIRoute because the GraphQLRoute in a different namespace has an identical-specificity path; namespace-scoped checker admits it

### TC-CROSS-005: Config validation rejects overlapping REST/GraphQL routes
- **Description**: Test that the config validator detects overlapping REST and GraphQL routes in a GatewayConfig
- **Preconditions**: None
- **Steps**:
  1. Create a GatewayConfig with a REST route on prefix `/api` and a GraphQL route on exact path `/api/graphql`
  2. Run ValidateConfig on the configuration
- **Expected Results**: Validation returns an error about overlapping REST and GraphQL routes

### TC-CROSS-006: Update operation that would create an identical-specificity duplicate → rejected
- **Description**: Test that updating an APIRoute to an identical-specificity path duplicate of a GraphQLRoute is rejected
- **Preconditions**: An APIRoute with prefix `/rest` and a GraphQLRoute with exact path `/graphql` exist
- **Steps**:
  1. Create an APIRoute with prefix `/rest` (no conflict)
  2. Create a GraphQLRoute with exact path `/graphql`
  3. Update the APIRoute to change its match to the identical exact path `/graphql`
  4. Submit the update to the webhook validator
- **Expected Results**: Webhook rejects the update with a path conflict error

## OpenAPI Request Validation Tests

### Functional Tests

#### TestFunctional_OpenAPIValidation_ConfigParsing
- **Description**: Test OpenAPI validation configuration parsing from YAML
- **Preconditions**: None
- **Steps**:
  1. Parse YAML with global OpenAPI validation (specFile, all boolean options)
  2. Parse YAML with specURL instead of specFile
  3. Parse YAML with disabled OpenAPI validation
  4. Parse YAML without OpenAPI validation section
- **Expected Results**: All config variants parse correctly with expected values

#### TestFunctional_OpenAPIValidation_GlobalAndRouteLevel
- **Description**: Test global and route-level OpenAPI validation configuration
- **Preconditions**: None
- **Steps**:
  1. Parse YAML with both global and route-level OpenAPI validation
  2. Verify global config has global spec file
  3. Verify route-level config has route-specific spec file
  4. Verify route-level failOnError overrides global
- **Expected Results**: Both levels parse independently, route overrides global

#### TestFunctional_OpenAPIValidation_ConfigValidation
- **Description**: Test validation of OpenAPI validation configuration
- **Preconditions**: None
- **Steps**:
  1. Validate disabled config (should pass)
  2. Validate enabled config with specFile (should pass)
  3. Validate enabled config without specFile or specURL (should fail)
  4. Validate enabled config with both specFile and specURL (should fail - mutually exclusive)
  5. Validate enabled config with invalid specURL (should fail)
  6. Validate route-level enabled config without spec (should fail)
- **Expected Results**: Invalid configs are rejected with clear error messages

#### TestFunctional_OpenAPIValidation_EffectiveDefaults
- **Description**: Test effective default values for OpenAPI validation config
- **Preconditions**: None
- **Steps**:
  1. Verify failOnError defaults to true
  2. Verify validateRequestBody defaults to true
  3. Verify validateRequestParams defaults to true
  4. Verify validateRequestHeaders defaults to false
  5. Verify validateSecurity defaults to false
  6. Verify nil config returns safe defaults
- **Expected Results**: All defaults match documented behavior

#### TestFunctional_OpenAPIValidation_MiddlewareChainPosition
- **Description**: Test validation middleware position in chain
- **Preconditions**: None
- **Steps**:
  1. Verify validation middleware executes before proxy handler
  2. Verify failOnError=true rejects invalid requests with 400
  3. Verify failOnError=false logs but passes invalid requests
- **Expected Results**: Middleware chain order and behavior are correct

#### TestFunctional_ProtoValidation_ConfigParsing
- **Description**: Test ProtoValidation configuration parsing
- **Preconditions**: None
- **Steps**:
  1. Parse YAML with gRPC route ProtoValidation config
  2. Verify effective defaults (failOnError=true, validateRequestMessage=true)
  3. Verify nil config returns safe defaults
  4. Validate enabled config without descriptorFile (should fail)
- **Expected Results**: ProtoValidation config parses and validates correctly

#### TestFunctional_GraphQLSchemaValidation_ConfigParsing
- **Description**: Test GraphQLSchemaValidation configuration parsing
- **Preconditions**: None
- **Steps**:
  1. Parse YAML with GraphQL route SchemaValidation config
  2. Verify effective defaults (failOnError=true, validateVariables=true)
  3. Verify nil config returns safe defaults
  4. Validate enabled config without schemaFile (should fail)
- **Expected Results**: GraphQLSchemaValidation config parses and validates correctly

#### TestFunctional_OpenAPIValidation_TestDataSpecs
- **Description**: Test that OpenAPI spec test data files are loadable
- **Preconditions**: Test data files exist in test/testdata/openapi/
- **Steps**:
  1. Verify items-api.yaml can be referenced in config
  2. Verify minimal.yaml can be referenced in config
  3. Verify invalid.yaml exists (for negative testing)
- **Expected Results**: All test data spec files are accessible

#### TestFunctional_OpenAPI_SpecURLLoading
- **Description**: Test hardened remote OpenAPI spec loading (bounded fetch, external-ref deny)
- **Preconditions**: None (uses in-process httptest servers)
- **Steps**:
  1. Load a valid spec from a URL and verify it parses; verify a second load is served from cache (no refetch) and Invalidate forces a refetch
  2. Load a spec whose $ref targets a second URL and verify the load fails with "disallowed external reference" (external refs are denied unless explicitly allowed)
  3. Load a spec from a URL that never responds with a short caller context deadline and verify the fetch aborts promptly (every fetch is also capped by a 30s client timeout instead of the unbounded http.DefaultClient)
  4. Load a spec from a URL returning HTTP 500 and verify the status code is surfaced in the error
- **Expected Results**: Remote spec loading cannot hang startup/reload, denies external references by default (SSRF/local-file read protection), and surfaces fetch errors

### Functional Operator Tests

#### TestFunctional_APIRoute_OpenAPIValidation
- **Description**: Test CRD APIRoute with OpenAPIValidation field
- **Preconditions**: None
- **Steps**:
  1. Create APIRoute with OpenAPIValidation specFile
  2. Create APIRoute with OpenAPIValidation specURL
  3. Create APIRoute with OpenAPIValidation specConfigMapRef
  4. Create APIRoute with all OpenAPIValidation options
  5. Create APIRoute with disabled OpenAPIValidation
  6. Create APIRoute without OpenAPIValidation (nil)
  7. Update APIRoute adding OpenAPIValidation
  8. Create full APIRoute with OpenAPIValidation and other features
- **Expected Results**: All CRD variants validate successfully

#### TestFunctional_GRPCRoute_ProtoValidation
- **Description**: Test CRD GRPCRoute with ProtoValidation field
- **Preconditions**: None
- **Steps**:
  1. Create GRPCRoute with ProtoValidation descriptorFile
  2. Create GRPCRoute with ProtoValidation all options
  3. Create GRPCRoute with ProtoValidation configMapRef
  4. Create GRPCRoute with disabled ProtoValidation
  5. Update GRPCRoute adding ProtoValidation
- **Expected Results**: All CRD variants validate successfully

#### TestFunctional_GraphQLRoute_SchemaValidation
- **Description**: Test CRD GraphQLRoute with SchemaValidation field
- **Preconditions**: None
- **Steps**:
  1. Create GraphQLRoute with SchemaValidation schemaFile
  2. Create GraphQLRoute with SchemaValidation all options
  3. Create GraphQLRoute with SchemaValidation configMapRef
  4. Create GraphQLRoute with disabled SchemaValidation
  5. Update GraphQLRoute adding SchemaValidation
- **Expected Results**: All CRD variants validate successfully

#### TestFunctional_CRD_ValidationConfigPreservation
- **Description**: Test CRD deep copy preserves validation settings
- **Preconditions**: None
- **Steps**:
  1. Deep copy APIRoute with OpenAPIValidation, verify fields preserved
  2. Deep copy GRPCRoute with ProtoValidation, verify fields preserved
  3. Deep copy GraphQLRoute with SchemaValidation, verify fields preserved
  4. Verify deep copy independence (modifying copy doesn't affect original)
- **Expected Results**: Deep copy preserves all validation config fields

### Integration Tests

#### TestIntegration_OpenAPIValidation_ValidRequestProxy
- **Description**: Test gateway with OpenAPI validation proxies valid requests
- **Preconditions**: Backend service running on port 8801
- **Steps**:
  1. Send valid GET request through validation middleware to backend
  2. Send valid POST request with JSON body through validation middleware
- **Expected Results**: Valid requests pass validation and reach backend

#### TestIntegration_OpenAPIValidation_RejectInvalidBody
- **Description**: Test gateway rejects invalid request body
- **Preconditions**: Backend service running
- **Steps**:
  1. Send POST without Content-Type header
  2. Verify 400 response with validation error message
- **Expected Results**: Invalid body is rejected with 400

#### TestIntegration_OpenAPIValidation_RejectInvalidParams
- **Description**: Test gateway rejects invalid query parameters
- **Preconditions**: Backend service running
- **Steps**:
  1. Send GET with non-numeric limit parameter
  2. Verify 400 response
  3. Send GET with valid numeric limit parameter
  4. Verify 200 response
- **Expected Results**: Invalid params rejected, valid params accepted

#### TestIntegration_OpenAPIValidation_LogOnlyMode
- **Description**: Test log-only mode passes invalid requests
- **Preconditions**: Backend service running
- **Steps**:
  1. Configure validation with failOnError=false
  2. Send invalid request (missing Content-Type)
  3. Verify request passes through to backend (not 400)
- **Expected Results**: Invalid requests pass in log-only mode

#### TestIntegration_OpenAPIValidation_WithRateLimiting
- **Description**: Test validation and rate limiting both active
- **Preconditions**: Backend service running
- **Steps**:
  1. Chain rate limit and validation middlewares
  2. Send valid request
  3. Verify request passes both middlewares
- **Expected Results**: Both middlewares work together

#### TestIntegration_OpenAPIValidation_WithTransform
- **Description**: Test validation and header transform both active
- **Preconditions**: Backend service running
- **Steps**:
  1. Chain header transform and validation middlewares
  2. Send valid request
  3. Verify response has transformed headers
- **Expected Results**: Both middlewares work together

#### TestIntegration_OpenAPIValidation_WithAuthentication
- **Description**: Test validation runs after auth middleware
- **Preconditions**: None
- **Steps**:
  1. Chain auth, validation, and proxy middlewares
  2. Send request
  3. Verify execution order: auth → validation → proxy
- **Expected Results**: Middleware chain order is correct

#### TestIntegration_OpenAPIValidation_WithCircuitBreaker
- **Description**: Test validation and circuit breaker both active
- **Preconditions**: Backend service running
- **Steps**:
  1. Chain circuit breaker and validation middlewares
  2. Send valid request
  3. Verify request passes both middlewares
- **Expected Results**: Both middlewares work together

### E2E Tests

#### TestE2E_OpenAPIValidation_GatewayStartup
- **Description**: Test gateway starts with OpenAPI validation enabled
- **Preconditions**: Backend service running
- **Steps**:
  1. Start gateway with OpenAPI validation middleware
  2. Verify gateway is running
  3. Verify health endpoint responds
- **Expected Results**: Gateway starts cleanly with validation enabled

#### TestE2E_OpenAPIValidation_ValidPost
- **Description**: Test valid POST request passes validation end-to-end
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Send POST with valid JSON body containing "name" field
  2. Verify 200 or 201 response from backend
- **Expected Results**: Valid POST passes validation and reaches backend

#### TestE2E_OpenAPIValidation_InvalidPost
- **Description**: Test invalid POST requests return 400
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Send POST without Content-Type header → 400
  2. Send POST with missing required "name" field → 400
  3. Send POST with invalid JSON → 400
- **Expected Results**: All invalid POST variants return 400

#### TestE2E_OpenAPIValidation_ValidQueryParams
- **Description**: Test valid query parameters pass validation
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Send GET with valid limit and offset params
  2. Send GET without query params
  3. Verify both return 200
- **Expected Results**: Valid query params pass validation

#### TestE2E_OpenAPIValidation_InvalidQueryParams
- **Description**: Test invalid query parameter types return 400
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Send GET with non-integer limit → 400
  2. Send GET with non-integer offset → 400
- **Expected Results**: Invalid query param types return 400

#### TestE2E_OpenAPIValidation_WithCORS
- **Description**: Test OpenAPI validation with CORS headers
- **Preconditions**: Backend service running, gateway started with CORS
- **Steps**:
  1. Send CORS preflight request
  2. Verify CORS headers in response
  3. Send actual CORS request with validation
  4. Verify both CORS headers and validation work
- **Expected Results**: CORS and validation work together

#### TestE2E_OpenAPIValidation_WithRateLimiting
- **Description**: Test OpenAPI validation with rate limiting
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Send valid request → passes both rate limit and validation
  2. Send invalid request → rejected by validation
- **Expected Results**: Both features work together

#### TestE2E_OpenAPIValidation_WithBasicAuth
- **Description**: Test OpenAPI validation with basic auth
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Send authenticated valid request → 200
  2. Send unauthenticated request → 401 (rejected by auth before validation)
- **Expected Results**: Auth runs before validation

#### TestE2E_OpenAPIValidation_WithAPIKeyAuth
- **Description**: Test OpenAPI validation with API key auth
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Send request with valid API key → 200
  2. Send request without API key → 401
- **Expected Results**: API key auth and validation work together

#### TestE2E_OpenAPIValidation_WithOIDCAuth
- **Description**: Test OpenAPI validation with OIDC auth (simulated)
- **Preconditions**: Backend service running, gateway started
- **Steps**:
  1. Send request with Bearer token → 200
  2. Send request without token → 401
- **Expected Results**: OIDC auth and validation work together

#### TestE2E_OpenAPIValidation_Metrics
- **Description**: Test OpenAPI validation metrics available
- **Preconditions**: Backend service running, gateway started with metrics
- **Steps**:
  1. Start gateway with metrics and OpenAPI validation config
  2. Make request to generate metrics
  3. Verify gateway is running
- **Expected Results**: Gateway with validation and metrics runs correctly

#### TestE2E_OpenAPIValidation_HotReload
- **Description**: Test hot-reload changes OpenAPI spec without restart
- **Preconditions**: Backend service running
- **Steps**:
  1. Start config watcher with initial OpenAPI validation config
  2. Update config file with different spec file and failOnError
  3. Verify watcher detects change
  4. Verify new config has updated spec file and failOnError value
- **Expected Results**: Config changes are detected and applied

#### TestE2E_OpenAPIValidation_WithCacheConfig
- **Description**: Test OpenAPI validation with cache configuration
- **Preconditions**: None
- **Steps**:
  1. Create config with both cache and OpenAPI validation on same route
  2. Validate config
- **Expected Results**: Both features can be configured together

## OpenAPI Validation Performance Test Cases

Performance test cases for routes with OpenAPI validation enabled, deployed in K8s
(namespace: avapigw-test). Each scenario measures the overhead of OpenAPI validation
combined with other gateway features under sustained load.

**Common Setup**: Gateway accessible via HTTPS at NodePort 30150. CRDs defined in
`test/performance/operator/crds-validation-perftest.yaml`. Load profile: 3 min
(30s warmup → 2m sustain → 30s cooldown). Configs in `test/performance/configs/`.
Runner script: `test/performance/scripts/run-validation-perftest.sh`.

### TestPerf_Validated_HTTP_Basic
- **Description**: Baseline HTTP throughput with OpenAPI validation only (no extra features)
- **Route Path**: `/api/v1/validated/basic/items`
- **Route Name**: `perf-validated-http-basic`
- **Config**: `k8s-validated-http-basic.yaml`
- **Expected Behavior**: All valid GET requests pass OpenAPI validation and are proxied to backend. Invalid requests (wrong params, missing body on POST) are rejected with 400.
- **Success Criteria**:
  - P99 latency < 500ms at 200 RPS sustained
  - Error rate (5xx) < 1%
  - Validation rejection rate (4xx) < 5% for valid traffic
  - Throughput ≥ 180 RPS sustained

### TestPerf_Validated_HTTP_RateLimit
- **Description**: OpenAPI validation combined with rate limiting (100 RPS, burst 200)
- **Route Path**: `/api/v1/validated/ratelimit/items`
- **Route Name**: `perf-validated-http-ratelimit`
- **Config**: `k8s-validated-http-ratelimit.yaml`
- **Expected Behavior**: Requests first pass OpenAPI validation, then rate limiting. When rate limit is exceeded, 429 responses are returned. Valid requests within limit return 200.
- **Success Criteria**:
  - P99 latency < 500ms for accepted requests
  - 429 responses appear when exceeding 100 RPS
  - No 5xx errors from validation + rate limit interaction
  - Rate limit correctly enforced after validation passes

### TestPerf_Validated_HTTP_Cache
- **Description**: OpenAPI validation combined with Redis Sentinel caching (TTL 5m)
- **Route Path**: `/api/v1/validated/cache/items`
- **Route Name**: `perf-validated-http-cache`
- **Config**: `k8s-validated-http-cache.yaml`
- **Expected Behavior**: First request validates and fetches from backend (cache miss). Subsequent identical requests validate and serve from Redis cache (cache hit). Cache hits should have lower latency.
- **Success Criteria**:
  - P99 latency < 300ms at 200 RPS (cache hits dominate)
  - Cache hit ratio > 80% after warmup
  - Error rate (5xx) < 1%
  - Throughput ≥ 190 RPS sustained

### TestPerf_Validated_HTTP_Transform
- **Description**: OpenAPI validation combined with request/response transformation
- **Route Path**: `/api/v1/validated/transform/items`
- **Route Name**: `perf-validated-http-transform`
- **Config**: `k8s-validated-http-transform.yaml`
- **Expected Behavior**: Requests are validated against OpenAPI spec, then request body is wrapped and response fields are filtered (allow: id, name; deny: password, secret).
- **Success Criteria**:
  - P99 latency < 600ms at 200 RPS (transform adds overhead)
  - Error rate (5xx) < 1%
  - Response bodies do not contain denied fields (password, secret)
  - Throughput ≥ 170 RPS sustained

### TestPerf_Validated_HTTP_Encoding
- **Description**: OpenAPI validation combined with response encoding (gzip/deflate)
- **Route Path**: `/api/v1/validated/encoding/items`
- **Route Name**: `perf-validated-http-encoding`
- **Config**: `k8s-validated-http-encoding.yaml`
- **Expected Behavior**: Requests are validated, then responses are compressed using gzip or deflate based on Accept-Encoding header. Compressed responses should be smaller.
- **Success Criteria**:
  - P99 latency < 500ms at 200 RPS
  - Content-Encoding header present in responses
  - Error rate (5xx) < 1%
  - Throughput ≥ 180 RPS sustained

### TestPerf_Validated_HTTP_CORS
- **Description**: OpenAPI validation combined with CORS middleware
- **Route Path**: `/api/v1/validated/cors/items`
- **Route Name**: `perf-validated-http-cors`
- **Config**: `k8s-validated-http-cors.yaml`
- **Expected Behavior**: Requests with Origin header receive CORS response headers. Preflight OPTIONS requests are handled by CORS middleware before validation. Actual requests pass both CORS and validation.
- **Success Criteria**:
  - P99 latency < 500ms at 200 RPS
  - Access-Control-Allow-Origin header present in responses
  - Error rate (5xx) < 1%
  - Throughput ≥ 180 RPS sustained

### TestPerf_Validated_HTTP_OIDC
- **Description**: OpenAPI validation combined with OIDC/JWT authentication
- **Route Path**: `/api/v1/validated/oidc/items`
- **Route Name**: `perf-validated-http-oidc`
- **Config**: `k8s-validated-http-oidc.yaml`
- **Expected Behavior**: Unauthenticated requests are rejected with 401 before validation runs. Authenticated requests (valid JWT Bearer token) pass auth, then OpenAPI validation, then proxy.
- **Success Criteria**:
  - Unauthenticated: 100% 401 responses, P99 < 100ms
  - Authenticated: P99 latency < 600ms at 150 RPS
  - No 5xx errors
  - Auth middleware runs before validation middleware

### TestPerf_Validated_HTTP_APIKey
- **Description**: OpenAPI validation combined with API key authentication
- **Route Path**: `/api/v1/validated/apikey/items`
- **Route Name**: `perf-validated-http-apikey`
- **Config**: `k8s-validated-http-apikey.yaml`
- **Expected Behavior**: Requests without X-API-Key header are rejected with 401. Requests with valid API key pass auth, then OpenAPI validation, then proxy.
- **Success Criteria**:
  - Unauthenticated: 100% 401 responses, P99 < 100ms
  - Authenticated: P99 latency < 500ms at 200 RPS
  - No 5xx errors
  - API key validation runs before OpenAPI validation

### TestPerf_Validated_HTTP_LogOnly
- **Description**: OpenAPI validation in log-only mode (failOnError=false)
- **Route Path**: `/api/v1/validated/logonly/items`
- **Route Name**: `perf-validated-http-logonly`
- **Config**: `k8s-validated-http-logonly.yaml`
- **Expected Behavior**: All requests pass through to backend regardless of validation result. Validation errors are logged but do not reject requests. This measures pure validation overhead without rejection.
- **Success Criteria**:
  - P99 latency < 500ms at 200 RPS
  - 0% rejection rate (all requests pass through)
  - Error rate (5xx) < 1%
  - Throughput ≥ 190 RPS sustained
  - Validation metrics show logged violations

### TestPerf_Validated_HTTPS
- **Description**: HTTPS TLS termination combined with OpenAPI validation
- **Route Path**: `/api/v1/validated/https/items`
- **Route Name**: `perf-validated-https`
- **Config**: `k8s-validated-https.yaml`
- **Expected Behavior**: TLS handshake at gateway, then OpenAPI validation, then proxy to backend. Measures combined TLS + validation overhead.
- **Success Criteria**:
  - P99 latency < 600ms at 200 RPS (TLS adds overhead)
  - Error rate (5xx) < 1%
  - TLS handshake successful with Vault PKI certificates
  - Throughput ≥ 170 RPS sustained

### TestPerf_Validated_GRPC_Basic
- **Description**: gRPC throughput with protobuf descriptor-based request validation
- **Route Path**: gRPC service `api.v1.TestService/Unary`
- **Route Name**: `perf-validated-grpc-basic`
- **Config**: `k8s-validated-grpc-basic.yaml`
- **Expected Behavior**: gRPC requests are validated against proto descriptors before forwarding. Invalid messages are rejected with gRPC INVALID_ARGUMENT status.
- **Success Criteria**:
  - P99 latency < 50ms for unary calls
  - Error rate < 1%
  - Throughput ≥ 500 RPS for unary calls
  - Proto validation does not significantly degrade gRPC performance

### TestPerf_Validated_GraphQL_Basic
- **Description**: GraphQL throughput with schema-based query/mutation validation
- **Route Path**: `/graphql/validated/basic`
- **Route Name**: `perf-validated-graphql-basic`
- **Config**: `k8s-validated-graphql-basic.yaml`
- **Expected Behavior**: GraphQL queries and mutations are validated against the schema before execution. Invalid queries are rejected with validation error response.
- **Success Criteria**:
  - P99 latency < 500ms at 150 RPS
  - Error rate (5xx) < 1%
  - Schema validation errors return proper GraphQL error format
  - Throughput ≥ 130 RPS sustained

### TestPerf_Validated_Comparison_BaselineVsValidation
- **Description**: Compare baseline (no validation) vs validation-enabled route performance
- **Route Paths**: Baseline route vs `/api/v1/validated/basic/items`
- **Expected Behavior**: Validation adds measurable but acceptable overhead compared to baseline. The overhead should be consistent and predictable.
- **Success Criteria**:
  - Validation overhead < 20% additional latency vs baseline
  - Validation overhead < 15% throughput reduction vs baseline
  - P99 latency delta < 100ms between baseline and validated routes
  - No memory leaks during sustained validation load

### TestPerf_Validated_LogOnly_Vs_FailOnError
- **Description**: Compare log-only mode vs fail-on-error mode performance
- **Route Paths**: `/api/v1/validated/logonly/items` vs `/api/v1/validated/basic/items`
- **Expected Behavior**: Log-only mode should have similar or slightly lower latency since it skips error response generation. Both modes perform the same validation work.
- **Success Criteria**:
  - Log-only mode latency ≤ fail-on-error mode latency
  - Both modes show validation metrics
  - Log-only mode has 0% rejection rate
  - Fail-on-error mode rejects invalid requests with 400

### TestPerf_Validated_Metrics_Verification
- **Description**: Verify validation performance metrics are exposed in VictoriaMetrics
- **Route Paths**: All validated routes
- **Expected Behavior**: After running performance tests, VictoriaMetrics should contain validation-specific metrics including request counts, validation durations, and error rates per route.
- **Success Criteria**:
  - `avapigw_http_requests_total` metric present with route labels
  - `avapigw_http_request_duration_seconds` histogram present
  - `avapigw_openapi_validation_total` metric present with result labels
  - `avapigw_openapi_validation_errors_total` metric present for routes with validation errors
  - Metrics queryable via VictoriaMetrics API at http://127.0.0.1:8428

---

## Aggregate (Fan-out) Mirroring Tests

Aggregate mirroring fans a single client request out to multiple backends in
parallel, optionally merges their responses (or wraps them in labeled
envelopes), and returns a single aggregated response. It is additive and
distinct from single-destination `MirrorConfig` shadow traffic.

### AGG-15 — Functional (`test/functional/aggregate_test.go`, `-tags=functional`)

In-process httptest backends are used for deterministic merge behavior, matching
the existing in-proc functional-test convention.

#### TestFunctional_Aggregate_REST_Merge (F-1)
- **Description**: REST aggregate deep-merge across three REST backends into one merged JSON document.
- **Steps**: fan out to 3 JSON backends; deep-merge nested objects, preserve scalars, concatenate arrays.
- **Expected**: single merged JSON; `gateway_aggregate_requests_total`=1, `targets_total`=3; duration histogram observed.

#### TestFunctional_Aggregate_REST_Envelope_NonJSON (F-2)
- **Description**: REST aggregate of non-JSON (text/plain) backends falls back to labeled envelopes.
- **Expected**: JSON array of `{target,status,payload}` frames; non-JSON payloads JSON-string-encoded; one frame per target.

#### TestFunctional_Aggregate_GraphQL_MergeDataAndErrors (F-3)
- **Description**: GraphQL aggregate deep-merges `data`/`extensions` and concatenates `errors[]`.
- **Expected**: merged `data` contains all backends' fields; `errors[]` contains every backend error.

#### TestFunctional_Aggregate_GRPC_Unary_Combined (F-4)
- **Description**: gRPC unary aggregate combines JSON-mappable unary payloads via a caller-injected Invoker.
- **Expected**: descriptor-based merge produces a combined response (`Merged=true`).

#### TestFunctional_Aggregate_WS_InterleavedFrames (F-5)
- **Description**: WebSocket aggregate interleaves labeled frames from all backend streams (StreamMux).
- **Expected**: every backend message becomes a valid labeled JSON frame; all targets' frames present and interleaved.

#### TestFunctional_Aggregate_GRPC_Streaming_FramedInterleave (F-6)
- **Description**: gRPC streaming aggregate framed interleave + FailMode behavior on stream error.
- **Expected**: framed interleave from all streams; FailMode=any tolerates one failed stream; FailMode=all fails.

#### TestFunctional_Aggregate_CoexistWithSingleMirror (F-7)
- **Description**: An aggregate route and a single-mirror-configured normal route coexist through one proxy (regression).
- **Expected**: aggregate route returns merged JSON; normal route proxies to its primary unchanged; `MirrorConfig` preserved.

#### TestFunctional_Aggregate_MetricsQueryable (F-8)
- **Description**: Aggregate metrics emitted and queryable, including per-target error metric on partial failure.
- **Expected**: request/targets counters, per-target error counter for the dead target, duration + merge histograms observable.

### AGG-15 NDJSON — Functional (`test/functional/aggregate_ndjson_test.go`, `-tags=functional`)

NDJSON aggregate merge strategy. In-process httptest NDJSON backends keep merges
deterministic; each test asserts the response content type and body shape (valid
NDJSON: each line valid JSON, whole body NOT valid JSON).

#### TestFunctional_Aggregate_NDJSON_Explicit_SortDedupeLimit (FN-1)
- **Description**: Explicit `strategy: ndjson` across two `application/x-ndjson` backends; records collected, sorted by `_time` (numeric), deduped by `id` (first-wins), limited.
- **Expected**: `Content-Type: application/stream+json` + `X-Content-Type-Options: nosniff`; 2 records after sort+dedupe+limit; first-wins keeps the earliest-`_time` duplicate.

#### TestFunctional_Aggregate_NDJSON_Explicit_PlainConcatOrder (FN-1b)
- **Description**: Explicit ndjson with `TimeField=""` (sort disabled) over two backends.
- **Expected**: plain concat preserves target-then-line order; `application/stream+json` output.

#### TestFunctional_Aggregate_NDJSON_AutoPromotion (FN-2)
- **Description**: Deep strategy (non-ndjson) + NDJSON bodies -> auto-promotion on the would-be-envelope branch. Data-driven over content types `application/x-ndjson`, `application/jsonl`, `application/stream+json`, charset-parameterized, and a body-heuristic case (no NDJSON content type, detection via valid-per-line/invalid-whole shape).
- **Expected**: `application/stream+json` output (auto-promoted); records sorted by `_time` by the auto path too.

#### TestFunctional_Aggregate_NDJSON_NoPromotion_MixedNonJSON (FN-2b)
- **Description**: Mixed targets (one NDJSON, one non-JSON text) with deep strategy.
- **Expected**: NOT promoted (not ALL bodies NDJSON) -> labeled envelope JSON array, `application/json`.

#### TestFunctional_Aggregate_NDJSON_Regression_JSONMergeUnchanged (FN-3a)
- **Description**: deep/shallow/replace JSON merge over valid-JSON-whole bodies (data-driven over the three strategies).
- **Expected**: NEVER promoted; output stays `application/json` (single JSON document); strategy-specific semantics intact (deep nests, shallow replaces nested object, replace keeps last doc only).

#### TestFunctional_Aggregate_NDJSON_Regression_DeepMergeByteIdentical (FN-3b)
- **Description**: Deep-merge fixture (nested object + arrays) with the NDJSON code path present.
- **Expected**: nested objects deep-merged, arrays concatenated (unchanged behavior); `application/json`.

#### TestFunctional_Aggregate_NDJSON_Regression_MergeDisabledEnvelopes (FN-3c)
- **Description**: Merge DISABLED over NDJSON bodies.
- **Expected**: labeled envelope (NDJSON detection only fires on the would-be-envelope branch of an enabled non-ndjson merge); `application/json`.

#### TestFunctional_Aggregate_NDJSON_CoexistWithSingleMirror (FN-3d)
- **Description**: An NDJSON aggregate route and a single-mirror normal route coexist through one proxy (additive-config regression for the ndjson strategy).
- **Expected**: ndjson aggregate route returns a `_time`-sorted `application/stream+json` stream; normal single-mirror route proxies to its primary unchanged; `MirrorConfig` preserved.

### AGG-16 — Integration (`test/integration/aggregate_test.go`, `-tags=integration`)

Runs against the docker-compose test ENV (Vault PKI, Keycloak, REST/gRPC
backends, Redis standalone + sentinel). All addresses/credentials come from ENV.

#### TestIntegration_Aggregate_MTLS_PerTarget / _MTLS_LiveBackend (I-1)
- **Description**: Per-target mTLS fan-out using Vault-PKI-issued client certs; plus the live mTLS REST backend (8804).
- **Expected**: both mTLS backends require + accept the client cert; merged response returned; live 8804 accepts the Vault PKI client cert.

#### TestIntegration_Aggregate_OIDC_PerTarget (I-2)
- **Description**: Per-target OIDC fan-out using a real Keycloak `backend-test` client_credentials token injected as a per-target bearer.
- **Note**: in-test bearer-validating backends are used because the live OIDC backend (8803) validates `iss=host.docker.internal:8090`, unreachable from host-side tests (token `iss` is `127.0.0.1:8090`). The real token is still acquired from Keycloak.

#### TestIntegration_Aggregate_MixedAuth (I-3)
- **Description**: One aggregate with none / basic / API-key / OIDC-bearer targets (live 8801/8805 when reachable, in-test otherwise).
- **Expected**: every target authenticates (status 200) and appears as a labeled envelope.

#### TestIntegration_Aggregate_Spool_RedisStandalone (I-4)
- **Description**: 256KB body spooled off-heap to Redis standalone, retrieved intact, key cleaned up.

#### TestIntegration_Aggregate_Spool_RedisSentinel (I-5)
- **Description**: Same off-heap spool round-trip against Redis Sentinel (failover-tolerant connection via the Docker sentinel dialer).

#### TestIntegration_Aggregate_Spool_RedisOutage_MemoryFallback (I-6)
- **Description**: Redis outage mid-flight (failing store) → memory fallback; Put/Get still succeed; spool error metric increments.

#### TestIntegration_Aggregate_CoOperatesWithStack (I-7)
- **Description**: Aggregate route co-operates with CORS + transform via the real proxy per-route middleware chain, and with a redis-sentinel-backed cache.
- **Expected**: CORS headers applied to the aggregate response; transform strips denied fields from the merged body; sentinel cache stores/serves the aggregated response.

#### TestIntegration_Aggregate_PartialFailure_AllFailModes (I-8)
- **Description**: Partial failure (one dead target) under each FailMode (all/any/quorum-majority/quorum-explicit).
- **Expected**: all → error; any → success; quorum majority (2/3) → success; explicit quorum 3 → error; dead-target error metric increments in all cases.

### AGG-16 NDJSON — Integration (`test/integration/aggregate_ndjson_test.go`, `-tags=integration`)

NDJSON aggregate strategy against the docker-compose ENV. The live REST backends
(rest_api_1..5) do not emit native NDJSON, so the NDJSON record streams are
produced by in-test backends while the production REST aggregate invoker, the
proxy per-route middleware chain, and the merge pipeline all run through real
code paths.

#### TestIntegration_Aggregate_NDJSON_ThroughProxy (IN-1)
- **Description**: REST aggregate `strategy: ndjson` over two in-test NDJSON backends wired through a real `ReverseProxy` + per-route middleware manager; RFC3339 `_time` sort, `id` dedupe (first-wins), `limit: 2`.
- **Expected**: client receives `application/stream+json` + `nosniff`; 2 records after RFC3339 sort + first-wins dedupe + limit; `targets_total`=2.

#### TestIntegration_Aggregate_NDJSON_AutoPromotion (IN-2)
- **Description**: Deep strategy + `application/jsonl` bodies -> auto-promotion on the would-be-envelope branch.
- **Expected**: `application/stream+json` output; all records collected and sorted by `_time` by the auto path.

#### TestIntegration_Aggregate_NDJSON_PartialFailure_FailModeAny (IN-3)
- **Description**: Two successful NDJSON targets + one dead target under FailMode=any with `strategy: ndjson`.
- **Expected**: request succeeds (dead tolerated); only the 3 records from the 2 successful targets contribute; `application/stream+json`; dead-target error metric increments.

## E2E Tests — Aggregate (Fan-out) Mirroring, OPERATOR MODE (AGG-17)

Files: `test/e2e/aggregate_operator_e2e_test.go`, `test/e2e/aggregate_live_helpers_test.go`
(build tag `e2e`). These are user-journey tests against the **deployed** operator-mode
gateway + operator in the `avapigw-test` namespace (docker-desktop). All endpoints,
namespaces, route names and credentials come from ENV (`AVAPIGW_E2E_NAMESPACE`,
`AVAPIGW_E2E_FIXTURE_NAMESPACE`, `AVAPIGW_E2E_AGGREGATE_ROUTE`,
`AVAPIGW_E2E_AGGREGATE_PATH`, `AVAPIGW_E2E_VM_URL`, `AVAPIGW_E2E_GATEWAY_SVC`,
`TEST_REDIS_SENTINEL_*`) with sane defaults; no hardcoded secrets.

Namespaces: the gateway/operator DEPLOYMENT lives in the deployment namespace
(`AVAPIGW_E2E_NAMESPACE`, default `avapigw-test`), while the DO-04 perf FIXTURE CRs
(`crds-do04-aggregate.yaml` — `do04-aggregate-route`, `do04-http-backend-1/2`) live in a
dedicated fixture namespace (`AVAPIGW_E2E_FIXTURE_NAMESPACE`, default `avapigw-perf`) so
the namespace-scoped admission duplicate checker never rejects them against the
avapigw-test suites. The operator watches all namespaces, so fixture CRs still reconcile
and reach the gateway. Fixture reads (`do04-*` route/backends and the live gate) use the
fixture namespace; routes the tests create themselves use the deployment namespace.

The whole live suite auto-skips (CI-safe) when `AVAPIGW_E2E_LIVE=0`, when the
cluster/aggregate CRD is not reachable in the FIXTURE namespace, or when the gateway
Service has no ready endpoints in the deployment namespace (stale CRDs alone — e.g. left
over after an undeploy — must not enable the suite, since port-forwards and
Ready-condition waits can only fail without a live deployment).

How the gateway is reached: the gateway Service exposes only TLS listeners
(https/8443, grpcs/9443) + metrics/9090; NodePorts are not host-routable on
docker-desktop, so tests use `kubectl port-forward svc/avapigw <local>:8443` (unique
local port per test for parallel isolation) and an InsecureSkipVerify TLS client.

#### TestE2E_Aggregate_E1_CRDReconciledAndEffective (E-1)
- **Description**: Aggregate config delivered ONLY via CRD → reconciled → effective.
- **Steps**: read deployed `do04-aggregate-route` CRD; assert `spec.aggregate`
  (enabled, ≥2 targets, deep merge) is present; poll until operator sets
  `status.conditions[Ready]=True reason=Reconciled`; port-forward and hit the aggregate
  path, asserting the gateway owns the route (stamps `X-Request-Id`, non-5xx).
- **Expected**: aggregate config is CRD-only; route reconciled to Ready; route effective
  at the gateway data plane.

#### TestE2E_Aggregate_E2_FanOutMerge (E-2)
- **Description**: Fan-out + merge verified through the deployed gateway.
- **Steps**: port-forward; GET the aggregate path; if a 2xx merged JSON object is
  returned, assert it is a non-empty merged document.
- **Expected**: merged response from both backends. **Documented skip** when the deployed
  gateway image does not execute fan-out at the data plane (runtime proxy built without
  `proxy.WithAggregateHandler` in `cmd/gateway/app.go`); the test first proves the route
  is reachable, then skips with the precise root cause. Fan-out+merge behavior is covered
  at functional (`test/functional/aggregate_test.go`) and integration
  (`test/integration/aggregate_test.go`) layers.

#### TestE2E_Aggregate_E3_RedisSentinelSpool (E-3)
- **Description**: Redis Sentinel spool verified in-cluster via CRD.
- **Steps**: apply an aggregate APIRoute with `spool.backend=redis` + `redisRef.sentinel`
  (addrs/master from ENV) and a low `thresholdBytes` (large-body path); poll until Ready;
  verify the spool block round-tripped on the reconciled CRD; delete the CRD (cleanup,
  unique name per run).
- **Expected**: redis-sentinel spool aggregate CRD admitted, reconciled Ready, spool
  config effective; resource cleaned up.

#### TestE2E_Aggregate_E4_MetricsScraped (E-4)
- **Description**: Metrics scraped into VictoriaMetrics.
- **Steps**: query VM (`http://localhost:8428`) for `up{namespace=...}` and a
  representative `gateway_*` series (proves the scrape pipeline); drive aggregate traffic;
  query VM for `gateway_aggregate_*` series.
- **Expected**: gateway scraped into VM. **Documented skip** for the aggregate-series
  assertion when the data plane emits no aggregate metrics (same root cause as E-2);
  scrape-pipeline health is still asserted. Aggregate metric emission is covered by
  `test/functional/aggregate_test.go`.

#### TestE2E_Aggregate_E5_VaultAuthAndBackends (E-5)
- **Description**: Vault kubernetes-auth path used by gateway+operator; backends healthy.
- **Steps**: read gateway pod logs and assert Vault usage (CA pool loaded / certificate
  issued from Vault); read Backend CRD status for `do04-http-backend-1/2`, asserting the
  `Healthy` condition is True with ≥1 healthy host.
- **Expected**: gateway uses the Vault path; aggregate fan-out backends are healthy.

#### TestE2E_Aggregate_E6_AdmissionRejectsInvalid (E-6)
- **Description**: Admission rejects invalid aggregate CRDs in-cluster (data-driven).
- **Cases**: zero targets (MinItems), invalid `failMode` enum, invalid `merge.strategy`
  enum, invalid `spool.backend` enum.
- **Steps**: `kubectl apply` each invalid manifest (short RFC-1123 names); assert the
  apiserver rejects it at admission via the CRD kubebuilder validation surface with a
  message naming the violated constraint; defensive cleanup.
- **Expected**: every invalid aggregate CRD is rejected at admission; no invalid object
  is persisted.

### AGG-17 NDJSON — E2E (`test/e2e/aggregate_ndjson_e2e_test.go`, `-tags=e2e`)

NDJSON aggregate strategy driven via operator CRD against the deployed
`avapigw-test` gateway + operator. Self-gated on `AVAPIGW_E2E_LIVE` + live
cluster reachability (same gate as AGG-17). Each test first PROBES the installed
APIRoute CRD with a server-side dry-run apply: if the CRD predates the NDJSON
merge surface (no `strategy=ndjson` / `timeField` / `keyField` / `limit`), the
test SKIPS gracefully with the precise reason (CRD re-apply pending) rather than
failing.

#### TestE2E_Aggregate_EN1_NDJSONStrategyViaCRD (EN-1)
- **Description**: Apply an aggregate APIRoute with `strategy: ndjson` + `timeField`/`keyField`/`limit` (unique name per run), reconcile, drive through the deployed gateway.
- **Subtests**:
  - `crd_admitted_and_reconciled` — always asserts: route admitted, reconciled `Ready`, and the ndjson/timeField/keyField/limit fields round-trip on the CRD spec.
  - `data_plane_ndjson_stream` — drives the route; asserts `application/stream+json` + `nosniff` + NDJSON stream shape (valid-per-line / invalid-as-a-whole, `_time`-sorted when records are JSON objects). **Documented skip** when the running gateway does not hot-reload newly-created APIRoutes into the live data plane (routes loaded at gateway startup) so the fresh route falls through to the catch-all; the data-plane NDJSON behavior is fully covered at the functional/integration layers.
- **Expected**: CRD admission + operator reconcile of the ndjson strategy fully asserted; data-plane stream asserted when the route is served, else graceful skip.

#### TestE2E_Aggregate_EN2_AdmissionNDJSON (EN-2)
- **Description**: Black-box admission (via `kubectl --dry-run=server`) of the ndjson merge surface.
- **Subtests**: valid ndjson aggregate CRD (`strategy: ndjson`, `timeField`/`keyField`, `limit: 0`) is admitted; a negative `limit` (`-1`) is rejected at admission with a message naming the `limit` constraint (`Minimum=0`).
- **Expected**: valid ndjson CRD admitted; negative limit rejected; persists nothing (dry-run). Graceful skip when the installed CRD lacks the NDJSON surface.

## API Key Authentication Tests

### Functional Tests

Files: `test/functional/apikey_test.go`, `test/functional/apikey_validation_test.go`
(build tag `functional`). They cover the tightened load-time validation of static API
key entries: an enabled config is rejected unless every entry carries either a raw key
or a pre-computed hash compatible with the effective hash algorithm (previously such
entries were accepted and silently failed every lookup), plus hash-only authentication
and the `store_error` metric reason.

#### TestFunctional_APIKey_ConfigValidation_StaticKeys
- **Description**: Data-driven test of tightened static key entry validation at config load
- **Preconditions**: None
- **Steps**:
  1. Validate entries with a raw key only → accepted for any algorithm
  2. Validate hash-only entries with an algorithm-compatible hash (sha256 64-hex, sha512 128-hex, bcrypt string, uppercase hex) → accepted
  3. Validate an entry with neither key nor hash → rejected ("either key or hash must be set")
  4. Validate entries whose hash cannot match the algorithm (fake "hash1" under sha256, sha512-length hash under sha256 and vice versa, non-bcrypt hash under bcrypt, any hash-only entry under plaintext, non-hex value of digest length) → rejected ("hash is not compatible with hash algorithm")
  5. Validate a disabled config containing a broken entry → accepted (validation applies to enabled configs only)
- **Expected Results**: Entries that could never authenticate are rejected at load time with the offending index/ID in the error; usable entries load

#### TestFunctional_APIKey_ConfigValidation_VaultBcrypt
- **Description**: Test bcrypt/Vault-store incompatibility rejection at config load
- **Preconditions**: None
- **Steps**:
  1. Validate hashAlgorithm bcrypt with store.type=vault → rejected at load (bcrypt hashes are salted and cannot address Vault paths)
  2. Validate hashAlgorithm bcrypt with an enabled vault section → rejected at load
  3. Validate hashAlgorithm sha256 with the vault store → accepted
  4. Validate hashAlgorithm bcrypt with the memory store → accepted
- **Expected Results**: bcrypt+Vault is rejected at load time with guidance to use sha256/sha512; bcrypt remains supported for the memory store

#### TestFunctional_APIKey_Validator_HashOnlyKeys
- **Description**: Test hash-only static entries (no raw key material in config) authenticate through the public Validator API
- **Preconditions**: None
- **Steps**:
  1. For each of sha256, sha512, bcrypt: configure a hash-only entry, validate the raw key → KeyInfo returned with ID/scopes
  2. Validate a wrong key → ErrAPIKeyNotFound
  3. Configure an uppercase-hex sha256 hash → raw key still validates (hash normalization for lookup and comparison)
- **Expected Results**: Hash-only entries authenticate presented raw keys; config never needs to retain plaintext keys

#### TestFunctional_APIKey_Validator_StoreErrorMetric
- **Description**: Test that store outages surface as reason="store_error" while genuine misses stay reason="not_found"
- **Preconditions**: None (uses a failing Store stub and an isolated metrics registry)
- **Steps**:
  1. Build a validator with a store whose lookups fail with ErrStoreUnavailable and dedicated metrics
  2. Validate any key → error wrapping ErrStoreUnavailable (not ErrAPIKeyNotFound)
  3. Gather the registry → apikey_validation_total{status="error",reason="store_error"} == 1 and reason="not_found" == 0
  4. Build a validator with a normal memory store, validate an unknown key → reason="not_found" == 1 and reason="store_error" == 0
- **Expected Results**: Operators can distinguish store outages (store_error) from genuine misses (not_found) in metrics; outage errors propagate to the caller

## Redis-Backed Distributed Rate Limiting Tests

Route-level HTTP rate limiting is now enforced by the per-route middleware chain
(previously it was silently ignored by the data path), and `rateLimit.store: redis`
enables a distributed Lua token bucket shared across gateway instances through Redis
standalone or Redis Sentinel. Functional tests run against miniredis (no external
dependencies); integration/e2e tests run against the LIVE docker-compose Redis
Sentinel (`TEST_REDIS_SENTINEL_ADDRS`, `TEST_REDIS_SENTINEL_MASTER_NAME`,
`TEST_REDIS_MASTER_PASSWORD`). New metrics:
`gateway_middleware_redis_rate_limit_{allowed,denied,errors}_total` and
`gateway_middleware_redis_rate_limit_duration_seconds`.

### Functional Tests

File: `test/functional/ratelimit_redis_functional_test.go` (build tag `functional`).
All gateway tests exercise the FULL production route chain via the new
`helpers.StartGatewayWithRouteMiddleware` (RouteMiddlewareManager + CacheFactory wired
the same way `cmd/gateway` initApplication does).

#### TestFunctional_RateLimit_RouteChain_MemoryStore
- **Description**: Test that route-level rate limiting with the default in-memory store is enforced through the full gateway route chain (newly enforced behavior)
- **Preconditions**: None (in-process httptest backend)
- **Steps**:
  1. Start a gateway with a route rateLimit {enabled, rps=1, burst=3} via StartGatewayWithRouteMiddleware
  2. Fire 8 sequential GET requests
  3. Verify the first 3 are 200, the tail is 429, at most one refill token of slack
  4. Verify the backend hit counter equals the number of admitted requests
- **Expected Results**: Burst admitted, past-burst throttled with 429, throttled requests never reach the backend

#### TestFunctional_RateLimit_RouteChain_RedisStore
- **Description**: Test the redis-store distributed limiter through the full route chain with miniredis
- **Preconditions**: None (miniredis)
- **Steps**:
  1. Start a gateway with route rateLimit {store: redis, url: miniredis, rps=1, burst=3, keyPrefix "fnrl:"}
  2. Fire 8 requests → verify allowed∈[3,4], denied≥4, first three 200, last 429
  3. Verify the 429 carries Retry-After: 1 and the JSON rate-limit error body
  4. Verify the token bucket key `fnrl:ratelimit:<route>` exists in miniredis
  5. Verify gateway_middleware_redis_rate_limit_{allowed,denied}_total grow with the per-route label
- **Expected Results**: Distributed token bucket enforced through the production chain; bucket state and metrics observable

#### TestFunctional_RateLimit_RouteChain_RedisStore_PerClient
- **Description**: Test PerClient=true bucket isolation keyed by client IP derived from X-Forwarded-For behind a trusted proxy
- **Preconditions**: None (miniredis; swaps the process-global client IP extractor and restores it)
- **Steps**:
  1. Configure trusted proxy 127.0.0.1 (as cmd/gateway initClientIPExtractor does) and route rateLimit {store: redis, perClient: true, burst=2}
  2. Client A (XFF 10.1.1.1) sends 3 requests → 200, 200, 429
  3. Client B (XFF 10.2.2.2) sends 2 requests → 200, 200
  4. Verify per-client bucket keys `...:client:10.1.1.1` and `...:client:10.2.2.2` exist in redis
- **Expected Results**: Each client gets its own token bucket; exhausting one client's bucket does not affect others

#### TestFunctional_RateLimit_RouteChain_RedisStore_SharedBucket
- **Description**: Test that two gateway instances sharing redis + key prefix + scope enforce ONE combined token bucket
- **Preconditions**: None (miniredis)
- **Steps**:
  1. Start two gateways (different ports) with the same route name, redis URL and key prefix (burst=4)
  2. Alternate 10 requests across both gateways
  3. Verify combined allowed∈[4,5] (10 would mean per-instance buckets) and denied≥5
  4. Verify a single shared bucket key exists
- **Expected Results**: Distributed semantics: the burst is shared across instances, not per-instance

#### TestFunctional_RateLimit_RouteChain_RedisStore_FailOpenOutage
- **Description**: Test failOpen (default) behavior during a redis outage
- **Preconditions**: None (miniredis stopped mid-test)
- **Steps**:
  1. Start gateway with redis-store rate limit, verify a request passes with redis up
  2. Stop miniredis
  3. Fire 4 requests → all 200
  4. Verify gateway_middleware_redis_rate_limit_errors_total{policy="fail_open"} grows by ≥4
- **Expected Results**: Fail-open keeps the route available during outages and records an error metric per decision

#### TestFunctional_RateLimit_RouteChain_RedisStore_FailClosedOutage
- **Description**: Test failOpen=false behavior during a redis outage
- **Preconditions**: None (miniredis stopped mid-test)
- **Steps**:
  1. Start gateway with redis-store rate limit {failOpen: false}, verify a request passes with redis up
  2. Stop miniredis
  3. Fire 3 requests → all 429; backend hit counter unchanged
  4. Verify errors_total{policy="fail_closed"} grows by ≥3
- **Expected Results**: Fail-closed rejects traffic (429) rather than running unlimited during outages

#### TestFunctional_RateLimitAndCache_Redis_ConfigValidationSurface
- **Description**: Data-driven YAML validation surface for the redis rate limiter store and route-level redis cache (loader → validator, the config-file startup path)
- **Preconditions**: None
- **Steps**:
  1. Valid: store=redis with url; store=redis with sentinel (masterName + addrs + password); cache type=redis with sentinel and ttlJitter 0.3
  2. Invalid store enum (etcd) → "invalid store"
  3. store=redis without redis block → "redis configuration with url or sentinel is required"
  4. rateLimit url+sentinel together → "url and sentinel are mutually exclusive"
  5. store=memory with a redis block → "redis configuration is only valid when store is 'redis'"
  6. Invalid cache type enum; cache type=redis without redis block; cache url+sentinel together
  7. cache ttlJitter 1.5 and -0.1 → "ttlJitter must be between 0.0 and 1.0"
- **Expected Results**: The YAML surface enforces store/type enums, redis-required-when-selected, url/sentinel exclusivity and ttlJitter bounds

### Integration Tests

Files: `test/integration/ratelimit_sentinel_test.go`, `test/integration/ratelimit_vault_test.go`
(build tag `integration`, LIVE docker-compose sentinel; announced Docker-internal master
IPs are reachable through the shared `helpers.SentinelDialer`).

#### TestIntegration_RateLimit_Sentinel_BurstSplit
- **Description**: Test the distributed token bucket against the REAL Redis Sentinel deployment (mymaster, 3 sentinels, password)
- **Preconditions**: docker-compose sentinel + REST backend 8801 running
- **Steps**:
  1. Build a RedisRateLimiter on a sentinel failover client (ENV-config: mymaster, 26379-26381, password), wrap a gateway route handler with it (rps=1, burst=5, unique keyPrefix)
  2. Fire 12 requests → verify allowed∈[5,6] and denied≥6 (observed 5×200/7×429)
  3. Inspect the master through the sentinel-discovered client: bucket key `<prefix>ratelimit:<scope>` exists, carries hash fields t/ts and a positive idle TTL
- **Expected Results**: ~burst/rest 200/429 split enforced via sentinel; bucket observable on the master (EVALSHA token bucket, PEXPIRE 65000)

#### TestIntegration_RateLimit_Sentinel_SharedBucket
- **Description**: Test one combined token bucket across two gateway instances through the real sentinel
- **Preconditions**: docker-compose sentinel + REST backend 8801 running
- **Steps**:
  1. Start two gateways, each with its own RedisRateLimiter instance sharing scope + prefix + sentinel (burst=6)
  2. Alternate 12 requests across both → verify combined allowed∈[6,7], denied≥5 (observed 6/6)
  3. Verify exactly one shared bucket key exists on the master
- **Expected Results**: Combined rate enforced across instances through the shared sentinel-managed bucket

#### TestIntegration_RateLimit_RouteChain_SentinelMasterURL
- **Description**: Test the FULL production route chain (CRD-shaped route config through RouteMiddlewareManager) with store=redis pointing at the sentinel-managed master via its host-mapped URL
- **Preconditions**: docker-compose sentinel + REST backend 8801 running
- **Steps**:
  1. Start gateway via StartGatewayWithRouteMiddleware with route rateLimit {store: redis, url: redis://default:password@127.0.0.1:6380, burst=4, keyPrefix}
  2. Fire 10 requests → verify allowed∈[4,5], denied≥5 (observed 4×200/6×429)
  3. Verify the bucket key with the configured prefix exists on the master
- **Expected Results**: CRD-expressible redis rate limiting works end-to-end through the production chain against the sentinel-managed master

#### TestIntegration_RateLimit_RouteChain_Sentinel_FailOpen
- **Description**: Test the full route chain building a sentinel-mode limiter internally (no injected client) with fail-open availability semantics
- **Preconditions**: docker-compose sentinel + REST backend 8801 running
- **Steps**:
  1. Route rateLimit carries the real sentinel config (mymaster, 3 addrs, password), failOpen default, burst=100, short connect/read timeouts
  2. First (warm-up) request triggers the lazy chain build including the best-effort connectivity check → must answer 200
  3. Fire 5 requests → all 200 whether or not the announced master is reachable from the host (unreachable on macOS, fail-open applies; reachable on Linux CI, bucket enforces)
  4. Log whether the bucket key appeared on the master (reachability probe)
- **Expected Results**: Fail-open sentinel-configured routes never block traffic; decisions stay bounded by readTimeout

#### TestIntegration_RateLimit_RedisStore_VaultPassword
- **Description**: Test the redis rate limiter resolving the Redis password from Vault (passwordVaultPath), mirroring the cache Vault-password pattern
- **Preconditions**: docker-compose sentinel + Vault (myroot) + REST backend 8801 running
- **Steps**:
  1. Write the master password to Vault KV `redis/ratelimit` (key "password")
  2. Start gateway (full route chain + Vault client) with route rateLimit {store: redis, url WITHOUT password, passwordVaultPath, failOpen: false, burst=3}
  3. Fire 8 requests → verify allowed∈[3,4], denied≥4 (a password failure with failOpen=false would reject everything)
  4. Verify the bucket key exists on the password-protected master
- **Expected Results**: Password resolved from Vault; limiter authenticates and enforces limits through the full chain

### E2E Tests

File: `test/e2e/redis_ratelimit_cache_e2e_test.go` (build tag `e2e`, LIVE docker-compose env).

#### TestE2E_Sentinel_DistributedRateLimit
- **Description**: Distributed rate limiting user journey through REAL Redis Sentinel discovery across two gateway instances
- **Preconditions**: docker-compose sentinel + REST backend 8801 running
- **Steps**:
  1. Two gateways, each with a sentinel-mode RedisRateLimiter (mymaster, 3 addrs, password; rps=1, burst=6)
  2. Alternate 14 requests → combined allowed∈[6,7], denied≥7 (observed 6×200/8×429)
  3. Verify exactly one shared bucket key exists on the sentinel-managed master
  4. Wait 1.5s (rps=1) → traffic recovers with 200
  5. Register + Init the middleware metrics on a registry, serve /metrics, verify gateway_middleware_redis_rate_limit_{allowed,denied,errors}_total and the duration histogram are exposed
- **Expected Results**: One shared bucket across instances via sentinel; bucket refills; new metrics exposed on the metrics endpoint

## Route-Level Redis/Sentinel Cache via CRD Tests

Route-level caching is now CRD-expressible (`APIRoute spec.cache.type: redis` +
`spec.cache.redis` with url XOR sentinel, keyPrefix, ttlJitter, hashKeys, retry,
Vault password paths). The operator translates the spec to gateway JSON and the
webhook validates it; gRPC/GraphQL routes accept but admission-warn (data path
not implemented there yet).

### Functional Operator Tests

File: `test/functional/operator/redis_route_config_functional_test.go` (build tag `functional`).

#### TestFunctional_APIRoute_RedisCache_Admission
- **Description**: Black-box admission of APIRoute route-level redis cache configuration through the public webhook validator
- **Preconditions**: None
- **Steps**:
  1. type=redis with sentinel (env-shaped: mymaster, 3 addrs, password) → admitted with plaintext-secret warning
  2. type=redis with standalone url → admitted
  3. url+sentinel together → rejected "mutually exclusive"
  4. type=redis without redis block → rejected "cache.redis is required"
  5. redis block without url or sentinel → rejected "requires either url or sentinel"
  6. type=memory with redis block → rejected "only valid when cache.type is 'redis'"
  7. ttlJitter 1.5 / -0.1 → rejected "ttlJitter must be between 0.0 and 1.0"
- **Expected Results**: Admission enforces the same rules as gateway config validation; plaintext sentinel secrets warn

#### TestFunctional_APIRoute_RedisRateLimit_Admission
- **Description**: Black-box admission of APIRoute distributed rate limiter configuration
- **Preconditions**: None
- **Steps**:
  1. store=redis with sentinel → admitted with plaintext warning; store=redis with url + readTimeout → admitted
  2. store=redis without redis block → rejected; url+sentinel → rejected "mutually exclusive"
  3. store=memory with redis block → rejected; invalid enum (etcd) → rejected
  4. Disabled rate limit with store=redis but no redis block → still rejected (store validated even when disabled)
- **Expected Results**: Store selection and Redis connection rules enforced at admission, before the limiter is ever enabled

#### TestFunctional_Route_RedisStore_UnappliedWarnings
- **Description**: Test truthful admission warnings for redis-backed stores per route kind
- **Preconditions**: None
- **Steps**:
  1. GRPCRoute with rateLimit.store=redis and cache.type=redis → admitted with "not applied for GRPCRoute" warnings (in-memory limiter, no caching on the gRPC data path)
  2. GraphQLRoute likewise → admitted with NO unapplied rate-limit warning (redis store enforced via the shared route middleware chain) but a precise cache warning: redis cache has no effect for POST GraphQL operations (GET-only caching)
  3. APIRoute with the same config → NO unapplied warnings (redis store/cache are enforced for HTTP routes)
- **Expected Results**: Forward-compatible acceptance with honest operator warnings; APIRoutes warn-free

#### TestFunctional_APIRoute_RedisConfig_GatewayContract
- **Description**: Full CRD → gateway contract: admitted APIRoute spec with sentinel cache + redis rate limit survives the operator's JSON translation and passes gateway validation
- **Preconditions**: None
- **Steps**:
  1. Build APIRoute with cache {type: redis, sentinel, keyPrefix, ttlJitter 0.25, hashKeys} and rateLimit {store: redis, sentinel, perClient, failOpen: false, readTimeout}
  2. ValidateCreate admits it
  3. Marshal the spec to JSON (as the controller does) and unmarshal onto config.Route
  4. Embed in a GatewayConfig → config.ValidateConfig passes
  5. Verify effective values survive: GetEffectiveStore()=redis, GetEffectiveFailOpen()=false, TTLJitter, HashKeys, sentinel identity
- **Expected Results**: Every CRD field round-trips intact into the gateway's runtime configuration

### Integration Tests

File: `test/integration/cache_sentinel_route_test.go` (build tag `integration`, LIVE docker-compose sentinel).

#### TestIntegration_Cache_Sentinel_RouteChain
- **Description**: Route cache data path against the REAL sentinel deployment: miss → hit, key prefix, TTL jitter bounds, POST bypass, invalidation
- **Preconditions**: docker-compose sentinel + REST backend 8801 running
- **Steps**:
  1. Gateway route wrapped with the route cache middleware backed by a sentinel-mode cache (mymaster, 3 addrs, password; TTL 2m, ttlJitter 0.2, unique keyPrefix)
  2. First GET → 200 without X-Cache; wait for the entry on the master
  3. Second GET → 200 with X-Cache: HIT
  4. Verify entry `<prefix>GET:/api/v1/items` exists on the master; PTTL within [ttl*(1-jitter), ttl*(1+jitter)]
  5. POST bypasses the cache; deleting the key restores miss behavior
- **Expected Results**: Sentinel-backed response caching works on the gateway data path with jittered TTLs and correct method semantics

#### TestIntegration_Cache_RouteChain_MasterURL_FullChain
- **Description**: FULL production route chain (RouteMiddlewareManager + CacheFactory from CRD-shaped route config) with redis cache on the sentinel-managed master, including hashKeys
- **Preconditions**: docker-compose sentinel + REST backend 8801 running
- **Steps**:
  1. Start gateway via StartGatewayWithRouteMiddleware with route cache {type: redis, url: master host-mapped URL, hashKeys: true, TTL 90s}
  2. GET → miss; wait for fill; GET → X-Cache: HIT
  3. Verify the SHA256-hashed key exists and the raw key does NOT
  4. Verify TTL is positive and ≤ 90s (no jitter configured)
- **Expected Results**: CRD-expressible redis cache is served through the production chain; hashKeys stores hashed keys only

### E2E Tests

File: `test/e2e/redis_ratelimit_cache_e2e_test.go` (build tag `e2e`).

#### TestE2E_FullConfig_AuthRateLimitCacheTransformCORS
- **Description**: Full-config journey on ONE route combining JWT auth + distributed rate limit (redis on the sentinel-managed master) + redis cache (TTL jitter) + response transform (deny fields) + CORS, built through the production per-route middleware chain
- **Preconditions**: docker-compose sentinel + REST backend 8801 running
- **Steps**:
  1. Request without token → 401; with an invalid token → 401 (auth first, no tokens consumed)
  2. Authenticated GET (no Origin) → 200, cache miss, body transformed (data field denied); entry appears on the master
  3. Authenticated GET with allowed Origin → X-Cache: HIT + Access-Control-Allow-Origin added per-request + still transformed
  4. Authenticated GET with a non-allowlisted Origin on the hit path → no gateway CORS grant
  5. Repeat authenticated GETs until burst is exhausted → 429 with Retry-After: 1, rejected before the cache
  6. Verify rate limit bucket and cache entry on the sentinel-managed master; cache PTTL within jitter bounds [ttl*(1-j), ttl*(1+j)]
  7. Serve the middleware metrics registry over HTTP → gateway_middleware_redis_rate_limit_{allowed,denied}_total{route="full-config-route"} and the duration histogram are exposed
- **Expected Results**: All five features cooperate on one route with correct ordering (auth → rate limit → CORS → cache → transform → proxy); sentinel-backed state and new metrics observable

## Webhook Admission Lifecycle Tests

The validating webhooks admit lifecycle-driven updates that can never introduce new
conflicts, eliminating the webhook/finalizer deadlock: updates to TERMINATING objects
(deletionTimestamp set) are admitted unconditionally so finalizer removal always
proceeds; METADATA-ONLY updates (semantically unchanged spec) run local spec validation
only and skip duplicate/cross-kind conflict checks; and terminating resources are
excluded from every duplicate and cross-kind conflict CANDIDATE set so a stuck
terminating peer never blocks a surviving or replacement resource.

Files: `internal/operator/webhook/finalizer_deadlock_test.go` (runs under
`test-operator-unit/functional/integration`).

### TestValidateUpdate_TerminatingObjectAdmitted
- **Description**: Updates to a resource being deleted are admitted unconditionally, even when the object overlaps a live peer and even when its spec is locally invalid (data-driven across APIRoute, Backend, GRPCRoute, GraphQLRoute)
- **Preconditions**: Resource has deletionTimestamp set (finalizer keeps it alive); an overlapping live peer exists
- **Steps**:
  1. Create a terminating resource whose spec conflicts with a live peer
  2. Submit a finalizer-removal update (metadata change) via ValidateUpdate
  3. Repeat with a locally invalid spec on the terminating object
- **Expected Results**: All updates admitted — deletion can always complete; no duplicate/conflict/spec error blocks the terminating object

### TestValidateUpdate_FinalizerAddOnLegacyOverlappingPair
- **Description**: Metadata-only updates (finalizer/label add) on LEGACY overlapping resources (admitted before conflict rules tightened) are not blocked by duplicate or cross-kind checks
- **Preconditions**: Two overlapping same-kind resources already persisted (legacy state)
- **Steps**:
  1. Add a finalizer to one of the pair without touching the spec
  2. Submit the update to the webhook
- **Expected Results**: Update admitted — the unchanged spec cannot introduce NEW conflicts; local spec validation still runs

### TestValidateUpdate_SpecChangeToConflict_StillRejected
- **Description**: The lifecycle short-circuits do not weaken real conflict enforcement: a genuine spec change that creates an identical-specificity duplicate is still rejected
- **Preconditions**: A live peer resource exists
- **Steps**:
  1. Update a live resource's spec to collide with the peer (identical-specificity match)
  2. Submit the update
- **Expected Results**: Update rejected with a conflict error naming the peer

### TestValidateUpdate_TerminatingPeerUnblocksSurvivor
- **Description**: A conflicting candidate that is TERMINATING is skipped from the conflict set, so the surviving resource can be created/updated while its old peer drains
- **Preconditions**: A terminating resource (deletionTimestamp set, finalizer pending) holds the contested match/hosts
- **Steps**:
  1. Create (or spec-update) a replacement resource with the same match as the terminating peer
  2. Submit to the webhook; also exercise Backend/GRPCBackend/GraphQLBackend cross-kind host:port candidate sets (TestCrossKindBackendChecks_TerminatingCandidatesSkipped)
- **Expected Results**: Replacement admitted — terminating peers never block survivors; live peers still conflict

### TestValidateUpdate_MetadataOnlyInvalidSpec_StillValidated
- **Description**: The metadata-only short-circuit skips CONFLICT checks only — local spec validation still applies to non-terminating objects
- **Preconditions**: Persisted resource with a spec that fails current local validation
- **Steps**:
  1. Submit a metadata-only update (old spec == new spec, both locally invalid) on a NON-terminating object
- **Expected Results**: Update rejected by local spec validation (invalid specs do not ride through on the metadata-only path)

## Same-Kind Route Overlap Relaxation Tests (gRPC + GraphQL)

Same-kind duplicate admission now mirrors the APIRoute philosophy: only
IDENTICAL-SPECIFICITY duplicates — match conditions the data-plane router cannot order
deterministically for a user — are rejected. Match conditions of DIFFERENT specificity
coexist and are resolved by the router's specificity sort. gRPC: nested (non-identical)
service/method prefixes are now ADMITTED (`com.example` + `com.example.user` coexist;
longest-prefix wins at the data plane); identical prefixes/exacts and double catch-alls
remain rejected. GraphQL: block specificity is scored with the data plane's
authoritative `graphqlrouter.Specificity` weights (path exact=1000 | prefix=500+len |
regex=100; operationName exact=500 | prefix=250+len | regex=50; operationType set=+200;
+10 per header) — a generic route vs a more specific one on the same path is ADMITTED;
only equal-specificity blocks whose values can cover the same request are rejected.

Files: `internal/operator/webhook/duplicate_grpc_relax_test.go`,
`internal/operator/webhook/duplicate_graphql_relax_test.go` (run under
`test-operator-unit/functional/integration`).

### TestCheckGRPCRouteDuplicate_SpecificityTopology
- **Description**: Data-driven topology of gRPC same-kind admission: identical exact services (same/absent methods), identical service prefixes, identical method prefixes, and double catch-alls are conflicts; nested service prefixes, nested method prefixes, exact-vs-prefix service matches, different exact methods, and catch-all vs specific are admitted
- **Preconditions**: Existing GRPCRoute persisted; DuplicateChecker with fake client
- **Steps**:
  1. For each pair in the table, persist route A and run CheckGRPCRouteDuplicate on route B
- **Expected Results**: Only identical-specificity pairs report conflicts; every different-specificity pair is admitted

### TestGRPCDataplaneParity_NestedPrefixesDeterministic
- **Description**: Admission/data-plane parity — every ADMITTED nested-prefix pair must be deterministically ordered by the gRPC router (longest prefix wins), and identical-prefix pairs the webhook REJECTS are exactly those the router cannot order by specificity (equal priority, name tie-break only)
- **Preconditions**: gRPC router loaded with the admitted pair
- **Steps**:
  1. Load `com.example` and `com.example.user` prefix routes in both insertion orders
  2. Match a request under the longer prefix; also exercise nested METHOD prefixes (TestGRPCDataplaneParity_NestedMethodPrefixesDeterministic)
  3. For the rejected identical-prefix pair, verify both routes compile to equal priority (TestGRPCDataplaneParity_IdenticalPrefixesAmbiguous)
- **Expected Results**: Longest-prefix route wins regardless of load order; the webhook rejects exactly the pairs whose ordering would fall through to the arbitrary name tie-break

### TestCheckGraphQLRouteDuplicate_SpecificityTopology
- **Description**: Data-driven topology of GraphQL same-kind admission: identical exact paths (with equal operationType/operationName surfaces), identical prefixes, and double catch-alls conflict; exact vs prefix on the same path, nested prefixes, typed vs untyped blocks, named vs unnamed operations, header-count differences, and catch-all vs specific are admitted (different specificity)
- **Preconditions**: Existing GraphQLRoute persisted; DuplicateChecker with fake client
- **Steps**:
  1. For each pair in the table, persist route A and run CheckGraphQLRouteDuplicate on route B
- **Expected Results**: Only identical-specificity blocks with overlapping values (path/operationType/operationName/headers all able to cover one request) are conflicts

### TestGraphQLMatchSpecificity_ParityWithRouterWeights
- **Description**: The webhook's block scoring delegates to the exported `graphqlrouter.Specificity` — the single source of truth — so admission and data-plane precedence cannot drift
- **Preconditions**: None
- **Steps**:
  1. Score representative CRD match blocks via the webhook path and via the router package directly
- **Expected Results**: Identical scores for identical blocks (exact/prefix/regex path, operationName, operationType, headers)

### TestGraphQLDataplaneParity_SpecificityOrdering
- **Description**: Every ADMITTED different-specificity GraphQL pair resolves deterministically in the router — the more specific block wins regardless of load order; TestGraphQLBasicVsDo04FixturePair_Admitted pins the real-world fixture pair (generic `/graphql` route vs the DO-04 header-conditioned route) as admitted and deterministic
- **Preconditions**: GraphQL router loaded with the admitted pair in both orders
- **Steps**:
  1. Load pair, Match a request satisfying both blocks
  2. Reverse load order and repeat
- **Expected Results**: Same winner in both orders (higher specificity); no admission rejection for the pair

## Route Precedence Determinism Tests (HTTP, gRPC, GraphQL)

All three routers now yield a DETERMINISTIC total match order independent of input
order (Kubernetes map iteration, cross-namespace merges, file loads). HTTP and gRPC
routers order by descending priority with an ascending route-NAME tie-break at equal
priority. The GraphQL router now sorts compiled routes by descending Specificity with
the same name tie-break (previously input-order/first-match — operator-mode map
iteration made matches nondeterministic). `LoadRoutes` with an empty/nil slice clears
each router.

Files: `internal/router/router_determinism_test.go`,
`internal/grpc/router/router_determinism_test.go`,
`internal/graphql/router/specificity_test.go` (unit suites).

### TestRouter_EqualPriorityNameTieBreak (HTTP + gRPC)
- **Description**: Two routes compiling to EQUAL priority (e.g. same-length prefixes, equal-priority regex pairs) always match in route-name order, in both insertion orders and via AddRoute increments
- **Preconditions**: None
- **Steps**:
  1. Load equal-priority routes named "b-route", "a-route" (insertion order b, a); match a request satisfying both
  2. Reverse insertion order and repeat; also load via incremental AddRoute
- **Expected Results**: "a-route" (name ascending) wins every time; shuffled load orders produce identical match tables (TestRouter_LoadRoutes_ShuffledOrderDeterministic)

### TestRouter_Match_SpecificityIndependentOfLoadOrder (GraphQL)
- **Description**: GraphQL route matching is specificity-ordered, not input-ordered: loading [generic, specific] and [specific, generic] both match the specific route; the full documented specificity ladder (exact > long prefix > short prefix > regex > catch-all; operationType/operationName/headers add weight) is pinned by TestSpecificity_DocumentedOrdering and TestRouter_Match_SpecificityLadder
- **Preconditions**: None
- **Steps**:
  1. Load a generic catch-all and a specific exact-path route in both orders
  2. Match a request satisfying both; shuffle larger route sets (TestRouter_Match_ShuffledDeterminism)
- **Expected Results**: Most specific route always wins; equal-specificity falls back to the name tie-break (TestRouter_Match_EqualSpecificityNameTieBreak); `SortRoutesBySpecificity` orders config slices exactly like LoadRoutes

### TestConfigHandler_CollectGraphQLRoutes_SpecificityOrder (operator handler)
- **Description**: The gateway's operator ConfigHandler hands GraphQL route slices to the applier pre-sorted by `SortRoutesBySpecificity` (and all other resource slices sorted by composite state key — TestConfigHandler_CollectSorted_DeterministicOrder), so apply logs, diffs, and router order stay aligned across identical snapshots
- **Preconditions**: Handler state populated from a snapshot with routes in adversarial map order
- **Steps**:
  1. HandleSnapshot with shuffled resources; capture the slice passed to the applier
- **Expected Results**: Deterministic, specificity-ordered (GraphQL) / key-ordered (others) slices on every call

## Operator FULL_SYNC Empty-Type Clearing Tests

FULL_SYNC snapshots are authoritative: an EMPTY resource type in the merged operator
config now CLEARS the corresponding router/registry (previously `len(...) > 0` guards
skipped empty sets, so deleting the LAST resource of a type left stale state serving
traffic). Emptiness POLICY stays upstream in `operator.ConfigHandler`: an all-types-empty
snapshot is still guarded, and a post-reconnect REGRESSING snapshot (total shrinks) is
still deferred to protect operator restarts; a non-regressing snapshot with one type
empty applies and clears. Nil-component guards remain (partially initialized apps skip
the subsystem).

Files: `cmd/gateway/operator_empty_clear_test.go` (applier seam, real routers),
`internal/gateway/operator/handler_snapshot_keys_test.go` (handler policy seam) — unit
suites; the pairing covers the full HandleSnapshot → applier → router path.

### TestApplyFullConfig_PartialEmptyClearsOnlyEmptyTypes
- **Description**: The full FULL_SYNC apply path with HTTP routes populated and GraphQL routes empty clears the GraphQL router while the HTTP router serves the new set — per-type independence through the operator-mode applier (`ApplyFullConfig`)
- **Preconditions**: Applier over real HTTP router, backend registry, and GraphQL router, each preloaded with one resource
- **Steps**:
  1. ApplyFullConfig with 1 HTTP route, zero GraphQL routes/backends/gRPC resources
  2. Match an HTTP request; count GraphQL routes
- **Expected Results**: GraphQL router count = 0; HTTP route matches; per-type clears covered for HTTP routes, backends, gRPC listener routes, and GraphQL router (sibling TestApplyMerged*_Empty* tests)

### TestConfigHandler_PartialEmptySnapshotApplies_WithinWindow
- **Description**: Handler policy — a NON-regressing FULL_SYNC (total resource count preserved or grown) with one type emptied applies immediately, even inside the post-reconnect regression window
- **Preconditions**: Handler seeded (2 HTTP + 1 GraphQL), MarkReconnected called
- **Steps**:
  1. HandleSnapshot with 3 HTTP routes and zero GraphQL routes (total 3, non-regressing)
- **Expected Results**: Applied — populated type updated, GraphQL state empty; a REGRESSING partial-empty snapshot within the window is still deferred with last-known-good kept (TestConfigHandler_PartialEmptyRegressingSnapshotDeferred_WithinWindow); an ALL-empty snapshot never wipes running config (existing handler_empty_snapshot_test.go)

## Deterministic Operator Snapshots & Leadership-Gated Seeding Tests

Files: `internal/operator/grpc/service_determinism_test.go`,
`internal/operator/grpc/server_leadership_test.go`, `cmd/operator/store_seeding_test.go`
(operator unit suites); `internal/gateway/operator/client_conn_leak_test.go`,
`internal/gateway/operator/handler_snapshot_keys_test.go` (gateway unit suite).

### TestBuildSnapshot_DeterministicChecksum_AcrossInsertionOrders
- **Description**: buildSnapshot orders every resource slice by ascending resource key (namespace/name), so identical store contents produce byte-identical snapshots and checksums regardless of Go map insertion/iteration order — gateways no longer see spurious checksum changes on operator restart
- **Preconditions**: Store populated with all six resource types across multiple namespaces, in several insertion orders
- **Steps**:
  1. Build snapshots from permuted stores; compare checksums and per-type key order
- **Expected Results**: Identical checksums; slices sorted by resource key (TestBuildSnapshot_SlicesSortedByResourceKey); checksum changes exactly when content changes; empty types stay nil

### TestWaitForStoreSeeded_NotElected_ParksPastSeedTimeout
- **Description**: The gRPC store readiness gate is LEADERSHIP-GATED: a non-leader replica (controllers never run, store permanently empty) parks initial-snapshot RPCs past the seed timeout instead of timing out into an empty FULL_SYNC that would wipe a connecting gateway's running config
- **Preconditions**: Server with leadership signal wired (SetLeadershipSignal), replica not elected
- **Steps**:
  1. Call the seeded wait with a context outliving the seed timeout
  2. Elect the replica mid-wait in sibling cases (TestWaitForStoreSeeded_TimeoutClockStartsAtElection, _ElectedThenSeeded)
- **Expected Results**: Not-elected wait reports awaiting_leadership and never opens the gate; the bounded seed-timeout clock starts AT election; nil signal preserves the old single-replica behavior (gating disabled); store revisions on a non-leader do not open the gate

### TestSeedGRPCStore (leadership ordering, cmd/operator)
- **Description**: The operator wires the leadership signal into the gRPC server BEFORE serving and the seeding goroutine waits for election → cache sync → initial reconcile before MarkStoreSeeded; shutdown before/during any stage skips the seed mark
- **Preconditions**: Fake manager elected-channel and cache-sync waiter
- **Steps**:
  1. Run seedGRPCStore with elected closed/never-closed/closed-late and canceled contexts
- **Expected Results**: Seed mark only after election + sync (+ bounded reconcile wait); non-leaders and canceled shutdowns never mark the (empty) store seeded

### TestClient_Connect_ClosesPreviousConnection
- **Description**: The gateway's operator client closes the PREVIOUS gRPC connection before replacing it on reconnect, so retry/reconnect loops cannot leak sockets
- **Preconditions**: Client connected to a mock operator endpoint
- **Steps**:
  1. Connect; capture conn; Connect again; Stop
- **Expected Results**: First conn observed closed before replacement; already-closed conns are logged and skipped; Stop after reconnect never double-closes

### TestConfigHandler_SnapshotThenIncrementalDelete_KeySymmetry
- **Description**: FULL_SYNC seeds handler state under the SAME composite namespace/name key incremental updates use, so a snapshot-seeded resource is addressable by later incremental MODIFY/DELETE events (previously snapshots keyed by bare name, orphaning namespaced increments)
- **Preconditions**: Snapshot with a namespaced resource applied
- **Steps**:
  1. HandleSnapshot seeding `prod/orders-route`; send incremental DELETE for the same namespace/name
  2. Repeat for MODIFY (no duplicate entries) and GraphQL kinds
- **Expected Results**: State entry removed/updated in place; undecodable snapshot resources are logged and skipped without half-clearing state (TestConfigHandler_SnapshotUndecodableResourceSkipped)

## TLS Handshake Duration Metrics Tests

The `gateway_tls_handshake_duration_seconds` histogram (labels: tls version, mode) is
now WIRED on both the HTTPS listener and the gRPC TLS listener via
`tls.InstrumentHandshakeTiming` (GetConfigForClient starts the clock at ClientHello;
the per-connection VerifyConnection observes on success). Failed connection
verifications record `gateway_tls_handshake_errors_total{reason="verify_connection_failed"}`
and no duration sample. Existing GetConfigForClient/VerifyConnection chains (route TLS,
ALPN enforcement, connection metrics) are preserved.

Files: `internal/tls/handshake_test.go`, `internal/gateway/listener_handshake_metrics_test.go`,
`internal/grpc/server/tls_handshake_metrics_test.go` (unit suites);
`test/e2e/tls_handshake_metrics_e2e_test.go` (build tag `e2e`).

### TestListener_TLSHandshakeDurationMetric_Recorded
- **Description**: A real HTTPS handshake through the gateway Listener records exactly one histogram sample with a sane (0, 5s) duration while the existing connection counter still fires
- **Preconditions**: HTTPS listener with self-signed certs, isolated Prometheus registry
- **Steps**:
  1. Start listener; TLS-dial and complete one HTTP request; gather registry
- **Expected Results**: count=1, 0 < sum < 5s, gateway_tls_connections_total=1; failed mTLS handshakes record NO duration sample (TestListener_TLSHandshakeMetrics_MutualBadClientCert); VerifyConnection rejections count a bounded handshake error instead

### TestGRPCListener_TLSHandshakeDurationMetric_Recorded
- **Description**: A TLS handshake against the gRPC listener (h2 ALPN) records on the same histogram; the instrumentation is installed AFTER ALPN verification so the observation wraps the full chain (TestConfigureGRPCTLS_HandshakeTiming_ALPNFailureChainPreserved)
- **Preconditions**: GRPC listener with TLS enabled, isolated registry
- **Steps**:
  1. Start listener; raw TLS dial with h2 ALPN; send HTTP/2 preface; read server answer; gather registry
- **Expected Results**: ≥1 histogram sample with sane duration

### TestE2E_TLS_HandshakeDurationMetric_GatewayJourney
- **Description**: Full user journey — a gateway configured with an HTTPS listener via `gateway.New(cfg, WithGatewayTLSMetrics(...))` serves TLS traffic and the handshake-duration histogram becomes observable, proving the gateway→listener metrics wiring end-to-end (not just the listener seam)
- **Preconditions**: None external (self-generated certs, direct-response route, isolated registry)
- **Steps**:
  1. Build a gateway config with one HTTPS listener (SIMPLE mode, generated cert/key) and a direct-response route
  2. Start the gateway; make HTTPS requests through it (InsecureSkipVerify client)
  3. Gather the registry and locate gateway_tls_handshake_duration_seconds
- **Expected Results**: ≥1 sample after traffic (0 before), sum > 0; response served over TLS with the expected body

## WSS (WebSocket-over-TLS) Gateway Tests

Secure WebSocket journeys through a REAL gateway HTTPS listener (TLS mode
SIMPLE, self-signed test CA): the gateway terminates TLS, upgrades the
connection, and proxies frames to the plain-ws backend `/ws`. The backend
streams data and accepts (does not echo) client messages, so bidirectional
exchange is asserted as write-then-continue-streaming.

Files: `test/e2e/websocket_wss_e2e_test.go` (build tag `e2e`);
helpers `test/helpers/wss_helpers.go`.

### TestE2E_WSS_UpgradeAndStream
- **Description**: Primary secure WebSocket journey — wss:// handshake through the HTTPS listener, then streamed backend data through the TLS-terminating gateway
- **Preconditions**: Backend 1 running (`TEST_BACKEND1_URL`, default http://127.0.0.1:8801)
- **Steps**:
  1. Generate test CA/server certs; start gateway with HTTPS listener (SIMPLE) routing /ws to the backend
  2. Dial wss://…/ws with a CA-trusting dialer
  3. Read 3 streamed messages
- **Expected Results**: 101 Switching Protocols; underlying transport is *tls.Conn; 3 messages relayed over TLS

### TestE2E_WSS_MessageExchange
- **Description**: Bidirectional exchange over the TLS tunnel — client writes through the gateway, backend streaming continues, graceful close
- **Preconditions**: Backend 1 running
- **Steps**:
  1. Dial wss; write a text frame; read 2 further messages; send close frame
- **Expected Results**: Write accepted; streaming continues after the write; clean close

### TestE2E_WSS_OriginPolicy
- **Description**: Cross-Site WebSocket Hijacking policy on the TLS listener (spec.websocket.allowedOrigins)
- **Preconditions**: Backend 1 running
- **Steps**:
  1. Start wss gateway with allowedOrigins=[https://app.example.com]
  2. Dial with allowed Origin, disallowed Origin, and no Origin header
- **Expected Results**: Allowed origin connects; disallowed origin rejected with 403 during upgrade; no-Origin (non-browser) connects

### TestE2E_WSS_TLSFailureModes
- **Description**: TLS layer rejects broken client trust before any WS traffic
- **Preconditions**: Backend 1 running
- **Steps**:
  1. Dial wss with a dialer lacking the test CA
  2. Dial plaintext ws:// against the HTTPS listener
- **Expected Results**: Certificate-verification error; plaintext-to-TLS dial fails

### TestE2E_WSS_ConcurrentConnections
- **Description**: TLS listener sustains multiple concurrent WSS tunnels
- **Preconditions**: Backend 1 running
- **Steps**:
  1. Open 5 concurrent wss connections; read 2 messages each
- **Expected Results**: 5/5 connect; ≥1 message per connection

## GraphQL-over-WebSocket (graphql-transport-ws) Subscription Tests

The gateway's graphql-ws pipeline (route match → middleware → upgrade →
bidirectional relay) is exercised end-to-end. LIVE-BACKEND LIMITATION
(verified): the reference restapi-example image serves NO /graphql endpoint
(POST and WS upgrade both 404), so subscriptions run against an in-process
mock backend implementing the graphql-transport-ws protocol
(`test/helpers/graphql_ws_helpers.go`) — the documented fallback. KNOWN
PRODUCT LIMITATION (documented in the protocol-negotiation test): the
gateway's client-side upgrader does not echo the negotiated
Sec-WebSocket-Protocol back to the client; the requested protocol IS
forwarded on the backend dial and the relay is protocol-agnostic.

Files: `test/integration/graphql_subscription_test.go` (build tag
`integration`); `test/e2e/graphql_ws_e2e_test.go` (build tag `e2e`);
helpers `test/helpers/graphql_ws_helpers.go`,
`test/helpers/graphql_gateway_helpers.go`.

### TestIntegration_GraphQLWS_SubscriptionLifecycle
- **Description**: Full graphql-transport-ws lifecycle through the gateway relay: connection_init → connection_ack → subscribe → next×3 → complete, plus ping→pong
- **Preconditions**: None external (mock graphql-ws backend)
- **Steps**:
  1. Build production GraphQLHandler (router+proxy) on an httptest server
  2. Upgrade with subprotocol graphql-transport-ws; run the message lifecycle
- **Expected Results**: ack received; 3 next payloads relayed byte-for-byte; terminal complete; pong answered

### TestIntegration_GraphQLWS_ErrorMessage
- **Description**: Backend subscription error frames relay to the client
- **Steps**:
  1. Subscribe with a query the mock fails ("failNow")
- **Expected Results**: Terminal error message, no next events

### TestIntegration_GraphQLWS_ProtocolNegotiation
- **Description**: Subprotocol path through the relay — client-requested graphql-transport-ws is forwarded on the backend dial and negotiated/echoed by the gateway upgrader on the 101 response (RFC 6455)
- **Expected Results**: Backend observes the requested subprotocol; relay functions; client connection negotiates graphql-transport-ws (echoed by the gateway)

### TestIntegration_GraphQLWS_OriginAllowlist
- **Description**: CSWSH origin allowlist on the graphql-ws upgrade
- **Expected Results**: Allowed origin upgrades and completes init; disallowed origin rejected with 403

### TestIntegration_GraphQLWS_RouteAndBackendFailureModes
- **Description**: Failure paths — unmatched route and unreachable backend
- **Expected Results**: Unmatched upgrade fails with 404; when the backend dial fails after a successful client upgrade, the client connection is closed promptly

### TestE2E_GraphQLWS_QueryAndSubscription
- **Description**: Primary GraphQL user journey through a REAL running gateway — HTTP query on /graphql plus graphql-ws subscription on the same endpoint
- **Preconditions**: None external (mock graphql-ws backend)
- **Steps**:
  1. Start gateway (embedded GraphQL pipeline) with an HTTP listener
  2. POST a query; then upgrade and run subscribe → next×3 → complete
- **Expected Results**: Query returns data without errors; subscription delivers all events and completes

### TestE2E_GraphQLWS_ConcurrentSubscriptions
- **Description**: Multiple concurrent subscription tunnels through one gateway
- **Expected Results**: 4/4 subscriptions complete with full event streams

### TestE2E_GraphQLWS_OriginPolicy
- **Description**: spec.websocket.allowedOrigins enforced on the running gateway's graphql-ws upgrade
- **Expected Results**: Allowed origin subscribes; disallowed origin rejected with 403

### TestE2E_GraphQLWS_ErrorPropagation
- **Description**: Backend subscription errors reach the client through the running gateway
- **Expected Results**: Terminal error message, no next events

## TLS-GraphQL + WSS Tests

Secure GraphQL journeys through a REAL gateway HTTPS listener: queries over
HTTPS and graphql-transport-ws subscriptions over wss://, TLS-terminated at
the gateway and relayed to the backend GraphQL WebSocket (mock backend; see
live-backend limitation above).

Files: `test/e2e/graphql_tls_wss_e2e_test.go` (build tag `e2e`).

### TestE2E_GraphQLTLS_QueryOverHTTPS
- **Description**: GraphQL query routed through the HTTPS listener
- **Steps**:
  1. Start gateway with HTTPS listener (SIMPLE, generated certs) + GraphQL pipeline
  2. POST query over HTTPS with a CA-trusting client
- **Expected Results**: Data returned, no errors

### TestE2E_GraphQLTLS_SubscriptionOverWSS
- **Description**: Full secure subscription journey — wss:// upgrade on the HTTPS listener, graphql-ws lifecycle relayed, transport verified as TLS
- **Expected Results**: 101 upgrade; underlying transport *tls.Conn; 3 events + complete relayed over TLS

### TestE2E_GraphQLTLS_WSSFailureModes
- **Description**: TLS trust and origin failures on the secure subscription path
- **Expected Results**: Untrusted CA fails the wss handshake with a certificate error; disallowed origin 403; allowed origin subscribes

## Dedicated CORS Preflight Tests

The browser cross-origin contract through the production per-route
middleware chain: OPTIONS preflights, actual-request grants, global
spec.cors inheritance, and route-level cors overrides. DOCUMENTED PROXY
BEHAVIOR: the reference backend emits its own permissive CORS headers which
the gateway forwards on actual (non-preflight) proxied responses; the
gateway's own deny semantics are asserted against a no-CORS mock backend.

Files: `test/e2e/cors_e2e_test.go` (build tag `e2e`);
`test/functional/cors_preflight_test.go` (build tag `functional`).

### TestE2E_CORS_PreflightGlobalPolicy
- **Description**: OPTIONS preflight on a route inheriting the GLOBAL spec.cors policy
- **Preconditions**: Backend 1 running
- **Steps**:
  1. Start gateway (route middleware chain) with global cors: exact origin + `*.wild.example.com` wildcard
  2. Preflight with allowed, wildcard-subdomain, and denied origins
- **Expected Results**: 204 with echoed Access-Control-Allow-Origin + methods/headers/max-age + Vary: Origin for allowed and wildcard origins; 204 with NO grant for denied origins

### TestE2E_CORS_ActualRequestHeaders
- **Description**: Actual-request CORS semantics — gateway grant on allowed origins, no grant on denied origins (no-CORS mock backend), gateway CORS authoritative over backend-emitted CORS headers on proxied routes
- **Expected Results**: Allowed origin gets exactly the gateway grant (single value) + expose headers; denied origin gets response without any grant (backend grant stripped); no-Origin requests unaffected

### TestE2E_CORS_RouteLevelOverride
- **Description**: Route-level cors block fully replaces the global policy on that route only
- **Expected Results**: Route origin granted with credentials + route maxAge; globally-allowed origin denied on the override route; route origin denied on global routes; actual GET honors the route policy

### TestE2E_CORS_UnmatchedPreflight
- **Description**: Preflight for an unmatched path is not granted CORS
- **Expected Results**: 404 without CORS headers

### TestFunctional_CORS_Preflight
- **Description**: Data-driven preflight matrix over global-only, route-only, and route-overriding-global policies through the production RouteMiddlewareManager chain
- **Expected Results**: Grants/denials, credentials, and max-age per scenario; preflights never reach the terminal handler

### TestFunctional_CORS_ActualRequest
- **Description**: Actual-request grants through the chain (allowed/denied/no-Origin), expose headers, Vary: Origin
- **Expected Results**: Terminal handler reached in all cases; grant only for the allowed origin

## Live Auth-Backend Tests (docker-compose environment)

REAL gateway journeys against the LIVE compose auth backends. All endpoints
are env-overridable (see `helpers.GetLiveAuthBackendConfig`:
TEST_MTLS_REST_BACKEND_ADDR, TEST_OIDC_REST_BACKEND_URL,
TEST_BASIC_REST_BACKEND_URL, TEST_MTLS_GRPC_BACKEND_ADDR,
TEST_OIDC_GRPC_BACKEND_ADDR, TEST_KEYCLOAK_ADDR,
TEST_KEYCLOAK_BACKEND_REALM, TEST_BACKEND_OIDC_CLIENT_ID/SECRET,
TEST_BACKEND_ISSUER_HOST, TEST_VAULT_PKI_CLIENT_ROLE,
TEST_VAULT_BASIC_AUTH_PATH); every test skips cleanly when
Vault/Keycloak/the backend is unreachable. The issuer-rewrite proxy
(`helpers.StartIssuerRewriteProxy`) bridges the host.docker.internal DNS gap
so Keycloak mints tokens with the backend-expected iss while OIDC discovery
keeps pointing the gateway at the proxy.

Files: `test/integration/live_backend_auth_test.go`,
`test/integration/live_grpc_auth_test.go` (build tag `integration`);
helpers `test/helpers/live_env_helpers.go`.

### TestIntegration_LiveBackend_MTLS_VaultPKIFileCerts
- **Description**: Gateway route → rest_api_4 (mTLS) with a client certificate issued at test runtime by the LIVE Vault PKI client-role, configured file-based on the backend TLS block
- **Preconditions**: Vault (:8200) and rest_api_4 (:8804) reachable
- **Steps**:
  1. Issue client cert from pki/issue/client-role; write cert/key/CA to temp files
  2. Start gateway with backend TLS MUTUAL (certFile/keyFile/caFile, serverName localhost)
  3. GET /api/v1/items through the gateway; repeat with a SIMPLE (no client cert) backend
- **Expected Results**: 200 with the client cert; 502 without it (backend rejects the handshake)

### TestIntegration_LiveBackend_MTLS_VaultRuntimeCerts
- **Description**: Same journey with backend tls.vault — the GATEWAY issues its own client certificate from the live Vault PKI at startup (no cert files)
- **Preconditions**: Vault and rest_api_4 reachable
- **Expected Results**: 200 through the gateway with the runtime-issued cert

### TestIntegration_LiveBackend_OIDC_S2S
- **Description**: Gateway route → rest_api_3 (OIDC) — the gateway acquires a client_credentials token from the LIVE Keycloak backend-test realm (gateway-backend client) and attaches it to backend requests
- **Preconditions**: Keycloak (:8090) and rest_api_3 (:8803) reachable
- **Expected Results**: 200 with the gateway-acquired token; 401 pass-through without backend auth

### TestIntegration_LiveBackend_BasicAuth_VaultKV
- **Description**: Gateway route → rest_api_5 (basic) with credentials read from the LIVE Vault KV secret/backend-auth/basic
- **Preconditions**: Vault and rest_api_5 (:8805) reachable
- **Expected Results**: 200 with KV credentials; 401 pass-through without backend auth

### TestIntegration_LiveGRPCBackend_MTLS_VaultPKI
- **Description**: Gateway grpcRoute → grpc_3 (mTLS) with a Vault-PKI-issued client cert — UNARY + SERVER STREAMING + BIDI STREAMING all through the gateway (client→gateway plaintext, gateway→backend mTLS)
- **Preconditions**: Vault and grpc_3 (:8813) reachable
- **Steps**:
  1. Issue client cert (client-role); start gRPC gateway with GRPCBackend TLS MUTUAL and backend-registry resolution
  2. Unary echo; ServerStream count=4 (sequence-contiguous); Bidi ×3 with operation=double
  3. Negative: SIMPLE TLS without client cert
- **Expected Results**: Unary echoes; 4 stream messages with sequences 1..4; bidi doubles each value; no-cert dial surfaces UNAVAILABLE

### TestIntegration_LiveGRPCBackend_OIDC_S2S
- **Description**: Gateway grpcRoute → grpc_4 (OIDC) — the gateway injects live-Keycloak client_credentials tokens into backend metadata; UNARY + SERVER STREAMING + BIDI STREAMING through the gateway
- **Preconditions**: Keycloak and grpc_4 (:8814) reachable
- **Expected Results**: All three call shapes succeed with injected tokens; without backend auth the backend answers UNAUTHENTICATED

## Phase-3 CRD Field Contract Tests (operator functional)

The NEW Phase-3 CRD fields verified at the CR → gateway boundary: admitted
by the real webhook validator, serialized exactly as the operator pushes
config, deserialized onto the gateway configuration types, and asserted for
a lossless wire shape.

Files: `test/functional/operator/phase3_fields_functional_test.go` (build
tag `functional`).

### TestFunctional_APIRoute_TransformAdvanced_GatewayContract
- **Description**: transform.request staticHeaders/dynamicHeaders/injectFields/removeFields/defaultValues/validateBeforeTransform + template→bodyTemplate mapping; transform.response groupFields/flattenFields/arrayOperations/mergeStrategy=ndjson
- **Expected Results**: Every field survives CR → config.Route byte-compatibly; CRD template lands in gateway bodyTemplate; ndjson merge strategy reaches the data plane

### TestFunctional_APIRoute_CacheAdvanced_GatewayContract
- **Description**: cache maxEntries/keyConfig{includeMethod,includePath,includeQueryParams,includeHeaders,includeBodyHash,keyTemplate}/honorCacheControl/negativeCacheTTL; deprecated keyComponents admission warning
- **Expected Results**: All cache tuning fields survive the wire; keyComponents warns on admission

### TestFunctional_RedisTLS_GatewayContract
- **Description**: redis TLS blocks on cache.redis.tls and rateLimit.redis.tls
- **Expected Results**: Enabled/certFile/keyFile/caFile/minVersion survive to the gateway TLS config on both paths

### TestFunctional_AuthzCache_RedisShape_GatewayContract
- **Description**: authorization.cache redis shape (preferred) round-trips incl. redis.sentinel; the legacy top-level sentinel key is consumable by the gateway type (operator normalizer folds it into redis.sentinel; gateway deserializes the legacy key for compatibility)
- **Expected Results**: Preferred redis block survives with sentinel topology intact; legacy sentinel key reaches config.AuthzCacheConfig.Sentinel

### TestFunctional_Security_Structured_GatewayContract
- **Description**: structured security.hsts (maxAge/includeSubDomains/preload) + security.csp (policy/reportUri) + referrerPolicy + headers.customHeaders
- **Expected Results**: All structured security fields survive CR → config.SecurityConfig

### TestFunctional_Backend_HealthCheckGRPC_GatewayContract
- **Description**: Backend healthCheck useGRPC/grpcService/port (probe-port override for backends probing on 9090)
- **Expected Results**: Fields survive CR → config.Backend and the translated backend passes full gateway validation
