# API Gateway Test Cases

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
