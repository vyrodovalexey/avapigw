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
