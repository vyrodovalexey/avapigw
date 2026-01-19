// Package metrics provides Prometheus metrics for the API Gateway.
package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecordHTTPRequest(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		path         string
		statusCode   string
		duration     float64
		requestSize  int64
		responseSize int64
	}{
		{
			name:         "GET request with response",
			method:       "GET",
			path:         "/api/v1/users",
			statusCode:   "200",
			duration:     0.123,
			requestSize:  0,
			responseSize: 1024,
		},
		{
			name:         "POST request with body",
			method:       "POST",
			path:         "/api/v1/users",
			statusCode:   "201",
			duration:     0.456,
			requestSize:  512,
			responseSize: 256,
		},
		{
			name:         "error response",
			method:       "GET",
			path:         "/api/v1/notfound",
			statusCode:   "404",
			duration:     0.010,
			requestSize:  0,
			responseSize: 64,
		},
		{
			name:         "server error",
			method:       "POST",
			path:         "/api/v1/error",
			statusCode:   "500",
			duration:     5.0,
			requestSize:  100,
			responseSize: 32,
		},
		{
			name:         "zero sizes",
			method:       "DELETE",
			path:         "/api/v1/users/123",
			statusCode:   "204",
			duration:     0.050,
			requestSize:  0,
			responseSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordHTTPRequest(tt.method, tt.path, tt.statusCode, tt.duration, tt.requestSize, tt.responseSize)
			})
		})
	}
}

func TestRecordHTTPError(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		path      string
		errorType string
	}{
		{
			name:      "timeout error",
			method:    "GET",
			path:      "/api/v1/slow",
			errorType: "timeout",
		},
		{
			name:      "connection error",
			method:    "POST",
			path:      "/api/v1/users",
			errorType: "connection_refused",
		},
		{
			name:      "validation error",
			method:    "PUT",
			path:      "/api/v1/users/123",
			errorType: "validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordHTTPError(tt.method, tt.path, tt.errorType)
			})
		})
	}
}

func TestIncrementHTTPInFlight(t *testing.T) {
	tests := []struct {
		name   string
		method string
	}{
		{
			name:   "GET method",
			method: "GET",
		},
		{
			name:   "POST method",
			method: "POST",
		},
		{
			name:   "PUT method",
			method: "PUT",
		},
		{
			name:   "DELETE method",
			method: "DELETE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				IncrementHTTPInFlight(tt.method)
			})
		})
	}
}

func TestDecrementHTTPInFlight(t *testing.T) {
	tests := []struct {
		name   string
		method string
	}{
		{
			name:   "GET method",
			method: "GET",
		},
		{
			name:   "POST method",
			method: "POST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Increment first to avoid negative values
			IncrementHTTPInFlight(tt.method)

			// Should not panic
			assert.NotPanics(t, func() {
				DecrementHTTPInFlight(tt.method)
			})
		})
	}
}

func TestRecordGRPCRequest(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		method   string
		code     string
		duration float64
	}{
		{
			name:     "successful unary call",
			service:  "UserService",
			method:   "GetUser",
			code:     "OK",
			duration: 0.050,
		},
		{
			name:     "failed call",
			service:  "UserService",
			method:   "CreateUser",
			code:     "INVALID_ARGUMENT",
			duration: 0.010,
		},
		{
			name:     "not found",
			service:  "ProductService",
			method:   "GetProduct",
			code:     "NOT_FOUND",
			duration: 0.025,
		},
		{
			name:     "internal error",
			service:  "OrderService",
			method:   "PlaceOrder",
			code:     "INTERNAL",
			duration: 1.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordGRPCRequest(tt.service, tt.method, tt.code, tt.duration)
			})
		})
	}
}

func TestRecordGRPCStreamMessage(t *testing.T) {
	tests := []struct {
		name    string
		service string
		method  string
		sent    bool
	}{
		{
			name:    "sent message",
			service: "ChatService",
			method:  "StreamMessages",
			sent:    true,
		},
		{
			name:    "received message",
			service: "ChatService",
			method:  "StreamMessages",
			sent:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordGRPCStreamMessage(tt.service, tt.method, tt.sent)
			})
		})
	}
}

func TestRecordBackendRequest(t *testing.T) {
	tests := []struct {
		name     string
		backend  string
		method   string
		status   string
		duration float64
	}{
		{
			name:     "successful request",
			backend:  "user-service",
			method:   "GET",
			status:   "success",
			duration: 0.100,
		},
		{
			name:     "failed request",
			backend:  "payment-service",
			method:   "POST",
			status:   "error",
			duration: 5.0,
		},
		{
			name:     "timeout",
			backend:  "inventory-service",
			method:   "GET",
			status:   "timeout",
			duration: 30.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordBackendRequest(tt.backend, tt.method, tt.status, tt.duration)
			})
		})
	}
}

func TestSetBackendConnectionsActive(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		count   int
	}{
		{
			name:    "zero connections",
			backend: "user-service",
			count:   0,
		},
		{
			name:    "some connections",
			backend: "payment-service",
			count:   10,
		},
		{
			name:    "many connections",
			backend: "inventory-service",
			count:   100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				SetBackendConnectionsActive(tt.backend, tt.count)
			})
		})
	}
}

func TestRecordBackendConnection(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		status  string
	}{
		{
			name:    "successful connection",
			backend: "user-service",
			status:  "success",
		},
		{
			name:    "failed connection",
			backend: "payment-service",
			status:  "error",
		},
		{
			name:    "timeout connection",
			backend: "inventory-service",
			status:  "timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordBackendConnection(tt.backend, tt.status)
			})
		})
	}
}

func TestSetBackendHealthStatus(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		healthy bool
	}{
		{
			name:    "healthy backend",
			backend: "user-service",
			healthy: true,
		},
		{
			name:    "unhealthy backend",
			backend: "payment-service",
			healthy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				SetBackendHealthStatus(tt.backend, tt.healthy)
			})
		})
	}
}

func TestSetBackendLatencyPercentiles(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		p50     float64
		p95     float64
		p99     float64
	}{
		{
			name:    "fast backend",
			backend: "user-service",
			p50:     0.010,
			p95:     0.050,
			p99:     0.100,
		},
		{
			name:    "slow backend",
			backend: "payment-service",
			p50:     0.500,
			p95:     2.0,
			p99:     5.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				SetBackendLatencyPercentiles(tt.backend, tt.p50, tt.p95, tt.p99)
			})
		})
	}
}

func TestRecordRateLimitCheck(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		allowed   bool
		remaining int
	}{
		{
			name:      "allowed request",
			key:       "user:123",
			allowed:   true,
			remaining: 99,
		},
		{
			name:      "rejected request",
			key:       "user:456",
			allowed:   false,
			remaining: 0,
		},
		{
			name:      "last allowed request",
			key:       "ip:192.168.1.1",
			allowed:   true,
			remaining: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordRateLimitCheck(tt.key, tt.allowed, tt.remaining)
			})
		})
	}
}

func TestRecordRateLimitCheckDuration(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		duration  float64
	}{
		{
			name:      "token bucket fast",
			algorithm: "token_bucket",
			duration:  0.0001,
		},
		{
			name:      "sliding window",
			algorithm: "sliding_window",
			duration:  0.001,
		},
		{
			name:      "fixed window",
			algorithm: "fixed_window",
			duration:  0.0005,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordRateLimitCheckDuration(tt.algorithm, tt.duration)
			})
		})
	}
}

func TestSetCircuitBreakerState(t *testing.T) {
	tests := []struct {
		name   string
		cbName string
		state  int
	}{
		{
			name:   "closed state",
			cbName: "user-service",
			state:  0,
		},
		{
			name:   "open state",
			cbName: "payment-service",
			state:  1,
		},
		{
			name:   "half-open state",
			cbName: "inventory-service",
			state:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				SetCircuitBreakerState(tt.cbName, tt.state)
			})
		})
	}
}

func TestRecordCircuitBreakerRequest(t *testing.T) {
	tests := []struct {
		name    string
		cbName  string
		allowed bool
	}{
		{
			name:    "allowed request",
			cbName:  "user-service",
			allowed: true,
		},
		{
			name:    "rejected request",
			cbName:  "payment-service",
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordCircuitBreakerRequest(tt.cbName, tt.allowed)
			})
		})
	}
}

func TestRecordCircuitBreakerStateChange(t *testing.T) {
	tests := []struct {
		name   string
		cbName string
		from   string
		to     string
	}{
		{
			name:   "closed to open",
			cbName: "user-service",
			from:   "closed",
			to:     "open",
		},
		{
			name:   "open to half-open",
			cbName: "payment-service",
			from:   "open",
			to:     "half-open",
		},
		{
			name:   "half-open to closed",
			cbName: "inventory-service",
			from:   "half-open",
			to:     "closed",
		},
		{
			name:   "half-open to open",
			cbName: "order-service",
			from:   "half-open",
			to:     "open",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordCircuitBreakerStateChange(tt.cbName, tt.from, tt.to)
			})
		})
	}
}

func TestRecordAuthRequest(t *testing.T) {
	tests := []struct {
		name     string
		authType string
		result   string
		duration float64
	}{
		{
			name:     "successful JWT auth",
			authType: "jwt",
			result:   "success",
			duration: 0.005,
		},
		{
			name:     "failed JWT auth",
			authType: "jwt",
			result:   "failure",
			duration: 0.002,
		},
		{
			name:     "successful API key auth",
			authType: "api_key",
			result:   "success",
			duration: 0.001,
		},
		{
			name:     "failed API key auth",
			authType: "api_key",
			result:   "failure",
			duration: 0.001,
		},
		{
			name:     "OAuth auth",
			authType: "oauth",
			result:   "success",
			duration: 0.100,
		},
		{
			name:     "basic auth",
			authType: "basic",
			result:   "success",
			duration: 0.010,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordAuthRequest(tt.authType, tt.result, tt.duration)
			})
		})
	}
}

func TestMetricsConstants(t *testing.T) {
	// Test that constants are defined correctly
	assert.Equal(t, "avapigw", Namespace)
	assert.Equal(t, "http", SubsystemHTTP)
	assert.Equal(t, "grpc", SubsystemGRPC)
	assert.Equal(t, "backend", SubsystemBackend)
	assert.Equal(t, "ratelimit", SubsystemRateLimit)
	assert.Equal(t, "circuitbreaker", SubsystemCircuitBreaker)
	assert.Equal(t, "auth", SubsystemAuth)
}

func TestMetricsVariablesInitialized(t *testing.T) {
	// Test that all metric variables are initialized
	assert.NotNil(t, HTTPRequestsTotal)
	assert.NotNil(t, HTTPRequestDuration)
	assert.NotNil(t, HTTPRequestSize)
	assert.NotNil(t, HTTPResponseSize)
	assert.NotNil(t, HTTPRequestsInFlight)
	assert.NotNil(t, HTTPErrorsTotal)
	assert.NotNil(t, GRPCRequestsTotal)
	assert.NotNil(t, GRPCRequestDuration)
	assert.NotNil(t, GRPCStreamMessagesReceived)
	assert.NotNil(t, GRPCStreamMessagesSent)
	assert.NotNil(t, BackendRequestsTotal)
	assert.NotNil(t, BackendRequestDuration)
	assert.NotNil(t, BackendConnectionsActive)
	assert.NotNil(t, BackendConnectionsTotal)
	assert.NotNil(t, BackendHealthStatus)
	assert.NotNil(t, BackendLatencyP50)
	assert.NotNil(t, BackendLatencyP95)
	assert.NotNil(t, BackendLatencyP99)
	assert.NotNil(t, RateLimitRequestsTotal)
	assert.NotNil(t, RateLimitRejectedTotal)
	assert.NotNil(t, RateLimitRemaining)
	assert.NotNil(t, RateLimitCheckDuration)
	assert.NotNil(t, CircuitBreakerState)
	assert.NotNil(t, CircuitBreakerRequestsTotal)
	assert.NotNil(t, CircuitBreakerStateChangesTotal)
	assert.NotNil(t, AuthRequestsTotal)
	assert.NotNil(t, AuthDuration)
}

func TestConcurrentMetricRecording(t *testing.T) {
	done := make(chan bool)

	// Concurrent HTTP metrics
	go func() {
		for i := 0; i < 100; i++ {
			RecordHTTPRequest("GET", "/api/v1/test", "200", 0.1, 100, 200)
			RecordHTTPError("GET", "/api/v1/test", "timeout")
			IncrementHTTPInFlight("GET")
			DecrementHTTPInFlight("GET")
		}
		done <- true
	}()

	// Concurrent gRPC metrics
	go func() {
		for i := 0; i < 100; i++ {
			RecordGRPCRequest("TestService", "TestMethod", "OK", 0.05)
			RecordGRPCStreamMessage("TestService", "TestMethod", true)
			RecordGRPCStreamMessage("TestService", "TestMethod", false)
		}
		done <- true
	}()

	// Concurrent backend metrics
	go func() {
		for i := 0; i < 100; i++ {
			RecordBackendRequest("test-backend", "GET", "success", 0.1)
			SetBackendConnectionsActive("test-backend", i)
			RecordBackendConnection("test-backend", "success")
			SetBackendHealthStatus("test-backend", true)
			SetBackendLatencyPercentiles("test-backend", 0.01, 0.05, 0.1)
		}
		done <- true
	}()

	// Concurrent rate limit metrics
	go func() {
		for i := 0; i < 100; i++ {
			RecordRateLimitCheck("test-key", true, 99)
			RecordRateLimitCheckDuration("token_bucket", 0.001)
		}
		done <- true
	}()

	// Concurrent circuit breaker metrics
	go func() {
		for i := 0; i < 100; i++ {
			SetCircuitBreakerState("test-cb", i%3)
			RecordCircuitBreakerRequest("test-cb", true)
			RecordCircuitBreakerStateChange("test-cb", "closed", "open")
		}
		done <- true
	}()

	// Concurrent auth metrics
	go func() {
		for i := 0; i < 100; i++ {
			RecordAuthRequest("jwt", "success", 0.005)
		}
		done <- true
	}()

	// Wait for all goroutines
	for i := 0; i < 6; i++ {
		<-done
	}
}
