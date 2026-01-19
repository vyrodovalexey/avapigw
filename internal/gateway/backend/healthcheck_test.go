package backend

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// Test Cases for HealthChecker
// ============================================================================

func TestHealthChecker_NewHealthChecker(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	require.NotNil(t, hc)
	assert.NotNil(t, hc.config)
	assert.NotNil(t, hc.client)
	assert.NotNil(t, hc.results)
	assert.False(t, hc.IsRunning())
}

func TestHealthChecker_NewHealthChecker_WithConfig(t *testing.T) {
	logger := zap.NewNop()
	config := &HealthCheckConfig{
		Enabled:            true,
		Interval:           5,
		Timeout:            2,
		HealthyThreshold:   3,
		UnhealthyThreshold: 2,
		Path:               "/healthz",
	}
	hc := NewHealthChecker(config, logger)

	require.NotNil(t, hc)
	assert.Equal(t, config, hc.config)
}

func TestHealthChecker_StartStop(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	endpoints := []*Endpoint{{Address: "localhost", Port: 8080, Healthy: true}}

	// Start the health checker
	hc.Start(endpoints)
	assert.True(t, hc.IsRunning())

	// Stop the health checker
	hc.Stop()
	assert.False(t, hc.IsRunning())
}

func TestHealthChecker_StartAlreadyRunning(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	endpoints := []*Endpoint{{Address: "localhost", Port: 8080, Healthy: true}}

	// Start the health checker
	hc.Start(endpoints)
	assert.True(t, hc.IsRunning())

	// Starting again should be a no-op
	hc.Start(endpoints)
	assert.True(t, hc.IsRunning())

	hc.Stop()
}

// Test 1: Double Stop Should Not Panic
func TestHealthChecker_DoubleStop(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	endpoints := []*Endpoint{{Address: "localhost", Port: 8080, Healthy: true}}
	hc.Start(endpoints)

	// First stop
	hc.Stop()

	// Second stop should not panic
	assert.NotPanics(t, func() {
		hc.Stop()
	})
}

// Test 2: Restart After Stop
func TestHealthChecker_RestartAfterStop(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	endpoints := []*Endpoint{{Address: "localhost", Port: 8080, Healthy: true}}

	// Start, stop, restart
	hc.Start(endpoints)
	assert.True(t, hc.IsRunning())

	hc.Stop()
	assert.False(t, hc.IsRunning())

	// Should be able to restart
	hc.Start(endpoints)
	assert.True(t, hc.IsRunning())

	hc.Stop()
	assert.False(t, hc.IsRunning())
}

// Test 3: Concurrent Stop Calls
func TestHealthChecker_ConcurrentStop(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	endpoints := []*Endpoint{{Address: "localhost", Port: 8080, Healthy: true}}
	hc.Start(endpoints)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hc.Stop()
		}()
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})
}

// Test 4: Multiple Start/Stop Cycles
func TestHealthChecker_MultipleStartStopCycles(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	endpoints := []*Endpoint{{Address: "localhost", Port: 8080, Healthy: true}}

	for i := 0; i < 5; i++ {
		hc.Start(endpoints)
		assert.True(t, hc.IsRunning(), "cycle %d: should be running after start", i)

		hc.Stop()
		assert.False(t, hc.IsRunning(), "cycle %d: should not be running after stop", i)
	}
}

// Test 5: Stop Without Start
func TestHealthChecker_StopWithoutStart(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	// Stop without start should not panic
	assert.NotPanics(t, func() {
		hc.Stop()
	})
	assert.False(t, hc.IsRunning())
}

// Test 6: Concurrent Start and Stop
func TestHealthChecker_ConcurrentStartStop(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	endpoints := []*Endpoint{{Address: "localhost", Port: 8080, Healthy: true}}

	var wg sync.WaitGroup

	// Start multiple goroutines that start and stop
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			hc.Start(endpoints)
		}()
		go func() {
			defer wg.Done()
			hc.Stop()
		}()
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})

	// Ensure we can still stop cleanly
	hc.Stop()
}

func TestHealthChecker_UpdateEndpoints(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	endpoints1 := []*Endpoint{{Address: "host1", Port: 8080, Healthy: true}}
	endpoints2 := []*Endpoint{
		{Address: "host2", Port: 8080, Healthy: true},
		{Address: "host3", Port: 8080, Healthy: true},
	}

	hc.Start(endpoints1)

	// Update endpoints
	hc.UpdateEndpoints(endpoints2)

	// Verify endpoints were updated
	hc.mu.RLock()
	assert.Len(t, hc.endpoints, 2)
	hc.mu.RUnlock()

	hc.Stop()
}

func TestHealthChecker_GetResult(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	endpoint := &Endpoint{Address: "localhost", Port: 8080, Healthy: true}

	// Initially no result
	result := hc.GetResult(endpoint)
	assert.Nil(t, result)

	// Add a result manually for testing
	hc.resultsMu.Lock()
	hc.results[endpoint.FullAddress()] = &HealthCheckResult{
		Endpoint: endpoint,
		Healthy:  true,
	}
	hc.resultsMu.Unlock()

	// Now should return the result
	result = hc.GetResult(endpoint)
	require.NotNil(t, result)
	assert.True(t, result.Healthy)
}

func TestHealthChecker_GetAllResults(t *testing.T) {
	logger := zap.NewNop()
	hc := NewHealthChecker(nil, logger)

	endpoint1 := &Endpoint{Address: "host1", Port: 8080, Healthy: true}
	endpoint2 := &Endpoint{Address: "host2", Port: 8080, Healthy: true}

	// Add results manually for testing
	hc.resultsMu.Lock()
	hc.results[endpoint1.FullAddress()] = &HealthCheckResult{
		Endpoint: endpoint1,
		Healthy:  true,
	}
	hc.results[endpoint2.FullAddress()] = &HealthCheckResult{
		Endpoint: endpoint2,
		Healthy:  false,
	}
	hc.resultsMu.Unlock()

	// Get all results
	results := hc.GetAllResults()
	assert.Len(t, results, 2)
	assert.True(t, results[endpoint1.FullAddress()].Healthy)
	assert.False(t, results[endpoint2.FullAddress()].Healthy)
}

// ============================================================================
// Test Cases for CircuitBreaker
// ============================================================================

func TestCircuitBreaker_NewCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(nil)

	require.NotNil(t, cb)
	assert.NotNil(t, cb.config)
	assert.Equal(t, CircuitClosed, cb.State())
}

func TestCircuitBreaker_NewCircuitBreaker_WithConfig(t *testing.T) {
	config := &CircuitBreakerConfig{
		Enabled:           true,
		ConsecutiveErrors: 3,
		Interval:          60,
		BaseEjectionTime:  60,
		MaxEjectionPct:    100,
	}
	cb := NewCircuitBreaker(config)

	require.NotNil(t, cb)
	assert.Equal(t, config, cb.config)
}

func TestCircuitBreaker_Allow_Closed(t *testing.T) {
	cb := NewCircuitBreaker(nil)

	// Closed circuit should allow requests
	assert.True(t, cb.Allow())
}

func TestCircuitBreaker_RecordSuccess(t *testing.T) {
	cb := NewCircuitBreaker(nil)

	// Record some failures
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}

	// Record success should reset failures
	cb.RecordSuccess()

	cb.mu.RLock()
	assert.Equal(t, 0, cb.failures)
	cb.mu.RUnlock()
}

func TestCircuitBreaker_RecordFailure_OpensCircuit(t *testing.T) {
	config := &CircuitBreakerConfig{
		Enabled:           true,
		ConsecutiveErrors: 3,
		Interval:          30,
		BaseEjectionTime:  30,
		MaxEjectionPct:    50,
	}
	cb := NewCircuitBreaker(config)

	// Record failures to open circuit
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}

	assert.Equal(t, CircuitOpen, cb.State())
	assert.False(t, cb.Allow())
}

func TestCircuitBreaker_HalfOpen_Transition(t *testing.T) {
	config := &CircuitBreakerConfig{
		Enabled:           true,
		ConsecutiveErrors: 1,
		Interval:          30,
		BaseEjectionTime:  0, // Immediate transition to half-open
		MaxEjectionPct:    50,
	}
	cb := NewCircuitBreaker(config)

	// Open the circuit
	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.State())

	// Wait a tiny bit and check - should transition to half-open
	time.Sleep(10 * time.Millisecond)
	assert.True(t, cb.Allow())
	assert.Equal(t, CircuitHalfOpen, cb.State())
}

func TestCircuitBreaker_HalfOpen_Success_CloseCircuit(t *testing.T) {
	config := &CircuitBreakerConfig{
		Enabled:           true,
		ConsecutiveErrors: 1,
		Interval:          30,
		BaseEjectionTime:  0,
		MaxEjectionPct:    50,
	}
	cb := NewCircuitBreaker(config)

	// Open the circuit
	cb.RecordFailure()

	// Transition to half-open
	time.Sleep(10 * time.Millisecond)
	cb.Allow()
	assert.Equal(t, CircuitHalfOpen, cb.State())

	// Success should close the circuit
	cb.RecordSuccess()
	assert.Equal(t, CircuitClosed, cb.State())
}

func TestCircuitBreaker_Reset(t *testing.T) {
	config := &CircuitBreakerConfig{
		Enabled:           true,
		ConsecutiveErrors: 1,
		Interval:          30,
		BaseEjectionTime:  30,
		MaxEjectionPct:    50,
	}
	cb := NewCircuitBreaker(config)

	// Open the circuit
	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.State())

	// Reset should close the circuit
	cb.Reset()
	assert.Equal(t, CircuitClosed, cb.State())

	cb.mu.RLock()
	assert.Equal(t, 0, cb.failures)
	cb.mu.RUnlock()
}

// ============================================================================
// Test Cases for HealthChecker TCP Check
// ============================================================================

func TestHealthChecker_TCPCheck(t *testing.T) {
	// Create a TCP listener for testing
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Get the port
	addr := listener.Addr().(*net.TCPAddr)

	logger := zap.NewNop()
	config := &HealthCheckConfig{
		Enabled:            true,
		Interval:           1,
		Timeout:            2,
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
		Path:               "", // Empty path triggers TCP check
	}
	hc := NewHealthChecker(config, logger)

	endpoint := &Endpoint{
		Address: "127.0.0.1",
		Port:    addr.Port,
		Healthy: true,
	}

	// TCP check should succeed
	healthy, err := hc.tcpCheck(endpoint)
	assert.NoError(t, err)
	assert.True(t, healthy)
}

func TestHealthChecker_TCPCheck_ConnectionRefused(t *testing.T) {
	logger := zap.NewNop()
	config := &HealthCheckConfig{
		Enabled:            true,
		Interval:           1,
		Timeout:            1,
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
		Path:               "", // Empty path triggers TCP check
	}
	hc := NewHealthChecker(config, logger)

	endpoint := &Endpoint{
		Address: "127.0.0.1",
		Port:    59999, // Unlikely to be in use
		Healthy: true,
	}

	// TCP check should fail
	healthy, err := hc.tcpCheck(endpoint)
	assert.Error(t, err)
	assert.False(t, healthy)
}

func TestHealthChecker_TCPCheck_Timeout(t *testing.T) {
	logger := zap.NewNop()
	config := &HealthCheckConfig{
		Enabled:            true,
		Interval:           1,
		Timeout:            1, // 1 second timeout
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
		Path:               "", // Empty path triggers TCP check
	}
	hc := NewHealthChecker(config, logger)

	endpoint := &Endpoint{
		Address: "192.0.2.1", // Non-routable IP (TEST-NET-1)
		Port:    8080,
		Healthy: true,
	}

	// TCP check should timeout
	healthy, err := hc.tcpCheck(endpoint)
	assert.Error(t, err)
	assert.False(t, healthy)
}

// ============================================================================
// Test Cases for HealthChecker handleHealthyResult
// ============================================================================

func TestHealthChecker_HandleHealthyResult(t *testing.T) {
	logger := zap.NewNop()
	config := &HealthCheckConfig{
		Enabled:            true,
		Interval:           1,
		Timeout:            1,
		HealthyThreshold:   2,
		UnhealthyThreshold: 2,
		Path:               "/health",
	}
	hc := NewHealthChecker(config, logger)

	endpoint := &Endpoint{
		Address: "localhost",
		Port:    8080,
		Healthy: false, // Start unhealthy
	}
	addr := endpoint.FullAddress()

	result := &HealthCheckResult{
		Endpoint:        endpoint,
		Healthy:         false,
		ConsecutiveOK:   0,
		ConsecutiveFail: 1,
	}

	// First healthy result - should not mark healthy yet (threshold is 2)
	hc.handleHealthyResult(result, endpoint, addr)
	assert.Equal(t, 1, result.ConsecutiveOK)
	assert.Equal(t, 0, result.ConsecutiveFail)
	assert.False(t, result.Healthy)

	// Second healthy result - should mark healthy now
	hc.handleHealthyResult(result, endpoint, addr)
	assert.Equal(t, 2, result.ConsecutiveOK)
	assert.True(t, result.Healthy)
	assert.True(t, endpoint.IsHealthy())
}

func TestHealthChecker_HandleHealthyResult_AlreadyHealthy(t *testing.T) {
	logger := zap.NewNop()
	config := &HealthCheckConfig{
		Enabled:            true,
		Interval:           1,
		Timeout:            1,
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
		Path:               "/health",
	}
	hc := NewHealthChecker(config, logger)

	endpoint := &Endpoint{
		Address: "localhost",
		Port:    8080,
		Healthy: true, // Already healthy
	}
	addr := endpoint.FullAddress()

	result := &HealthCheckResult{
		Endpoint:        endpoint,
		Healthy:         true,
		ConsecutiveOK:   5,
		ConsecutiveFail: 0,
	}

	// Healthy result when already healthy - should stay healthy
	hc.handleHealthyResult(result, endpoint, addr)
	assert.Equal(t, 6, result.ConsecutiveOK)
	assert.True(t, result.Healthy)
}

// ============================================================================
// Test Cases for HealthChecker HTTP Check with Server
// ============================================================================

func TestHealthChecker_HTTPCheck_Success(t *testing.T) {
	// Create a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Parse server URL
	parsedURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(parsedURL.Port())

	logger := zap.NewNop()
	config := &HealthCheckConfig{
		Enabled:            true,
		Interval:           1,
		Timeout:            5,
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
		Path:               "/health",
	}
	hc := NewHealthChecker(config, logger)

	endpoint := &Endpoint{
		Address: parsedURL.Hostname(),
		Port:    port,
		Healthy: true,
	}

	healthy, err := hc.httpCheck(endpoint)
	assert.NoError(t, err)
	assert.True(t, healthy)
}

func TestHealthChecker_HTTPCheck_UnhealthyStatus(t *testing.T) {
	// Create a test HTTP server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Parse server URL
	parsedURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(parsedURL.Port())

	logger := zap.NewNop()
	config := &HealthCheckConfig{
		Enabled:            true,
		Interval:           1,
		Timeout:            5,
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
		Path:               "/health",
	}
	hc := NewHealthChecker(config, logger)

	endpoint := &Endpoint{
		Address: parsedURL.Hostname(),
		Port:    port,
		Healthy: true,
	}

	healthy, err := hc.httpCheck(endpoint)
	assert.Error(t, err)
	assert.False(t, healthy)
	assert.Contains(t, err.Error(), "unhealthy status code")
}

func TestHealthChecker_HTTPCheck_CustomPort(t *testing.T) {
	// Create a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Parse server URL
	parsedURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(parsedURL.Port())

	logger := zap.NewNop()
	config := &HealthCheckConfig{
		Enabled:            true,
		Interval:           1,
		Timeout:            5,
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
		Path:               "/health",
		Port:               port, // Use custom port
	}
	hc := NewHealthChecker(config, logger)

	endpoint := &Endpoint{
		Address: parsedURL.Hostname(),
		Port:    9999, // Different port - should use config.Port instead
		Healthy: true,
	}

	healthy, err := hc.httpCheck(endpoint)
	assert.NoError(t, err)
	assert.True(t, healthy)
}

// ============================================================================
// Test Cases for HealthChecker checkEndpoint with TCP
// ============================================================================

func TestHealthChecker_CheckEndpoint_TCP(t *testing.T) {
	// Create a TCP listener for testing
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Get the port
	addr := listener.Addr().(*net.TCPAddr)

	logger := zap.NewNop()
	config := &HealthCheckConfig{
		Enabled:            true,
		Interval:           1,
		Timeout:            2,
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
		Path:               "", // Empty path triggers TCP check
	}
	hc := NewHealthChecker(config, logger)

	endpoint := &Endpoint{
		Address: "127.0.0.1",
		Port:    addr.Port,
		Healthy: false,
	}

	// Run check
	hc.checkEndpoint(endpoint)

	// Verify result was recorded
	result := hc.GetResult(endpoint)
	require.NotNil(t, result)
	assert.True(t, result.Healthy)
}

// ============================================================================
// Test Cases for CircuitBreaker Allow with default state
// ============================================================================

func TestCircuitBreaker_Allow_DefaultState(t *testing.T) {
	cb := NewCircuitBreaker(nil)

	// Default state should be closed, allowing requests
	assert.True(t, cb.Allow())
	assert.Equal(t, CircuitClosed, cb.State())
}

func TestCircuitBreaker_Allow_HalfOpen(t *testing.T) {
	config := &CircuitBreakerConfig{
		Enabled:           true,
		ConsecutiveErrors: 1,
		Interval:          30,
		BaseEjectionTime:  0, // Immediate transition
		MaxEjectionPct:    50,
	}
	cb := NewCircuitBreaker(config)

	// Open the circuit
	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.State())

	// Wait for transition to half-open
	time.Sleep(10 * time.Millisecond)

	// Allow should transition to half-open and return true
	assert.True(t, cb.Allow())
	assert.Equal(t, CircuitHalfOpen, cb.State())

	// Subsequent Allow in half-open should also return true
	assert.True(t, cb.Allow())
}

func TestCircuitBreaker_RecordSuccess_InClosedState(t *testing.T) {
	cb := NewCircuitBreaker(nil)

	// Record success in closed state
	cb.RecordSuccess()

	// Should remain closed
	assert.Equal(t, CircuitClosed, cb.State())
	cb.mu.RLock()
	assert.Equal(t, 0, cb.failures)
	cb.mu.RUnlock()
}
