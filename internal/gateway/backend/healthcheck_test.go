package backend

import (
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
