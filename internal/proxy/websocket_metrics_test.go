package proxy

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetWebSocketMetrics_Singleton(t *testing.T) {
	// Get metrics twice and verify they are the same instance
	metrics1 := getWebSocketMetrics()
	metrics2 := getWebSocketMetrics()

	assert.Same(t, metrics1, metrics2, "getWebSocketMetrics should return the same instance")
}

func TestGetWebSocketMetrics_MetricsExist(t *testing.T) {
	metrics := getWebSocketMetrics()

	// Verify all metrics are initialized
	assert.NotNil(t, metrics.connectionsTotal, "connectionsTotal should be initialized")
	assert.NotNil(t, metrics.connectionsActive, "connectionsActive should be initialized")
	assert.NotNil(t, metrics.errorsTotal, "errorsTotal should be initialized")
	assert.NotNil(t, metrics.messagesSentTotal, "messagesSentTotal should be initialized")
	assert.NotNil(t, metrics.messagesReceivedTotal, "messagesReceivedTotal should be initialized")
	assert.NotNil(t, metrics.connectionDuration, "connectionDuration should be initialized")
}

func TestGetWebSocketMetrics_CounterOperations(t *testing.T) {
	metrics := getWebSocketMetrics()

	// Test counter increment
	metrics.connectionsTotal.WithLabelValues("test-backend").Inc()

	// Test gauge increment/decrement
	metrics.connectionsActive.WithLabelValues("test-backend").Inc()
	metrics.connectionsActive.WithLabelValues("test-backend").Dec()

	// Test error counter with labels
	metrics.errorsTotal.WithLabelValues("test-backend", "connection_failed").Inc()
}

func TestGetWebSocketMetrics_BackendLabels(t *testing.T) {
	metrics := getWebSocketMetrics()

	// Test with different backend labels
	backends := []string{"backend-1", "backend-2", "backend-3"}

	for _, backend := range backends {
		metrics.connectionsTotal.WithLabelValues(backend).Inc()
		metrics.connectionsActive.WithLabelValues(backend).Inc()
		metrics.errorsTotal.WithLabelValues(backend, "timeout").Inc()
	}

	// Verify no panic occurred - metrics should handle multiple labels
}

func TestGetWebSocketMetrics_ErrorTypes(t *testing.T) {
	metrics := getWebSocketMetrics()

	// Test various error types
	errorTypes := []string{
		"connection_failed",
		"timeout",
		"protocol_error",
		"backend_unavailable",
	}

	for _, errType := range errorTypes {
		metrics.errorsTotal.WithLabelValues("test-backend", errType).Inc()
	}
}

// ============================================================================
// messagesSentTotal Tests
// ============================================================================

func TestGetWebSocketMetrics_MessagesSentTotal(t *testing.T) {
	metrics := getWebSocketMetrics()
	require.NotNil(t, metrics.messagesSentTotal)

	tests := []struct {
		name    string
		backend string
		count   int
	}{
		{name: "single message", backend: "sent-be-1", count: 1},
		{name: "multiple messages", backend: "sent-be-2", count: 5},
		{name: "many messages", backend: "sent-be-3", count: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange: capture counter before
			before := testutil.ToFloat64(
				metrics.messagesSentTotal.WithLabelValues(tt.backend),
			)

			// Act: increment counter tt.count times
			for i := 0; i < tt.count; i++ {
				metrics.messagesSentTotal.WithLabelValues(tt.backend).Inc()
			}

			// Assert: counter should have increased by tt.count
			after := testutil.ToFloat64(
				metrics.messagesSentTotal.WithLabelValues(tt.backend),
			)
			assert.Equal(t, before+float64(tt.count), after,
				"messagesSentTotal should increment by %d", tt.count)
		})
	}
}

// ============================================================================
// messagesReceivedTotal Tests
// ============================================================================

func TestGetWebSocketMetrics_MessagesReceivedTotal(t *testing.T) {
	metrics := getWebSocketMetrics()
	require.NotNil(t, metrics.messagesReceivedTotal)

	tests := []struct {
		name    string
		backend string
		count   int
	}{
		{name: "single message", backend: "recv-be-1", count: 1},
		{name: "multiple messages", backend: "recv-be-2", count: 5},
		{name: "many messages", backend: "recv-be-3", count: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange: capture counter before
			before := testutil.ToFloat64(
				metrics.messagesReceivedTotal.WithLabelValues(tt.backend),
			)

			// Act: increment counter tt.count times
			for i := 0; i < tt.count; i++ {
				metrics.messagesReceivedTotal.WithLabelValues(tt.backend).Inc()
			}

			// Assert: counter should have increased by tt.count
			after := testutil.ToFloat64(
				metrics.messagesReceivedTotal.WithLabelValues(tt.backend),
			)
			assert.Equal(t, before+float64(tt.count), after,
				"messagesReceivedTotal should increment by %d", tt.count)
		})
	}
}

// ============================================================================
// connectionDuration Tests
// ============================================================================

func TestGetWebSocketMetrics_ConnectionDuration(t *testing.T) {
	metrics := getWebSocketMetrics()
	require.NotNil(t, metrics.connectionDuration)

	tests := []struct {
		name     string
		backend  string
		duration float64
	}{
		{name: "short connection", backend: "dur-be-1", duration: 0.5},
		{name: "medium connection", backend: "dur-be-2", duration: 30.0},
		{name: "long connection", backend: "dur-be-3", duration: 3600.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act: observe a duration value
			metrics.connectionDuration.WithLabelValues(tt.backend).Observe(tt.duration)

			// Assert: histogram should have observations
			count := testutil.CollectAndCount(metrics.connectionDuration)
			assert.Greater(t, count, 0, "connectionDuration should have observations")
		})
	}
}

func TestGetWebSocketMetrics_ConnectionDuration_Buckets(t *testing.T) {
	metrics := getWebSocketMetrics()
	require.NotNil(t, metrics.connectionDuration)

	// Observe multiple durations across different buckets
	durations := []float64{0.5, 2.0, 7.0, 15.0, 45.0, 90.0, 200.0, 500.0, 1200.0, 2400.0}
	for _, d := range durations {
		metrics.connectionDuration.WithLabelValues("bucket-test-be").Observe(d)
	}

	// Verify histogram has observations
	count := testutil.CollectAndCount(metrics.connectionDuration)
	assert.Greater(t, count, 0, "connectionDuration should have observations across buckets")
}

// ============================================================================
// Concurrent Access Tests for New Metrics
// ============================================================================

func TestGetWebSocketMetrics_NewMetrics_ConcurrentAccess(t *testing.T) {
	metrics := getWebSocketMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines * 3) // 3 metric types

	// Concurrent messagesSentTotal increments
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				metrics.messagesSentTotal.WithLabelValues("concurrent-be").Inc()
			}
		}()
	}

	// Concurrent messagesReceivedTotal increments
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				metrics.messagesReceivedTotal.WithLabelValues("concurrent-be").Inc()
			}
		}()
	}

	// Concurrent connectionDuration observations
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				metrics.connectionDuration.WithLabelValues("concurrent-be").Observe(1.5)
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions occur (run with -race flag)
}

// ============================================================================
// Multiple Backend Labels for New Metrics
// ============================================================================

func TestGetWebSocketMetrics_NewMetrics_BackendLabels(t *testing.T) {
	metrics := getWebSocketMetrics()

	backends := []string{"new-backend-1", "new-backend-2", "new-backend-3"}

	for _, backend := range backends {
		// Arrange
		sentBefore := testutil.ToFloat64(
			metrics.messagesSentTotal.WithLabelValues(backend),
		)
		recvBefore := testutil.ToFloat64(
			metrics.messagesReceivedTotal.WithLabelValues(backend),
		)

		// Act
		metrics.messagesSentTotal.WithLabelValues(backend).Inc()
		metrics.messagesReceivedTotal.WithLabelValues(backend).Inc()
		metrics.connectionDuration.WithLabelValues(backend).Observe(10.0)

		// Assert
		sentAfter := testutil.ToFloat64(
			metrics.messagesSentTotal.WithLabelValues(backend),
		)
		recvAfter := testutil.ToFloat64(
			metrics.messagesReceivedTotal.WithLabelValues(backend),
		)

		assert.Equal(t, sentBefore+1, sentAfter,
			"messagesSentTotal for %s should increment by 1", backend)
		assert.Equal(t, recvBefore+1, recvAfter,
			"messagesReceivedTotal for %s should increment by 1", backend)
	}
}
