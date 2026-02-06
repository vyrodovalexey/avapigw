package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
