package controller

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// resetControllerMetricsForTesting resets the controller metrics singleton so
// tests can re-initialize with a fresh Prometheus registry. This prevents
// "duplicate metrics collector registration" panics when multiple tests need
// isolated metrics instances. Must only be called from tests.
func resetControllerMetricsForTesting() {
	globalMetrics = nil
	globalMetricsOnce = sync.Once{}
}

// resetStatusUpdateMetricsForTesting resets the status update metrics singleton
// so tests can re-initialize with a fresh Prometheus registry.
func resetStatusUpdateMetricsForTesting() {
	statusUpdateMetrics = nil
	statusUpdateMetricsOnce = sync.Once{}
}

func TestInitControllerVecMetrics_NoPanic(t *testing.T) {
	// InitControllerVecMetrics uses the singleton, which is already initialized
	// by the time tests run. It should not panic.
	assert.NotPanics(t, func() {
		InitControllerVecMetrics()
	})

	// Idempotent - calling again should not panic
	assert.NotPanics(t, func() {
		InitControllerVecMetrics()
	})
}

func TestInitStatusUpdateVecMetrics_NoPanic(t *testing.T) {
	// InitStatusUpdateVecMetrics uses the singleton, which is already initialized
	// by the time tests run. It should not panic.
	assert.NotPanics(t, func() {
		InitStatusUpdateVecMetrics()
	})

	// Idempotent - calling again should not panic
	assert.NotPanics(t, func() {
		InitStatusUpdateVecMetrics()
	})
}
