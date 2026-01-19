package base

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetricsRegistry(t *testing.T) {
	t.Run("creates registry with default registerer", func(t *testing.T) {
		registry := NewMetricsRegistry(nil)
		assert.NotNil(t, registry)
		assert.NotNil(t, registry.metrics)
	})

	t.Run("creates registry with custom registerer", func(t *testing.T) {
		customReg := prometheus.NewRegistry()
		registry := NewMetricsRegistry(customReg)
		assert.NotNil(t, registry)
	})
}

func TestMetricsRegistry_RegisterController(t *testing.T) {
	t.Run("registers new controller metrics", func(t *testing.T) {
		customReg := prometheus.NewRegistry()
		registry := NewMetricsRegistry(customReg)

		metrics := registry.RegisterController("test_controller")
		require.NotNil(t, metrics)
		assert.NotNil(t, metrics.ReconcileDuration)
		assert.NotNil(t, metrics.ReconcileTotal)
		assert.Equal(t, "test_controller", metrics.controllerName)
	})

	t.Run("returns existing metrics for same controller", func(t *testing.T) {
		customReg := prometheus.NewRegistry()
		registry := NewMetricsRegistry(customReg)

		metrics1 := registry.RegisterController("test_controller2")
		metrics2 := registry.RegisterController("test_controller2")

		assert.Same(t, metrics1, metrics2)
	})

	t.Run("registers different metrics for different controllers", func(t *testing.T) {
		customReg := prometheus.NewRegistry()
		registry := NewMetricsRegistry(customReg)

		metrics1 := registry.RegisterController("controller_a")
		metrics2 := registry.RegisterController("controller_b")

		assert.NotSame(t, metrics1, metrics2)
	})
}

func TestMetricsRegistry_GetMetrics(t *testing.T) {
	t.Run("returns nil for unregistered controller", func(t *testing.T) {
		customReg := prometheus.NewRegistry()
		registry := NewMetricsRegistry(customReg)

		metrics := registry.GetMetrics("nonexistent")
		assert.Nil(t, metrics)
	})

	t.Run("returns metrics for registered controller", func(t *testing.T) {
		customReg := prometheus.NewRegistry()
		registry := NewMetricsRegistry(customReg)

		registered := registry.RegisterController("test_get")
		retrieved := registry.GetMetrics("test_get")

		assert.Same(t, registered, retrieved)
	})
}

func TestControllerMetrics_ObserveReconcile(t *testing.T) {
	t.Run("records success metrics", func(t *testing.T) {
		customReg := prometheus.NewRegistry()
		registry := NewMetricsRegistry(customReg)
		metrics := registry.RegisterController("observe_test1")

		// Should not panic
		metrics.ObserveReconcile(0.5, true)
	})

	t.Run("records error metrics", func(t *testing.T) {
		customReg := prometheus.NewRegistry()
		registry := NewMetricsRegistry(customReg)
		metrics := registry.RegisterController("observe_test2")

		// Should not panic
		metrics.ObserveReconcile(1.0, false)
	})
}
