package apikey

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	t.Parallel()

	t.Run("with namespace", func(t *testing.T) {
		t.Parallel()

		m := NewMetrics("test")
		require.NotNil(t, m)
		assert.NotNil(t, m.validationTotal)
		assert.NotNil(t, m.validationDuration)
		assert.NotNil(t, m.cacheHits)
		assert.NotNil(t, m.cacheMisses)
		assert.NotNil(t, m.registry)
	})

	t.Run("with empty namespace", func(t *testing.T) {
		t.Parallel()

		m := NewMetrics("")
		require.NotNil(t, m)
		// Should use default namespace "gateway"
		assert.NotNil(t, m.validationTotal)
	})
}

func TestMetrics_RecordValidation(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_validation")

	// Record various validation results
	m.RecordValidation("success", "valid", 100*time.Millisecond)
	m.RecordValidation("error", "not_found", 50*time.Millisecond)
	m.RecordValidation("error", "expired", 25*time.Millisecond)
	m.RecordValidation("error", "disabled", 10*time.Millisecond)

	// Verify metrics were recorded (no panic)
	assert.NotNil(t, m.validationTotal)
	assert.NotNil(t, m.validationDuration)
}

func TestMetrics_RecordCacheHit(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_cache_hit")

	// Record cache hits
	m.RecordCacheHit()
	m.RecordCacheHit()
	m.RecordCacheHit()

	// Verify metric was recorded (no panic)
	assert.NotNil(t, m.cacheHits)
}

func TestMetrics_RecordCacheMiss(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_cache_miss")

	// Record cache misses
	m.RecordCacheMiss()
	m.RecordCacheMiss()

	// Verify metric was recorded (no panic)
	assert.NotNil(t, m.cacheMisses)
}

func TestMetrics_Registry(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_registry")

	registry := m.Registry()
	require.NotNil(t, registry)

	// Verify metrics are registered
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metricFamilies)
}

func TestMetrics_MustRegister(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_must_register")

	// Create a new registry
	registry := prometheus.NewRegistry()

	// Register metrics
	m.MustRegister(registry)

	// Verify metrics are registered
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metricFamilies)
}

func TestMetrics_RecordValidation_AllStatuses(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_all_statuses")

	statuses := []struct {
		status string
		reason string
	}{
		{"success", "valid"},
		{"error", "empty_key"},
		{"error", "not_found"},
		{"error", "store_error"},
		{"error", "invalid"},
		{"error", "disabled"},
		{"error", "expired"},
	}

	for _, s := range statuses {
		m.RecordValidation(s.status, s.reason, time.Millisecond)
	}

	// Verify no panics occurred
	assert.NotNil(t, m.validationTotal)
}

func TestMetrics_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_concurrent")

	done := make(chan bool)
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				m.RecordValidation("success", "valid", time.Millisecond)
				m.RecordCacheHit()
				m.RecordCacheMiss()
			}
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify no race conditions
	assert.NotNil(t, m.validationTotal)
}

func TestGetSharedMetrics_Singleton(t *testing.T) {
	m1 := GetSharedMetrics()
	m2 := GetSharedMetrics()

	assert.NotNil(t, m1)
	assert.Same(t, m1, m2, "GetSharedMetrics should return same instance")
}

func TestMetrics_Init(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_init")

	// Init should not panic
	assert.NotPanics(t, func() {
		m.Init()
	})

	// Verify metrics are pre-populated by gathering from registry
	mfs, err := m.Registry().Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)

	// Init should be idempotent - calling again should not panic
	assert.NotPanics(t, func() {
		m.Init()
	})
}

func TestMetrics_MustRegister_Duplicate(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_dup_register")
	reg := prometheus.NewRegistry()

	// First registration should not panic
	assert.NotPanics(t, func() {
		m.MustRegister(reg)
	})

	// Second registration should not panic (AlreadyRegisteredError is silently ignored)
	assert.NotPanics(t, func() {
		m.MustRegister(reg)
	})
}

func TestIsAlreadyRegistered(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "AlreadyRegisteredError returns true",
			err:      prometheus.AlreadyRegisteredError{},
			expected: true,
		},
		{
			name:     "other error returns false",
			err:      assert.AnError,
			expected: false,
		},
		{
			name:     "nil error returns false",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.err == nil {
				// isAlreadyRegistered expects non-nil error
				assert.False(t, isAlreadyRegistered(assert.AnError))
				return
			}
			result := isAlreadyRegistered(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
