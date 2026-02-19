package rbac

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		namespace string
	}{
		{name: "with namespace", namespace: "test"},
		{name: "empty namespace defaults to gateway", namespace: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMetrics(tt.namespace)
			require.NotNil(t, m)
			assert.NotNil(t, m.evaluationTotal)
			assert.NotNil(t, m.evaluationDuration)
			assert.NotNil(t, m.policyCount)
			assert.NotNil(t, m.registry)
		})
	}
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

	// Init should be idempotent
	assert.NotPanics(t, func() {
		m.Init()
	})
}

func TestMetrics_SetPolicyCount(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_policy_count")

	// Should not panic
	assert.NotPanics(t, func() {
		m.SetPolicyCount(0)
		m.SetPolicyCount(5)
		m.SetPolicyCount(100)
	})

	// Verify metric is recorded
	mfs, err := m.Registry().Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)
}

func TestMetrics_Registry(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_registry")

	registry := m.Registry()
	require.NotNil(t, registry)

	// Record some metrics so they appear in gather
	m.RecordEvaluation("default", "allow", time.Millisecond)

	mfs, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)
}

func TestMetrics_MustRegister(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_must_register")
	reg := prometheus.NewRegistry()

	// First registration should not panic
	assert.NotPanics(t, func() {
		m.MustRegister(reg)
	})

	// Verify metrics are registered
	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)
}

func TestMetrics_MustRegister_Duplicate(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_dup_register")
	reg := prometheus.NewRegistry()

	// First registration
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := isAlreadyRegistered(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMetrics_RecordEvaluation(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_eval")

	assert.NotPanics(t, func() {
		m.RecordEvaluation("default", "allow", 10*time.Millisecond)
		m.RecordEvaluation("default", "deny", 5*time.Millisecond)
		m.RecordEvaluation("custom", "allow", 1*time.Millisecond)
	})
}

func TestMetrics_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_concurrent")

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				m.RecordEvaluation("default", "allow", time.Millisecond)
				m.SetPolicyCount(j)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
