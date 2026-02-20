package jwt

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
