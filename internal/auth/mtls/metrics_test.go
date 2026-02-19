package mtls

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
		{
			name:      "with namespace",
			namespace: "test",
		},
		{
			name:      "empty namespace defaults to gateway",
			namespace: "",
		},
		{
			name:      "custom namespace",
			namespace: "myapp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMetrics(tt.namespace)
			require.NotNil(t, m)
			assert.NotNil(t, m.validationTotal)
			assert.NotNil(t, m.validationDuration)
			assert.NotNil(t, m.revocationChecks)
			assert.NotNil(t, m.registry)
		})
	}
}

func TestMetrics_RecordValidation(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	tests := []struct {
		name     string
		status   string
		reason   string
		duration time.Duration
	}{
		{
			name:     "success validation",
			status:   "success",
			reason:   "valid",
			duration: 10 * time.Millisecond,
		},
		{
			name:     "error - no certificate",
			status:   "error",
			reason:   "no_certificate",
			duration: 1 * time.Millisecond,
		},
		{
			name:     "error - expired",
			status:   "error",
			reason:   "expired",
			duration: 5 * time.Millisecond,
		},
		{
			name:     "error - not yet valid",
			status:   "error",
			reason:   "not_yet_valid",
			duration: 2 * time.Millisecond,
		},
		{
			name:     "error - revoked",
			status:   "error",
			reason:   "revoked",
			duration: 50 * time.Millisecond,
		},
		{
			name:     "error - invalid chain",
			status:   "error",
			reason:   "invalid_chain",
			duration: 100 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record validation - should not panic
			assert.NotPanics(t, func() {
				m.RecordValidation(tt.status, tt.reason, tt.duration)
			})
		})
	}
}

func TestMetrics_RecordRevocationCheck(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	tests := []struct {
		name      string
		checkType string
		status    string
	}{
		{
			name:      "CRL success",
			checkType: "crl",
			status:    "success",
		},
		{
			name:      "CRL error",
			checkType: "crl",
			status:    "error",
		},
		{
			name:      "OCSP success",
			checkType: "ocsp",
			status:    "success",
		},
		{
			name:      "OCSP error",
			checkType: "ocsp",
			status:    "error",
		},
		{
			name:      "OCSP revoked",
			checkType: "ocsp",
			status:    "revoked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record revocation check - should not panic
			assert.NotPanics(t, func() {
				m.RecordRevocationCheck(tt.checkType, tt.status)
			})
		})
	}
}

func TestMetrics_Registry(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	registry := m.Registry()
	assert.NotNil(t, registry)

	// Record some metrics first so they appear in gather
	m.RecordValidation("success", "valid", time.Millisecond)
	m.RecordRevocationCheck("crl", "success")

	// Verify metrics are registered
	mfs, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)

	// Check that expected metrics exist
	metricNames := make(map[string]bool)
	for _, mf := range mfs {
		metricNames[mf.GetName()] = true
	}

	assert.True(t, metricNames["test_mtls_validation_total"])
	assert.True(t, metricNames["test_mtls_validation_duration_seconds"])
	assert.True(t, metricNames["test_mtls_revocation_checks_total"])
}

func TestMetrics_MustRegister(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_register")

	// Create a new registry
	registry := prometheus.NewRegistry()

	// Should not panic
	assert.NotPanics(t, func() {
		m.MustRegister(registry)
	})

	// Verify metrics are registered in the new registry
	mfs, err := registry.Gather()
	require.NoError(t, err)

	// Record some metrics
	m.RecordValidation("success", "valid", time.Millisecond)

	mfs, err = registry.Gather()
	require.NoError(t, err)

	metricNames := make(map[string]bool)
	for _, mf := range mfs {
		metricNames[mf.GetName()] = true
	}

	assert.True(t, metricNames["test_register_mtls_validation_total"])
}

func TestMetrics_MultipleRecords(t *testing.T) {
	t.Parallel()

	m := NewMetrics("multi")

	// Record multiple validations
	for i := 0; i < 10; i++ {
		m.RecordValidation("success", "valid", time.Duration(i)*time.Millisecond)
	}

	for i := 0; i < 5; i++ {
		m.RecordValidation("error", "expired", time.Duration(i)*time.Millisecond)
	}

	// Record multiple revocation checks
	for i := 0; i < 3; i++ {
		m.RecordRevocationCheck("crl", "success")
		m.RecordRevocationCheck("ocsp", "success")
	}

	// Gather and verify
	mfs, err := m.Registry().Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := isAlreadyRegistered(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
