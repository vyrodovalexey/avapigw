package cert

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCertMetrics_Singleton(t *testing.T) {
	m1 := GetCertMetrics()
	m2 := GetCertMetrics()

	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "should return same instance")
}

func TestGetCertMetrics_AllFieldsInitialized(t *testing.T) {
	m := GetCertMetrics()

	require.NotNil(t, m)
	assert.NotNil(t, m.issuedTotal, "issuedTotal should be initialized")
	assert.NotNil(t, m.rotationsTotal, "rotationsTotal should be initialized")
	assert.NotNil(t, m.errorsTotal, "errorsTotal should be initialized")
	assert.NotNil(t, m.expirySeconds, "expirySeconds should be initialized")
}

func TestCertMetrics_RecordIssued(t *testing.T) {
	m := GetCertMetrics()

	tests := []struct {
		name     string
		provider string
	}{
		{name: "selfsigned provider", provider: "metrics-test-selfsigned"},
		{name: "vault provider", provider: "metrics-test-vault"},
		{name: "acme provider", provider: "metrics-test-acme"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(
				m.issuedTotal.WithLabelValues(tt.provider),
			)
			m.issuedTotal.WithLabelValues(tt.provider).Inc()
			after := testutil.ToFloat64(
				m.issuedTotal.WithLabelValues(tt.provider),
			)

			assert.Equal(t, before+1, after, "issuedTotal should increment by 1")
		})
	}
}

func TestCertMetrics_RecordRotation(t *testing.T) {
	m := GetCertMetrics()

	before := testutil.ToFloat64(
		m.rotationsTotal.WithLabelValues("metrics-test-rotation"),
	)
	m.rotationsTotal.WithLabelValues("metrics-test-rotation").Inc()
	after := testutil.ToFloat64(
		m.rotationsTotal.WithLabelValues("metrics-test-rotation"),
	)

	assert.Equal(t, before+1, after, "rotationsTotal should increment by 1")
}

func TestCertMetrics_RecordError(t *testing.T) {
	m := GetCertMetrics()

	tests := []struct {
		name      string
		provider  string
		operation string
	}{
		{name: "issue error", provider: "metrics-test-err", operation: "issue"},
		{name: "rotate error", provider: "metrics-test-err", operation: "rotate"},
		{name: "renew error", provider: "metrics-test-err", operation: "renew"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(
				m.errorsTotal.WithLabelValues(tt.provider, tt.operation),
			)
			m.errorsTotal.WithLabelValues(tt.provider, tt.operation).Inc()
			after := testutil.ToFloat64(
				m.errorsTotal.WithLabelValues(tt.provider, tt.operation),
			)

			assert.Equal(t, before+1, after, "errorsTotal should increment by 1")
		})
	}
}

func TestCertMetrics_SetExpiry(t *testing.T) {
	m := GetCertMetrics()

	tests := []struct {
		name       string
		commonName string
		seconds    float64
	}{
		{name: "long expiry", commonName: "metrics-test-long.example.com", seconds: 86400},
		{name: "short expiry", commonName: "metrics-test-short.example.com", seconds: 3600},
		{name: "expired", commonName: "metrics-test-expired.example.com", seconds: -100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.expirySeconds.WithLabelValues(tt.commonName).Set(tt.seconds)
			val := testutil.ToFloat64(
				m.expirySeconds.WithLabelValues(tt.commonName),
			)

			assert.Equal(t, tt.seconds, val, "expirySeconds should be set correctly")
		})
	}
}

func TestCertMetrics_ConcurrentAccess(t *testing.T) {
	m := GetCertMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.issuedTotal.WithLabelValues("concurrent-provider").Inc()
				m.rotationsTotal.WithLabelValues("concurrent-provider").Inc()
				m.errorsTotal.WithLabelValues("concurrent-provider", "issue").Inc()
				m.expirySeconds.WithLabelValues("concurrent.example.com").Set(float64(j))
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions occur (run with -race flag)
}

// ============================================================================
// newCertMetricsWithFactory Tests
// ============================================================================

// newTestCertMetrics creates a CertMetrics instance with a fresh registry
// to avoid duplicate registration panics across tests.
func newTestCertMetrics(t *testing.T) (*CertMetrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := newCertMetricsWithFactory(promauto.With(reg))
	return m, reg
}

func TestNewCertMetricsWithFactory_AllFieldsInitialized(t *testing.T) {
	m, _ := newTestCertMetrics(t)

	require.NotNil(t, m)
	assert.NotNil(t, m.issuedTotal, "issuedTotal should be initialized")
	assert.NotNil(t, m.rotationsTotal, "rotationsTotal should be initialized")
	assert.NotNil(t, m.errorsTotal, "errorsTotal should be initialized")
	assert.NotNil(t, m.expirySeconds, "expirySeconds should be initialized")
}

func TestNewCertMetricsWithFactory_MetricNames(t *testing.T) {
	m, reg := newTestCertMetrics(t)

	// Initialize metrics with label values so they appear in Gather()
	m.issuedTotal.WithLabelValues("selfsigned").Inc()
	m.rotationsTotal.WithLabelValues("selfsigned").Inc()
	m.errorsTotal.WithLabelValues("selfsigned", "issue").Inc()
	m.expirySeconds.WithLabelValues("test.example.com").Set(86400)

	families, err := reg.Gather()
	require.NoError(t, err)

	expectedNames := map[string]bool{
		"avapigw_operator_cert_issued_total":    false,
		"avapigw_operator_cert_rotations_total": false,
		"avapigw_operator_cert_errors_total":    false,
		"avapigw_operator_cert_expiry_seconds":  false,
	}

	for _, family := range families {
		if _, ok := expectedNames[family.GetName()]; ok {
			expectedNames[family.GetName()] = true
		}
	}

	for name, found := range expectedNames {
		assert.True(t, found, "metric %s should be registered", name)
	}
}

func TestNewCertMetricsWithFactory_RecordOperations(t *testing.T) {
	m, _ := newTestCertMetrics(t)

	tests := []struct {
		name string
		fn   func()
	}{
		{"issue selfsigned", func() { m.issuedTotal.WithLabelValues("selfsigned").Inc() }},
		{"issue vault", func() { m.issuedTotal.WithLabelValues("vault").Inc() }},
		{"rotate selfsigned", func() { m.rotationsTotal.WithLabelValues("selfsigned").Inc() }},
		{"error issue", func() { m.errorsTotal.WithLabelValues("selfsigned", "issue").Inc() }},
		{"error rotate", func() { m.errorsTotal.WithLabelValues("selfsigned", "rotate").Inc() }},
		{"set expiry", func() { m.expirySeconds.WithLabelValues("test.example.com").Set(3600) }},
		{"set negative expiry", func() { m.expirySeconds.WithLabelValues("expired.example.com").Set(-100) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			tt.fn()
		})
	}
}

func TestNewCertMetricsWithFactory_IsolatedRegistry(t *testing.T) {
	m1, _ := newTestCertMetrics(t)
	m2, _ := newTestCertMetrics(t)

	m1.issuedTotal.WithLabelValues("test-provider").Inc()

	val1 := testutil.ToFloat64(m1.issuedTotal.WithLabelValues("test-provider"))
	val2 := testutil.ToFloat64(m2.issuedTotal.WithLabelValues("test-provider"))

	assert.Equal(t, float64(1), val1, "m1 should have the metric")
	assert.Equal(t, float64(0), val2, "m2 should be independent from m1")
}

// ============================================================================
// newVaultAuthMetricsWithFactory Tests
// ============================================================================

func newTestVaultAuthMetrics(t *testing.T) (*vaultAuthMetrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := newVaultAuthMetricsWithFactory(promauto.With(reg))
	return m, reg
}

func TestNewVaultAuthMetricsWithFactory_AllFieldsInitialized(t *testing.T) {
	m, _ := newTestVaultAuthMetrics(t)

	require.NotNil(t, m)
	assert.NotNil(t, m.authRetriesTotal, "authRetriesTotal should be initialized")
}

func TestNewVaultAuthMetricsWithFactory_MetricNames(t *testing.T) {
	m, reg := newTestVaultAuthMetrics(t)

	// Initialize metrics with label values so they appear in Gather()
	m.authRetriesTotal.WithLabelValues("success").Inc()
	m.authRetriesTotal.WithLabelValues("failure").Inc()

	families, err := reg.Gather()
	require.NoError(t, err)

	expectedNames := map[string]bool{
		"avapigw_operator_vault_auth_retries_total": false,
	}

	for _, family := range families {
		if _, ok := expectedNames[family.GetName()]; ok {
			expectedNames[family.GetName()] = true
		}
	}

	for name, found := range expectedNames {
		assert.True(t, found, "metric %s should be registered", name)
	}
}

func TestNewVaultAuthMetricsWithFactory_RecordOperations(t *testing.T) {
	m, _ := newTestVaultAuthMetrics(t)

	tests := []struct {
		name   string
		result string
	}{
		{"success", "success"},
		{"failure", "failure"},
		{"retry", "retry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(m.authRetriesTotal.WithLabelValues(tt.result))
			m.authRetriesTotal.WithLabelValues(tt.result).Inc()
			after := testutil.ToFloat64(m.authRetriesTotal.WithLabelValues(tt.result))
			assert.Equal(t, before+1, after, "authRetriesTotal should increment by 1")
		})
	}
}

func TestNewVaultAuthMetricsWithFactory_IsolatedRegistry(t *testing.T) {
	m1, _ := newTestVaultAuthMetrics(t)
	m2, _ := newTestVaultAuthMetrics(t)

	m1.authRetriesTotal.WithLabelValues("success").Inc()

	val1 := testutil.ToFloat64(m1.authRetriesTotal.WithLabelValues("success"))
	val2 := testutil.ToFloat64(m2.authRetriesTotal.WithLabelValues("success"))

	assert.Equal(t, float64(1), val1, "m1 should have the metric")
	assert.Equal(t, float64(0), val2, "m2 should be independent from m1")
}

func TestInitCertVecMetrics_NoPanic(t *testing.T) {
	// InitCertVecMetrics uses the singleton. It should not panic.
	assert.NotPanics(t, func() {
		InitCertVecMetrics()
	})

	// Idempotent - calling again should not panic
	assert.NotPanics(t, func() {
		InitCertVecMetrics()
	})
}

func TestInitVaultAuthVecMetrics_NoPanic(t *testing.T) {
	// InitVaultAuthVecMetrics uses the singleton. It should not panic.
	assert.NotPanics(t, func() {
		InitVaultAuthVecMetrics()
	})

	// Idempotent - calling again should not panic
	assert.NotPanics(t, func() {
		InitVaultAuthVecMetrics()
	})
}

func TestInitWebhookInjectorVecMetrics_NoPanic(t *testing.T) {
	// InitWebhookInjectorVecMetrics uses the singleton. It should not panic.
	assert.NotPanics(t, func() {
		InitWebhookInjectorVecMetrics()
	})

	// Idempotent - calling again should not panic
	assert.NotPanics(t, func() {
		InitWebhookInjectorVecMetrics()
	})
}
