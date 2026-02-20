package webhook

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetWebhookMetricsForTesting resets the webhook metrics singleton so
// tests can re-initialize with a fresh Prometheus registry. This prevents
// "duplicate metrics collector registration" panics when multiple tests need
// isolated metrics instances. Must only be called from tests.
func resetWebhookMetricsForTesting() {
	webhookMetricsInstance = nil
	webhookMetricsOnce = sync.Once{}
}

// resetDuplicateMetricsForTesting resets the duplicate detection metrics
// singleton so tests can re-initialize with a fresh Prometheus registry.
func resetDuplicateMetricsForTesting() {
	duplicateMetricsInstance = nil
	duplicateMetricsOnce = sync.Once{}
}

func TestGetWebhookMetrics_Singleton(t *testing.T) {
	m1 := GetWebhookMetrics()
	m2 := GetWebhookMetrics()

	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "should return same instance")
}

func TestGetWebhookMetrics_AllFieldsInitialized(t *testing.T) {
	m := GetWebhookMetrics()

	require.NotNil(t, m)
	assert.NotNil(t, m.validationsTotal, "validationsTotal should be initialized")
	assert.NotNil(t, m.validationDuration, "validationDuration should be initialized")
	assert.NotNil(t, m.validationWarnings, "validationWarnings should be initialized")
}

func TestWebhookMetrics_RecordValidation(t *testing.T) {
	m := GetWebhookMetrics()

	tests := []struct {
		name         string
		resource     string
		operation    string
		result       string
		duration     time.Duration
		warningCount int
	}{
		{
			name:         "successful create validation",
			resource:     "metrics-test-apiroute",
			operation:    "CREATE",
			result:       "allowed",
			duration:     10 * time.Millisecond,
			warningCount: 0,
		},
		{
			name:         "failed update validation",
			resource:     "metrics-test-apiroute",
			operation:    "UPDATE",
			result:       "denied",
			duration:     5 * time.Millisecond,
			warningCount: 0,
		},
		{
			name:         "validation with warnings",
			resource:     "metrics-test-backend",
			operation:    "CREATE",
			result:       "allowed",
			duration:     15 * time.Millisecond,
			warningCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforeTotal := testutil.ToFloat64(
				m.validationsTotal.WithLabelValues(tt.resource, tt.operation, tt.result),
			)
			beforeWarnings := testutil.ToFloat64(
				m.validationWarnings.WithLabelValues(tt.resource),
			)

			m.RecordValidation(tt.resource, tt.operation, tt.result, tt.duration, tt.warningCount)

			afterTotal := testutil.ToFloat64(
				m.validationsTotal.WithLabelValues(tt.resource, tt.operation, tt.result),
			)
			assert.Equal(t, beforeTotal+1, afterTotal, "validationsTotal should increment by 1")

			// Verify duration was recorded by collecting from the vec
			durationCount := testutil.CollectAndCount(m.validationDuration)
			assert.Greater(t, durationCount, 0, "validationDuration should have observations")

			// Verify warnings
			if tt.warningCount > 0 {
				afterWarnings := testutil.ToFloat64(
					m.validationWarnings.WithLabelValues(tt.resource),
				)
				assert.Equal(t, beforeWarnings+float64(tt.warningCount), afterWarnings,
					"validationWarnings should increment by warningCount")
			}
		})
	}
}

func TestWebhookMetrics_RecordValidation_ZeroWarnings(t *testing.T) {
	m := GetWebhookMetrics()

	beforeWarnings := testutil.ToFloat64(
		m.validationWarnings.WithLabelValues("metrics-test-zero-warn"),
	)

	m.RecordValidation("metrics-test-zero-warn", "CREATE", "allowed", time.Millisecond, 0)

	afterWarnings := testutil.ToFloat64(
		m.validationWarnings.WithLabelValues("metrics-test-zero-warn"),
	)

	assert.Equal(t, beforeWarnings, afterWarnings,
		"validationWarnings should not change when warningCount is 0")
}

func TestWebhookMetrics_ConcurrentAccess(t *testing.T) {
	m := GetWebhookMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.RecordValidation(
					"concurrent-resource",
					"CREATE",
					"allowed",
					time.Duration(j)*time.Microsecond,
					1,
				)
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions occur (run with -race flag)
}

// ============================================================================
// newWebhookMetricsWithFactory Tests
// ============================================================================

// newTestWebhookMetrics creates a WebhookMetrics instance with a fresh registry
// to avoid duplicate registration panics across tests.
func newTestWebhookMetrics(t *testing.T) (*WebhookMetrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := newWebhookMetricsWithFactory(promauto.With(reg))
	return m, reg
}

func TestNewWebhookMetricsWithFactory_AllFieldsInitialized(t *testing.T) {
	m, _ := newTestWebhookMetrics(t)

	require.NotNil(t, m)
	assert.NotNil(t, m.validationsTotal, "validationsTotal should be initialized")
	assert.NotNil(t, m.validationDuration, "validationDuration should be initialized")
	assert.NotNil(t, m.validationWarnings, "validationWarnings should be initialized")
}

func TestNewWebhookMetricsWithFactory_MetricNames(t *testing.T) {
	m, reg := newTestWebhookMetrics(t)

	// Initialize metrics with label values so they appear in Gather()
	m.validationsTotal.WithLabelValues("APIRoute", "CREATE", "allowed").Inc()
	m.validationDuration.WithLabelValues("APIRoute", "CREATE").Observe(0.01)
	m.validationWarnings.WithLabelValues("APIRoute").Inc()

	families, err := reg.Gather()
	require.NoError(t, err)

	expectedNames := map[string]bool{
		"avapigw_operator_webhook_validations_total":           false,
		"avapigw_operator_webhook_validation_duration_seconds": false,
		"avapigw_operator_webhook_validation_warnings_total":   false,
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

func TestNewWebhookMetricsWithFactory_RecordValidation(t *testing.T) {
	m, _ := newTestWebhookMetrics(t)

	tests := []struct {
		name         string
		resource     string
		operation    string
		result       string
		duration     time.Duration
		warningCount int
	}{
		{
			name:         "successful create",
			resource:     "APIRoute",
			operation:    "CREATE",
			result:       "allowed",
			duration:     10 * time.Millisecond,
			warningCount: 0,
		},
		{
			name:         "denied update",
			resource:     "Backend",
			operation:    "UPDATE",
			result:       "denied",
			duration:     5 * time.Millisecond,
			warningCount: 0,
		},
		{
			name:         "with warnings",
			resource:     "GRPCRoute",
			operation:    "CREATE",
			result:       "allowed",
			duration:     15 * time.Millisecond,
			warningCount: 2,
		},
		{
			name:         "delete operation",
			resource:     "GRPCBackend",
			operation:    "DELETE",
			result:       "allowed",
			duration:     1 * time.Millisecond,
			warningCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforeTotal := testutil.ToFloat64(
				m.validationsTotal.WithLabelValues(tt.resource, tt.operation, tt.result),
			)

			m.RecordValidation(tt.resource, tt.operation, tt.result, tt.duration, tt.warningCount)

			afterTotal := testutil.ToFloat64(
				m.validationsTotal.WithLabelValues(tt.resource, tt.operation, tt.result),
			)
			assert.Equal(t, beforeTotal+1, afterTotal, "validationsTotal should increment by 1")
		})
	}
}

func TestNewWebhookMetricsWithFactory_IsolatedRegistry(t *testing.T) {
	// Verify that two separate factory-created metrics don't interfere
	m1, reg1 := newTestWebhookMetrics(t)
	m2, reg2 := newTestWebhookMetrics(t)

	m1.RecordValidation("resource1", "CREATE", "allowed", time.Millisecond, 0)

	// reg1 should have metrics, reg2 should not have the same label values
	families1, err := reg1.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families1, "reg1 should have metrics")

	families2, err := reg2.Gather()
	require.NoError(t, err)
	_ = families2

	// m2 should be independent
	val := testutil.ToFloat64(m2.validationsTotal.WithLabelValues("resource1", "CREATE", "allowed"))
	assert.Equal(t, float64(0), val, "m2 should not have m1's metrics")
}

func TestInitWebhookVecMetrics_NoPanic(t *testing.T) {
	// InitWebhookVecMetrics uses the singleton. It should not panic.
	assert.NotPanics(t, func() {
		InitWebhookVecMetrics()
	})

	// Idempotent - calling again should not panic
	assert.NotPanics(t, func() {
		InitWebhookVecMetrics()
	})
}

func TestInitDuplicateVecMetrics_NoPanic(t *testing.T) {
	// InitDuplicateVecMetrics uses the singleton. It should not panic.
	assert.NotPanics(t, func() {
		InitDuplicateVecMetrics()
	})

	// Idempotent - calling again should not panic
	assert.NotPanics(t, func() {
		InitDuplicateVecMetrics()
	})
}
