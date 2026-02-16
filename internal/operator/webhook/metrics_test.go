package webhook

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
