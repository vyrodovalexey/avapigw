package health

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetHealthMetrics_Singleton(t *testing.T) {
	m1 := GetHealthMetrics()
	m2 := GetHealthMetrics()

	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "should return same instance")
}

func TestGetHealthMetrics_AllFieldsInitialized(t *testing.T) {
	m := GetHealthMetrics()

	require.NotNil(t, m)
	assert.NotNil(t, m.checksTotal, "checksTotal should be initialized")
	assert.NotNil(t, m.checkStatus, "checkStatus should be initialized")
}

func TestHealthMetrics_RecordHealthCheck(t *testing.T) {
	m := GetHealthMetrics()

	tests := []struct {
		name      string
		checkType string
	}{
		{name: "health check", checkType: "health"},
		{name: "readiness check", checkType: "readiness"},
		{name: "liveness check", checkType: "liveness"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(
				m.checksTotal.WithLabelValues(tt.checkType),
			)
			m.checksTotal.WithLabelValues(tt.checkType).Inc()
			after := testutil.ToFloat64(
				m.checksTotal.WithLabelValues(tt.checkType),
			)

			assert.Equal(t, before+1, after, "checksTotal should increment by 1")
		})
	}
}

func TestHealthMetrics_SetCheckStatus(t *testing.T) {
	m := GetHealthMetrics()

	tests := []struct {
		name      string
		checkName string
		healthy   bool
		expected  float64
	}{
		{name: "healthy check", checkName: "metrics-test-db", healthy: true, expected: 1},
		{name: "unhealthy check", checkName: "metrics-test-cache", healthy: false, expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.healthy {
				m.checkStatus.WithLabelValues(tt.checkName).Set(1)
			} else {
				m.checkStatus.WithLabelValues(tt.checkName).Set(0)
			}

			val := testutil.ToFloat64(
				m.checkStatus.WithLabelValues(tt.checkName),
			)
			assert.Equal(t, tt.expected, val)
		})
	}
}

func TestHealthMetrics_SetCheckStatus_Toggle(t *testing.T) {
	m := GetHealthMetrics()

	// Set healthy
	m.checkStatus.WithLabelValues("metrics-test-toggle").Set(1)
	val := testutil.ToFloat64(m.checkStatus.WithLabelValues("metrics-test-toggle"))
	assert.Equal(t, float64(1), val)

	// Set unhealthy
	m.checkStatus.WithLabelValues("metrics-test-toggle").Set(0)
	val = testutil.ToFloat64(m.checkStatus.WithLabelValues("metrics-test-toggle"))
	assert.Equal(t, float64(0), val)
}

func TestHealthMetrics_ConcurrentAccess(t *testing.T) {
	m := GetHealthMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.checksTotal.WithLabelValues("health").Inc()
				m.checksTotal.WithLabelValues("readiness").Inc()
				m.checkStatus.WithLabelValues("concurrent-db").Set(1)
				m.checkStatus.WithLabelValues("concurrent-cache").Set(0)
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions occur (run with -race flag)
}
