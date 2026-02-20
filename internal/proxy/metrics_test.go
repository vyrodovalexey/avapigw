package proxy

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetProxyMetrics_Singleton(t *testing.T) {
	m1 := getProxyMetrics()
	m2 := getProxyMetrics()

	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "should return same instance")
}

func TestGetProxyMetrics_AllFieldsInitialized(t *testing.T) {
	m := getProxyMetrics()

	require.NotNil(t, m)
	assert.NotNil(t, m.errorsTotal, "errorsTotal should be initialized")
	assert.NotNil(t, m.backendDuration, "backendDuration should be initialized")
}

func TestProxyMetrics_RecordError(t *testing.T) {
	m := getProxyMetrics()

	tests := []struct {
		name      string
		backend   string
		errorType string
	}{
		{name: "connection error", backend: "metrics-test-be", errorType: "connection"},
		{name: "timeout error", backend: "metrics-test-be", errorType: "timeout"},
		{name: "protocol error", backend: "metrics-test-be", errorType: "protocol"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(
				m.errorsTotal.WithLabelValues(tt.backend, tt.errorType),
			)
			m.errorsTotal.WithLabelValues(tt.backend, tt.errorType).Inc()
			after := testutil.ToFloat64(
				m.errorsTotal.WithLabelValues(tt.backend, tt.errorType),
			)

			assert.Equal(t, before+1, after, "errorsTotal should increment by 1")
		})
	}
}

func TestProxyMetrics_RecordBackendDuration(t *testing.T) {
	m := getProxyMetrics()

	tests := []struct {
		name     string
		backend  string
		duration float64
	}{
		{name: "fast request", backend: "metrics-test-dur", duration: 0.001},
		{name: "medium request", backend: "metrics-test-dur", duration: 0.1},
		{name: "slow request", backend: "metrics-test-dur", duration: 5.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.backendDuration.WithLabelValues(tt.backend).Observe(tt.duration)

			// Verify histogram has observations by collecting from the vec
			count := testutil.CollectAndCount(m.backendDuration)
			assert.Greater(t, count, 0, "backendDuration should have observations")
		})
	}
}

func TestProxyMetrics_ConcurrentAccess(t *testing.T) {
	m := getProxyMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.errorsTotal.WithLabelValues("concurrent-be", "timeout").Inc()
				m.backendDuration.WithLabelValues("concurrent-be").Observe(0.01)
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions occur (run with -race flag)
}
