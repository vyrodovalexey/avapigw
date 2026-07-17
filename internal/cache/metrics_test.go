package cache

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCacheMetrics_Singleton(t *testing.T) {
	m1 := GetCacheMetrics()
	m2 := GetCacheMetrics()

	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "should return same instance")
}

func TestGetCacheMetrics_AllFieldsInitialized(t *testing.T) {
	m := GetCacheMetrics()

	require.NotNil(t, m)
	assert.NotNil(t, m.hitsTotal, "hitsTotal should be initialized")
	assert.NotNil(t, m.missesTotal, "missesTotal should be initialized")
	assert.NotNil(t, m.evictionsTotal, "evictionsTotal should be initialized")
	assert.NotNil(t, m.sizeGauge, "sizeGauge should be initialized")
	assert.NotNil(t, m.operationDuration, "operationDuration should be initialized")
	assert.NotNil(t, m.errorsTotal, "errorsTotal should be initialized")
}

func TestCacheMetrics_RecordHit(t *testing.T) {
	m := GetCacheMetrics()

	before := testutil.ToFloat64(m.hitsTotal.WithLabelValues("metrics-test-hit"))
	m.hitsTotal.WithLabelValues("metrics-test-hit").Inc()
	after := testutil.ToFloat64(m.hitsTotal.WithLabelValues("metrics-test-hit"))

	assert.Equal(t, before+1, after, "hitsTotal should increment by 1")
}

func TestCacheMetrics_RecordMiss(t *testing.T) {
	m := GetCacheMetrics()

	before := testutil.ToFloat64(m.missesTotal.WithLabelValues("metrics-test-miss"))
	m.missesTotal.WithLabelValues("metrics-test-miss").Inc()
	after := testutil.ToFloat64(m.missesTotal.WithLabelValues("metrics-test-miss"))

	assert.Equal(t, before+1, after, "missesTotal should increment by 1")
}

func TestCacheMetrics_RecordEviction(t *testing.T) {
	m := GetCacheMetrics()

	before := testutil.ToFloat64(m.evictionsTotal.WithLabelValues("metrics-test-evict"))
	m.evictionsTotal.WithLabelValues("metrics-test-evict").Inc()
	after := testutil.ToFloat64(m.evictionsTotal.WithLabelValues("metrics-test-evict"))

	assert.Equal(t, before+1, after, "evictionsTotal should increment by 1")
}

func TestCacheMetrics_SetSize(t *testing.T) {
	m := GetCacheMetrics()

	m.sizeGauge.WithLabelValues("metrics-test-size").Set(100)
	val := testutil.ToFloat64(m.sizeGauge.WithLabelValues("metrics-test-size"))

	assert.Equal(t, float64(100), val, "sizeGauge should be set to 100")

	m.sizeGauge.WithLabelValues("metrics-test-size").Set(0)
	val = testutil.ToFloat64(m.sizeGauge.WithLabelValues("metrics-test-size"))

	assert.Equal(t, float64(0), val, "sizeGauge should be set to 0")
}

func TestCacheMetrics_RecordOperation(t *testing.T) {
	m := GetCacheMetrics()

	tests := []struct {
		name      string
		backend   string
		operation string
		duration  float64
	}{
		{name: "get operation", backend: "metrics-test-op", operation: "get", duration: 0.001},
		{name: "set operation", backend: "metrics-test-op", operation: "set", duration: 0.005},
		{name: "delete operation", backend: "metrics-test-op", operation: "delete", duration: 0.0001},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Observe should not panic and should record the value
			m.operationDuration.WithLabelValues(tt.backend, tt.operation).Observe(tt.duration)

			// Verify histogram has observations by collecting from the vec
			count := testutil.CollectAndCount(m.operationDuration)
			assert.Greater(t, count, 0, "operationDuration should have observations")
		})
	}
}

func TestCacheMetrics_RecordError(t *testing.T) {
	m := GetCacheMetrics()

	tests := []struct {
		name      string
		backend   string
		operation string
	}{
		{name: "get error", backend: "metrics-test-err", operation: "get"},
		{name: "set error", backend: "metrics-test-err", operation: "set"},
		{name: "delete error", backend: "metrics-test-err", operation: "delete"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(
				m.errorsTotal.WithLabelValues(tt.backend, tt.operation),
			)
			m.errorsTotal.WithLabelValues(tt.backend, tt.operation).Inc()
			after := testutil.ToFloat64(
				m.errorsTotal.WithLabelValues(tt.backend, tt.operation),
			)

			assert.Equal(t, before+1, after, "errorsTotal should increment by 1")
		})
	}
}

// metricSeriesExists reports whether a series with the given label values
// exists for the named metric family in the default registry.
func metricSeriesExists(t *testing.T, name string, want map[string]string) bool {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := make(map[string]string, len(metric.GetLabel()))
			for _, pair := range metric.GetLabel() {
				labels[pair.GetName()] = pair.GetValue()
			}
			matches := true
			for k, v := range want {
				if labels[k] != v {
					matches = false
					break
				}
			}
			if matches {
				return true
			}
		}
	}
	return false
}

func TestCacheMetrics_Init_PreInitializesLabelCombinations(t *testing.T) {
	m := GetCacheMetrics()
	m.Init()
	m.Init() // idempotent

	for _, backend := range []string{"memory", "redis"} {
		for _, op := range []string{"get", "set", "delete", "exists"} {
			labels := map[string]string{"backend": backend, "operation": op}
			assert.True(t,
				metricSeriesExists(t, "gateway_cache_errors_total", labels),
				"errors_total series for %s/%s must be pre-initialized", backend, op)
			assert.True(t,
				metricSeriesExists(t, "gateway_cache_operation_duration_seconds", labels),
				"operation_duration series for %s/%s must be pre-initialized", backend, op)
		}
	}

	// Redis-only operations added for metric parity (GetWithTTL/SetNX/Expire).
	for _, op := range []string{"get_with_ttl", "setnx", "expire"} {
		labels := map[string]string{"backend": "redis", "operation": op}
		assert.True(t,
			metricSeriesExists(t, "gateway_cache_errors_total", labels),
			"errors_total series for redis/%s must be pre-initialized", op)
		assert.True(t,
			metricSeriesExists(t, "gateway_cache_operation_duration_seconds", labels),
			"operation_duration series for redis/%s must be pre-initialized", op)
	}
}

func TestCacheMetrics_MustRegister(t *testing.T) {
	m := GetCacheMetrics()
	m.Init()

	registry := prometheus.NewRegistry()
	m.MustRegister(registry)

	families, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families, "registered collectors must be gatherable")
}

func TestCacheMetrics_ConcurrentAccess(t *testing.T) {
	m := GetCacheMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.hitsTotal.WithLabelValues("concurrent-test").Inc()
				m.missesTotal.WithLabelValues("concurrent-test").Inc()
				m.evictionsTotal.WithLabelValues("concurrent-test").Inc()
				m.sizeGauge.WithLabelValues("concurrent-test").Set(float64(j))
				m.operationDuration.WithLabelValues("concurrent-test", "get").Observe(0.001)
				m.errorsTotal.WithLabelValues("concurrent-test", "get").Inc()
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions occur (run with -race flag)
}
