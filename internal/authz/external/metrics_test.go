package external

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMetrics tests that NewMetrics creates a valid Metrics instance.
func TestNewMetrics(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		namespace         string
		expectedNamespace string
	}{
		{
			name:              "WithNamespace",
			namespace:         "test",
			expectedNamespace: "test",
		},
		{
			name:              "EmptyNamespace",
			namespace:         "",
			expectedNamespace: "gateway",
		},
		{
			name:              "CustomNamespace",
			namespace:         "myapp",
			expectedNamespace: "myapp",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act
			metrics := NewMetrics(tc.namespace)

			// Assert
			require.NotNil(t, metrics)
			require.NotNil(t, metrics.requestTotal)
			require.NotNil(t, metrics.requestDuration)
			require.NotNil(t, metrics.cacheHits)
			require.NotNil(t, metrics.cacheMisses)
			require.NotNil(t, metrics.errors)
			require.NotNil(t, metrics.registry)
		})
	}
}

// TestMetrics_RecordRequest tests that RecordRequest properly records metrics.
func TestMetrics_RecordRequest(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		authzType string
		decision  string
		duration  time.Duration
	}{
		{
			name:      "OPAAllowed",
			authzType: "opa",
			decision:  "allowed",
			duration:  10 * time.Millisecond,
		},
		{
			name:      "OPADenied",
			authzType: "opa",
			decision:  "denied",
			duration:  5 * time.Millisecond,
		},
		{
			name:      "OPAError",
			authzType: "opa",
			decision:  "error",
			duration:  100 * time.Millisecond,
		},
		{
			name:      "GRPCAllowed",
			authzType: "grpc",
			decision:  "allowed",
			duration:  15 * time.Millisecond,
		},
		{
			name:      "HTTPDenied",
			authzType: "http",
			decision:  "denied",
			duration:  20 * time.Millisecond,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			metrics := NewMetrics("test")

			// Act
			metrics.RecordRequest(tc.authzType, tc.decision, tc.duration)

			// Assert - verify counter was incremented
			counter, err := metrics.requestTotal.GetMetricWithLabelValues(tc.authzType, tc.decision)
			require.NoError(t, err)

			var m io_prometheus_client.Metric
			err = counter.Write(&m)
			require.NoError(t, err)
			assert.Equal(t, float64(1), m.GetCounter().GetValue())

			// Verify histogram was observed
			histogram, err := metrics.requestDuration.GetMetricWithLabelValues(tc.authzType, tc.decision)
			require.NoError(t, err)

			err = histogram.(prometheus.Metric).Write(&m)
			require.NoError(t, err)
			assert.Equal(t, uint64(1), m.GetHistogram().GetSampleCount())
		})
	}
}

// TestMetrics_RecordRequest_Multiple tests multiple RecordRequest calls.
func TestMetrics_RecordRequest_Multiple(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := NewMetrics("test")

	// Act - record multiple requests
	for i := 0; i < 5; i++ {
		metrics.RecordRequest("opa", "allowed", 10*time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		metrics.RecordRequest("opa", "denied", 5*time.Millisecond)
	}

	// Assert
	allowedCounter, err := metrics.requestTotal.GetMetricWithLabelValues("opa", "allowed")
	require.NoError(t, err)

	var m io_prometheus_client.Metric
	err = allowedCounter.Write(&m)
	require.NoError(t, err)
	assert.Equal(t, float64(5), m.GetCounter().GetValue())

	deniedCounter, err := metrics.requestTotal.GetMetricWithLabelValues("opa", "denied")
	require.NoError(t, err)

	err = deniedCounter.Write(&m)
	require.NoError(t, err)
	assert.Equal(t, float64(3), m.GetCounter().GetValue())
}

// TestMetrics_RecordCacheHit tests that RecordCacheHit properly records cache hits.
func TestMetrics_RecordCacheHit(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := NewMetrics("test")

	// Act
	metrics.RecordCacheHit()
	metrics.RecordCacheHit()
	metrics.RecordCacheHit()

	// Assert
	var m io_prometheus_client.Metric
	err := metrics.cacheHits.Write(&m)
	require.NoError(t, err)
	assert.Equal(t, float64(3), m.GetCounter().GetValue())
}

// TestMetrics_RecordCacheMiss tests that RecordCacheMiss properly records cache misses.
func TestMetrics_RecordCacheMiss(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := NewMetrics("test")

	// Act
	metrics.RecordCacheMiss()
	metrics.RecordCacheMiss()

	// Assert
	var m io_prometheus_client.Metric
	err := metrics.cacheMisses.Write(&m)
	require.NoError(t, err)
	assert.Equal(t, float64(2), m.GetCounter().GetValue())
}

// TestMetrics_RecordError tests that RecordError properly records errors.
func TestMetrics_RecordError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		authzType string
		reason    string
	}{
		{
			name:      "OPANetworkError",
			authzType: "opa",
			reason:    "network_error",
		},
		{
			name:      "OPATimeout",
			authzType: "opa",
			reason:    "timeout",
		},
		{
			name:      "GRPCConnectionError",
			authzType: "grpc",
			reason:    "connection_error",
		},
		{
			name:      "HTTPInvalidResponse",
			authzType: "http",
			reason:    "invalid_response",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			metrics := NewMetrics("test")

			// Act
			metrics.RecordError(tc.authzType, tc.reason)

			// Assert
			counter, err := metrics.errors.GetMetricWithLabelValues(tc.authzType, tc.reason)
			require.NoError(t, err)

			var m io_prometheus_client.Metric
			err = counter.Write(&m)
			require.NoError(t, err)
			assert.Equal(t, float64(1), m.GetCounter().GetValue())
		})
	}
}

// TestMetrics_RecordError_Multiple tests multiple RecordError calls.
func TestMetrics_RecordError_Multiple(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := NewMetrics("test")

	// Act
	for i := 0; i < 4; i++ {
		metrics.RecordError("opa", "timeout")
	}
	for i := 0; i < 2; i++ {
		metrics.RecordError("opa", "network_error")
	}

	// Assert
	timeoutCounter, err := metrics.errors.GetMetricWithLabelValues("opa", "timeout")
	require.NoError(t, err)

	var m io_prometheus_client.Metric
	err = timeoutCounter.Write(&m)
	require.NoError(t, err)
	assert.Equal(t, float64(4), m.GetCounter().GetValue())

	networkCounter, err := metrics.errors.GetMetricWithLabelValues("opa", "network_error")
	require.NoError(t, err)

	err = networkCounter.Write(&m)
	require.NoError(t, err)
	assert.Equal(t, float64(2), m.GetCounter().GetValue())
}

// TestMetrics_Registry tests that Registry returns the internal registry.
func TestMetrics_Registry(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := NewMetrics("test")

	// Record some metrics to ensure they appear in Gather()
	metrics.RecordRequest("opa", "allowed", time.Millisecond)
	metrics.RecordCacheHit()
	metrics.RecordCacheMiss()
	metrics.RecordError("opa", "timeout")

	// Act
	registry := metrics.Registry()

	// Assert
	require.NotNil(t, registry)
	assert.IsType(t, &prometheus.Registry{}, registry)

	// Verify metrics are registered
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metricFamilies)

	// Check that expected metrics are present
	metricNames := make(map[string]bool)
	for _, mf := range metricFamilies {
		metricNames[mf.GetName()] = true
	}

	assert.True(t, metricNames["test_external_authz_request_total"])
	assert.True(t, metricNames["test_external_authz_request_duration_seconds"])
	assert.True(t, metricNames["test_external_authz_cache_hits_total"])
	assert.True(t, metricNames["test_external_authz_cache_misses_total"])
	assert.True(t, metricNames["test_external_authz_errors_total"])
}

// TestMetrics_MustRegister tests that MustRegister registers metrics with external registry.
func TestMetrics_MustRegister(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := NewMetrics("custom")
	externalRegistry := prometheus.NewRegistry()

	// Act
	metrics.MustRegister(externalRegistry)

	// Record some metrics to ensure they appear in Gather()
	metrics.RecordRequest("opa", "allowed", time.Millisecond)
	metrics.RecordCacheHit()
	metrics.RecordCacheMiss()
	metrics.RecordError("opa", "timeout")

	// Assert - verify metrics are registered in external registry
	metricFamilies, err := externalRegistry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metricFamilies)

	// Check that expected metrics are present
	metricNames := make(map[string]bool)
	for _, mf := range metricFamilies {
		metricNames[mf.GetName()] = true
	}

	assert.True(t, metricNames["custom_external_authz_request_total"])
	assert.True(t, metricNames["custom_external_authz_request_duration_seconds"])
	assert.True(t, metricNames["custom_external_authz_cache_hits_total"])
	assert.True(t, metricNames["custom_external_authz_cache_misses_total"])
	assert.True(t, metricNames["custom_external_authz_errors_total"])
}

// TestMetrics_ConcurrentAccess tests that metrics are safe for concurrent access.
func TestMetrics_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := NewMetrics("test")
	done := make(chan bool)

	// Act - concurrent access from multiple goroutines
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				metrics.RecordRequest("opa", "allowed", time.Millisecond)
				metrics.RecordCacheHit()
				metrics.RecordCacheMiss()
				metrics.RecordError("opa", "timeout")
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Assert - verify total counts
	var m io_prometheus_client.Metric

	counter, _ := metrics.requestTotal.GetMetricWithLabelValues("opa", "allowed")
	_ = counter.Write(&m)
	assert.Equal(t, float64(1000), m.GetCounter().GetValue())

	_ = metrics.cacheHits.Write(&m)
	assert.Equal(t, float64(1000), m.GetCounter().GetValue())

	_ = metrics.cacheMisses.Write(&m)
	assert.Equal(t, float64(1000), m.GetCounter().GetValue())

	errorCounter, _ := metrics.errors.GetMetricWithLabelValues("opa", "timeout")
	_ = errorCounter.Write(&m)
	assert.Equal(t, float64(1000), m.GetCounter().GetValue())
}

// TestMetrics_DurationBuckets tests that histogram buckets are properly configured.
func TestMetrics_DurationBuckets(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := NewMetrics("test")

	// Record requests with various durations
	durations := []time.Duration{
		500 * time.Microsecond, // 0.0005s - bucket .001
		2 * time.Millisecond,   // 0.002s - bucket .005
		8 * time.Millisecond,   // 0.008s - bucket .01
		20 * time.Millisecond,  // 0.02s - bucket .025
		40 * time.Millisecond,  // 0.04s - bucket .05
		80 * time.Millisecond,  // 0.08s - bucket .1
		200 * time.Millisecond, // 0.2s - bucket .25
		400 * time.Millisecond, // 0.4s - bucket .5
		800 * time.Millisecond, // 0.8s - bucket 1
		2 * time.Second,        // 2s - bucket 2.5
		4 * time.Second,        // 4s - bucket 5
	}

	// Act
	for _, d := range durations {
		metrics.RecordRequest("opa", "allowed", d)
	}

	// Assert
	histogram, err := metrics.requestDuration.GetMetricWithLabelValues("opa", "allowed")
	require.NoError(t, err)

	var m io_prometheus_client.Metric
	err = histogram.(prometheus.Metric).Write(&m)
	require.NoError(t, err)

	assert.Equal(t, uint64(len(durations)), m.GetHistogram().GetSampleCount())
}

// TestMetrics_Labels tests that metrics have correct labels.
func TestMetrics_Labels(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := NewMetrics("test")

	// Act - record with different label combinations
	metrics.RecordRequest("opa", "allowed", time.Millisecond)
	metrics.RecordRequest("opa", "denied", time.Millisecond)
	metrics.RecordRequest("grpc", "allowed", time.Millisecond)
	metrics.RecordRequest("http", "error", time.Millisecond)

	metrics.RecordError("opa", "timeout")
	metrics.RecordError("grpc", "connection_refused")
	metrics.RecordError("http", "invalid_response")

	// Assert - gather all metrics and verify labels
	metricFamilies, err := metrics.Registry().Gather()
	require.NoError(t, err)

	for _, mf := range metricFamilies {
		switch mf.GetName() {
		case "test_external_authz_request_total":
			assert.Len(t, mf.GetMetric(), 4) // 4 unique label combinations
		case "test_external_authz_errors_total":
			assert.Len(t, mf.GetMetric(), 3) // 3 unique label combinations
		}
	}
}

// TestMetrics_ZeroDuration tests recording with zero duration.
func TestMetrics_ZeroDuration(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := NewMetrics("test")

	// Act
	metrics.RecordRequest("opa", "allowed", 0)

	// Assert
	histogram, err := metrics.requestDuration.GetMetricWithLabelValues("opa", "allowed")
	require.NoError(t, err)

	var m io_prometheus_client.Metric
	err = histogram.(prometheus.Metric).Write(&m)
	require.NoError(t, err)

	assert.Equal(t, uint64(1), m.GetHistogram().GetSampleCount())
	assert.Equal(t, float64(0), m.GetHistogram().GetSampleSum())
}

// TestMetrics_EmptyLabels tests recording with empty label values.
func TestMetrics_EmptyLabels(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := NewMetrics("test")

	// Act - empty labels should still work
	metrics.RecordRequest("", "", time.Millisecond)
	metrics.RecordError("", "")

	// Assert - verify metrics were recorded
	counter, err := metrics.requestTotal.GetMetricWithLabelValues("", "")
	require.NoError(t, err)

	var m io_prometheus_client.Metric
	err = counter.Write(&m)
	require.NoError(t, err)
	assert.Equal(t, float64(1), m.GetCounter().GetValue())

	errorCounter, err := metrics.errors.GetMetricWithLabelValues("", "")
	require.NoError(t, err)

	err = errorCounter.Write(&m)
	require.NoError(t, err)
	assert.Equal(t, float64(1), m.GetCounter().GetValue())
}

func TestGetSharedMetrics_Singleton(t *testing.T) {
	m1 := GetSharedMetrics()
	m2 := GetSharedMetrics()

	assert.NotNil(t, m1)
	assert.Same(t, m1, m2, "GetSharedMetrics should return same instance")
}

func TestMetrics_Init(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_init")

	// Init should not panic
	assert.NotPanics(t, func() {
		metrics.Init()
	})

	// Verify metrics are pre-populated by gathering from registry
	mfs, err := metrics.Registry().Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)

	// Init should be idempotent
	assert.NotPanics(t, func() {
		metrics.Init()
	})
}

func TestMetrics_MustRegister_Duplicate(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_dup_register")
	reg := prometheus.NewRegistry()

	// First registration should not panic
	assert.NotPanics(t, func() {
		metrics.MustRegister(reg)
	})

	// Second registration should not panic (AlreadyRegisteredError is silently ignored)
	assert.NotPanics(t, func() {
		metrics.MustRegister(reg)
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
