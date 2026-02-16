package vault

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestMetrics creates a Metrics instance with a fresh registry for testing,
// avoiding duplicate registration panics on the global default registry.
func newTestMetrics(namespace string) *Metrics {
	return NewMetrics(namespace, WithMetricsRegistry(prometheus.NewRegistry()))
}

func TestNewMetrics(t *testing.T) {
	tests := []struct {
		name              string
		namespace         string
		expectedNamespace string
	}{
		{
			name:              "default namespace when empty",
			namespace:         "",
			expectedNamespace: "gateway",
		},
		{
			name:              "custom namespace",
			namespace:         "custom",
			expectedNamespace: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestMetrics(tt.namespace)
			if m == nil {
				t.Fatal("NewMetrics() returned nil")
			}
			if m.requestsTotal == nil {
				t.Error("requestsTotal should not be nil")
			}
			if m.requestDuration == nil {
				t.Error("requestDuration should not be nil")
			}
			if m.tokenTTL == nil {
				t.Error("tokenTTL should not be nil")
			}
			if m.cacheHits == nil {
				t.Error("cacheHits should not be nil")
			}
			if m.cacheMisses == nil {
				t.Error("cacheMisses should not be nil")
			}
			if m.authAttempts == nil {
				t.Error("authAttempts should not be nil")
			}
			if m.errors == nil {
				t.Error("errors should not be nil")
			}
		})
	}
}

func TestNewMetrics_DefaultUsesPromauto(t *testing.T) {
	// Verify that NewMetrics without a custom registry does not set the registry field,
	// confirming it uses promauto with the default global registerer.
	m := NewMetrics("test_default_promauto")
	require.NotNil(t, m, "NewMetrics() should not return nil")
	assert.Nil(t, m.registry, "registry should be nil when using default global registerer via promauto")
}

func TestNewMetrics_WithRegistry(t *testing.T) {
	customRegistry := prometheus.NewRegistry()
	m := NewMetrics("test", WithMetricsRegistry(customRegistry))

	if m.registry != customRegistry {
		t.Error("registry should be the custom registry")
	}
}

func TestMetrics_RecordRequest(t *testing.T) {
	m := newTestMetrics("test_record_req")

	m.RecordRequest("read", "success", 100*time.Millisecond)
	m.RecordRequest("write", "error", 200*time.Millisecond)
	m.RecordRequest("authenticate", "success", 50*time.Millisecond)

	// Verify counter values
	readSuccess := testutil.ToFloat64(m.requestsTotal.WithLabelValues("read", "success"))
	assert.Equal(t, float64(1), readSuccess, "read/success counter should be 1")

	writeError := testutil.ToFloat64(m.requestsTotal.WithLabelValues("write", "error"))
	assert.Equal(t, float64(1), writeError, "write/error counter should be 1")

	authSuccess := testutil.ToFloat64(m.requestsTotal.WithLabelValues("authenticate", "success"))
	assert.Equal(t, float64(1), authSuccess, "authenticate/success counter should be 1")

	// Verify histogram has observations
	histCount := testutil.CollectAndCount(m.requestDuration)
	assert.Greater(t, histCount, 0, "requestDuration should have observations")
}

func TestMetrics_SetTokenTTL(t *testing.T) {
	m := newTestMetrics("test_ttl")

	m.SetTokenTTL(3600)
	val := testutil.ToFloat64(m.tokenTTL)
	assert.Equal(t, float64(3600), val, "tokenTTL should be 3600")

	m.SetTokenTTL(0)
	val = testutil.ToFloat64(m.tokenTTL)
	assert.Equal(t, float64(0), val, "tokenTTL should be 0")

	m.SetTokenTTL(-1)
	val = testutil.ToFloat64(m.tokenTTL)
	assert.Equal(t, float64(-1), val, "tokenTTL should be -1")
}

func TestMetrics_RecordCacheHit(t *testing.T) {
	m := newTestMetrics("test_cache_hit")

	m.RecordCacheHit()
	m.RecordCacheHit()

	val := testutil.ToFloat64(m.cacheHits)
	assert.Equal(t, float64(2), val, "cacheHits should be 2 after two calls")
}

func TestMetrics_RecordCacheMiss(t *testing.T) {
	m := newTestMetrics("test_cache_miss")

	m.RecordCacheMiss()
	m.RecordCacheMiss()

	val := testutil.ToFloat64(m.cacheMisses)
	assert.Equal(t, float64(2), val, "cacheMisses should be 2 after two calls")
}

func TestMetrics_RecordAuthAttempt(t *testing.T) {
	m := newTestMetrics("test_auth_attempt")

	m.RecordAuthAttempt("token", "success")
	m.RecordAuthAttempt("kubernetes", "error")
	m.RecordAuthAttempt("approle", "success")

	tokenSuccess := testutil.ToFloat64(m.authAttempts.WithLabelValues("token", "success"))
	assert.Equal(t, float64(1), tokenSuccess, "token/success should be 1")

	k8sError := testutil.ToFloat64(m.authAttempts.WithLabelValues("kubernetes", "error"))
	assert.Equal(t, float64(1), k8sError, "kubernetes/error should be 1")

	approleSuccess := testutil.ToFloat64(m.authAttempts.WithLabelValues("approle", "success"))
	assert.Equal(t, float64(1), approleSuccess, "approle/success should be 1")
}

func TestMetrics_RecordError(t *testing.T) {
	m := newTestMetrics("test_record_error")

	m.RecordError("authentication")
	m.RecordError("connection")
	m.RecordError("timeout")

	authErr := testutil.ToFloat64(m.errors.WithLabelValues("authentication"))
	assert.Equal(t, float64(1), authErr, "authentication error should be 1")

	connErr := testutil.ToFloat64(m.errors.WithLabelValues("connection"))
	assert.Equal(t, float64(1), connErr, "connection error should be 1")

	timeoutErr := testutil.ToFloat64(m.errors.WithLabelValues("timeout"))
	assert.Equal(t, float64(1), timeoutErr, "timeout error should be 1")
}

func TestMetrics_Registry(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics("test", WithMetricsRegistry(reg))

	registry := m.Registry()
	assert.Equal(t, reg, registry, "Registry() should return the custom registry")
}

func TestMetrics_Registry_DefaultIsNil(t *testing.T) {
	m := NewMetrics("test_registry_nil")

	registry := m.Registry()
	assert.Nil(t, registry, "Registry() should return nil when using default global registerer")
}

func TestMetrics_Describe(t *testing.T) {
	m := newTestMetrics("test_describe")

	ch := make(chan *prometheus.Desc, 100)
	m.Describe(ch)
	close(ch)

	descs := make([]*prometheus.Desc, 0)
	for d := range ch {
		descs = append(descs, d)
	}

	// We expect exactly 7 metric descriptors:
	// requestsTotal, requestDuration, tokenTTL, cacheHits, cacheMisses, authAttempts, errors
	assert.Equal(t, 7, len(descs), "Describe() should send exactly 7 metric descriptions")

	// Verify each descriptor is non-nil
	for i, d := range descs {
		assert.NotNil(t, d, "descriptor %d should not be nil", i)
	}
}

func TestMetrics_Collect(t *testing.T) {
	m := newTestMetrics("test_collect")

	// Record some metrics first
	m.RecordRequest("read", "success", 100*time.Millisecond)
	m.RecordCacheHit()
	m.SetTokenTTL(3600)
	m.RecordCacheMiss()
	m.RecordAuthAttempt("token", "success")
	m.RecordError("connection")

	ch := make(chan prometheus.Metric, 100)
	m.Collect(ch)
	close(ch)

	metrics := make([]prometheus.Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}

	// We expect at least 7 metrics:
	// 1 requestsTotal (read/success), 1 requestDuration (read), 1 tokenTTL,
	// 1 cacheHits, 1 cacheMisses, 1 authAttempts (token/success), 1 errors (connection)
	assert.GreaterOrEqual(t, len(metrics), 7,
		"Collect() should send at least 7 metrics after recording all types")

	// Verify each metric is non-nil
	for i, metric := range metrics {
		assert.NotNil(t, metric, "metric %d should not be nil", i)
	}
}

func TestNopMetrics(t *testing.T) {
	m := NewNopMetrics()

	require.NotNil(t, m, "NewNopMetrics() should not return nil")

	// All methods should be no-ops and not panic
	m.RecordRequest("read", "success", 100*time.Millisecond)
	m.SetTokenTTL(3600)
	m.RecordCacheHit()
	m.RecordCacheMiss()
	m.RecordAuthAttempt("token", "success")
	m.RecordError("test")

	// Verify NopMetrics satisfies the interface
	var recorder MetricsRecorder = m
	assert.NotNil(t, recorder, "NopMetrics should satisfy MetricsRecorder interface")
}

func TestMetricsRecorder_Interface(t *testing.T) {
	// Verify both implementations satisfy the interface
	var _ MetricsRecorder = (*Metrics)(nil)
	var _ MetricsRecorder = (*NopMetrics)(nil)
}

func TestWithMetricsRegistry(t *testing.T) {
	registry := prometheus.NewRegistry()
	opt := WithMetricsRegistry(registry)

	m := &Metrics{}
	opt(m)

	if m.registry != registry {
		t.Error("WithMetricsRegistry should set the registry")
	}
}

func TestMetrics_ConcurrentAccess(t *testing.T) {
	m := newTestMetrics("test_concurrent")

	var wg sync.WaitGroup
	wg.Add(5)

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			m.RecordRequest("read", "success", time.Duration(i)*time.Millisecond)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			m.RecordCacheHit()
			m.RecordCacheMiss()
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			m.SetTokenTTL(float64(i))
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			m.RecordAuthAttempt("token", "success")
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			m.RecordError("test")
		}
	}()

	wg.Wait()

	// Verify all goroutines completed their work
	readSuccess := testutil.ToFloat64(m.requestsTotal.WithLabelValues("read", "success"))
	assert.Equal(t, float64(100), readSuccess, "read/success counter should be 100 after concurrent writes")

	cacheHits := testutil.ToFloat64(m.cacheHits)
	assert.Equal(t, float64(100), cacheHits, "cacheHits should be 100 after concurrent writes")

	cacheMisses := testutil.ToFloat64(m.cacheMisses)
	assert.Equal(t, float64(100), cacheMisses, "cacheMisses should be 100 after concurrent writes")

	authAttempts := testutil.ToFloat64(m.authAttempts.WithLabelValues("token", "success"))
	assert.Equal(t, float64(100), authAttempts, "auth attempts should be 100 after concurrent writes")

	errors := testutil.ToFloat64(m.errors.WithLabelValues("test"))
	assert.Equal(t, float64(100), errors, "errors should be 100 after concurrent writes")
}

func TestMetrics_RegistryScrapeOutput(t *testing.T) {
	// Arrange: create metrics with a custom registry and record some data
	reg := prometheus.NewRegistry()
	m := NewMetrics("scrape_test", WithMetricsRegistry(reg))

	m.RecordRequest("read", "success", 100*time.Millisecond)
	m.RecordRequest("write", "error", 200*time.Millisecond)
	m.SetTokenTTL(3600)
	m.RecordCacheHit()
	m.RecordCacheMiss()
	m.RecordAuthAttempt("kubernetes", "success")
	m.RecordError("timeout")

	// Act: gather metrics from the registry (simulates a Prometheus scrape)
	families, err := reg.Gather()
	require.NoError(t, err, "Gather() should not return error")

	// Assert: verify expected metric families are present
	familyNames := make(map[string]bool)
	for _, f := range families {
		familyNames[f.GetName()] = true
	}

	expectedMetrics := []string{
		"scrape_test_vault_requests_total",
		"scrape_test_vault_request_duration_seconds",
		"scrape_test_vault_token_ttl_seconds",
		"scrape_test_vault_cache_hits_total",
		"scrape_test_vault_cache_misses_total",
		"scrape_test_vault_auth_attempts_total",
		"scrape_test_vault_errors_total",
	}

	for _, name := range expectedMetrics {
		assert.True(t, familyNames[name], "metric family %q should be present in scrape output", name)
	}

	// Verify the total number of metric families matches expectations
	assert.Equal(t, len(expectedMetrics), len(families),
		"should have exactly %d metric families", len(expectedMetrics))
}

func TestMetrics_PromautoRegistration(t *testing.T) {
	// Verify that metrics created with a custom registry can be gathered
	// and contain the expected metric names in their string representation
	reg := prometheus.NewRegistry()
	m := NewMetrics("promauto_test", WithMetricsRegistry(reg))

	m.RecordRequest("test_op", "success", 50*time.Millisecond)

	// Use testutil to verify the metric content
	expected := `
		# HELP promauto_test_vault_requests_total Total number of Vault requests by operation and status
		# TYPE promauto_test_vault_requests_total counter
		promauto_test_vault_requests_total{operation="test_op",status="success"} 1
	`
	err := testutil.CollectAndCompare(m.requestsTotal, strings.NewReader(expected))
	assert.NoError(t, err, "requestsTotal metric should match expected output")
}

func TestMetrics_AllOperations(t *testing.T) {
	m := newTestMetrics("test_all_ops")

	operations := []string{"read", "write", "delete", "list", "authenticate", "renew_token", "health"}
	statuses := []string{"success", "error"}

	for _, op := range operations {
		for _, status := range statuses {
			m.RecordRequest(op, status, 100*time.Millisecond)
		}
	}

	// Verify each operation/status combination was recorded
	for _, op := range operations {
		for _, status := range statuses {
			val := testutil.ToFloat64(m.requestsTotal.WithLabelValues(op, status))
			assert.Equal(t, float64(1), val, "%s/%s counter should be 1", op, status)
		}
	}

	// Verify histogram has observations for each operation
	histCount := testutil.CollectAndCount(m.requestDuration)
	assert.Equal(t, len(operations), histCount,
		"requestDuration should have entries for each operation")
}

func TestMetrics_AuthMethods(t *testing.T) {
	m := newTestMetrics("test_auth_methods")

	methods := []string{"token", "kubernetes", "approle"}
	statuses := []string{"success", "error"}

	for _, method := range methods {
		for _, status := range statuses {
			m.RecordAuthAttempt(method, status)
		}
	}

	// Verify each method/status combination was recorded
	for _, method := range methods {
		for _, status := range statuses {
			val := testutil.ToFloat64(m.authAttempts.WithLabelValues(method, status))
			assert.Equal(t, float64(1), val, "%s/%s auth attempt should be 1", method, status)
		}
	}
}

func TestMetrics_ErrorTypes(t *testing.T) {
	m := newTestMetrics("test_error_types")

	errorTypes := []string{
		"authentication",
		"authorization",
		"connection",
		"timeout",
		"configuration",
		"secret_not_found",
	}

	for _, errType := range errorTypes {
		m.RecordError(errType)
	}

	// Verify each error type was recorded
	for _, errType := range errorTypes {
		val := testutil.ToFloat64(m.errors.WithLabelValues(errType))
		assert.Equal(t, float64(1), val, "%s error should be 1", errType)
	}
}
