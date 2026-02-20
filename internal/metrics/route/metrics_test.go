package route

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testMetrics is a package-level instance created once to avoid
// duplicate promauto registration panics. We use GetRouteMetrics()
// so the singleton is initialized first, and all tests share it.
var (
	testMetrics     *RouteMetrics
	testMetricsOnce sync.Once
	testReg         *prometheus.Registry
)

func getTestMetrics() (*RouteMetrics, *prometheus.Registry) {
	testMetricsOnce.Do(func() {
		// Use the singleton so that GetRouteMetrics() tests work.
		testMetrics = GetRouteMetrics()
		testReg = prometheus.NewRegistry()
		testMetrics.MustRegister(testReg)
	})
	return testMetrics, testReg
}

// gatherAndFind gathers metrics from the registry and checks that
// the named metric family exists and has at least one metric.
func gatherAndFind(t *testing.T, reg *prometheus.Registry, name string) {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == name {
			found = true
			assert.NotEmpty(t, mf.GetMetric(),
				"%s should have at least one metric", name)
			break
		}
	}
	assert.True(t, found, "%s should be present in gathered metrics", name)
}

// --- Constructor & Singleton ---

func TestNewRouteMetrics(t *testing.T) {
	m, _ := getTestMetrics()
	require.NotNil(t, m)

	assert.NotNil(t, m.RequestsTotal)
	assert.NotNil(t, m.RequestSizeBytes)
	assert.NotNil(t, m.ResponseSizeBytes)
	assert.NotNil(t, m.RequestDurationSeconds)
	assert.NotNil(t, m.UpstreamDurationSeconds)
	assert.NotNil(t, m.ErrorsTotal)
	assert.NotNil(t, m.TimeoutsTotal)
	assert.NotNil(t, m.RateLimitHitsTotal)
	assert.NotNil(t, m.AuthFailuresTotal)
	assert.NotNil(t, m.AuthSuccessesTotal)
	assert.NotNil(t, m.CircuitBreakerState)
	assert.NotNil(t, m.CircuitBreakerTripsTotal)
	assert.NotNil(t, m.CacheHitsTotal)
	assert.NotNil(t, m.CacheMissesTotal)
	assert.NotNil(t, m.CacheBypassTotal)
	assert.NotNil(t, m.RetriesTotal)
	assert.NotNil(t, m.RetryExhaustedTotal)
	assert.NotNil(t, m.CertExpirySeconds)
}

func TestGetRouteMetrics_Singleton(t *testing.T) {
	m1 := GetRouteMetrics()
	m2 := GetRouteMetrics()

	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "should return same instance")
}

// --- Registration ---

func TestRouteMetrics_MustRegister(t *testing.T) {
	m, reg := getTestMetrics()

	// Trigger a metric so Gather returns something.
	m.RequestsTotal.WithLabelValues("reg-test", "GET", "200").Inc()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs, "registry should contain metrics after registration")
}

func TestRouteMetrics_MustRegister_Duplicate(t *testing.T) {
	m, reg := getTestMetrics()

	// Second registration of the same collectors should not panic
	// because AlreadyRegisteredError is silently ignored.
	assert.NotPanics(t, func() {
		m.MustRegister(reg)
	})
}

// --- Init ---

func TestRouteMetrics_Init(t *testing.T) {
	m, reg := getTestMetrics()

	// Init should not panic.
	assert.NotPanics(t, func() {
		m.Init()
	})

	// After Init, many metric families should be pre-populated.
	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs, "Init should pre-populate metrics")

	// Verify a few key metric families exist.
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	assert.True(t, names["gateway_route_requests_total"])
	assert.True(t, names["gateway_route_request_size_bytes"])
	assert.True(t, names["gateway_route_errors_total"])
	assert.True(t, names["gateway_route_circuit_breaker_state"])
	assert.True(t, names["gateway_route_cert_expiry_seconds"])
}

// --- Record helpers ---

func TestRouteMetrics_RecordRequest(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.RequestsTotal.WithLabelValues("record-req", "GET", "200"),
	)

	m.RecordRequest("record-req", "GET", 200, 100*time.Millisecond, 1024, 2048)

	gatherAndFind(t, reg, "gateway_route_requests_total")
	gatherAndFind(t, reg, "gateway_route_request_size_bytes")
	gatherAndFind(t, reg, "gateway_route_response_size_bytes")
	gatherAndFind(t, reg, "gateway_route_request_duration_seconds")

	after := testutil.ToFloat64(
		m.RequestsTotal.WithLabelValues("record-req", "GET", "200"),
	)
	assert.Equal(t, before+1, after)
}

func TestRouteMetrics_RecordUpstreamDuration(t *testing.T) {
	m, reg := getTestMetrics()

	m.RecordUpstreamDuration("upstream-test", "POST", 201, 50*time.Millisecond)

	gatherAndFind(t, reg, "gateway_route_upstream_duration_seconds")
}

func TestRouteMetrics_RecordError(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.ErrorsTotal.WithLabelValues("error-test", "GET", "proxy_error"),
	)

	m.RecordError("error-test", "GET", "proxy_error")

	gatherAndFind(t, reg, "gateway_route_errors_total")

	after := testutil.ToFloat64(
		m.ErrorsTotal.WithLabelValues("error-test", "GET", "proxy_error"),
	)
	assert.Equal(t, before+1, after)
}

func TestRouteMetrics_RecordTimeout(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.TimeoutsTotal.WithLabelValues("timeout-test", "GET", "upstream"),
	)

	m.RecordTimeout("timeout-test", "GET", "upstream")

	gatherAndFind(t, reg, "gateway_route_timeouts_total")

	after := testutil.ToFloat64(
		m.TimeoutsTotal.WithLabelValues("timeout-test", "GET", "upstream"),
	)
	assert.Equal(t, before+1, after)
}

func TestRouteMetrics_RecordRateLimitHit(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.RateLimitHitsTotal.WithLabelValues("rl-test", "GET", "consumer-1"),
	)

	m.RecordRateLimitHit("rl-test", "GET", "consumer-1")

	gatherAndFind(t, reg, "gateway_route_ratelimit_hits_total")

	after := testutil.ToFloat64(
		m.RateLimitHitsTotal.WithLabelValues("rl-test", "GET", "consumer-1"),
	)
	assert.Equal(t, before+1, after)
}

func TestRouteMetrics_RecordAuthFailure(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.AuthFailuresTotal.WithLabelValues("auth-fail-test", "POST", "jwt", "expired"),
	)

	m.RecordAuthFailure("auth-fail-test", "POST", "jwt", "expired")

	gatherAndFind(t, reg, "gateway_route_auth_failures_total")

	after := testutil.ToFloat64(
		m.AuthFailuresTotal.WithLabelValues("auth-fail-test", "POST", "jwt", "expired"),
	)
	assert.Equal(t, before+1, after)
}

func TestRouteMetrics_RecordAuthSuccess(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.AuthSuccessesTotal.WithLabelValues("auth-ok-test", "GET", "apikey"),
	)

	m.RecordAuthSuccess("auth-ok-test", "GET", "apikey")

	gatherAndFind(t, reg, "gateway_route_auth_successes_total")

	after := testutil.ToFloat64(
		m.AuthSuccessesTotal.WithLabelValues("auth-ok-test", "GET", "apikey"),
	)
	assert.Equal(t, before+1, after)
}

func TestRouteMetrics_RecordCacheHit(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.CacheHitsTotal.WithLabelValues("cache-hit-test", "GET"),
	)

	m.RecordCacheHit("cache-hit-test", "GET")

	gatherAndFind(t, reg, "gateway_route_cache_hits_total")

	after := testutil.ToFloat64(
		m.CacheHitsTotal.WithLabelValues("cache-hit-test", "GET"),
	)
	assert.Equal(t, before+1, after)
}

func TestRouteMetrics_RecordCacheMiss(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.CacheMissesTotal.WithLabelValues("cache-miss-test", "GET"),
	)

	m.RecordCacheMiss("cache-miss-test", "GET")

	gatherAndFind(t, reg, "gateway_route_cache_misses_total")

	after := testutil.ToFloat64(
		m.CacheMissesTotal.WithLabelValues("cache-miss-test", "GET"),
	)
	assert.Equal(t, before+1, after)
}

func TestRouteMetrics_RecordCacheBypass(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.CacheBypassTotal.WithLabelValues("cache-bypass-test", "GET", "no_cache_header"),
	)

	m.RecordCacheBypass("cache-bypass-test", "GET", "no_cache_header")

	gatherAndFind(t, reg, "gateway_route_cache_bypass_total")

	after := testutil.ToFloat64(
		m.CacheBypassTotal.WithLabelValues("cache-bypass-test", "GET", "no_cache_header"),
	)
	assert.Equal(t, before+1, after)
}

func TestRouteMetrics_RecordRetry(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.RetriesTotal.WithLabelValues("retry-test", "GET"),
	)

	m.RecordRetry("retry-test", "GET")

	gatherAndFind(t, reg, "gateway_route_retries_total")

	after := testutil.ToFloat64(
		m.RetriesTotal.WithLabelValues("retry-test", "GET"),
	)
	assert.Equal(t, before+1, after)
}

func TestRouteMetrics_RecordRetryExhausted(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.RetryExhaustedTotal.WithLabelValues("retry-exhaust-test", "GET"),
	)

	m.RecordRetryExhausted("retry-exhaust-test", "GET")

	gatherAndFind(t, reg, "gateway_route_retry_exhausted_total")

	after := testutil.ToFloat64(
		m.RetryExhaustedTotal.WithLabelValues("retry-exhaust-test", "GET"),
	)
	assert.Equal(t, before+1, after)
}

// --- isAlreadyRegistered ---

func TestIsAlreadyRegistered(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name: "AlreadyRegisteredError",
			err: prometheus.AlreadyRegisteredError{
				ExistingCollector: nil,
				NewCollector:      nil,
			},
			expected: true,
		},
		{
			name:     "other error",
			err:      assert.AnError,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isAlreadyRegistered(tt.err))
		})
	}
}

// --- Concurrent access ---

func TestRouteMetrics_ConcurrentAccess(t *testing.T) {
	m, _ := getTestMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.RecordRequest("concurrent", "GET", 200, time.Millisecond, 100, 200)
				m.RecordUpstreamDuration("concurrent", "GET", 200, time.Millisecond)
				m.RecordError("concurrent", "GET", "timeout")
				m.RecordTimeout("concurrent", "GET", "upstream")
				m.RecordRateLimitHit("concurrent", "GET", "c")
				m.RecordAuthFailure("concurrent", "GET", "jwt", "expired")
				m.RecordAuthSuccess("concurrent", "GET", "jwt")
				m.RecordCacheHit("concurrent", "GET")
				m.RecordCacheMiss("concurrent", "GET")
				m.RecordCacheBypass("concurrent", "GET", "no_cache_header")
				m.RecordRetry("concurrent", "GET")
				m.RecordRetryExhausted("concurrent", "GET")
			}
		}()
	}

	wg.Wait()
}

// --- collectors ---

func TestRouteMetrics_Collectors(t *testing.T) {
	m, _ := getTestMetrics()
	collectors := m.collectors()

	// 18 metric fields.
	assert.Len(t, collectors, 18, "should return 18 collectors")

	for i, c := range collectors {
		assert.NotNil(t, c, "collector %d should not be nil", i)
	}
}

// --- Table-driven RecordRequest ---

func TestRouteMetrics_RecordRequest_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		route      string
		method     string
		statusCode int
		duration   time.Duration
		reqSize    int64
		respSize   int64
	}{
		{
			name:       "GET 200",
			route:      "td-api-v1",
			method:     "GET",
			statusCode: 200,
			duration:   50 * time.Millisecond,
			reqSize:    512,
			respSize:   1024,
		},
		{
			name:       "POST 201",
			route:      "td-api-v2",
			method:     "POST",
			statusCode: 201,
			duration:   100 * time.Millisecond,
			reqSize:    2048,
			respSize:   4096,
		},
		{
			name:       "DELETE 204",
			route:      "td-api-v1",
			method:     "DELETE",
			statusCode: 204,
			duration:   10 * time.Millisecond,
			reqSize:    0,
			respSize:   0,
		},
		{
			name:       "GET 500",
			route:      "td-api-v1",
			method:     "GET",
			statusCode: 500,
			duration:   200 * time.Millisecond,
			reqSize:    256,
			respSize:   128,
		},
	}

	m, reg := getTestMetrics()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.RecordRequest(tt.route, tt.method, tt.statusCode,
				tt.duration, tt.reqSize, tt.respSize)

			gatherAndFind(t, reg, "gateway_route_requests_total")
		})
	}
}
