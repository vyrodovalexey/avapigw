package backend

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
// duplicate promauto registration panics. We use GetBackendMetrics()
// so the singleton is initialized first, and all tests share it.
var (
	testMetrics     *BackendMetrics
	testMetricsOnce sync.Once
	testReg         *prometheus.Registry
)

func getTestMetrics() (*BackendMetrics, *prometheus.Registry) {
	testMetricsOnce.Do(func() {
		testMetrics = GetBackendMetrics()
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

func TestNewBackendMetrics(t *testing.T) {
	m, _ := getTestMetrics()
	require.NotNil(t, m)

	assert.NotNil(t, m.RequestsTotal)
	assert.NotNil(t, m.ConnectionsTotal)
	assert.NotNil(t, m.ConnectionErrorsTotal)
	assert.NotNil(t, m.ResponseDurationSeconds)
	assert.NotNil(t, m.ConnectDurationSeconds)
	assert.NotNil(t, m.HealthCheckStatus)
	assert.NotNil(t, m.HealthChecksTotal)
	assert.NotNil(t, m.HealthCheckDurationSeconds)
	assert.NotNil(t, m.ConsecutiveFailures)
	assert.NotNil(t, m.LBSelectionsTotal)
	assert.NotNil(t, m.LBWeight)
	assert.NotNil(t, m.PoolSize)
	assert.NotNil(t, m.CircuitBreakerState)
	assert.NotNil(t, m.CircuitBreakerTripsTotal)
	assert.NotNil(t, m.CircuitBreakerRejectionsTotal)
	assert.NotNil(t, m.PoolIdleConnections)
	assert.NotNil(t, m.PoolActiveConnections)
	assert.NotNil(t, m.PoolWaitTotal)
	assert.NotNil(t, m.PoolWaitDurationSeconds)
	assert.NotNil(t, m.PoolExhaustedTotal)
	assert.NotNil(t, m.CacheHitsTotal)
	assert.NotNil(t, m.CacheMissesTotal)
	assert.NotNil(t, m.CacheBypassTotal)
	assert.NotNil(t, m.RateLimitHitsTotal)
	assert.NotNil(t, m.AuthFailuresTotal)
	assert.NotNil(t, m.AuthSuccessesTotal)
	assert.NotNil(t, m.TLSHandshakeDurationSeconds)
	assert.NotNil(t, m.TLSErrorsTotal)
	assert.NotNil(t, m.CertExpirySeconds)
}

func TestGetBackendMetrics_Singleton(t *testing.T) {
	m1 := GetBackendMetrics()
	m2 := GetBackendMetrics()

	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "should return same instance")
}

// --- Registration ---

func TestBackendMetrics_MustRegister(t *testing.T) {
	m, reg := getTestMetrics()

	// Trigger a metric so Gather returns something.
	m.RequestsTotal.WithLabelValues("reg-be", "GET", "200").Inc()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs, "registry should contain metrics after registration")
}

func TestBackendMetrics_MustRegister_Duplicate(t *testing.T) {
	m, reg := getTestMetrics()

	assert.NotPanics(t, func() {
		m.MustRegister(reg)
	})
}

// --- Init ---

func TestBackendMetrics_Init(t *testing.T) {
	m, reg := getTestMetrics()

	assert.NotPanics(t, func() {
		m.Init()
	})

	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs, "Init should pre-populate metrics")

	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	assert.True(t, names["gateway_backend_requests_total"])
	assert.True(t, names["gateway_backend_connections_total"])
	assert.True(t, names["gateway_backend_connection_errors_total"])
	assert.True(t, names["gateway_backend_health_check_status"])
	assert.True(t, names["gateway_backend_circuit_breaker_state"])
	assert.True(t, names["gateway_backend_pool_size"])
	assert.True(t, names["gateway_backend_cert_expiry_seconds"])
}

// --- Record helpers ---

func TestBackendMetrics_RecordRequest(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.RequestsTotal.WithLabelValues("rec-req-be", "GET", "200"),
	)

	m.RecordRequest("rec-req-be", "GET", 200, 100*time.Millisecond)

	gatherAndFind(t, reg, "gateway_backend_requests_total")
	gatherAndFind(t, reg, "gateway_backend_response_duration_seconds")

	after := testutil.ToFloat64(
		m.RequestsTotal.WithLabelValues("rec-req-be", "GET", "200"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordConnection(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.ConnectionsTotal.WithLabelValues("conn-be"),
	)

	m.RecordConnection("conn-be")

	gatherAndFind(t, reg, "gateway_backend_connections_total")

	after := testutil.ToFloat64(
		m.ConnectionsTotal.WithLabelValues("conn-be"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordConnectionError(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.ConnectionErrorsTotal.WithLabelValues("conn-err-be", "timeout"),
	)

	m.RecordConnectionError("conn-err-be", "timeout")

	gatherAndFind(t, reg, "gateway_backend_connection_errors_total")

	after := testutil.ToFloat64(
		m.ConnectionErrorsTotal.WithLabelValues("conn-err-be", "timeout"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordConnectDuration(t *testing.T) {
	m, reg := getTestMetrics()

	m.RecordConnectDuration("connect-dur-be", 25*time.Millisecond)

	gatherAndFind(t, reg, "gateway_backend_connect_duration_seconds")
}

func TestBackendMetrics_RecordHealthCheck(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.HealthChecksTotal.WithLabelValues("hc-be", "success"),
	)

	m.RecordHealthCheck("hc-be", "success", 10*time.Millisecond)

	gatherAndFind(t, reg, "gateway_backend_health_checks_total")
	gatherAndFind(t, reg, "gateway_backend_health_check_duration_seconds")

	after := testutil.ToFloat64(
		m.HealthChecksTotal.WithLabelValues("hc-be", "success"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordLBSelection(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.LBSelectionsTotal.WithLabelValues("lb-be", "round_robin"),
	)

	m.RecordLBSelection("lb-be", "round_robin")

	gatherAndFind(t, reg, "gateway_backend_lb_selections_total")

	after := testutil.ToFloat64(
		m.LBSelectionsTotal.WithLabelValues("lb-be", "round_robin"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordPoolWait(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.PoolWaitTotal.WithLabelValues("pool-wait-be"),
	)

	m.RecordPoolWait("pool-wait-be", 5*time.Millisecond)

	gatherAndFind(t, reg, "gateway_backend_pool_wait_total")
	gatherAndFind(t, reg, "gateway_backend_pool_wait_duration_seconds")

	after := testutil.ToFloat64(
		m.PoolWaitTotal.WithLabelValues("pool-wait-be"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordPoolExhausted(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.PoolExhaustedTotal.WithLabelValues("pool-exhaust-be"),
	)

	m.RecordPoolExhausted("pool-exhaust-be")

	gatherAndFind(t, reg, "gateway_backend_pool_exhausted_total")

	after := testutil.ToFloat64(
		m.PoolExhaustedTotal.WithLabelValues("pool-exhaust-be"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordCacheHit(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.CacheHitsTotal.WithLabelValues("cache-hit-be", "GET"),
	)

	m.RecordCacheHit("cache-hit-be", "GET")

	gatherAndFind(t, reg, "gateway_backend_cache_hits_total")

	after := testutil.ToFloat64(
		m.CacheHitsTotal.WithLabelValues("cache-hit-be", "GET"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordCacheMiss(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.CacheMissesTotal.WithLabelValues("cache-miss-be", "GET"),
	)

	m.RecordCacheMiss("cache-miss-be", "GET")

	gatherAndFind(t, reg, "gateway_backend_cache_misses_total")

	after := testutil.ToFloat64(
		m.CacheMissesTotal.WithLabelValues("cache-miss-be", "GET"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordCacheBypass(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.CacheBypassTotal.WithLabelValues("cache-bypass-be", "GET", "no_cache_header"),
	)

	m.RecordCacheBypass("cache-bypass-be", "GET", "no_cache_header")

	gatherAndFind(t, reg, "gateway_backend_cache_bypass_total")

	after := testutil.ToFloat64(
		m.CacheBypassTotal.WithLabelValues("cache-bypass-be", "GET", "no_cache_header"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordRateLimitHit(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.RateLimitHitsTotal.WithLabelValues("rl-be", "GET", "consumer-1"),
	)

	m.RecordRateLimitHit("rl-be", "GET", "consumer-1")

	gatherAndFind(t, reg, "gateway_backend_ratelimit_hits_total")

	after := testutil.ToFloat64(
		m.RateLimitHitsTotal.WithLabelValues("rl-be", "GET", "consumer-1"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordAuthFailure(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.AuthFailuresTotal.WithLabelValues("auth-fail-be", "POST", "oidc", "token_error"),
	)

	m.RecordAuthFailure("auth-fail-be", "POST", "oidc", "token_error")

	gatherAndFind(t, reg, "gateway_backend_auth_failures_total")

	after := testutil.ToFloat64(
		m.AuthFailuresTotal.WithLabelValues("auth-fail-be", "POST", "oidc", "token_error"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordAuthSuccess(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.AuthSuccessesTotal.WithLabelValues("auth-ok-be", "GET", "apikey"),
	)

	m.RecordAuthSuccess("auth-ok-be", "GET", "apikey")

	gatherAndFind(t, reg, "gateway_backend_auth_successes_total")

	after := testutil.ToFloat64(
		m.AuthSuccessesTotal.WithLabelValues("auth-ok-be", "GET", "apikey"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordTLSHandshake(t *testing.T) {
	m, reg := getTestMetrics()

	m.RecordTLSHandshake("tls-hs-be", "1.3", 15*time.Millisecond)

	gatherAndFind(t, reg, "gateway_backend_tls_handshake_duration_seconds")
}

func TestBackendMetrics_RecordTLSError(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.TLSErrorsTotal.WithLabelValues("tls-err-be", "certificate_expired"),
	)

	m.RecordTLSError("tls-err-be", "certificate_expired")

	gatherAndFind(t, reg, "gateway_backend_tls_errors_total")

	after := testutil.ToFloat64(
		m.TLSErrorsTotal.WithLabelValues("tls-err-be", "certificate_expired"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordCircuitBreakerTrip(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.CircuitBreakerTripsTotal.WithLabelValues("cb-trip-be"),
	)

	m.RecordCircuitBreakerTrip("cb-trip-be")

	gatherAndFind(t, reg, "gateway_backend_circuit_breaker_trips_total")

	after := testutil.ToFloat64(
		m.CircuitBreakerTripsTotal.WithLabelValues("cb-trip-be"),
	)
	assert.Equal(t, before+1, after)
}

func TestBackendMetrics_RecordCircuitBreakerRejection(t *testing.T) {
	m, reg := getTestMetrics()

	before := testutil.ToFloat64(
		m.CircuitBreakerRejectionsTotal.WithLabelValues("cb-rej-be"),
	)

	m.RecordCircuitBreakerRejection("cb-rej-be")

	gatherAndFind(t, reg, "gateway_backend_circuit_breaker_rejections_total")

	after := testutil.ToFloat64(
		m.CircuitBreakerRejectionsTotal.WithLabelValues("cb-rej-be"),
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

// --- collectors ---

func TestBackendMetrics_Collectors(t *testing.T) {
	m, _ := getTestMetrics()
	collectors := m.collectors()

	// 29 metric fields.
	assert.Len(t, collectors, 29, "should return 29 collectors")

	for i, c := range collectors {
		assert.NotNil(t, c, "collector %d should not be nil", i)
	}
}

// --- Concurrent access ---

func TestBackendMetrics_ConcurrentAccess(t *testing.T) {
	m, _ := getTestMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.RecordRequest("concurrent", "GET", 200, time.Millisecond)
				m.RecordConnection("concurrent")
				m.RecordConnectionError("concurrent", "timeout")
				m.RecordConnectDuration("concurrent", time.Millisecond)
				m.RecordHealthCheck("concurrent", "success", time.Millisecond)
				m.RecordLBSelection("concurrent", "round_robin")
				m.RecordPoolWait("concurrent", time.Millisecond)
				m.RecordPoolExhausted("concurrent")
				m.RecordCacheHit("concurrent", "GET")
				m.RecordCacheMiss("concurrent", "GET")
				m.RecordCacheBypass("concurrent", "GET", "no_cache_header")
				m.RecordRateLimitHit("concurrent", "GET", "c")
				m.RecordAuthFailure("concurrent", "GET", "oidc", "expired")
				m.RecordAuthSuccess("concurrent", "GET", "oidc")
				m.RecordTLSHandshake("concurrent", "1.3", time.Millisecond)
				m.RecordTLSError("concurrent", "cert_expired")
				m.RecordCircuitBreakerTrip("concurrent")
				m.RecordCircuitBreakerRejection("concurrent")
			}
		}()
	}

	wg.Wait()
}

// --- Table-driven RecordRequest ---

func TestBackendMetrics_RecordRequest_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		backend    string
		method     string
		statusCode int
		duration   time.Duration
	}{
		{
			name:       "GET 200",
			backend:    "td-be-a",
			method:     "GET",
			statusCode: 200,
			duration:   50 * time.Millisecond,
		},
		{
			name:       "POST 201",
			backend:    "td-be-b",
			method:     "POST",
			statusCode: 201,
			duration:   100 * time.Millisecond,
		},
		{
			name:       "DELETE 500",
			backend:    "td-be-a",
			method:     "DELETE",
			statusCode: 500,
			duration:   200 * time.Millisecond,
		},
	}

	m, reg := getTestMetrics()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.RecordRequest(tt.backend, tt.method, tt.statusCode, tt.duration)

			gatherAndFind(t, reg, "gateway_backend_requests_total")
			gatherAndFind(t, reg, "gateway_backend_response_duration_seconds")
		})
	}
}
