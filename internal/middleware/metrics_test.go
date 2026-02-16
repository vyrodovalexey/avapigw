package middleware

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMiddlewareMetrics_Singleton(t *testing.T) {
	m1 := GetMiddlewareMetrics()
	m2 := GetMiddlewareMetrics()

	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "should return same instance")
}

func TestGetMiddlewareMetrics_AllFieldsInitialized(t *testing.T) {
	m := GetMiddlewareMetrics()

	require.NotNil(t, m)
	assert.NotNil(t, m.rateLimitAllowed, "rateLimitAllowed should be initialized")
	assert.NotNil(t, m.rateLimitRejected, "rateLimitRejected should be initialized")
	assert.NotNil(t, m.circuitBreakerRequests, "circuitBreakerRequests should be initialized")
	assert.NotNil(t, m.circuitBreakerTransitions, "circuitBreakerTransitions should be initialized")
	assert.NotNil(t, m.timeoutsTotal, "timeoutsTotal should be initialized")
	assert.NotNil(t, m.retryAttemptsTotal, "retryAttemptsTotal should be initialized")
	assert.NotNil(t, m.retrySuccessTotal, "retrySuccessTotal should be initialized")
	assert.NotNil(t, m.bodyLimitRejected, "bodyLimitRejected should be initialized")
	assert.NotNil(t, m.maxSessionsRejected, "maxSessionsRejected should be initialized")
	assert.NotNil(t, m.maxSessionsCurrent, "maxSessionsCurrent should be initialized")
	assert.NotNil(t, m.panicsRecovered, "panicsRecovered should be initialized")
	assert.NotNil(t, m.corsRequestsTotal, "corsRequestsTotal should be initialized")
}

func TestMiddlewareMetrics_RateLimitAllowed(t *testing.T) {
	m := GetMiddlewareMetrics()

	before := testutil.ToFloat64(m.rateLimitAllowed.WithLabelValues("metrics-test-rl-allowed"))
	m.rateLimitAllowed.WithLabelValues("metrics-test-rl-allowed").Inc()
	after := testutil.ToFloat64(m.rateLimitAllowed.WithLabelValues("metrics-test-rl-allowed"))

	assert.Equal(t, before+1, after, "rateLimitAllowed should increment by 1")
}

func TestMiddlewareMetrics_RateLimitRejected(t *testing.T) {
	m := GetMiddlewareMetrics()

	before := testutil.ToFloat64(m.rateLimitRejected.WithLabelValues("metrics-test-rl-rejected"))
	m.rateLimitRejected.WithLabelValues("metrics-test-rl-rejected").Inc()
	after := testutil.ToFloat64(m.rateLimitRejected.WithLabelValues("metrics-test-rl-rejected"))

	assert.Equal(t, before+1, after, "rateLimitRejected should increment by 1")
}

func TestMiddlewareMetrics_CircuitBreakerRequests(t *testing.T) {
	m := GetMiddlewareMetrics()

	tests := []struct {
		name  string
		cbNm  string
		state string
	}{
		{name: "closed state", cbNm: "metrics-test-cb", state: "closed"},
		{name: "open state", cbNm: "metrics-test-cb", state: "open"},
		{name: "half-open state", cbNm: "metrics-test-cb", state: "half-open"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(
				m.circuitBreakerRequests.WithLabelValues(tt.cbNm, tt.state),
			)
			m.circuitBreakerRequests.WithLabelValues(tt.cbNm, tt.state).Inc()
			after := testutil.ToFloat64(
				m.circuitBreakerRequests.WithLabelValues(tt.cbNm, tt.state),
			)

			assert.Equal(t, before+1, after)
		})
	}
}

func TestMiddlewareMetrics_CircuitBreakerTransitions(t *testing.T) {
	m := GetMiddlewareMetrics()

	before := testutil.ToFloat64(
		m.circuitBreakerTransitions.WithLabelValues("metrics-test-cb-trans", "closed", "open"),
	)
	m.circuitBreakerTransitions.WithLabelValues("metrics-test-cb-trans", "closed", "open").Inc()
	after := testutil.ToFloat64(
		m.circuitBreakerTransitions.WithLabelValues("metrics-test-cb-trans", "closed", "open"),
	)

	assert.Equal(t, before+1, after)
}

func TestMiddlewareMetrics_TimeoutsTotal(t *testing.T) {
	m := GetMiddlewareMetrics()

	before := testutil.ToFloat64(m.timeoutsTotal.WithLabelValues("metrics-test-timeout-route"))
	m.timeoutsTotal.WithLabelValues("metrics-test-timeout-route").Inc()
	after := testutil.ToFloat64(m.timeoutsTotal.WithLabelValues("metrics-test-timeout-route"))

	assert.Equal(t, before+1, after)
}

func TestMiddlewareMetrics_RetryAttemptsTotal(t *testing.T) {
	m := GetMiddlewareMetrics()

	before := testutil.ToFloat64(m.retryAttemptsTotal.WithLabelValues("metrics-test-retry-route"))
	m.retryAttemptsTotal.WithLabelValues("metrics-test-retry-route").Inc()
	after := testutil.ToFloat64(m.retryAttemptsTotal.WithLabelValues("metrics-test-retry-route"))

	assert.Equal(t, before+1, after)
}

func TestMiddlewareMetrics_RetrySuccessTotal(t *testing.T) {
	m := GetMiddlewareMetrics()

	before := testutil.ToFloat64(m.retrySuccessTotal.WithLabelValues("metrics-test-retry-success"))
	m.retrySuccessTotal.WithLabelValues("metrics-test-retry-success").Inc()
	after := testutil.ToFloat64(m.retrySuccessTotal.WithLabelValues("metrics-test-retry-success"))

	assert.Equal(t, before+1, after)
}

func TestMiddlewareMetrics_BodyLimitRejected(t *testing.T) {
	m := GetMiddlewareMetrics()

	before := testutil.ToFloat64(m.bodyLimitRejected)
	m.bodyLimitRejected.Inc()
	after := testutil.ToFloat64(m.bodyLimitRejected)

	assert.Equal(t, before+1, after)
}

func TestMiddlewareMetrics_MaxSessionsRejected(t *testing.T) {
	m := GetMiddlewareMetrics()

	before := testutil.ToFloat64(m.maxSessionsRejected)
	m.maxSessionsRejected.Inc()
	after := testutil.ToFloat64(m.maxSessionsRejected)

	assert.Equal(t, before+1, after)
}

func TestMiddlewareMetrics_MaxSessionsCurrent(t *testing.T) {
	m := GetMiddlewareMetrics()

	m.maxSessionsCurrent.Set(42)
	val := testutil.ToFloat64(m.maxSessionsCurrent)

	assert.Equal(t, float64(42), val)

	m.maxSessionsCurrent.Set(0)
	val = testutil.ToFloat64(m.maxSessionsCurrent)

	assert.Equal(t, float64(0), val)
}

func TestMiddlewareMetrics_PanicsRecovered(t *testing.T) {
	m := GetMiddlewareMetrics()

	before := testutil.ToFloat64(m.panicsRecovered)
	m.panicsRecovered.Inc()
	after := testutil.ToFloat64(m.panicsRecovered)

	assert.Equal(t, before+1, after)
}

func TestMiddlewareMetrics_CorsRequestsTotal(t *testing.T) {
	m := GetMiddlewareMetrics()

	tests := []struct {
		name     string
		corsType string
	}{
		{name: "preflight", corsType: "preflight"},
		{name: "actual", corsType: "actual"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(
				m.corsRequestsTotal.WithLabelValues(tt.corsType),
			)
			m.corsRequestsTotal.WithLabelValues(tt.corsType).Inc()
			after := testutil.ToFloat64(
				m.corsRequestsTotal.WithLabelValues(tt.corsType),
			)

			assert.Equal(t, before+1, after)
		})
	}
}

func TestMiddlewareMetrics_ConcurrentAccess(t *testing.T) {
	m := GetMiddlewareMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.rateLimitAllowed.WithLabelValues("concurrent-test").Inc()
				m.rateLimitRejected.WithLabelValues("concurrent-test").Inc()
				m.circuitBreakerRequests.WithLabelValues("concurrent-cb", "closed").Inc()
				m.timeoutsTotal.WithLabelValues("concurrent-route").Inc()
				m.retryAttemptsTotal.WithLabelValues("concurrent-route").Inc()
				m.bodyLimitRejected.Inc()
				m.maxSessionsRejected.Inc()
				m.panicsRecovered.Inc()
				m.corsRequestsTotal.WithLabelValues("preflight").Inc()
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions occur (run with -race flag)
}
