// Package middleware provides HTTP middleware components for the
// API Gateway.
package middleware

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metric/label constants.
const (
	metricsNamespace = "gateway"
	metricsSubsystem = "middleware"
	labelRoute       = "route"
	stateClosed      = "closed"
	stateHalfOpen    = "half-open"
	stateOpen        = "open"
)

// Redis rate limiter failure-policy label values.
const (
	failPolicyOpen   = "fail_open"
	failPolicyClosed = "fail_closed"
)

// MiddlewareMetrics holds Prometheus metrics for middleware
// operations.
type MiddlewareMetrics struct {
	rateLimitAllowed  *prometheus.CounterVec
	rateLimitRejected *prometheus.CounterVec

	redisRateLimitAllowed  *prometheus.CounterVec
	redisRateLimitDenied   *prometheus.CounterVec
	redisRateLimitErrors   *prometheus.CounterVec
	redisRateLimitDuration *prometheus.HistogramVec

	circuitBreakerRequests    *prometheus.CounterVec
	circuitBreakerTransitions *prometheus.CounterVec

	timeoutsTotal *prometheus.CounterVec

	retryAttemptsTotal *prometheus.CounterVec
	retrySuccessTotal  *prometheus.CounterVec

	bodyLimitRejected prometheus.Counter

	maxSessionsRejected prometheus.Counter
	maxSessionsCurrent  prometheus.Gauge

	panicsRecovered prometheus.Counter

	corsRequestsTotal          *prometheus.CounterVec
	corsUpstreamHeadersDropped prometheus.Counter
}

var (
	middlewareMetrics     *MiddlewareMetrics
	middlewareMetricsOnce sync.Once
)

// GetMiddlewareMetrics returns the singleton middleware metrics
// instance.
func GetMiddlewareMetrics() *MiddlewareMetrics {
	middlewareMetricsOnce.Do(func() {
		middlewareMetrics = newMiddlewareMetrics()
	})
	return middlewareMetrics
}

// MustRegister registers all middleware metric collectors with the
// given Prometheus registry. This is needed because promauto registers
// metrics with the default global registry, but the gateway serves
// /metrics from a custom registry. Calling MustRegister bridges the
// two so middleware metrics appear on the gateway's metrics endpoint.
func (m *MiddlewareMetrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		m.rateLimitAllowed,
		m.rateLimitRejected,
		m.redisRateLimitAllowed,
		m.redisRateLimitDenied,
		m.redisRateLimitErrors,
		m.redisRateLimitDuration,
		m.circuitBreakerRequests,
		m.circuitBreakerTransitions,
		m.timeoutsTotal,
		m.retryAttemptsTotal,
		m.retrySuccessTotal,
		m.bodyLimitRejected,
		m.maxSessionsRejected,
		m.maxSessionsCurrent,
		m.panicsRecovered,
		m.corsRequestsTotal,
		m.corsUpstreamHeadersDropped,
	)
}

// Init pre-initializes common label combinations with zero values so
// that metrics appear in /metrics output immediately after startup.
// Prometheus *Vec types only emit metric lines after WithLabelValues()
// is called at least once. This method is idempotent and safe to call
// multiple times.
func (m *MiddlewareMetrics) Init() {
	for _, route := range []string{"default"} {
		m.rateLimitAllowed.WithLabelValues(route)
		m.rateLimitRejected.WithLabelValues(route)
		m.redisRateLimitAllowed.WithLabelValues(route)
		m.redisRateLimitDenied.WithLabelValues(route)
		m.redisRateLimitDuration.WithLabelValues(route)
		for _, policy := range []string{failPolicyOpen, failPolicyClosed} {
			m.redisRateLimitErrors.WithLabelValues(route, policy)
		}
		m.timeoutsTotal.WithLabelValues(route)
		m.retryAttemptsTotal.WithLabelValues(route)
		m.retrySuccessTotal.WithLabelValues(route)
	}
	for _, state := range []string{stateClosed, stateOpen, stateHalfOpen} {
		m.circuitBreakerRequests.WithLabelValues("default", state)
	}
	for _, pair := range [][2]string{
		{stateClosed, stateOpen},
		{stateOpen, stateHalfOpen},
		{stateHalfOpen, stateClosed},
	} {
		m.circuitBreakerTransitions.WithLabelValues("default", pair[0], pair[1])
	}
	for _, corsType := range []string{"preflight", "actual"} {
		m.corsRequestsTotal.WithLabelValues(corsType)
	}
}

//nolint:funlen // metric initialization requires many declarations
func newMiddlewareMetrics() *MiddlewareMetrics {
	return &MiddlewareMetrics{
		rateLimitAllowed: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "rate_limit_allowed_total",
				Help: "Total number of requests " +
					"allowed by rate limiter",
			},
			[]string{labelRoute},
		),
		rateLimitRejected: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "rate_limit_rejected_total",
				Help: "Total number of requests " +
					"rejected by rate limiter",
			},
			[]string{labelRoute},
		),
		redisRateLimitAllowed: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "redis_rate_limit_allowed_total",
				Help: "Total number of requests " +
					"allowed by the redis rate limiter",
			},
			[]string{labelRoute},
		),
		redisRateLimitDenied: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "redis_rate_limit_denied_total",
				Help: "Total number of requests " +
					"denied by the redis rate limiter",
			},
			[]string{labelRoute},
		),
		redisRateLimitErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "redis_rate_limit_errors_total",
				Help: "Total number of redis rate " +
					"limiter errors by failure policy",
			},
			[]string{labelRoute, "policy"},
		),
		redisRateLimitDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name: "redis_rate_limit_" +
					"duration_seconds",
				Help: "Duration of redis rate limit " +
					"decisions in seconds",
				Buckets: []float64{
					.0005, .001, .0025, .005,
					.01, .025, .05, .1, .25,
				},
			},
			[]string{labelRoute},
		),
		circuitBreakerRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name: "circuit_breaker_" +
					"requests_total",
				Help: "Total number of requests " +
					"through circuit breaker by state",
			},
			[]string{"name", "state"},
		),
		circuitBreakerTransitions: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name: "circuit_breaker_" +
					"transitions_total",
				Help: "Total number of circuit " +
					"breaker state transitions",
			},
			[]string{"name", "from", "to"},
		),
		timeoutsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "request_timeouts_total",
				Help: "Total number of request " +
					"timeouts",
			},
			[]string{labelRoute},
		),
		retryAttemptsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "retry_attempts_total",
				Help: "Total number of retry " +
					"attempts",
			},
			[]string{labelRoute},
		),
		retrySuccessTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "retry_success_total",
				Help: "Total number of successful " +
					"retries",
			},
			[]string{labelRoute},
		),
		bodyLimitRejected: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "body_limit_rejected_total",
				Help: "Total number of requests " +
					"rejected due to body size limit",
			},
		),
		maxSessionsRejected: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name: "max_sessions_" +
					"rejected_total",
				Help: "Total number of requests " +
					"rejected due to max sessions",
			},
		),
		maxSessionsCurrent: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "max_sessions_current",
				Help: "Current number of active " +
					"sessions",
			},
		),
		panicsRecovered: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "panics_recovered_total",
				Help: "Total number of panics " +
					"recovered",
			},
		),
		corsRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "cors_requests_total",
				Help: "Total number of CORS " +
					"requests by type",
			},
			[]string{"type"},
		),
		corsUpstreamHeadersDropped: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name: "cors_upstream_headers_" +
					"dropped_total",
				Help: "Total number of responses whose " +
					"upstream Access-Control-* headers were " +
					"replaced by the gateway CORS policy",
			},
		),
	}
}
