// Package middleware provides HTTP middleware components for the
// API Gateway.
package middleware

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MiddlewareMetrics holds Prometheus metrics for middleware
// operations.
type MiddlewareMetrics struct {
	rateLimitAllowed  *prometheus.CounterVec
	rateLimitRejected *prometheus.CounterVec

	circuitBreakerRequests    *prometheus.CounterVec
	circuitBreakerTransitions *prometheus.CounterVec

	timeoutsTotal *prometheus.CounterVec

	retryAttemptsTotal *prometheus.CounterVec
	retrySuccessTotal  *prometheus.CounterVec

	bodyLimitRejected prometheus.Counter

	maxSessionsRejected prometheus.Counter
	maxSessionsCurrent  prometheus.Gauge

	panicsRecovered prometheus.Counter

	corsRequestsTotal *prometheus.CounterVec
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

//nolint:funlen // metric initialization requires many declarations
func newMiddlewareMetrics() *MiddlewareMetrics {
	return &MiddlewareMetrics{
		rateLimitAllowed: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name:      "rate_limit_allowed_total",
				Help: "Total number of requests " +
					"allowed by rate limiter",
			},
			[]string{"route"},
		),
		rateLimitRejected: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name:      "rate_limit_rejected_total",
				Help: "Total number of requests " +
					"rejected by rate limiter",
			},
			[]string{"route"},
		),
		circuitBreakerRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name: "circuit_breaker_" +
					"requests_total",
				Help: "Total number of requests " +
					"through circuit breaker by state",
			},
			[]string{"name", "state"},
		),
		circuitBreakerTransitions: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name: "circuit_breaker_" +
					"transitions_total",
				Help: "Total number of circuit " +
					"breaker state transitions",
			},
			[]string{"name", "from", "to"},
		),
		timeoutsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name:      "request_timeouts_total",
				Help: "Total number of request " +
					"timeouts",
			},
			[]string{"route"},
		),
		retryAttemptsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name:      "retry_attempts_total",
				Help: "Total number of retry " +
					"attempts",
			},
			[]string{"route"},
		),
		retrySuccessTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name:      "retry_success_total",
				Help: "Total number of successful " +
					"retries",
			},
			[]string{"route"},
		),
		bodyLimitRejected: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name:      "body_limit_rejected_total",
				Help: "Total number of requests " +
					"rejected due to body size limit",
			},
		),
		maxSessionsRejected: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name: "max_sessions_" +
					"rejected_total",
				Help: "Total number of requests " +
					"rejected due to max sessions",
			},
		),
		maxSessionsCurrent: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name:      "max_sessions_current",
				Help: "Current number of active " +
					"sessions",
			},
		),
		panicsRecovered: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name:      "panics_recovered_total",
				Help: "Total number of panics " +
					"recovered",
			},
		),
		corsRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "middleware",
				Name:      "cors_requests_total",
				Help: "Total number of CORS " +
					"requests by type",
			},
			[]string{"type"},
		),
	}
}
