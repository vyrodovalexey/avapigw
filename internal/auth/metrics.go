package auth

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for authentication operations.
type Metrics struct {
	requestsTotal    *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	authSuccessTotal *prometheus.CounterVec
	authFailureTotal *prometheus.CounterVec
	cacheHits        prometheus.Counter
	cacheMisses      prometheus.Counter
	registry         *prometheus.Registry
}

// NewMetrics creates a new Metrics instance.
func NewMetrics(namespace string) *Metrics {
	if namespace == "" {
		namespace = "gateway"
	}

	m := &Metrics{
		registry: prometheus.NewRegistry(),
	}

	m.requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth",
			Name:      "requests_total",
			Help:      "Total number of authentication requests",
		},
		[]string{"method", "auth_type", "status"},
	)

	m.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "auth",
			Name:      "request_duration_seconds",
			Help:      "Authentication request duration in seconds",
			Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"method", "auth_type"},
	)

	m.authSuccessTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth",
			Name:      "success_total",
			Help:      "Total number of successful authentications",
		},
		[]string{"auth_type"},
	)

	m.authFailureTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth",
			Name:      "failure_total",
			Help:      "Total number of failed authentications",
		},
		[]string{"auth_type", "reason"},
	)

	m.cacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth",
			Name:      "cache_hits_total",
			Help:      "Total number of authentication cache hits",
		},
	)

	m.cacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth",
			Name:      "cache_misses_total",
			Help:      "Total number of authentication cache misses",
		},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.authSuccessTotal,
		m.authFailureTotal,
		m.cacheHits,
		m.cacheMisses,
	)

	return m
}

// RecordRequest records an authentication request.
func (m *Metrics) RecordRequest(method, authType, status string, duration time.Duration) {
	m.requestsTotal.WithLabelValues(method, authType, status).Inc()
	m.requestDuration.WithLabelValues(method, authType).Observe(duration.Seconds())
}

// RecordSuccess records a successful authentication.
func (m *Metrics) RecordSuccess(authType string) {
	m.authSuccessTotal.WithLabelValues(authType).Inc()
}

// RecordFailure records a failed authentication.
func (m *Metrics) RecordFailure(authType, reason string) {
	m.authFailureTotal.WithLabelValues(authType, reason).Inc()
}

// RecordCacheHit records a cache hit.
func (m *Metrics) RecordCacheHit() {
	m.cacheHits.Inc()
}

// RecordCacheMiss records a cache miss.
func (m *Metrics) RecordCacheMiss() {
	m.cacheMisses.Inc()
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// MustRegister registers the metrics with the given registry.
func (m *Metrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.authSuccessTotal,
		m.authFailureTotal,
		m.cacheHits,
		m.cacheMisses,
	)
}
