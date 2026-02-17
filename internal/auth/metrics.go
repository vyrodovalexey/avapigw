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
	registerer       prometheus.Registerer
}

// NewMetrics creates a new Metrics instance.
// Metrics are registered with prometheus.DefaultRegisterer so they are
// automatically exposed on the default /metrics endpoint.
func NewMetrics(namespace string) *Metrics {
	return NewMetricsWithRegisterer(namespace, prometheus.DefaultRegisterer)
}

// NewMetricsWithRegisterer creates a new Metrics instance with a custom registerer.
// This is useful for testing where a private registry is preferred.
func NewMetricsWithRegisterer(namespace string, registerer prometheus.Registerer) *Metrics {
	if namespace == "" {
		namespace = "gateway"
	}

	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}

	m := &Metrics{
		registerer: registerer,
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

	// Register all metrics with the provided registerer, ignoring duplicates.
	// This is safe because the metric descriptors are identical when re-registered.
	collectors := []prometheus.Collector{
		m.requestsTotal,
		m.requestDuration,
		m.authSuccessTotal,
		m.authFailureTotal,
		m.cacheHits,
		m.cacheMisses,
	}
	for _, c := range collectors {
		// Use Register instead of MustRegister to handle duplicate registration gracefully.
		// If the metric is already registered (e.g., in tests), we ignore the error.
		_ = m.registerer.Register(c)
	}

	return m
}

// Init pre-initializes common label combinations with zero values so that
// metrics appear in /metrics output immediately after startup. Prometheus
// *Vec types only emit metric lines after WithLabelValues() is called at
// least once. This method is idempotent and safe to call multiple times.
func (m *Metrics) Init() {
	for _, authType := range []string{"jwt", "basic", "apikey", "mtls", "oidc"} {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			for _, status := range []string{"success", "failure"} {
				m.requestsTotal.WithLabelValues(method, authType, status)
			}
			m.requestDuration.WithLabelValues(method, authType)
		}
		m.authSuccessTotal.WithLabelValues(authType)
		for _, reason := range []string{"invalid_token", "expired", "unauthorized"} {
			m.authFailureTotal.WithLabelValues(authType, reason)
		}
	}
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

// Registry returns a Prometheus registry containing these metrics.
// This creates a new registry and re-registers the collectors for
// backward compatibility with code that calls Gather() on the returned registry.
func (m *Metrics) Registry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.authSuccessTotal,
		m.authFailureTotal,
		m.cacheHits,
		m.cacheMisses,
	)
	return reg
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
