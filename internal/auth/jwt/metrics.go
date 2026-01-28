package jwt

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for JWT operations.
type Metrics struct {
	validationTotal     *prometheus.CounterVec
	validationDuration  *prometheus.HistogramVec
	signingTotal        *prometheus.CounterVec
	signingDuration     *prometheus.HistogramVec
	cacheHits           prometheus.Counter
	cacheMisses         prometheus.Counter
	jwksRefreshTotal    *prometheus.CounterVec
	jwksRefreshDuration prometheus.Histogram
	registry            *prometheus.Registry
}

// NewMetrics creates a new Metrics instance.
func NewMetrics(namespace string) *Metrics {
	if namespace == "" {
		namespace = "gateway"
	}

	m := &Metrics{
		registry: prometheus.NewRegistry(),
	}

	m.validationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "jwt",
			Name:      "validation_total",
			Help:      "Total number of JWT validation attempts",
		},
		[]string{"status", "algorithm"},
	)

	m.validationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "jwt",
			Name:      "validation_duration_seconds",
			Help:      "JWT validation duration in seconds",
			Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"status", "algorithm"},
	)

	m.signingTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "jwt",
			Name:      "signing_total",
			Help:      "Total number of JWT signing attempts",
		},
		[]string{"status", "algorithm"},
	)

	m.signingDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "jwt",
			Name:      "signing_duration_seconds",
			Help:      "JWT signing duration in seconds",
			Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"status", "algorithm"},
	)

	m.cacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "jwt",
			Name:      "cache_hits_total",
			Help:      "Total number of JWT cache hits",
		},
	)

	m.cacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "jwt",
			Name:      "cache_misses_total",
			Help:      "Total number of JWT cache misses",
		},
	)

	m.jwksRefreshTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "jwt",
			Name:      "jwks_refresh_total",
			Help:      "Total number of JWKS refresh attempts",
		},
		[]string{"status"},
	)

	m.jwksRefreshDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "jwt",
			Name:      "jwks_refresh_duration_seconds",
			Help:      "JWKS refresh duration in seconds",
			Buckets:   []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.validationTotal,
		m.validationDuration,
		m.signingTotal,
		m.signingDuration,
		m.cacheHits,
		m.cacheMisses,
		m.jwksRefreshTotal,
		m.jwksRefreshDuration,
	)

	return m
}

// RecordValidation records a JWT validation attempt.
func (m *Metrics) RecordValidation(status, algorithm string, duration time.Duration) {
	m.validationTotal.WithLabelValues(status, algorithm).Inc()
	m.validationDuration.WithLabelValues(status, algorithm).Observe(duration.Seconds())
}

// RecordSigning records a JWT signing attempt.
func (m *Metrics) RecordSigning(status, algorithm string, duration time.Duration) {
	m.signingTotal.WithLabelValues(status, algorithm).Inc()
	m.signingDuration.WithLabelValues(status, algorithm).Observe(duration.Seconds())
}

// RecordCacheHit records a cache hit.
func (m *Metrics) RecordCacheHit() {
	m.cacheHits.Inc()
}

// RecordCacheMiss records a cache miss.
func (m *Metrics) RecordCacheMiss() {
	m.cacheMisses.Inc()
}

// RecordJWKSRefresh records a JWKS refresh attempt.
func (m *Metrics) RecordJWKSRefresh(status string, duration time.Duration) {
	m.jwksRefreshTotal.WithLabelValues(status).Inc()
	m.jwksRefreshDuration.Observe(duration.Seconds())
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// MustRegister registers the metrics with the given registry.
func (m *Metrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		m.validationTotal,
		m.validationDuration,
		m.signingTotal,
		m.signingDuration,
		m.cacheHits,
		m.cacheMisses,
		m.jwksRefreshTotal,
		m.jwksRefreshDuration,
	)
}
