package vault

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// defaultMetrics holds the singleton Metrics instance registered with the default global registry.
// This ensures metrics are only registered once with the default Prometheus registry,
// avoiding duplicate registration panics.
var (
	defaultMetrics     *Metrics
	defaultMetricsOnce sync.Once
)

// Metrics holds Prometheus metrics for Vault operations.
type Metrics struct {
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	tokenTTL        prometheus.Gauge
	cacheHits       prometheus.Counter
	cacheMisses     prometheus.Counter
	authAttempts    *prometheus.CounterVec
	errors          *prometheus.CounterVec

	registry *prometheus.Registry
	mu       sync.RWMutex
}

// MetricsOption is a functional option for configuring Metrics.
type MetricsOption func(*Metrics)

// WithMetricsRegistry sets a custom Prometheus registry for backward compatibility.
// When not set, metrics are automatically registered with the default global registry via promauto.
func WithMetricsRegistry(registry *prometheus.Registry) MetricsOption {
	return func(m *Metrics) {
		m.registry = registry
	}
}

// NewMetrics creates a new Metrics instance with the given namespace.
// By default, metrics are registered with the default global Prometheus registry via promauto
// using a singleton pattern to avoid duplicate registration panics.
// Use WithMetricsRegistry to register with a custom registry instead.
func NewMetrics(namespace string, opts ...MetricsOption) *Metrics {
	if namespace == "" {
		namespace = "gateway"
	}

	m := &Metrics{}

	for _, opt := range opts {
		opt(m)
	}

	// When a custom registry is provided, create a new Metrics instance with that registry.
	// Otherwise, return the singleton instance registered with the default global registry.
	if m.registry != nil {
		factory := promauto.With(m.registry)
		m.initWithFactory(namespace, factory)
		return m
	}

	// Use singleton pattern for the default global registry to prevent duplicate registration.
	defaultMetricsOnce.Do(func() {
		defaultMetrics = &Metrics{}
		factory := promauto.With(prometheus.DefaultRegisterer)
		defaultMetrics.initWithFactory(namespace, factory)
	})

	return defaultMetrics
}

// initWithFactory initializes all metrics using the given promauto factory.
func (m *Metrics) initWithFactory(namespace string, factory promauto.Factory) {
	m.requestsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "vault",
			Name:      "requests_total",
			Help:      "Total number of Vault requests by operation and status",
		},
		[]string{"operation", "status"},
	)

	m.requestDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "vault",
			Name:      "request_duration_seconds",
			Help:      "Vault request duration in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"operation"},
	)

	m.tokenTTL = factory.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "vault",
			Name:      "token_ttl_seconds",
			Help:      "Current Vault token TTL in seconds",
		},
	)

	m.cacheHits = factory.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "vault",
			Name:      "cache_hits_total",
			Help:      "Total number of Vault cache hits",
		},
	)

	m.cacheMisses = factory.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "vault",
			Name:      "cache_misses_total",
			Help:      "Total number of Vault cache misses",
		},
	)

	m.authAttempts = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "vault",
			Name:      "auth_attempts_total",
			Help:      "Total number of Vault authentication attempts by method and status",
		},
		[]string{"method", "status"},
	)

	m.errors = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "vault",
			Name:      "errors_total",
			Help:      "Total number of Vault errors by type",
		},
		[]string{"type"},
	)
}

// RecordRequest records a Vault request.
func (m *Metrics) RecordRequest(operation, status string, duration time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.requestsTotal.WithLabelValues(operation, status).Inc()
	m.requestDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// SetTokenTTL sets the current token TTL.
func (m *Metrics) SetTokenTTL(ttl float64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.tokenTTL.Set(ttl)
}

// RecordCacheHit records a cache hit.
func (m *Metrics) RecordCacheHit() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.cacheHits.Inc()
}

// RecordCacheMiss records a cache miss.
func (m *Metrics) RecordCacheMiss() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.cacheMisses.Inc()
}

// RecordAuthAttempt records an authentication attempt.
func (m *Metrics) RecordAuthAttempt(method, status string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.authAttempts.WithLabelValues(method, status).Inc()
}

// RecordError records an error.
func (m *Metrics) RecordError(errorType string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.errors.WithLabelValues(errorType).Inc()
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// Describe implements prometheus.Collector.
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.requestsTotal.Describe(ch)
	m.requestDuration.Describe(ch)
	m.tokenTTL.Describe(ch)
	m.cacheHits.Describe(ch)
	m.cacheMisses.Describe(ch)
	m.authAttempts.Describe(ch)
	m.errors.Describe(ch)
}

// Collect implements prometheus.Collector.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	m.requestsTotal.Collect(ch)
	m.requestDuration.Collect(ch)
	m.tokenTTL.Collect(ch)
	m.cacheHits.Collect(ch)
	m.cacheMisses.Collect(ch)
	m.authAttempts.Collect(ch)
	m.errors.Collect(ch)
}

// NopMetrics is a no-op implementation of metrics for testing.
type NopMetrics struct{}

// NewNopMetrics creates a new NopMetrics instance.
func NewNopMetrics() *NopMetrics {
	return &NopMetrics{}
}

// RecordRequest is a no-op.
func (m *NopMetrics) RecordRequest(_, _ string, _ time.Duration) {}

// SetTokenTTL is a no-op.
func (m *NopMetrics) SetTokenTTL(_ float64) {}

// RecordCacheHit is a no-op.
func (m *NopMetrics) RecordCacheHit() {}

// RecordCacheMiss is a no-op.
func (m *NopMetrics) RecordCacheMiss() {}

// RecordAuthAttempt is a no-op.
func (m *NopMetrics) RecordAuthAttempt(_, _ string) {}

// RecordError is a no-op.
func (m *NopMetrics) RecordError(_ string) {}

// MetricsRecorder defines the interface for recording Vault metrics.
type MetricsRecorder interface {
	RecordRequest(operation, status string, duration time.Duration)
	SetTokenTTL(ttl float64)
	RecordCacheHit()
	RecordCacheMiss()
	RecordAuthAttempt(method, status string)
	RecordError(errorType string)
}

// Ensure implementations satisfy the interface.
var (
	_ MetricsRecorder = (*Metrics)(nil)
	_ MetricsRecorder = (*NopMetrics)(nil)
)
