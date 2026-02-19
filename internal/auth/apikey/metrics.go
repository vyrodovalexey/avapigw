package apikey

import (
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for API key operations.
type Metrics struct {
	validationTotal    *prometheus.CounterVec
	validationDuration *prometheus.HistogramVec
	cacheHits          prometheus.Counter
	cacheMisses        prometheus.Counter
	registry           *prometheus.Registry
}

var (
	sharedMetrics     *Metrics
	sharedMetricsOnce sync.Once
)

// GetSharedMetrics returns the singleton Metrics instance.
func GetSharedMetrics() *Metrics {
	sharedMetricsOnce.Do(func() {
		sharedMetrics = NewMetrics("gateway")
	})
	return sharedMetrics
}

// Init pre-initializes common label combinations with zero values so that
// metrics appear in /metrics output immediately after startup. Prometheus
// *Vec types only emit metric lines after WithLabelValues() is called at
// least once. This method is idempotent and safe to call multiple times.
func (m *Metrics) Init() {
	reasons := []string{
		"valid", "empty_key", "not_found",
		"store_error", "invalid", "disabled", "expired",
	}
	for _, status := range []string{"success", "error"} {
		for _, reason := range reasons {
			m.validationTotal.WithLabelValues(status, reason)
			m.validationDuration.WithLabelValues(status, reason)
		}
	}
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
			Subsystem: "apikey",
			Name:      "validation_total",
			Help:      "Total number of API key validation attempts",
		},
		[]string{"status", "reason"},
	)

	m.validationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "apikey",
			Name:      "validation_duration_seconds",
			Help:      "API key validation duration in seconds",
			Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"status", "reason"},
	)

	m.cacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "apikey",
			Name:      "cache_hits_total",
			Help:      "Total number of API key cache hits",
		},
	)

	m.cacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "apikey",
			Name:      "cache_misses_total",
			Help:      "Total number of API key cache misses",
		},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.validationTotal,
		m.validationDuration,
		m.cacheHits,
		m.cacheMisses,
	)

	return m
}

// RecordValidation records an API key validation attempt.
func (m *Metrics) RecordValidation(status, reason string, duration time.Duration) {
	m.validationTotal.WithLabelValues(status, reason).Inc()
	m.validationDuration.WithLabelValues(status, reason).Observe(duration.Seconds())
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
// It uses Register (not MustRegister) to gracefully handle duplicate
// registration that can occur when providers are recreated on config
// reload. AlreadyRegisteredError is silently ignored.
func (m *Metrics) MustRegister(registry *prometheus.Registry) {
	for _, c := range []prometheus.Collector{
		m.validationTotal,
		m.validationDuration,
		m.cacheHits,
		m.cacheMisses,
	} {
		if err := registry.Register(c); err != nil {
			if !isAlreadyRegistered(err) {
				panic(err)
			}
		}
	}
}

// isAlreadyRegistered returns true if the error indicates the
// collector was already registered with the registry.
func isAlreadyRegistered(err error) bool {
	var are prometheus.AlreadyRegisteredError
	return errors.As(err, &are)
}
