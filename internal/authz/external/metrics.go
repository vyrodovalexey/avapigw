package external

import (
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for external authorization operations.
type Metrics struct {
	requestTotal    *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	cacheHits       prometheus.Counter
	cacheMisses     prometheus.Counter
	errors          *prometheus.CounterVec
	registry        *prometheus.Registry
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
	for _, typ := range []string{"http", "grpc"} {
		for _, decision := range []string{"allow", "deny"} {
			m.requestTotal.WithLabelValues(typ, decision)
			m.requestDuration.WithLabelValues(typ, decision)
		}
	}
	for _, typ := range []string{"http", "grpc"} {
		for _, reason := range []string{"timeout", "connection_error", "invalid_response"} {
			m.errors.WithLabelValues(typ, reason)
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

	m.requestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "external_authz",
			Name:      "request_total",
			Help:      "Total number of external authorization requests",
		},
		[]string{"type", "decision"},
	)

	m.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "external_authz",
			Name:      "request_duration_seconds",
			Help:      "External authorization request duration in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
		[]string{"type", "decision"},
	)

	m.cacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "external_authz",
			Name:      "cache_hits_total",
			Help:      "Total number of cache hits",
		},
	)

	m.cacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "external_authz",
			Name:      "cache_misses_total",
			Help:      "Total number of cache misses",
		},
	)

	m.errors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "external_authz",
			Name:      "errors_total",
			Help:      "Total number of errors",
		},
		[]string{"type", "reason"},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.requestTotal,
		m.requestDuration,
		m.cacheHits,
		m.cacheMisses,
		m.errors,
	)

	return m
}

// RecordRequest records an external authorization request.
func (m *Metrics) RecordRequest(authzType, decision string, duration time.Duration) {
	m.requestTotal.WithLabelValues(authzType, decision).Inc()
	m.requestDuration.WithLabelValues(authzType, decision).Observe(duration.Seconds())
}

// RecordCacheHit records a cache hit.
func (m *Metrics) RecordCacheHit() {
	m.cacheHits.Inc()
}

// RecordCacheMiss records a cache miss.
func (m *Metrics) RecordCacheMiss() {
	m.cacheMisses.Inc()
}

// RecordError records an error.
func (m *Metrics) RecordError(authzType, reason string) {
	m.errors.WithLabelValues(authzType, reason).Inc()
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
		m.requestTotal,
		m.requestDuration,
		m.cacheHits,
		m.cacheMisses,
		m.errors,
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
