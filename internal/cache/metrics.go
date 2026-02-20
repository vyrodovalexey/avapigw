// Package cache provides caching capabilities for the API Gateway.
package cache

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// CacheMetrics holds Prometheus metrics for cache operations.
type CacheMetrics struct {
	hitsTotal         *prometheus.CounterVec
	missesTotal       *prometheus.CounterVec
	evictionsTotal    *prometheus.CounterVec
	sizeGauge         *prometheus.GaugeVec
	operationDuration *prometheus.HistogramVec
	errorsTotal       *prometheus.CounterVec
}

var (
	cacheMetricsInstance *CacheMetrics
	cacheMetricsOnce     sync.Once
)

// GetCacheMetrics returns the singleton cache metrics instance.
func GetCacheMetrics() *CacheMetrics {
	cacheMetricsOnce.Do(func() {
		cacheMetricsInstance = newCacheMetrics()
	})
	return cacheMetricsInstance
}

// MustRegister registers all cache metric collectors with the given
// Prometheus registry. This is needed because promauto registers
// metrics with the default global registry, but the gateway serves
// /metrics from a custom registry. Calling MustRegister bridges the
// two so cache metrics appear on the gateway's metrics endpoint.
func (m *CacheMetrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		m.hitsTotal,
		m.missesTotal,
		m.evictionsTotal,
		m.sizeGauge,
		m.operationDuration,
		m.errorsTotal,
	)
}

// Init pre-initializes common label combinations with zero values so that
// metrics appear in /metrics output immediately after startup. Prometheus
// *Vec types only emit metric lines after WithLabelValues() is called at
// least once. This method is idempotent and safe to call multiple times.
func (m *CacheMetrics) Init() {
	for _, backend := range []string{"memory", "redis"} {
		m.hitsTotal.WithLabelValues(backend)
		m.missesTotal.WithLabelValues(backend)
		m.evictionsTotal.WithLabelValues(backend)
		m.sizeGauge.WithLabelValues(backend)
		for _, op := range []string{"get", "set", "delete", "exists"} {
			m.operationDuration.WithLabelValues(backend, op)
			m.errorsTotal.WithLabelValues(backend, op)
		}
	}
}

func newCacheMetrics() *CacheMetrics {
	return &CacheMetrics{
		hitsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "cache",
				Name:      "hits_total",
				Help: "Total number of " +
					"cache hits",
			},
			[]string{"backend"},
		),
		missesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "cache",
				Name:      "misses_total",
				Help: "Total number of " +
					"cache misses",
			},
			[]string{"backend"},
		),
		evictionsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "cache",
				Name:      "evictions_total",
				Help: "Total number of " +
					"cache evictions",
			},
			[]string{"backend"},
		),
		sizeGauge: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "gateway",
				Subsystem: "cache",
				Name:      "size",
				Help: "Current number of " +
					"items in cache",
			},
			[]string{"backend"},
		),
		operationDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "gateway",
				Subsystem: "cache",
				Name: "operation_duration" +
					"_seconds",
				Help: "Duration of cache " +
					"operations",
				Buckets: []float64{
					.0001, .0005, .001, .005,
					.01, .025, .05, .1,
				},
			},
			[]string{"backend", "operation"},
		),
		errorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "cache",
				Name:      "errors_total",
				Help: "Total number of " +
					"cache errors",
			},
			[]string{"backend", "operation"},
		),
	}
}
