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
