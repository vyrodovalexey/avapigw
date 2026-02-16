// Package router provides HTTP routing functionality for the API Gateway.
package router

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// regexCacheMetrics contains Prometheus metrics for the regex cache.
type regexCacheMetrics struct {
	cacheHits      prometheus.Counter
	cacheMisses    prometheus.Counter
	cacheEvictions prometheus.Counter
	cacheSize      prometheus.Gauge
}

var (
	regexCacheMetricsInstance *regexCacheMetrics
	regexCacheMetricsOnce     sync.Once
)

// getRegexCacheMetrics returns the singleton regex cache metrics instance.
func getRegexCacheMetrics() *regexCacheMetrics {
	regexCacheMetricsOnce.Do(func() {
		regexCacheMetricsInstance = &regexCacheMetrics{
			cacheHits: promauto.NewCounter(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "router",
					Name:      "regex_cache_hits_total",
					Help:      "Total number of regex cache hits",
				},
			),
			cacheMisses: promauto.NewCounter(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "router",
					Name:      "regex_cache_misses_total",
					Help:      "Total number of regex cache misses",
				},
			),
			cacheEvictions: promauto.NewCounter(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "router",
					Name:      "regex_cache_evictions_total",
					Help:      "Total number of regex cache evictions",
				},
			),
			cacheSize: promauto.NewGauge(
				prometheus.GaugeOpts{
					Namespace: "gateway",
					Subsystem: "router",
					Name:      "regex_cache_size",
					Help:      "Current number of entries in the regex cache",
				},
			),
		}
	})
	return regexCacheMetricsInstance
}
