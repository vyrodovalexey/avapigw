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

// RouterMetrics provides an exported handle for registering the
// router's regex-cache metrics with an external Prometheus registry.
type RouterMetrics struct {
	m *regexCacheMetrics
}

// GetRouterMetrics returns the exported router metrics handle backed
// by the singleton regex cache metrics instance.
func GetRouterMetrics() *RouterMetrics {
	return &RouterMetrics{m: getRegexCacheMetrics()}
}

// MustRegister registers all router metric collectors with the given
// Prometheus registry. This is needed because promauto registers
// metrics with the default global registry, but the gateway serves
// /metrics from a custom registry. Calling MustRegister bridges the
// two so router metrics appear on the gateway's metrics endpoint.
func (rm *RouterMetrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		rm.m.cacheHits,
		rm.m.cacheMisses,
		rm.m.cacheEvictions,
		rm.m.cacheSize,
	)
}

// Init pre-initializes metrics so they appear in /metrics output
// immediately after startup. For router metrics all collectors are
// plain counters/gauges (no label vectors), so this is a no-op
// included for API consistency with other subsystem metrics.
func (rm *RouterMetrics) Init() {
	// No-op: all router metrics are scalar (no label vectors) and
	// are emitted by Prometheus immediately after registration.
}
