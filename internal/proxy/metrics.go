// Package proxy provides HTTP reverse proxy functionality.
package proxy

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// proxyMetrics contains Prometheus metrics for proxy operations.
type proxyMetrics struct {
	errorsTotal        *prometheus.CounterVec
	backendDuration    *prometheus.HistogramVec
	cryptoRandFailures prometheus.Counter
}

var (
	proxyMetricsInstance *proxyMetrics
	proxyMetricsOnce     sync.Once
)

// initProxyMetrics initializes the singleton proxy metrics instance
// with the given Prometheus registry. If registry is nil, metrics are
// registered with the default registerer. Must be called before
// getProxyMetrics; subsequent calls are no-ops (sync.Once).
func initProxyMetrics(registry *prometheus.Registry) {
	proxyMetricsOnce.Do(func() {
		var registerer prometheus.Registerer
		if registry != nil {
			registerer = registry
		} else {
			registerer = prometheus.DefaultRegisterer
		}
		factory := promauto.With(registerer)
		proxyMetricsInstance = &proxyMetrics{
			errorsTotal: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "proxy",
					Name:      "errors_total",
					Help: "Total number of " +
						"proxy errors",
				},
				[]string{"backend", "error_type"},
			),
			backendDuration: factory.NewHistogramVec(
				prometheus.HistogramOpts{
					Namespace: "gateway",
					Subsystem: "proxy",
					Name: "backend_duration" +
						"_seconds",
					Help: "Duration of backend " +
						"proxy requests",
					Buckets: []float64{
						.001, .005, .01, .025,
						.05, .1, .25, .5,
						1, 2.5, 5, 10,
					},
				},
				[]string{"backend"},
			),
			cryptoRandFailures: factory.NewCounter(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "proxy",
					Name:      "crypto_rand_failures_total",
					Help:      "Total number of crypto/rand failures with math/rand fallback",
				},
			),
		}
	})
}

// initProxyVecMetrics pre-populates common label combinations with
// zero values so that proxy Vec metrics appear in /metrics output
// immediately after startup. Must be called after initProxyMetrics.
func initProxyVecMetrics() {
	m := getProxyMetrics()

	errorTypes := []string{
		"connection_refused",
		"timeout",
		"bad_gateway",
		"service_unavailable",
	}
	for _, et := range errorTypes {
		m.errorsTotal.WithLabelValues("default", et)
	}

	m.backendDuration.WithLabelValues("default")
}

// getProxyMetrics returns the singleton proxy metrics instance.
// If initProxyMetrics has not been called, metrics are lazily
// initialized with the default registerer.
func getProxyMetrics() *proxyMetrics {
	initProxyMetrics(nil)
	return proxyMetricsInstance
}
