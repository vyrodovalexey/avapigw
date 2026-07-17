package openapi

import (
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Metric label constants.
const (
	metricsNamespace = "gateway"
	metricsSubsystem = "openapi_validation"
	labelRoute       = "route"
)

var (
	sharedMetrics     *Metrics
	sharedMetricsOnce sync.Once
)

// InitSharedMetrics initializes the process-wide shared OpenAPI validation
// metrics singleton with the given registerer (nil falls back to
// prometheus.DefaultRegisterer). It must be called with the gateway's custom
// registry before validation middleware is built so the
// gateway_openapi_validation_* series appear on the /metrics endpoint.
// Subsequent calls are no-ops and return the existing instance.
func InitSharedMetrics(registerer prometheus.Registerer) *Metrics {
	sharedMetricsOnce.Do(func() {
		sharedMetrics = NewMetrics(registerer)
	})
	return sharedMetrics
}

// GetSharedMetrics returns the shared OpenAPI validation metrics singleton,
// lazily initializing it with the default registerer when InitSharedMetrics
// has not been called (test/embedded use).
func GetSharedMetrics() *Metrics {
	return InitSharedMetrics(nil)
}

// Metrics holds Prometheus metrics for OpenAPI validation.
type Metrics struct {
	requestsTotal  *prometheus.CounterVec
	duration       *prometheus.HistogramVec
	errorsTotal    *prometheus.CounterVec
	registerer     prometheus.Registerer
	registeredOnce bool
}

// NewMetrics creates a new Metrics instance and registers it with the given registerer.
// If registerer is nil, prometheus.DefaultRegisterer is used.
func NewMetrics(registerer prometheus.Registerer) *Metrics {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}

	m := &Metrics{
		registerer: registerer,
		requestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "requests_total",
				Help:      "Total number of requests validated against OpenAPI spec.",
			},
			[]string{labelRoute, "result"},
		),
		duration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "duration_seconds",
				Help:      "Duration of OpenAPI request validation in seconds.",
				Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25},
			},
			[]string{labelRoute},
		),
		errorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "errors_total",
				Help:      "Total number of OpenAPI validation errors.",
			},
			[]string{labelRoute, "error_type"},
		),
	}

	m.register()
	return m
}

// register registers all metrics with the registerer. Duplicate
// registration (e.g. an explicit NewMetrics against the default registerer
// after the shared singleton already registered there) adopts the existing
// collector so recordings land on the registered series instead of
// panicking.
func (m *Metrics) register() {
	if m.registeredOnce {
		return
	}
	m.registeredOnce = true

	m.requestsTotal = registerOrReuseCounterVec(m.registerer, m.requestsTotal)
	m.duration = registerOrReuseHistogramVec(m.registerer, m.duration)
	m.errorsTotal = registerOrReuseCounterVec(m.registerer, m.errorsTotal)
}

// registerOrReuseCounterVec registers the counter vec, reusing the already
// registered collector on duplicate registration.
func registerOrReuseCounterVec(reg prometheus.Registerer, c *prometheus.CounterVec) *prometheus.CounterVec {
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
			return c
		}
		panic(err)
	}
	return c
}

// registerOrReuseHistogramVec registers the histogram vec, reusing the
// already registered collector on duplicate registration.
func registerOrReuseHistogramVec(reg prometheus.Registerer, h *prometheus.HistogramVec) *prometheus.HistogramVec {
	if err := reg.Register(h); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(*prometheus.HistogramVec); ok {
				return existing
			}
			return h
		}
		panic(err)
	}
	return h
}

// RecordSuccess records a successful validation.
func (m *Metrics) RecordSuccess(route string, durationSec float64) {
	m.requestsTotal.WithLabelValues(route, "success").Inc()
	m.duration.WithLabelValues(route).Observe(durationSec)
}

// RecordFailure records a failed validation.
func (m *Metrics) RecordFailure(route string, errorType string, durationSec float64) {
	m.requestsTotal.WithLabelValues(route, "failure").Inc()
	m.errorsTotal.WithLabelValues(route, errorType).Inc()
	m.duration.WithLabelValues(route).Observe(durationSec)
}
