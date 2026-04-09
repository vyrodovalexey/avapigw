package openapi

import (
	"github.com/prometheus/client_golang/prometheus"
)

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
				Namespace: "gateway",
				Subsystem: "openapi_validation",
				Name:      "requests_total",
				Help:      "Total number of requests validated against OpenAPI spec.",
			},
			[]string{"route", "result"},
		),
		duration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "gateway",
				Subsystem: "openapi_validation",
				Name:      "duration_seconds",
				Help:      "Duration of OpenAPI request validation in seconds.",
				Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25},
			},
			[]string{"route"},
		),
		errorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "openapi_validation",
				Name:      "errors_total",
				Help:      "Total number of OpenAPI validation errors.",
			},
			[]string{"route", "error_type"},
		),
	}

	m.register()
	return m
}

// register registers all metrics with the registerer.
func (m *Metrics) register() {
	if m.registeredOnce {
		return
	}
	m.registeredOnce = true

	m.registerer.MustRegister(
		m.requestsTotal,
		m.duration,
		m.errorsTotal,
	)
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
