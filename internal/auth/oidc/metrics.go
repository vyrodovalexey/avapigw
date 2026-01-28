package oidc

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for OIDC operations.
type Metrics struct {
	discoveryTotal          *prometheus.CounterVec
	tokenValidationTotal    *prometheus.CounterVec
	tokenValidationDuration *prometheus.HistogramVec
	introspectionTotal      *prometheus.CounterVec
	introspectionDuration   *prometheus.HistogramVec
	userinfoTotal           *prometheus.CounterVec
	registry                *prometheus.Registry
}

// NewMetrics creates a new Metrics instance.
func NewMetrics(namespace string) *Metrics {
	if namespace == "" {
		namespace = "gateway"
	}

	m := &Metrics{
		registry: prometheus.NewRegistry(),
	}

	m.discoveryTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "oidc",
			Name:      "discovery_total",
			Help:      "Total number of OIDC discovery requests",
		},
		[]string{"status", "provider"},
	)

	m.tokenValidationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "oidc",
			Name:      "token_validation_total",
			Help:      "Total number of OIDC token validation attempts",
		},
		[]string{"status", "provider"},
	)

	m.tokenValidationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "oidc",
			Name:      "token_validation_duration_seconds",
			Help:      "OIDC token validation duration in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
		[]string{"status", "provider"},
	)

	m.introspectionTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "oidc",
			Name:      "introspection_total",
			Help:      "Total number of token introspection requests",
		},
		[]string{"status", "provider"},
	)

	m.introspectionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "oidc",
			Name:      "introspection_duration_seconds",
			Help:      "Token introspection duration in seconds",
			Buckets:   []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
		[]string{"status", "provider"},
	)

	m.userinfoTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "oidc",
			Name:      "userinfo_total",
			Help:      "Total number of userinfo requests",
		},
		[]string{"status", "provider"},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.discoveryTotal,
		m.tokenValidationTotal,
		m.tokenValidationDuration,
		m.introspectionTotal,
		m.introspectionDuration,
		m.userinfoTotal,
	)

	return m
}

// RecordDiscovery records a discovery request.
func (m *Metrics) RecordDiscovery(status, provider string) {
	m.discoveryTotal.WithLabelValues(status, provider).Inc()
}

// RecordTokenValidation records a token validation attempt.
func (m *Metrics) RecordTokenValidation(status, provider string, duration time.Duration) {
	m.tokenValidationTotal.WithLabelValues(status, provider).Inc()
	m.tokenValidationDuration.WithLabelValues(status, provider).Observe(duration.Seconds())
}

// RecordIntrospection records a token introspection request.
func (m *Metrics) RecordIntrospection(status, provider string, duration time.Duration) {
	m.introspectionTotal.WithLabelValues(status, provider).Inc()
	m.introspectionDuration.WithLabelValues(status, provider).Observe(duration.Seconds())
}

// RecordUserinfo records a userinfo request.
func (m *Metrics) RecordUserinfo(status, provider string) {
	m.userinfoTotal.WithLabelValues(status, provider).Inc()
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// MustRegister registers the metrics with the given registry.
func (m *Metrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		m.discoveryTotal,
		m.tokenValidationTotal,
		m.tokenValidationDuration,
		m.introspectionTotal,
		m.introspectionDuration,
		m.userinfoTotal,
	)
}
