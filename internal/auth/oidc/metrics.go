package oidc

import (
	"errors"
	"sync"
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
	for _, status := range []string{"success", "error"} {
		for _, provider := range []string{"default"} {
			m.discoveryTotal.WithLabelValues(status, provider)
			m.tokenValidationTotal.WithLabelValues(status, provider)
			m.tokenValidationDuration.WithLabelValues(status, provider)
			m.introspectionTotal.WithLabelValues(status, provider)
			m.introspectionDuration.WithLabelValues(status, provider)
			m.userinfoTotal.WithLabelValues(status, provider)
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
// It uses Register (not MustRegister) to gracefully handle duplicate
// registration that can occur when providers are recreated on config
// reload. AlreadyRegisteredError is silently ignored.
func (m *Metrics) MustRegister(registry *prometheus.Registry) {
	for _, c := range []prometheus.Collector{
		m.discoveryTotal,
		m.tokenValidationTotal,
		m.tokenValidationDuration,
		m.introspectionTotal,
		m.introspectionDuration,
		m.userinfoTotal,
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
