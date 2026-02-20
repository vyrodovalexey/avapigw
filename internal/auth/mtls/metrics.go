package mtls

import (
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for mTLS operations.
type Metrics struct {
	validationTotal    *prometheus.CounterVec
	validationDuration *prometheus.HistogramVec
	revocationChecks   *prometheus.CounterVec
	registry           *prometheus.Registry
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
		for _, reason := range []string{"valid", "expired", "revoked", "untrusted", "invalid_chain"} {
			m.validationTotal.WithLabelValues(status, reason)
			m.validationDuration.WithLabelValues(status, reason)
		}
	}
	for _, typ := range []string{"crl", "ocsp"} {
		for _, status := range []string{"success", "error"} {
			m.revocationChecks.WithLabelValues(typ, status)
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

	m.validationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "mtls",
			Name:      "validation_total",
			Help:      "Total number of mTLS validation attempts",
		},
		[]string{"status", "reason"},
	)

	m.validationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "mtls",
			Name:      "validation_duration_seconds",
			Help:      "mTLS validation duration in seconds",
			Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"status", "reason"},
	)

	m.revocationChecks = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "mtls",
			Name:      "revocation_checks_total",
			Help:      "Total number of certificate revocation checks",
		},
		[]string{"type", "status"},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.validationTotal,
		m.validationDuration,
		m.revocationChecks,
	)

	return m
}

// RecordValidation records an mTLS validation attempt.
func (m *Metrics) RecordValidation(status, reason string, duration time.Duration) {
	m.validationTotal.WithLabelValues(status, reason).Inc()
	m.validationDuration.WithLabelValues(status, reason).Observe(duration.Seconds())
}

// RecordRevocationCheck records a revocation check.
func (m *Metrics) RecordRevocationCheck(checkType, status string) {
	m.revocationChecks.WithLabelValues(checkType, status).Inc()
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
		m.validationTotal,
		m.validationDuration,
		m.revocationChecks,
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
