package abac

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for ABAC operations.
type Metrics struct {
	evaluationTotal    *prometheus.CounterVec
	evaluationDuration *prometheus.HistogramVec
	policyCount        prometheus.Gauge
	compilationErrors  prometheus.Counter
	registry           *prometheus.Registry
}

// NewMetrics creates a new Metrics instance.
func NewMetrics(namespace string) *Metrics {
	if namespace == "" {
		namespace = "gateway"
	}

	m := &Metrics{
		registry: prometheus.NewRegistry(),
	}

	m.evaluationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "abac",
			Name:      "evaluation_total",
			Help:      "Total number of ABAC evaluations",
		},
		[]string{"policy", "decision"},
	)

	m.evaluationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "abac",
			Name:      "evaluation_duration_seconds",
			Help:      "ABAC evaluation duration in seconds",
			Buckets:   []float64{.00001, .00005, .0001, .0005, .001, .005, .01, .025, .05, .1},
		},
		[]string{"policy", "decision"},
	)

	m.policyCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "abac",
			Name:      "policy_count",
			Help:      "Number of ABAC policies",
		},
	)

	m.compilationErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "abac",
			Name:      "compilation_errors_total",
			Help:      "Total number of CEL compilation errors",
		},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.evaluationTotal,
		m.evaluationDuration,
		m.policyCount,
		m.compilationErrors,
	)

	return m
}

// RecordEvaluation records an ABAC evaluation.
func (m *Metrics) RecordEvaluation(policy, decision string, duration time.Duration) {
	m.evaluationTotal.WithLabelValues(policy, decision).Inc()
	m.evaluationDuration.WithLabelValues(policy, decision).Observe(duration.Seconds())
}

// SetPolicyCount sets the policy count.
func (m *Metrics) SetPolicyCount(count int) {
	m.policyCount.Set(float64(count))
}

// RecordCompilationError records a compilation error.
func (m *Metrics) RecordCompilationError() {
	m.compilationErrors.Inc()
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// MustRegister registers the metrics with the given registry.
func (m *Metrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		m.evaluationTotal,
		m.evaluationDuration,
		m.policyCount,
		m.compilationErrors,
	)
}
