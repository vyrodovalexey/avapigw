package rbac

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for RBAC operations.
type Metrics struct {
	evaluationTotal    *prometheus.CounterVec
	evaluationDuration *prometheus.HistogramVec
	policyCount        prometheus.Gauge
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
			Subsystem: "rbac",
			Name:      "evaluation_total",
			Help:      "Total number of RBAC evaluations",
		},
		[]string{"policy", "decision"},
	)

	m.evaluationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "rbac",
			Name:      "evaluation_duration_seconds",
			Help:      "RBAC evaluation duration in seconds",
			Buckets:   []float64{.00001, .00005, .0001, .0005, .001, .005, .01, .025, .05, .1},
		},
		[]string{"policy", "decision"},
	)

	m.policyCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "rbac",
			Name:      "policy_count",
			Help:      "Number of RBAC policies",
		},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.evaluationTotal,
		m.evaluationDuration,
		m.policyCount,
	)

	return m
}

// RecordEvaluation records an RBAC evaluation.
func (m *Metrics) RecordEvaluation(policy, decision string, duration time.Duration) {
	m.evaluationTotal.WithLabelValues(policy, decision).Inc()
	m.evaluationDuration.WithLabelValues(policy, decision).Observe(duration.Seconds())
}

// SetPolicyCount sets the policy count.
func (m *Metrics) SetPolicyCount(count int) {
	m.policyCount.Set(float64(count))
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
	)
}
