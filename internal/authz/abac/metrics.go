package abac

import (
	"errors"
	"sync"
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
	for _, policy := range []string{"default"} {
		for _, decision := range []string{"allow", "deny"} {
			m.evaluationTotal.WithLabelValues(policy, decision)
			m.evaluationDuration.WithLabelValues(policy, decision)
		}
	}
	m.policyCount.Set(0)
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
// It uses Register (not MustRegister) to gracefully handle duplicate
// registration that can occur when providers are recreated on config
// reload. AlreadyRegisteredError is silently ignored.
func (m *Metrics) MustRegister(registry *prometheus.Registry) {
	for _, c := range []prometheus.Collector{
		m.evaluationTotal,
		m.evaluationDuration,
		m.policyCount,
		m.compilationErrors,
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
