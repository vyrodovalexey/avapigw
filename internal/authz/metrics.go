package authz

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics contains authorization metrics.
type Metrics struct {
	// evaluationTotal counts total authorization evaluations.
	evaluationTotal *prometheus.CounterVec

	// evaluationDuration measures authorization evaluation duration.
	evaluationDuration *prometheus.HistogramVec

	// decisionTotal counts authorization decisions.
	decisionTotal *prometheus.CounterVec

	// cacheHits counts cache hits.
	cacheHits prometheus.Counter

	// cacheMisses counts cache misses.
	cacheMisses prometheus.Counter

	// externalRequestTotal counts external authorization requests.
	externalRequestTotal *prometheus.CounterVec

	// externalRequestDuration measures external authorization request duration.
	externalRequestDuration *prometheus.HistogramVec

	// policyCount tracks the number of loaded policies.
	policyCount *prometheus.GaugeVec
}

// NewMetrics creates new authorization metrics.
func NewMetrics(namespace string) *Metrics {
	return &Metrics{
		evaluationTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "authz",
				Name:      "evaluation_total",
				Help:      "Total number of authorization evaluations",
			},
			[]string{"engine", "result"},
		),
		evaluationDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: "authz",
				Name:      "evaluation_duration_seconds",
				Help:      "Authorization evaluation duration in seconds",
				Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
			},
			[]string{"engine"},
		),
		decisionTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "authz",
				Name:      "decision_total",
				Help:      "Total number of authorization decisions",
			},
			[]string{"decision", "policy"},
		),
		cacheHits: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "authz",
				Name:      "cache_hits_total",
				Help:      "Total number of authorization cache hits",
			},
		),
		cacheMisses: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "authz",
				Name:      "cache_misses_total",
				Help:      "Total number of authorization cache misses",
			},
		),
		externalRequestTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "authz",
				Name:      "external_request_total",
				Help:      "Total number of external authorization requests",
			},
			[]string{"provider", "result"},
		),
		externalRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: "authz",
				Name:      "external_request_duration_seconds",
				Help:      "External authorization request duration in seconds",
				Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
			},
			[]string{"provider"},
		),
		policyCount: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: "authz",
				Name:      "policy_count",
				Help:      "Number of loaded authorization policies",
			},
			[]string{"engine"},
		),
	}
}

// RecordEvaluation records an authorization evaluation.
func (m *Metrics) RecordEvaluation(engine, result string, duration time.Duration) {
	if m == nil || m.evaluationTotal == nil {
		return
	}
	m.evaluationTotal.WithLabelValues(engine, result).Inc()
	m.evaluationDuration.WithLabelValues(engine).Observe(duration.Seconds())
}

// RecordDecision records an authorization decision.
func (m *Metrics) RecordDecision(decision, policy string) {
	if m == nil || m.decisionTotal == nil {
		return
	}
	m.decisionTotal.WithLabelValues(decision, policy).Inc()
}

// RecordCacheHit records a cache hit.
func (m *Metrics) RecordCacheHit() {
	if m == nil || m.cacheHits == nil {
		return
	}
	m.cacheHits.Inc()
}

// RecordCacheMiss records a cache miss.
func (m *Metrics) RecordCacheMiss() {
	if m == nil || m.cacheMisses == nil {
		return
	}
	m.cacheMisses.Inc()
}

// RecordExternalRequest records an external authorization request.
func (m *Metrics) RecordExternalRequest(provider, result string, duration time.Duration) {
	if m == nil || m.externalRequestTotal == nil {
		return
	}
	m.externalRequestTotal.WithLabelValues(provider, result).Inc()
	m.externalRequestDuration.WithLabelValues(provider).Observe(duration.Seconds())
}

// SetPolicyCount sets the policy count for an engine.
func (m *Metrics) SetPolicyCount(engine string, count int) {
	if m == nil || m.policyCount == nil {
		return
	}
	m.policyCount.WithLabelValues(engine).Set(float64(count))
}
