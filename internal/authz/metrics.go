package authz

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics contains authorization metrics.
type Metrics struct {
	registerer prometheus.Registerer

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
// Metrics are registered with prometheus.DefaultRegisterer so they are
// automatically exposed on the default /metrics endpoint.
func NewMetrics(namespace string) *Metrics {
	return NewMetricsWithRegisterer(namespace, prometheus.DefaultRegisterer)
}

// NewMetricsWithRegisterer creates a new Metrics instance with a custom registerer.
// This is useful for registering metrics with the gateway's custom registry
// so they appear on the gateway's /metrics endpoint.
func NewMetricsWithRegisterer(namespace string, registerer prometheus.Registerer) *Metrics {
	if namespace == "" {
		namespace = "gateway"
	}

	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}

	m := &Metrics{
		registerer: registerer,
	}

	m.evaluationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "authz",
			Name:      "evaluation_total",
			Help:      "Total number of authorization evaluations",
		},
		[]string{"engine", "result"},
	)

	m.evaluationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "authz",
			Name:      "evaluation_duration_seconds",
			Help:      "Authorization evaluation duration in seconds",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
		},
		[]string{"engine"},
	)

	m.decisionTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "authz",
			Name:      "decision_total",
			Help:      "Total number of authorization decisions",
		},
		[]string{"decision", "policy"},
	)

	m.cacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "authz",
			Name:      "cache_hits_total",
			Help:      "Total number of authorization cache hits",
		},
	)

	m.cacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "authz",
			Name:      "cache_misses_total",
			Help:      "Total number of authorization cache misses",
		},
	)

	m.externalRequestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "authz",
			Name:      "external_request_total",
			Help:      "Total number of external authorization requests",
		},
		[]string{"provider", "result"},
	)

	m.externalRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "authz",
			Name:      "external_request_duration_seconds",
			Help:      "External authorization request duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"provider"},
	)

	m.policyCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "authz",
			Name:      "policy_count",
			Help:      "Number of loaded authorization policies",
		},
		[]string{"engine"},
	)

	// Register all metrics with the provided registerer, ignoring duplicates.
	collectors := []prometheus.Collector{
		m.evaluationTotal,
		m.evaluationDuration,
		m.decisionTotal,
		m.cacheHits,
		m.cacheMisses,
		m.externalRequestTotal,
		m.externalRequestDuration,
		m.policyCount,
	}
	for _, c := range collectors {
		_ = registerer.Register(c)
	}

	return m
}

// Init pre-initializes common label combinations with zero values so that
// metrics appear in /metrics output immediately after startup. Prometheus
// *Vec types only emit metric lines after WithLabelValues() is called at
// least once. This method is idempotent and safe to call multiple times.
func (m *Metrics) Init() {
	if m == nil {
		return
	}
	for _, engine := range []string{"rbac", "abac", "external", "combined"} {
		for _, result := range []string{"allowed", "denied", "error"} {
			m.evaluationTotal.WithLabelValues(engine, result)
		}
		m.evaluationDuration.WithLabelValues(engine)
	}
	for _, decision := range []string{"allowed", "denied"} {
		m.decisionTotal.WithLabelValues(decision, "default")
	}
	for _, engine := range []string{"rbac", "abac"} {
		m.policyCount.WithLabelValues(engine)
	}
	for _, result := range []string{"allowed", "denied", "error"} {
		m.externalRequestTotal.WithLabelValues("opa", result)
	}
	m.externalRequestDuration.WithLabelValues("opa")
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
