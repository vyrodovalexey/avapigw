// Package metrics provides Prometheus metrics for GraphQL operations.
package metrics

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics contains Prometheus metrics for GraphQL operations.
type Metrics struct {
	requestsTotal        *prometheus.CounterVec
	requestDuration      *prometheus.HistogramVec
	errorsTotal          *prometheus.CounterVec
	depthLimitExceeded   prometheus.Counter
	complexityExceeded   prometheus.Counter
	introspectionBlocked prometheus.Counter
	activeSubscriptions  prometheus.Gauge
	queryDepth           *prometheus.HistogramVec
	queryComplexity      *prometheus.HistogramVec
}

var (
	defaultMetrics     *Metrics
	defaultMetricsOnce sync.Once
)

// InitMetrics initializes the singleton GraphQL metrics instance with the given
// Prometheus registerer. If registerer is nil, metrics are registered with the
// default registerer. Must be called before GetMetrics; subsequent calls are no-ops.
func InitMetrics(registerer prometheus.Registerer) {
	defaultMetricsOnce.Do(func() {
		if registerer == nil {
			registerer = prometheus.DefaultRegisterer
		}
		defaultMetrics = newMetricsWithFactory(promauto.With(registerer))
	})
}

// GetMetrics returns the singleton GraphQL metrics instance.
// If InitMetrics has not been called, metrics are lazily initialized
// with the default registerer.
func GetMetrics() *Metrics {
	InitMetrics(nil)
	return defaultMetrics
}

// newMetricsWithFactory creates GraphQL metrics using the given promauto factory.
func newMetricsWithFactory(factory promauto.Factory) *Metrics {
	return &Metrics{
		requestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw",
				Subsystem: "graphql",
				Name:      "requests_total",
				Help:      "Total number of GraphQL requests",
			},
			[]string{"backend", "operation_type", "status_code"},
		),
		requestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "avapigw",
				Subsystem: "graphql",
				Name:      "request_duration_seconds",
				Help:      "GraphQL request duration in seconds",
				Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
			},
			[]string{"backend", "operation_type"},
		),
		errorsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw",
				Subsystem: "graphql",
				Name:      "errors_total",
				Help:      "Total number of GraphQL errors",
			},
			[]string{"backend", "operation_type", "error_type"},
		),
		depthLimitExceeded: factory.NewCounter(
			prometheus.CounterOpts{
				Namespace: "avapigw",
				Subsystem: "graphql",
				Name:      "depth_limit_exceeded_total",
				Help:      "Total number of queries rejected due to depth limit",
			},
		),
		complexityExceeded: factory.NewCounter(
			prometheus.CounterOpts{
				Namespace: "avapigw",
				Subsystem: "graphql",
				Name:      "complexity_limit_exceeded_total",
				Help:      "Total number of queries rejected due to complexity limit",
			},
		),
		introspectionBlocked: factory.NewCounter(
			prometheus.CounterOpts{
				Namespace: "avapigw",
				Subsystem: "graphql",
				Name:      "introspection_blocked_total",
				Help:      "Total number of introspection queries blocked",
			},
		),
		activeSubscriptions: factory.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "avapigw",
				Subsystem: "graphql",
				Name:      "active_subscriptions",
				Help:      "Number of active GraphQL subscriptions",
			},
		),
		queryDepth: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "avapigw",
				Subsystem: "graphql",
				Name:      "query_depth",
				Help:      "Distribution of GraphQL query depths",
				Buckets:   []float64{1, 2, 3, 5, 7, 10, 15, 20, 30, 50},
			},
			[]string{"operation_type"},
		),
		queryComplexity: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "avapigw",
				Subsystem: "graphql",
				Name:      "query_complexity",
				Help:      "Distribution of GraphQL query complexity scores",
				Buckets:   []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000},
			},
			[]string{"operation_type"},
		),
	}
}

// InitVecMetrics pre-populates all vector metrics with common label combinations
// so they appear on /metrics immediately with zero values.
func InitVecMetrics() {
	m := GetMetrics()

	operationTypes := []string{"query", "mutation", "subscription"}
	statusCodes := []string{"200", "400", "500"}
	errorTypes := []string{
		"backend_not_found", "transport_error", "request_creation_failed",
		"depth_exceeded", "complexity_exceeded", "introspection_blocked",
	}

	for _, op := range operationTypes {
		for _, sc := range statusCodes {
			m.requestsTotal.WithLabelValues("", op, sc)
		}
		m.requestDuration.WithLabelValues("", op)
		m.queryDepth.WithLabelValues(op)
		m.queryComplexity.WithLabelValues(op)
		for _, et := range errorTypes {
			m.errorsTotal.WithLabelValues("", op, et)
		}
	}
}

// RecordRequest records a GraphQL request metric.
func (m *Metrics) RecordRequest(backend, operationType string, statusCode int, duration time.Duration) {
	m.requestsTotal.WithLabelValues(backend, operationType, strconv.Itoa(statusCode)).Inc()
	m.requestDuration.WithLabelValues(backend, operationType).Observe(duration.Seconds())
}

// RecordError records a GraphQL error metric.
func (m *Metrics) RecordError(backend, operationType, errorType string) {
	m.errorsTotal.WithLabelValues(backend, operationType, errorType).Inc()
}

// RecordDepthLimitExceeded records a depth limit exceeded event.
func (m *Metrics) RecordDepthLimitExceeded() {
	m.depthLimitExceeded.Inc()
}

// RecordComplexityExceeded records a complexity limit exceeded event.
func (m *Metrics) RecordComplexityExceeded() {
	m.complexityExceeded.Inc()
}

// RecordIntrospectionBlocked records an introspection blocked event.
func (m *Metrics) RecordIntrospectionBlocked() {
	m.introspectionBlocked.Inc()
}

// SetActiveSubscriptions sets the number of active subscriptions.
func (m *Metrics) SetActiveSubscriptions(count float64) {
	m.activeSubscriptions.Set(count)
}

// RecordQueryDepth records the depth of a GraphQL query.
func (m *Metrics) RecordQueryDepth(operationType string, depth float64) {
	m.queryDepth.WithLabelValues(operationType).Observe(depth)
}

// RecordQueryComplexity records the complexity of a GraphQL query.
func (m *Metrics) RecordQueryComplexity(operationType string, complexity float64) {
	m.queryComplexity.WithLabelValues(operationType).Observe(complexity)
}
