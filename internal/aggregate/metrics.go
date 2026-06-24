package aggregate

import (
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metric namespacing constants.
const (
	namespaceGateway   = "gateway"
	subsystemAggregate = "aggregate"

	labelResult = "result"
	labelTarget = "target"

	resultSuccess = "success"
	resultFailure = "failure"
)

// Metrics holds the Prometheus collectors for aggregate fan-out observability.
//
// Cardinality is intentionally bounded: only the aggregate-level result label
// and the (operator-controlled, finite) target name label are used.
type Metrics struct {
	RequestsTotal       prometheus.Counter
	TargetsTotal        prometheus.Counter
	TargetErrorsTotal   *prometheus.CounterVec
	ResultsTotal        *prometheus.CounterVec
	DurationSeconds     prometheus.Histogram
	MergeDurationSecond prometheus.Histogram
	SpoolBytes          prometheus.Histogram
	SpoolErrorsTotal    prometheus.Counter

	enabled bool
}

var (
	defaultMetricsOnce sync.Once
	defaultMetrics     *Metrics
	nopMetricsOnce     sync.Once
	nopMetricsInstance *Metrics
)

// byteBuckets defines histogram buckets for spool body sizes:
// 1K, 10K, 100K, 1M, 10M, 100M.
var byteBuckets = prometheus.ExponentialBuckets(1024, 10, 6)

// NewMetrics creates a new Metrics instance registered via promauto on the
// default global registry.
func NewMetrics() *Metrics {
	return newMetricsWithFactory(promauto.With(prometheus.DefaultRegisterer))
}

// NewMetricsWith creates a new Metrics instance whose collectors are registered
// on the provided registry instead of the global default registerer. This is
// useful for tests and for embedding the aggregate metrics on a dedicated
// gateway registry without colliding with the process-wide default registry.
//
// When registry is nil it falls back to the default global registerer (matching
// NewMetrics).
func NewMetricsWith(registry *prometheus.Registry) *Metrics {
	registerer := prometheus.DefaultRegisterer
	if registry != nil {
		registerer = registry
	}
	return newMetricsWithFactory(promauto.With(registerer))
}

// newMetricsWithFactory builds all aggregate collectors via the given promauto
// factory, so the same construction logic backs both the global and the
// registry-scoped constructors.
func newMetricsWithFactory(factory promauto.Factory) *Metrics {
	return &Metrics{
		enabled: true,
		RequestsTotal: factory.NewCounter(prometheus.CounterOpts{
			Namespace: namespaceGateway,
			Subsystem: subsystemAggregate,
			Name:      "requests_total",
			Help:      "Total number of aggregate fan-out requests",
		}),
		TargetsTotal: factory.NewCounter(prometheus.CounterOpts{
			Namespace: namespaceGateway,
			Subsystem: subsystemAggregate,
			Name:      "targets_total",
			Help:      "Total number of target invocations across all aggregate requests",
		}),
		TargetErrorsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespaceGateway,
			Subsystem: subsystemAggregate,
			Name:      "target_errors_total",
			Help:      "Total number of failed target invocations by target",
		}, []string{labelTarget}),
		ResultsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespaceGateway,
			Subsystem: subsystemAggregate,
			Name:      "results_total",
			Help:      "Total number of aggregate results by outcome",
		}, []string{labelResult}),
		DurationSeconds: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespaceGateway,
			Subsystem: subsystemAggregate,
			Name:      "duration_seconds",
			Help:      "Aggregate fan-out duration in seconds",
			Buckets:   prometheus.DefBuckets,
		}),
		MergeDurationSecond: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespaceGateway,
			Subsystem: subsystemAggregate,
			Name:      "merge_duration_seconds",
			Help:      "Aggregate response merge duration in seconds",
			Buckets:   prometheus.DefBuckets,
		}),
		SpoolBytes: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespaceGateway,
			Subsystem: subsystemAggregate,
			Name:      "spool_bytes",
			Help:      "Size in bytes of responses spooled off-heap",
			Buckets:   byteBuckets,
		}),
		SpoolErrorsTotal: factory.NewCounter(prometheus.CounterOpts{
			Namespace: namespaceGateway,
			Subsystem: subsystemAggregate,
			Name:      "spool_errors_total",
			Help:      "Total number of spool errors",
		}),
	}
}

// DefaultMetrics returns the process-wide singleton Metrics instance.
func DefaultMetrics() *Metrics {
	defaultMetricsOnce.Do(func() {
		defaultMetrics = NewMetrics()
	})
	return defaultMetrics
}

// NopMetrics returns a Metrics instance that records nothing. Useful for tests
// and when metrics are disabled.
func NopMetrics() *Metrics {
	nopMetricsOnce.Do(func() {
		nopMetricsInstance = &Metrics{enabled: false}
	})
	return nopMetricsInstance
}

// MustRegister registers all aggregate collectors with the given registry,
// silently ignoring AlreadyRegisteredError to tolerate provider recreation on
// config reload.
func (m *Metrics) MustRegister(registry *prometheus.Registry) {
	if m == nil || !m.enabled || registry == nil {
		return
	}
	for _, c := range m.collectors() {
		if err := registry.Register(c); err != nil && !isAlreadyRegistered(err) {
			panic(err)
		}
	}
}

// collectors returns all aggregate collectors for registration.
func (m *Metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.RequestsTotal,
		m.TargetsTotal,
		m.TargetErrorsTotal,
		m.ResultsTotal,
		m.DurationSeconds,
		m.MergeDurationSecond,
		m.SpoolBytes,
		m.SpoolErrorsTotal,
	}
}

// RecordRequest records the start of an aggregate request with its target count.
func (m *Metrics) RecordRequest(targets int) {
	if !m.enabled {
		return
	}
	m.RequestsTotal.Inc()
	m.TargetsTotal.Add(float64(targets))
}

// RecordTargetError records a failed target invocation.
func (m *Metrics) RecordTargetError(target string) {
	if !m.enabled {
		return
	}
	m.TargetErrorsTotal.WithLabelValues(target).Inc()
}

// RecordResult records the aggregate-level success/failure counts.
func (m *Metrics) RecordResult(success, failure int) {
	if !m.enabled {
		return
	}
	if success > 0 {
		m.ResultsTotal.WithLabelValues(resultSuccess).Add(float64(success))
	}
	if failure > 0 {
		m.ResultsTotal.WithLabelValues(resultFailure).Add(float64(failure))
	}
}

// RecordDuration records the aggregate fan-out duration.
func (m *Metrics) RecordDuration(d time.Duration) {
	if !m.enabled {
		return
	}
	m.DurationSeconds.Observe(d.Seconds())
}

// RecordMergeDuration records the response merge duration.
func (m *Metrics) RecordMergeDuration(d time.Duration) {
	if !m.enabled {
		return
	}
	m.MergeDurationSecond.Observe(d.Seconds())
}

// RecordSpoolBytes records the size of a spooled response.
func (m *Metrics) RecordSpoolBytes(n int64) {
	if !m.enabled {
		return
	}
	m.SpoolBytes.Observe(float64(n))
}

// RecordSpoolError records a spool error.
func (m *Metrics) RecordSpoolError() {
	if !m.enabled {
		return
	}
	m.SpoolErrorsTotal.Inc()
}

// isAlreadyRegistered returns true if the error indicates the collector was
// already registered.
func isAlreadyRegistered(err error) bool {
	var are prometheus.AlreadyRegisteredError
	return errors.As(err, &are)
}
