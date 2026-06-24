package aggregate

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRegisteredMetrics builds a fresh Metrics on an isolated registry to avoid
// touching the global default registry and to allow assertions.
func newRegisteredMetrics(t *testing.T) (*Metrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := &Metrics{
		enabled:             true,
		RequestsTotal:       prometheus.NewCounter(prometheus.CounterOpts{Name: "agg_requests_total"}),
		TargetsTotal:        prometheus.NewCounter(prometheus.CounterOpts{Name: "agg_targets_total"}),
		TargetErrorsTotal:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "agg_target_errors_total"}, []string{labelTarget}),
		ResultsTotal:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "agg_results_total"}, []string{labelResult}),
		DurationSeconds:     prometheus.NewHistogram(prometheus.HistogramOpts{Name: "agg_duration_seconds"}),
		MergeDurationSecond: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "agg_merge_duration_seconds"}),
		SpoolBytes:          prometheus.NewHistogram(prometheus.HistogramOpts{Name: "agg_spool_bytes"}),
		SpoolErrorsTotal:    prometheus.NewCounter(prometheus.CounterOpts{Name: "agg_spool_errors_total"}),
	}
	m.MustRegister(reg)
	return m, reg
}

// U-OBS-1: metrics registered, no duplicate-register panic (idempotent register).
func TestMetrics_MustRegister_NoDuplicatePanic(t *testing.T) {
	m, reg := newRegisteredMetrics(t)
	assert.NotPanics(t, func() {
		m.MustRegister(reg) // second register tolerated
	})
}

func TestMetrics_MustRegister_GuardClauses(t *testing.T) {
	reg := prometheus.NewRegistry()
	// nil metrics
	var nilM *Metrics
	assert.NotPanics(t, func() { nilM.MustRegister(reg) })
	// disabled metrics
	assert.NotPanics(t, func() { NopMetrics().MustRegister(reg) })
	// nil registry
	m, _ := newRegisteredMetrics(t)
	assert.NotPanics(t, func() { m.MustRegister(nil) })
}

// U-OBS-2: counters/histograms increment.
func TestMetrics_RecordIncrements(t *testing.T) {
	m, _ := newRegisteredMetrics(t)

	m.RecordRequest(3)
	assert.Equal(t, float64(1), testutil.ToFloat64(m.RequestsTotal))
	assert.Equal(t, float64(3), testutil.ToFloat64(m.TargetsTotal))

	m.RecordTargetError("svc-a")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.TargetErrorsTotal.WithLabelValues("svc-a")))

	m.RecordResult(2, 1)
	assert.Equal(t, float64(2), testutil.ToFloat64(m.ResultsTotal.WithLabelValues(resultSuccess)))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.ResultsTotal.WithLabelValues(resultFailure)))

	m.RecordSpoolError()
	assert.Equal(t, float64(1), testutil.ToFloat64(m.SpoolErrorsTotal))

	// Histograms: just ensure no panic.
	m.RecordDuration(10 * time.Millisecond)
	m.RecordMergeDuration(5 * time.Millisecond)
	m.RecordSpoolBytes(2048)
}

func TestMetrics_RecordResult_ZeroCounts(t *testing.T) {
	m, _ := newRegisteredMetrics(t)
	m.RecordResult(0, 0)
	assert.Equal(t, float64(0), testutil.ToFloat64(m.ResultsTotal.WithLabelValues(resultSuccess)))
	assert.Equal(t, float64(0), testutil.ToFloat64(m.ResultsTotal.WithLabelValues(resultFailure)))
}

// U-OBS-2: Nop metrics record nothing and never panic.
func TestMetrics_Nop_NoOp(t *testing.T) {
	m := NopMetrics()
	assert.NotPanics(t, func() {
		m.RecordRequest(2)
		m.RecordTargetError("x")
		m.RecordResult(1, 1)
		m.RecordDuration(time.Second)
		m.RecordMergeDuration(time.Second)
		m.RecordSpoolBytes(100)
		m.RecordSpoolError()
	})
}

func TestNewMetrics_DefaultRegistration(t *testing.T) {
	// NewMetrics uses promauto on the default registry; calling twice would
	// panic on duplicate registration, so DefaultMetrics caches a singleton.
	m1 := DefaultMetrics()
	m2 := DefaultMetrics()
	require.NotNil(t, m1)
	assert.Same(t, m1, m2)
	assert.True(t, m1.enabled)
}

func TestNopMetrics_Singleton(t *testing.T) {
	assert.Same(t, NopMetrics(), NopMetrics())
}

func TestIsAlreadyRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "dup_test"})
	require.NoError(t, reg.Register(c))
	err := reg.Register(prometheus.NewCounter(prometheus.CounterOpts{Name: "dup_test"}))
	require.Error(t, err)
	assert.True(t, isAlreadyRegistered(err))
	assert.False(t, isAlreadyRegistered(assert.AnError))
}
