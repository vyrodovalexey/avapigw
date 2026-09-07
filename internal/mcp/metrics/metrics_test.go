package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMetricsSingleton(t *testing.T) {
	m1 := GetMetrics()
	m2 := GetMetrics()
	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "GetMetrics must return the same singleton")
}

func TestRegisterNilRegistryNoop(t *testing.T) {
	m := newMetrics()
	// Must not panic on a nil registry.
	m.Register(nil)
}

func TestRegisterAllCollectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics()
	m.Register(reg)

	families, err := reg.Gather()
	require.NoError(t, err)
	// Registration is empty until series are touched; instead assert the
	// collector count is what we registered.
	assert.Len(t, m.collectors(), 22)
	_ = families
}

func TestRegisterIdempotent(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics()
	m.Register(reg)
	// Re-registering the same collectors must not panic (AlreadyRegistered
	// is ignored).
	m.Register(reg)
}

func TestRecordRequest(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics()
	m.Register(reg)

	m.RecordRequest("up1", "tools/call", "echo", "2026-07-28", OutcomeSuccess, OutcomeSuccess, 100*time.Millisecond)

	got := testutil.ToFloat64(m.RequestsTotal.WithLabelValues(
		"up1", "tools/call", "echo", "2026-07-28", OutcomeSuccess, OutcomeSuccess))
	assert.Equal(t, float64(1), got)
	assert.Equal(t, 1, testutil.CollectAndCount(m.RequestDuration))
}

func TestInFlightGauge(t *testing.T) {
	m := newMetrics()
	m.IncInFlight("up1", "tools/call")
	m.IncInFlight("up1", "tools/call")
	assert.Equal(t, float64(2), testutil.ToFloat64(m.InFlight.WithLabelValues("up1", "tools/call")))
	m.DecInFlight("up1", "tools/call")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.InFlight.WithLabelValues("up1", "tools/call")))
}

func TestRecordUpstreamFailure(t *testing.T) {
	m := newMetrics()
	m.RecordUpstreamFailure("up1", "tools/call")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.UpstreamFailuresTotal.WithLabelValues("up1", "tools/call")))
}

func TestRecordHeaderMismatch(t *testing.T) {
	m := newMetrics()
	m.RecordHeaderMismatch("tools/call")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.HeaderMismatchTotal.WithLabelValues("tools/call")))
}

func TestRecordSchemaRejection(t *testing.T) {
	m := newMetrics()
	m.RecordSchemaRejection("tools/list")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.SchemaRejectionTotal.WithLabelValues("tools/list")))
}

func TestRecordAuthFailure(t *testing.T) {
	m := newMetrics()
	m.RecordAuthFailure("tools/call", AuthClassScope)
	assert.Equal(t, float64(1), testutil.ToFloat64(m.AuthFailuresTotal.WithLabelValues("tools/call", AuthClassScope)))

	// Empty class defaults to invalid_token.
	m.RecordAuthFailure("tools/call", "")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.AuthFailuresTotal.WithLabelValues("tools/call", AuthClassInvalidToken)))
}

func TestRecordCacheHitMiss(t *testing.T) {
	m := newMetrics()
	m.RecordCacheHit("up1", "tools/list")
	m.RecordCacheMiss("up1", "tools/list")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.CacheHitsTotal.WithLabelValues("up1", "tools/list")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.CacheMissesTotal.WithLabelValues("up1", "tools/list")))
}

func TestSSEStreamGauge(t *testing.T) {
	m := newMetrics()
	m.IncSSEStreams("up1")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.SSEStreamsOpen.WithLabelValues("up1")))
	m.DecSSEStreams("up1")
	assert.Equal(t, float64(0), testutil.ToFloat64(m.SSEStreamsOpen.WithLabelValues("up1")))
}

func TestMRTRRounds(t *testing.T) {
	m := newMetrics()
	m.RecordMRTRRound("up1", "tools/call")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.MRTRRoundsTotal.WithLabelValues("up1", "tools/call")))
	m.ObserveMRTRRounds("up1", "tools/call", 3)
	assert.Equal(t, 1, testutil.CollectAndCount(m.MRTRRoundsPerOp))
}

func TestRecordDrift(t *testing.T) {
	m := newMetrics()
	m.RecordDrift("up1", "echo")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.DriftDetectedTotal.WithLabelValues("up1", "echo")))
}

func TestSetUpstreamHealthy(t *testing.T) {
	m := newMetrics()
	m.SetUpstreamHealthy("up1", true)
	assert.Equal(t, float64(1), testutil.ToFloat64(m.UpstreamHealthy.WithLabelValues("up1")))
	m.SetUpstreamHealthy("up1", false)
	assert.Equal(t, float64(0), testutil.ToFloat64(m.UpstreamHealthy.WithLabelValues("up1")))
}

func TestRecordEraDetermination(t *testing.T) {
	m := newMetrics()
	m.RecordEraDetermination("up1", EraModern)
	assert.Equal(t, float64(1), testutil.ToFloat64(m.EraDeterminationTotal.WithLabelValues("up1", EraModern)))
}

func TestLegacySessionGauges(t *testing.T) {
	m := newMetrics()
	m.IncLegacySessions("up1")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.LegacySessionsOpen.WithLabelValues("up1")))
	m.DecLegacySessions("up1")
	assert.Equal(t, float64(0), testutil.ToFloat64(m.LegacySessionsOpen.WithLabelValues("up1")))
	m.RecordLegacySessionReinit("up1")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.LegacySessionReinitsTotal.WithLabelValues("up1")))
}

func TestHeldRequestSeries(t *testing.T) {
	m := newMetrics()
	m.IncHeldRequests("up1")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.HeldRequestsOpen.WithLabelValues("up1")))
	m.DecHeldRequests("up1")
	assert.Equal(t, float64(0), testutil.ToFloat64(m.HeldRequestsOpen.WithLabelValues("up1")))
	m.RecordHeldRequestExpired("up1")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.HeldRequestExpiredTotal.WithLabelValues("up1")))
}

func TestRecordUpstreamSelected(t *testing.T) {
	m := newMetrics()
	m.RecordUpstreamSelected("route-a", "upstream-1")
	assert.Equal(t, float64(1),
		testutil.ToFloat64(m.UpstreamSelectedTotal.WithLabelValues("route-a", "upstream-1")))

	// A second selection on the same series increments it; a different label
	// tuple is tracked independently.
	m.RecordUpstreamSelected("route-a", "upstream-1")
	m.RecordUpstreamSelected("route-a", "upstream-2")
	assert.Equal(t, float64(2),
		testutil.ToFloat64(m.UpstreamSelectedTotal.WithLabelValues("route-a", "upstream-1")))
	assert.Equal(t, float64(1),
		testutil.ToFloat64(m.UpstreamSelectedTotal.WithLabelValues("route-a", "upstream-2")))
}

func TestRecordCryptoRandFailure(t *testing.T) {
	m := newMetrics()
	m.RecordCryptoRandFailure()
	assert.Equal(t, float64(1), testutil.ToFloat64(m.CryptoRandFailuresTotal))
	m.RecordCryptoRandFailure()
	assert.Equal(t, float64(2), testutil.ToFloat64(m.CryptoRandFailuresTotal))
}

func TestIsAlreadyRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "dup_total", Help: "h"})
	require.NoError(t, reg.Register(c))
	err := reg.Register(c)
	require.Error(t, err)
	assert.True(t, isAlreadyRegistered(err))
	assert.False(t, isAlreadyRegistered(assert.AnError))
}
