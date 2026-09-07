// Package metrics provides Prometheus metrics for the MCP (Model Context
// Protocol) hub. It follows the singleton pattern used elsewhere in the code
// base (internal/metrics/route): a package-level instance is created once via
// sync.Once, its collectors are registered with the gateway's custom registry
// via Register, and Record* helpers update the series.
//
// The metric set is intentionally forward-compatible: fields for later
// milestones (SSE streams, subscriptions, MRTR rounds, cache hit ratio) are
// declared now with no-op-safe recorders so the wiring never changes when
// those milestones land.
package metrics

import (
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metric namespace/subsystem and label constants (bounded label values keep
// cardinality predictable).
const (
	metricsNamespace = "avapigw"
	metricsSubsystem = "mcp"

	// LabelUpstream identifies the selected MCP upstream.
	LabelUpstream = "upstream"
	// LabelMethod identifies the MCP method (tools/call, tools/list, ...).
	LabelMethod = "mcp_method"
	// LabelName identifies the (de-namespaced) MCP primitive name.
	LabelName = "mcp_name"
	// LabelProtocolVersion identifies the negotiated protocol version.
	LabelProtocolVersion = "protocol_version"
	// LabelResultType identifies the result type (complete, input_required).
	LabelResultType = "result_type"
	// LabelOutcome identifies the request outcome (success, error).
	LabelOutcome = "outcome"
	// LabelRoute identifies the MCP route driving a weighted selection.
	LabelRoute = "route"
)

// Outcome label values (bounded).
const (
	// OutcomeSuccess marks a successfully brokered request.
	OutcomeSuccess = "success"
	// OutcomeError marks a request that ended in an error.
	OutcomeError = "error"
)

// LabelClass is the auth-failure classification label (HUB-505).
const LabelClass = "class"

// LabelEra identifies the determined upstream protocol era (HUB-721..724).
const LabelEra = "era"

// Upstream era label values (bounded, HUB-721..724).
const (
	// EraModern marks an upstream determined/pinned to the modern era.
	EraModern = "modern"
	// EraLegacy marks an upstream determined/pinned to the legacy era.
	EraLegacy = "legacy"
)

// Auth-failure classification values (bounded, HUB-505). They partition
// AuthFailuresTotal so operators can distinguish the failure mode.
const (
	// AuthClassNoToken marks a missing bearer token.
	AuthClassNoToken = "no_token"
	// AuthClassInvalidToken marks a token that failed validation.
	AuthClassInvalidToken = "invalid_token"
	// AuthClassAudience marks an audience/resource mismatch.
	AuthClassAudience = "audience_mismatch"
	// AuthClassScope marks an insufficient-scope rejection.
	AuthClassScope = "insufficient_scope"
	// AuthClassPolicy marks a deny-by-policy rejection.
	AuthClassPolicy = "policy_denied"
	// AuthClassRetryState marks an invalid MRTR retry-state rejection.
	AuthClassRetryState = "invalid_retry_state"
)

// requestLabels is the label set shared by the per-request series.
var requestLabels = []string{
	LabelUpstream, LabelMethod, LabelName, LabelProtocolVersion,
	LabelResultType, LabelOutcome,
}

// upstreamOnlyLabels is the label set for upstream-scoped failure counters.
var upstreamOnlyLabels = []string{LabelUpstream, LabelMethod}

// durationBuckets covers sub-millisecond to multi-second MCP round-trips.
var durationBuckets = []float64{
	.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30,
}

// roundsBuckets covers the small integer distribution of MRTR rounds per
// operation (HUB-505).
var roundsBuckets = []float64{1, 2, 3, 4, 5, 6, 8, 10, 16}

// Metrics holds all MCP hub Prometheus collectors.
type Metrics struct {
	// RequestsTotal counts brokered MCP requests by outcome.
	RequestsTotal *prometheus.CounterVec
	// RequestDuration observes end-to-end broker latency.
	RequestDuration *prometheus.HistogramVec
	// InFlight tracks concurrently in-flight brokered requests.
	InFlight *prometheus.GaugeVec
	// UpstreamFailuresTotal counts upstream transport/protocol failures.
	UpstreamFailuresTotal *prometheus.CounterVec
	// HeaderMismatchTotal counts mirrored-header validation rejections.
	HeaderMismatchTotal *prometheus.CounterVec
	// SchemaRejectionTotal counts _meta/schema validation rejections.
	SchemaRejectionTotal *prometheus.CounterVec
	// AuthFailuresTotal counts authorization failures on the MCP path.
	AuthFailuresTotal *prometheus.CounterVec

	// Forward-compatible series (recorders are safe no-ops until wired by
	// later milestones).

	// SSEStreamsOpen tracks open SSE relay streams (M4).
	SSEStreamsOpen *prometheus.GaugeVec
	// SubscriptionsOpen tracks open subscriptions (later milestone).
	SubscriptionsOpen *prometheus.GaugeVec
	// MRTRRoundsTotal counts MRTR input_required rounds (later milestone).
	MRTRRoundsTotal *prometheus.CounterVec
	// MRTRRoundsPerOp observes the number of MRTR rounds per completed
	// operation (HUB-505).
	MRTRRoundsPerOp *prometheus.HistogramVec
	// CacheHitsTotal counts aggregation cache hits (M3).
	CacheHitsTotal *prometheus.CounterVec
	// CacheMissesTotal counts aggregation cache misses (M3).
	CacheMissesTotal *prometheus.CounterVec

	// DriftDetectedTotal counts tool-definition drift detections (HUB-402).
	DriftDetectedTotal *prometheus.CounterVec
	// UpstreamHealthy is a per-upstream health gauge: 1 healthy, 0 degraded
	// (HUB-505/T-60).
	UpstreamHealthy *prometheus.GaugeVec

	// EraDeterminationTotal counts per-upstream era determinations by era
	// (HUB-721..724).
	EraDeterminationTotal *prometheus.CounterVec
	// LegacySessionsOpen tracks open pooled legacy upstream sessions
	// (HUB-701/702).
	LegacySessionsOpen *prometheus.GaugeVec
	// LegacySessionReinitsTotal counts legacy session re-initializations
	// after session loss (HUB-702).
	LegacySessionReinitsTotal *prometheus.CounterVec
	// HeldRequestsOpen tracks open held legacy server-initiated requests
	// awaiting downstream inputResponses (HUB-704/705).
	HeldRequestsOpen *prometheus.GaugeVec
	// HeldRequestExpiredTotal counts held requests that expired before the
	// client responded (HUB-705).
	HeldRequestExpiredTotal *prometheus.CounterVec

	// UpstreamSelectedTotal counts weighted single-upstream selections by
	// route and selected upstream so canary/A-B splits can be verified.
	UpstreamSelectedTotal *prometheus.CounterVec
	// CryptoRandFailuresTotal counts crypto/rand read failures that fell back
	// to the math/rand path during weighted selection.
	CryptoRandFailuresTotal prometheus.Counter
}

var (
	instance *Metrics
	once     sync.Once
)

// GetMetrics returns the package-level singleton, creating it on first use.
func GetMetrics() *Metrics {
	once.Do(func() {
		instance = newMetrics()
	})
	return instance
}

// newMetrics constructs the collectors without registering them. Registration
// is deferred to Register so the collectors bind to the gateway's custom
// registry (not the global default registry).
func newMetrics() *Metrics {
	return &Metrics{
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "requests_total",
				Help:      "Total number of brokered MCP requests",
			},
			requestLabels,
		),
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "request_duration_seconds",
				Help:      "End-to-end MCP broker latency in seconds",
				Buckets:   durationBuckets,
			},
			requestLabels,
		),
		InFlight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "requests_in_flight",
				Help:      "Number of MCP requests currently in flight",
			},
			upstreamOnlyLabels,
		),
		UpstreamFailuresTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "upstream_failures_total",
				Help:      "Total number of MCP upstream failures",
			},
			upstreamOnlyLabels,
		),
		HeaderMismatchTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "header_mismatch_total",
				Help:      "Total number of mirrored-header validation rejections",
			},
			[]string{LabelMethod},
		),
		SchemaRejectionTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "schema_rejection_total",
				Help:      "Total number of _meta/schema validation rejections",
			},
			[]string{LabelMethod},
		),
		AuthFailuresTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "auth_failures_total",
				Help:      "Total number of MCP authorization failures by class",
			},
			[]string{LabelMethod, LabelClass},
		),
		SSEStreamsOpen: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "sse_streams_open",
				Help:      "Number of open MCP SSE relay streams",
			},
			[]string{LabelUpstream},
		),
		SubscriptionsOpen: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "subscriptions_open",
				Help:      "Number of open MCP subscriptions",
			},
			[]string{LabelUpstream},
		),
		MRTRRoundsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "mrtr_rounds_total",
				Help:      "Total number of MRTR input_required rounds",
			},
			[]string{LabelUpstream, LabelMethod},
		),
		CacheHitsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "cache_hits_total",
				Help:      "Total number of MCP aggregation cache hits",
			},
			[]string{LabelUpstream, LabelMethod},
		),
		CacheMissesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "cache_misses_total",
				Help:      "Total number of MCP aggregation cache misses",
			},
			[]string{LabelUpstream, LabelMethod},
		),
		MRTRRoundsPerOp: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "mrtr_rounds_per_operation",
				Help:      "Number of MRTR rounds per completed operation",
				Buckets:   roundsBuckets,
			},
			[]string{LabelUpstream, LabelMethod},
		),
		DriftDetectedTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "drift_detected_total",
				Help:      "Total number of tool-definition drift detections",
			},
			[]string{LabelUpstream, LabelName},
		),
		UpstreamHealthy: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "upstream_healthy",
				Help:      "Per-upstream health: 1 healthy, 0 degraded",
			},
			[]string{LabelUpstream},
		),
		EraDeterminationTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "era_determination_total",
				Help:      "Total per-upstream protocol-era determinations by era",
			},
			[]string{LabelUpstream, LabelEra},
		),
		LegacySessionsOpen: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "legacy_sessions_open",
				Help:      "Number of open pooled legacy upstream sessions",
			},
			[]string{LabelUpstream},
		),
		LegacySessionReinitsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "legacy_session_reinits_total",
				Help:      "Total legacy upstream session re-initializations after session loss",
			},
			[]string{LabelUpstream},
		),
		HeldRequestsOpen: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "held_requests_open",
				Help:      "Number of open held legacy server-initiated requests",
			},
			[]string{LabelUpstream},
		),
		HeldRequestExpiredTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "held_request_expired_total",
				Help:      "Total held legacy requests that expired before a client response",
			},
			[]string{LabelUpstream},
		),
		UpstreamSelectedTotal:   newUpstreamSelectedCounter(),
		CryptoRandFailuresTotal: newCryptoRandFailuresCounter(),
	}
}

// newUpstreamSelectedCounter constructs the weighted-selection counter.
func newUpstreamSelectedCounter() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "upstream_selected_total",
			Help:      "Total weighted single-upstream selections by route and selected upstream",
		},
		[]string{LabelRoute, LabelUpstream},
	)
}

// newCryptoRandFailuresCounter constructs the crypto/rand fallback counter.
func newCryptoRandFailuresCounter() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "crypto_rand_failures_total",
			Help:      "Total crypto/rand failures that fell back to math/rand during weighted selection",
		},
	)
}

// Register registers all MCP metric collectors with the given registry. It
// uses Register (not MustRegister) and ignores AlreadyRegisteredError so
// hot-reload paths that re-register the singleton do not panic.
func (m *Metrics) Register(reg *prometheus.Registry) {
	if reg == nil {
		return
	}
	for _, c := range m.collectors() {
		if err := reg.Register(c); err != nil && !isAlreadyRegistered(err) {
			panic(err)
		}
	}
}

// collectors returns all collectors for registration.
func (m *Metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.RequestsTotal,
		m.RequestDuration,
		m.InFlight,
		m.UpstreamFailuresTotal,
		m.HeaderMismatchTotal,
		m.SchemaRejectionTotal,
		m.AuthFailuresTotal,
		m.SSEStreamsOpen,
		m.SubscriptionsOpen,
		m.MRTRRoundsTotal,
		m.MRTRRoundsPerOp,
		m.CacheHitsTotal,
		m.CacheMissesTotal,
		m.DriftDetectedTotal,
		m.UpstreamHealthy,
		m.EraDeterminationTotal,
		m.LegacySessionsOpen,
		m.LegacySessionReinitsTotal,
		m.HeldRequestsOpen,
		m.HeldRequestExpiredTotal,
		m.UpstreamSelectedTotal,
		m.CryptoRandFailuresTotal,
	}
}

// RecordUpstreamSelected records a weighted single-upstream selection for a
// route so canary/A-B distribution can be verified from metrics.
func (m *Metrics) RecordUpstreamSelected(route, upstream string) {
	m.UpstreamSelectedTotal.WithLabelValues(route, upstream).Inc()
}

// RecordCryptoRandFailure records a crypto/rand read failure that fell back to
// math/rand during weighted selection.
func (m *Metrics) RecordCryptoRandFailure() {
	m.CryptoRandFailuresTotal.Inc()
}

// RecordRequest records a completed MCP request: it increments the request
// counter and observes the broker latency with the same label set.
func (m *Metrics) RecordRequest(
	upstream, method, name, protocolVersion, resultType, outcome string,
	duration time.Duration,
) {
	m.RequestsTotal.WithLabelValues(
		upstream, method, name, protocolVersion, resultType, outcome,
	).Inc()
	m.RequestDuration.WithLabelValues(
		upstream, method, name, protocolVersion, resultType, outcome,
	).Observe(duration.Seconds())
}

// IncInFlight increments the in-flight gauge for an upstream/method.
func (m *Metrics) IncInFlight(upstream, method string) {
	m.InFlight.WithLabelValues(upstream, method).Inc()
}

// DecInFlight decrements the in-flight gauge for an upstream/method.
func (m *Metrics) DecInFlight(upstream, method string) {
	m.InFlight.WithLabelValues(upstream, method).Dec()
}

// RecordUpstreamFailure records an upstream transport/protocol failure.
func (m *Metrics) RecordUpstreamFailure(upstream, method string) {
	m.UpstreamFailuresTotal.WithLabelValues(upstream, method).Inc()
}

// RecordHeaderMismatch records a mirrored-header validation rejection.
func (m *Metrics) RecordHeaderMismatch(method string) {
	m.HeaderMismatchTotal.WithLabelValues(method).Inc()
}

// RecordSchemaRejection records a _meta/schema validation rejection.
func (m *Metrics) RecordSchemaRejection(method string) {
	m.SchemaRejectionTotal.WithLabelValues(method).Inc()
}

// RecordAuthFailure records an authorization failure on the MCP path,
// classified by class (HUB-505). Use the AuthClass* constants.
func (m *Metrics) RecordAuthFailure(method, class string) {
	if class == "" {
		class = AuthClassInvalidToken
	}
	m.AuthFailuresTotal.WithLabelValues(method, class).Inc()
}

// RecordCacheHit records an MCP result-cache hit for the given upstream/method.
func (m *Metrics) RecordCacheHit(upstream, method string) {
	m.CacheHitsTotal.WithLabelValues(upstream, method).Inc()
}

// RecordCacheMiss records an MCP result-cache miss for the given
// upstream/method.
func (m *Metrics) RecordCacheMiss(upstream, method string) {
	m.CacheMissesTotal.WithLabelValues(upstream, method).Inc()
}

// IncSSEStreams increments the open-SSE-stream gauge for an upstream.
func (m *Metrics) IncSSEStreams(upstream string) {
	m.SSEStreamsOpen.WithLabelValues(upstream).Inc()
}

// DecSSEStreams decrements the open-SSE-stream gauge for an upstream.
func (m *Metrics) DecSSEStreams(upstream string) {
	m.SSEStreamsOpen.WithLabelValues(upstream).Dec()
}

// RecordMRTRRound increments the per-round MRTR counter.
func (m *Metrics) RecordMRTRRound(upstream, method string) {
	m.MRTRRoundsTotal.WithLabelValues(upstream, method).Inc()
}

// ObserveMRTRRounds records the total number of rounds for a completed MRTR
// operation.
func (m *Metrics) ObserveMRTRRounds(upstream, method string, rounds int) {
	m.MRTRRoundsPerOp.WithLabelValues(upstream, method).Observe(float64(rounds))
}

// RecordDrift records a tool-definition drift detection (HUB-402).
func (m *Metrics) RecordDrift(upstream, name string) {
	m.DriftDetectedTotal.WithLabelValues(upstream, name).Inc()
}

// SetUpstreamHealthy sets the per-upstream health gauge (1 healthy, 0
// degraded).
func (m *Metrics) SetUpstreamHealthy(upstream string, healthy bool) {
	v := 0.0
	if healthy {
		v = 1.0
	}
	m.UpstreamHealthy.WithLabelValues(upstream).Set(v)
}

// RecordEraDetermination records a per-upstream era determination (HUB-721..724).
// Use the EraModern / EraLegacy constants for era.
func (m *Metrics) RecordEraDetermination(upstream, era string) {
	m.EraDeterminationTotal.WithLabelValues(upstream, era).Inc()
}

// IncLegacySessions increments the open-legacy-session gauge for an upstream.
func (m *Metrics) IncLegacySessions(upstream string) {
	m.LegacySessionsOpen.WithLabelValues(upstream).Inc()
}

// DecLegacySessions decrements the open-legacy-session gauge for an upstream.
func (m *Metrics) DecLegacySessions(upstream string) {
	m.LegacySessionsOpen.WithLabelValues(upstream).Dec()
}

// RecordLegacySessionReinit records a legacy session re-initialization after
// session loss (HUB-702).
func (m *Metrics) RecordLegacySessionReinit(upstream string) {
	m.LegacySessionReinitsTotal.WithLabelValues(upstream).Inc()
}

// IncHeldRequests increments the open-held-request gauge for an upstream.
func (m *Metrics) IncHeldRequests(upstream string) {
	m.HeldRequestsOpen.WithLabelValues(upstream).Inc()
}

// DecHeldRequests decrements the open-held-request gauge for an upstream.
func (m *Metrics) DecHeldRequests(upstream string) {
	m.HeldRequestsOpen.WithLabelValues(upstream).Dec()
}

// RecordHeldRequestExpired records a held request that expired before the
// downstream client responded (HUB-705).
func (m *Metrics) RecordHeldRequestExpired(upstream string) {
	m.HeldRequestExpiredTotal.WithLabelValues(upstream).Inc()
}

// isAlreadyRegistered reports whether err is a Prometheus
// AlreadyRegisteredError.
func isAlreadyRegistered(err error) bool {
	var are prometheus.AlreadyRegisteredError
	return errors.As(err, &are)
}
