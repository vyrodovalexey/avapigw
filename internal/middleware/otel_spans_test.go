package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sony/gobreaker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// cbInstrumentationScope is the tracer scope name that was previously
// (incorrectly) used to start orphan root spans on circuit breaker state
// changes. The regression tests below assert it never appears again.
const cbInstrumentationScope = "avapigw/circuitbreaker"

// TestCircuitBreaker_NoOrphanSpanOnStateChange verifies that circuit
// breaker state changes do NOT start orphan root spans. OnStateChange
// runs outside any request context, so a span started there from
// context.Background() could never join the trace that triggered the
// transition. Transitions must instead be observable via the Info log,
// the state callback, and the circuit_breaker_transitions_total metric.
// This test is NOT parallel because it modifies the global OTEL tracer
// provider and asserts exact metric deltas on process-global counters.
func TestCircuitBreaker_NoOrphanSpanOnStateChange(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	oldTP := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(oldTP)

	const cbName = "test-no-orphan-span-cb"

	stateChanges := make([]int, 0)

	// Long timeout keeps the breaker open for the duration of the test.
	cb := NewCircuitBreaker(
		cbName,
		2,
		30*time.Second,
		WithCircuitBreakerLogger(observability.NopLogger()),
		WithCircuitBreakerStateCallback(func(_ string, state int) {
			stateChanges = append(stateChanges, state)
		}),
	)

	transitions := GetMiddlewareMetrics().circuitBreakerTransitions
	before := testutil.ToFloat64(
		transitions.WithLabelValues(cbName, "closed", "open"),
	)

	// Force failures to trigger a state change (closed -> open).
	for i := 0; i < 10; i++ {
		_, _ = cb.Execute(func() (interface{}, error) {
			return nil, assert.AnError
		})
	}

	require.Equal(t, gobreaker.StateOpen, cb.State(),
		"circuit breaker should be open after consecutive failures")
	require.NotEmpty(t, stateChanges, "state change callback should fire")
	assert.Contains(t, stateChanges, int(gobreaker.StateOpen))

	// The transition metric must still record the state change.
	after := testutil.ToFloat64(
		transitions.WithLabelValues(cbName, "closed", "open"),
	)
	assert.Equal(t, before+1, after,
		"transition metric should record closed->open exactly once")

	// No span may be created for the state change: it would be an
	// orphan root span disconnected from the triggering trace.
	for _, s := range exporter.GetSpans() {
		assert.NotEqual(t, "circuitbreaker.state_change", s.Name,
			"state change must not create a span")
		assert.NotEqual(t, cbInstrumentationScope, s.InstrumentationScope.Name,
			"no span may originate from the circuit breaker tracer scope")
	}
}

// TestCircuitBreaker_NoOrphanSpanOnRecovery covers the open -> half-open
// -> closed transitions and verifies none of them create spans either.
// Not parallel: modifies the global OTEL tracer provider.
func TestCircuitBreaker_NoOrphanSpanOnRecovery(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	oldTP := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(oldTP)

	// Short timeout so the breaker moves to half-open quickly.
	cb := NewCircuitBreaker(
		"test-no-orphan-span-recovery-cb",
		1,
		50*time.Millisecond,
		WithCircuitBreakerLogger(observability.NopLogger()),
	)

	// Trip the breaker (closed -> open).
	for i := 0; i < 5; i++ {
		_, _ = cb.Execute(func() (interface{}, error) {
			return nil, assert.AnError
		})
	}
	require.Equal(t, gobreaker.StateOpen, cb.State())

	// Wait for half-open, then close it again with a success.
	require.Eventually(t, func() bool {
		return cb.State() == gobreaker.StateHalfOpen
	}, 2*time.Second, 10*time.Millisecond, "breaker should become half-open")

	_, err := cb.Execute(func() (interface{}, error) {
		return "ok", nil
	})
	require.NoError(t, err)
	require.Equal(t, gobreaker.StateClosed, cb.State())

	// Full open -> half-open -> closed cycle recorded zero spans.
	assert.Empty(t, exporter.GetSpans(),
		"circuit breaker state transitions must not create any spans")
}
