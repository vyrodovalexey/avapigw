package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sony/gobreaker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// cbRequestsLabelName is the hardcoded circuit breaker name label used by
// CircuitBreakerMiddleware for the requests-by-state counter.
const cbRequestsLabelName = "gateway"

// cbRequestStateCount reads the current value of the
// circuit_breaker_requests_total counter for the given state label.
func cbRequestStateCount(state string) float64 {
	return testutil.ToFloat64(
		GetMiddlewareMetrics().circuitBreakerRequests.WithLabelValues(
			cbRequestsLabelName, state,
		),
	)
}

// snapshotCBRequestCounts captures the counter value for every state label.
func snapshotCBRequestCounts(states []string) map[string]float64 {
	snapshot := make(map[string]float64, len(states))
	for _, s := range states {
		snapshot[s] = cbRequestStateCount(s)
	}
	return snapshot
}

// TestCircuitBreakerMiddleware_StateLabelMatchesExecutedState asserts the
// core WP14 invariant: the state label recorded on
// circuit_breaker_requests_total is the state observed WHILE the request
// executes inside cb.Execute, not a value captured before Execute that
// may have gone stale. The handler records the state it runs under and
// the test verifies exactly that label was incremented.
// Not parallel: asserts exact deltas on process-global counters.
func TestCircuitBreakerMiddleware_StateLabelMatchesExecutedState(t *testing.T) {
	states := []string{stateClosed, stateHalfOpen, stateOpen}

	cb := NewCircuitBreaker(
		"test-label-matches-cb", 100, 30*time.Second,
		WithCircuitBreakerLogger(observability.NopLogger()),
	)
	handlerChain := CircuitBreakerMiddleware(cb)

	var observedState string
	handler := handlerChain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// The state the request actually executes under.
		observedState = cb.State().String()
		w.WriteHeader(http.StatusOK)
	}))

	before := snapshotCBRequestCounts(states)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, observedState, "handler must have executed")

	for _, s := range states {
		after := cbRequestStateCount(s)
		if s == observedState {
			assert.Equal(t, before[s]+1, after,
				"executed state %q must be incremented", s)
		} else {
			assert.Equal(t, before[s], after,
				"non-executed state %q must stay unchanged", s)
		}
	}
}

// TestCircuitBreakerMiddleware_StateLabel_HalfOpen drives the breaker
// into half-open and verifies a request admitted in that state is
// counted under the "half-open" label (the stale pre-Execute read could
// misreport this as "open" or "closed").
// Not parallel: asserts exact deltas on process-global counters.
func TestCircuitBreakerMiddleware_StateLabel_HalfOpen(t *testing.T) {
	states := []string{stateClosed, stateHalfOpen, stateOpen}

	// Short timeout so the breaker transitions to half-open quickly.
	cb := NewCircuitBreaker(
		"test-half-open-label-cb", 2, 100*time.Millisecond,
		WithCircuitBreakerLogger(observability.NopLogger()),
	)

	// Trip the breaker: closed -> open.
	for i := 0; i < 10; i++ {
		_, _ = cb.Execute(func() (interface{}, error) {
			return nil, assert.AnError
		})
	}
	require.Equal(t, gobreaker.StateOpen, cb.State())

	// Wait until the open timeout elapses and the breaker reports half-open.
	require.Eventually(t, func() bool {
		return cb.State() == gobreaker.StateHalfOpen
	}, 2*time.Second, 10*time.Millisecond, "breaker should become half-open")

	handlerChain := CircuitBreakerMiddleware(cb)
	handler := handlerChain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	before := snapshotCBRequestCounts(states)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	assert.Equal(t, before[stateHalfOpen]+1, cbRequestStateCount(stateHalfOpen),
		"request admitted in half-open must be labeled half-open")
	assert.Equal(t, before[stateClosed], cbRequestStateCount(stateClosed),
		"closed label must not change for a half-open request")
	assert.Equal(t, before[stateOpen], cbRequestStateCount(stateOpen),
		"open label must not change for a half-open request")
}

// TestCircuitBreakerMiddleware_StateLabel_OpenRejection verifies the
// rejection path: a request rejected by an open breaker is counted under
// the "open" label and the handler never runs.
// Not parallel: asserts exact deltas on process-global counters.
func TestCircuitBreakerMiddleware_StateLabel_OpenRejection(t *testing.T) {
	// Long timeout keeps the breaker open for the duration of the test.
	cb := NewCircuitBreaker(
		"test-open-label-cb", 2, 30*time.Second,
		WithCircuitBreakerLogger(observability.NopLogger()),
	)

	for i := 0; i < 10; i++ {
		_, _ = cb.Execute(func() (interface{}, error) {
			return nil, assert.AnError
		})
	}
	require.Equal(t, gobreaker.StateOpen, cb.State())

	handlerChain := CircuitBreakerMiddleware(cb)

	handlerRan := false
	handler := handlerChain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerRan = true
		w.WriteHeader(http.StatusOK)
	}))

	beforeOpen := cbRequestStateCount(stateOpen)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, handlerRan, "handler must not run while the breaker is open")
	assert.Equal(t, beforeOpen+1, cbRequestStateCount(stateOpen),
		"rejected request must be counted under the open label")
}
