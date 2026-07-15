package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// timeoutsCount reads the current value of the request_timeouts_total
// counter for the given route label.
func timeoutsCount(route string) float64 {
	return testutil.ToFloat64(
		GetMiddlewareMetrics().timeoutsTotal.WithLabelValues(route),
	)
}

// TestWriteTimeoutResponse_UsesRouteLabel verifies WP10: the timeout
// counter is labeled with the bounded route name from the request
// context, never with the raw (unbounded-cardinality) URL path.
// Not parallel: asserts exact deltas on process-global counters.
func TestWriteTimeoutResponse_UsesRouteLabel(t *testing.T) {
	const routeName = "timeout-metrics-direct-route"
	const rawPath = "/orders/12345/items/67890"

	logger := observability.NopLogger()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, rawPath, nil)
	req = req.WithContext(util.ContextWithRoute(req.Context(), routeName))

	beforeRoute := timeoutsCount(routeName)
	beforePath := timeoutsCount(rawPath)

	writeTimeoutResponse(rec, req, 50*time.Millisecond, logger)

	assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
	assert.Equal(t, beforeRoute+1, timeoutsCount(routeName),
		"timeout counter must be labeled with the route name")
	assert.Equal(t, beforePath, timeoutsCount(rawPath),
		"raw URL path must not be used as a metric label")
}

// TestWriteTimeoutResponse_UnknownRouteFallback verifies the bounded
// fallback label when no route name is present in the context.
// Not parallel: asserts exact deltas on process-global counters.
func TestWriteTimeoutResponse_UnknownRouteFallback(t *testing.T) {
	const rawPath = "/no/route/in/context"

	logger := observability.NopLogger()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, rawPath, nil)

	beforeUnknown := timeoutsCount(unknownRoute)
	beforePath := timeoutsCount(rawPath)

	writeTimeoutResponse(rec, req, 50*time.Millisecond, logger)

	assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
	assert.Equal(t, beforeUnknown+1, timeoutsCount(unknownRoute),
		"missing route must fall back to the bounded unknown label")
	assert.Equal(t, beforePath, timeoutsCount(rawPath),
		"raw URL path must not be used as a metric label")
}

// TestTimeout_MetricRouteLabel_EndToEnd runs a request with a route in
// its context through the full Timeout middleware until it times out and
// asserts the counter is incremented under the route label.
// Not parallel: timing sensitivity + exact metric delta assertions.
func TestTimeout_MetricRouteLabel_EndToEnd(t *testing.T) {
	const routeName = "timeout-metrics-e2e-route"
	const rawPath = "/api/v1/slow-endpoint"

	logger := observability.NopLogger()
	handlerChain := Timeout(30*time.Millisecond, logger)

	handler := handlerChain(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Block until the middleware cancels the request context.
		<-r.Context().Done()
	}))

	req := httptest.NewRequest(http.MethodGet, rawPath, nil)
	req = req.WithContext(util.ContextWithRoute(req.Context(), routeName))
	rec := httptest.NewRecorder()

	beforeRoute := timeoutsCount(routeName)
	beforeUnknown := timeoutsCount(unknownRoute)
	beforePath := timeoutsCount(rawPath)

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusGatewayTimeout, rec.Code)
	assert.Contains(t, rec.Body.String(), "gateway timeout")

	assert.Equal(t, beforeRoute+1, timeoutsCount(routeName),
		"timed-out request must increment the route-labeled counter")
	assert.Equal(t, beforeUnknown, timeoutsCount(unknownRoute),
		"unknown label must not change when a route is present")
	assert.Equal(t, beforePath, timeoutsCount(rawPath),
		"raw URL path must not be used as a metric label")
}

// TestTimeout_MetricUnknownRoute_EndToEnd runs a request WITHOUT a route
// in its context through the Timeout middleware and asserts the counter
// falls back to the bounded unknown label.
// Not parallel: timing sensitivity + exact metric delta assertions.
func TestTimeout_MetricUnknownRoute_EndToEnd(t *testing.T) {
	const rawPath = "/api/v1/unrouted-slow-endpoint"

	logger := observability.NopLogger()
	handlerChain := Timeout(30*time.Millisecond, logger)

	handler := handlerChain(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))

	req := httptest.NewRequest(http.MethodGet, rawPath, nil)
	rec := httptest.NewRecorder()

	beforeUnknown := timeoutsCount(unknownRoute)
	beforePath := timeoutsCount(rawPath)

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusGatewayTimeout, rec.Code)
	assert.Equal(t, beforeUnknown+1, timeoutsCount(unknownRoute),
		"request without route must increment the unknown label")
	assert.Equal(t, beforePath, timeoutsCount(rawPath),
		"raw URL path must not be used as a metric label")
}
