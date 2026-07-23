// Direct-response middleware tests: directResponse routes must run through
// the same per-route middleware chain as proxied requests (CORS at
// minimum, security headers, admission middleware) while preserving the
// configured status/body/headers semantics.
package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// newDirectResponseProxy builds a proxy with one directResponse route and
// an optional route middleware applier.
func newDirectResponseProxy(t *testing.T, rm RouteMiddlewareApplier) *ReverseProxy {
	t.Helper()

	r := router.New()
	require.NoError(t, r.AddRoute(config.Route{
		Name: "direct-cors",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Exact: "/direct"}},
		},
		DirectResponse: &config.DirectResponseConfig{
			Status: http.StatusTeapot,
			Body:   `{"direct":true}`,
			Headers: map[string]string{
				"Content-Type": "application/json",
				"X-Direct":     "configured",
			},
		},
	}))

	registry := backend.NewRegistry(observability.NopLogger())
	opts := []ProxyOption{WithProxyLogger(observability.NopLogger())}
	if rm != nil {
		opts = append(opts, WithRouteMiddleware(rm))
	}
	return NewReverseProxy(r, registry, opts...)
}

// corsApplier returns a route middleware applier whose chain is a real
// CORS middleware for the given policy.
func corsApplier(policy middleware.CORSConfig) *mockRouteMiddlewareApplier {
	return &mockRouteMiddlewareApplier{
		middlewares: []func(http.Handler) http.Handler{middleware.CORS(policy)},
	}
}

// directCORSPolicy is the CORS policy used across the direct-response
// middleware tests.
func directCORSPolicy() middleware.CORSConfig {
	return middleware.CORSConfig{
		AllowOrigins: []string{"https://app.example.com"},
		AllowMethods: []string{"GET", "OPTIONS"},
		MaxAge:       300,
	}
}

// TestServeDirectResponse_CORSMiddlewareRuns verifies the route middleware
// chain (real CORS middleware) executes around directResponse serving.
func TestServeDirectResponse_CORSMiddlewareRuns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		origin    string
		wantGrant string
	}{
		{
			name:      "allowed origin receives the gateway grant",
			origin:    "https://app.example.com",
			wantGrant: "https://app.example.com",
		},
		{
			name:      "denied origin receives no grant",
			origin:    "https://evil.example.org",
			wantGrant: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			proxy := newDirectResponseProxy(t, corsApplier(directCORSPolicy()))

			req := httptest.NewRequest(http.MethodGet, "/direct", nil)
			req.Header.Set("Origin", tt.origin)
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, req)

			// Configured direct response semantics preserved.
			assert.Equal(t, http.StatusTeapot, rec.Code)
			assert.JSONEq(t, `{"direct":true}`, rec.Body.String())
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			assert.Equal(t, "configured", rec.Header().Get("X-Direct"))

			// CORS decision produced by the route chain.
			assert.Equal(t, tt.wantGrant,
				rec.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

// TestServeDirectResponse_PreflightAnswered verifies an OPTIONS preflight
// on a directResponse route is answered by the route chain's CORS
// middleware instead of bypassing it.
func TestServeDirectResponse_PreflightAnswered(t *testing.T) {
	t.Parallel()

	proxy := newDirectResponseProxy(t, corsApplier(directCORSPolicy()))

	req := httptest.NewRequest(http.MethodOptions, "/direct", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code,
		"preflight must short-circuit with 204, not serve the direct response")
	assert.Equal(t, "https://app.example.com",
		rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "300", rec.Header().Get("Access-Control-Max-Age"))
	assert.Empty(t, rec.Body.String(),
		"preflight must not carry the direct response body")
}

// TestServeDirectResponse_WithoutMiddleware verifies behavior is unchanged
// when no route middleware is configured (no applier, or an empty chain).
func TestServeDirectResponse_WithoutMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rm   RouteMiddlewareApplier
	}{
		{name: "no applier configured", rm: nil},
		{name: "applier with empty chain", rm: &mockRouteMiddlewareApplier{}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			proxy := newDirectResponseProxy(t, tt.rm)

			req := httptest.NewRequest(http.MethodGet, "/direct", nil)
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusTeapot, rec.Code)
			assert.JSONEq(t, `{"direct":true}`, rec.Body.String())
			assert.Equal(t, "configured", rec.Header().Get("X-Direct"))
			assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

// TestServeDirectResponse_MiddlewareOrder verifies arbitrary route
// middleware wraps the direct response terminal (executes before and can
// observe the response), proving directResponse is INSIDE the chain.
func TestServeDirectResponse_MiddlewareOrder(t *testing.T) {
	t.Parallel()

	var order []string
	marker := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "before")
			next.ServeHTTP(w, r)
			order = append(order, "after")
		})
	}
	rm := &mockRouteMiddlewareApplier{
		middlewares: []func(http.Handler) http.Handler{marker},
	}
	proxy := newDirectResponseProxy(t, rm)

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/direct", nil))

	assert.Equal(t, []string{"before", "after"}, order,
		"route middleware must wrap the direct response terminal")
	assert.Equal(t, http.StatusTeapot, rec.Code)
}

// TestServeDirectResponse_RejectingMiddlewareShortCircuits verifies
// admission middleware (auth/rate-limit style) can now reject requests to
// directResponse routes before the response is served.
func TestServeDirectResponse_RejectingMiddlewareShortCircuits(t *testing.T) {
	t.Parallel()

	reject := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	rm := &mockRouteMiddlewareApplier{
		middlewares: []func(http.Handler) http.Handler{reject},
	}
	proxy := newDirectResponseProxy(t, rm)

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/direct", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"rejecting middleware must short-circuit the direct response")
	assert.Empty(t, rec.Body.String())
}
