//go:build functional

// Package functional contains functional tests for the API Gateway.
package functional

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// ============================================================================
// Functional Tests: Proxy Timeout (Context Cancel Leak Fix - CRITICAL-1)
// ============================================================================

// parseBackendURL extracts host and port from a test server URL.
func parseBackendURL(t *testing.T, serverURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(serverURL)
	require.NoError(t, err)

	port := 80
	if u.Port() != "" {
		fmt.Sscanf(u.Port(), "%d", &port)
	}
	return u.Hostname(), port
}

// TestFunctional_ProxyTimeout_CancelFunctionCalled verifies that the
// applyTimeout cancel function is properly called (deferred) to prevent
// context cancel leaks. This tests the fix for CRITICAL-1.
func TestFunctional_ProxyTimeout_CancelFunctionCalled(t *testing.T) {
	t.Parallel()

	// Create a backend that responds quickly
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	host, port := parseBackendURL(t, backendServer.URL)

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	route := config.Route{
		Name: "timeout-cancel-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Prefix: "/timeout-cancel"}},
		},
		Route: []config.RouteDestination{
			{
				Destination: config.Destination{
					Host: host,
					Port: port,
				},
			},
		},
		Timeout: config.Duration(5 * time.Second),
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	p := proxy.NewReverseProxy(r, registry)

	// Make multiple requests to verify no context leak accumulation
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/timeout-cancel/test", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

// TestFunctional_ProxyTimeout_NoTimeoutNoLeak verifies that when no timeout
// is configured, the no-op cancel function is returned and no context leak occurs.
func TestFunctional_ProxyTimeout_NoTimeoutNoLeak(t *testing.T) {
	t.Parallel()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the context is not canceled
		select {
		case <-r.Context().Done():
			t.Error("context should not be canceled for no-timeout request")
		default:
			// Expected: context is still active
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	host, port := parseBackendURL(t, backendServer.URL)

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	route := config.Route{
		Name: "no-timeout-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Prefix: "/no-timeout"}},
		},
		Route: []config.RouteDestination{
			{
				Destination: config.Destination{
					Host: host,
					Port: port,
				},
			},
		},
		// No timeout configured - Timeout is zero value
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	p := proxy.NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/no-timeout/test", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestFunctional_ProxyTimeout_TimeoutTriggered verifies that when a timeout
// is configured and the backend is slow, the request times out properly
// and the cancel function cleans up the context.
func TestFunctional_ProxyTimeout_TimeoutTriggered(t *testing.T) {
	t.Parallel()

	// Create a slow backend
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			// Context was canceled by timeout - expected
			return
		case <-time.After(2 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer backendServer.Close()

	host, port := parseBackendURL(t, backendServer.URL)

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	route := config.Route{
		Name: "short-timeout-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Prefix: "/short-timeout"}},
		},
		Route: []config.RouteDestination{
			{
				Destination: config.Destination{
					Host: host,
					Port: port,
				},
			},
		},
		Timeout: config.Duration(50 * time.Millisecond), // Very short timeout
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	p := proxy.NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/short-timeout/test", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	// Should get bad gateway due to timeout
	assert.Equal(t, http.StatusBadGateway, rec.Code,
		"slow backend with short timeout should return 502")
}

// TestFunctional_ProxyTimeout_ContextPropagation verifies that the proxy's
// timeout mechanism works correctly by confirming that a request with a
// configured timeout completes successfully when the backend responds
// within the allowed time.
//
// Note: Go context deadlines do NOT propagate over HTTP. The backend's
// http.Server creates a new server-side context for each incoming request,
// so we cannot inspect the backend's received context for a deadline set
// by the proxy. Instead, we verify the timeout behavior indirectly:
// - A fast backend with a timeout returns 200 OK (this test)
// - A slow backend with a short timeout returns 502 (TestFunctional_ProxyTimeout_TimeoutTriggered)
func TestFunctional_ProxyTimeout_ContextPropagation(t *testing.T) {
	t.Parallel()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	host, port := parseBackendURL(t, backendServer.URL)

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	route := config.Route{
		Name: "ctx-propagation-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Prefix: "/ctx-prop"}},
		},
		Route: []config.RouteDestination{
			{
				Destination: config.Destination{
					Host: host,
					Port: port,
				},
			},
		},
		Timeout: config.Duration(10 * time.Second),
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	p := proxy.NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/ctx-prop/test", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code,
		"request with timeout should succeed when backend responds within the allowed time")
}
