//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for the API Gateway.
//
// Dedicated CORS E2E tests verify the browser cross-origin contract through
// a REAL running gateway with the production per-route middleware chain:
// OPTIONS preflights (allowed and denied origins), actual-request CORS
// headers, global spec.cors inheritance, and route-level cors overrides.
package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// corsTestPort is the listener port for the CORS e2e gateway.
const corsTestPort = 18471

// corsGatewayConfig builds a gateway config with a GLOBAL spec.cors policy,
// routes inheriting it (live backend + clean mock backend), and a route
// overriding it with stricter rules.
//
// cleanHost/cleanPort point at a mock backend that emits NO CORS headers of
// its own, isolating the gateway middleware's grant semantics on actual
// requests (the reference backend echoes permissive CORS for any origin).
func corsGatewayConfig(
	port int, backendHost string, backendPort int, cleanHost string, cleanPort int,
) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "cors-test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     port,
					Protocol: config.ProtocolHTTP,
					Bind:     "127.0.0.1",
				},
			},
			// Global CORS: inherited by routes without a route-level block.
			CORS: &config.CORSConfig{
				AllowOrigins:  []string{"https://global.example.com", "*.wild.example.com"},
				AllowMethods:  []string{"GET", "POST", "OPTIONS"},
				AllowHeaders:  []string{"Content-Type", "Authorization", "X-Request-ID"},
				ExposeHeaders: []string{"X-Request-ID"},
				MaxAge:        600,
			},
			Routes: []config.Route{
				{
					Name: "inherit-global-cors",
					Match: []config.RouteMatch{
						{
							URI:     &config.URIMatch{Prefix: "/api/v1/items"},
							Methods: []string{http.MethodGet, http.MethodOptions},
						},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: backendHost, Port: backendPort,
							},
						},
					},
				},
				{
					// Clean route: proxied to a mock backend that emits no
					// CORS headers, so every grant observed on this route was
					// produced by the gateway middleware.
					Name: "clean-cors",
					Match: []config.RouteMatch{
						{
							URI:     &config.URIMatch{Prefix: "/clean"},
							Methods: []string{http.MethodGet, http.MethodOptions},
						},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: cleanHost, Port: cleanPort,
							},
						},
					},
				},
				{
					Name: "route-level-cors",
					Match: []config.RouteMatch{
						{
							URI:     &config.URIMatch{Prefix: "/override"},
							Methods: []string{http.MethodGet, http.MethodOptions},
						},
					},
					Rewrite: &config.RewriteConfig{URI: "/api/v1/items"},
					// Route-level override: different origin set + credentials.
					CORS: &config.CORSConfig{
						AllowOrigins:     []string{"https://route.example.com"},
						AllowMethods:     []string{"GET", "OPTIONS"},
						AllowHeaders:     []string{"Content-Type"},
						AllowCredentials: true,
						MaxAge:           300,
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: backendHost, Port: backendPort,
							},
						},
					},
				},
			},
			Backends: []config.Backend{
				{
					Name: "cors-backend",
					Hosts: []config.BackendHost{
						{Address: backendHost, Port: backendPort, Weight: 1},
					},
					HealthCheck: &config.HealthCheck{
						Path:               "/health",
						Interval:           config.Duration(5 * time.Second),
						Timeout:            config.Duration(3 * time.Second),
						HealthyThreshold:   2,
						UnhealthyThreshold: 3,
					},
				},
				{
					Name: "cors-clean-backend",
					Hosts: []config.BackendHost{
						{Address: cleanHost, Port: cleanPort, Weight: 1},
					},
				},
			},
		},
	}
}

// startCORSGateway starts the CORS test gateway with the production
// per-route middleware chain wired, plus a no-CORS mock backend.
func startCORSGateway(t *testing.T, ctx context.Context) *helpers.GatewayInstance {
	t.Helper()

	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	// Mock backend WITHOUT any CORS headers of its own.
	clean := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"clean":true}`))
	}))
	t.Cleanup(clean.Close)
	cleanInfo := helpers.GetGraphQLBackendInfo(clean.Listener.Addr().String())

	backendInfo := helpers.GetGraphQLBackendInfo(testCfg.Backend1URL)
	cfg := corsGatewayConfig(corsTestPort, backendInfo.Host, backendInfo.Port,
		cleanInfo.Host, cleanInfo.Port)

	gi, err := helpers.StartGatewayWithRouteMiddleware(ctx, cfg)
	require.NoError(t, err, "Failed to start CORS gateway")
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = gi.Stop(stopCtx)
	})

	// The route middleware chain answers preflights once routes are live.
	err = helpers.WaitForReady(gi.BaseURL+"/api/v1/items", 10*time.Second)
	require.NoError(t, err, "CORS gateway did not become ready")

	return gi
}

// preflight sends an OPTIONS preflight with the given origin and returns
// the response.
func preflight(t *testing.T, url, origin string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodOptions, url, nil)
	require.NoError(t, err)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")

	resp, err := helpers.HTTPClient().Do(req)
	require.NoError(t, err, "preflight request failed")
	return resp
}

// TestE2E_CORS_PreflightGlobalPolicy verifies OPTIONS preflight behavior on
// a route inheriting the GLOBAL spec.cors policy.
func TestE2E_CORS_PreflightGlobalPolicy(t *testing.T) {
	ctx := context.Background()
	gi := startCORSGateway(t, ctx)
	url := gi.BaseURL + "/api/v1/items"

	t.Run("allowed origin preflight grants CORS", func(t *testing.T) {
		resp := preflight(t, url, "https://global.example.com")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode,
			"preflight must short-circuit with 204")
		assert.Equal(t, "https://global.example.com",
			resp.Header.Get("Access-Control-Allow-Origin"),
			"allowed origin must be echoed")
		assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "GET")
		assert.Contains(t, resp.Header.Get("Access-Control-Allow-Headers"), "Content-Type")
		assert.Equal(t, "600", resp.Header.Get("Access-Control-Max-Age"))
		assert.Equal(t, "Origin", resp.Header.Get("Vary"),
			"Vary: Origin must be set for correct caching")
	})

	t.Run("wildcard subdomain origin preflight grants CORS", func(t *testing.T) {
		resp := preflight(t, url, "https://api.wild.example.com")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		assert.Equal(t, "https://api.wild.example.com",
			resp.Header.Get("Access-Control-Allow-Origin"),
			"wildcard subdomain origin must be granted")
	})

	t.Run("denied origin preflight carries no CORS grant", func(t *testing.T) {
		resp := preflight(t, url, "https://evil.example.org")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode,
			"denied preflight still answers 204 (browser rejects without grant)")
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"),
			"denied origin must NOT receive Access-Control-Allow-Origin")
	})
}

// TestE2E_CORS_ActualRequestHeaders verifies CORS headers on actual (non
// preflight) requests proxied to the backend.
func TestE2E_CORS_ActualRequestHeaders(t *testing.T) {
	ctx := context.Background()
	gi := startCORSGateway(t, ctx)
	url := gi.BaseURL + "/api/v1/items"

	t.Run("allowed origin gets grant plus response", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://global.example.com")

		resp, err := helpers.HTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"actual request must reach the backend")
		assert.Equal(t, []string{"https://global.example.com"},
			resp.Header.Values("Access-Control-Allow-Origin"),
			"exactly the gateway grant, never merged with a backend grant")
		assert.Contains(t, resp.Header.Get("Access-Control-Expose-Headers"), "X-Request-ID")
	})

	t.Run("denied origin gets no gateway grant on clean route", func(t *testing.T) {
		// The clean route's backend emits no CORS headers, so the absence
		// of a grant proves the gateway middleware denied the origin.
		req, err := http.NewRequest(http.MethodGet, gi.BaseURL+"/clean", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://evil.example.org")

		resp, err := helpers.HTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"server-side CORS does not block; the browser enforces")
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"),
			"denied origin must NOT receive a gateway CORS grant")
	})

	t.Run("allowed origin gets gateway grant on clean route", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, gi.BaseURL+"/clean", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://global.example.com")

		resp, err := helpers.HTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "https://global.example.com",
			resp.Header.Get("Access-Control-Allow-Origin"))
	})

	t.Run("backend CORS headers stripped for denied origin on proxied routes", func(t *testing.T) {
		// GATEWAY CORS IS AUTHORITATIVE: the reference backend emits its
		// own permissive CORS headers on actual (non-preflight) requests,
		// but when a gateway CORS policy is configured on the route the
		// backend's Access-Control-* headers are stripped and replaced by
		// the gateway's grant decision. A denied origin must therefore see
		// NO grant, even though the backend issued one.
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://evil.example.org")

		resp, err := helpers.HTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"),
			"backend grant must not leak through the gateway for denied origins")
	})

	t.Run("same-origin request without Origin header unaffected", func(t *testing.T) {
		resp, err := helpers.HTTPClient().Get(gi.BaseURL + "/clean")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
	})
}

// TestE2E_CORS_RouteLevelOverride verifies that a route-level cors block
// fully overrides the global policy on that route only.
func TestE2E_CORS_RouteLevelOverride(t *testing.T) {
	ctx := context.Background()
	gi := startCORSGateway(t, ctx)
	overrideURL := gi.BaseURL + "/override"
	globalURL := gi.BaseURL + "/api/v1/items"

	t.Run("route origin allowed on override route", func(t *testing.T) {
		resp := preflight(t, overrideURL, "https://route.example.com")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		assert.Equal(t, "https://route.example.com",
			resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"),
			"route-level allowCredentials must apply")
		assert.Equal(t, "300", resp.Header.Get("Access-Control-Max-Age"),
			"route-level maxAge must override the global value")
	})

	t.Run("globally-allowed origin denied on override route", func(t *testing.T) {
		resp := preflight(t, overrideURL, "https://global.example.com")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"),
			"route-level cors must replace (not extend) the global origin set")
	})

	t.Run("route-allowed origin denied on global route", func(t *testing.T) {
		resp := preflight(t, globalURL, "https://route.example.com")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"),
			"route-level origins must not leak into other routes")
	})

	t.Run("actual GET on override route honors route policy", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, overrideURL, nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://route.example.com")

		resp, err := helpers.HTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "https://route.example.com",
			resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	})
}

// TestE2E_CORS_UnmatchedPreflight verifies that a preflight for a path with
// no matching route is not granted CORS.
func TestE2E_CORS_UnmatchedPreflight(t *testing.T) {
	ctx := context.Background()
	gi := startCORSGateway(t, ctx)

	resp := preflight(t, gi.BaseURL+"/no-such-route", "https://global.example.com")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"unmatched preflight must 404 (no route, no CORS middleware)")
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}
