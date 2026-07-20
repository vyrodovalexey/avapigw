//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
//
// Dedicated CORS preflight tests black-box the production per-route
// middleware chain (RouteMiddlewareManager): OPTIONS preflights and actual
// requests are pushed through the chain a matched route would execute,
// asserting the browser-visible CORS contract for global and route-level
// policies. Data-driven per scenario.
package functional

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// newCORSChainHandler builds the production route middleware chain for a
// route with the given CORS blocks and wraps a marker terminal handler.
func newCORSChainHandler(
	routeCORS, globalCORS *config.CORSConfig,
) http.Handler {
	spec := &config.GatewaySpec{
		CORS: globalCORS,
		Routes: []config.Route{
			{
				Name: "cors-func-route",
				Match: []config.RouteMatch{
					{URI: &config.URIMatch{Prefix: "/api"}},
				},
				CORS: routeCORS,
			},
		},
	}

	mgr := gateway.NewRouteMiddlewareManager(spec, observability.NopLogger())

	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Backend-Reached", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	return mgr.ApplyMiddleware(terminal, &spec.Routes[0])
}

// TestFunctional_CORS_Preflight is a data-driven preflight matrix over
// global-only, route-only, and route-overriding-global CORS policies.
func TestFunctional_CORS_Preflight(t *testing.T) {
	t.Parallel()

	globalPolicy := &config.CORSConfig{
		AllowOrigins:  []string{"https://global.example.com", "*.wild.example.com"},
		AllowMethods:  []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:  []string{"Content-Type", "Authorization"},
		ExposeHeaders: []string{"X-Request-ID"},
		MaxAge:        600,
	}
	routePolicy := &config.CORSConfig{
		AllowOrigins:     []string{"https://route.example.com"},
		AllowMethods:     []string{"GET", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}

	tests := []struct {
		name            string
		routeCORS       *config.CORSConfig
		globalCORS      *config.CORSConfig
		origin          string
		wantStatus      int
		wantGrant       string // expected Access-Control-Allow-Origin ("" = none)
		wantCredentials string
		wantMaxAge      string
	}{
		{
			name:       "global policy grants allowed origin",
			globalCORS: globalPolicy,
			origin:     "https://global.example.com",
			wantStatus: http.StatusNoContent,
			wantGrant:  "https://global.example.com",
			wantMaxAge: "600",
		},
		{
			name:       "global policy grants wildcard subdomain",
			globalCORS: globalPolicy,
			origin:     "https://deep.wild.example.com",
			wantStatus: http.StatusNoContent,
			wantGrant:  "https://deep.wild.example.com",
			wantMaxAge: "600",
		},
		{
			name:       "global policy denies unknown origin",
			globalCORS: globalPolicy,
			origin:     "https://evil.example.org",
			wantStatus: http.StatusNoContent,
			wantGrant:  "",
		},
		{
			name:            "route policy overrides global for its origin",
			routeCORS:       routePolicy,
			globalCORS:      globalPolicy,
			origin:          "https://route.example.com",
			wantStatus:      http.StatusNoContent,
			wantGrant:       "https://route.example.com",
			wantCredentials: "true",
			wantMaxAge:      "300",
		},
		{
			name:       "route policy replaces global origin set",
			routeCORS:  routePolicy,
			globalCORS: globalPolicy,
			origin:     "https://global.example.com",
			wantStatus: http.StatusNoContent,
			wantGrant:  "",
		},
		{
			name:            "route-only policy without global",
			routeCORS:       routePolicy,
			origin:          "https://route.example.com",
			wantStatus:      http.StatusNoContent,
			wantGrant:       "https://route.example.com",
			wantCredentials: "true",
			wantMaxAge:      "300",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := newCORSChainHandler(tt.routeCORS, tt.globalCORS)

			req := httptest.NewRequest(http.MethodOptions, "/api/items", nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Access-Control-Request-Method", http.MethodGet)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code,
				"preflight must short-circuit with the expected status")
			assert.Equal(t, tt.wantGrant,
				rec.Header().Get("Access-Control-Allow-Origin"))
			assert.Empty(t, rec.Header().Get("X-Backend-Reached"),
				"preflight must never reach the terminal handler")

			if tt.wantCredentials != "" {
				assert.Equal(t, tt.wantCredentials,
					rec.Header().Get("Access-Control-Allow-Credentials"))
			}
			if tt.wantMaxAge != "" {
				assert.Equal(t, tt.wantMaxAge,
					rec.Header().Get("Access-Control-Max-Age"))
			}
		})
	}
}

// newLayeredCORSHandler composes the production layering: the GLOBAL CORS
// middleware (with the route-CORS skipper) wrapping a route dispatcher that
// applies each matched route's own middleware chain — the same
// global-chain -> proxy -> route-chain nesting cmd/gateway builds.
func newLayeredCORSHandler(t *testing.T, spec *config.GatewaySpec) http.Handler {
	t.Helper()

	r := router.New()
	require.NoError(t, r.LoadRoutes(spec.Routes))

	mgr := gateway.NewRouteMiddlewareManager(spec, observability.NopLogger())

	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") // backend grant, must be stripped
		w.Header().Set("X-Backend-Reached", "true")
		w.WriteHeader(http.StatusOK)
	})

	dispatcher := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		result, err := r.Match(req)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		mgr.ApplyMiddleware(terminal, &result.Route.Config).ServeHTTP(w, req)
	})

	skip := gateway.NewRouteCORSSkipper(r, nil, "/graphql")
	return middleware.CORSFromConfigWithSkipper(spec.CORS, skip)(dispatcher)
}

// TestFunctional_CORS_RoutePolicyPrecedenceOverGlobal proves the fix for
// "route-level CORS shadowed by global * CORS on preflight": with a global
// wildcard policy in the static chain, a route defining its own cors block
// is answered by the ROUTE policy (allowed and denied paths), while routes
// without route CORS keep the global behavior.
func TestFunctional_CORS_RoutePolicyPrecedenceOverGlobal(t *testing.T) {
	t.Parallel()

	spec := &config.GatewaySpec{
		CORS: &config.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowMethods: []string{"GET", "POST", "OPTIONS"},
			AllowHeaders: []string{"Content-Type"},
			MaxAge:       86400,
		},
		Routes: []config.Route{
			{
				Name: "cors-route",
				Match: []config.RouteMatch{
					{
						URI:     &config.URIMatch{Prefix: "/api/v1/cors/"},
						Methods: []string{"GET", "POST", "OPTIONS"},
					},
				},
				CORS: &config.CORSConfig{
					AllowOrigins: []string{"https://cors-test.example.com"},
					AllowMethods: []string{"GET", "POST", "OPTIONS"},
					AllowHeaders: []string{"Content-Type", "Authorization", "X-Request-ID"},
					MaxAge:       3600,
				},
			},
			{
				Name: "plain-route",
				Match: []config.RouteMatch{
					{
						URI:     &config.URIMatch{Prefix: "/api/v1/items"},
						Methods: []string{"GET", "OPTIONS"},
					},
				},
			},
		},
	}

	handler := newLayeredCORSHandler(t, spec)

	preflight := func(path, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodOptions, path, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	t.Run("route policy answers allowed-origin preflight", func(t *testing.T) {
		rec := preflight("/api/v1/cors/items", "https://cors-test.example.com")
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://cors-test.example.com",
			rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "3600", rec.Header().Get("Access-Control-Max-Age"),
			"ROUTE maxAge must win over global 86400")
	})

	t.Run("route policy denies non-listed origin despite global wildcard", func(t *testing.T) {
		rec := preflight("/api/v1/cors/items", "https://evil.example.org")
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"),
			"global * must NOT answer preflight for a route with route CORS")
	})

	t.Run("route policy owns actual-request grant (single, authoritative)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/cors/items", nil)
		req.Header.Set("Origin", "https://cors-test.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, []string{"https://cors-test.example.com"},
			rec.Header().Values("Access-Control-Allow-Origin"),
			"backend grant stripped; exactly one route grant; global layer silent")
	})

	t.Run("route without route CORS keeps global wildcard behavior", func(t *testing.T) {
		rec := preflight("/api/v1/items", "https://anywhere.example.net")
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://anywhere.example.net",
			rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "86400", rec.Header().Get("Access-Control-Max-Age"))
	})
}

// TestFunctional_CORS_ActualRequest verifies actual-request (non-OPTIONS)
// CORS behavior through the chain: grants for allowed origins, no grant for
// denied origins, and pass-through to the terminal handler either way.
func TestFunctional_CORS_ActualRequest(t *testing.T) {
	t.Parallel()

	policy := &config.CORSConfig{
		AllowOrigins:  []string{"https://app.example.com"},
		AllowMethods:  []string{"GET", "OPTIONS"},
		AllowHeaders:  []string{"Content-Type"},
		ExposeHeaders: []string{"X-Request-ID"},
		MaxAge:        120,
	}

	tests := []struct {
		name       string
		origin     string
		wantGrant  string
		wantExpose string
	}{
		{
			name:       "allowed origin grant with expose headers",
			origin:     "https://app.example.com",
			wantGrant:  "https://app.example.com",
			wantExpose: "X-Request-ID",
		},
		{
			name:      "denied origin no grant",
			origin:    "https://evil.example.org",
			wantGrant: "",
		},
		{
			name:      "no origin header no grant",
			origin:    "",
			wantGrant: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := newCORSChainHandler(policy, nil)

			req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "true", rec.Header().Get("X-Backend-Reached"),
				"actual requests must reach the terminal handler")
			assert.Equal(t, tt.wantGrant,
				rec.Header().Get("Access-Control-Allow-Origin"))
			if tt.wantExpose != "" {
				assert.Contains(t,
					rec.Header().Get("Access-Control-Expose-Headers"), tt.wantExpose)
			}
			if tt.wantGrant != "" {
				assert.Equal(t, "Origin", rec.Header().Get("Vary"),
					"granted responses must set Vary: Origin")
			}
		})
	}
}
