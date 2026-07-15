// Package gateway tests for the embedded-mode GraphQL wiring: gateway
// options propagate the aggregator, route middleware, and subscription
// origins into the handler built by setupRoutes, and Stop closes the
// handler's subscription relays.
package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	graphqlproxy "github.com/vyrodovalexey/avapigw/internal/graphql/proxy"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestGatewayOptions_GraphQLWiring verifies the gateway options store the
// GraphQL collaborators used by setupRoutes.
func TestGatewayOptions_GraphQLWiring(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{Metadata: config.Metadata{Name: "test-gw"}}
	agg := &stubGraphQLAggregator{}
	mgr := NewRouteMiddlewareManager(nil, observability.NopLogger())
	defer mgr.Stop()

	gw, err := New(cfg,
		WithGraphQLAggregateHandler(agg),
		WithGraphQLRouteMiddleware(mgr),
	)
	require.NoError(t, err)

	assert.NotNil(t, gw.graphqlAggregator)
	assert.NotNil(t, gw.graphqlRouteMiddleware)
}

// TestSetupRoutes_GraphQLRouteMiddlewareEnforced verifies the embedded
// (gin-registered) GraphQL path also enforces route middleware.
func TestSetupRoutes_GraphQLRouteMiddlewareEnforced(t *testing.T) {
	t.Parallel()

	routes := []config.GraphQLRoute{{
		Name: "limited",
		RateLimit: &config.RateLimitConfig{
			Enabled: true, RequestsPerSecond: 100, Burst: 1,
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "missing-backend"}},
		},
	}}

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQLRoutes: routes,
			WebSocket:     &config.WebSocketConfig{AllowedOrigins: []string{"https://app.example.com"}},
		},
	}

	router := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
	require.NoError(t, router.LoadRoutes(routes))
	proxy := graphqlproxy.New(graphqlproxy.WithLogger(observability.NopLogger()))

	mgr := NewRouteMiddlewareManager(nil, observability.NopLogger())
	defer mgr.Stop()

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGraphQLRouter(router),
		WithGraphQLProxy(proxy),
		WithGraphQLRouteMiddleware(mgr),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	gw.engine = gin.New()
	gw.setupRoutes()
	require.NotNil(t, gw.graphqlHandler, "setupRoutes must build the shared GraphQL handler")

	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ ok }"}`))
		rec := httptest.NewRecorder()
		gw.engine.ServeHTTP(rec, req)
		return rec
	}

	// First request consumes the burst (fails at the backend → 502);
	// the second is throttled by the ROUTE middleware → 429.
	first := post()
	require.Equal(t, http.StatusBadGateway, first.Code)
	second := post()
	assert.Equal(t, http.StatusTooManyRequests, second.Code,
		"gin-registered GraphQL endpoint must enforce route middleware")

	// OPTIONS is registered for preflight handling (behavior covered in
	// graphql_handler_test.go; here we assert the gin registration).
	foundOptions := false
	for _, r := range gw.engine.Routes() {
		if r.Path == "/graphql" && r.Method == http.MethodOptions {
			foundOptions = true
		}
	}
	assert.True(t, foundOptions, "OPTIONS /graphql must be registered for preflight")
}

// TestGatewayStop_ClosesGraphQLSubscriptions verifies Stop closes the
// embedded handler's subscription relays without error.
func TestGatewayStop_ClosesGraphQLSubscriptions(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{{Name: "http", Port: 0, Protocol: "HTTP"}},
			GraphQLRoutes: []config.GraphQLRoute{{
				Name: "catch-all",
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "b"}},
				},
			}},
		},
	}

	router := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
	require.NoError(t, router.LoadRoutes(cfg.Spec.GraphQLRoutes))
	proxy := graphqlproxy.New(graphqlproxy.WithLogger(observability.NopLogger()))

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGraphQLRouter(router),
		WithGraphQLProxy(proxy),
	)
	require.NoError(t, err)

	ctx := t.Context()
	require.NoError(t, gw.Start(ctx))
	require.NotNil(t, gw.graphqlHandler)
	require.NoError(t, gw.Stop(ctx))
}

// TestGraphQLHandler_SubscriptionOriginAllowlist verifies the origin
// allowlist option reaches the subscription upgrader.
func TestGraphQLHandler_SubscriptionOriginAllowlist(t *testing.T) {
	t.Parallel()

	routes := []config.GraphQLRoute{{
		Name: "sub",
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: testGraphQLBackendName}},
		},
	}}
	router := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
	require.NoError(t, router.LoadRoutes(routes))
	proxy := graphqlproxy.New(graphqlproxy.WithLogger(observability.NopLogger()))
	// Backend resolution precedes the upgrade; register a placeholder host
	// (never dialed — the origin check rejects the handshake first).
	proxy.UpdateBackends([]config.GraphQLBackend{
		{Name: testGraphQLBackendName, Hosts: []config.BackendHost{{Address: "127.0.0.1", Port: 1}}},
	})

	handler, err := NewGraphQLHandler(router, proxy,
		WithGraphQLHandlerLogger(observability.NopLogger()),
		WithGraphQLHandlerSubscriptionOrigins([]string{"https://allowed.example.com"}),
	)
	require.NoError(t, err)
	defer handler.Close()

	front := httptest.NewServer(handler)
	defer front.Close()

	// A browser-style upgrade with a disallowed Origin is rejected by the
	// upgrader's origin check (403 from gorilla/websocket).
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, front.URL+"/graphql", nil)
	require.NoError(t, err)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Origin", "https://evil.example.com")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"disallowed origins must be rejected during the subscription handshake")
}
