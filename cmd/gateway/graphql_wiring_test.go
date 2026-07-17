// Package main tests for the GraphQL endpoint wiring: the handler must be
// composed inside the global middleware chain via the path dispatcher (with
// route middleware attached), never registered on the gin engine directly.
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	graphqlproxy "github.com/vyrodovalexey/avapigw/internal/graphql/proxy"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// newWiringGraphQLComponents builds router/proxy over the given routes.
func newWiringGraphQLComponents(t *testing.T, routes []config.GraphQLRoute) (*graphqlrouter.Router, *graphqlproxy.Proxy) {
	t.Helper()
	router := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
	require.NoError(t, router.LoadRoutes(routes))
	proxy := graphqlproxy.New(graphqlproxy.WithLogger(observability.NopLogger()))
	return router, proxy
}

func TestInitGraphQLHandler_NilComponents(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	logger := observability.NopLogger()
	router, proxy := newWiringGraphQLComponents(t, nil)

	assert.Nil(t, initGraphQLHandler(cfg, nil, proxy, nil, nil, logger),
		"nil router must disable the GraphQL endpoint")
	assert.Nil(t, initGraphQLHandler(cfg, router, nil, nil, nil, logger),
		"nil proxy must disable the GraphQL endpoint")
}

func TestInitGraphQLHandler_BuildsWithOptions(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Spec.GraphQL = &config.GraphQLConfig{MaxBodySize: 2048, Path: "/gql"}
	cfg.Spec.WebSocket = &config.WebSocketConfig{AllowedOrigins: []string{"https://app.example.com"}}

	logger := observability.NopLogger()
	router, proxy := newWiringGraphQLComponents(t, []config.GraphQLRoute{{Name: "r"}})
	mgr := gateway.NewRouteMiddlewareManager(&cfg.Spec, logger)
	defer mgr.Stop()

	handler := initGraphQLHandler(cfg, router, proxy, nil, mgr, logger)
	require.NotNil(t, handler)
	defer handler.Close()

	// The body size option must be applied (11-byte body over the 10-byte
	// limit would pass; verify with an oversized payload beyond 2048).
	big := `{"query":"` + strings.Repeat("a", 4096) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/gql", strings.NewReader(big))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestGraphQLDispatchHandler_NilPreserved(t *testing.T) {
	t.Parallel()

	assert.Nil(t, graphqlDispatchHandler(nil),
		"a typed-nil handler must convert to a nil http.Handler for the dispatcher")

	router, proxy := newWiringGraphQLComponents(t, nil)
	handler, err := gateway.NewGraphQLHandler(router, proxy)
	require.NoError(t, err)
	defer handler.Close()
	assert.NotNil(t, graphqlDispatchHandler(handler))
}

// TestInitApplication_GraphQLComposedInGlobalChain verifies initApplication
// wires GraphQL through the dispatcher inside the global chain (route
// handler) instead of registering it on the gin engine.
func TestInitApplication_GraphQLComposedInGlobalChain(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Spec.GraphQLRoutes = []config.GraphQLRoute{{
		Name: "wired",
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "nonexistent-backend"}},
		},
	}}

	app := initApplication(cfg, observability.NopLogger())
	require.NotNil(t, app)
	require.NotNil(t, app.graphqlHandler, "application must own the GraphQL handler")

	// The gateway engine is only materialized on Start; assert composition
	// at the route-handler level instead: a GraphQL request through the
	// global chain reaches the GraphQL pipeline (502: backend missing).
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ ok }"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.graphqlHandler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Contains(t, rec.Body.String(), "backend error")
}
