// Tests for WP2 (FULL_SYNC empty-type clears routers): applyMerged* must
// treat FULL_SYNC snapshots as authoritative and apply EMPTY resource sets so
// routers/registries clear when the last resource of a type is deleted,
// while populated types stay intact. Emptiness policy (all-empty guard +
// regression window) lives upstream in operator.ConfigHandler, not here.
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// newEmptyClearApplier builds an applier whose app carries an HTTP router, a
// backend registry, and a GraphQL router — all preloaded with one resource —
// so tests can assert which components clear on empty merged sets.
func newEmptyClearApplier(t *testing.T, name string) (*gatewayConfigApplier, *application) {
	t.Helper()
	logger := observability.NopLogger()
	cfg := createTestGatewayConfig(name)

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	httpRouter := router.New()
	require.NoError(t, httpRouter.LoadRoutes([]config.Route{
		{
			Name:  "seed-http-route",
			Match: []config.RouteMatch{{URI: &config.URIMatch{Prefix: "/api"}}},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		},
	}))

	gqlRouter := graphqlrouter.New(graphqlrouter.WithRouterLogger(logger))
	require.NoError(t, gqlRouter.LoadRoutes([]config.GraphQLRoute{
		{
			Name:  "seed-graphql-route",
			Match: []config.GraphQLRouteMatch{{Path: &config.StringMatch{Exact: "/graphql"}}},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 4000}},
			},
		},
	}))

	app := &application{
		gateway:         gw,
		router:          httpRouter,
		backendRegistry: backend.NewRegistry(logger),
		graphqlRouter:   gqlRouter,
		config:          cfg,
	}
	opApp := &operatorApplication{application: app}

	return &gatewayConfigApplier{app: opApp, logger: logger}, app
}

// TestApplyMergedComponents_EmptyGraphQLClearsRouterHTTPIntact is the core
// WP2 scenario: a FULL_SYNC with zero GraphQL routes but populated HTTP
// routes clears the GraphQL router while HTTP routes stay intact.
func TestApplyMergedComponents_EmptyGraphQLClearsRouterHTTPIntact(t *testing.T) {
	t.Parallel()

	applier, app := newEmptyClearApplier(t, "test-empty-gql")
	require.Equal(t, 1, app.graphqlRouter.RouteCount())

	merged := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Routes: []config.Route{
				{
					Name:  "kept-http-route",
					Match: []config.RouteMatch{{URI: &config.URIMatch{Prefix: "/api"}}},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "localhost", Port: 8080}},
					},
				},
			},
			GraphQLRoutes: nil, // authoritative: last GraphQL route was deleted
		},
	}

	require.NoError(t, applier.applyMergedComponents(context.Background(), merged))

	assert.Equal(t, 0, app.graphqlRouter.RouteCount(),
		"empty GraphQL route set must clear the GraphQL router")

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	result, err := app.router.Match(req)
	require.NoError(t, err, "HTTP routes must stay intact")
	assert.Equal(t, "kept-http-route", result.Route.Name)
}

// TestApplyMergedComponents_EmptyHTTPRoutesClearsRouter verifies deleting the
// last HTTP route clears the HTTP router.
func TestApplyMergedComponents_EmptyHTTPRoutesClearsRouter(t *testing.T) {
	t.Parallel()

	applier, app := newEmptyClearApplier(t, "test-empty-http")
	require.Len(t, app.router.GetRoutes(), 1)

	merged := &config.GatewayConfig{Spec: config.GatewaySpec{}}
	require.NoError(t, applier.applyMergedComponents(context.Background(), merged))

	assert.Empty(t, app.router.GetRoutes(),
		"empty HTTP route set must clear the HTTP router")
	assert.Equal(t, 0, app.graphqlRouter.RouteCount(),
		"empty GraphQL route set must clear the GraphQL router")
}

// TestApplyMergedComponents_EmptyBackendsClearsRegistry verifies deleting the
// last backend clears the backend registry.
func TestApplyMergedComponents_EmptyBackendsClearsRegistry(t *testing.T) {
	t.Parallel()

	applier, app := newEmptyClearApplier(t, "test-empty-backends")
	ctx := context.Background()

	require.NoError(t, app.backendRegistry.ReloadFromConfig(ctx, []config.Backend{
		{Name: "seed-backend", Hosts: []config.BackendHost{{Address: "localhost", Port: 8080}}},
	}))
	require.Len(t, app.backendRegistry.GetAll(), 1)

	merged := &config.GatewayConfig{Spec: config.GatewaySpec{}}
	require.NoError(t, applier.applyMergedComponents(ctx, merged))

	assert.Empty(t, app.backendRegistry.GetAll(),
		"empty backend set must clear the backend registry")
}

// TestApplyMergedGRPCComponents_EmptyClearsListenerRoutes verifies deleting
// the last GRPCRoute clears every gRPC listener's routing table.
func TestApplyMergedGRPCComponents_EmptyClearsListenerRoutes(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-empty-grpc"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, gw.Start(ctx))
	defer func() { _ = gw.Stop(ctx) }()
	require.Len(t, gw.GetGRPCListeners(), 1)

	// Seed the listener with one gRPC route.
	seed := []config.GRPCRoute{
		{
			Name:  "seed-grpc-route",
			Match: []config.GRPCRouteMatch{{Service: &config.StringMatch{Exact: "test.Service"}}},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50051}},
			},
		},
	}
	listener := gw.GetGRPCListeners()[0]
	require.NoError(t, listener.LoadRoutes(seed))
	require.Equal(t, 1, listener.Router().RouteCount())

	applier := &gatewayConfigApplier{
		app:    &operatorApplication{application: &application{gateway: gw, config: cfg}},
		logger: logger,
	}

	merged := &config.GatewayConfig{Spec: config.GatewaySpec{}}
	require.NoError(t, applier.applyMergedGRPCComponents(ctx, merged))

	assert.Equal(t, 0, listener.Router().RouteCount(),
		"empty gRPC route set must clear the listener's routing table")
}

// TestApplyMergedGRPCComponents_NilGateway verifies the nil-component guard:
// a missing gateway skips gRPC application entirely without error.
func TestApplyMergedGRPCComponents_NilGateway(t *testing.T) {
	t.Parallel()

	applier := &gatewayConfigApplier{
		app:    &operatorApplication{application: &application{gateway: nil}},
		logger: observability.NopLogger(),
	}

	merged := &config.GatewayConfig{Spec: config.GatewaySpec{
		GRPCRoutes: []config.GRPCRoute{{Name: "route"}},
	}}
	assert.NoError(t, applier.applyMergedGRPCComponents(context.Background(), merged))
}

// TestApplyMergedGraphQLComponents_EmptyClearsGraphQLRouter verifies the
// GraphQL-specific applier clears the router on an empty set.
func TestApplyMergedGraphQLComponents_EmptyClearsGraphQLRouter(t *testing.T) {
	t.Parallel()

	applier, app := newEmptyClearApplier(t, "test-empty-gql-only")
	require.Equal(t, 1, app.graphqlRouter.RouteCount())

	merged := &config.GatewayConfig{Spec: config.GatewaySpec{}}
	require.NoError(t, applier.applyMergedGraphQLComponents(context.Background(), merged))

	assert.Equal(t, 0, app.graphqlRouter.RouteCount())
}

// TestApplyMergedComponents_GraphQLErrorPropagates verifies a GraphQL route
// compile failure inside applyMergedGraphQLComponents propagates out of
// applyMergedComponents.
func TestApplyMergedComponents_GraphQLErrorPropagates(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-gql-err-propagate")
	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	applier := &gatewayConfigApplier{
		app: &operatorApplication{application: &application{
			gateway:       gw,
			graphqlRouter: graphqlrouter.New(graphqlrouter.WithRouterLogger(logger)),
			config:        cfg,
		}},
		logger: logger,
	}

	merged := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name:  "bad-regex-route",
					Match: []config.GraphQLRouteMatch{{Path: &config.StringMatch{Regex: "[invalid"}}},
				},
			},
		},
	}

	err = applier.applyMergedComponents(context.Background(), merged)
	assert.Error(t, err, "GraphQL route compile failure must propagate")
}

// TestApplyMergedComponents_GRPCErrorPropagates verifies a gRPC route
// compile failure inside applyMergedGRPCComponents propagates out of
// applyMergedComponents.
func TestApplyMergedComponents_GRPCErrorPropagates(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-grpc-err-propagate"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}
	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, gw.Start(ctx))
	defer func() { _ = gw.Stop(ctx) }()
	require.NotEmpty(t, gw.GetGRPCListeners())

	applier := &gatewayConfigApplier{
		app:    &operatorApplication{application: &application{gateway: gw, config: cfg}},
		logger: logger,
	}

	merged := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			GRPCRoutes: []config.GRPCRoute{
				{
					Name:  "bad-grpc-route",
					Match: []config.GRPCRouteMatch{{Service: &config.StringMatch{Regex: "[invalid"}}},
				},
			},
		},
	}

	err = applier.applyMergedComponents(ctx, merged)
	assert.Error(t, err, "gRPC route compile failure must propagate")
}

// TestApplyFullConfig_PartialEmptyClearsOnlyEmptyTypes exercises the full
// FULL_SYNC apply path: HTTP routes populated, GraphQL routes empty — the
// GraphQL router clears while the HTTP router serves the new route set.
func TestApplyFullConfig_PartialEmptyClearsOnlyEmptyTypes(t *testing.T) {
	t.Parallel()

	applier, app := newEmptyClearApplier(t, "test-full-partial-empty")
	require.Equal(t, 1, app.graphqlRouter.RouteCount())

	operatorCfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Routes: []config.Route{
				{
					Name:  "operator-http-route",
					Match: []config.RouteMatch{{URI: &config.URIMatch{Prefix: "/api"}}},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "localhost", Port: 8080}},
					},
				},
			},
			// GraphQL, gRPC, and backend sets intentionally empty.
		},
	}

	require.NoError(t, applier.ApplyFullConfig(context.Background(), operatorCfg))

	assert.Equal(t, 0, app.graphqlRouter.RouteCount(),
		"FULL_SYNC with zero GraphQL routes must clear the GraphQL router")

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	result, err := app.router.Match(req)
	require.NoError(t, err)
	assert.Equal(t, "operator-http-route", result.Route.Name,
		"HTTP routes from the snapshot must be served")
}
