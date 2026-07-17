// Package router tests for deterministic gRPC route ordering: equal-priority
// routes must resolve by ascending route name regardless of insertion order
// (mirrors internal/router/router_determinism_test.go — WP4 load-time
// ordering audit ported to the gRPC router).
package router

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// samePriorityGRPCRoute builds a route whose priority is identical for every
// name (same service prefix, so same specificity: 500 + len(prefix)).
func samePriorityGRPCRoute(name string) config.GRPCRoute {
	return config.GRPCRoute{
		Name: name,
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "test."}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: name + "-backend", Port: 50051}},
		},
	}
}

// TestRouter_EqualPriorityNameTieBreak verifies two same-priority routes
// always order by name, for both insertion orders.
func TestRouter_EqualPriorityNameTieBreak(t *testing.T) {
	t.Parallel()

	routeA := samePriorityGRPCRoute("aaa-route")
	routeB := samePriorityGRPCRoute("bbb-route")

	for _, order := range [][]config.GRPCRoute{{routeA, routeB}, {routeB, routeA}} {
		r := New()
		require.NoError(t, r.LoadRoutes(order))

		result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
		require.NoError(t, err)
		assert.Equal(t, "aaa-route", result.Route.Name,
			"equal priority must tie-break by ascending name")
	}
}

// TestRouter_EqualPriorityRegexPair_NameTieBreak pins the tie-break for the
// deliberately-admitted equal-priority case: two regex service matches share
// priority 100, so only the name orders them.
func TestRouter_EqualPriorityRegexPair_NameTieBreak(t *testing.T) {
	t.Parallel()

	regexRoute := func(name, pattern string) config.GRPCRoute {
		return config.GRPCRoute{
			Name: name,
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Regex: pattern}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: name + "-backend", Port: 50051}},
			},
		}
	}
	// Both patterns match the request; both carry regex priority 100.
	routeA := regexRoute("alpha-regex", `^test\..*`)
	routeB := regexRoute("beta-regex", `.*UserService$`)

	for _, order := range [][]config.GRPCRoute{{routeA, routeB}, {routeB, routeA}} {
		r := New()
		require.NoError(t, r.LoadRoutes(order))

		result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
		require.NoError(t, err)
		assert.Equal(t, "alpha-regex", result.Route.Name,
			"equal-priority regex pair must tie-break by ascending name")
	}
}

// TestRouter_LoadRoutes_ShuffledOrderDeterministic loads a mixed-priority
// route set in many shuffled orders and asserts both the stored order and
// the match winner never change.
func TestRouter_LoadRoutes_ShuffledOrderDeterministic(t *testing.T) {
	t.Parallel()

	routes := []config.GRPCRoute{
		samePriorityGRPCRoute("charlie"),
		samePriorityGRPCRoute("alpha"),
		samePriorityGRPCRoute("bravo"),
		{
			Name: "exact-route",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.UserService"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "exact-backend", Port: 50051}},
			},
		},
	}

	wantOrder := []string{"exact-route", "alpha", "bravo", "charlie"}

	rng := rand.New(rand.NewSource(7)) //nolint:gosec // deterministic shuffle for the test
	for i := 0; i < 50; i++ {
		shuffled := append([]config.GRPCRoute(nil), routes...)
		rng.Shuffle(len(shuffled), func(a, b int) {
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		})

		r := New()
		require.NoError(t, r.LoadRoutes(shuffled))

		got := make([]string, 0, len(routes))
		for _, cr := range r.GetRoutes() {
			got = append(got, cr.Name)
		}
		assert.Equal(t, wantOrder, got, "shuffle %d: stored order must be stable", i)

		result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
		require.NoError(t, err)
		assert.Equal(t, "exact-route", result.Route.Name,
			"shuffle %d: match winner must be stable", i)
	}
}

// TestRouter_AddRoute_IncrementalKeepsTieBreak verifies the tie-break also
// holds for incremental AddRoute calls (not just bulk LoadRoutes): adding a
// lexicographically-smaller name later must still place it first.
func TestRouter_AddRoute_IncrementalKeepsTieBreak(t *testing.T) {
	t.Parallel()

	r := New()
	require.NoError(t, r.AddRoute(samePriorityGRPCRoute("zulu")))
	require.NoError(t, r.AddRoute(samePriorityGRPCRoute("mike")))
	require.NoError(t, r.AddRoute(samePriorityGRPCRoute("alpha")))

	got := make([]string, 0, 3)
	for _, cr := range r.GetRoutes() {
		got = append(got, cr.Name)
	}
	assert.Equal(t, []string{"alpha", "mike", "zulu"}, got,
		"incremental adds must keep the name-ascending order for equal priorities")
}

// TestRouter_LoadRoutes_EmptyClearsRoutes verifies loading an empty slice
// clears previously loaded routes (FULL_SYNC empty-clear contract).
func TestRouter_LoadRoutes_EmptyClearsRoutes(t *testing.T) {
	t.Parallel()

	r := New()
	require.NoError(t, r.LoadRoutes([]config.GRPCRoute{samePriorityGRPCRoute("only-route")}))
	require.Equal(t, 1, r.RouteCount())

	require.NoError(t, r.LoadRoutes(nil))
	assert.Zero(t, r.RouteCount())

	_, err := r.Match("/test.UserService/GetUser", metadata.MD{})
	assert.Error(t, err, "cleared router must not match")
}
