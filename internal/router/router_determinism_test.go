// Package router tests for deterministic route ordering: equal-priority
// routes must resolve by ascending route name regardless of insertion order
// (WP4 load-time ordering audit).
package router

import (
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// samePriorityRoute builds a route whose priority is identical for every
// name (same prefix, so same specificity).
func samePriorityRoute(name string) config.Route {
	return config.Route{
		Name: name,
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Prefix: "/api"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: name + "-backend", Port: 8080}},
		},
	}
}

// TestRouter_EqualPriorityNameTieBreak verifies two same-priority routes
// always order by name, for both insertion orders.
func TestRouter_EqualPriorityNameTieBreak(t *testing.T) {
	t.Parallel()

	routeA := samePriorityRoute("aaa-route")
	routeB := samePriorityRoute("bbb-route")

	for _, order := range [][]config.Route{{routeA, routeB}, {routeB, routeA}} {
		r := New()
		require.NoError(t, r.LoadRoutes(order))

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		result, err := r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "aaa-route", result.Route.Name,
			"equal priority must tie-break by ascending name")
	}
}

// TestRouter_LoadRoutes_ShuffledOrderDeterministic loads a mixed-priority
// route set in many shuffled orders and asserts both the stored order and
// the match winner never change.
func TestRouter_LoadRoutes_ShuffledOrderDeterministic(t *testing.T) {
	t.Parallel()

	routes := []config.Route{
		samePriorityRoute("charlie"),
		samePriorityRoute("alpha"),
		samePriorityRoute("bravo"),
		{
			Name: "exact-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Exact: "/api/users"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "exact-backend", Port: 8080}},
			},
		},
	}

	wantOrder := []string{"exact-route", "alpha", "bravo", "charlie"}

	rng := rand.New(rand.NewSource(7)) //nolint:gosec // deterministic shuffle for the test
	for i := 0; i < 50; i++ {
		shuffled := append([]config.Route(nil), routes...)
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

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		result, err := r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "exact-route", result.Route.Name,
			"shuffle %d: match winner must be stable", i)
	}
}

// TestRouter_LoadRoutes_EmptyClearsRoutes verifies loading an empty slice
// clears previously loaded routes (FULL_SYNC empty-clear contract).
func TestRouter_LoadRoutes_EmptyClearsRoutes(t *testing.T) {
	t.Parallel()

	r := New()
	require.NoError(t, r.LoadRoutes([]config.Route{samePriorityRoute("only-route")}))
	require.Len(t, r.GetRoutes(), 1)

	require.NoError(t, r.LoadRoutes(nil))
	assert.Empty(t, r.GetRoutes())

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	_, err := r.Match(req)
	assert.Error(t, err, "cleared router must not match")
}
