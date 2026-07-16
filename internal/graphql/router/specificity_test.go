// Package router tests for the route specificity ordering: LoadRoutes must
// order routes deterministically (descending specificity, name tie-break) so
// first-match-wins selection is independent of the caller's input order.
package router

import (
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestSpecificity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		route config.GraphQLRoute
		want  int
	}{
		{
			name:  "no match blocks (catch-all)",
			route: config.GraphQLRoute{Name: "catch-all"},
			want:  0,
		},
		{
			name: "exact path",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{Path: &config.StringMatch{Exact: "/graphql"}},
			}},
			want: 1000,
		},
		{
			name: "prefix path gains length",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{Path: &config.StringMatch{Prefix: "/graphql"}},
			}},
			want: 500 + len("/graphql"),
		},
		{
			name: "regex path",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{Path: &config.StringMatch{Regex: "^/graphql/v[0-9]+$"}},
			}},
			want: 100,
		},
		{
			name: "exact beats prefix within one StringMatch (field precedence)",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{Path: &config.StringMatch{Exact: "/graphql", Prefix: "/gra", Regex: ".*"}},
			}},
			want: 1000,
		},
		{
			name: "empty StringMatch scores zero",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{Path: &config.StringMatch{}},
			}},
			want: 0,
		},
		{
			name: "operation type",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{OperationType: "mutation"},
			}},
			want: 200,
		},
		{
			name: "exact operation name",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{OperationName: &config.StringMatch{Exact: "GetUser"}},
			}},
			want: 500,
		},
		{
			name: "prefix operation name gains length",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{OperationName: &config.StringMatch{Prefix: "Get"}},
			}},
			want: 250 + len("Get"),
		},
		{
			name: "regex operation name",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{OperationName: &config.StringMatch{Regex: "^Get.*$"}},
			}},
			want: 50,
		},
		{
			name: "headers add 10 each",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{Headers: []config.HeaderMatchConfig{
					{Name: "X-Tenant", Exact: "acme"},
					{Name: "X-Version", Prefix: "v"},
				}},
			}},
			want: 20,
		},
		{
			name: "combined conditions sum within a block",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{
					Path:          &config.StringMatch{Exact: "/graphql"},
					OperationType: "query",
					OperationName: &config.StringMatch{Exact: "GetUser"},
					Headers:       []config.HeaderMatchConfig{{Name: "X-Tenant", Exact: "acme"}},
				},
			}},
			want: 1000 + 200 + 500 + 10,
		},
		{
			name: "multiple match blocks sum",
			route: config.GraphQLRoute{Match: []config.GraphQLRouteMatch{
				{OperationType: "query"},
				{OperationType: "mutation"},
			}},
			want: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, Specificity(&tt.route))
		})
	}
}

// TestSpecificity_DocumentedOrdering pins the documented relative ordering:
// exact path > prefix path > regex path > opName exact > opType > headers > none.
func TestSpecificity_DocumentedOrdering(t *testing.T) {
	t.Parallel()

	spec := func(m config.GraphQLRouteMatch) int {
		return Specificity(&config.GraphQLRoute{Match: []config.GraphQLRouteMatch{m}})
	}

	exactPath := spec(config.GraphQLRouteMatch{Path: &config.StringMatch{Exact: "/graphql"}})
	prefixPath := spec(config.GraphQLRouteMatch{Path: &config.StringMatch{Prefix: "/graphql"}})
	regexPath := spec(config.GraphQLRouteMatch{Path: &config.StringMatch{Regex: "^/graphql$"}})
	exactOpName := spec(config.GraphQLRouteMatch{OperationName: &config.StringMatch{Exact: "GetUser"}})
	opType := spec(config.GraphQLRouteMatch{OperationType: "query"})
	oneHeader := spec(config.GraphQLRouteMatch{Headers: []config.HeaderMatchConfig{{Name: "X-T", Exact: "a"}}})

	assert.Greater(t, exactPath, prefixPath, "exact path must outrank prefix path")
	assert.Greater(t, prefixPath, regexPath, "prefix path must outrank regex path")
	assert.Greater(t, regexPath, oneHeader, "regex path must outrank a lone header condition")
	assert.Greater(t, exactOpName, opType, "exact operation name must outrank operation type")
	assert.Greater(t, opType, oneHeader, "operation type must outrank a lone header condition")
	assert.Positive(t, oneHeader, "header conditions must contribute specificity")

	// Longer prefixes outrank shorter ones.
	longPrefix := spec(config.GraphQLRouteMatch{Path: &config.StringMatch{Prefix: "/graphql/v1"}})
	assert.Greater(t, longPrefix, prefixPath, "longer prefix must outrank shorter prefix")
}

// overlappingRoutes returns routes that ALL match a POST /graphql request
// carrying "query GetUser", from most to least specific.
func overlappingRoutes() []config.GraphQLRoute {
	dest := func(host string) []config.RouteDestination {
		return []config.RouteDestination{{Destination: config.Destination{Host: host}}}
	}
	return []config.GraphQLRoute{
		{
			Name: "path-exact",
			Match: []config.GraphQLRouteMatch{
				{Path: &config.StringMatch{Exact: "/graphql"}},
			},
			Route: dest("path-backend"),
		},
		{
			Name: "op-name-specific",
			Match: []config.GraphQLRouteMatch{
				{OperationName: &config.StringMatch{Exact: "GetUser"}},
			},
			Route: dest("opname-backend"),
		},
		{
			Name: "op-type-specific",
			Match: []config.GraphQLRouteMatch{
				{OperationType: "query"},
			},
			Route: dest("optype-backend"),
		},
		{
			Name:  "generic",
			Route: dest("generic-backend"),
		},
	}
}

// matchingRequest builds the request/GraphQL pair matched by every route in
// overlappingRoutes.
func matchingRequest() (*http.Request, *GraphQLRequest) {
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	gql := &GraphQLRequest{Query: "query GetUser { user { name } }", OperationName: "GetUser"}
	return req, gql
}

// permutations returns every ordering of the given routes (n! permutations).
func permutations(routes []config.GraphQLRoute) [][]config.GraphQLRoute {
	if len(routes) <= 1 {
		return [][]config.GraphQLRoute{append([]config.GraphQLRoute(nil), routes...)}
	}
	var result [][]config.GraphQLRoute
	for i := range routes {
		rest := make([]config.GraphQLRoute, 0, len(routes)-1)
		rest = append(rest, routes[:i]...)
		rest = append(rest, routes[i+1:]...)
		for _, perm := range permutations(rest) {
			result = append(result, append([]config.GraphQLRoute{routes[i]}, perm...))
		}
	}
	return result
}

// TestRouter_Match_SpecificityIndependentOfLoadOrder is the WP3 property
// test: overlapping routes (generic vs opType-specific vs opName-specific vs
// path-exact) must resolve to the SAME winner for every LoadRoutes input
// permutation.
func TestRouter_Match_SpecificityIndependentOfLoadOrder(t *testing.T) {
	t.Parallel()

	base := overlappingRoutes()
	for _, perm := range permutations(base) {
		r := New(WithRouterLogger(observability.NopLogger()))
		require.NoError(t, r.LoadRoutes(perm))

		req, gql := matchingRequest()
		result := r.Match(req, gql)
		require.NotNil(t, result)
		assert.Equal(t, "path-exact", result.Route.Name,
			"the most specific route must win regardless of load order")
		assert.Equal(t, "path-backend", result.BackendName)
	}
}

// TestRouter_Match_SpecificityLadder removes the winner tier by tier and
// asserts the next most specific route takes over, pinning the full
// precedence chain path-exact > opName > opType > generic.
func TestRouter_Match_SpecificityLadder(t *testing.T) {
	t.Parallel()

	ladder := []string{"path-exact", "op-name-specific", "op-type-specific", "generic"}
	base := overlappingRoutes()

	for tier := range ladder {
		routes := append([]config.GraphQLRoute(nil), base[tier:]...)
		// Load in reverse (least specific first) to prove ordering is
		// established by LoadRoutes, not by input order.
		reversed := make([]config.GraphQLRoute, 0, len(routes))
		for i := len(routes) - 1; i >= 0; i-- {
			reversed = append(reversed, routes[i])
		}

		r := New(WithRouterLogger(observability.NopLogger()))
		require.NoError(t, r.LoadRoutes(reversed))

		req, gql := matchingRequest()
		result := r.Match(req, gql)
		require.NotNil(t, result)
		assert.Equal(t, ladder[tier], result.Route.Name)
	}
}

// TestRouter_Match_EqualSpecificityNameTieBreak verifies equal-specificity
// routes resolve by ascending route name regardless of load order.
func TestRouter_Match_EqualSpecificityNameTieBreak(t *testing.T) {
	t.Parallel()

	routeA := config.GraphQLRoute{
		Name:  "aaa-route",
		Match: []config.GraphQLRouteMatch{{OperationType: "query"}},
		Route: []config.RouteDestination{{Destination: config.Destination{Host: "a-backend"}}},
	}
	routeB := config.GraphQLRoute{
		Name:  "bbb-route",
		Match: []config.GraphQLRouteMatch{{OperationType: "query"}},
		Route: []config.RouteDestination{{Destination: config.Destination{Host: "b-backend"}}},
	}

	for _, order := range [][]config.GraphQLRoute{{routeA, routeB}, {routeB, routeA}} {
		r := New(WithRouterLogger(observability.NopLogger()))
		require.NoError(t, r.LoadRoutes(order))

		req, gql := matchingRequest()
		result := r.Match(req, gql)
		require.NotNil(t, result)
		assert.Equal(t, "aaa-route", result.Route.Name,
			"equal specificity must tie-break by ascending name")
	}
}

// TestRouter_Match_ShuffledDeterminism shuffles a larger route set many
// times and asserts the winner never changes (randomized-input stability).
func TestRouter_Match_ShuffledDeterminism(t *testing.T) {
	t.Parallel()

	routes := overlappingRoutes()
	routes = append(routes,
		config.GraphQLRoute{
			Name: "header-specific",
			Match: []config.GraphQLRouteMatch{
				{Headers: []config.HeaderMatchConfig{{Name: "X-Tenant", Exact: "acme"}}},
			},
			Route: []config.RouteDestination{{Destination: config.Destination{Host: "header-backend"}}},
		},
		config.GraphQLRoute{
			Name: "path-prefix",
			Match: []config.GraphQLRouteMatch{
				{Path: &config.StringMatch{Prefix: "/graph"}},
			},
			Route: []config.RouteDestination{{Destination: config.Destination{Host: "prefix-backend"}}},
		},
	)

	rng := rand.New(rand.NewSource(42)) //nolint:gosec // deterministic shuffle for the test
	for i := 0; i < 100; i++ {
		shuffled := append([]config.GraphQLRoute(nil), routes...)
		rng.Shuffle(len(shuffled), func(a, b int) {
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		})

		r := New(WithRouterLogger(observability.NopLogger()))
		require.NoError(t, r.LoadRoutes(shuffled))

		req, gql := matchingRequest()
		req.Header.Set("X-Tenant", "acme")
		result := r.Match(req, gql)
		require.NotNil(t, result)
		assert.Equal(t, "path-exact", result.Route.Name,
			"shuffle %d: winner must be stable across input orders", i)
	}
}

// TestSortRoutesBySpecificity verifies the exported sorter yields the same
// deterministic order LoadRoutes uses, for any input permutation.
func TestSortRoutesBySpecificity(t *testing.T) {
	t.Parallel()

	want := []string{"path-exact", "op-name-specific", "op-type-specific", "generic"}

	for _, perm := range permutations(overlappingRoutes()) {
		routes := append([]config.GraphQLRoute(nil), perm...)
		SortRoutesBySpecificity(routes)

		got := make([]string, 0, len(routes))
		for i := range routes {
			got = append(got, routes[i].Name)
		}
		assert.Equal(t, want, got)
	}
}

// TestSortRoutesBySpecificity_NameTieBreak verifies the exported sorter
// tie-breaks equal specificity by ascending name.
func TestSortRoutesBySpecificity_NameTieBreak(t *testing.T) {
	t.Parallel()

	routes := []config.GraphQLRoute{
		{Name: "zzz", Match: []config.GraphQLRouteMatch{{OperationType: "query"}}},
		{Name: "mmm", Match: []config.GraphQLRouteMatch{{OperationType: "query"}}},
		{Name: "aaa", Match: []config.GraphQLRouteMatch{{OperationType: "query"}}},
	}
	SortRoutesBySpecificity(routes)

	assert.Equal(t, "aaa", routes[0].Name)
	assert.Equal(t, "mmm", routes[1].Name)
	assert.Equal(t, "zzz", routes[2].Name)
}

// TestRouter_LoadRoutes_EmptyClearsRoutes verifies loading an empty slice
// clears previously loaded routes (FULL_SYNC empty-clear contract).
func TestRouter_LoadRoutes_EmptyClearsRoutes(t *testing.T) {
	t.Parallel()

	r := New(WithRouterLogger(observability.NopLogger()))
	require.NoError(t, r.LoadRoutes(overlappingRoutes()))
	require.Equal(t, 4, r.RouteCount())

	require.NoError(t, r.LoadRoutes(nil))
	assert.Equal(t, 0, r.RouteCount())

	req, gql := matchingRequest()
	assert.Nil(t, r.Match(req, gql), "cleared router must not match")
}
