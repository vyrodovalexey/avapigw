//go:build functional
// +build functional

package functional

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestFunctional_GraphQLRouter_PathMatching(t *testing.T) {
	t.Parallel()

	t.Run("exact path match", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "exact-path-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, 1, r.RouteCount())

		// Should match exact path
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ users { id } }"}`))
		gqlReq := &graphqlrouter.GraphQLRequest{Query: "{ users { id } }"}
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "exact-path-route", result.Route.Name)

		// Should not match different path
		req2 := httptest.NewRequest(http.MethodPost, "/graphql-v2", strings.NewReader(`{"query":"{ users { id } }"}`))
		result2 := r.Match(req2, gqlReq)
		assert.Nil(t, result2)
	})

	t.Run("prefix path match", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "prefix-path-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Prefix: "/graphql"},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.NoError(t, err)

		gqlReq := &graphqlrouter.GraphQLRequest{Query: "{ users { id } }"}

		// Should match paths with prefix
		paths := []string{"/graphql", "/graphql/v1", "/graphql-admin"}
		for _, path := range paths {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"query":"{ users { id } }"}`))
			result := r.Match(req, gqlReq)
			require.NotNil(t, result, "path %s should match", path)
			assert.Equal(t, "prefix-path-route", result.Route.Name)
		}

		// Should not match different prefix
		req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(`{"query":"{ users { id } }"}`))
		result := r.Match(req, gqlReq)
		assert.Nil(t, result)
	})

	t.Run("regex path match", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "regex-path-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Regex: `^/graphql(-v[0-9]+)?$`},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.NoError(t, err)

		gqlReq := &graphqlrouter.GraphQLRequest{Query: "{ users { id } }"}

		// Should match regex pattern
		matchPaths := []string{"/graphql", "/graphql-v1", "/graphql-v2"}
		for _, path := range matchPaths {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"query":"{ users { id } }"}`))
			result := r.Match(req, gqlReq)
			require.NotNil(t, result, "path %s should match", path)
			assert.Equal(t, "regex-path-route", result.Route.Name)
		}

		// Should not match non-matching pattern
		req := httptest.NewRequest(http.MethodPost, "/graphql-admin", strings.NewReader(`{"query":"{ users { id } }"}`))
		result := r.Match(req, gqlReq)
		assert.Nil(t, result)
	})

	t.Run("no match conditions matches everything", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name:  "catch-all-route",
				Match: []config.GraphQLRouteMatch{},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.NoError(t, err)

		gqlReq := &graphqlrouter.GraphQLRequest{Query: "{ users { id } }"}
		req := httptest.NewRequest(http.MethodPost, "/any-path", strings.NewReader(`{"query":"{ users { id } }"}`))
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "catch-all-route", result.Route.Name)
	})

	t.Run("invalid regex returns error", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "invalid-regex-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Regex: "[invalid(regex"},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.Error(t, err)
	})
}

func TestFunctional_GraphQLRouter_OperationTypeMatching(t *testing.T) {
	t.Parallel()

	t.Run("query operation type match", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "query-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path:          &config.StringMatch{Exact: "/graphql"},
						OperationType: "query",
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.NoError(t, err)

		// Should match query
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"query { users { id } }"}`))
		gqlReq := &graphqlrouter.GraphQLRequest{Query: "query { users { id } }"}
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "query-route", result.Route.Name)
		assert.Equal(t, "query", result.OperationType)

		// Should not match mutation
		req2 := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"mutation { createUser { id } }"}`))
		gqlReq2 := &graphqlrouter.GraphQLRequest{Query: "mutation { createUser { id } }"}
		result2 := r.Match(req2, gqlReq2)
		assert.Nil(t, result2)
	})

	t.Run("mutation operation type match", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "mutation-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path:          &config.StringMatch{Exact: "/graphql"},
						OperationType: "mutation",
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8822}},
				},
			},
		})
		require.NoError(t, err)

		// Should match mutation
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"mutation { createUser { id } }"}`))
		gqlReq := &graphqlrouter.GraphQLRequest{Query: "mutation { createUser { id } }"}
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "mutation-route", result.Route.Name)
		assert.Equal(t, "mutation", result.OperationType)
	})

	t.Run("subscription operation type match", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "subscription-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path:          &config.StringMatch{Exact: "/graphql"},
						OperationType: "subscription",
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8823}},
				},
			},
		})
		require.NoError(t, err)

		// Should match subscription
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"subscription { onUserCreated { id } }"}`))
		gqlReq := &graphqlrouter.GraphQLRequest{Query: "subscription { onUserCreated { id } }"}
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "subscription-route", result.Route.Name)
		assert.Equal(t, "subscription", result.OperationType)
	})

	t.Run("shorthand query detection", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "query-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path:          &config.StringMatch{Exact: "/graphql"},
						OperationType: "query",
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.NoError(t, err)

		// Shorthand query (without "query" keyword) should be detected as query
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ users { id } }"}`))
		gqlReq := &graphqlrouter.GraphQLRequest{Query: "{ users { id } }"}
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "query", result.OperationType)
	})

	t.Run("operation name matching", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "named-operation-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path:          &config.StringMatch{Exact: "/graphql"},
						OperationName: &config.StringMatch{Exact: "GetUsers"},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.NoError(t, err)

		// Should match named operation
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"query GetUsers { users { id } }","operationName":"GetUsers"}`))
		gqlReq := &graphqlrouter.GraphQLRequest{
			Query:         "query GetUsers { users { id } }",
			OperationName: "GetUsers",
		}
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "named-operation-route", result.Route.Name)
		assert.Equal(t, "GetUsers", result.OperationName)

		// Should not match different operation name
		req2 := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"query GetPosts { posts { id } }","operationName":"GetPosts"}`))
		gqlReq2 := &graphqlrouter.GraphQLRequest{
			Query:         "query GetPosts { posts { id } }",
			OperationName: "GetPosts",
		}
		result2 := r.Match(req2, gqlReq2)
		assert.Nil(t, result2)
	})

	t.Run("operation name prefix matching", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "prefix-operation-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path:          &config.StringMatch{Exact: "/graphql"},
						OperationName: &config.StringMatch{Prefix: "Get"},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.NoError(t, err)

		// Should match operations with prefix
		operations := []string{"GetUsers", "GetPosts", "GetComments"}
		for _, op := range operations {
			req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
			gqlReq := &graphqlrouter.GraphQLRequest{
				Query:         "query " + op + " { data { id } }",
				OperationName: op,
			}
			result := r.Match(req, gqlReq)
			require.NotNil(t, result, "operation %s should match", op)
			assert.Equal(t, "prefix-operation-route", result.Route.Name)
		}

		// Should not match different prefix
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		gqlReq := &graphqlrouter.GraphQLRequest{
			Query:         "mutation CreateUser { createUser { id } }",
			OperationName: "CreateUser",
		}
		result := r.Match(req, gqlReq)
		assert.Nil(t, result)
	})
}

func TestFunctional_GraphQLRouter_HeaderMatching(t *testing.T) {
	t.Parallel()

	t.Run("exact header match", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "header-exact-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
						Headers: []config.HeaderMatchConfig{
							{Name: "X-API-Version", Exact: "v2"},
						},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8822}},
				},
			},
		})
		require.NoError(t, err)

		gqlReq := &graphqlrouter.GraphQLRequest{Query: "{ users { id } }"}

		// Should match with correct header
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req.Header.Set("X-API-Version", "v2")
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "header-exact-route", result.Route.Name)

		// Should not match with wrong header value
		req2 := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req2.Header.Set("X-API-Version", "v1")
		result2 := r.Match(req2, gqlReq)
		assert.Nil(t, result2)

		// Should not match without header
		req3 := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		result3 := r.Match(req3, gqlReq)
		assert.Nil(t, result3)
	})

	t.Run("prefix header match", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "header-prefix-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
						Headers: []config.HeaderMatchConfig{
							{Name: "Authorization", Prefix: "Bearer "},
						},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.NoError(t, err)

		gqlReq := &graphqlrouter.GraphQLRequest{Query: "{ users { id } }"}

		// Should match with correct prefix
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req.Header.Set("Authorization", "Bearer token123")
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "header-prefix-route", result.Route.Name)

		// Should not match with wrong prefix
		req2 := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req2.Header.Set("Authorization", "Basic token123")
		result2 := r.Match(req2, gqlReq)
		assert.Nil(t, result2)
	})

	t.Run("regex header match", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "header-regex-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
						Headers: []config.HeaderMatchConfig{
							{Name: "X-Request-ID", Regex: `^[a-f0-9-]+$`},
						},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.NoError(t, err)

		gqlReq := &graphqlrouter.GraphQLRequest{Query: "{ users { id } }"}

		// Should match with valid UUID-like header
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req.Header.Set("X-Request-ID", "abc-123-def-456")
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "header-regex-route", result.Route.Name)

		// Should not match with invalid header value
		req2 := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req2.Header.Set("X-Request-ID", "INVALID_ID!")
		result2 := r.Match(req2, gqlReq)
		assert.Nil(t, result2)
	})

	t.Run("multiple header conditions", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "multi-header-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
						Headers: []config.HeaderMatchConfig{
							{Name: "X-API-Version", Exact: "v2"},
							{Name: "X-Tenant-ID", Prefix: "tenant-"},
						},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8822}},
				},
			},
		})
		require.NoError(t, err)

		gqlReq := &graphqlrouter.GraphQLRequest{Query: "{ users { id } }"}

		// Should match when all header conditions are met
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req.Header.Set("X-API-Version", "v2")
		req.Header.Set("X-Tenant-ID", "tenant-123")
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "multi-header-route", result.Route.Name)

		// Should not match when only some conditions are met
		req2 := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req2.Header.Set("X-API-Version", "v2")
		result2 := r.Match(req2, gqlReq)
		assert.Nil(t, result2)
	})

	t.Run("route priority - first match wins", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "specific-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path:          &config.StringMatch{Exact: "/graphql"},
						OperationType: "mutation",
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8822}},
				},
			},
			{
				Name: "catch-all-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8821}},
				},
			},
		})
		require.NoError(t, err)

		// Mutation should match specific route
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		gqlReq := &graphqlrouter.GraphQLRequest{Query: "mutation { createUser { id } }"}
		result := r.Match(req, gqlReq)
		require.NotNil(t, result)
		assert.Equal(t, "specific-route", result.Route.Name)

		// Query should match catch-all route
		req2 := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		gqlReq2 := &graphqlrouter.GraphQLRequest{Query: "{ users { id } }"}
		result2 := r.Match(req2, gqlReq2)
		require.NotNil(t, result2)
		assert.Equal(t, "catch-all-route", result2.Route.Name)
	})

	t.Run("no routes returns nil", func(t *testing.T) {
		t.Parallel()

		r := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
		err := r.LoadRoutes([]config.GraphQLRoute{})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		gqlReq := &graphqlrouter.GraphQLRequest{Query: "{ users { id } }"}
		result := r.Match(req, gqlReq)
		assert.Nil(t, result)
	})
}

func TestFunctional_GraphQLRouter_ParseRequest(t *testing.T) {
	t.Parallel()

	t.Run("parse valid GraphQL request", func(t *testing.T) {
		t.Parallel()

		body := `{"query":"{ users { id name } }","variables":{"limit":10},"operationName":"GetUsers"}`
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		gqlReq, err := graphqlrouter.ParseGraphQLRequest(req)
		require.NoError(t, err)
		require.NotNil(t, gqlReq)

		assert.Equal(t, "{ users { id name } }", gqlReq.Query)
		assert.Equal(t, "GetUsers", gqlReq.OperationName)
		assert.NotNil(t, gqlReq.Variables)
		assert.Equal(t, float64(10), gqlReq.Variables["limit"])
	})

	t.Run("parse request without variables", func(t *testing.T) {
		t.Parallel()

		body := `{"query":"{ users { id } }"}`
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))

		gqlReq, err := graphqlrouter.ParseGraphQLRequest(req)
		require.NoError(t, err)
		require.NotNil(t, gqlReq)

		assert.Equal(t, "{ users { id } }", gqlReq.Query)
		assert.Empty(t, gqlReq.OperationName)
		assert.Nil(t, gqlReq.Variables)
	})

	t.Run("parse request with empty query fails", func(t *testing.T) {
		t.Parallel()

		body := `{"query":""}`
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))

		_, err := graphqlrouter.ParseGraphQLRequest(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("parse request with nil body fails", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req.Body = nil

		_, err := graphqlrouter.ParseGraphQLRequest(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("parse invalid JSON fails", func(t *testing.T) {
		t.Parallel()

		body := `{invalid json}`
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))

		_, err := graphqlrouter.ParseGraphQLRequest(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse")
	})
}
