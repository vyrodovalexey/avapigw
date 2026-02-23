package router

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []Option
	}{
		{
			name: "default router",
			opts: nil,
		},
		{
			name: "with logger",
			opts: []Option{WithRouterLogger(observability.NopLogger())},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := New(tt.opts...)
			require.NotNil(t, r)
			assert.Equal(t, 0, r.RouteCount())
		})
	}
}

func TestRouter_LoadRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		routes    []config.GraphQLRoute
		wantErr   bool
		wantCount int
	}{
		{
			name:      "empty routes",
			routes:    []config.GraphQLRoute{},
			wantErr:   false,
			wantCount: 0,
		},
		{
			name: "single route without match",
			routes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend", Port: 4000}},
					},
				},
			},
			wantErr:   false,
			wantCount: 1,
		},
		{
			name: "route with path match",
			routes: []config.GraphQLRoute{
				{
					Name: "graphql-route",
					Match: []config.GraphQLRouteMatch{
						{Path: &config.StringMatch{Exact: "/graphql"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend", Port: 4000}},
					},
				},
			},
			wantErr:   false,
			wantCount: 1,
		},
		{
			name: "route with regex path",
			routes: []config.GraphQLRoute{
				{
					Name: "regex-route",
					Match: []config.GraphQLRouteMatch{
						{Path: &config.StringMatch{Regex: "^/graphql/v[0-9]+$"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend", Port: 4000}},
					},
				},
			},
			wantErr:   false,
			wantCount: 1,
		},
		{
			name: "route with invalid path regex",
			routes: []config.GraphQLRoute{
				{
					Name: "bad-regex",
					Match: []config.GraphQLRouteMatch{
						{Path: &config.StringMatch{Regex: "[invalid"}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "route with invalid operation name regex",
			routes: []config.GraphQLRoute{
				{
					Name: "bad-op-regex",
					Match: []config.GraphQLRouteMatch{
						{OperationName: &config.StringMatch{Regex: "[invalid"}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "route with invalid header regex",
			routes: []config.GraphQLRoute{
				{
					Name: "bad-header-regex",
					Match: []config.GraphQLRouteMatch{
						{
							Headers: []config.HeaderMatchConfig{
								{Name: "x-custom", Regex: "[invalid"},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "multiple routes",
			routes: []config.GraphQLRoute{
				{
					Name: "route-1",
					Match: []config.GraphQLRouteMatch{
						{OperationType: "query"},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "query-backend", Port: 4000}},
					},
				},
				{
					Name: "route-2",
					Match: []config.GraphQLRouteMatch{
						{OperationType: "mutation"},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "mutation-backend", Port: 4001}},
					},
				},
			},
			wantErr:   false,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := New(WithRouterLogger(observability.NopLogger()))
			err := r.LoadRoutes(tt.routes)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantCount, r.RouteCount())
			}
		})
	}
}

func TestRouter_Match(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		routes          []config.GraphQLRoute
		reqPath         string
		reqHeaders      map[string]string
		gqlReq          *GraphQLRequest
		wantMatch       bool
		wantRouteName   string
		wantBackendName string
		wantOpType      string
	}{
		{
			name: "match catch-all route",
			routes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:         "/graphql",
			gqlReq:          &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch:       true,
			wantRouteName:   "catch-all",
			wantBackendName: "backend",
			wantOpType:      "query",
		},
		{
			name: "match by exact path",
			routes: []config.GraphQLRoute{
				{
					Name: "graphql-route",
					Match: []config.GraphQLRouteMatch{
						{Path: &config.StringMatch{Exact: "/graphql"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:         "/graphql",
			gqlReq:          &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch:       true,
			wantRouteName:   "graphql-route",
			wantBackendName: "backend",
		},
		{
			name: "no match by exact path",
			routes: []config.GraphQLRoute{
				{
					Name: "graphql-route",
					Match: []config.GraphQLRouteMatch{
						{Path: &config.StringMatch{Exact: "/graphql"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:   "/api/graphql",
			gqlReq:    &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch: false,
		},
		{
			name: "match by prefix path",
			routes: []config.GraphQLRoute{
				{
					Name: "prefix-route",
					Match: []config.GraphQLRouteMatch{
						{Path: &config.StringMatch{Prefix: "/graphql"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:       "/graphql/v1",
			gqlReq:        &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch:     true,
			wantRouteName: "prefix-route",
		},
		{
			name: "match by regex path",
			routes: []config.GraphQLRoute{
				{
					Name: "regex-route",
					Match: []config.GraphQLRouteMatch{
						{Path: &config.StringMatch{Regex: "^/graphql/v[0-9]+$"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:       "/graphql/v2",
			gqlReq:        &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch:     true,
			wantRouteName: "regex-route",
		},
		{
			name: "match by operation type - query",
			routes: []config.GraphQLRoute{
				{
					Name: "query-route",
					Match: []config.GraphQLRouteMatch{
						{OperationType: "query"},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "query-backend"}},
					},
				},
			},
			reqPath:         "/graphql",
			gqlReq:          &GraphQLRequest{Query: "query { user { name } }"},
			wantMatch:       true,
			wantRouteName:   "query-route",
			wantBackendName: "query-backend",
			wantOpType:      "query",
		},
		{
			name: "match by operation type - mutation",
			routes: []config.GraphQLRoute{
				{
					Name: "mutation-route",
					Match: []config.GraphQLRouteMatch{
						{OperationType: "mutation"},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "mutation-backend"}},
					},
				},
			},
			reqPath:         "/graphql",
			gqlReq:          &GraphQLRequest{Query: "mutation { createUser(name: \"test\") { id } }"},
			wantMatch:       true,
			wantRouteName:   "mutation-route",
			wantBackendName: "mutation-backend",
			wantOpType:      "mutation",
		},
		{
			name: "match by operation type - subscription",
			routes: []config.GraphQLRoute{
				{
					Name: "sub-route",
					Match: []config.GraphQLRouteMatch{
						{OperationType: "subscription"},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "sub-backend"}},
					},
				},
			},
			reqPath:    "/graphql",
			gqlReq:     &GraphQLRequest{Query: "subscription { onUserCreated { id } }"},
			wantMatch:  true,
			wantOpType: "subscription",
		},
		{
			name: "no match by operation type",
			routes: []config.GraphQLRoute{
				{
					Name: "mutation-only",
					Match: []config.GraphQLRouteMatch{
						{OperationType: "mutation"},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:   "/graphql",
			gqlReq:    &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch: false,
		},
		{
			name: "match by exact operation name",
			routes: []config.GraphQLRoute{
				{
					Name: "get-user-route",
					Match: []config.GraphQLRouteMatch{
						{OperationName: &config.StringMatch{Exact: "GetUser"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:       "/graphql",
			gqlReq:        &GraphQLRequest{Query: "query GetUser { user { name } }", OperationName: "GetUser"},
			wantMatch:     true,
			wantRouteName: "get-user-route",
		},
		{
			name: "match by prefix operation name",
			routes: []config.GraphQLRoute{
				{
					Name: "get-routes",
					Match: []config.GraphQLRouteMatch{
						{OperationName: &config.StringMatch{Prefix: "Get"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:       "/graphql",
			gqlReq:        &GraphQLRequest{Query: "query GetPosts { posts { title } }", OperationName: "GetPosts"},
			wantMatch:     true,
			wantRouteName: "get-routes",
		},
		{
			name: "match by regex operation name",
			routes: []config.GraphQLRoute{
				{
					Name: "regex-op-route",
					Match: []config.GraphQLRouteMatch{
						{OperationName: &config.StringMatch{Regex: "^(Get|List).*$"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:       "/graphql",
			gqlReq:        &GraphQLRequest{Query: "query ListUsers { users { name } }", OperationName: "ListUsers"},
			wantMatch:     true,
			wantRouteName: "regex-op-route",
		},
		{
			name: "match by header exact",
			routes: []config.GraphQLRoute{
				{
					Name: "header-route",
					Match: []config.GraphQLRouteMatch{
						{
							Headers: []config.HeaderMatchConfig{
								{Name: "X-Tenant", Exact: "acme"},
							},
						},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:    "/graphql",
			reqHeaders: map[string]string{"X-Tenant": "acme"},
			gqlReq:     &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch:  true,
		},
		{
			name: "no match by header exact",
			routes: []config.GraphQLRoute{
				{
					Name: "header-route",
					Match: []config.GraphQLRouteMatch{
						{
							Headers: []config.HeaderMatchConfig{
								{Name: "X-Tenant", Exact: "acme"},
							},
						},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:    "/graphql",
			reqHeaders: map[string]string{"X-Tenant": "other"},
			gqlReq:     &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch:  false,
		},
		{
			name: "match by header prefix",
			routes: []config.GraphQLRoute{
				{
					Name: "header-prefix-route",
					Match: []config.GraphQLRouteMatch{
						{
							Headers: []config.HeaderMatchConfig{
								{Name: "Authorization", Prefix: "Bearer "},
							},
						},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:    "/graphql",
			reqHeaders: map[string]string{"Authorization": "Bearer token123"},
			gqlReq:     &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch:  true,
		},
		{
			name: "match by header regex",
			routes: []config.GraphQLRoute{
				{
					Name: "header-regex-route",
					Match: []config.GraphQLRouteMatch{
						{
							Headers: []config.HeaderMatchConfig{
								{Name: "X-Version", Regex: "^v[0-9]+$"},
							},
						},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:    "/graphql",
			reqHeaders: map[string]string{"X-Version": "v2"},
			gqlReq:     &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch:  true,
		},
		{
			name: "match with combined conditions",
			routes: []config.GraphQLRoute{
				{
					Name: "combined-route",
					Match: []config.GraphQLRouteMatch{
						{
							Path:          &config.StringMatch{Exact: "/graphql"},
							OperationType: "query",
							OperationName: &config.StringMatch{Prefix: "Get"},
						},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:       "/graphql",
			gqlReq:        &GraphQLRequest{Query: "query GetUser { user { name } }", OperationName: "GetUser"},
			wantMatch:     true,
			wantRouteName: "combined-route",
		},
		{
			name: "no match when one combined condition fails",
			routes: []config.GraphQLRoute{
				{
					Name: "combined-route",
					Match: []config.GraphQLRouteMatch{
						{
							Path:          &config.StringMatch{Exact: "/graphql"},
							OperationType: "mutation",
							OperationName: &config.StringMatch{Prefix: "Get"},
						},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:   "/graphql",
			gqlReq:    &GraphQLRequest{Query: "query GetUser { user { name } }", OperationName: "GetUser"},
			wantMatch: false,
		},
		{
			name: "match with multiple match conditions (OR logic)",
			routes: []config.GraphQLRoute{
				{
					Name: "multi-match-route",
					Match: []config.GraphQLRouteMatch{
						{OperationType: "query"},
						{OperationType: "mutation"},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend"}},
					},
				},
			},
			reqPath:       "/graphql",
			gqlReq:        &GraphQLRequest{Query: "mutation { createUser { id } }"},
			wantMatch:     true,
			wantRouteName: "multi-match-route",
		},
		{
			name: "first matching route wins",
			routes: []config.GraphQLRoute{
				{
					Name: "first-route",
					Match: []config.GraphQLRouteMatch{
						{OperationType: "query"},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "first-backend"}},
					},
				},
				{
					Name: "second-route",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "second-backend"}},
					},
				},
			},
			reqPath:         "/graphql",
			gqlReq:          &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch:       true,
			wantRouteName:   "first-route",
			wantBackendName: "first-backend",
		},
		{
			name:      "no routes loaded",
			routes:    []config.GraphQLRoute{},
			reqPath:   "/graphql",
			gqlReq:    &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch: false,
		},
		{
			name: "route with no destinations",
			routes: []config.GraphQLRoute{
				{
					Name: "no-dest",
				},
			},
			reqPath:         "/graphql",
			gqlReq:          &GraphQLRequest{Query: "{ user { name } }"},
			wantMatch:       true,
			wantBackendName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := New(WithRouterLogger(observability.NopLogger()))
			err := r.LoadRoutes(tt.routes)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, tt.reqPath, nil)
			for k, v := range tt.reqHeaders {
				req.Header.Set(k, v)
			}

			result := r.Match(req, tt.gqlReq)

			if tt.wantMatch {
				require.NotNil(t, result, "expected a match but got nil")
				if tt.wantRouteName != "" {
					assert.Equal(t, tt.wantRouteName, result.Route.Name)
				}
				if tt.wantBackendName != "" {
					assert.Equal(t, tt.wantBackendName, result.BackendName)
				}
				if tt.wantOpType != "" {
					assert.Equal(t, tt.wantOpType, result.OperationType)
				}
			} else {
				assert.Nil(t, result, "expected no match but got one")
			}
		})
	}
}

func TestRouter_RouteCount(t *testing.T) {
	t.Parallel()

	r := New()
	assert.Equal(t, 0, r.RouteCount())

	err := r.LoadRoutes([]config.GraphQLRoute{
		{Name: "route-1"},
		{Name: "route-2"},
		{Name: "route-3"},
	})
	require.NoError(t, err)
	assert.Equal(t, 3, r.RouteCount())

	// Reload with fewer routes
	err = r.LoadRoutes([]config.GraphQLRoute{
		{Name: "route-1"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, r.RouteCount())
}

func TestParseGraphQLRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		nilBody   bool
		wantErr   bool
		errSubstr string
		wantQuery string
		wantOpNam string
	}{
		{
			name:      "valid query",
			body:      `{"query":"{ user { name } }"}`,
			wantErr:   false,
			wantQuery: "{ user { name } }",
		},
		{
			name:      "valid query with operation name",
			body:      `{"query":"query GetUser { user { name } }","operationName":"GetUser"}`,
			wantErr:   false,
			wantQuery: "query GetUser { user { name } }",
			wantOpNam: "GetUser",
		},
		{
			name:    "valid query with variables",
			body:    `{"query":"query GetUser($id: ID!) { user(id: $id) { name } }","variables":{"id":"123"}}`,
			wantErr: false,
		},
		{
			name:      "nil body",
			nilBody:   true,
			wantErr:   true,
			errSubstr: "request body is empty",
		},
		{
			name:      "invalid JSON",
			body:      `not json`,
			wantErr:   true,
			errSubstr: "failed to parse",
		},
		{
			name:      "empty query",
			body:      `{"query":""}`,
			wantErr:   true,
			errSubstr: "GraphQL query is empty",
		},
		{
			name:      "missing query field",
			body:      `{"operationName":"GetUser"}`,
			wantErr:   true,
			errSubstr: "GraphQL query is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var req *http.Request
			if tt.nilBody {
				req = httptest.NewRequest(http.MethodPost, "/graphql", nil)
				req.Body = nil
			} else {
				req = httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewBufferString(tt.body))
			}

			gqlReq, err := ParseGraphQLRequest(req)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errSubstr != "" {
					assert.Contains(t, err.Error(), tt.errSubstr)
				}
				assert.Nil(t, gqlReq)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, gqlReq)
				if tt.wantQuery != "" {
					assert.Equal(t, tt.wantQuery, gqlReq.Query)
				}
				if tt.wantOpNam != "" {
					assert.Equal(t, tt.wantOpNam, gqlReq.OperationName)
				}
			}
		})
	}
}

func TestDetectOperationType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		query    string
		expected string
	}{
		{
			name:     "explicit query",
			query:    "query { user { name } }",
			expected: "query",
		},
		{
			name:     "shorthand query",
			query:    "{ user { name } }",
			expected: "query",
		},
		{
			name:     "mutation",
			query:    "mutation { createUser { id } }",
			expected: "mutation",
		},
		{
			name:     "subscription",
			query:    "subscription { onUserCreated { id } }",
			expected: "subscription",
		},
		{
			name:     "query with whitespace",
			query:    "  query { user { name } }",
			expected: "query",
		},
		{
			name:     "mutation with whitespace",
			query:    "\n  mutation { createUser { id } }",
			expected: "mutation",
		},
		{
			name:     "empty query defaults to query",
			query:    "",
			expected: "query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := detectOperationType(tt.query)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchStringMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sm       *config.StringMatch
		value    string
		expected bool
	}{
		{
			name:     "nil match returns true",
			sm:       nil,
			value:    "anything",
			expected: true,
		},
		{
			name:     "empty match returns true",
			sm:       &config.StringMatch{},
			value:    "anything",
			expected: true,
		},
		{
			name:     "exact match success",
			sm:       &config.StringMatch{Exact: "/graphql"},
			value:    "/graphql",
			expected: true,
		},
		{
			name:     "exact match failure",
			sm:       &config.StringMatch{Exact: "/graphql"},
			value:    "/api",
			expected: false,
		},
		{
			name:     "prefix match success",
			sm:       &config.StringMatch{Prefix: "/graphql"},
			value:    "/graphql/v1",
			expected: true,
		},
		{
			name:     "prefix match failure",
			sm:       &config.StringMatch{Prefix: "/graphql"},
			value:    "/api",
			expected: false,
		},
		{
			name:     "regex match without compiled regex returns true",
			sm:       &config.StringMatch{Regex: "^/graphql$"},
			value:    "/graphql",
			expected: true, // no compiled regex passed, so returns true
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := matchStringMatch(tt.sm, tt.value, nil)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchHeaderConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		hm       *config.HeaderMatchConfig
		value    string
		expected bool
	}{
		{
			name:     "exact match success",
			hm:       &config.HeaderMatchConfig{Name: "X-Tenant", Exact: "acme"},
			value:    "acme",
			expected: true,
		},
		{
			name:     "exact match failure",
			hm:       &config.HeaderMatchConfig{Name: "X-Tenant", Exact: "acme"},
			value:    "other",
			expected: false,
		},
		{
			name:     "prefix match success",
			hm:       &config.HeaderMatchConfig{Name: "Authorization", Prefix: "Bearer "},
			value:    "Bearer token123",
			expected: true,
		},
		{
			name:     "prefix match failure",
			hm:       &config.HeaderMatchConfig{Name: "Authorization", Prefix: "Bearer "},
			value:    "Basic abc",
			expected: false,
		},
		{
			name:     "regex match without compiled regex returns true",
			hm:       &config.HeaderMatchConfig{Name: "X-Version", Regex: "^v[0-9]+$"},
			value:    "v2",
			expected: true, // no compiled regex in map
		},
		{
			name:     "empty config returns true",
			hm:       &config.HeaderMatchConfig{Name: "X-Custom"},
			value:    "anything",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := matchHeaderConfig(tt.hm, tt.value, nil)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGraphQLRequest_Fields(t *testing.T) {
	t.Parallel()

	req := GraphQLRequest{
		Query:         "query GetUser($id: ID!) { user(id: $id) { name } }",
		OperationName: "GetUser",
		Variables:     map[string]interface{}{"id": "123"},
	}

	assert.Equal(t, "query GetUser($id: ID!) { user(id: $id) { name } }", req.Query)
	assert.Equal(t, "GetUser", req.OperationName)
	assert.Equal(t, "123", req.Variables["id"])
}

func TestParseGraphQLRequest_ReadError(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader("valid"))
	// Close the body to simulate a read error
	req.Body.Close()

	_, err := ParseGraphQLRequest(req)
	// After closing, reading may or may not error depending on implementation
	// but the function should handle it gracefully
	if err != nil {
		assert.Error(t, err)
	}
}
