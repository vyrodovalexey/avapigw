//go:build e2e
// +build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/graphql/middleware"
	"github.com/vyrodovalexey/avapigw/internal/graphql/proxy"
	"github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// graphqlGatewayHandler creates an http.Handler that wires together the GraphQL
// router and proxy, mimicking the real gateway request lifecycle.
func graphqlGatewayHandler(
	rt *router.Router,
	px *proxy.Proxy,
	depthLimiter *middleware.DepthLimiter,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the GraphQL request from the body.
		gqlReq, err := router.ParseGraphQLRequest(r)
		if err != nil {
			writeGraphQLError(w, http.StatusBadRequest, "failed to parse GraphQL request: "+err.Error())
			return
		}

		// Apply depth limit if configured.
		if depthLimiter != nil {
			if dlErr := depthLimiter.Check(gqlReq.Query); dlErr != nil {
				writeGraphQLError(w, http.StatusBadRequest, dlErr.Error())
				return
			}
		}

		// Rebuild the body so the proxy can read it again.
		bodyBytes, _ := json.Marshal(gqlReq)

		// Match the request to a route.
		matchResult := rt.Match(r, gqlReq)
		if matchResult == nil {
			writeGraphQLError(w, http.StatusNotFound, "no matching GraphQL route")
			return
		}

		// Create a new request with the buffered body for forwarding.
		proxyReq, _ := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), io.NopCloser(
			newBytesReader(bodyBytes),
		))
		proxyReq.Header = r.Header.Clone()
		proxyReq.RemoteAddr = r.RemoteAddr
		proxyReq.Host = r.Host
		proxyReq.URL = r.URL

		// Forward to the backend via the proxy.
		resp, fwdErr := px.Forward(r.Context(), matchResult.BackendName, proxyReq)
		if fwdErr != nil {
			writeGraphQLError(w, http.StatusBadGateway, "proxy forward error: "+fwdErr.Error())
			return
		}
		defer resp.Body.Close()

		// Copy the backend response to the client.
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

// newBytesReader is a helper that returns a *bytes.Reader-like io.Reader.
func newBytesReader(b []byte) io.Reader {
	return &bytesReaderWrapper{data: b, pos: 0}
}

type bytesReaderWrapper struct {
	data []byte
	pos  int
}

func (br *bytesReaderWrapper) Read(p []byte) (int, error) {
	if br.pos >= len(br.data) {
		return 0, io.EOF
	}
	n := copy(p, br.data[br.pos:])
	br.pos += n
	return n, nil
}

// newMultiPathMockGraphQLBackend creates a mock GraphQL backend that handles
// GraphQL requests on any path (not just /graphql). This is needed for tests
// that verify routing to different paths like /api/v1/graphql, /api/v2/graphql.
func newMultiPathMockGraphQLBackend(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":[{"message":"failed to read body"}]}`))
			return
		}
		defer r.Body.Close()

		var gqlReq struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(body, &gqlReq); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":[{"message":"invalid JSON"}]}`))
			return
		}

		// Return a generic successful GraphQL response for any query.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"items":[{"id":"1","name":"Item 1"},{"id":"2","name":"Item 2"}]}}`))
	}))
	t.Cleanup(server.Close)

	return server
}

// writeGraphQLError writes a standard GraphQL error response.
func writeGraphQLError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := map[string]interface{}{
		"errors": []map[string]interface{}{
			{"message": message},
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// TestE2E_GraphQLGateway_BasicQuery starts a full gateway with GraphQL proxy,
// sends a query through it, and verifies the response.
func TestE2E_GraphQLGateway_BasicQuery(t *testing.T) {
	mockBackend := helpers.NewMockGraphQLBackend(t)

	logger := observability.NopLogger()
	backendInfo := helpers.GetGraphQLBackendInfo(mockBackend.Listener.Addr().String())

	t.Run("simple query through gateway proxy", func(t *testing.T) {
		// Set up the router with a single route.
		rt := router.New(router.WithRouterLogger(logger))
		err := rt.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "items-query",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []config.RouteDestination{
					{
						Destination: config.Destination{
							Host: backendInfo.Host,
							Port: backendInfo.Port,
						},
						Weight: 100,
					},
				},
				Timeout: config.Duration(30 * time.Second),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, 1, rt.RouteCount())

		// Set up the proxy with the backend.
		px := proxy.New(
			proxy.WithLogger(logger),
			proxy.WithTimeout(30*time.Second),
		)
		px.UpdateBackends([]config.GraphQLBackend{
			{
				Name: backendInfo.Host,
				Hosts: []config.BackendHost{
					{Address: backendInfo.Host, Port: backendInfo.Port},
				},
			},
		})
		defer px.Close()

		// Create the test server.
		handler := graphqlGatewayHandler(rt, px, nil)
		srv := httptest.NewServer(handler)
		defer srv.Close()

		// Send a query for items.
		resp, err := helpers.MakeGraphQLRequest(
			srv.URL+"/graphql",
			`query { items { id name } }`,
			nil,
		)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)
		assert.Empty(t, gqlResp.Errors, "expected no GraphQL errors")
		assert.NotNil(t, gqlResp.Data, "expected data in response")
	})

	t.Run("query with variables", func(t *testing.T) {
		rt := router.New(router.WithRouterLogger(logger))
		err := rt.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "item-by-id",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []config.RouteDestination{
					{
						Destination: config.Destination{
							Host: backendInfo.Host,
							Port: backendInfo.Port,
						},
						Weight: 100,
					},
				},
				Timeout: config.Duration(30 * time.Second),
			},
		})
		require.NoError(t, err)

		px := proxy.New(
			proxy.WithLogger(logger),
			proxy.WithTimeout(30*time.Second),
		)
		px.UpdateBackends([]config.GraphQLBackend{
			{
				Name: backendInfo.Host,
				Hosts: []config.BackendHost{
					{Address: backendInfo.Host, Port: backendInfo.Port},
				},
			},
		})
		defer px.Close()

		handler := graphqlGatewayHandler(rt, px, nil)
		srv := httptest.NewServer(handler)
		defer srv.Close()

		// Send a query with variables.
		resp, err := helpers.MakeGraphQLRequest(
			srv.URL+"/graphql",
			`query GetItem($id: ID!) { item(id: $id) { id name } }`,
			map[string]interface{}{"id": "1"},
		)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)
		assert.Empty(t, gqlResp.Errors, "expected no GraphQL errors")
		assert.NotNil(t, gqlResp.Data, "expected data in response")
	})
}

// TestE2E_GraphQLGateway_MutationFlow performs a mutation flow:
// create item via mutation, query it back, then delete it.
// Uses a stateless mock backend, so assertions verify mock responses.
func TestE2E_GraphQLGateway_MutationFlow(t *testing.T) {
	mockBackend := helpers.NewMockGraphQLBackend(t)

	logger := observability.NopLogger()
	backendInfo := helpers.GetGraphQLBackendInfo(mockBackend.Listener.Addr().String())

	// Set up the router and proxy once for the entire mutation flow.
	rt := router.New(router.WithRouterLogger(logger))
	err := rt.LoadRoutes([]config.GraphQLRoute{
		{
			Name: "crud-route",
			Match: []config.GraphQLRouteMatch{
				{
					Path: &config.StringMatch{Exact: "/graphql"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: backendInfo.Host,
						Port: backendInfo.Port,
					},
					Weight: 100,
				},
			},
			Timeout: config.Duration(30 * time.Second),
		},
	})
	require.NoError(t, err)

	px := proxy.New(
		proxy.WithLogger(logger),
		proxy.WithTimeout(30*time.Second),
	)
	px.UpdateBackends([]config.GraphQLBackend{
		{
			Name: backendInfo.Host,
			Hosts: []config.BackendHost{
				{Address: backendInfo.Host, Port: backendInfo.Port},
			},
		},
	})
	defer px.Close()

	handler := graphqlGatewayHandler(rt, px, nil)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	var createdItemID string

	t.Run("create item via mutation", func(t *testing.T) {
		resp, reqErr := helpers.MakeGraphQLRequest(
			srv.URL+"/graphql",
			`mutation CreateItem($input: CreateItemInput!) { createItem(input: $input) { id name } }`,
			map[string]interface{}{
				"input": map[string]interface{}{
					"name": "e2e-test-item",
				},
			},
		)
		require.NoError(t, reqErr)

		gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, parseErr)
		assert.Empty(t, gqlResp.Errors, "expected no errors on createItem mutation")
		assert.NotNil(t, gqlResp.Data, "expected data in createItem response")

		// Extract the created item ID for subsequent operations.
		if gqlResp.Data != nil {
			var data map[string]interface{}
			if unmarshalErr := json.Unmarshal(gqlResp.Data, &data); unmarshalErr == nil {
				if createItem, ok := data["createItem"].(map[string]interface{}); ok {
					if id, ok := createItem["id"].(string); ok {
						createdItemID = id
					}
				}
			}
		}
		assert.NotEmpty(t, createdItemID, "expected created item to have an ID")
	})

	t.Run("query item back", func(t *testing.T) {
		if createdItemID == "" {
			t.Skip("no item was created in previous step")
		}

		resp, reqErr := helpers.MakeGraphQLRequest(
			srv.URL+"/graphql",
			`query GetItem($id: ID!) { item(id: $id) { id name } }`,
			map[string]interface{}{"id": createdItemID},
		)
		require.NoError(t, reqErr)

		gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, parseErr)
		assert.Empty(t, gqlResp.Errors, "expected no errors on item query")
		assert.NotNil(t, gqlResp.Data, "expected data in item query response")

		// Verify the mock returns item data.
		if gqlResp.Data != nil {
			var data map[string]interface{}
			if unmarshalErr := json.Unmarshal(gqlResp.Data, &data); unmarshalErr == nil {
				item, ok := data["item"].(map[string]interface{})
				assert.True(t, ok, "expected item field in response data")
				if ok {
					assert.NotEmpty(t, item["id"], "expected item to have an id")
					assert.NotEmpty(t, item["name"], "expected item to have a name")
				}
			}
		}
	})

	t.Run("delete item via mutation", func(t *testing.T) {
		if createdItemID == "" {
			t.Skip("no item was created in previous step")
		}

		resp, reqErr := helpers.MakeGraphQLRequest(
			srv.URL+"/graphql",
			`mutation DeleteItem($id: ID!) { deleteItem(id: $id) { id } }`,
			map[string]interface{}{"id": createdItemID},
		)
		require.NoError(t, reqErr)

		gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, parseErr)
		assert.Empty(t, gqlResp.Errors, "expected no errors on deleteItem mutation")
	})

	t.Run("verify delete mutation was processed", func(t *testing.T) {
		if createdItemID == "" {
			t.Skip("no item was created in previous step")
		}

		// With a stateless mock, we verify the gateway can still proxy queries
		// after a delete mutation was processed successfully.
		resp, reqErr := helpers.MakeGraphQLRequest(
			srv.URL+"/graphql",
			`query { items { id name } }`,
			nil,
		)
		require.NoError(t, reqErr)

		gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, parseErr)
		assert.Empty(t, gqlResp.Errors, "expected no errors after delete flow")
		assert.NotNil(t, gqlResp.Data, "expected data in response after delete flow")
	})
}

// TestE2E_GraphQLGateway_DepthLimitEnforcement starts a gateway with a depth limit
// and verifies that deeply nested queries are rejected.
func TestE2E_GraphQLGateway_DepthLimitEnforcement(t *testing.T) {
	mockBackend := helpers.NewMockGraphQLBackend(t)

	logger := observability.NopLogger()
	backendInfo := helpers.GetGraphQLBackendInfo(mockBackend.Listener.Addr().String())

	// Set up the router.
	rt := router.New(router.WithRouterLogger(logger))
	err := rt.LoadRoutes([]config.GraphQLRoute{
		{
			Name: "depth-limited-route",
			Match: []config.GraphQLRouteMatch{
				{
					Path: &config.StringMatch{Exact: "/graphql"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: backendInfo.Host,
						Port: backendInfo.Port,
					},
					Weight: 100,
				},
			},
			Timeout:    config.Duration(30 * time.Second),
			DepthLimit: 3,
		},
	})
	require.NoError(t, err)

	// Set up the proxy.
	px := proxy.New(
		proxy.WithLogger(logger),
		proxy.WithTimeout(30*time.Second),
	)
	px.UpdateBackends([]config.GraphQLBackend{
		{
			Name: backendInfo.Host,
			Hosts: []config.BackendHost{
				{Address: backendInfo.Host, Port: backendInfo.Port},
			},
		},
	})
	defer px.Close()

	// Create a depth limiter with max depth of 3.
	depthLimiter := middleware.NewDepthLimiter(3, logger)

	handler := graphqlGatewayHandler(rt, px, depthLimiter)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	t.Run("shallow query passes depth limit", func(t *testing.T) {
		resp, reqErr := helpers.MakeGraphQLRequest(
			srv.URL+"/graphql",
			`query { items { id name } }`,
			nil,
		)
		require.NoError(t, reqErr)

		gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, parseErr)
		assert.Empty(t, gqlResp.Errors, "shallow query should pass depth limit")
		assert.NotNil(t, gqlResp.Data, "expected data for shallow query")
	})

	t.Run("deep query is rejected by depth limit", func(t *testing.T) {
		// This query has depth > 3: items -> nested1 -> nested2 -> nested3 -> nested4
		deepQuery := `query {
			items {
				nested1 {
					nested2 {
						nested3 {
							nested4 {
								id
							}
						}
					}
				}
			}
		}`

		resp, reqErr := helpers.MakeGraphQLRequest(
			srv.URL+"/graphql",
			deepQuery,
			nil,
		)
		require.NoError(t, reqErr)

		gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, parseErr)
		require.NotEmpty(t, gqlResp.Errors, "deep query should be rejected")
		assert.Contains(t, gqlResp.Errors[0].Message, "depth", "error should mention depth")
	})

	t.Run("query at exact depth limit passes", func(t *testing.T) {
		// Depth 3: items -> subfield -> leaf
		resp, reqErr := helpers.MakeGraphQLRequest(
			srv.URL+"/graphql",
			`query { items { subfield { leaf } } }`,
			nil,
		)
		require.NoError(t, reqErr)

		gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, parseErr)
		// At exactly the limit, the query should pass the depth check.
		assert.Empty(t, gqlResp.Errors, "query at exact depth limit should pass")
	})
}

// TestE2E_GraphQLGateway_MultipleRoutes configures multiple GraphQL routes
// with different paths and verifies routing works correctly.
func TestE2E_GraphQLGateway_MultipleRoutes(t *testing.T) {
	// Use a multi-path mock that handles GraphQL requests on any path,
	// since this test verifies routing to /api/v1/graphql, /api/v2/graphql, etc.
	mockBackend := newMultiPathMockGraphQLBackend(t)

	logger := observability.NopLogger()
	backendInfo := helpers.GetGraphQLBackendInfo(mockBackend.Listener.Addr().String())

	t.Run("routes to correct backend by path", func(t *testing.T) {
		// Set up the router with multiple routes on different paths.
		rt := router.New(router.WithRouterLogger(logger))
		err := rt.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "api-v1-graphql",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/api/v1/graphql"},
					},
				},
				Route: []config.RouteDestination{
					{
						Destination: config.Destination{
							Host: backendInfo.Host,
							Port: backendInfo.Port,
						},
						Weight: 100,
					},
				},
				Timeout: config.Duration(30 * time.Second),
			},
			{
				Name: "api-v2-graphql",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/api/v2/graphql"},
					},
				},
				Route: []config.RouteDestination{
					{
						Destination: config.Destination{
							Host: backendInfo.Host,
							Port: backendInfo.Port,
						},
						Weight: 100,
					},
				},
				Timeout: config.Duration(30 * time.Second),
			},
			{
				Name: "default-graphql",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []config.RouteDestination{
					{
						Destination: config.Destination{
							Host: backendInfo.Host,
							Port: backendInfo.Port,
						},
						Weight: 100,
					},
				},
				Timeout: config.Duration(30 * time.Second),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, 3, rt.RouteCount())

		// Set up the proxy.
		px := proxy.New(
			proxy.WithLogger(logger),
			proxy.WithTimeout(30*time.Second),
		)
		px.UpdateBackends([]config.GraphQLBackend{
			{
				Name: backendInfo.Host,
				Hosts: []config.BackendHost{
					{Address: backendInfo.Host, Port: backendInfo.Port},
				},
			},
		})
		defer px.Close()

		handler := graphqlGatewayHandler(rt, px, nil)
		srv := httptest.NewServer(handler)
		defer srv.Close()

		// Test each path routes correctly.
		paths := []string{"/api/v1/graphql", "/api/v2/graphql", "/graphql"}
		for _, path := range paths {
			t.Run(fmt.Sprintf("path_%s", path), func(t *testing.T) {
				resp, reqErr := helpers.MakeGraphQLRequest(
					srv.URL+path,
					`query { items { id name } }`,
					nil,
				)
				require.NoError(t, reqErr)

				gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
				require.NoError(t, parseErr)
				assert.Empty(t, gqlResp.Errors, "expected no errors for path %s", path)
				assert.NotNil(t, gqlResp.Data, "expected data for path %s", path)
			})
		}
	})

	t.Run("unmatched path returns not found", func(t *testing.T) {
		rt := router.New(router.WithRouterLogger(logger))
		err := rt.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "specific-path",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []config.RouteDestination{
					{
						Destination: config.Destination{
							Host: backendInfo.Host,
							Port: backendInfo.Port,
						},
						Weight: 100,
					},
				},
			},
		})
		require.NoError(t, err)

		px := proxy.New(proxy.WithLogger(logger))
		px.UpdateBackends([]config.GraphQLBackend{
			{
				Name: backendInfo.Host,
				Hosts: []config.BackendHost{
					{Address: backendInfo.Host, Port: backendInfo.Port},
				},
			},
		})
		defer px.Close()

		handler := graphqlGatewayHandler(rt, px, nil)
		srv := httptest.NewServer(handler)
		defer srv.Close()

		resp, reqErr := helpers.MakeGraphQLRequest(
			srv.URL+"/unknown-path",
			`query { items { id } }`,
			nil,
		)
		require.NoError(t, reqErr)

		gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, parseErr)
		require.NotEmpty(t, gqlResp.Errors, "expected error for unmatched path")
		assert.Contains(t, gqlResp.Errors[0].Message, "no matching", "error should indicate no route match")
	})

	t.Run("routes by operation type", func(t *testing.T) {
		rt := router.New(router.WithRouterLogger(logger))
		err := rt.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "queries-only",
				Match: []config.GraphQLRouteMatch{
					{
						Path:          &config.StringMatch{Exact: "/graphql"},
						OperationType: "query",
					},
				},
				Route: []config.RouteDestination{
					{
						Destination: config.Destination{
							Host: backendInfo.Host,
							Port: backendInfo.Port,
						},
						Weight: 100,
					},
				},
				Timeout: config.Duration(30 * time.Second),
			},
			{
				Name: "mutations-only",
				Match: []config.GraphQLRouteMatch{
					{
						Path:          &config.StringMatch{Exact: "/graphql"},
						OperationType: "mutation",
					},
				},
				Route: []config.RouteDestination{
					{
						Destination: config.Destination{
							Host: backendInfo.Host,
							Port: backendInfo.Port,
						},
						Weight: 100,
					},
				},
				Timeout: config.Duration(30 * time.Second),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, 2, rt.RouteCount())

		px := proxy.New(
			proxy.WithLogger(logger),
			proxy.WithTimeout(30*time.Second),
		)
		px.UpdateBackends([]config.GraphQLBackend{
			{
				Name: backendInfo.Host,
				Hosts: []config.BackendHost{
					{Address: backendInfo.Host, Port: backendInfo.Port},
				},
			},
		})
		defer px.Close()

		handler := graphqlGatewayHandler(rt, px, nil)
		srv := httptest.NewServer(handler)
		defer srv.Close()

		// Query should match the queries-only route.
		resp, reqErr := helpers.MakeGraphQLRequest(
			srv.URL+"/graphql",
			`query { items { id name } }`,
			nil,
		)
		require.NoError(t, reqErr)

		gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, parseErr)
		assert.Empty(t, gqlResp.Errors, "query should match queries-only route")

		// Mutation should match the mutations-only route.
		resp, reqErr = helpers.MakeGraphQLRequest(
			srv.URL+"/graphql",
			`mutation { createItem(input: {name: "test"}) { id } }`,
			nil,
		)
		require.NoError(t, reqErr)

		gqlResp, parseErr = helpers.ReadGraphQLResponse(resp)
		require.NoError(t, parseErr)
		assert.Empty(t, gqlResp.Errors, "mutation should match mutations-only route")
	})
}

// TestE2E_GraphQLGateway_LoadBalancing configures 2 backends, sends multiple
// requests, and verifies distribution across backends.
func TestE2E_GraphQLGateway_LoadBalancing(t *testing.T) {
	mockBackend1 := helpers.NewMockGraphQLBackend(t)
	mockBackend2 := helpers.NewMockGraphQLBackend(t)

	logger := observability.NopLogger()
	backend1Info := helpers.GetGraphQLBackendInfo(mockBackend1.Listener.Addr().String())
	backend2Info := helpers.GetGraphQLBackendInfo(mockBackend2.Listener.Addr().String())

	t.Run("requests distributed across two backends", func(t *testing.T) {
		// Track which backend received each request using intercepting test servers.
		var backend1Count, backend2Count atomic.Int64

		// Create intercepting backend servers that count requests and forward to mock backends.
		interceptBackend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backend1Count.Add(1)
			// Forward to the mock backend.
			proxyToBackend(w, r, mockBackend1.URL)
		}))
		defer interceptBackend1.Close()

		interceptBackend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backend2Count.Add(1)
			// Forward to the mock backend.
			proxyToBackend(w, r, mockBackend2.URL)
		}))
		defer interceptBackend2.Close()

		intercept1Info := helpers.GetGraphQLBackendInfo(interceptBackend1.URL)
		intercept2Info := helpers.GetGraphQLBackendInfo(interceptBackend2.URL)

		// Set up the router.
		rt := router.New(router.WithRouterLogger(logger))
		err := rt.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "lb-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []config.RouteDestination{
					{
						Destination: config.Destination{
							Host: intercept1Info.Host,
							Port: intercept1Info.Port,
						},
						Weight: 50,
					},
					{
						Destination: config.Destination{
							Host: intercept2Info.Host,
							Port: intercept2Info.Port,
						},
						Weight: 50,
					},
				},
				Timeout: config.Duration(30 * time.Second),
			},
		})
		require.NoError(t, err)

		// Set up the proxy with both backends.
		// The proxy uses the backend name from the route match (the host of the first destination).
		// We register a single backend with both hosts for round-robin.
		px := proxy.New(
			proxy.WithLogger(logger),
			proxy.WithTimeout(30*time.Second),
		)
		px.UpdateBackends([]config.GraphQLBackend{
			{
				Name: intercept1Info.Host,
				Hosts: []config.BackendHost{
					{Address: intercept1Info.Host, Port: intercept1Info.Port},
					{Address: intercept2Info.Host, Port: intercept2Info.Port},
				},
			},
		})
		defer px.Close()

		handler := graphqlGatewayHandler(rt, px, nil)
		srv := httptest.NewServer(handler)
		defer srv.Close()

		// Send multiple requests.
		const totalRequests = 10
		for i := range totalRequests {
			resp, reqErr := helpers.MakeGraphQLRequest(
				srv.URL+"/graphql",
				fmt.Sprintf(`query { items { id name } }`),
				nil,
			)
			require.NoError(t, reqErr, "request %d failed", i)

			gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
			require.NoError(t, parseErr, "failed to parse response for request %d", i)
			assert.Empty(t, gqlResp.Errors, "request %d returned errors", i)
		}

		// Verify that requests were distributed across both backends.
		b1 := backend1Count.Load()
		b2 := backend2Count.Load()
		total := b1 + b2

		assert.Equal(t, int64(totalRequests), total, "total requests should match")
		assert.Greater(t, b1, int64(0), "backend 1 should have received at least one request")
		assert.Greater(t, b2, int64(0), "backend 2 should have received at least one request")

		t.Logf("Load distribution: backend1=%d, backend2=%d (total=%d)", b1, b2, total)
	})

	t.Run("proxy routes with multiple backend hosts", func(t *testing.T) {
		// Verify that the proxy's round-robin works with multiple hosts in a single backend.
		rt := router.New(router.WithRouterLogger(logger))
		err := rt.LoadRoutes([]config.GraphQLRoute{
			{
				Name: "multi-host-route",
				Match: []config.GraphQLRouteMatch{
					{
						Path: &config.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []config.RouteDestination{
					{
						Destination: config.Destination{
							Host: backend1Info.Host,
							Port: backend1Info.Port,
						},
						Weight: 100,
					},
				},
				Timeout: config.Duration(30 * time.Second),
			},
		})
		require.NoError(t, err)

		px := proxy.New(
			proxy.WithLogger(logger),
			proxy.WithTimeout(30*time.Second),
		)
		px.UpdateBackends([]config.GraphQLBackend{
			{
				Name: backend1Info.Host,
				Hosts: []config.BackendHost{
					{Address: backend1Info.Host, Port: backend1Info.Port},
					{Address: backend2Info.Host, Port: backend2Info.Port},
				},
			},
		})
		defer px.Close()

		handler := graphqlGatewayHandler(rt, px, nil)
		srv := httptest.NewServer(handler)
		defer srv.Close()

		// Send several requests; they should alternate between the two hosts.
		for i := range 6 {
			resp, reqErr := helpers.MakeGraphQLRequest(
				srv.URL+"/graphql",
				`query { items { id name } }`,
				nil,
			)
			require.NoError(t, reqErr, "request %d failed", i)

			gqlResp, parseErr := helpers.ReadGraphQLResponse(resp)
			require.NoError(t, parseErr, "failed to parse response for request %d", i)
			assert.Empty(t, gqlResp.Errors, "request %d returned errors", i)
			assert.NotNil(t, gqlResp.Data, "request %d should have data", i)
		}
	})
}

// proxyToBackend forwards an HTTP request to the specified backend URL.
func proxyToBackend(w http.ResponseWriter, r *http.Request, backendURL string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	targetURL := backendURL + r.URL.Path
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, newBytesReader(body))
	if err != nil {
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}
	req.Header = r.Header.Clone()

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "backend request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
