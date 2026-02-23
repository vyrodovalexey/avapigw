//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/graphql/middleware"
	graphqlproxy "github.com/vyrodovalexey/avapigw/internal/graphql/proxy"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// graphqlProxyHandler creates an http.Handler that combines the GraphQL router,
// middleware checks, and proxy forwarding — mimicking the gateway's request lifecycle.
func graphqlProxyHandler(
	router *graphqlrouter.Router,
	proxy *graphqlproxy.Proxy,
	route *config.GraphQLRoute,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		// Read the body so we can parse it and still forward it
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeGraphQLError(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		r.Body.Close()

		// Parse the GraphQL request
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		gqlReq, err := graphqlrouter.ParseGraphQLRequest(r)
		if err != nil {
			writeGraphQLError(w, http.StatusBadRequest, fmt.Sprintf("invalid GraphQL request: %v", err))
			return
		}

		// Match the route
		result := router.Match(r, gqlReq)
		if result == nil {
			writeGraphQLError(w, http.StatusNotFound, "no matching GraphQL route")
			return
		}

		matchedRoute := result.Route

		// Apply depth limit middleware
		if matchedRoute.DepthLimit > 0 {
			limiter := middleware.NewDepthLimiter(matchedRoute.DepthLimit, observability.NopLogger())
			if checkErr := limiter.Check(gqlReq.Query); checkErr != nil {
				writeGraphQLError(w, http.StatusBadRequest, checkErr.Error())
				return
			}
		}

		// Apply complexity limit middleware
		if matchedRoute.ComplexityLimit > 0 {
			analyzer := middleware.NewComplexityAnalyzer(matchedRoute.ComplexityLimit, observability.NopLogger())
			if checkErr := analyzer.Check(gqlReq.Query); checkErr != nil {
				writeGraphQLError(w, http.StatusBadRequest, checkErr.Error())
				return
			}
		}

		// Apply introspection guard middleware
		if matchedRoute.IntrospectionEnabled != nil {
			guard := middleware.NewIntrospectionGuard(*matchedRoute.IntrospectionEnabled, observability.NopLogger())
			if checkErr := guard.Check(gqlReq.Query); checkErr != nil {
				writeGraphQLError(w, http.StatusForbidden, checkErr.Error())
				return
			}
		}

		// Restore the body for forwarding
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Forward the request via the proxy
		resp, fwdErr := proxy.Forward(ctx, result.BackendName, r)
		if fwdErr != nil {
			writeGraphQLError(w, http.StatusBadGateway, fmt.Sprintf("proxy error: %v", fwdErr))
			return
		}
		defer resp.Body.Close()

		// Copy response headers
		for key, values := range resp.Header {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
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

// setupGraphQLProxy creates a router, proxy, and test server for a given route and backend config.
func setupGraphQLProxy(
	t *testing.T,
	route config.GraphQLRoute,
	backends []config.GraphQLBackend,
) (*httptest.Server, *graphqlproxy.Proxy) {
	t.Helper()

	router := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
	err := router.LoadRoutes([]config.GraphQLRoute{route})
	require.NoError(t, err)
	require.Equal(t, 1, router.RouteCount())

	proxy := graphqlproxy.New(
		graphqlproxy.WithLogger(observability.NopLogger()),
		graphqlproxy.WithTimeout(30*time.Second),
	)
	proxy.UpdateBackends(backends)

	handler := graphqlProxyHandler(router, proxy, &route)
	server := httptest.NewServer(handler)

	t.Cleanup(func() {
		server.Close()
		proxy.Close()
	})

	return server, proxy
}

// setupMockBackendProxy creates a mock GraphQL backend and wires up a proxy test server.
// It returns the proxy test server URL and the mock backend info for use in assertions.
func setupMockBackendProxy(
	t *testing.T,
	routeName string,
	depthLimit int,
	complexityLimit int,
	introspectionEnabled *bool,
) *httptest.Server {
	t.Helper()

	mockBackend := helpers.NewMockGraphQLBackend(t)
	backendInfo := helpers.GetGraphQLBackendInfo(mockBackend.Listener.Addr().String())

	route := config.GraphQLRoute{
		Name: routeName,
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
		Timeout:              config.Duration(30 * time.Second),
		DepthLimit:           depthLimit,
		ComplexityLimit:      complexityLimit,
		IntrospectionEnabled: introspectionEnabled,
	}

	backends := []config.GraphQLBackend{
		{
			Name: backendInfo.Host,
			Hosts: []config.BackendHost{
				{Address: backendInfo.Host, Port: backendInfo.Port, Weight: 1},
			},
		},
	}

	server, _ := setupGraphQLProxy(t, route, backends)
	return server
}

func TestIntegration_GraphQLProxy_QueryItems(t *testing.T) {
	introspectionEnabled := true
	server := setupMockBackendProxy(t, "test-query-items", 10, 100, &introspectionEnabled)

	t.Run("query all items returns 200 with data", func(t *testing.T) {
		query := `{ items { id name } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)

		assert.Empty(t, gqlResp.Errors, "expected no GraphQL errors")
		assert.NotNil(t, gqlResp.Data, "expected data in response")

		// Verify the data contains items
		var data map[string]json.RawMessage
		err = json.Unmarshal(gqlResp.Data, &data)
		require.NoError(t, err)
		assert.Contains(t, data, "items", "response data should contain 'items' field")
	})

	t.Run("query items with operation name", func(t *testing.T) {
		query := `query GetAllItems { items { id name } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)

		assert.Empty(t, gqlResp.Errors, "expected no GraphQL errors")
		assert.NotNil(t, gqlResp.Data, "expected data in response")
	})
}

func TestIntegration_GraphQLProxy_QuerySingleItem(t *testing.T) {
	introspectionEnabled := true
	server := setupMockBackendProxy(t, "test-query-single-item", 10, 100, &introspectionEnabled)

	t.Run("query single item by ID returns data", func(t *testing.T) {
		query := `{ item(id: "1") { id name price } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)

		assert.NotNil(t, gqlResp.Data, "expected data in response")

		// Parse the data to verify structure
		var data map[string]json.RawMessage
		err = json.Unmarshal(gqlResp.Data, &data)
		require.NoError(t, err)
		assert.Contains(t, data, "item", "response data should contain 'item' field")
	})

	t.Run("query single item with variables", func(t *testing.T) {
		query := `query GetItem($id: ID!) { item(id: $id) { id name price } }`
		variables := map[string]interface{}{
			"id": "1",
		}
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, variables)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)

		assert.NotNil(t, gqlResp.Data, "expected data in response")
	})
}

func TestIntegration_GraphQLProxy_CreateMutation(t *testing.T) {
	introspectionEnabled := true
	server := setupMockBackendProxy(t, "test-create-mutation", 10, 100, &introspectionEnabled)

	t.Run("create item mutation returns created item", func(t *testing.T) {
		query := `mutation { createItem(input: { name: "Integration Test Item", description: "Created by integration test", price: 29.99 }) { id name } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)

		assert.NotNil(t, gqlResp.Data, "expected data in response")

		// Parse the data to verify structure
		var data map[string]json.RawMessage
		err = json.Unmarshal(gqlResp.Data, &data)
		require.NoError(t, err)
		assert.Contains(t, data, "createItem", "response data should contain 'createItem' field")
	})

	t.Run("create item mutation with variables", func(t *testing.T) {
		query := `mutation CreateItem($input: CreateItemInput!) { createItem(input: $input) { id name } }`
		variables := map[string]interface{}{
			"input": map[string]interface{}{
				"name":        "Variable Test Item",
				"description": "Created with variables",
				"price":       39.99,
			},
		}
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, variables)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)

		assert.NotNil(t, gqlResp.Data, "expected data in response")
	})
}

func TestIntegration_GraphQLProxy_DepthLimit(t *testing.T) {
	introspectionEnabled := true
	server := setupMockBackendProxy(t, "test-depth-limit", 2, 100, &introspectionEnabled)

	t.Run("deeply nested query is rejected with 400", func(t *testing.T) {
		// This query has depth 4: items -> details -> category -> subcategory
		query := `{ items { details { category { subcategory { name } } } } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "deeply nested query should be rejected")

		var gqlResp helpers.GraphQLResponse
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		err = json.Unmarshal(body, &gqlResp)
		require.NoError(t, err)

		require.NotEmpty(t, gqlResp.Errors, "expected error in response")
		assert.Contains(t, gqlResp.Errors[0].Message, "depth", "error should mention depth limit")
	})

	t.Run("shallow query within depth limit is allowed", func(t *testing.T) {
		// This query has depth 2: items -> id, name
		query := `{ items { id name } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)

		assert.NotNil(t, gqlResp.Data, "shallow query should be allowed")
	})
}

func TestIntegration_GraphQLProxy_ComplexityLimit(t *testing.T) {
	introspectionEnabled := true
	server := setupMockBackendProxy(t, "test-complexity-limit", 20, 5, &introspectionEnabled)

	t.Run("complex query exceeding limit is rejected with 400", func(t *testing.T) {
		// This query has complexity > 5: items(1) + id(1) + name(1) + price(1) + description(1) + createdAt(1) = 6
		query := `{ items { id name price description createdAt updatedAt } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "complex query should be rejected")

		var gqlResp helpers.GraphQLResponse
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		err = json.Unmarshal(body, &gqlResp)
		require.NoError(t, err)

		require.NotEmpty(t, gqlResp.Errors, "expected error in response")
		assert.Contains(t, gqlResp.Errors[0].Message, "complexity", "error should mention complexity limit")
	})

	t.Run("simple query within complexity limit is allowed", func(t *testing.T) {
		// This query has complexity 3: items(1) + id(1) + name(1) = 3
		query := `{ items { id name } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)

		assert.NotNil(t, gqlResp.Data, "simple query should be allowed")
	})
}

func TestIntegration_GraphQLProxy_IntrospectionBlocked(t *testing.T) {
	introspectionEnabled := false
	server := setupMockBackendProxy(t, "test-introspection-blocked", 10, 100, &introspectionEnabled)

	t.Run("__schema introspection query is blocked", func(t *testing.T) {
		query := `{ __schema { types { name } } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "introspection should be blocked")

		var gqlResp helpers.GraphQLResponse
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		err = json.Unmarshal(body, &gqlResp)
		require.NoError(t, err)

		require.NotEmpty(t, gqlResp.Errors, "expected error in response")
		assert.Contains(t, gqlResp.Errors[0].Message, "introspection", "error should mention introspection")
	})

	t.Run("__type introspection query is blocked", func(t *testing.T) {
		query := `{ __type(name: "Query") { name fields { name } } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "introspection should be blocked")
	})

	t.Run("regular query is still allowed", func(t *testing.T) {
		query := `{ items { id name } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)

		assert.NotNil(t, gqlResp.Data, "regular query should still work")
	})
}

func TestIntegration_GraphQLProxy_IntrospectionAllowed(t *testing.T) {
	introspectionEnabled := true
	server := setupMockBackendProxy(t, "test-introspection-allowed", 20, 200, &introspectionEnabled)

	t.Run("__schema introspection query is allowed", func(t *testing.T) {
		query := `{ __schema { types { name } } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)

		// The backend should process the introspection query
		// It may return data or an error depending on backend support,
		// but the proxy should NOT block it
		assert.NotEqual(t, http.StatusForbidden, resp.StatusCode,
			"introspection should not be blocked when enabled")
		// If the backend supports introspection, we expect data
		if len(gqlResp.Errors) == 0 {
			assert.NotNil(t, gqlResp.Data, "expected introspection data")
		}
	})

	t.Run("__type introspection query is allowed", func(t *testing.T) {
		query := `{ __type(name: "Query") { name } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
		require.NoError(t, err)

		// ReadGraphQLResponse closes the body
		_, err = helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)

		// The proxy should not block introspection
		assert.NotEqual(t, http.StatusForbidden, resp.StatusCode,
			"introspection should not be blocked when enabled")
	})
}

func TestIntegration_GraphQLProxy_MultipleBackends(t *testing.T) {
	t.Run("traffic is distributed across multiple backends", func(t *testing.T) {
		// Create two mock GraphQL backends with tracking counters
		mockBackend1 := helpers.NewMockGraphQLBackend(t)
		mockBackend2 := helpers.NewMockGraphQLBackend(t)

		var backend1Hits atomic.Int64
		var backend2Hits atomic.Int64

		// Wrap mock backends with hit counters
		trackingBackend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backend1Hits.Add(1)
			proxyToBackend(w, r, mockBackend1.URL)
		}))
		defer trackingBackend1.Close()

		trackingBackend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backend2Hits.Add(1)
			proxyToBackend(w, r, mockBackend2.URL)
		}))
		defer trackingBackend2.Close()

		tb1Info := helpers.GetGraphQLBackendInfo(trackingBackend1.Listener.Addr().String())
		tb2Info := helpers.GetGraphQLBackendInfo(trackingBackend2.Listener.Addr().String())

		// Use the first tracking backend's host as the backend name (router returns first destination host)
		backendName := tb1Info.Host

		introspectionEnabled := true
		route := config.GraphQLRoute{
			Name: "test-multi-backend",
			Match: []config.GraphQLRouteMatch{
				{
					Path: &config.StringMatch{Exact: "/graphql"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: backendName,
						Port: tb1Info.Port,
					},
					Weight: 50,
				},
				{
					Destination: config.Destination{
						Host: tb2Info.Host,
						Port: tb2Info.Port,
					},
					Weight: 50,
				},
			},
			Timeout:              config.Duration(30 * time.Second),
			DepthLimit:           10,
			ComplexityLimit:      100,
			IntrospectionEnabled: &introspectionEnabled,
		}

		// The router Match returns BackendName as the first destination's host.
		// We configure the proxy with a single backend name that has both tracking servers as hosts.
		backends := []config.GraphQLBackend{
			{
				Name: backendName,
				Hosts: []config.BackendHost{
					{Address: tb1Info.Host, Port: tb1Info.Port, Weight: 1},
					{Address: tb2Info.Host, Port: tb2Info.Port, Weight: 1},
				},
			},
		}

		server, _ := setupGraphQLProxy(t, route, backends)

		// Send multiple requests
		const numRequests = 20
		for i := 0; i < numRequests; i++ {
			query := `{ items { id name } }`
			resp, err := helpers.MakeGraphQLRequest(server.URL+"/graphql", query, nil)
			require.NoError(t, err)

			gqlResp, err := helpers.ReadGraphQLResponse(resp)
			require.NoError(t, err)
			assert.NotNil(t, gqlResp.Data, "request %d should return data", i)
		}

		// Verify both backends received traffic (round-robin)
		hits1 := backend1Hits.Load()
		hits2 := backend2Hits.Load()
		totalHits := hits1 + hits2

		assert.Equal(t, int64(numRequests), totalHits, "total hits should equal number of requests")
		assert.Greater(t, hits1, int64(0), "backend 1 should receive some traffic")
		assert.Greater(t, hits2, int64(0), "backend 2 should receive some traffic")

		t.Logf("Traffic distribution: backend1=%d, backend2=%d (total=%d)", hits1, hits2, totalHits)
	})
}

// proxyToBackend forwards a request to a backend and writes the response back.
func proxyToBackend(w http.ResponseWriter, r *http.Request, backendURL string) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, backendURL+r.URL.Path, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("backend error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func TestIntegration_GraphQLProxy_ErrorHandling(t *testing.T) {
	introspectionEnabled := true
	server := setupMockBackendProxy(t, "test-error-handling", 10, 100, &introspectionEnabled)

	t.Run("malformed request body returns 400", func(t *testing.T) {
		// Send non-JSON body
		req, err := http.NewRequest(http.MethodPost, server.URL+"/graphql",
			strings.NewReader("this is not json"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := helpers.HTTPClient()
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "malformed request should return 400")

		var gqlResp helpers.GraphQLResponse
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		err = json.Unmarshal(body, &gqlResp)
		require.NoError(t, err)

		require.NotEmpty(t, gqlResp.Errors, "expected error in response")
	})

	t.Run("empty query returns 400", func(t *testing.T) {
		// Send JSON with empty query
		reqBody := map[string]interface{}{
			"query": "",
		}
		jsonBody, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, server.URL+"/graphql",
			bytes.NewReader(jsonBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := helpers.HTTPClient()
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "empty query should return 400")
	})

	t.Run("empty body returns 400", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/graphql",
			strings.NewReader(""))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := helpers.HTTPClient()
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "empty body should return 400")
	})

	t.Run("request to non-matching path returns 404", func(t *testing.T) {
		query := `{ items { id name } }`
		resp, err := helpers.MakeGraphQLRequest(server.URL+"/nonexistent", query, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// The route only matches /graphql, so /nonexistent should not match
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "non-matching path should return 404")
	})
}
