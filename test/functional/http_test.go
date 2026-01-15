//go:build functional
// +build functional

package functional

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwhttp "github.com/vyrodovalexey/avapigw/internal/gateway/server/http"
)

// ============================================================================
// Server Startup and Shutdown Tests
// ============================================================================

func TestFunctional_HTTP_ServerStartup(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)
	require.NotNil(t, server)

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()

	// Wait for server to be ready
	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	assert.True(t, server.IsRunning())

	// Stop server
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	err := server.Stop(stopCtx)
	require.NoError(t, err)

	assert.False(t, server.IsRunning())
}

func TestFunctional_HTTP_ServerDoubleStart(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	// Try to start again - should fail
	err := server.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

func TestFunctional_HTTP_ServerGracefulShutdown(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	err := server.Stop(shutdownCtx)
	require.NoError(t, err)
	assert.False(t, server.IsRunning())
}

// ============================================================================
// Request Routing Tests
// ============================================================================

func TestFunctional_HTTP_RouteMatching_ExactPath(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	// Add route with exact path match
	route := &gwhttp.Route{
		Name:      "exact-route",
		Hostnames: []string{"*"},
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchExact,
							Value: "/api/v1/users",
						},
					},
				},
			},
		},
	}
	err := server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	// Test exact match
	resp, err := client.Get(fmt.Sprintf("http://%s/api/v1/users", addr))
	require.NoError(t, err)
	defer resp.Body.Close()
	// Route matches but no backend configured, so we get a response from the handler
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode)

	// Test non-matching path
	resp2, err := client.Get(fmt.Sprintf("http://%s/api/v1/users/123", addr))
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

func TestFunctional_HTTP_RouteMatching_PrefixPath(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	// Add route with prefix path match
	route := &gwhttp.Route{
		Name:      "prefix-route",
		Hostnames: []string{"*"},
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchPrefix,
							Value: "/api/",
						},
					},
				},
			},
		},
	}
	err := server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	// Test prefix matches
	testPaths := []string{
		"/api/v1/users",
		"/api/v2/products",
		"/api/health",
	}

	for _, path := range testPaths {
		resp, err := client.Get(fmt.Sprintf("http://%s%s", addr, path))
		require.NoError(t, err)
		resp.Body.Close()
		assert.NotEqual(t, http.StatusNotFound, resp.StatusCode, "path %s should match", path)
	}

	// Test non-matching path
	resp, err := client.Get(fmt.Sprintf("http://%s/other/path", addr))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

func TestFunctional_HTTP_RouteMatching_MethodMatch(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	// Add route with method match
	getMethod := "GET"
	route := &gwhttp.Route{
		Name:      "method-route",
		Hostnames: []string{"*"},
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchPrefix,
							Value: "/api/",
						},
						Method: &getMethod,
					},
				},
			},
		},
	}
	err := server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	// Test GET request - should match
	resp, err := client.Get(fmt.Sprintf("http://%s/api/users", addr))
	require.NoError(t, err)
	resp.Body.Close()
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode)

	// Test POST request - should not match
	resp2, err := client.Post(fmt.Sprintf("http://%s/api/users", addr), "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

func TestFunctional_HTTP_RouteMatching_HeaderMatch(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	// Add route with header match
	route := &gwhttp.Route{
		Name:      "header-route",
		Hostnames: []string{"*"},
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchPrefix,
							Value: "/api/",
						},
						Headers: []gwhttp.HeaderMatch{
							{
								Type:  gwhttp.HeaderMatchExact,
								Name:  "X-API-Version",
								Value: "v2",
							},
						},
					},
				},
			},
		},
	}
	err := server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	// Test with matching header
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/users", addr), nil)
	req.Header.Set("X-API-Version", "v2")
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode)

	// Test without header - should not match
	resp2, err := client.Get(fmt.Sprintf("http://%s/api/users", addr))
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

func TestFunctional_HTTP_RouteMatching_QueryParamMatch(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	// Add route with query param match
	route := &gwhttp.Route{
		Name:      "query-route",
		Hostnames: []string{"*"},
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchPrefix,
							Value: "/api/",
						},
						QueryParams: []gwhttp.QueryParamMatch{
							{
								Type:  gwhttp.QueryParamMatchExact,
								Name:  "version",
								Value: "2",
							},
						},
					},
				},
			},
		},
	}
	err := server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	// Test with matching query param
	resp, err := client.Get(fmt.Sprintf("http://%s/api/users?version=2", addr))
	require.NoError(t, err)
	resp.Body.Close()
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode)

	// Test without query param - should not match
	resp2, err := client.Get(fmt.Sprintf("http://%s/api/users", addr))
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

func TestFunctional_HTTP_RouteMatching_HostnameMatch(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	// Add route with hostname match
	route := &gwhttp.Route{
		Name:      "hostname-route",
		Hostnames: []string{"api.example.com"},
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchPrefix,
							Value: "/",
						},
					},
				},
			},
		},
	}
	err := server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	// Test with matching host header
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/users", addr), nil)
	req.Host = "api.example.com"
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode)

	// Test with non-matching host - should not match
	req2, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/users", addr), nil)
	req2.Host = "other.example.com"
	resp2, err := client.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

// ============================================================================
// Route Management Tests
// ============================================================================

func TestFunctional_HTTP_RouteManagement_AddRemoveUpdate(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)
	router := server.GetRouter()

	// Add route
	route := &gwhttp.Route{
		Name:      "test-route",
		Hostnames: []string{"*"},
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchPrefix,
							Value: "/api/",
						},
					},
				},
			},
		},
	}

	err := router.AddRoute(route)
	require.NoError(t, err)

	// Verify route exists
	assert.Contains(t, router.ListRoutes(), "test-route")

	// Try to add duplicate - should fail
	err = router.AddRoute(route)
	assert.Error(t, err)

	// Update route
	route.Priority = 10
	err = router.UpdateRoute(route)
	require.NoError(t, err)

	// Remove route
	err = router.RemoveRoute("test-route")
	require.NoError(t, err)

	// Verify route removed
	assert.NotContains(t, router.ListRoutes(), "test-route")

	// Try to remove non-existent route - should fail
	err = router.RemoveRoute("non-existent")
	assert.Error(t, err)
}

// ============================================================================
// Error Response Tests
// ============================================================================

func TestFunctional_HTTP_ErrorResponse_NotFound(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	// Request to non-existent route
	resp, err := client.Get(fmt.Sprintf("http://%s/non-existent", addr))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Not Found")

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

// ============================================================================
// Request Body Size Limit Tests
// ============================================================================

func TestFunctional_HTTP_RequestBodySizeLimit(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.MaxRequestBodySize = 1024 // 1KB limit

	server := suite.CreateHTTPServer(config)

	// Add a route that accepts POST
	route := &gwhttp.Route{
		Name:      "post-route",
		Hostnames: []string{"*"},
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchPrefix,
							Value: "/",
						},
					},
				},
			},
		},
	}
	server.GetRouter().AddRoute(route)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	// Small body - should succeed
	smallBody := strings.Repeat("a", 100)
	resp, err := client.Post(fmt.Sprintf("http://%s/test", addr), "text/plain", strings.NewReader(smallBody))
	require.NoError(t, err)
	resp.Body.Close()
	// Route matches, request is processed
	assert.NotEqual(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

// ============================================================================
// Concurrent Request Tests
// ============================================================================

func TestFunctional_HTTP_ConcurrentRequests(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	// Add a route
	route := &gwhttp.Route{
		Name:      "concurrent-route",
		Hostnames: []string{"*"},
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchPrefix,
							Value: "/",
						},
					},
				},
			},
		},
	}
	server.GetRouter().AddRoute(route)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(30 * time.Second)

	// Execute concurrent requests
	requester := NewConcurrentRequester(client, 10, 100)
	results := requester.Execute(t, "GET", fmt.Sprintf("http://%s/test", addr))

	// All requests should complete without errors
	assert.Equal(t, 0, requester.CountErrors())
	assert.Equal(t, 100, len(results))

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

// ============================================================================
// Route Priority Tests
// ============================================================================

func TestFunctional_HTTP_RoutePriority(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	// Add low priority route (matches all)
	lowPriorityRoute := &gwhttp.Route{
		Name:      "low-priority",
		Hostnames: []string{"*"},
		Priority:  1,
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchPrefix,
							Value: "/api/",
						},
					},
				},
			},
		},
	}
	server.GetRouter().AddRoute(lowPriorityRoute)

	// Add high priority route (more specific)
	highPriorityRoute := &gwhttp.Route{
		Name:      "high-priority",
		Hostnames: []string{"*"},
		Priority:  10,
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchExact,
							Value: "/api/v1/users",
						},
					},
				},
			},
		},
	}
	server.GetRouter().AddRoute(highPriorityRoute)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	// Request to /api/v1/users should match high priority route
	resp, err := client.Get(fmt.Sprintf("http://%s/api/v1/users", addr))
	require.NoError(t, err)
	resp.Body.Close()
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode)

	// Request to /api/other should match low priority route
	resp2, err := client.Get(fmt.Sprintf("http://%s/api/other", addr))
	require.NoError(t, err)
	resp2.Body.Close()
	assert.NotEqual(t, http.StatusNotFound, resp2.StatusCode)

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

// ============================================================================
// Regex Path Matching Tests
// ============================================================================

func TestFunctional_HTTP_RouteMatching_RegexPath(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	// Add route with regex path match
	route := &gwhttp.Route{
		Name:      "regex-route",
		Hostnames: []string{"*"},
		Rules: []gwhttp.RouteRule{
			{
				Matches: []gwhttp.RouteMatch{
					{
						Path: &gwhttp.PathMatch{
							Type:  gwhttp.PathMatchRegularExpression,
							Value: "^/api/v[0-9]+/users/[0-9]+$",
						},
					},
				},
			},
		},
	}
	err := server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	// Test matching paths
	matchingPaths := []string{
		"/api/v1/users/123",
		"/api/v2/users/456",
		"/api/v10/users/1",
	}

	for _, path := range matchingPaths {
		resp, err := client.Get(fmt.Sprintf("http://%s%s", addr, path))
		require.NoError(t, err)
		resp.Body.Close()
		assert.NotEqual(t, http.StatusNotFound, resp.StatusCode, "path %s should match", path)
	}

	// Test non-matching paths
	nonMatchingPaths := []string{
		"/api/v1/users",
		"/api/v1/users/abc",
		"/api/users/123",
	}

	for _, path := range nonMatchingPaths {
		resp, err := client.Get(fmt.Sprintf("http://%s%s", addr, path))
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "path %s should not match", path)
	}

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

// ============================================================================
// Table-Driven Tests
// ============================================================================

func TestFunctional_HTTP_RouteMatching_TableDriven(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwhttp.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateHTTPServer(config)

	// Add multiple routes
	routes := []*gwhttp.Route{
		{
			Name:      "users-route",
			Hostnames: []string{"*"},
			Priority:  10,
			Rules: []gwhttp.RouteRule{
				{
					Matches: []gwhttp.RouteMatch{
						{
							Path: &gwhttp.PathMatch{
								Type:  gwhttp.PathMatchPrefix,
								Value: "/users",
							},
						},
					},
				},
			},
		},
		{
			Name:      "products-route",
			Hostnames: []string{"*"},
			Priority:  10,
			Rules: []gwhttp.RouteRule{
				{
					Matches: []gwhttp.RouteMatch{
						{
							Path: &gwhttp.PathMatch{
								Type:  gwhttp.PathMatchPrefix,
								Value: "/products",
							},
						},
					},
				},
			},
		},
	}

	for _, route := range routes {
		err := server.GetRouter().AddRoute(route)
		require.NoError(t, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	tests := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{
			name:           "users route matches",
			path:           "/users/123",
			expectedStatus: http.StatusOK, // Route matches, handler returns OK
		},
		{
			name:           "products route matches",
			path:           "/products/456",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "no route matches",
			path:           "/orders/789",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Get(fmt.Sprintf("http://%s%s", addr, tt.path))
			require.NoError(t, err)
			defer resp.Body.Close()

			if tt.expectedStatus == http.StatusNotFound {
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			} else {
				assert.NotEqual(t, http.StatusNotFound, resp.StatusCode)
			}
		})
	}

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}
