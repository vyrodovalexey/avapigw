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

	"github.com/gin-gonic/gin"
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

	// Test exact match - route matches, handler returns 200 OK (no backend configured)
	resp, err := client.Get(fmt.Sprintf("http://%s/api/v1/users", addr))
	require.NoError(t, err, "request should not fail")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "exact path match should return 200 OK")

	// Test non-matching path - should return 404 Not Found
	resp2, err := client.Get(fmt.Sprintf("http://%s/api/v1/users/123", addr))
	require.NoError(t, err, "request should not fail")
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode, "non-matching path should return 404 Not Found")

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

	// Test prefix matches - all should return 200 OK
	testPaths := []string{
		"/api/v1/users",
		"/api/v2/products",
		"/api/health",
	}

	for _, path := range testPaths {
		resp, err := client.Get(fmt.Sprintf("http://%s%s", addr, path))
		require.NoError(t, err, "request to %s should not fail", path)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "path %s should match and return 200 OK", path)
	}

	// Test non-matching path - should return 404 Not Found
	resp, err := client.Get(fmt.Sprintf("http://%s/other/path", addr))
	require.NoError(t, err, "request should not fail")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "non-matching path should return 404 Not Found")

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

	// Test GET request - should match and return 200 OK
	resp, err := client.Get(fmt.Sprintf("http://%s/api/users", addr))
	require.NoError(t, err, "GET request should not fail")
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GET request should match and return 200 OK")

	// Test POST request - should not match and return 404 Not Found
	resp2, err := client.Post(fmt.Sprintf("http://%s/api/users", addr), "application/json", strings.NewReader("{}"))
	require.NoError(t, err, "POST request should not fail")
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode, "POST request should not match and return 404 Not Found")

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

	// Test with matching header - should return 200 OK
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/users", addr), nil)
	req.Header.Set("X-API-Version", "v2")
	resp, err := client.Do(req)
	require.NoError(t, err, "request with matching header should not fail")
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "request with matching header should return 200 OK")

	// Test without header - should not match and return 404 Not Found
	resp2, err := client.Get(fmt.Sprintf("http://%s/api/users", addr))
	require.NoError(t, err, "request without header should not fail")
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode, "request without matching header should return 404 Not Found")

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

	// Test with matching query param - should return 200 OK
	resp, err := client.Get(fmt.Sprintf("http://%s/api/users?version=2", addr))
	require.NoError(t, err, "request with matching query param should not fail")
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "request with matching query param should return 200 OK")

	// Test without query param - should not match and return 404 Not Found
	resp2, err := client.Get(fmt.Sprintf("http://%s/api/users", addr))
	require.NoError(t, err, "request without query param should not fail")
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode, "request without matching query param should return 404 Not Found")

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

	// Test with matching host header - should return 200 OK
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/users", addr), nil)
	req.Host = "api.example.com"
	resp, err := client.Do(req)
	require.NoError(t, err, "request with matching host should not fail")
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "request with matching host should return 200 OK")

	// Test with non-matching host - should not match and return 404 Not Found
	req2, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/users", addr), nil)
	req2.Host = "other.example.com"
	resp2, err := client.Do(req2)
	require.NoError(t, err, "request with non-matching host should not fail")
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode, "request with non-matching host should return 404 Not Found")

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

	// Add a route that accepts POST and reads the body
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

	// Add a middleware that reads the body to trigger the size limit check
	server.Use(func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			// MaxBytesReader returns an error when limit is exceeded
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			c.Abort()
			return
		}
		// Echo back the body size for verification
		c.JSON(http.StatusOK, gin.H{"size": len(body)})
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForServer(t, addr, 5*time.Second)

	client := CreateTestHTTPClient(5 * time.Second)

	t.Run("small body succeeds", func(t *testing.T) {
		smallBody := strings.Repeat("a", 100)
		resp, err := client.Post(fmt.Sprintf("http://%s/test", addr), "text/plain", strings.NewReader(smallBody))
		require.NoError(t, err, "request should not fail")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "small body should be accepted")
	})

	t.Run("large body rejected", func(t *testing.T) {
		// Create a body larger than the 1024 byte limit
		largeBody := strings.Repeat("a", 2048)
		resp, err := client.Post(fmt.Sprintf("http://%s/test", addr), "text/plain", strings.NewReader(largeBody))
		require.NoError(t, err, "request should not fail at transport level")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode, "large body should be rejected with 413 status")
	})

	t.Run("body at exact limit succeeds", func(t *testing.T) {
		// Body exactly at the limit should succeed
		exactBody := strings.Repeat("a", 1024)
		resp, err := client.Post(fmt.Sprintf("http://%s/test", addr), "text/plain", strings.NewReader(exactBody))
		require.NoError(t, err, "request should not fail")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "body at exact limit should be accepted")
	})

	t.Run("body just over limit rejected", func(t *testing.T) {
		// Body just over the limit should be rejected
		overLimitBody := strings.Repeat("a", 1025)
		resp, err := client.Post(fmt.Sprintf("http://%s/test", addr), "text/plain", strings.NewReader(overLimitBody))
		require.NoError(t, err, "request should not fail at transport level")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode, "body just over limit should be rejected with 413 status")
	})

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

	// Request to /api/v1/users should match high priority route and return 200 OK
	resp, err := client.Get(fmt.Sprintf("http://%s/api/v1/users", addr))
	require.NoError(t, err, "request to high priority route should not fail")
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "high priority route should match and return 200 OK")

	// Request to /api/other should match low priority route and return 200 OK
	resp2, err := client.Get(fmt.Sprintf("http://%s/api/other", addr))
	require.NoError(t, err, "request to low priority route should not fail")
	resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "low priority route should match and return 200 OK")

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

	// Test matching paths - all should return 200 OK
	matchingPaths := []string{
		"/api/v1/users/123",
		"/api/v2/users/456",
		"/api/v10/users/1",
	}

	for _, path := range matchingPaths {
		resp, err := client.Get(fmt.Sprintf("http://%s%s", addr, path))
		require.NoError(t, err, "request to %s should not fail", path)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "path %s should match regex and return 200 OK", path)
	}

	// Test non-matching paths - all should return 404 Not Found
	nonMatchingPaths := []string{
		"/api/v1/users",
		"/api/v1/users/abc",
		"/api/users/123",
	}

	for _, path := range nonMatchingPaths {
		resp, err := client.Get(fmt.Sprintf("http://%s%s", addr, path))
		require.NoError(t, err, "request to %s should not fail", path)
		resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "path %s should not match regex and return 404 Not Found", path)
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
		description    string
	}{
		{
			name:           "users route matches",
			path:           "/users/123",
			expectedStatus: http.StatusOK,
			description:    "users route should match prefix /users and return 200 OK",
		},
		{
			name:           "products route matches",
			path:           "/products/456",
			expectedStatus: http.StatusOK,
			description:    "products route should match prefix /products and return 200 OK",
		},
		{
			name:           "no route matches",
			path:           "/orders/789",
			expectedStatus: http.StatusNotFound,
			description:    "orders path should not match any route and return 404 Not Found",
		},
		{
			name:           "users root path matches",
			path:           "/users",
			expectedStatus: http.StatusOK,
			description:    "users root path should match prefix /users and return 200 OK",
		},
		{
			name:           "products root path matches",
			path:           "/products",
			expectedStatus: http.StatusOK,
			description:    "products root path should match prefix /products and return 200 OK",
		},
		{
			name:           "root path no match",
			path:           "/",
			expectedStatus: http.StatusNotFound,
			description:    "root path should not match any route and return 404 Not Found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Get(fmt.Sprintf("http://%s%s", addr, tt.path))
			require.NoError(t, err, "request to %s should not fail", tt.path)
			defer resp.Body.Close()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode, tt.description)
		})
	}

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}
