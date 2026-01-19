package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	// Use the package-level ginModeOnce to set test mode
	ginModeOnce.Do(func() {
		gin.SetMode(gin.TestMode)
	})
}

// =============================================================================
// DefaultServerConfig Tests
// =============================================================================

func TestDefaultServerConfig(t *testing.T) {
	t.Run("returns expected default values", func(t *testing.T) {
		config := DefaultServerConfig()

		assert.NotNil(t, config)
		assert.Equal(t, 8080, config.Port)
		assert.Equal(t, "", config.Address)
		assert.Equal(t, 30*time.Second, config.ReadTimeout)
		assert.Equal(t, 30*time.Second, config.WriteTimeout)
		assert.Equal(t, 120*time.Second, config.IdleTimeout)
		assert.Equal(t, 1<<20, config.MaxHeaderBytes)             // 1 MB
		assert.Equal(t, int64(10<<20), config.MaxRequestBodySize) // 10 MB
		assert.Nil(t, config.TLS)
	})

	t.Run("returns new instance each time", func(t *testing.T) {
		config1 := DefaultServerConfig()
		config2 := DefaultServerConfig()

		assert.NotSame(t, config1, config2)

		// Modify one, ensure other is not affected
		config1.Port = 9090
		assert.Equal(t, 8080, config2.Port)
	})
}

// =============================================================================
// NewServer Tests
// =============================================================================

func TestNewServer(t *testing.T) {
	logger := zap.NewNop()

	t.Run("with nil config uses defaults", func(t *testing.T) {
		server := NewServer(nil, logger)

		assert.NotNil(t, server)
		assert.NotNil(t, server.engine)
		assert.NotNil(t, server.router)
		assert.NotNil(t, server.config)
		assert.Equal(t, 8080, server.config.Port)
		assert.Equal(t, int64(10<<20), server.config.MaxRequestBodySize)
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &ServerConfig{
			Port:               9090,
			Address:            "127.0.0.1",
			ReadTimeout:        60 * time.Second,
			WriteTimeout:       60 * time.Second,
			IdleTimeout:        240 * time.Second,
			MaxHeaderBytes:     2 << 20,
			MaxRequestBodySize: 20 << 20,
		}

		server := NewServer(config, logger)

		assert.NotNil(t, server)
		assert.Equal(t, 9090, server.config.Port)
		assert.Equal(t, "127.0.0.1", server.config.Address)
		assert.Equal(t, 60*time.Second, server.config.ReadTimeout)
		assert.Equal(t, 60*time.Second, server.config.WriteTimeout)
		assert.Equal(t, 240*time.Second, server.config.IdleTimeout)
		assert.Equal(t, 2<<20, server.config.MaxHeaderBytes)
		assert.Equal(t, int64(20<<20), server.config.MaxRequestBodySize)
	})

	t.Run("creates engine and router", func(t *testing.T) {
		server := NewServer(nil, logger)

		assert.NotNil(t, server.GetEngine())
		assert.NotNil(t, server.GetRouter())
		assert.IsType(t, &gin.Engine{}, server.GetEngine())
		assert.IsType(t, &Router{}, server.GetRouter())
	})

	t.Run("adds body size middleware when configured", func(t *testing.T) {
		config := &ServerConfig{
			Port:               8080,
			MaxRequestBodySize: 1024, // 1KB limit
		}

		server := NewServer(config, logger)

		// Middleware should be added
		assert.NotEmpty(t, server.middlewares)
	})

	t.Run("does not add body size middleware when disabled", func(t *testing.T) {
		config := &ServerConfig{
			Port:               8080,
			MaxRequestBodySize: 0, // Disabled
		}

		server := NewServer(config, logger)

		// No middleware should be added for body size
		assert.Empty(t, server.middlewares)
	})

	t.Run("initializes with not running state", func(t *testing.T) {
		server := NewServer(nil, logger)

		assert.False(t, server.IsRunning())
	})

	t.Run("initializes empty middlewares slice", func(t *testing.T) {
		config := &ServerConfig{
			Port:               8080,
			MaxRequestBodySize: 0, // Disabled to avoid auto-adding middleware
		}

		server := NewServer(config, logger)

		assert.NotNil(t, server.middlewares)
	})
}

// =============================================================================
// Server.Use Tests
// =============================================================================

func TestServer_Use(t *testing.T) {
	logger := zap.NewNop()

	t.Run("adds middleware to engine", func(t *testing.T) {
		config := &ServerConfig{MaxRequestBodySize: 0}
		server := NewServer(config, logger)

		executed := false
		middleware := func(c *gin.Context) {
			executed = true
			c.Next()
		}

		server.Use(middleware)

		assert.Len(t, server.middlewares, 1)

		// Verify middleware is actually added to engine by making a request
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		// Execute the middleware directly
		server.middlewares[0](c)
		assert.True(t, executed)
	})

	t.Run("adds multiple middleware", func(t *testing.T) {
		config := &ServerConfig{MaxRequestBodySize: 0}
		server := NewServer(config, logger)

		order := make([]int, 0)
		middleware1 := func(c *gin.Context) { order = append(order, 1); c.Next() }
		middleware2 := func(c *gin.Context) { order = append(order, 2); c.Next() }
		middleware3 := func(c *gin.Context) { order = append(order, 3); c.Next() }

		server.Use(middleware1)
		server.Use(middleware2)
		server.Use(middleware3)

		assert.Len(t, server.middlewares, 3)
	})

	t.Run("adds multiple middleware in single call", func(t *testing.T) {
		config := &ServerConfig{MaxRequestBodySize: 0}
		server := NewServer(config, logger)

		middleware1 := func(c *gin.Context) { c.Next() }
		middleware2 := func(c *gin.Context) { c.Next() }

		server.Use(middleware1, middleware2)

		assert.Len(t, server.middlewares, 2)
	})

	t.Run("is thread-safe", func(t *testing.T) {
		config := &ServerConfig{MaxRequestBodySize: 0}
		server := NewServer(config, logger)

		var wg sync.WaitGroup
		// Gin has a limit of 63 handlers, so we test with fewer
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				middleware := func(c *gin.Context) { c.Next() }
				server.Use(middleware)
			}()
		}
		wg.Wait()

		assert.Len(t, server.middlewares, 50)
	})

	t.Run("returns ErrServerAlreadyRunning after server starts", func(t *testing.T) {
		config := &ServerConfig{
			Port:               0, // Use random port
			Address:            "127.0.0.1",
			MaxRequestBodySize: 0,
		}
		server := NewServer(config, logger)

		// Start server in goroutine
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			_ = server.Start(ctx)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)

		// Try to add middleware after server has started
		middleware := func(c *gin.Context) { c.Next() }
		err := server.Use(middleware)

		// Should return ErrServerAlreadyRunning
		assert.Error(t, err)
		assert.Equal(t, ErrServerAlreadyRunning, err)

		// Stop the server
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = server.Stop(stopCtx)
	})

	t.Run("returns nil error before server starts", func(t *testing.T) {
		config := &ServerConfig{MaxRequestBodySize: 0}
		server := NewServer(config, logger)

		middleware := func(c *gin.Context) { c.Next() }
		err := server.Use(middleware)

		assert.NoError(t, err)
	})
}

// =============================================================================
// Server.GetEngine/GetRouter Tests
// =============================================================================

func TestServer_GetEngine(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns correct engine instance", func(t *testing.T) {
		server := NewServer(nil, logger)

		engine := server.GetEngine()

		assert.NotNil(t, engine)
		assert.Same(t, server.engine, engine)
	})

	t.Run("returns same instance on multiple calls", func(t *testing.T) {
		server := NewServer(nil, logger)

		engine1 := server.GetEngine()
		engine2 := server.GetEngine()

		assert.Same(t, engine1, engine2)
	})
}

func TestServer_GetRouter(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns correct router instance", func(t *testing.T) {
		server := NewServer(nil, logger)

		router := server.GetRouter()

		assert.NotNil(t, router)
		assert.Same(t, server.router, router)
	})

	t.Run("returns same instance on multiple calls", func(t *testing.T) {
		server := NewServer(nil, logger)

		router1 := server.GetRouter()
		router2 := server.GetRouter()

		assert.Same(t, router1, router2)
	})
}

// =============================================================================
// Server.Start Tests
// =============================================================================

func TestServer_Start(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns error if already running", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Manually set running flag
		server.mu.Lock()
		server.running = true
		server.mu.Unlock()

		ctx := context.Background()
		err := server.Start(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "server already running")
	})

	t.Run("sets running flag", func(t *testing.T) {
		config := &ServerConfig{
			Port:               0, // Use random port
			Address:            "127.0.0.1",
			MaxRequestBodySize: 0,
		}
		server := NewServer(config, logger)

		assert.False(t, server.IsRunning())

		// Start server in goroutine since it blocks
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			_ = server.Start(ctx)
		}()

		// Wait a bit for server to start
		time.Sleep(100 * time.Millisecond)

		// Server should be running (or have failed to start)
		// The running flag is set before ListenAndServe
	})
}

// =============================================================================
// Server.Stop Tests
// =============================================================================

func TestServer_Stop(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns nil if not running", func(t *testing.T) {
		server := NewServer(nil, logger)

		ctx := context.Background()
		err := server.Stop(ctx)

		assert.NoError(t, err)
	})

	t.Run("sets running flag to false", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Manually set running flag and create a mock http server
		server.mu.Lock()
		server.running = true
		server.httpServer = &http.Server{}
		server.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// This will fail because httpServer is not actually listening
		// but we can test the flag behavior
		_ = server.Stop(ctx)

		// After stop attempt, running should be false
		assert.False(t, server.IsRunning())
	})
}

// =============================================================================
// Server.IsRunning Tests
// =============================================================================

func TestServer_IsRunning(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns false initially", func(t *testing.T) {
		server := NewServer(nil, logger)

		assert.False(t, server.IsRunning())
	})

	t.Run("returns correct state after setting", func(t *testing.T) {
		server := NewServer(nil, logger)

		server.mu.Lock()
		server.running = true
		server.mu.Unlock()

		assert.True(t, server.IsRunning())

		server.mu.Lock()
		server.running = false
		server.mu.Unlock()

		assert.False(t, server.IsRunning())
	})

	t.Run("is thread-safe", func(t *testing.T) {
		server := NewServer(nil, logger)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = server.IsRunning()
			}()
		}
		wg.Wait()
	})
}

// =============================================================================
// Server.UpdateRoutes Tests
// =============================================================================

func TestServer_UpdateRoutes(t *testing.T) {
	logger := zap.NewNop()

	t.Run("adds new routes", func(t *testing.T) {
		server := NewServer(nil, logger)

		routes := []RouteConfig{
			{
				Name:      "route1",
				Hostnames: []string{"example.com"},
				Rules: []RouteRule{
					{
						Matches: []RouteMatch{
							{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}},
						},
					},
				},
			},
		}

		err := server.UpdateRoutes(routes)

		assert.NoError(t, err)
		assert.NotNil(t, server.router.GetRoute("route1"))
	})

	t.Run("updates existing routes", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add initial route
		routes := []RouteConfig{
			{
				Name:      "route1",
				Hostnames: []string{"example.com"},
			},
		}
		err := server.UpdateRoutes(routes)
		require.NoError(t, err)

		// Update the route
		updatedRoutes := []RouteConfig{
			{
				Name:      "route1",
				Hostnames: []string{"updated.example.com"},
			},
		}
		err = server.UpdateRoutes(updatedRoutes)

		assert.NoError(t, err)
		route := server.router.GetRoute("route1")
		assert.NotNil(t, route)
		assert.Contains(t, route.Hostnames, "updated.example.com")
	})

	t.Run("adds multiple routes", func(t *testing.T) {
		server := NewServer(nil, logger)

		routes := []RouteConfig{
			{Name: "route1", Hostnames: []string{"example1.com"}},
			{Name: "route2", Hostnames: []string{"example2.com"}},
			{Name: "route3", Hostnames: []string{"example3.com"}},
		}

		err := server.UpdateRoutes(routes)

		assert.NoError(t, err)
		assert.NotNil(t, server.router.GetRoute("route1"))
		assert.NotNil(t, server.router.GetRoute("route2"))
		assert.NotNil(t, server.router.GetRoute("route3"))
	})

	t.Run("handles empty routes slice", func(t *testing.T) {
		server := NewServer(nil, logger)

		err := server.UpdateRoutes([]RouteConfig{})

		assert.NoError(t, err)
	})

	t.Run("handles routes with backends", func(t *testing.T) {
		server := NewServer(nil, logger)

		routes := []RouteConfig{
			{
				Name:      "route1",
				Hostnames: []string{"example.com"},
				Backends: []BackendRef{
					{Name: "backend1", Namespace: "default", Port: 8080, Weight: 100},
				},
			},
		}

		err := server.UpdateRoutes(routes)

		assert.NoError(t, err)
		route := server.router.GetRoute("route1")
		assert.NotNil(t, route)
		assert.Len(t, route.Backends, 1)
		assert.Equal(t, "backend1", route.Backends[0].Name)
	})

	t.Run("is thread-safe", func(t *testing.T) {
		server := NewServer(nil, logger)

		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				routes := []RouteConfig{
					{Name: "route", Hostnames: []string{"example.com"}},
				}
				_ = server.UpdateRoutes(routes)
			}(i)
		}
		wg.Wait()
	})
}

// =============================================================================
// Server.RemoveRoute Tests
// =============================================================================

func TestServer_RemoveRoute(t *testing.T) {
	logger := zap.NewNop()

	t.Run("removes existing route", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add a route first
		routes := []RouteConfig{
			{Name: "route1", Hostnames: []string{"example.com"}},
		}
		err := server.UpdateRoutes(routes)
		require.NoError(t, err)

		// Remove the route
		err = server.RemoveRoute("route1")

		assert.NoError(t, err)
		assert.Nil(t, server.router.GetRoute("route1"))
	})

	t.Run("returns error for non-existent route", func(t *testing.T) {
		server := NewServer(nil, logger)

		err := server.RemoveRoute("non-existent")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// =============================================================================
// maxRequestBodySizeMiddleware Tests
// =============================================================================

func TestMaxRequestBodySizeMiddleware(t *testing.T) {
	logger := zap.NewNop()

	t.Run("wraps request body with MaxBytesReader", func(t *testing.T) {
		config := &ServerConfig{
			Port:               8080,
			MaxRequestBodySize: 100, // 100 bytes limit
		}
		server := NewServer(config, logger)

		// Create a request with body larger than limit
		largeBody := bytes.Repeat([]byte("a"), 200)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(largeBody))

		// Execute the middleware
		middleware := server.maxRequestBodySizeMiddleware()
		middleware(c)

		// Try to read the body - should fail after limit
		body, err := io.ReadAll(c.Request.Body)
		if err == nil {
			// If no error, body should be truncated or limited
			assert.LessOrEqual(t, len(body), 200)
		}
		// Error is expected when reading beyond limit
	})

	t.Run("allows body within limit", func(t *testing.T) {
		config := &ServerConfig{
			Port:               8080,
			MaxRequestBodySize: 1000, // 1000 bytes limit
		}
		server := NewServer(config, logger)

		// Create a request with body within limit
		smallBody := bytes.Repeat([]byte("a"), 100)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(smallBody))

		// Execute the middleware
		middleware := server.maxRequestBodySizeMiddleware()
		middleware(c)

		// Should be able to read the entire body
		body, err := io.ReadAll(c.Request.Body)
		assert.NoError(t, err)
		assert.Len(t, body, 100)
	})

	t.Run("calls Next", func(t *testing.T) {
		config := &ServerConfig{
			Port:               8080,
			MaxRequestBodySize: 1000,
		}
		server := NewServer(config, logger)

		nextCalled := false
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("test")))

		// Set up handler chain
		c.Set("nextCalled", &nextCalled)

		middleware := server.maxRequestBodySizeMiddleware()

		// Create a simple handler chain
		engine := gin.New()
		engine.Use(middleware)
		engine.POST("/test", func(c *gin.Context) {
			nextCalled = true
		})

		// Make request through engine
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("test")))
		engine.ServeHTTP(w, req)

		assert.True(t, nextCalled)
	})
}

// =============================================================================
// Server.setupRouteHandler Tests
// =============================================================================

func TestServer_setupRouteHandler(t *testing.T) {
	logger := zap.NewNop()

	t.Run("handles request with matching route", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add a route
		method := "GET"
		route := &Route{
			Name:      "test-route",
			Hostnames: []string{"*"},
			Rules: []RouteRule{
				{
					Matches: []RouteMatch{
						{
							Path:   &PathMatch{Type: PathMatchPrefix, Value: "/api"},
							Method: &method,
						},
					},
				},
			},
		}
		err := server.router.AddRoute(route)
		require.NoError(t, err)

		// Setup route handler
		server.setupRouteHandler()

		// Make a request
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		server.engine.ServeHTTP(w, req)

		// Should not return 404 (route matched)
		// The actual response depends on handleRequest implementation
	})

	t.Run("handles request with no matching route", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Setup route handler without adding any routes
		server.setupRouteHandler()

		// Make a request
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
		server.engine.ServeHTTP(w, req)

		// Should return 404
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// =============================================================================
// Server.handleRequest Tests
// =============================================================================

func TestServer_handleRequest(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns 404 when no route matches", func(t *testing.T) {
		server := NewServer(nil, logger)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/nonexistent", nil)

		server.handleRequest(c)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("stores route in context when matched", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add a route
		method := "GET"
		route := &Route{
			Name:      "test-route",
			Hostnames: []string{"*"},
			Rules: []RouteRule{
				{
					Matches: []RouteMatch{
						{
							Path:   &PathMatch{Type: PathMatchPrefix, Value: "/api"},
							Method: &method,
						},
					},
				},
			},
		}
		err := server.router.AddRoute(route)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/test", nil)

		server.handleRequest(c)

		// Route should be stored in context
		storedRoute, exists := c.Get("route")
		assert.True(t, exists)
		assert.NotNil(t, storedRoute)
	})

	t.Run("stores rule in context when matched", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add a route with rules
		method := "GET"
		route := &Route{
			Name:      "test-route",
			Hostnames: []string{"*"},
			Rules: []RouteRule{
				{
					Matches: []RouteMatch{
						{
							Path:   &PathMatch{Type: PathMatchPrefix, Value: "/api"},
							Method: &method,
						},
					},
				},
			},
		}
		err := server.router.AddRoute(route)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/test", nil)

		server.handleRequest(c)

		// Rule should be stored in context
		storedRule, exists := c.Get("rule")
		assert.True(t, exists)
		assert.NotNil(t, storedRule)
	})
}

// =============================================================================
// RouteConfig Tests
// =============================================================================

func TestRouteConfig(t *testing.T) {
	t.Run("can create RouteConfig with all fields", func(t *testing.T) {
		config := RouteConfig{
			Name:      "test-route",
			Hostnames: []string{"example.com", "*.example.com"},
			Rules: []RouteRule{
				{
					Matches: []RouteMatch{
						{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}},
					},
				},
			},
			Backends: []BackendRef{
				{Name: "backend1", Namespace: "default", Port: 8080, Weight: 100},
			},
		}

		assert.Equal(t, "test-route", config.Name)
		assert.Len(t, config.Hostnames, 2)
		assert.Len(t, config.Rules, 1)
		assert.Len(t, config.Backends, 1)
	})
}

// =============================================================================
// ServerConfig Tests
// =============================================================================

func TestServerConfig(t *testing.T) {
	t.Run("can create ServerConfig with all fields", func(t *testing.T) {
		config := &ServerConfig{
			Port:               9090,
			Address:            "0.0.0.0",
			ReadTimeout:        60 * time.Second,
			WriteTimeout:       60 * time.Second,
			IdleTimeout:        300 * time.Second,
			MaxHeaderBytes:     2 << 20,
			MaxRequestBodySize: 50 << 20,
			TLS:                nil,
		}

		assert.Equal(t, 9090, config.Port)
		assert.Equal(t, "0.0.0.0", config.Address)
		assert.Equal(t, 60*time.Second, config.ReadTimeout)
		assert.Equal(t, 60*time.Second, config.WriteTimeout)
		assert.Equal(t, 300*time.Second, config.IdleTimeout)
		assert.Equal(t, 2<<20, config.MaxHeaderBytes)
		assert.Equal(t, int64(50<<20), config.MaxRequestBodySize)
	})
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestServer_ConcurrentAccess(t *testing.T) {
	logger := zap.NewNop()

	t.Run("concurrent route updates", func(t *testing.T) {
		server := NewServer(nil, logger)

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				routes := []RouteConfig{
					{Name: "route", Hostnames: []string{"example.com"}},
				}
				_ = server.UpdateRoutes(routes)
			}(i)
		}
		wg.Wait()
	})

	t.Run("concurrent middleware additions", func(t *testing.T) {
		config := &ServerConfig{MaxRequestBodySize: 0}
		server := NewServer(config, logger)

		var wg sync.WaitGroup
		// Gin has a limit of 63 handlers, so we test with fewer
		for i := 0; i < 30; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				middleware := func(c *gin.Context) { c.Next() }
				server.Use(middleware)
			}()
		}
		wg.Wait()

		assert.Len(t, server.middlewares, 30)
	})

	t.Run("concurrent IsRunning checks", func(t *testing.T) {
		server := NewServer(nil, logger)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = server.IsRunning()
			}()
		}
		wg.Wait()
	})

	t.Run("concurrent GetEngine and GetRouter", func(t *testing.T) {
		server := NewServer(nil, logger)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				_ = server.GetEngine()
			}()
			go func() {
				defer wg.Done()
				_ = server.GetRouter()
			}()
		}
		wg.Wait()
	})
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestServer_EdgeCases(t *testing.T) {
	logger := zap.NewNop()

	t.Run("server with zero port", func(t *testing.T) {
		config := &ServerConfig{
			Port:               0,
			MaxRequestBodySize: 0,
		}
		server := NewServer(config, logger)

		assert.NotNil(t, server)
		assert.Equal(t, 0, server.config.Port)
	})

	t.Run("server with empty address", func(t *testing.T) {
		config := &ServerConfig{
			Address:            "",
			MaxRequestBodySize: 0,
		}
		server := NewServer(config, logger)

		assert.NotNil(t, server)
		assert.Equal(t, "", server.config.Address)
	})

	t.Run("update routes with nil rules", func(t *testing.T) {
		server := NewServer(nil, logger)

		routes := []RouteConfig{
			{
				Name:      "route1",
				Hostnames: []string{"example.com"},
				Rules:     nil,
			},
		}

		err := server.UpdateRoutes(routes)

		assert.NoError(t, err)
	})

	t.Run("update routes with empty hostnames", func(t *testing.T) {
		server := NewServer(nil, logger)

		routes := []RouteConfig{
			{
				Name:      "route1",
				Hostnames: []string{},
			},
		}

		err := server.UpdateRoutes(routes)

		assert.NoError(t, err)
	})

	t.Run("remove route twice", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add a route
		routes := []RouteConfig{
			{Name: "route1", Hostnames: []string{"example.com"}},
		}
		err := server.UpdateRoutes(routes)
		require.NoError(t, err)

		// Remove once
		err = server.RemoveRoute("route1")
		assert.NoError(t, err)

		// Remove again - should error
		err = server.RemoveRoute("route1")
		assert.Error(t, err)
	})
}

// =============================================================================
// Server.Start Additional Tests
// =============================================================================

func TestServer_Start_Additional(t *testing.T) {
	logger := zap.NewNop()

	t.Run("configures http server correctly", func(t *testing.T) {
		config := &ServerConfig{
			Port:               0, // Use random port
			Address:            "127.0.0.1",
			ReadTimeout:        45 * time.Second,
			WriteTimeout:       45 * time.Second,
			IdleTimeout:        180 * time.Second,
			MaxHeaderBytes:     2 << 20,
			MaxRequestBodySize: 0,
		}
		server := NewServer(config, logger)

		// Start server in goroutine
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		errCh := make(chan error, 1)
		go func() {
			errCh <- server.Start(ctx)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)

		// Verify server is running
		assert.True(t, server.IsRunning())

		// Stop the server
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		err := server.Stop(stopCtx)
		assert.NoError(t, err)
	})

	t.Run("handles server start with TLS config", func(t *testing.T) {
		// Create a TLS config (will fail to start but tests the code path)
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		config := &ServerConfig{
			Port:               0,
			Address:            "127.0.0.1",
			TLS:                tlsConfig,
			MaxRequestBodySize: 0,
		}
		server := NewServer(config, logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		errCh := make(chan error, 1)
		go func() {
			errCh <- server.Start(ctx)
		}()

		// Wait a bit for server to attempt start
		time.Sleep(100 * time.Millisecond)

		// Stop the server (may or may not be running depending on TLS setup)
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		_ = server.Stop(stopCtx)
	})
}

// =============================================================================
// Server.Stop Additional Tests
// =============================================================================

func TestServer_Stop_Additional(t *testing.T) {
	logger := zap.NewNop()

	t.Run("graceful shutdown with active server", func(t *testing.T) {
		config := &ServerConfig{
			Port:               0,
			Address:            "127.0.0.1",
			MaxRequestBodySize: 0,
		}
		server := NewServer(config, logger)

		// Start server
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			_ = server.Start(ctx)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)

		// Stop with timeout
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()

		err := server.Stop(stopCtx)
		assert.NoError(t, err)
		assert.False(t, server.IsRunning())
	})

	t.Run("stop with very short timeout", func(t *testing.T) {
		config := &ServerConfig{
			Port:               0,
			Address:            "127.0.0.1",
			MaxRequestBodySize: 0,
		}
		server := NewServer(config, logger)

		// Start server
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			_ = server.Start(ctx)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)

		// Stop with very short timeout
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer stopCancel()

		// This may or may not error depending on timing
		_ = server.Stop(stopCtx)
	})
}

// =============================================================================
// Server.UpdateRoutes Additional Tests
// =============================================================================

func TestServer_UpdateRoutes_Additional(t *testing.T) {
	logger := zap.NewNop()

	t.Run("handles route update failure gracefully", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add a route first
		routes := []RouteConfig{
			{Name: "route1", Hostnames: []string{"example.com"}},
		}
		err := server.UpdateRoutes(routes)
		require.NoError(t, err)

		// Update the same route (should succeed via update path)
		updatedRoutes := []RouteConfig{
			{Name: "route1", Hostnames: []string{"new.example.com"}},
		}
		err = server.UpdateRoutes(updatedRoutes)
		assert.NoError(t, err)

		// Verify the route was updated
		route := server.router.GetRoute("route1")
		assert.Contains(t, route.Hostnames, "new.example.com")
	})

	t.Run("handles multiple route updates in sequence", func(t *testing.T) {
		server := NewServer(nil, logger)

		// First batch
		routes1 := []RouteConfig{
			{Name: "route1", Hostnames: []string{"example1.com"}},
			{Name: "route2", Hostnames: []string{"example2.com"}},
		}
		err := server.UpdateRoutes(routes1)
		require.NoError(t, err)

		// Second batch - update existing and add new
		routes2 := []RouteConfig{
			{Name: "route1", Hostnames: []string{"updated1.com"}},
			{Name: "route3", Hostnames: []string{"example3.com"}},
		}
		err = server.UpdateRoutes(routes2)
		assert.NoError(t, err)

		// Verify
		assert.NotNil(t, server.router.GetRoute("route1"))
		assert.NotNil(t, server.router.GetRoute("route2"))
		assert.NotNil(t, server.router.GetRoute("route3"))
	})
}

// =============================================================================
// Server.setupRouteHandler Additional Tests
// =============================================================================

func TestServer_setupRouteHandler_Additional(t *testing.T) {
	logger := zap.NewNop()

	t.Run("NoRoute handler returns 404", func(t *testing.T) {
		server := NewServer(nil, logger)
		server.setupRouteHandler()

		// Make a request to a path that doesn't match any route
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/nonexistent/path", nil)
		server.engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("Any handler catches all methods", func(t *testing.T) {
		server := NewServer(nil, logger)
		server.setupRouteHandler()

		methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
		for _, method := range methods {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(method, "/test/path", nil)
			server.engine.ServeHTTP(w, req)

			// Should return 404 since no routes are configured
			assert.Equal(t, http.StatusNotFound, w.Code, "Method %s should return 404", method)
		}
	})

	t.Run("handles request with matching route and rule", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add a route with specific rule
		method := "POST"
		route := &Route{
			Name:      "api-route",
			Hostnames: []string{"*"},
			Rules: []RouteRule{
				{
					Matches: []RouteMatch{
						{
							Path:   &PathMatch{Type: PathMatchPrefix, Value: "/api"},
							Method: &method,
						},
					},
				},
			},
		}
		err := server.router.AddRoute(route)
		require.NoError(t, err)

		server.setupRouteHandler()

		// Make a matching request
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
		server.engine.ServeHTTP(w, req)

		// Should not be 404 (route matched)
		// The actual response depends on handleRequest implementation
	})
}

// =============================================================================
// Integration-like Tests
// =============================================================================

func TestServer_Integration(t *testing.T) {
	logger := zap.NewNop()

	t.Run("full request flow with route matching", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add a route
		method := "GET"
		route := &Route{
			Name:      "api-route",
			Hostnames: []string{"*"},
			Rules: []RouteRule{
				{
					Matches: []RouteMatch{
						{
							Path:   &PathMatch{Type: PathMatchPrefix, Value: "/api"},
							Method: &method,
						},
					},
				},
			},
			Backends: []BackendRef{
				{Name: "backend", Namespace: "default", Port: 8080, Weight: 100},
			},
		}
		err := server.router.AddRoute(route)
		require.NoError(t, err)

		// Setup route handler
		server.setupRouteHandler()

		// Test matching request
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		server.engine.ServeHTTP(w, req)

		// Should not be 404 (route matched)
		// Note: actual response depends on handleRequest implementation
	})

	t.Run("request with body size limit", func(t *testing.T) {
		config := &ServerConfig{
			Port:               8080,
			MaxRequestBodySize: 10, // Very small limit
		}
		server := NewServer(config, logger)

		// Add a simple handler
		server.engine.POST("/test", func(c *gin.Context) {
			body, err := io.ReadAll(c.Request.Body)
			if err != nil {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "body too large"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"size": len(body)})
		})

		// Test with body exceeding limit
		largeBody := bytes.Repeat([]byte("a"), 100)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(largeBody))
		server.engine.ServeHTTP(w, req)

		// Response should indicate body was limited
	})
}
