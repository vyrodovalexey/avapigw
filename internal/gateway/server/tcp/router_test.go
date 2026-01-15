// Package tcp provides the TCP server implementation for the API Gateway.
package tcp

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewRouter(t *testing.T) {
	t.Run("creates empty router", func(t *testing.T) {
		logger := zap.NewNop()

		router := NewRouter(logger)

		assert.NotNil(t, router)
		assert.Empty(t, router.routes)
		assert.NotNil(t, router.logger)
	})
}

func TestRouter_AddRoute(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		route       *TCPRoute
		expectError bool
		errorMsg    string
	}{
		{
			name: "adds route successfully",
			route: &TCPRoute{
				Name: "test-route",
				BackendRefs: []BackendRef{
					{Name: "backend1", Port: 8080},
				},
			},
			expectError: false,
		},
		{
			name: "sets default idle timeout",
			route: &TCPRoute{
				Name:        "route-no-idle-timeout",
				IdleTimeout: 0,
			},
			expectError: false,
		},
		{
			name: "sets default connect timeout",
			route: &TCPRoute{
				Name:           "route-no-connect-timeout",
				ConnectTimeout: 0,
			},
			expectError: false,
		},
		{
			name: "preserves custom timeouts",
			route: &TCPRoute{
				Name:           "route-custom-timeouts",
				IdleTimeout:    10 * time.Minute,
				ConnectTimeout: 1 * time.Minute,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(logger)

			err := router.AddRoute(tt.route)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Len(t, router.routes, 1)

				// Verify default timeouts are set
				if tt.route.IdleTimeout == 0 {
					assert.Equal(t, 5*time.Minute, router.routes[0].IdleTimeout)
				}
				if tt.route.ConnectTimeout == 0 {
					assert.Equal(t, 30*time.Second, router.routes[0].ConnectTimeout)
				}
			}
		})
	}

	t.Run("returns error for duplicate route", func(t *testing.T) {
		router := NewRouter(logger)
		route := &TCPRoute{Name: "duplicate-route"}

		err := router.AddRoute(route)
		require.NoError(t, err)

		err = router.AddRoute(route)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("sorts routes by priority", func(t *testing.T) {
		router := NewRouter(logger)

		router.AddRoute(&TCPRoute{Name: "low-priority", Priority: 1})
		router.AddRoute(&TCPRoute{Name: "high-priority", Priority: 10})
		router.AddRoute(&TCPRoute{Name: "medium-priority", Priority: 5})

		assert.Equal(t, "high-priority", router.routes[0].Name)
		assert.Equal(t, "medium-priority", router.routes[1].Name)
		assert.Equal(t, "low-priority", router.routes[2].Name)
	})

	t.Run("concurrent adds are safe", func(t *testing.T) {
		router := NewRouter(logger)
		var wg sync.WaitGroup

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				route := &TCPRoute{
					Name:     "route-" + string(rune('a'+i)),
					Priority: i,
				}
				router.AddRoute(route)
			}(i)
		}

		wg.Wait()
		// Some may fail due to duplicates, but should not panic
	})
}

func TestRouter_RemoveRoute(t *testing.T) {
	logger := zap.NewNop()

	t.Run("removes existing route", func(t *testing.T) {
		router := NewRouter(logger)
		route := &TCPRoute{Name: "test-route"}
		router.AddRoute(route)

		err := router.RemoveRoute("test-route")

		assert.NoError(t, err)
		assert.Empty(t, router.routes)
	})

	t.Run("returns error for non-existent route", func(t *testing.T) {
		router := NewRouter(logger)

		err := router.RemoveRoute("non-existent")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("removes correct route from multiple", func(t *testing.T) {
		router := NewRouter(logger)
		router.AddRoute(&TCPRoute{Name: "route1"})
		router.AddRoute(&TCPRoute{Name: "route2"})
		router.AddRoute(&TCPRoute{Name: "route3"})

		err := router.RemoveRoute("route2")

		assert.NoError(t, err)
		assert.Len(t, router.routes, 2)
		assert.Nil(t, router.GetRoute("route2"))
		assert.NotNil(t, router.GetRoute("route1"))
		assert.NotNil(t, router.GetRoute("route3"))
	})
}

func TestRouter_UpdateRoute(t *testing.T) {
	logger := zap.NewNop()

	t.Run("updates existing route", func(t *testing.T) {
		router := NewRouter(logger)
		originalRoute := &TCPRoute{
			Name:     "test-route",
			Priority: 1,
			BackendRefs: []BackendRef{
				{Name: "backend1", Port: 8080},
			},
		}
		router.AddRoute(originalRoute)

		updatedRoute := &TCPRoute{
			Name:     "test-route",
			Priority: 10,
			BackendRefs: []BackendRef{
				{Name: "backend2", Port: 9090},
			},
		}

		err := router.UpdateRoute(updatedRoute)

		assert.NoError(t, err)
		route := router.GetRoute("test-route")
		assert.Equal(t, 10, route.Priority)
		assert.Equal(t, "backend2", route.BackendRefs[0].Name)
	})

	t.Run("returns error for non-existent route", func(t *testing.T) {
		router := NewRouter(logger)

		err := router.UpdateRoute(&TCPRoute{Name: "non-existent"})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("sets default timeouts on update", func(t *testing.T) {
		router := NewRouter(logger)
		router.AddRoute(&TCPRoute{
			Name:           "test-route",
			IdleTimeout:    10 * time.Minute,
			ConnectTimeout: 1 * time.Minute,
		})

		err := router.UpdateRoute(&TCPRoute{
			Name:           "test-route",
			IdleTimeout:    0,
			ConnectTimeout: 0,
		})

		assert.NoError(t, err)
		route := router.GetRoute("test-route")
		assert.Equal(t, 5*time.Minute, route.IdleTimeout)
		assert.Equal(t, 30*time.Second, route.ConnectTimeout)
	})

	t.Run("re-sorts routes after update", func(t *testing.T) {
		router := NewRouter(logger)
		router.AddRoute(&TCPRoute{Name: "route1", Priority: 10})
		router.AddRoute(&TCPRoute{Name: "route2", Priority: 5})

		// Update route2 to have higher priority
		router.UpdateRoute(&TCPRoute{Name: "route2", Priority: 20})

		assert.Equal(t, "route2", router.routes[0].Name)
		assert.Equal(t, "route1", router.routes[1].Name)
	})
}

func TestRouter_Match(t *testing.T) {
	logger := zap.NewNop()

	t.Run("matches first route when routes exist", func(t *testing.T) {
		router := NewRouter(logger)
		router.AddRoute(&TCPRoute{Name: "route1", Priority: 10})
		router.AddRoute(&TCPRoute{Name: "route2", Priority: 5})

		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		route, err := router.Match(client)

		assert.NoError(t, err)
		assert.NotNil(t, route)
		assert.Equal(t, "route1", route.Name) // Highest priority
	})

	t.Run("returns error when no routes configured", func(t *testing.T) {
		router := NewRouter(logger)

		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		route, err := router.Match(client)

		assert.Error(t, err)
		assert.Nil(t, route)
		assert.Contains(t, err.Error(), "no routes configured")
	})
}

func TestRouter_MatchByPort(t *testing.T) {
	logger := zap.NewNop()

	t.Run("matches first route when routes exist", func(t *testing.T) {
		router := NewRouter(logger)
		router.AddRoute(&TCPRoute{Name: "route1", Priority: 10})

		route, err := router.MatchByPort(8080)

		assert.NoError(t, err)
		assert.NotNil(t, route)
		assert.Equal(t, "route1", route.Name)
	})

	t.Run("returns error when no routes configured", func(t *testing.T) {
		router := NewRouter(logger)

		route, err := router.MatchByPort(8080)

		assert.Error(t, err)
		assert.Nil(t, route)
		assert.Contains(t, err.Error(), "no routes configured")
	})
}

func TestRouter_GetRoute(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns existing route", func(t *testing.T) {
		router := NewRouter(logger)
		router.AddRoute(&TCPRoute{Name: "test-route", Priority: 5})

		route := router.GetRoute("test-route")

		assert.NotNil(t, route)
		assert.Equal(t, "test-route", route.Name)
		assert.Equal(t, 5, route.Priority)
	})

	t.Run("returns nil for non-existent route", func(t *testing.T) {
		router := NewRouter(logger)

		route := router.GetRoute("non-existent")

		assert.Nil(t, route)
	})
}

func TestRouter_ListRoutes(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns all route names", func(t *testing.T) {
		router := NewRouter(logger)
		router.AddRoute(&TCPRoute{Name: "route1"})
		router.AddRoute(&TCPRoute{Name: "route2"})
		router.AddRoute(&TCPRoute{Name: "route3"})

		names := router.ListRoutes()

		assert.Len(t, names, 3)
		assert.Contains(t, names, "route1")
		assert.Contains(t, names, "route2")
		assert.Contains(t, names, "route3")
	})

	t.Run("returns empty list when no routes", func(t *testing.T) {
		router := NewRouter(logger)

		names := router.ListRoutes()

		assert.Empty(t, names)
	})
}

func TestRouter_GetAllRoutes(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns copy of all routes", func(t *testing.T) {
		router := NewRouter(logger)
		router.AddRoute(&TCPRoute{Name: "route1", Priority: 10})
		router.AddRoute(&TCPRoute{Name: "route2", Priority: 5})

		routes := router.GetAllRoutes()

		assert.Len(t, routes, 2)
		// Verify it's a slice copy (not the same slice)
		// Note: The pointers still point to the same objects (shallow copy)
		originalLen := len(router.routes)
		routes = append(routes, &TCPRoute{Name: "route3"})
		assert.Equal(t, originalLen, len(router.routes)) // Original unchanged
	})

	t.Run("returns empty slice when no routes", func(t *testing.T) {
		router := NewRouter(logger)

		routes := router.GetAllRoutes()

		assert.Empty(t, routes)
	})
}

func TestRouter_Clear(t *testing.T) {
	logger := zap.NewNop()

	t.Run("removes all routes", func(t *testing.T) {
		router := NewRouter(logger)
		router.AddRoute(&TCPRoute{Name: "route1"})
		router.AddRoute(&TCPRoute{Name: "route2"})
		router.AddRoute(&TCPRoute{Name: "route3"})

		router.Clear()

		assert.Empty(t, router.routes)
		assert.Empty(t, router.ListRoutes())
	})

	t.Run("handles empty router", func(t *testing.T) {
		router := NewRouter(logger)

		// Should not panic
		router.Clear()

		assert.Empty(t, router.routes)
	})
}

func TestRouter_sortRoutes(t *testing.T) {
	logger := zap.NewNop()

	t.Run("sorts by priority descending", func(t *testing.T) {
		router := NewRouter(logger)
		router.routes = []*TCPRoute{
			{Name: "low", Priority: 1},
			{Name: "high", Priority: 100},
			{Name: "medium", Priority: 50},
		}

		router.sortRoutes()

		assert.Equal(t, "high", router.routes[0].Name)
		assert.Equal(t, "medium", router.routes[1].Name)
		assert.Equal(t, "low", router.routes[2].Name)
	})

	t.Run("handles equal priorities", func(t *testing.T) {
		router := NewRouter(logger)
		router.routes = []*TCPRoute{
			{Name: "route1", Priority: 5},
			{Name: "route2", Priority: 5},
			{Name: "route3", Priority: 5},
		}

		// Should not panic
		router.sortRoutes()

		assert.Len(t, router.routes, 3)
	})

	t.Run("handles single route", func(t *testing.T) {
		router := NewRouter(logger)
		router.routes = []*TCPRoute{
			{Name: "only", Priority: 1},
		}

		router.sortRoutes()

		assert.Len(t, router.routes, 1)
		assert.Equal(t, "only", router.routes[0].Name)
	})

	t.Run("handles empty routes", func(t *testing.T) {
		router := NewRouter(logger)
		router.routes = []*TCPRoute{}

		// Should not panic
		router.sortRoutes()

		assert.Empty(t, router.routes)
	})
}

func TestRouter_ConcurrentAccess(t *testing.T) {
	logger := zap.NewNop()
	router := NewRouter(logger)

	// Pre-populate with some routes
	for i := 0; i < 10; i++ {
		router.AddRoute(&TCPRoute{
			Name:     "initial-route-" + string(rune('a'+i)),
			Priority: i,
		})
	}

	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			router.ListRoutes()
			router.GetAllRoutes()
			router.GetRoute("initial-route-a")
		}()
	}

	// Concurrent writes
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			router.AddRoute(&TCPRoute{
				Name:     "concurrent-route-" + string(rune('A'+i)),
				Priority: i + 100,
			})
		}(i)
	}

	// Concurrent matches
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			router.Match(client)
		}()
	}

	wg.Wait()
	// Test passes if no race conditions or panics occur
}
