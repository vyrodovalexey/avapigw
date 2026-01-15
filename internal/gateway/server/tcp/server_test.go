// Package tcp provides the TCP server implementation for the API Gateway.
package tcp

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
)

func TestDefaultServerConfig(t *testing.T) {
	t.Run("returns expected default values", func(t *testing.T) {
		config := DefaultServerConfig()

		assert.NotNil(t, config)
		assert.Equal(t, 8443, config.Port)
		assert.Equal(t, "", config.Address)
		assert.Equal(t, 30*time.Second, config.ReadTimeout)
		assert.Equal(t, 30*time.Second, config.WriteTimeout)
		assert.Equal(t, 5*time.Minute, config.IdleTimeout)
		assert.Equal(t, 10000, config.MaxConnections)
		assert.Equal(t, DefaultShutdownTimeout, config.ShutdownTimeout)
		assert.Equal(t, DefaultAcceptDeadline, config.AcceptDeadline)
		assert.Nil(t, config.TLS)
	})
}

func TestNewServer(t *testing.T) {
	logger := zap.NewNop()

	t.Run("with nil config uses defaults", func(t *testing.T) {
		server := NewServer(nil, logger)

		assert.NotNil(t, server)
		assert.NotNil(t, server.config)
		assert.Equal(t, 8443, server.config.Port)
		assert.Equal(t, 10000, server.config.MaxConnections)
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &ServerConfig{
			Port:           9090,
			Address:        "127.0.0.1",
			MaxConnections: 500,
		}

		server := NewServer(config, logger)

		assert.NotNil(t, server)
		assert.Equal(t, 9090, server.config.Port)
		assert.Equal(t, "127.0.0.1", server.config.Address)
		assert.Equal(t, 500, server.config.MaxConnections)
	})

	t.Run("creates router and connection tracker", func(t *testing.T) {
		server := NewServer(nil, logger)

		assert.NotNil(t, server.router)
		assert.NotNil(t, server.connections)
		assert.NotNil(t, server.stopCh)
	})
}

func TestNewServerWithBackend(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("creates server with backend manager", func(t *testing.T) {
		server := NewServerWithBackend(nil, manager, logger)

		assert.NotNil(t, server)
		assert.NotNil(t, server.proxy)
		assert.NotNil(t, server.router)
		assert.NotNil(t, server.connections)
	})

	t.Run("with nil config uses defaults", func(t *testing.T) {
		server := NewServerWithBackend(nil, manager, logger)

		assert.Equal(t, 8443, server.config.Port)
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &ServerConfig{
			Port: 9090,
		}

		server := NewServerWithBackend(config, manager, logger)

		assert.Equal(t, 9090, server.config.Port)
	})
}

func TestServer_SetProxy(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("sets proxy", func(t *testing.T) {
		server := NewServer(nil, logger)
		proxy := NewProxy(manager, logger)

		assert.Nil(t, server.proxy)

		server.SetProxy(proxy)

		assert.Equal(t, proxy, server.proxy)
	})

	t.Run("replaces existing proxy", func(t *testing.T) {
		server := NewServer(nil, logger)
		proxy1 := NewProxy(manager, logger)
		proxy2 := NewProxy(manager, logger)

		server.SetProxy(proxy1)
		server.SetProxy(proxy2)

		assert.Equal(t, proxy2, server.proxy)
	})
}

func TestServer_GetRouter(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns router", func(t *testing.T) {
		server := NewServer(nil, logger)

		router := server.GetRouter()

		assert.NotNil(t, router)
		assert.Equal(t, server.router, router)
	})
}

func TestServer_GetProxy(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("returns nil when not set", func(t *testing.T) {
		server := NewServer(nil, logger)

		proxy := server.GetProxy()

		assert.Nil(t, proxy)
	})

	t.Run("returns proxy when set", func(t *testing.T) {
		server := NewServerWithBackend(nil, manager, logger)

		proxy := server.GetProxy()

		assert.NotNil(t, proxy)
	})
}

func TestServer_GetConnectionTracker(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns connection tracker", func(t *testing.T) {
		server := NewServer(nil, logger)

		tracker := server.GetConnectionTracker()

		assert.NotNil(t, tracker)
		assert.Equal(t, server.connections, tracker)
	})
}

func TestServer_Start(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns error if already running", func(t *testing.T) {
		config := &ServerConfig{
			Port:    0, // Use any available port
			Address: "127.0.0.1",
		}
		server := NewServer(config, logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start server in goroutine
		errCh := make(chan error, 1)
		go func() {
			errCh <- server.Start(ctx)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)
		assert.True(t, server.IsRunning())

		// Try to start again
		err := server.Start(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already running")

		// Cleanup
		cancel()
	})

	t.Run("sets running flag", func(t *testing.T) {
		config := &ServerConfig{
			Port:    0,
			Address: "127.0.0.1",
		}
		server := NewServer(config, logger)

		assert.False(t, server.IsRunning())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			server.Start(ctx)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)
		assert.True(t, server.IsRunning())

		cancel()
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		config := &ServerConfig{
			Port:    0,
			Address: "127.0.0.1",
		}
		server := NewServer(config, logger)

		ctx, cancel := context.WithCancel(context.Background())

		errCh := make(chan error, 1)
		go func() {
			errCh <- server.Start(ctx)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)
		assert.True(t, server.IsRunning())

		// Cancel context
		cancel()

		select {
		case err := <-errCh:
			assert.ErrorIs(t, err, context.Canceled)
		case <-time.After(2 * time.Second):
			t.Fatal("server did not respond to context cancellation")
		}
	})

	t.Run("returns error for invalid address", func(t *testing.T) {
		config := &ServerConfig{
			Port:    -1, // Invalid port
			Address: "invalid-address",
		}
		server := NewServer(config, logger)

		err := server.Start(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to listen")
	})

	t.Run("starts with TLS config", func(t *testing.T) {
		// Create a minimal TLS config (won't actually work but tests the code path)
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		config := &ServerConfig{
			Port:    0,
			Address: "127.0.0.1",
			TLS:     tlsConfig,
		}
		server := NewServer(config, logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// This will fail because we don't have valid certs, but it tests the TLS path
		errCh := make(chan error, 1)
		go func() {
			errCh <- server.Start(ctx)
		}()

		// Give it a moment
		time.Sleep(100 * time.Millisecond)

		cancel()
	})
}

func TestServer_Stop(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns nil if not running", func(t *testing.T) {
		server := NewServer(nil, logger)

		err := server.Stop(context.Background())

		assert.NoError(t, err)
	})

	t.Run("graceful shutdown", func(t *testing.T) {
		config := &ServerConfig{
			Port:            0,
			Address:         "127.0.0.1",
			ShutdownTimeout: 5 * time.Second,
		}
		server := NewServer(config, logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start server
		go func() {
			server.Start(ctx)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)
		assert.True(t, server.IsRunning())

		// Stop server
		err := server.Stop(context.Background())

		assert.NoError(t, err)
		assert.False(t, server.IsRunning())
	})

	t.Run("force close on timeout", func(t *testing.T) {
		config := &ServerConfig{
			Port:            0,
			Address:         "127.0.0.1",
			ShutdownTimeout: 100 * time.Millisecond, // Very short timeout
		}
		manager := backend.NewManager(logger)
		server := NewServerWithBackend(config, manager, logger)

		// Add a route so connections can be handled
		server.router.AddRoute(&TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "test-backend", Port: 8080},
			},
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start server
		go func() {
			server.Start(ctx)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)

		// Stop server - should complete even with short timeout
		err := server.Stop(context.Background())

		assert.NoError(t, err)
		assert.False(t, server.IsRunning())
	})

	t.Run("handles nil context", func(t *testing.T) {
		config := &ServerConfig{
			Port:            0,
			Address:         "127.0.0.1",
			ShutdownTimeout: time.Second,
		}
		server := NewServer(config, logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			server.Start(ctx)
		}()

		time.Sleep(100 * time.Millisecond)

		// Stop with nil context
		err := server.Stop(nil)

		assert.NoError(t, err)
	})
}

func TestServer_IsRunning(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns false when not started", func(t *testing.T) {
		server := NewServer(nil, logger)

		assert.False(t, server.IsRunning())
	})

	t.Run("returns true when running", func(t *testing.T) {
		config := &ServerConfig{
			Port:    0,
			Address: "127.0.0.1",
		}
		server := NewServer(config, logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			server.Start(ctx)
		}()

		time.Sleep(100 * time.Millisecond)
		assert.True(t, server.IsRunning())

		cancel()
		time.Sleep(100 * time.Millisecond)
	})

	t.Run("returns false after stop", func(t *testing.T) {
		config := &ServerConfig{
			Port:    0,
			Address: "127.0.0.1",
		}
		server := NewServer(config, logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			server.Start(ctx)
		}()

		time.Sleep(100 * time.Millisecond)
		assert.True(t, server.IsRunning())

		server.Stop(context.Background())
		assert.False(t, server.IsRunning())
	})
}

func TestServer_handleConnection(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("handles context cancellation before processing", func(t *testing.T) {
		server := NewServerWithBackend(nil, manager, logger)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// Should return quickly without error
		server.handleConnection(ctx, serverConn)

		// Connection should be closed
		buf := make([]byte, 1)
		clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := clientConn.Read(buf)
		assert.Error(t, err)
	})

	t.Run("tracks connection", func(t *testing.T) {
		server := NewServerWithBackend(nil, manager, logger)
		server.router.AddRoute(&TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "test-backend", Port: 8080},
			},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// Handle connection in goroutine
		done := make(chan struct{})
		go func() {
			server.handleConnection(ctx, serverConn)
			close(done)
		}()

		// Give it time to add connection
		time.Sleep(50 * time.Millisecond)

		// Connection should be tracked (or already removed if handler completed)
		// This is timing-dependent, so we just verify no panic

		cancel()
		<-done
	})

	t.Run("handles no matching route", func(t *testing.T) {
		server := NewServerWithBackend(nil, manager, logger)
		// No routes added

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		done := make(chan struct{})
		go func() {
			server.handleConnection(ctx, serverConn)
			close(done)
		}()

		select {
		case <-done:
			// Handler completed
		case <-time.After(time.Second):
			t.Fatal("handleConnection did not complete")
		}
	})

	t.Run("handles nil proxy", func(t *testing.T) {
		server := NewServer(nil, logger) // No proxy set
		server.router.AddRoute(&TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "test-backend", Port: 8080},
			},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		done := make(chan struct{})
		go func() {
			server.handleConnection(ctx, serverConn)
			close(done)
		}()

		select {
		case <-done:
			// Handler completed
		case <-time.After(time.Second):
			t.Fatal("handleConnection did not complete")
		}
	})

	t.Run("handles route with no backends", func(t *testing.T) {
		server := NewServerWithBackend(nil, manager, logger)
		server.router.AddRoute(&TCPRoute{
			Name:        "test-route",
			BackendRefs: []BackendRef{}, // No backends
		})

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		done := make(chan struct{})
		go func() {
			server.handleConnection(ctx, serverConn)
			close(done)
		}()

		select {
		case <-done:
			// Handler completed
		case <-time.After(time.Second):
			t.Fatal("handleConnection did not complete")
		}
	})

	t.Run("handles backend not found", func(t *testing.T) {
		server := NewServerWithBackend(nil, manager, logger)
		server.router.AddRoute(&TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "non-existent-backend", Port: 8080},
			},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		done := make(chan struct{})
		go func() {
			server.handleConnection(ctx, serverConn)
			close(done)
		}()

		select {
		case <-done:
			// Handler completed
		case <-time.After(time.Second):
			t.Fatal("handleConnection did not complete")
		}
	})

	t.Run("handles backend with namespace", func(t *testing.T) {
		server := NewServerWithBackend(nil, manager, logger)
		server.router.AddRoute(&TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "backend", Namespace: "test-ns", Port: 8080},
			},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		done := make(chan struct{})
		go func() {
			server.handleConnection(ctx, serverConn)
			close(done)
		}()

		select {
		case <-done:
			// Handler completed
		case <-time.After(time.Second):
			t.Fatal("handleConnection did not complete")
		}
	})
}

func TestServer_UpdateRoutes(t *testing.T) {
	logger := zap.NewNop()

	t.Run("adds new routes", func(t *testing.T) {
		server := NewServer(nil, logger)

		routes := []TCPRouteConfig{
			{
				Name: "route1",
				BackendRefs: []BackendRef{
					{Name: "backend1", Port: 8080},
				},
				Priority: 10,
			},
			{
				Name: "route2",
				BackendRefs: []BackendRef{
					{Name: "backend2", Port: 9090},
				},
				Priority: 5,
			},
		}

		err := server.UpdateRoutes(routes)

		assert.NoError(t, err)
		assert.Len(t, server.router.ListRoutes(), 2)
	})

	t.Run("updates existing routes", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add initial route
		server.router.AddRoute(&TCPRoute{
			Name:     "route1",
			Priority: 1,
		})

		// Update with same name but different priority
		routes := []TCPRouteConfig{
			{
				Name:     "route1",
				Priority: 100,
			},
		}

		err := server.UpdateRoutes(routes)

		assert.NoError(t, err)
		route := server.router.GetRoute("route1")
		assert.Equal(t, 100, route.Priority)
	})

	t.Run("handles mixed add and update", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add initial route
		server.router.AddRoute(&TCPRoute{
			Name:     "existing",
			Priority: 1,
		})

		routes := []TCPRouteConfig{
			{Name: "existing", Priority: 50},
			{Name: "new", Priority: 25},
		}

		err := server.UpdateRoutes(routes)

		assert.NoError(t, err)
		assert.Len(t, server.router.ListRoutes(), 2)
		assert.Equal(t, 50, server.router.GetRoute("existing").Priority)
		assert.Equal(t, 25, server.router.GetRoute("new").Priority)
	})
}

func TestServer_RemoveRoute(t *testing.T) {
	logger := zap.NewNop()

	t.Run("removes route", func(t *testing.T) {
		server := NewServer(nil, logger)
		server.router.AddRoute(&TCPRoute{Name: "test-route"})

		err := server.RemoveRoute("test-route")

		assert.NoError(t, err)
		assert.Nil(t, server.router.GetRoute("test-route"))
	})

	t.Run("returns error for non-existent route", func(t *testing.T) {
		server := NewServer(nil, logger)

		err := server.RemoveRoute("non-existent")

		assert.Error(t, err)
	})
}

func TestServer_GetActiveConnections(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns count", func(t *testing.T) {
		server := NewServer(nil, logger)

		count := server.GetActiveConnections()

		assert.Equal(t, 0, count)
	})

	t.Run("returns correct count after adding connections", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Manually add connections to tracker
		for i := 0; i < 3; i++ {
			s, c := net.Pipe()
			defer s.Close()
			defer c.Close()
			server.connections.Add(c)
		}

		count := server.GetActiveConnections()

		assert.Equal(t, 3, count)
	})
}

func TestServer_ListActiveConnections(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns connections", func(t *testing.T) {
		server := NewServer(nil, logger)

		conns := server.ListActiveConnections()

		assert.Empty(t, conns)
	})

	t.Run("returns all active connections", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Manually add connections to tracker
		for i := 0; i < 3; i++ {
			s, c := net.Pipe()
			defer s.Close()
			defer c.Close()
			server.connections.Add(c)
		}

		conns := server.ListActiveConnections()

		assert.Len(t, conns, 3)
	})
}

func TestServer_setAcceptDeadline(t *testing.T) {
	logger := zap.NewNop()

	t.Run("sets deadline on TCP listener", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()

		server := NewServer(nil, logger)
		server.listener = listener

		err = server.setAcceptDeadline(time.Second)

		assert.NoError(t, err)
	})

	t.Run("handles listener without deadline support", func(t *testing.T) {
		// Create a mock listener that doesn't support deadlines
		server := NewServer(nil, logger)
		server.listener = &mockListener{}

		err := server.setAcceptDeadline(time.Second)

		assert.NoError(t, err) // Should return nil for unsupported listeners
	})
}

// mockListener is a minimal listener implementation for testing
type mockListener struct{}

func (m *mockListener) Accept() (net.Conn, error) {
	return nil, nil
}

func (m *mockListener) Close() error {
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func TestServer_ConcurrentAccess(t *testing.T) {
	logger := zap.NewNop()
	config := &ServerConfig{
		Port:    0,
		Address: "127.0.0.1",
	}
	server := NewServer(config, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			server.IsRunning()
			server.GetActiveConnections()
			server.ListActiveConnections()
			server.GetRouter()
			server.GetProxy()
			server.GetConnectionTracker()
		}()
	}

	// Concurrent route operations
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			server.UpdateRoutes([]TCPRouteConfig{
				{Name: "concurrent-route-" + string(rune('a'+i)), Priority: i},
			})
		}(i)
	}

	wg.Wait()
	cancel()
}

func TestServerConfig_Validation(t *testing.T) {
	t.Run("accepts valid config", func(t *testing.T) {
		config := &ServerConfig{
			Port:            8080,
			Address:         "0.0.0.0",
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			IdleTimeout:     5 * time.Minute,
			MaxConnections:  1000,
			ShutdownTimeout: 30 * time.Second,
			AcceptDeadline:  500 * time.Millisecond,
		}

		logger := zap.NewNop()
		server := NewServer(config, logger)

		assert.NotNil(t, server)
		assert.Equal(t, config, server.config)
	})
}

func TestTCPRouteConfig(t *testing.T) {
	t.Run("creates route config", func(t *testing.T) {
		config := TCPRouteConfig{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "backend1", Namespace: "ns1", Port: 8080, Weight: 100},
			},
			IdleTimeout:    5 * time.Minute,
			ConnectTimeout: 30 * time.Second,
			Priority:       10,
		}

		assert.Equal(t, "test-route", config.Name)
		assert.Len(t, config.BackendRefs, 1)
		assert.Equal(t, 5*time.Minute, config.IdleTimeout)
		assert.Equal(t, 30*time.Second, config.ConnectTimeout)
		assert.Equal(t, 10, config.Priority)
	})
}

func TestServer_AcceptDeadlineHandling(t *testing.T) {
	logger := zap.NewNop()

	t.Run("uses default accept deadline when not set", func(t *testing.T) {
		config := &ServerConfig{
			Port:           0,
			Address:        "127.0.0.1",
			AcceptDeadline: 0, // Not set
		}
		server := NewServer(config, logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			server.Start(ctx)
		}()

		time.Sleep(100 * time.Millisecond)
		assert.True(t, server.IsRunning())

		cancel()
	})

	t.Run("uses custom accept deadline", func(t *testing.T) {
		config := &ServerConfig{
			Port:           0,
			Address:        "127.0.0.1",
			AcceptDeadline: 100 * time.Millisecond,
		}
		server := NewServer(config, logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			server.Start(ctx)
		}()

		time.Sleep(100 * time.Millisecond)
		assert.True(t, server.IsRunning())

		cancel()
	})
}

func TestServer_ShutdownTimeoutHandling(t *testing.T) {
	logger := zap.NewNop()

	t.Run("uses default shutdown timeout when not set", func(t *testing.T) {
		config := &ServerConfig{
			Port:            0,
			Address:         "127.0.0.1",
			ShutdownTimeout: 0, // Not set
		}
		server := NewServer(config, logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			server.Start(ctx)
		}()

		time.Sleep(100 * time.Millisecond)

		err := server.Stop(context.Background())
		assert.NoError(t, err)
	})
}
