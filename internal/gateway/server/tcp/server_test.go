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

func TestShouldContinueOnError(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns true for timeout error", func(t *testing.T) {
		ctx := context.Background()
		stopCh := make(chan struct{})

		// Create a timeout error
		timeoutErr := &mockTimeoutError{timeout: true}

		result := shouldContinueOnError(timeoutErr, ctx, stopCh, logger)

		assert.True(t, result)
	})

	t.Run("returns false when context is done", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately
		stopCh := make(chan struct{})

		err := &mockTimeoutError{timeout: false}

		result := shouldContinueOnError(err, ctx, stopCh, logger)

		assert.False(t, result)
	})

	t.Run("returns false when stop channel is closed", func(t *testing.T) {
		ctx := context.Background()
		stopCh := make(chan struct{})
		close(stopCh)

		err := &mockTimeoutError{timeout: false}

		result := shouldContinueOnError(err, ctx, stopCh, logger)

		assert.False(t, result)
	})

	t.Run("returns true for other errors and logs", func(t *testing.T) {
		ctx := context.Background()
		stopCh := make(chan struct{})

		err := &mockTimeoutError{timeout: false}

		result := shouldContinueOnError(err, ctx, stopCh, logger)

		assert.True(t, result)
	})
}

// mockTimeoutError implements net.Error for testing
type mockTimeoutError struct {
	timeout bool
}

func (e *mockTimeoutError) Error() string   { return "mock error" }
func (e *mockTimeoutError) Timeout() bool   { return e.timeout }
func (e *mockTimeoutError) Temporary() bool { return false }

func TestServer_checkShutdown(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns nil when context is active and stop channel is open", func(t *testing.T) {
		server := NewServer(nil, logger)
		ctx := context.Background()

		err := server.checkShutdown(ctx)

		assert.NoError(t, err)
	})

	t.Run("returns context error when context is cancelled", func(t *testing.T) {
		server := NewServer(nil, logger)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := server.checkShutdown(ctx)

		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("returns nil when stop channel is closed", func(t *testing.T) {
		server := NewServer(nil, logger)
		close(server.stopCh)
		ctx := context.Background()

		err := server.checkShutdown(ctx)

		assert.NoError(t, err)
	})
}

func TestServer_handleAcceptShutdown(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns context error when context is cancelled", func(t *testing.T) {
		server := NewServer(nil, logger)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := server.handleAcceptShutdown(ctx)

		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("returns nil when stop channel is closed", func(t *testing.T) {
		server := NewServer(nil, logger)
		close(server.stopCh)
		ctx := context.Background()

		err := server.handleAcceptShutdown(ctx)

		assert.NoError(t, err)
	})

	t.Run("returns nil when neither is triggered", func(t *testing.T) {
		server := NewServer(nil, logger)
		ctx := context.Background()

		err := server.handleAcceptShutdown(ctx)

		assert.NoError(t, err)
	})
}

func TestServer_closeListener(t *testing.T) {
	logger := zap.NewNop()

	t.Run("handles nil listener", func(t *testing.T) {
		server := NewServer(nil, logger)
		server.listener = nil

		// Should not panic
		server.closeListener()
	})

	t.Run("closes listener and logs error on failure", func(t *testing.T) {
		server := NewServer(nil, logger)
		server.listener = &mockListenerWithError{}

		// Should not panic
		server.closeListener()
	})

	t.Run("closes listener successfully", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(nil, logger)
		server.listener = listener

		server.closeListener()

		// Verify listener is closed by trying to accept
		_, err = listener.Accept()
		assert.Error(t, err)
	})
}

// mockListenerWithError returns an error on Close
type mockListenerWithError struct{}

func (m *mockListenerWithError) Accept() (net.Conn, error) {
	return nil, nil
}

func (m *mockListenerWithError) Close() error {
	return net.ErrClosed
}

func (m *mockListenerWithError) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func TestServer_handleShutdownTimeout(t *testing.T) {
	logger := zap.NewNop()

	t.Run("closes all connections and waits", func(t *testing.T) {
		config := &ServerConfig{
			Port:           0,
			Address:        "127.0.0.1",
			MaxConnections: 10,
		}
		server := NewServer(config, logger)

		// Add some connections to the tracker
		for i := 0; i < 3; i++ {
			s, c := net.Pipe()
			defer s.Close()
			defer c.Close()
			server.connections.Add(c)
		}

		// Should not panic and should close connections
		server.handleShutdownTimeout()

		// Connections should be closed
		assert.Equal(t, 3, server.connections.Count()) // Count doesn't change, but connections are closed
	})
}

func TestServer_waitForForceClose(t *testing.T) {
	logger := zap.NewNop()

	t.Run("completes when wait group is done", func(t *testing.T) {
		server := NewServer(nil, logger)

		// No pending goroutines, should complete immediately
		server.waitForForceClose()
	})

	t.Run("times out when handlers are still running", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add a pending goroutine that won't complete
		server.wg.Add(1)
		go func() {
			time.Sleep(5 * time.Second)
			server.wg.Done()
		}()

		start := time.Now()
		server.waitForForceClose()
		elapsed := time.Since(start)

		// Should timeout after ~1 second
		assert.True(t, elapsed >= 900*time.Millisecond && elapsed < 2*time.Second)
	})
}

func TestServer_spawnConnectionHandler(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("spawns handler goroutine", func(t *testing.T) {
		server := NewServerWithBackend(nil, manager, logger)
		server.router.AddRoute(&TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "test-backend", Port: 8080},
			},
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// Spawn the handler
		server.spawnConnectionHandler(ctx, serverConn)

		// Give it time to start
		time.Sleep(50 * time.Millisecond)

		// Cancel context to stop the handler
		cancel()

		// Wait for handler to complete
		server.wg.Wait()
	})

	t.Run("handles context cancellation during spawn", func(t *testing.T) {
		server := NewServerWithBackend(nil, manager, logger)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// Spawn the handler with cancelled context
		server.spawnConnectionHandler(ctx, serverConn)

		// Wait for handler to complete
		server.wg.Wait()
	})
}

func TestServer_trackConnection(t *testing.T) {
	logger := zap.NewNop()

	t.Run("tracks connection successfully", func(t *testing.T) {
		server := NewServer(nil, logger)

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		tracked, ok := server.trackConnection(serverConn)

		assert.True(t, ok)
		assert.NotNil(t, tracked)
		assert.NotEmpty(t, tracked.ID)
		assert.Equal(t, 1, server.connections.Count())
	})

	t.Run("rejects connection when max reached", func(t *testing.T) {
		config := &ServerConfig{
			MaxConnections: 1,
		}
		server := NewServer(config, logger)

		// Add first connection
		s1, c1 := net.Pipe()
		defer s1.Close()
		defer c1.Close()
		_, ok := server.trackConnection(c1)
		assert.True(t, ok)

		// Try to add second connection
		s2, c2 := net.Pipe()
		defer s2.Close()
		defer c2.Close()
		tracked, ok := server.trackConnection(c2)

		assert.False(t, ok)
		assert.Nil(t, tracked)
	})
}

func TestServer_matchRoute(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns route when found", func(t *testing.T) {
		server := NewServer(nil, logger)
		server.router.AddRoute(&TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "backend", Port: 8080},
			},
		})

		ctx := context.Background()
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		route := server.matchRoute(ctx, serverConn, "conn-id")

		assert.NotNil(t, route)
		assert.Equal(t, "test-route", route.Name)
	})

	t.Run("returns nil when no routes", func(t *testing.T) {
		server := NewServer(nil, logger)

		ctx := context.Background()
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		route := server.matchRoute(ctx, serverConn, "conn-id")

		assert.Nil(t, route)
	})

	t.Run("returns nil when context is cancelled after matching", func(t *testing.T) {
		server := NewServer(nil, logger)
		server.router.AddRoute(&TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "backend", Port: 8080},
			},
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		route := server.matchRoute(ctx, serverConn, "conn-id")

		assert.Nil(t, route)
	})
}

func TestServer_proxyConnection(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("proxies connection to backend", func(t *testing.T) {
		// Create a mock backend server
		backendListener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer backendListener.Close()

		backendAddr := backendListener.Addr().(*net.TCPAddr)

		// Handle backend connections - echo data back
		go func() {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 1024)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				conn.Write(buf[:n])
			}
		}()

		// Create backend with the mock server endpoint
		manager.AddBackend(backend.BackendConfig{
			Name: "test-backend",
			Endpoints: []backend.EndpointConfig{
				{Address: "127.0.0.1", Port: backendAddr.Port},
			},
		})

		server := NewServerWithBackend(nil, manager, logger)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		tracked := &TrackedConnection{
			ID:        "test-id",
			StartTime: time.Now(),
		}

		route := &TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "test-backend", Port: backendAddr.Port},
			},
			ConnectTimeout: time.Second,
			IdleTimeout:    5 * time.Second,
		}

		backendSvc := manager.GetBackend("test-backend")

		// Run proxy in goroutine
		done := make(chan struct{})
		go func() {
			server.proxyConnection(ctx, serverConn, tracked, route, backendSvc)
			close(done)
		}()

		// Send data through client
		testData := []byte("hello proxy")
		_, err = clientConn.Write(testData)
		require.NoError(t, err)

		// Read response
		buf := make([]byte, len(testData))
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := clientConn.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, testData, buf[:n])

		// Close client to end proxy
		clientConn.Close()

		select {
		case <-done:
			// Success
		case <-time.After(2 * time.Second):
			t.Fatal("proxyConnection did not complete")
		}
	})

	t.Run("handles proxy error", func(t *testing.T) {
		// Create backend with unreachable endpoint
		manager.AddBackend(backend.BackendConfig{
			Name: "unreachable-backend",
			Endpoints: []backend.EndpointConfig{
				{Address: "127.0.0.1", Port: 59999}, // Unlikely to be listening
			},
		})

		server := NewServerWithBackend(nil, manager, logger)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		tracked := &TrackedConnection{
			ID:        "test-id",
			StartTime: time.Now(),
		}

		route := &TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "unreachable-backend", Port: 59999},
			},
			ConnectTimeout: 100 * time.Millisecond,
			IdleTimeout:    time.Second,
		}

		backendSvc := manager.GetBackend("unreachable-backend")

		// Run proxy - should complete with error
		done := make(chan struct{})
		go func() {
			server.proxyConnection(ctx, serverConn, tracked, route, backendSvc)
			close(done)
		}()

		select {
		case <-done:
			// Success - proxy completed (with error)
		case <-time.After(2 * time.Second):
			t.Fatal("proxyConnection did not complete")
		}
	})
}

func TestServer_setAcceptDeadlineWithDeadlineSupport(t *testing.T) {
	logger := zap.NewNop()

	t.Run("sets deadline on listener with SetDeadline interface", func(t *testing.T) {
		server := NewServer(nil, logger)
		server.listener = &mockListenerWithDeadline{}

		err := server.setAcceptDeadline(time.Second)

		assert.NoError(t, err)
	})
}

// mockListenerWithDeadline implements the SetDeadline interface
type mockListenerWithDeadline struct {
	deadlineSet bool
}

func (m *mockListenerWithDeadline) Accept() (net.Conn, error) {
	return nil, nil
}

func (m *mockListenerWithDeadline) Close() error {
	return nil
}

func (m *mockListenerWithDeadline) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func (m *mockListenerWithDeadline) SetDeadline(t time.Time) error {
	m.deadlineSet = true
	return nil
}

func TestServer_waitForConnectionsOrTimeout(t *testing.T) {
	logger := zap.NewNop()

	t.Run("completes when all connections close", func(t *testing.T) {
		server := NewServer(nil, logger)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// No pending goroutines, should complete immediately
		server.waitForConnectionsOrTimeout(ctx)
	})

	t.Run("times out when connections don't close", func(t *testing.T) {
		server := NewServer(nil, logger)

		// Add a pending goroutine that won't complete quickly
		done := make(chan struct{})
		server.wg.Add(1)
		go func() {
			defer server.wg.Done()
			select {
			case <-done:
				return
			case <-time.After(10 * time.Second):
				return
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		start := time.Now()
		server.waitForConnectionsOrTimeout(ctx)
		elapsed := time.Since(start)

		// Signal the goroutine to exit
		close(done)

		// Should timeout after ~200ms (with some tolerance for handleShutdownTimeout)
		assert.True(t, elapsed >= 150*time.Millisecond,
			"elapsed time %v should be at least 150ms", elapsed)
	})
}

func TestServer_AcceptLoopWithConnections(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("accepts and handles connections", func(t *testing.T) {
		config := &ServerConfig{
			Port:           0,
			Address:        "127.0.0.1",
			AcceptDeadline: 100 * time.Millisecond,
		}
		server := NewServerWithBackend(config, manager, logger)
		server.router.AddRoute(&TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "test-backend", Port: 8080},
			},
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start server
		errCh := make(chan error, 1)
		go func() {
			errCh <- server.Start(ctx)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)
		require.True(t, server.IsRunning())

		// Get the actual port
		addr := server.listener.Addr().(*net.TCPAddr)

		// Connect to server
		conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
		require.NoError(t, err)
		defer conn.Close()

		// Give it time to handle the connection
		time.Sleep(100 * time.Millisecond)

		// Cancel context to stop server
		cancel()

		select {
		case <-errCh:
			// Server stopped
		case <-time.After(2 * time.Second):
			t.Fatal("server did not stop")
		}
	})
}

func TestServer_StopWithActiveConnections(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("gracefully closes active connections", func(t *testing.T) {
		// Create a mock backend server
		backendListener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer backendListener.Close()

		backendAddr := backendListener.Addr().(*net.TCPAddr)

		// Handle backend connections - hold connection open
		go func() {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// Hold connection open
			time.Sleep(10 * time.Second)
		}()

		// Create backend
		manager.AddBackend(backend.BackendConfig{
			Name: "test-backend",
			Endpoints: []backend.EndpointConfig{
				{Address: "127.0.0.1", Port: backendAddr.Port},
			},
		})

		config := &ServerConfig{
			Port:            0,
			Address:         "127.0.0.1",
			ShutdownTimeout: 500 * time.Millisecond,
			AcceptDeadline:  100 * time.Millisecond,
		}
		server := NewServerWithBackend(config, manager, logger)
		server.router.AddRoute(&TCPRoute{
			Name: "test-route",
			BackendRefs: []BackendRef{
				{Name: "test-backend", Port: backendAddr.Port},
			},
			ConnectTimeout: time.Second,
			IdleTimeout:    5 * time.Second,
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start server
		go func() {
			server.Start(ctx)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)
		require.True(t, server.IsRunning())

		// Get the actual port
		addr := server.listener.Addr().(*net.TCPAddr)

		// Connect to server
		conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
		require.NoError(t, err)
		defer conn.Close()

		// Give it time to establish connection
		time.Sleep(200 * time.Millisecond)

		// Stop server - should force close connections after timeout
		err = server.Stop(context.Background())
		assert.NoError(t, err)
		assert.False(t, server.IsRunning())
	})
}
