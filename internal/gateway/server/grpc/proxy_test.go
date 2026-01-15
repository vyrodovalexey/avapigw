package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
)

// TestDefaultProxyConfig tests that DefaultProxyConfig returns expected default values
func TestDefaultProxyConfig(t *testing.T) {
	t.Parallel()

	config := DefaultProxyConfig()

	assert.NotNil(t, config)
	assert.Equal(t, 4*1024*1024, config.MaxRecvMsgSize)
	assert.Equal(t, 4*1024*1024, config.MaxSendMsgSize)
	assert.True(t, config.EnableRetry)
	assert.Equal(t, 3, config.MaxRetries)
}

// TestNewProxy tests creating a new proxy
func TestNewProxy(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	proxy := NewProxy(manager, logger)

	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.backendManager)
	assert.NotNil(t, proxy.connections)
	assert.NotNil(t, proxy.logger)
	assert.NotNil(t, proxy.config)
	assert.Empty(t, proxy.connections)
}

// TestNewProxyWithConfig tests creating a proxy with custom configuration
func TestNewProxyWithConfig(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("with custom config", func(t *testing.T) {
		config := &ProxyConfig{
			MaxRecvMsgSize: 8 * 1024 * 1024,
			MaxSendMsgSize: 8 * 1024 * 1024,
			EnableRetry:    false,
			MaxRetries:     5,
		}

		proxy := NewProxyWithConfig(manager, logger, config)

		assert.NotNil(t, proxy)
		assert.Equal(t, 8*1024*1024, proxy.config.MaxRecvMsgSize)
		assert.Equal(t, 8*1024*1024, proxy.config.MaxSendMsgSize)
		assert.False(t, proxy.config.EnableRetry)
		assert.Equal(t, 5, proxy.config.MaxRetries)
	})

	t.Run("with nil config uses defaults", func(t *testing.T) {
		proxy := NewProxyWithConfig(manager, logger, nil)

		assert.NotNil(t, proxy)
		assert.Equal(t, 4*1024*1024, proxy.config.MaxRecvMsgSize)
		assert.Equal(t, 4*1024*1024, proxy.config.MaxSendMsgSize)
		assert.True(t, proxy.config.EnableRetry)
		assert.Equal(t, 3, proxy.config.MaxRetries)
	})
}

// TestProxyClose tests closing proxy connections
func TestProxyClose(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewProxy(manager, logger)

	// Close with no connections should not error
	err := proxy.Close()
	assert.NoError(t, err)
	assert.Empty(t, proxy.connections)
}

// TestProxyGetConnectionNilBackendRef tests GetConnection with nil backend ref
func TestProxyGetConnectionNilBackendRef(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewProxy(manager, logger)

	ctx := context.Background()
	conn, err := proxy.GetConnection(ctx, nil)

	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "backend reference is nil")
}

// TestProxyGetConnectionBackendNotFound tests GetConnection when backend is not found
func TestProxyGetConnectionBackendNotFound(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewProxy(manager, logger)

	ctx := context.Background()
	backendRef := &BackendRef{
		Name:      "non-existent-backend",
		Namespace: "default",
		Port:      8080,
	}

	conn, err := proxy.GetConnection(ctx, backendRef)

	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "not found")
}

// TestProxyGetConnectionNoHealthyEndpoints tests GetConnection when no healthy endpoints
func TestProxyGetConnectionNoHealthyEndpoints(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	// Add a backend with no healthy endpoints
	err := manager.AddBackend(backend.BackendConfig{
		Name:      "unhealthy-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080},
		},
	})
	require.NoError(t, err)

	// Mark endpoint as unhealthy
	be := manager.GetBackend("default/unhealthy-backend")
	require.NotNil(t, be)
	endpoints := be.GetAllEndpoints()
	require.Len(t, endpoints, 1)
	endpoints[0].SetHealthy(false)

	proxy := NewProxy(manager, logger)

	ctx := context.Background()
	backendRef := &BackendRef{
		Name:      "unhealthy-backend",
		Namespace: "default",
		Port:      8080,
	}

	conn, err := proxy.GetConnection(ctx, backendRef)

	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "no healthy endpoints")
}

// TestProxyGetConnectionSuccess tests successful connection creation
func TestProxyGetConnectionSuccess(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	// Add a backend with healthy endpoint
	err := manager.AddBackend(backend.BackendConfig{
		Name:      "healthy-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 50051},
		},
	})
	require.NoError(t, err)

	proxy := NewProxy(manager, logger)
	defer proxy.Close()

	ctx := context.Background()
	backendRef := &BackendRef{
		Name:      "healthy-backend",
		Namespace: "default",
		Port:      50051,
	}

	// This will create a connection (though it won't actually connect since there's no server)
	conn, err := proxy.GetConnection(ctx, backendRef)

	// The connection is created but may not be connected
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

// TestProxyGetConnectionCaching tests that connections are cached
func TestProxyGetConnectionCaching(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	err := manager.AddBackend(backend.BackendConfig{
		Name:      "cached-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 50052},
		},
	})
	require.NoError(t, err)

	proxy := NewProxy(manager, logger)
	defer proxy.Close()

	ctx := context.Background()
	backendRef := &BackendRef{
		Name:      "cached-backend",
		Namespace: "default",
		Port:      50052,
	}

	// Get connection twice
	conn1, err := proxy.GetConnection(ctx, backendRef)
	require.NoError(t, err)

	conn2, err := proxy.GetConnection(ctx, backendRef)
	require.NoError(t, err)

	// Should return the same connection
	assert.Same(t, conn1, conn2)
}

// TestParseFullMethod tests parsing full method names
func TestParseFullMethod(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		fullMethod     string
		expectedSvc    string
		expectedMethod string
	}{
		{
			name:           "standard format",
			fullMethod:     "/package.Service/Method",
			expectedSvc:    "package.Service",
			expectedMethod: "Method",
		},
		{
			name:           "without leading slash",
			fullMethod:     "package.Service/Method",
			expectedSvc:    "package.Service",
			expectedMethod: "Method",
		},
		{
			name:           "nested package",
			fullMethod:     "/com.example.users.UserService/GetUser",
			expectedSvc:    "com.example.users.UserService",
			expectedMethod: "GetUser",
		},
		{
			name:           "empty string",
			fullMethod:     "",
			expectedSvc:    "",
			expectedMethod: "",
		},
		{
			name:           "no method",
			fullMethod:     "/package.Service",
			expectedSvc:    "package.Service",
			expectedMethod: "",
		},
		{
			name:           "only service",
			fullMethod:     "Service",
			expectedSvc:    "Service",
			expectedMethod: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			service, method := parseFullMethod(tc.fullMethod)
			assert.Equal(t, tc.expectedSvc, service)
			assert.Equal(t, tc.expectedMethod, method)
		})
	}
}

// TestProxyTransparentHandler tests the transparent handler creation
func TestProxyTransparentHandler(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewProxy(manager, logger)
	router := NewRouter(logger)

	handler := proxy.TransparentHandler(router)
	assert.NotNil(t, handler)
}

// TestBackendRef tests the BackendRef struct
func TestBackendRef(t *testing.T) {
	t.Parallel()

	ref := BackendRef{
		Name:      "test-backend",
		Namespace: "default",
		Port:      8080,
		Weight:    100,
	}

	assert.Equal(t, "test-backend", ref.Name)
	assert.Equal(t, "default", ref.Namespace)
	assert.Equal(t, 8080, ref.Port)
	assert.Equal(t, 100, ref.Weight)
}

// TestProxyConfig tests the ProxyConfig struct
func TestProxyConfig(t *testing.T) {
	t.Parallel()

	config := ProxyConfig{
		MaxRecvMsgSize: 8 * 1024 * 1024,
		MaxSendMsgSize: 8 * 1024 * 1024,
		EnableRetry:    true,
		MaxRetries:     5,
	}

	assert.Equal(t, 8*1024*1024, config.MaxRecvMsgSize)
	assert.Equal(t, 8*1024*1024, config.MaxSendMsgSize)
	assert.True(t, config.EnableRetry)
	assert.Equal(t, 5, config.MaxRetries)
}

// TestProxyCloseWithConnections tests closing proxy with active connections
func TestProxyCloseWithConnections(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	err := manager.AddBackend(backend.BackendConfig{
		Name:      "close-test-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 50053},
		},
	})
	require.NoError(t, err)

	proxy := NewProxy(manager, logger)

	ctx := context.Background()
	backendRef := &BackendRef{
		Name:      "close-test-backend",
		Namespace: "default",
		Port:      50053,
	}

	// Create a connection
	_, err = proxy.GetConnection(ctx, backendRef)
	require.NoError(t, err)

	// Verify connection exists
	assert.NotEmpty(t, proxy.connections)

	// Close proxy
	err = proxy.Close()
	assert.NoError(t, err)

	// Verify connections are cleared
	assert.Empty(t, proxy.connections)
}

// TestProxyGetConnectionWithNamespaceKey tests connection key generation
func TestProxyGetConnectionWithNamespaceKey(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	// Add backend without namespace
	err := manager.AddBackend(backend.BackendConfig{
		Name: "no-namespace-backend",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 50054},
		},
	})
	require.NoError(t, err)

	proxy := NewProxy(manager, logger)
	defer proxy.Close()

	ctx := context.Background()
	backendRef := &BackendRef{
		Name:      "no-namespace-backend",
		Namespace: "",
		Port:      50054,
	}

	conn, err := proxy.GetConnection(ctx, backendRef)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}
