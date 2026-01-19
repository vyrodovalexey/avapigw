package backend

import (
	"context"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// ============================================================================
// Test Cases for DefaultGRPCProxyConfig
// ============================================================================

func TestDefaultGRPCProxyConfig(t *testing.T) {
	config := DefaultGRPCProxyConfig()

	require.NotNil(t, config)
	assert.Equal(t, 4*1024*1024, config.MaxRecvMsgSize)
	assert.Equal(t, 4*1024*1024, config.MaxSendMsgSize)
	assert.Equal(t, 10*time.Second, config.DialTimeout)
	assert.True(t, config.EnableRetry)
	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, config.RetryBackoff)
	assert.Nil(t, config.TLS)
}

// ============================================================================
// Test Cases for NewGRPCProxy
// ============================================================================

func TestNewGRPCProxy(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	proxy := NewGRPCProxy(manager, logger)

	require.NotNil(t, proxy)
	assert.NotNil(t, proxy.manager)
	assert.NotNil(t, proxy.logger)
	assert.NotNil(t, proxy.config)
	assert.NotNil(t, proxy.connections)
	assert.Empty(t, proxy.connections)
}

func TestNewGRPCProxy_UsesDefaultConfig(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	proxy := NewGRPCProxy(manager, logger)

	require.NotNil(t, proxy)
	assert.Equal(t, 4*1024*1024, proxy.config.MaxRecvMsgSize)
	assert.Equal(t, 4*1024*1024, proxy.config.MaxSendMsgSize)
	assert.Equal(t, 10*time.Second, proxy.config.DialTimeout)
}

// ============================================================================
// Test Cases for NewGRPCProxyWithConfig
// ============================================================================

func TestNewGRPCProxyWithConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *GRPCProxyConfig
	}{
		{
			name: "creates proxy with custom config",
			config: &GRPCProxyConfig{
				MaxRecvMsgSize: 8 * 1024 * 1024,
				MaxSendMsgSize: 8 * 1024 * 1024,
				DialTimeout:    20 * time.Second,
				EnableRetry:    false,
				MaxRetries:     5,
				RetryBackoff:   200 * time.Millisecond,
			},
		},
		{
			name:   "creates proxy with nil config (uses defaults)",
			config: nil,
		},
		{
			name: "creates proxy with TLS config",
			config: &GRPCProxyConfig{
				MaxRecvMsgSize: 4 * 1024 * 1024,
				MaxSendMsgSize: 4 * 1024 * 1024,
				DialTimeout:    10 * time.Second,
				TLS: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // test only
				},
			},
		},
		{
			name: "creates proxy with minimal config",
			config: &GRPCProxyConfig{
				MaxRecvMsgSize: 1024,
				MaxSendMsgSize: 1024,
				DialTimeout:    1 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			manager := NewManager(logger)

			proxy := NewGRPCProxyWithConfig(manager, logger, tt.config)

			require.NotNil(t, proxy)
			assert.NotNil(t, proxy.manager)
			assert.NotNil(t, proxy.logger)
			assert.NotNil(t, proxy.config)
			assert.NotNil(t, proxy.connections)

			if tt.config != nil {
				assert.Equal(t, tt.config.MaxRecvMsgSize, proxy.config.MaxRecvMsgSize)
				assert.Equal(t, tt.config.MaxSendMsgSize, proxy.config.MaxSendMsgSize)
				assert.Equal(t, tt.config.DialTimeout, proxy.config.DialTimeout)
			} else {
				// Should use defaults
				assert.Equal(t, 4*1024*1024, proxy.config.MaxRecvMsgSize)
			}
		})
	}
}

// ============================================================================
// Test Cases for GRPCProxy.GetConnection
// ============================================================================

func TestGRPCProxy_GetConnection_NilBackend(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	ctx := context.Background()
	conn, err := proxy.GetConnection(ctx, nil)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "backend is nil")
}

func TestGRPCProxy_GetConnection_NoHealthyEndpoints(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	backend := &Backend{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []*Endpoint{
			{Address: "localhost", Port: 8080, Healthy: false},
		},
		LoadBalancer: NewRoundRobinLB(),
	}

	ctx := context.Background()
	conn, err := proxy.GetConnection(ctx, backend)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "no healthy endpoints")
}

func TestGRPCProxy_GetConnection_EmptyEndpoints(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	backend := &Backend{
		Name:         "test-backend",
		Namespace:    "test-namespace",
		Endpoints:    []*Endpoint{},
		LoadBalancer: NewRoundRobinLB(),
	}

	ctx := context.Background()
	conn, err := proxy.GetConnection(ctx, backend)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "no healthy endpoints")
}

func TestGRPCProxy_GetConnection_ContextCanceled(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	// Use a very short dial timeout
	config := &GRPCProxyConfig{
		MaxRecvMsgSize: 4 * 1024 * 1024,
		MaxSendMsgSize: 4 * 1024 * 1024,
		DialTimeout:    1 * time.Nanosecond, // Extremely short timeout
	}
	proxy := NewGRPCProxyWithConfig(manager, logger, config)

	backend := &Backend{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []*Endpoint{
			{Address: "192.0.2.1", Port: 8080, Healthy: true}, // Non-routable IP (TEST-NET-1)
		},
		LoadBalancer: NewRoundRobinLB(),
	}

	// Create an already-canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, err := proxy.GetConnection(ctx, backend)

	// Note: gRPC uses lazy connection, so it may succeed initially
	// The connection will fail when actually used
	// We just verify the function doesn't panic with canceled context
	if err != nil {
		assert.Nil(t, conn)
	} else {
		// If connection was created (lazy), close it
		if conn != nil {
			conn.Close()
		}
	}
}

// ============================================================================
// Test Cases for GRPCProxy.Close
// ============================================================================

func TestGRPCProxy_Close_EmptyConnections(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	err := proxy.Close()

	assert.NoError(t, err)
	assert.Empty(t, proxy.connections)
}

func TestGRPCProxy_Close_ClearsConnections(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	// Verify that Close clears the connections map even when empty
	err := proxy.Close()

	assert.NoError(t, err)
	assert.Empty(t, proxy.connections)

	// Verify we can call Close again after clearing
	err = proxy.Close()
	assert.NoError(t, err)
}

func TestGRPCProxy_Close_Idempotent(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	// Multiple closes should not panic
	assert.NotPanics(t, func() {
		_ = proxy.Close()
		_ = proxy.Close()
		_ = proxy.Close()
	})
}

// ============================================================================
// Test Cases for GRPCProxy.buildDialOptions
// ============================================================================

func TestGRPCProxy_buildDialOptions_NoTLS(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := &GRPCProxyConfig{
		MaxRecvMsgSize: 4 * 1024 * 1024,
		MaxSendMsgSize: 4 * 1024 * 1024,
		DialTimeout:    10 * time.Second,
		TLS:            nil,
	}
	proxy := NewGRPCProxyWithConfig(manager, logger, config)

	opts := proxy.buildDialOptions()

	require.NotEmpty(t, opts)
	// Should have at least 2 options: call options and transport credentials
	assert.GreaterOrEqual(t, len(opts), 2)
}

func TestGRPCProxy_buildDialOptions_WithTLS(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := &GRPCProxyConfig{
		MaxRecvMsgSize: 4 * 1024 * 1024,
		MaxSendMsgSize: 4 * 1024 * 1024,
		DialTimeout:    10 * time.Second,
		TLS: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test only
		},
	}
	proxy := NewGRPCProxyWithConfig(manager, logger, config)

	opts := proxy.buildDialOptions()

	require.NotEmpty(t, opts)
	assert.GreaterOrEqual(t, len(opts), 2)
}

// ============================================================================
// Test Cases for GRPCProxy.ProxyUnary
// ============================================================================

func TestGRPCProxy_ProxyUnary_NilBackend(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	ctx := context.Background()
	resp, err := proxy.ProxyUnary(ctx, "/test.Service/Method", []byte("request"), nil)

	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestGRPCProxy_ProxyUnary_NoHealthyEndpoints(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	backend := &Backend{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []*Endpoint{
			{Address: "localhost", Port: 8080, Healthy: false},
		},
		LoadBalancer: NewRoundRobinLB(),
	}

	ctx := context.Background()
	resp, err := proxy.ProxyUnary(ctx, "/test.Service/Method", []byte("request"), backend)

	require.Error(t, err)
	assert.Nil(t, resp)
}

// ============================================================================
// Test Cases for GRPCProxy.ProxyStream
// ============================================================================

func TestGRPCProxy_ProxyStream_NilBackend(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	desc := &grpc.StreamDesc{
		ServerStreams: true,
		ClientStreams: false,
	}

	ctx := context.Background()
	stream, err := proxy.ProxyStream(ctx, desc, "/test.Service/StreamMethod", nil)

	require.Error(t, err)
	assert.Nil(t, stream)
}

func TestGRPCProxy_ProxyStream_NoHealthyEndpoints(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	backend := &Backend{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []*Endpoint{
			{Address: "localhost", Port: 8080, Healthy: false},
		},
		LoadBalancer: NewRoundRobinLB(),
	}

	desc := &grpc.StreamDesc{
		ServerStreams: true,
		ClientStreams: false,
	}

	ctx := context.Background()
	stream, err := proxy.ProxyStream(ctx, desc, "/test.Service/StreamMethod", backend)

	require.Error(t, err)
	assert.Nil(t, stream)
}

// ============================================================================
// Test Cases for GRPCProxy.ProxyBidirectionalStream
// ============================================================================

func TestGRPCProxy_ProxyBidirectionalStream_NilBackend(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	ctx := context.Background()
	err := proxy.ProxyBidirectionalStream(ctx, "/test.Service/BidiMethod", nil, nil)

	require.Error(t, err)
}

func TestGRPCProxy_ProxyBidirectionalStream_NoHealthyEndpoints(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	backend := &Backend{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []*Endpoint{
			{Address: "localhost", Port: 8080, Healthy: false},
		},
		LoadBalancer: NewRoundRobinLB(),
	}

	ctx := context.Background()
	err := proxy.ProxyBidirectionalStream(ctx, "/test.Service/BidiMethod", backend, nil)

	require.Error(t, err)
}

// ============================================================================
// Test Cases for rawCodec
// ============================================================================

func TestRawCodec_Marshal(t *testing.T) {
	codec := &rawCodec{}

	tests := []struct {
		name        string
		input       interface{}
		expected    []byte
		expectError bool
	}{
		{
			name:        "marshals rawFrame",
			input:       &rawFrame{data: []byte("test data")},
			expected:    []byte("test data"),
			expectError: false,
		},
		{
			name:        "marshals byte slice",
			input:       []byte("byte slice data"),
			expected:    []byte("byte slice data"),
			expectError: false,
		},
		{
			name:        "errors on unsupported type",
			input:       "string type",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "errors on int type",
			input:       123,
			expected:    nil,
			expectError: true,
		},
		{
			name:        "marshals empty rawFrame",
			input:       &rawFrame{data: []byte{}},
			expected:    []byte{},
			expectError: false,
		},
		{
			name:        "marshals nil data in rawFrame",
			input:       &rawFrame{data: nil},
			expected:    nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := codec.Marshal(tt.input)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported type")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestRawCodec_Unmarshal(t *testing.T) {
	codec := &rawCodec{}

	tests := []struct {
		name        string
		data        []byte
		target      interface{}
		expectError bool
		validate    func(t *testing.T, target interface{})
	}{
		{
			name:        "unmarshals to rawFrame",
			data:        []byte("test data"),
			target:      &rawFrame{},
			expectError: false,
			validate: func(t *testing.T, target interface{}) {
				frame := target.(*rawFrame)
				assert.Equal(t, []byte("test data"), frame.data)
			},
		},
		{
			name:        "unmarshals to byte slice pointer",
			data:        []byte("byte slice data"),
			target:      new([]byte),
			expectError: false,
			validate: func(t *testing.T, target interface{}) {
				data := target.(*[]byte)
				assert.Equal(t, []byte("byte slice data"), *data)
			},
		},
		{
			name:        "errors on unsupported type",
			data:        []byte("data"),
			target:      new(string),
			expectError: true,
			validate:    nil,
		},
		{
			name:        "unmarshals empty data to rawFrame",
			data:        []byte{},
			target:      &rawFrame{},
			expectError: false,
			validate: func(t *testing.T, target interface{}) {
				frame := target.(*rawFrame)
				assert.Equal(t, []byte{}, frame.data)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := codec.Unmarshal(tt.data, tt.target)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported type")
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, tt.target)
				}
			}
		})
	}
}

func TestRawCodec_Name(t *testing.T) {
	codec := &rawCodec{}

	name := codec.Name()

	assert.Equal(t, "raw", name)
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestGRPCProxy_ConcurrentClose(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = proxy.Close()
		}()
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})
}

func TestGRPCProxy_ConcurrentGetConnection(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	backend := &Backend{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []*Endpoint{
			{Address: "localhost", Port: 8080, Healthy: false}, // Unhealthy to avoid actual connection
		},
		LoadBalancer: NewRoundRobinLB(),
	}

	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			_, _ = proxy.GetConnection(ctx, backend)
		}()
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})
}

func TestGRPCProxy_ConcurrentProxyUnary(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	backend := &Backend{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []*Endpoint{
			{Address: "localhost", Port: 8080, Healthy: false},
		},
		LoadBalancer: NewRoundRobinLB(),
	}

	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			_, _ = proxy.ProxyUnary(ctx, "/test.Service/Method", []byte("request"), backend)
		}()
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})
}

func TestGRPCProxy_ConcurrentBuildDialOptions(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			opts := proxy.buildDialOptions()
			assert.NotEmpty(t, opts)
		}()
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

func TestGRPCProxy_GetConnection_BackendWithEmptyNamespace(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := &GRPCProxyConfig{
		MaxRecvMsgSize: 4 * 1024 * 1024,
		MaxSendMsgSize: 4 * 1024 * 1024,
		DialTimeout:    1 * time.Nanosecond, // Very short timeout
	}
	proxy := NewGRPCProxyWithConfig(manager, logger, config)

	backend := &Backend{
		Name:      "test-backend",
		Namespace: "", // Empty namespace
		Endpoints: []*Endpoint{
			{Address: "192.0.2.1", Port: 8080, Healthy: true}, // Non-routable IP (TEST-NET-1)
		},
		LoadBalancer: NewRoundRobinLB(),
	}

	ctx := context.Background()
	conn, err := proxy.GetConnection(ctx, backend)

	// Note: gRPC uses lazy connection, so it may succeed initially
	// The connection will fail when actually used
	// We just verify the function handles empty namespace correctly
	if err != nil {
		assert.Nil(t, conn)
	} else {
		// If connection was created (lazy), verify it exists and close it
		assert.NotNil(t, conn)
		if conn != nil {
			conn.Close()
		}
	}
}

func TestGRPCProxy_ProxyUnary_EmptyRequest(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	backend := &Backend{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []*Endpoint{
			{Address: "localhost", Port: 8080, Healthy: false},
		},
		LoadBalancer: NewRoundRobinLB(),
	}

	ctx := context.Background()
	resp, err := proxy.ProxyUnary(ctx, "/test.Service/Method", []byte{}, backend)

	// Should fail due to no healthy endpoints
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestGRPCProxy_ProxyUnary_NilRequest(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	backend := &Backend{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []*Endpoint{
			{Address: "localhost", Port: 8080, Healthy: false},
		},
		LoadBalancer: NewRoundRobinLB(),
	}

	ctx := context.Background()
	resp, err := proxy.ProxyUnary(ctx, "/test.Service/Method", nil, backend)

	// Should fail due to no healthy endpoints
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestGRPCProxy_ProxyStream_NilStreamDesc(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)
	proxy := NewGRPCProxy(manager, logger)

	backend := &Backend{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []*Endpoint{
			{Address: "localhost", Port: 8080, Healthy: false},
		},
		LoadBalancer: NewRoundRobinLB(),
	}

	ctx := context.Background()
	stream, err := proxy.ProxyStream(ctx, nil, "/test.Service/StreamMethod", backend)

	// Should fail due to no healthy endpoints (before reaching nil desc issue)
	require.Error(t, err)
	assert.Nil(t, stream)
}

func TestGRPCProxy_ConfigWithZeroValues(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := &GRPCProxyConfig{
		MaxRecvMsgSize: 0,
		MaxSendMsgSize: 0,
		DialTimeout:    0,
		MaxRetries:     0,
		RetryBackoff:   0,
	}

	proxy := NewGRPCProxyWithConfig(manager, logger, config)

	require.NotNil(t, proxy)
	assert.Equal(t, 0, proxy.config.MaxRecvMsgSize)
	assert.Equal(t, 0, proxy.config.MaxSendMsgSize)
	assert.Equal(t, time.Duration(0), proxy.config.DialTimeout)
}

// ============================================================================
// Test rawFrame
// ============================================================================

func TestRawFrame(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "with data",
			data: []byte("test data"),
		},
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "nil data",
			data: nil,
		},
		{
			name: "large data",
			data: make([]byte, 1024*1024), // 1MB
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := &rawFrame{data: tt.data}
			assert.Equal(t, tt.data, frame.data)
		})
	}
}

// ============================================================================
// Integration-like Tests (without actual gRPC server)
// ============================================================================

func TestGRPCProxy_FullWorkflow_NoServer(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	// Add a backend
	err := manager.AddBackend(BackendConfig{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 50051, Weight: 1},
		},
	})
	require.NoError(t, err)

	// Create proxy
	proxy := NewGRPCProxy(manager, logger)
	require.NotNil(t, proxy)

	// Get backend
	backend := manager.GetBackendByNamespace("test-namespace", "test-backend")
	require.NotNil(t, backend)

	// Mark endpoint as unhealthy to avoid actual connection attempts
	backend.Endpoints[0].SetHealthy(false)

	// Try to get connection (should fail due to no healthy endpoints)
	ctx := context.Background()
	conn, err := proxy.GetConnection(ctx, backend)
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "no healthy endpoints")

	// Close proxy
	err = proxy.Close()
	assert.NoError(t, err)
}

func TestGRPCProxy_MultipleBackends(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	// Add multiple backends
	backends := []BackendConfig{
		{
			Name:      "backend1",
			Namespace: "ns1",
			Endpoints: []EndpointConfig{
				{Address: "localhost", Port: 50051},
			},
		},
		{
			Name:      "backend2",
			Namespace: "ns2",
			Endpoints: []EndpointConfig{
				{Address: "localhost", Port: 50052},
			},
		},
		{
			Name:      "backend3",
			Namespace: "ns3",
			Endpoints: []EndpointConfig{
				{Address: "localhost", Port: 50053},
			},
		},
	}

	for _, config := range backends {
		err := manager.AddBackend(config)
		require.NoError(t, err)
	}

	proxy := NewGRPCProxy(manager, logger)
	require.NotNil(t, proxy)

	// Mark all endpoints as unhealthy
	for _, config := range backends {
		backend := manager.GetBackendByNamespace(config.Namespace, config.Name)
		require.NotNil(t, backend)
		backend.Endpoints[0].SetHealthy(false)
	}

	// Try to get connections for each backend
	ctx := context.Background()
	for _, config := range backends {
		backend := manager.GetBackendByNamespace(config.Namespace, config.Name)
		conn, err := proxy.GetConnection(ctx, backend)
		require.Error(t, err)
		assert.Nil(t, conn)
	}

	// Close proxy
	err := proxy.Close()
	assert.NoError(t, err)
}
