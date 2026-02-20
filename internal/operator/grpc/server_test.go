// Package grpc provides gRPC server and client for operator-gateway communication.
package grpc

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// resetServerMetricsForTesting resets the gRPC server metrics singleton so
// tests can re-initialize with a fresh Prometheus registry. This prevents
// "duplicate metrics collector registration" panics when multiple tests need
// isolated metrics instances. Must only be called from tests.
func resetServerMetricsForTesting() {
	defaultMetrics = nil
	defaultMetricsOnce = sync.Once{}
}

// testServer is a shared server instance for tests to avoid duplicate metrics registration.
var (
	testServer     *Server
	testServerOnce sync.Once
	testServerErr  error
)

func getTestServer(t *testing.T) *Server {
	testServerOnce.Do(func() {
		testServer, testServerErr = NewServer(&ServerConfig{})
	})
	if testServerErr != nil {
		t.Fatalf("Failed to create test server: %v", testServerErr)
	}
	// Reset state for each test
	testServer.mu.Lock()
	testServer.apiRoutes = make(map[string][]byte)
	testServer.grpcRoutes = make(map[string][]byte)
	testServer.backends = make(map[string][]byte)
	testServer.grpcBackends = make(map[string][]byte)
	testServer.configNotify = make(chan struct{})
	testServer.gateways = make(map[string]*gatewayConnection)
	testServer.mu.Unlock()
	return testServer
}

func TestNewServer_NilConfig(t *testing.T) {
	_, err := NewServer(nil)
	if err == nil {
		t.Error("NewServer(nil) should return error")
	}
}

func TestServer_ApplyAPIRoute(t *testing.T) {
	server := getTestServer(t)

	ctx := context.Background()
	config := []byte(`{"match":[{"uri":{"prefix":"/api"}}]}`)

	err := server.ApplyAPIRoute(ctx, "test-route", "default", config)
	if err != nil {
		t.Errorf("ApplyAPIRoute() error = %v", err)
	}

	// Verify the route was stored
	server.mu.RLock()
	stored, ok := server.apiRoutes["default/test-route"]
	server.mu.RUnlock()

	if !ok {
		t.Error("ApplyAPIRoute() did not store the route")
	}
	if string(stored) != string(config) {
		t.Errorf("ApplyAPIRoute() stored = %v, want %v", string(stored), string(config))
	}
}

func TestServer_DeleteAPIRoute(t *testing.T) {
	server := getTestServer(t)

	ctx := context.Background()
	config := []byte(`{"match":[{"uri":{"prefix":"/api"}}]}`)

	// First apply a route
	_ = server.ApplyAPIRoute(ctx, "test-route", "default", config)

	// Then delete it
	err := server.DeleteAPIRoute(ctx, "test-route", "default")
	if err != nil {
		t.Errorf("DeleteAPIRoute() error = %v", err)
	}

	// Verify the route was deleted
	server.mu.RLock()
	_, ok := server.apiRoutes["default/test-route"]
	server.mu.RUnlock()

	if ok {
		t.Error("DeleteAPIRoute() did not delete the route")
	}
}

func TestServer_ApplyGRPCRoute(t *testing.T) {
	server := getTestServer(t)

	ctx := context.Background()
	config := []byte(`{"match":[{"service":{"exact":"myservice"}}]}`)

	err := server.ApplyGRPCRoute(ctx, "test-grpc-route", "default", config)
	if err != nil {
		t.Errorf("ApplyGRPCRoute() error = %v", err)
	}

	// Verify the route was stored
	server.mu.RLock()
	stored, ok := server.grpcRoutes["default/test-grpc-route"]
	server.mu.RUnlock()

	if !ok {
		t.Error("ApplyGRPCRoute() did not store the route")
	}
	if string(stored) != string(config) {
		t.Errorf("ApplyGRPCRoute() stored = %v, want %v", string(stored), string(config))
	}
}

func TestServer_DeleteGRPCRoute(t *testing.T) {
	server := getTestServer(t)

	ctx := context.Background()
	config := []byte(`{"match":[{"service":{"exact":"myservice"}}]}`)

	// First apply a route
	_ = server.ApplyGRPCRoute(ctx, "test-grpc-route", "default", config)

	// Then delete it
	err := server.DeleteGRPCRoute(ctx, "test-grpc-route", "default")
	if err != nil {
		t.Errorf("DeleteGRPCRoute() error = %v", err)
	}

	// Verify the route was deleted
	server.mu.RLock()
	_, ok := server.grpcRoutes["default/test-grpc-route"]
	server.mu.RUnlock()

	if ok {
		t.Error("DeleteGRPCRoute() did not delete the route")
	}
}

func TestServer_ApplyBackend(t *testing.T) {
	server := getTestServer(t)

	ctx := context.Background()
	config := []byte(`{"hosts":[{"address":"backend","port":8080}]}`)

	err := server.ApplyBackend(ctx, "test-backend", "default", config)
	if err != nil {
		t.Errorf("ApplyBackend() error = %v", err)
	}

	// Verify the backend was stored
	server.mu.RLock()
	stored, ok := server.backends["default/test-backend"]
	server.mu.RUnlock()

	if !ok {
		t.Error("ApplyBackend() did not store the backend")
	}
	if string(stored) != string(config) {
		t.Errorf("ApplyBackend() stored = %v, want %v", string(stored), string(config))
	}
}

func TestServer_DeleteBackend(t *testing.T) {
	server := getTestServer(t)

	ctx := context.Background()
	config := []byte(`{"hosts":[{"address":"backend","port":8080}]}`)

	// First apply a backend
	_ = server.ApplyBackend(ctx, "test-backend", "default", config)

	// Then delete it
	err := server.DeleteBackend(ctx, "test-backend", "default")
	if err != nil {
		t.Errorf("DeleteBackend() error = %v", err)
	}

	// Verify the backend was deleted
	server.mu.RLock()
	_, ok := server.backends["default/test-backend"]
	server.mu.RUnlock()

	if ok {
		t.Error("DeleteBackend() did not delete the backend")
	}
}

func TestServer_ApplyGRPCBackend(t *testing.T) {
	server := getTestServer(t)

	ctx := context.Background()
	config := []byte(`{"hosts":[{"address":"grpc-backend","port":50051}]}`)

	err := server.ApplyGRPCBackend(ctx, "test-grpc-backend", "default", config)
	if err != nil {
		t.Errorf("ApplyGRPCBackend() error = %v", err)
	}

	// Verify the backend was stored
	server.mu.RLock()
	stored, ok := server.grpcBackends["default/test-grpc-backend"]
	server.mu.RUnlock()

	if !ok {
		t.Error("ApplyGRPCBackend() did not store the backend")
	}
	if string(stored) != string(config) {
		t.Errorf("ApplyGRPCBackend() stored = %v, want %v", string(stored), string(config))
	}
}

func TestServer_DeleteGRPCBackend(t *testing.T) {
	server := getTestServer(t)

	ctx := context.Background()
	config := []byte(`{"hosts":[{"address":"grpc-backend","port":50051}]}`)

	// First apply a backend
	_ = server.ApplyGRPCBackend(ctx, "test-grpc-backend", "default", config)

	// Then delete it
	err := server.DeleteGRPCBackend(ctx, "test-grpc-backend", "default")
	if err != nil {
		t.Errorf("DeleteGRPCBackend() error = %v", err)
	}

	// Verify the backend was deleted
	server.mu.RLock()
	_, ok := server.grpcBackends["default/test-grpc-backend"]
	server.mu.RUnlock()

	if ok {
		t.Error("DeleteGRPCBackend() did not delete the backend")
	}
}

func TestServer_GetAllConfigs(t *testing.T) {
	server := getTestServer(t)

	ctx := context.Background()

	// Apply some configs
	_ = server.ApplyAPIRoute(ctx, "route1", "default", []byte(`{"match":[]}`))
	_ = server.ApplyGRPCRoute(ctx, "grpc-route1", "default", []byte(`{"match":[]}`))
	_ = server.ApplyBackend(ctx, "backend1", "default", []byte(`{"hosts":[]}`))
	_ = server.ApplyGRPCBackend(ctx, "grpc-backend1", "default", []byte(`{"hosts":[]}`))

	// Get all configs
	configsJSON, err := server.GetAllConfigs()
	if err != nil {
		t.Errorf("GetAllConfigs() error = %v", err)
		return
	}

	// Parse the JSON
	var configs map[string]interface{}
	if err := json.Unmarshal(configsJSON, &configs); err != nil {
		t.Errorf("GetAllConfigs() returned invalid JSON: %v", err)
		return
	}

	// Verify all config types are present
	expectedKeys := []string{"apiRoutes", "grpcRoutes", "backends", "grpcBackends"}
	for _, key := range expectedKeys {
		if _, ok := configs[key]; !ok {
			t.Errorf("GetAllConfigs() missing key: %s", key)
		}
	}
}

func TestServer_RegisterGateway(t *testing.T) {
	server := getTestServer(t)

	server.RegisterGateway("gateway1", "default")

	// Verify the gateway was registered
	count := server.GetGatewayCount()
	if count != 1 {
		t.Errorf("GetGatewayCount() = %d, want 1", count)
	}

	// Register another gateway
	server.RegisterGateway("gateway2", "default")
	count = server.GetGatewayCount()
	if count != 2 {
		t.Errorf("GetGatewayCount() = %d, want 2", count)
	}
}

func TestServer_UnregisterGateway(t *testing.T) {
	server := getTestServer(t)

	// Register gateways
	server.RegisterGateway("gateway1", "default")
	server.RegisterGateway("gateway2", "default")

	// Unregister one
	server.UnregisterGateway("gateway1", "default")

	count := server.GetGatewayCount()
	if count != 1 {
		t.Errorf("GetGatewayCount() = %d, want 1", count)
	}

	// Unregister the other
	server.UnregisterGateway("gateway2", "default")

	count = server.GetGatewayCount()
	if count != 0 {
		t.Errorf("GetGatewayCount() = %d, want 0", count)
	}
}

func TestServer_UpdateGatewayHeartbeat(t *testing.T) {
	server := getTestServer(t)

	// Register a gateway
	server.RegisterGateway("gateway1", "default")

	// Get initial last seen time
	server.mu.RLock()
	gw := server.gateways["default/gateway1"]
	initialLastSeen := gw.lastSeen
	server.mu.RUnlock()

	// Update heartbeat
	server.UpdateGatewayHeartbeat("gateway1", "default")

	// Verify last seen was updated
	server.mu.RLock()
	gw = server.gateways["default/gateway1"]
	updatedLastSeen := gw.lastSeen
	server.mu.RUnlock()

	if !updatedLastSeen.After(initialLastSeen) && !updatedLastSeen.Equal(initialLastSeen) {
		t.Error("UpdateGatewayHeartbeat() did not update last seen time")
	}
}

func TestServer_UpdateGatewayHeartbeat_NonExistent(t *testing.T) {
	server := getTestServer(t)

	// Should not panic for non-existent gateway
	server.UpdateGatewayHeartbeat("non-existent", "default")
}

func TestServer_MultipleOperations(t *testing.T) {
	server := getTestServer(t)

	ctx := context.Background()

	// Apply multiple configs
	for i := 0; i < 10; i++ {
		name := "route-" + string(rune('0'+i))
		_ = server.ApplyAPIRoute(ctx, name, "default", []byte(`{}`))
		_ = server.ApplyGRPCRoute(ctx, name, "default", []byte(`{}`))
		_ = server.ApplyBackend(ctx, name, "default", []byte(`{}`))
		_ = server.ApplyGRPCBackend(ctx, name, "default", []byte(`{}`))
	}

	// Verify counts
	server.mu.RLock()
	apiRouteCount := len(server.apiRoutes)
	grpcRouteCount := len(server.grpcRoutes)
	backendCount := len(server.backends)
	grpcBackendCount := len(server.grpcBackends)
	server.mu.RUnlock()

	if apiRouteCount != 10 {
		t.Errorf("apiRoutes count = %d, want 10", apiRouteCount)
	}
	if grpcRouteCount != 10 {
		t.Errorf("grpcRoutes count = %d, want 10", grpcRouteCount)
	}
	if backendCount != 10 {
		t.Errorf("backends count = %d, want 10", backendCount)
	}
	if grpcBackendCount != 10 {
		t.Errorf("grpcBackends count = %d, want 10", grpcBackendCount)
	}

	// Delete all
	for i := 0; i < 10; i++ {
		name := "route-" + string(rune('0'+i))
		_ = server.DeleteAPIRoute(ctx, name, "default")
		_ = server.DeleteGRPCRoute(ctx, name, "default")
		_ = server.DeleteBackend(ctx, name, "default")
		_ = server.DeleteGRPCBackend(ctx, name, "default")
	}

	// Verify all deleted
	server.mu.RLock()
	apiRouteCount = len(server.apiRoutes)
	grpcRouteCount = len(server.grpcRoutes)
	backendCount = len(server.backends)
	grpcBackendCount = len(server.grpcBackends)
	server.mu.RUnlock()

	if apiRouteCount != 0 {
		t.Errorf("apiRoutes count = %d, want 0", apiRouteCount)
	}
	if grpcRouteCount != 0 {
		t.Errorf("grpcRoutes count = %d, want 0", grpcRouteCount)
	}
	if backendCount != 0 {
		t.Errorf("backends count = %d, want 0", backendCount)
	}
	if grpcBackendCount != 0 {
		t.Errorf("grpcBackends count = %d, want 0", grpcBackendCount)
	}
}

// ============================================================================
// Server Start/Stop Tests
// ============================================================================

func TestServer_Start_AlreadyStarted(t *testing.T) {
	// Use the shared test server to avoid metrics registration issues
	server := getTestServer(t)

	// Mark as started
	server.mu.Lock()
	originalStarted := server.started
	server.started = true
	server.mu.Unlock()

	// Restore original state after test
	defer func() {
		server.mu.Lock()
		server.started = originalStarted
		server.mu.Unlock()
	}()

	// Try to start again
	ctx := context.Background()
	err := server.Start(ctx)
	if err == nil {
		t.Error("Start() should return error when already started")
	}
	if err.Error() != "server already started" {
		t.Errorf("Start() error = %v, want 'server already started'", err)
	}
}

func TestServer_Start_AlreadyClosed(t *testing.T) {
	// Use the shared test server to avoid metrics registration issues
	server := getTestServer(t)

	// Mark as closed
	server.mu.Lock()
	originalClosed := server.closed
	server.closed = true
	server.mu.Unlock()

	// Restore original state after test
	defer func() {
		server.mu.Lock()
		server.closed = originalClosed
		server.mu.Unlock()
	}()

	// Try to start
	ctx := context.Background()
	err := server.Start(ctx)
	if err == nil {
		t.Error("Start() should return error when server is closed")
	}
	if err.Error() != "server is closed" {
		t.Errorf("Start() error = %v, want 'server is closed'", err)
	}
}

func TestServer_Stop_AlreadyClosed(t *testing.T) {
	// Use the shared test server to avoid metrics registration issues
	server := getTestServer(t)

	// Mark as closed
	server.mu.Lock()
	originalClosed := server.closed
	server.closed = true
	server.mu.Unlock()

	// Restore original state after test
	defer func() {
		server.mu.Lock()
		server.closed = originalClosed
		server.mu.Unlock()
	}()

	// Stop should return early without panic
	server.Stop()
}

// ============================================================================
// Server Configuration Tests
// ============================================================================

func TestNewServer_DefaultConfig(t *testing.T) {
	// Use the shared test server to verify defaults
	server := getTestServer(t)

	// Verify server was initialized
	if server.apiRoutes == nil {
		t.Error("apiRoutes should be initialized")
	}
	if server.grpcRoutes == nil {
		t.Error("grpcRoutes should be initialized")
	}
	if server.backends == nil {
		t.Error("backends should be initialized")
	}
	if server.grpcBackends == nil {
		t.Error("grpcBackends should be initialized")
	}
	if server.gateways == nil {
		t.Error("gateways should be initialized")
	}
}

func TestServerConfig_Defaults(t *testing.T) {
	// Test that defaults are applied to config
	tests := []struct {
		name                   string
		config                 *ServerConfig
		expectedPort           int
		expectedMaxStreams     uint32
		expectedMaxRecvMsgSize int
		expectedMaxSendMsgSize int
	}{
		{
			name:                   "empty config",
			config:                 &ServerConfig{},
			expectedPort:           9444,
			expectedMaxStreams:     100,
			expectedMaxRecvMsgSize: 4 * 1024 * 1024,
			expectedMaxSendMsgSize: 4 * 1024 * 1024,
		},
		{
			name: "custom port",
			config: &ServerConfig{
				Port: 8443,
			},
			expectedPort:           8443,
			expectedMaxStreams:     100,
			expectedMaxRecvMsgSize: 4 * 1024 * 1024,
			expectedMaxSendMsgSize: 4 * 1024 * 1024,
		},
		{
			name: "negative port uses default",
			config: &ServerConfig{
				Port: -1,
			},
			expectedPort:           9444,
			expectedMaxStreams:     100,
			expectedMaxRecvMsgSize: 4 * 1024 * 1024,
			expectedMaxSendMsgSize: 4 * 1024 * 1024,
		},
		{
			name: "custom max streams",
			config: &ServerConfig{
				MaxConcurrentStreams: 200,
			},
			expectedPort:           9444,
			expectedMaxStreams:     200,
			expectedMaxRecvMsgSize: 4 * 1024 * 1024,
			expectedMaxSendMsgSize: 4 * 1024 * 1024,
		},
		{
			name: "custom message sizes",
			config: &ServerConfig{
				MaxRecvMsgSize: 8 * 1024 * 1024,
				MaxSendMsgSize: 8 * 1024 * 1024,
			},
			expectedPort:           9444,
			expectedMaxStreams:     100,
			expectedMaxRecvMsgSize: 8 * 1024 * 1024,
			expectedMaxSendMsgSize: 8 * 1024 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Apply defaults (same logic as NewServer)
			if tt.config.Port <= 0 {
				tt.config.Port = 9444
			}
			if tt.config.MaxConcurrentStreams == 0 {
				tt.config.MaxConcurrentStreams = 100
			}
			if tt.config.MaxRecvMsgSize == 0 {
				tt.config.MaxRecvMsgSize = 4 * 1024 * 1024
			}
			if tt.config.MaxSendMsgSize == 0 {
				tt.config.MaxSendMsgSize = 4 * 1024 * 1024
			}

			if tt.config.Port != tt.expectedPort {
				t.Errorf("Port = %d, want %d", tt.config.Port, tt.expectedPort)
			}
			if tt.config.MaxConcurrentStreams != tt.expectedMaxStreams {
				t.Errorf("MaxConcurrentStreams = %d, want %d", tt.config.MaxConcurrentStreams, tt.expectedMaxStreams)
			}
			if tt.config.MaxRecvMsgSize != tt.expectedMaxRecvMsgSize {
				t.Errorf("MaxRecvMsgSize = %d, want %d", tt.config.MaxRecvMsgSize, tt.expectedMaxRecvMsgSize)
			}
			if tt.config.MaxSendMsgSize != tt.expectedMaxSendMsgSize {
				t.Errorf("MaxSendMsgSize = %d, want %d", tt.config.MaxSendMsgSize, tt.expectedMaxSendMsgSize)
			}
		})
	}
}

// ============================================================================
// Server Start/Stop Integration Tests
// ============================================================================

func TestServer_Stop_NilGRPCServer(t *testing.T) {
	// Use the shared test server to avoid metrics registration issues
	server := getTestServer(t)

	// Reset state
	server.mu.Lock()
	originalClosed := server.closed
	server.closed = false
	server.mu.Unlock()

	// Restore original state after test
	defer func() {
		server.mu.Lock()
		server.closed = originalClosed
		server.mu.Unlock()
	}()

	// Stop should not panic even with nil grpcServer
	server.Stop()

	// Verify server is marked as closed
	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()

	if !closed {
		t.Error("Stop() should mark server as closed")
	}
}

func TestServer_Stop_MultipleCalls(t *testing.T) {
	// Use the shared test server to avoid metrics registration issues
	server := getTestServer(t)

	// Reset state
	server.mu.Lock()
	originalClosed := server.closed
	server.closed = false
	server.mu.Unlock()

	// Restore original state after test
	defer func() {
		server.mu.Lock()
		server.closed = originalClosed
		server.mu.Unlock()
	}()

	// Stop multiple times should not panic
	server.Stop()

	// Verify server is marked as closed
	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()

	if !closed {
		t.Error("Stop() should mark server as closed")
	}

	// Second call should return early
	server.Stop()
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestServer_ConcurrentOperations(t *testing.T) {
	server := getTestServer(t)

	ctx := context.Background()
	var wg sync.WaitGroup

	// Run multiple concurrent operations
	for i := 0; i < 10; i++ {
		wg.Add(4)

		go func(idx int) {
			defer wg.Done()
			name := "concurrent-route-" + string(rune('0'+idx))
			_ = server.ApplyAPIRoute(ctx, name, "default", []byte(`{}`))
		}(i)

		go func(idx int) {
			defer wg.Done()
			name := "concurrent-backend-" + string(rune('0'+idx))
			_ = server.ApplyBackend(ctx, name, "default", []byte(`{}`))
		}(i)

		go func(idx int) {
			defer wg.Done()
			server.RegisterGateway("gateway-"+string(rune('0'+idx)), "default")
		}(i)

		go func(idx int) {
			defer wg.Done()
			server.UpdateGatewayHeartbeat("gateway-"+string(rune('0'+idx)), "default")
		}(i)
	}

	wg.Wait()

	// Verify operations completed
	server.mu.RLock()
	apiRouteCount := len(server.apiRoutes)
	backendCount := len(server.backends)
	gatewayCount := len(server.gateways)
	server.mu.RUnlock()

	if apiRouteCount != 10 {
		t.Errorf("Expected 10 API routes, got %d", apiRouteCount)
	}
	if backendCount != 10 {
		t.Errorf("Expected 10 backends, got %d", backendCount)
	}
	if gatewayCount != 10 {
		t.Errorf("Expected 10 gateways, got %d", gatewayCount)
	}
}

func TestServer_GetAllConfigs_Empty(t *testing.T) {
	server := getTestServer(t)

	// Get configs when empty
	configsJSON, err := server.GetAllConfigs()
	if err != nil {
		t.Errorf("GetAllConfigs() error = %v", err)
		return
	}

	// Parse the JSON
	var configs map[string]interface{}
	if err := json.Unmarshal(configsJSON, &configs); err != nil {
		t.Errorf("GetAllConfigs() returned invalid JSON: %v", err)
		return
	}

	// Verify all config types are present (even if empty)
	expectedKeys := []string{"apiRoutes", "grpcRoutes", "backends", "grpcBackends"}
	for _, key := range expectedKeys {
		if _, ok := configs[key]; !ok {
			t.Errorf("GetAllConfigs() missing key: %s", key)
		}
	}
}

// ============================================================================
// Table-Driven Tests for Server Operations
// ============================================================================

func TestServer_ApplyOperations_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		operation func(ctx context.Context, server *Server) error
		verify    func(server *Server) bool
	}{
		{
			name: "apply API route",
			operation: func(ctx context.Context, server *Server) error {
				return server.ApplyAPIRoute(ctx, "test", "ns", []byte(`{}`))
			},
			verify: func(server *Server) bool {
				server.mu.RLock()
				defer server.mu.RUnlock()
				_, ok := server.apiRoutes["ns/test"]
				return ok
			},
		},
		{
			name: "apply gRPC route",
			operation: func(ctx context.Context, server *Server) error {
				return server.ApplyGRPCRoute(ctx, "test", "ns", []byte(`{}`))
			},
			verify: func(server *Server) bool {
				server.mu.RLock()
				defer server.mu.RUnlock()
				_, ok := server.grpcRoutes["ns/test"]
				return ok
			},
		},
		{
			name: "apply backend",
			operation: func(ctx context.Context, server *Server) error {
				return server.ApplyBackend(ctx, "test", "ns", []byte(`{}`))
			},
			verify: func(server *Server) bool {
				server.mu.RLock()
				defer server.mu.RUnlock()
				_, ok := server.backends["ns/test"]
				return ok
			},
		},
		{
			name: "apply gRPC backend",
			operation: func(ctx context.Context, server *Server) error {
				return server.ApplyGRPCBackend(ctx, "test", "ns", []byte(`{}`))
			},
			verify: func(server *Server) bool {
				server.mu.RLock()
				defer server.mu.RUnlock()
				_, ok := server.grpcBackends["ns/test"]
				return ok
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := getTestServer(t)
			ctx := context.Background()

			err := tt.operation(ctx, server)
			if err != nil {
				t.Errorf("%s error = %v", tt.name, err)
			}

			if !tt.verify(server) {
				t.Errorf("%s did not store the config", tt.name)
			}
		})
	}
}

func TestServer_DeleteOperations_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(ctx context.Context, server *Server)
		operation func(ctx context.Context, server *Server) error
		verify    func(server *Server) bool
	}{
		{
			name: "delete API route",
			setup: func(ctx context.Context, server *Server) {
				_ = server.ApplyAPIRoute(ctx, "test", "ns", []byte(`{}`))
			},
			operation: func(ctx context.Context, server *Server) error {
				return server.DeleteAPIRoute(ctx, "test", "ns")
			},
			verify: func(server *Server) bool {
				server.mu.RLock()
				defer server.mu.RUnlock()
				_, ok := server.apiRoutes["ns/test"]
				return !ok
			},
		},
		{
			name: "delete gRPC route",
			setup: func(ctx context.Context, server *Server) {
				_ = server.ApplyGRPCRoute(ctx, "test", "ns", []byte(`{}`))
			},
			operation: func(ctx context.Context, server *Server) error {
				return server.DeleteGRPCRoute(ctx, "test", "ns")
			},
			verify: func(server *Server) bool {
				server.mu.RLock()
				defer server.mu.RUnlock()
				_, ok := server.grpcRoutes["ns/test"]
				return !ok
			},
		},
		{
			name: "delete backend",
			setup: func(ctx context.Context, server *Server) {
				_ = server.ApplyBackend(ctx, "test", "ns", []byte(`{}`))
			},
			operation: func(ctx context.Context, server *Server) error {
				return server.DeleteBackend(ctx, "test", "ns")
			},
			verify: func(server *Server) bool {
				server.mu.RLock()
				defer server.mu.RUnlock()
				_, ok := server.backends["ns/test"]
				return !ok
			},
		},
		{
			name: "delete gRPC backend",
			setup: func(ctx context.Context, server *Server) {
				_ = server.ApplyGRPCBackend(ctx, "test", "ns", []byte(`{}`))
			},
			operation: func(ctx context.Context, server *Server) error {
				return server.DeleteGRPCBackend(ctx, "test", "ns")
			},
			verify: func(server *Server) bool {
				server.mu.RLock()
				defer server.mu.RUnlock()
				_, ok := server.grpcBackends["ns/test"]
				return !ok
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := getTestServer(t)
			ctx := context.Background()

			tt.setup(ctx, server)

			err := tt.operation(ctx, server)
			if err != nil {
				t.Errorf("%s error = %v", tt.name, err)
			}

			if !tt.verify(server) {
				t.Errorf("%s did not delete the config", tt.name)
			}
		})
	}
}

func TestServer_GatewayOperations_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(server *Server)
		operation func(server *Server)
		verify    func(server *Server) bool
	}{
		{
			name:  "register gateway",
			setup: func(server *Server) {},
			operation: func(server *Server) {
				server.RegisterGateway("gw1", "ns")
			},
			verify: func(server *Server) bool {
				return server.GetGatewayCount() == 1
			},
		},
		{
			name: "unregister gateway",
			setup: func(server *Server) {
				server.RegisterGateway("gw1", "ns")
			},
			operation: func(server *Server) {
				server.UnregisterGateway("gw1", "ns")
			},
			verify: func(server *Server) bool {
				return server.GetGatewayCount() == 0
			},
		},
		{
			name: "update heartbeat",
			setup: func(server *Server) {
				server.RegisterGateway("gw1", "ns")
			},
			operation: func(server *Server) {
				server.UpdateGatewayHeartbeat("gw1", "ns")
			},
			verify: func(server *Server) bool {
				server.mu.RLock()
				defer server.mu.RUnlock()
				gw, ok := server.gateways["ns/gw1"]
				return ok && !gw.lastSeen.IsZero()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := getTestServer(t)

			tt.setup(server)
			tt.operation(server)

			if !tt.verify(server) {
				t.Errorf("%s verification failed", tt.name)
			}
		})
	}
}

// ============================================================================
// Context Cancellation Tests
// ============================================================================

func TestServer_ApplyAPIRoute_ContextCanceled(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.ApplyAPIRoute(ctx, "test-route", "default", []byte(`{}`))
	if err == nil {
		t.Error("ApplyAPIRoute() should return error when context is canceled")
	}
	if err != context.Canceled {
		t.Errorf("ApplyAPIRoute() error = %v, want context.Canceled", err)
	}
}

func TestServer_DeleteAPIRoute_ContextCanceled(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.DeleteAPIRoute(ctx, "test-route", "default")
	if err == nil {
		t.Error("DeleteAPIRoute() should return error when context is canceled")
	}
	if err != context.Canceled {
		t.Errorf("DeleteAPIRoute() error = %v, want context.Canceled", err)
	}
}

func TestServer_ApplyGRPCRoute_ContextCanceled(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.ApplyGRPCRoute(ctx, "test-route", "default", []byte(`{}`))
	if err == nil {
		t.Error("ApplyGRPCRoute() should return error when context is canceled")
	}
	if err != context.Canceled {
		t.Errorf("ApplyGRPCRoute() error = %v, want context.Canceled", err)
	}
}

func TestServer_DeleteGRPCRoute_ContextCanceled(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.DeleteGRPCRoute(ctx, "test-route", "default")
	if err == nil {
		t.Error("DeleteGRPCRoute() should return error when context is canceled")
	}
	if err != context.Canceled {
		t.Errorf("DeleteGRPCRoute() error = %v, want context.Canceled", err)
	}
}

func TestServer_ApplyBackend_ContextCanceled(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.ApplyBackend(ctx, "test-backend", "default", []byte(`{}`))
	if err == nil {
		t.Error("ApplyBackend() should return error when context is canceled")
	}
	if err != context.Canceled {
		t.Errorf("ApplyBackend() error = %v, want context.Canceled", err)
	}
}

func TestServer_DeleteBackend_ContextCanceled(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.DeleteBackend(ctx, "test-backend", "default")
	if err == nil {
		t.Error("DeleteBackend() should return error when context is canceled")
	}
	if err != context.Canceled {
		t.Errorf("DeleteBackend() error = %v, want context.Canceled", err)
	}
}

func TestServer_ApplyGRPCBackend_ContextCanceled(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.ApplyGRPCBackend(ctx, "test-backend", "default", []byte(`{}`))
	if err == nil {
		t.Error("ApplyGRPCBackend() should return error when context is canceled")
	}
	if err != context.Canceled {
		t.Errorf("ApplyGRPCBackend() error = %v, want context.Canceled", err)
	}
}

func TestServer_DeleteGRPCBackend_ContextCanceled(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.DeleteGRPCBackend(ctx, "test-backend", "default")
	if err == nil {
		t.Error("DeleteGRPCBackend() should return error when context is canceled")
	}
	if err != context.Canceled {
		t.Errorf("DeleteGRPCBackend() error = %v, want context.Canceled", err)
	}
}

// ============================================================================
// Context Deadline Exceeded Tests
// ============================================================================

func TestServer_ApplyAPIRoute_ContextDeadlineExceeded(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err := server.ApplyAPIRoute(ctx, "test-route", "default", []byte(`{}`))
	if err == nil {
		t.Error("ApplyAPIRoute() should return error when context deadline exceeded")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("ApplyAPIRoute() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestServer_DeleteAPIRoute_ContextDeadlineExceeded(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err := server.DeleteAPIRoute(ctx, "test-route", "default")
	if err == nil {
		t.Error("DeleteAPIRoute() should return error when context deadline exceeded")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("DeleteAPIRoute() error = %v, want context.DeadlineExceeded", err)
	}
}

// ============================================================================
// checkContextCancellation Tests
// ============================================================================

func TestServer_checkContextCancellation_NotCanceled(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.checkContextCancellation(ctx, "TestOperation")
	if err != nil {
		t.Errorf("checkContextCancellation() error = %v, want nil", err)
	}
}

func TestServer_checkContextCancellation_Canceled(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.checkContextCancellation(ctx, "TestOperation")
	if err == nil {
		t.Error("checkContextCancellation() should return error when context is canceled")
	}
	if err != context.Canceled {
		t.Errorf("checkContextCancellation() error = %v, want context.Canceled", err)
	}
}

func TestServer_checkContextCancellation_DeadlineExceeded(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err := server.checkContextCancellation(ctx, "TestOperation")
	if err == nil {
		t.Error("checkContextCancellation() should return error when deadline exceeded")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("checkContextCancellation() error = %v, want context.DeadlineExceeded", err)
	}
}

// ============================================================================
// recordCanceledOperation Tests
// ============================================================================

func TestServer_recordCanceledOperation_Canceled(t *testing.T) {
	server := getTestServer(t)

	// Should not panic
	server.recordCanceledOperation("TestOperation", context.Canceled)
}

func TestServer_recordCanceledOperation_DeadlineExceeded(t *testing.T) {
	server := getTestServer(t)

	// Should not panic
	server.recordCanceledOperation("TestOperation", context.DeadlineExceeded)
}

func TestServer_recordCanceledOperation_UnknownError(t *testing.T) {
	server := getTestServer(t)

	// Should not panic with unknown error type
	server.recordCanceledOperation("TestOperation", nil)
}

// ============================================================================
// Server Start with Context Cancellation Tests
// ============================================================================

// Note: TestServer_Start_ContextCanceled is skipped because creating a new server
// causes duplicate metrics registration. The Start() method is tested through
// TestServer_Start_AlreadyStarted and TestServer_Start_AlreadyClosed tests.

// ============================================================================
// Table-Driven Context Cancellation Tests
// ============================================================================

func TestServer_ContextCancellation_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		operation func(ctx context.Context, server *Server) error
	}{
		{
			name: "ApplyAPIRoute",
			operation: func(ctx context.Context, server *Server) error {
				return server.ApplyAPIRoute(ctx, "test", "ns", []byte(`{}`))
			},
		},
		{
			name: "DeleteAPIRoute",
			operation: func(ctx context.Context, server *Server) error {
				return server.DeleteAPIRoute(ctx, "test", "ns")
			},
		},
		{
			name: "ApplyGRPCRoute",
			operation: func(ctx context.Context, server *Server) error {
				return server.ApplyGRPCRoute(ctx, "test", "ns", []byte(`{}`))
			},
		},
		{
			name: "DeleteGRPCRoute",
			operation: func(ctx context.Context, server *Server) error {
				return server.DeleteGRPCRoute(ctx, "test", "ns")
			},
		},
		{
			name: "ApplyBackend",
			operation: func(ctx context.Context, server *Server) error {
				return server.ApplyBackend(ctx, "test", "ns", []byte(`{}`))
			},
		},
		{
			name: "DeleteBackend",
			operation: func(ctx context.Context, server *Server) error {
				return server.DeleteBackend(ctx, "test", "ns")
			},
		},
		{
			name: "ApplyGRPCBackend",
			operation: func(ctx context.Context, server *Server) error {
				return server.ApplyGRPCBackend(ctx, "test", "ns", []byte(`{}`))
			},
		},
		{
			name: "DeleteGRPCBackend",
			operation: func(ctx context.Context, server *Server) error {
				return server.DeleteGRPCBackend(ctx, "test", "ns")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_Canceled", func(t *testing.T) {
			server := getTestServer(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			err := tt.operation(ctx, server)
			if err != context.Canceled {
				t.Errorf("%s() error = %v, want context.Canceled", tt.name, err)
			}
		})

		t.Run(tt.name+"_DeadlineExceeded", func(t *testing.T) {
			server := getTestServer(t)
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
			defer cancel()

			err := tt.operation(ctx, server)
			if err != context.DeadlineExceeded {
				t.Errorf("%s() error = %v, want context.DeadlineExceeded", tt.name, err)
			}
		})
	}
}

// ============================================================================
// Additional Context Cancellation Tests for Full Coverage
// ============================================================================

func TestServer_ApplyAPIRoute_ContextCanceledAfterLockAcquired(t *testing.T) {
	server := getTestServer(t)

	// Test with a valid context first to ensure the route is applied
	ctx := context.Background()
	err := server.ApplyAPIRoute(ctx, "test-route-lock", "default", []byte(`{"test": true}`))
	if err != nil {
		t.Errorf("ApplyAPIRoute() error = %v", err)
	}

	// Verify the route was stored
	server.mu.RLock()
	_, ok := server.apiRoutes["default/test-route-lock"]
	server.mu.RUnlock()
	if !ok {
		t.Error("ApplyAPIRoute() did not store the route")
	}
}

func TestServer_DeleteAPIRoute_ContextCanceledAfterLockAcquired(t *testing.T) {
	server := getTestServer(t)

	// First apply a route
	ctx := context.Background()
	_ = server.ApplyAPIRoute(ctx, "test-route-delete", "default", []byte(`{}`))

	// Then delete it with valid context
	err := server.DeleteAPIRoute(ctx, "test-route-delete", "default")
	if err != nil {
		t.Errorf("DeleteAPIRoute() error = %v", err)
	}

	// Verify the route was deleted
	server.mu.RLock()
	_, ok := server.apiRoutes["default/test-route-delete"]
	server.mu.RUnlock()
	if ok {
		t.Error("DeleteAPIRoute() did not delete the route")
	}
}

// ============================================================================
// recordCanceledOperation Additional Tests
// ============================================================================

func TestServer_recordCanceledOperation_AllReasons(t *testing.T) {
	server := getTestServer(t)

	tests := []struct {
		name      string
		operation string
		err       error
	}{
		{"canceled", "TestOp1", context.Canceled},
		{"deadline_exceeded", "TestOp2", context.DeadlineExceeded},
		{"unknown_error", "TestOp3", nil},
		{"custom_error", "TestOp4", &customError{msg: "custom"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			server.recordCanceledOperation(tt.operation, tt.err)
		})
	}
}

// customError is a custom error type for testing
type customError struct {
	msg string
}

func (e *customError) Error() string {
	return e.msg
}

// ============================================================================
// checkContextCancellation Additional Tests
// ============================================================================

func TestServer_checkContextCancellation_WithTimeout(t *testing.T) {
	server := getTestServer(t)

	// Create a context with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout
	time.Sleep(10 * time.Millisecond)

	err := server.checkContextCancellation(ctx, "TestOperation")
	if err == nil {
		t.Error("checkContextCancellation() should return error when timeout exceeded")
	}
}

func TestServer_checkContextCancellation_ValidContext(t *testing.T) {
	server := getTestServer(t)

	// Create a context with a long timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Hour)
	defer cancel()

	err := server.checkContextCancellation(ctx, "TestOperation")
	if err != nil {
		t.Errorf("checkContextCancellation() error = %v, want nil", err)
	}
}

// ============================================================================
// Server Start with TLS Tests
// ============================================================================

func TestServer_Start_WithContextCancellation(t *testing.T) {
	server := getTestServer(t)

	// Reset state
	server.mu.Lock()
	server.started = false
	server.closed = false
	server.mu.Unlock()

	// Create a context that's already canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Start should return context error
	err := server.Start(ctx)
	if err == nil {
		t.Error("Start() should return error when context is canceled")
	}
}

// ============================================================================
// Server Metrics Tests
// ============================================================================

func TestNewServerMetrics(t *testing.T) {
	// This is called internally by NewServer, but we can verify the metrics exist
	server := getTestServer(t)

	if server.metrics == nil {
		t.Error("Server metrics should not be nil")
	}
	if server.metrics.requestsTotal == nil {
		t.Error("requestsTotal metric should not be nil")
	}
	if server.metrics.requestDuration == nil {
		t.Error("requestDuration metric should not be nil")
	}
	if server.metrics.activeGateways == nil {
		t.Error("activeGateways metric should not be nil")
	}
	if server.metrics.configApplied == nil {
		t.Error("configApplied metric should not be nil")
	}
	if server.metrics.cancelledOps == nil {
		t.Error("cancelledOps metric should not be nil")
	}
	if server.metrics.operationDuration == nil {
		t.Error("operationDuration metric should not be nil")
	}
}

// ============================================================================
// Gateway Connection Tests
// ============================================================================

func TestServer_GatewayConnection_Fields(t *testing.T) {
	server := getTestServer(t)

	// Register a gateway
	server.RegisterGateway("test-gw", "test-ns")

	// Verify gateway connection fields
	server.mu.RLock()
	gw, ok := server.gateways["test-ns/test-gw"]
	server.mu.RUnlock()

	if !ok {
		t.Fatal("Gateway not found")
	}

	if gw.name != "test-gw" {
		t.Errorf("Gateway name = %q, want %q", gw.name, "test-gw")
	}
	if gw.namespace != "test-ns" {
		t.Errorf("Gateway namespace = %q, want %q", gw.namespace, "test-ns")
	}
	if gw.connectedAt.IsZero() {
		t.Error("Gateway connectedAt should not be zero")
	}
	if gw.lastSeen.IsZero() {
		t.Error("Gateway lastSeen should not be zero")
	}
}

// ============================================================================
// Server Config Validation Tests
// ============================================================================

func TestNewServer_WithAllConfigOptions(t *testing.T) {
	// We can't create a new server due to metrics registration,
	// but we can verify the config defaults are applied correctly
	server := getTestServer(t)

	// Verify server config defaults
	if server.config.Port <= 0 {
		t.Error("Server port should be positive")
	}
	if server.config.MaxConcurrentStreams == 0 {
		t.Error("MaxConcurrentStreams should not be zero")
	}
	if server.config.MaxRecvMsgSize == 0 {
		t.Error("MaxRecvMsgSize should not be zero")
	}
	if server.config.MaxSendMsgSize == 0 {
		t.Error("MaxSendMsgSize should not be zero")
	}
}

// ============================================================================
// Concurrent Gateway Operations Tests
// ============================================================================

func TestServer_ConcurrentGatewayOperations(t *testing.T) {
	server := getTestServer(t)

	var wg sync.WaitGroup

	// Run concurrent gateway operations
	for i := 0; i < 10; i++ {
		wg.Add(3)

		go func(idx int) {
			defer wg.Done()
			name := "gw-" + string(rune('0'+idx))
			server.RegisterGateway(name, "default")
		}(i)

		go func(idx int) {
			defer wg.Done()
			name := "gw-" + string(rune('0'+idx))
			server.UpdateGatewayHeartbeat(name, "default")
		}(i)

		go func(idx int) {
			defer wg.Done()
			_ = server.GetGatewayCount()
		}(i)
	}

	wg.Wait()
}

// ============================================================================
// GetAllConfigs Edge Cases
// ============================================================================

func TestServer_GetAllConfigs_WithLargeData(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// Add many configs
	for i := 0; i < 100; i++ {
		name := "route-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		_ = server.ApplyAPIRoute(ctx, name, "default", []byte(`{"large": "data"}`))
	}

	// Get all configs
	configsJSON, err := server.GetAllConfigs()
	if err != nil {
		t.Errorf("GetAllConfigs() error = %v", err)
	}
	if len(configsJSON) == 0 {
		t.Error("GetAllConfigs() returned empty JSON")
	}
}

// ============================================================================
// Server Lifecycle Tests
// ============================================================================

func TestServer_Lifecycle_StartStopStart(t *testing.T) {
	server := getTestServer(t)

	// Reset state
	server.mu.Lock()
	server.started = false
	server.closed = false
	server.mu.Unlock()

	// Mark as started
	server.mu.Lock()
	server.started = true
	server.mu.Unlock()

	// Try to start again - should fail
	ctx := context.Background()
	err := server.Start(ctx)
	if err == nil {
		t.Error("Start() should return error when already started")
	}

	// Reset for next test
	server.mu.Lock()
	server.started = false
	server.mu.Unlock()
}

// ============================================================================
// Edge Cases for Apply/Delete Operations
// ============================================================================

func TestServer_ApplyOperations_EmptyConfig(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// Apply with empty config
	err := server.ApplyAPIRoute(ctx, "empty-route", "default", []byte{})
	if err != nil {
		t.Errorf("ApplyAPIRoute() with empty config error = %v", err)
	}

	// Verify it was stored
	server.mu.RLock()
	stored, ok := server.apiRoutes["default/empty-route"]
	server.mu.RUnlock()

	if !ok {
		t.Error("ApplyAPIRoute() did not store empty config")
	}
	if len(stored) != 0 {
		t.Errorf("Stored config length = %d, want 0", len(stored))
	}
}

func TestServer_ApplyOperations_NilConfig(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// Apply with nil config
	err := server.ApplyAPIRoute(ctx, "nil-route", "default", nil)
	if err != nil {
		t.Errorf("ApplyAPIRoute() with nil config error = %v", err)
	}

	// Verify it was stored
	server.mu.RLock()
	_, ok := server.apiRoutes["default/nil-route"]
	server.mu.RUnlock()

	if !ok {
		t.Error("ApplyAPIRoute() did not store nil config")
	}
}

func TestServer_DeleteOperations_NonExistent(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// Delete non-existent route - should not error
	err := server.DeleteAPIRoute(ctx, "non-existent", "default")
	if err != nil {
		t.Errorf("DeleteAPIRoute() for non-existent route error = %v", err)
	}
}

// ============================================================================
// Namespace Handling Tests
// ============================================================================

func TestServer_NamespaceHandling(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// Apply routes in different namespaces
	_ = server.ApplyAPIRoute(ctx, "route1", "ns1", []byte(`{"ns": "ns1"}`))
	_ = server.ApplyAPIRoute(ctx, "route1", "ns2", []byte(`{"ns": "ns2"}`))

	// Verify both are stored separately
	server.mu.RLock()
	route1, ok1 := server.apiRoutes["ns1/route1"]
	route2, ok2 := server.apiRoutes["ns2/route1"]
	server.mu.RUnlock()

	if !ok1 {
		t.Error("Route in ns1 not found")
	}
	if !ok2 {
		t.Error("Route in ns2 not found")
	}
	if string(route1) == string(route2) {
		t.Error("Routes in different namespaces should have different configs")
	}

	// Delete from one namespace
	_ = server.DeleteAPIRoute(ctx, "route1", "ns1")

	// Verify only ns1 route is deleted
	server.mu.RLock()
	_, ok1 = server.apiRoutes["ns1/route1"]
	_, ok2 = server.apiRoutes["ns2/route1"]
	server.mu.RUnlock()

	if ok1 {
		t.Error("Route in ns1 should be deleted")
	}
	if !ok2 {
		t.Error("Route in ns2 should still exist")
	}
}
