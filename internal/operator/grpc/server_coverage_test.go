// Package grpc provides gRPC server and client for operator-gateway communication.
package grpc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// executeWithRetry Tests - Comprehensive Coverage
// ============================================================================

func TestServer_executeWithRetry_Success(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	callCount := 0
	err := server.executeWithRetry(ctx, "test", "resource", func() error {
		callCount++
		return nil
	})

	if err != nil {
		t.Errorf("executeWithRetry() error = %v, want nil", err)
	}
	if callCount != 1 {
		t.Errorf("executeWithRetry() called function %d times, want 1", callCount)
	}
}

func TestServer_executeWithRetry_RetryOnError(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	callCount := 0
	maxCalls := 2
	err := server.executeWithRetry(ctx, "test", "resource", func() error {
		callCount++
		if callCount < maxCalls {
			return errors.New("temporary error")
		}
		return nil
	})

	if err != nil {
		t.Errorf("executeWithRetry() error = %v, want nil", err)
	}
	if callCount != maxCalls {
		t.Errorf("executeWithRetry() called function %d times, want %d", callCount, maxCalls)
	}
}

func TestServer_executeWithRetry_ExhaustedRetries(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	callCount := 0
	err := server.executeWithRetry(ctx, "test", "resource", func() error {
		callCount++
		return errors.New("persistent error")
	})

	if err == nil {
		t.Error("executeWithRetry() should return error when retries exhausted")
	}
	// Should have been called MaxRetries times
	if callCount < 2 {
		t.Errorf("executeWithRetry() called function %d times, want at least 2", callCount)
	}
}

func TestServer_executeWithRetry_ContextCanceled(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())

	callCount := 0
	err := server.executeWithRetry(ctx, "test", "resource", func() error {
		callCount++
		if callCount == 1 {
			cancel() // Cancel after first call
			return errors.New("error to trigger retry")
		}
		return nil
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("executeWithRetry() error = %v, want context.Canceled", err)
	}
}

func TestServer_executeWithRetry_ContextDeadlineExceeded(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err := server.executeWithRetry(ctx, "test", "resource", func() error {
		return errors.New("should not be called")
	})

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("executeWithRetry() error = %v, want context.DeadlineExceeded", err)
	}
}

// ============================================================================
// recordCanceledOperation Tests - Comprehensive Coverage
// ============================================================================

func TestServer_recordCanceledOperation_AllErrorTypes(t *testing.T) {
	server := getTestServer(t)

	tests := []struct {
		name      string
		operation string
		err       error
	}{
		{"context.Canceled", "TestOp1", context.Canceled},
		{"context.DeadlineExceeded", "TestOp2", context.DeadlineExceeded},
		{"nil error", "TestOp3", nil},
		{"generic error", "TestOp4", errors.New("generic error")},
		{"wrapped canceled", "TestOp5", errors.New("wrapped: " + context.Canceled.Error())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			server.recordCanceledOperation(tt.operation, tt.err)
		})
	}
}

// ============================================================================
// checkContextCancellation Tests - Comprehensive Coverage
// ============================================================================

func TestServer_checkContextCancellation_AllScenarios(t *testing.T) {
	server := getTestServer(t)

	tests := []struct {
		name      string
		setupCtx  func() (context.Context, context.CancelFunc)
		wantErr   error
		operation string
	}{
		{
			name: "valid context",
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			wantErr:   nil,
			operation: "ValidOp",
		},
		{
			name: "canceled context",
			setupCtx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			wantErr:   context.Canceled,
			operation: "CanceledOp",
		},
		{
			name: "deadline exceeded",
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
			},
			wantErr:   context.DeadlineExceeded,
			operation: "DeadlineOp",
		},
		{
			name: "timeout exceeded",
			setupCtx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
				time.Sleep(10 * time.Millisecond)
				return ctx, cancel
			},
			wantErr:   context.DeadlineExceeded,
			operation: "TimeoutOp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := tt.setupCtx()
			defer cancel()

			err := server.checkContextCancellation(ctx, tt.operation)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("checkContextCancellation() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// DeleteGRPCBackend Tests - Comprehensive Coverage
// ============================================================================

func TestServer_DeleteGRPCBackend_Success(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// First apply a backend
	config := []byte(`{"hosts":[{"address":"grpc-backend","port":50051}]}`)
	err := server.ApplyGRPCBackend(ctx, "test-grpc-backend", "default", config)
	if err != nil {
		t.Fatalf("ApplyGRPCBackend() error = %v", err)
	}

	// Verify it was stored
	server.mu.RLock()
	_, ok := server.grpcBackends["default/test-grpc-backend"]
	server.mu.RUnlock()
	if !ok {
		t.Fatal("ApplyGRPCBackend() did not store the backend")
	}

	// Delete it
	err = server.DeleteGRPCBackend(ctx, "test-grpc-backend", "default")
	if err != nil {
		t.Errorf("DeleteGRPCBackend() error = %v", err)
	}

	// Verify it was deleted
	server.mu.RLock()
	_, ok = server.grpcBackends["default/test-grpc-backend"]
	server.mu.RUnlock()
	if ok {
		t.Error("DeleteGRPCBackend() did not delete the backend")
	}
}

func TestServer_DeleteGRPCBackend_NonExistent(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// Delete non-existent backend - should not error
	err := server.DeleteGRPCBackend(ctx, "non-existent", "default")
	if err != nil {
		t.Errorf("DeleteGRPCBackend() for non-existent backend error = %v", err)
	}
}

func TestServer_DeleteGRPCBackend_ContextCanceled_Coverage(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.DeleteGRPCBackend(ctx, "test-backend", "default")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("DeleteGRPCBackend() error = %v, want context.Canceled", err)
	}
}

func TestServer_DeleteGRPCBackend_ContextDeadlineExceeded(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err := server.DeleteGRPCBackend(ctx, "test-backend", "default")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("DeleteGRPCBackend() error = %v, want context.DeadlineExceeded", err)
	}
}

// ============================================================================
// deleteGRPCBackendInternal Tests
// ============================================================================

func TestServer_deleteGRPCBackendInternal_Success(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// First add a backend directly
	server.mu.Lock()
	server.grpcBackends["default/internal-test"] = []byte(`{}`)
	server.mu.Unlock()

	// Delete it using internal method
	err := server.deleteGRPCBackendInternal(ctx, "internal-test", "default")
	if err != nil {
		t.Errorf("deleteGRPCBackendInternal() error = %v", err)
	}

	// Verify it was deleted
	server.mu.RLock()
	_, ok := server.grpcBackends["default/internal-test"]
	server.mu.RUnlock()
	if ok {
		t.Error("deleteGRPCBackendInternal() did not delete the backend")
	}
}

func TestServer_deleteGRPCBackendInternal_ContextCanceled(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.deleteGRPCBackendInternal(ctx, "test", "default")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("deleteGRPCBackendInternal() error = %v, want context.Canceled", err)
	}
}

// ============================================================================
// GetAllConfigs Tests - Comprehensive Coverage
// ============================================================================

func TestServer_GetAllConfigs_WithData(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// Add various configs
	_ = server.ApplyAPIRoute(ctx, "route1", "ns1", []byte(`{"match":[]}`))
	_ = server.ApplyGRPCRoute(ctx, "grpc-route1", "ns1", []byte(`{"match":[]}`))
	_ = server.ApplyBackend(ctx, "backend1", "ns1", []byte(`{"hosts":[]}`))
	_ = server.ApplyGRPCBackend(ctx, "grpc-backend1", "ns1", []byte(`{"hosts":[]}`))

	// Get all configs
	configsJSON, err := server.GetAllConfigs()
	if err != nil {
		t.Errorf("GetAllConfigs() error = %v", err)
		return
	}

	if len(configsJSON) == 0 {
		t.Error("GetAllConfigs() returned empty JSON")
	}
}

func TestServer_GetAllConfigs_EmptyState_Coverage(t *testing.T) {
	server := getTestServer(t)

	// Get configs when empty
	configsJSON, err := server.GetAllConfigs()
	if err != nil {
		t.Errorf("GetAllConfigs() error = %v", err)
		return
	}

	if len(configsJSON) == 0 {
		t.Error("GetAllConfigs() returned empty JSON even for empty state")
	}
}

// ============================================================================
// RegisterGateway Tests - Comprehensive Coverage
// ============================================================================

func TestServer_RegisterGateway_Success(t *testing.T) {
	server := getTestServer(t)

	server.RegisterGateway("gw1", "ns1")

	// Verify registration
	server.mu.RLock()
	gw, ok := server.gateways["ns1/gw1"]
	server.mu.RUnlock()

	if !ok {
		t.Error("RegisterGateway() did not register the gateway")
	}
	if gw.name != "gw1" {
		t.Errorf("Gateway name = %q, want %q", gw.name, "gw1")
	}
	if gw.namespace != "ns1" {
		t.Errorf("Gateway namespace = %q, want %q", gw.namespace, "ns1")
	}
	if gw.connectedAt.IsZero() {
		t.Error("Gateway connectedAt should not be zero")
	}
	if gw.lastSeen.IsZero() {
		t.Error("Gateway lastSeen should not be zero")
	}
}

func TestServer_RegisterGateway_Multiple(t *testing.T) {
	server := getTestServer(t)

	server.RegisterGateway("gw1", "ns1")
	server.RegisterGateway("gw2", "ns1")
	server.RegisterGateway("gw1", "ns2")

	count := server.GetGatewayCount()
	if count != 3 {
		t.Errorf("GetGatewayCount() = %d, want 3", count)
	}
}

func TestServer_RegisterGateway_Reregister(t *testing.T) {
	server := getTestServer(t)

	// Register first time
	server.RegisterGateway("gw1", "ns1")

	server.mu.RLock()
	firstConnectedAt := server.gateways["ns1/gw1"].connectedAt
	server.mu.RUnlock()

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Re-register
	server.RegisterGateway("gw1", "ns1")

	server.mu.RLock()
	secondConnectedAt := server.gateways["ns1/gw1"].connectedAt
	server.mu.RUnlock()

	// connectedAt should be updated
	if !secondConnectedAt.After(firstConnectedAt) && !secondConnectedAt.Equal(firstConnectedAt) {
		t.Error("Re-registration should update connectedAt")
	}
}

// ============================================================================
// UnregisterGateway Tests - Comprehensive Coverage
// ============================================================================

func TestServer_UnregisterGateway_Success(t *testing.T) {
	server := getTestServer(t)

	// Register first
	server.RegisterGateway("gw1", "ns1")

	// Verify registered
	if server.GetGatewayCount() != 1 {
		t.Fatal("Gateway not registered")
	}

	// Unregister
	server.UnregisterGateway("gw1", "ns1")

	// Verify unregistered
	if server.GetGatewayCount() != 0 {
		t.Error("UnregisterGateway() did not unregister the gateway")
	}
}

func TestServer_UnregisterGateway_NonExistent(t *testing.T) {
	server := getTestServer(t)

	// Should not panic
	server.UnregisterGateway("non-existent", "ns1")
}

func TestServer_UnregisterGateway_WrongNamespace(t *testing.T) {
	server := getTestServer(t)

	server.RegisterGateway("gw1", "ns1")

	// Unregister from wrong namespace
	server.UnregisterGateway("gw1", "ns2")

	// Should still be registered in ns1
	if server.GetGatewayCount() != 1 {
		t.Error("UnregisterGateway() should not affect gateway in different namespace")
	}
}

// ============================================================================
// UpdateGatewayHeartbeat Tests - Comprehensive Coverage
// ============================================================================

func TestServer_UpdateGatewayHeartbeat_Success(t *testing.T) {
	server := getTestServer(t)

	// Register first
	server.RegisterGateway("gw1", "ns1")

	server.mu.RLock()
	initialLastSeen := server.gateways["ns1/gw1"].lastSeen
	server.mu.RUnlock()

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Update heartbeat
	server.UpdateGatewayHeartbeat("gw1", "ns1")

	server.mu.RLock()
	updatedLastSeen := server.gateways["ns1/gw1"].lastSeen
	server.mu.RUnlock()

	if !updatedLastSeen.After(initialLastSeen) {
		t.Error("UpdateGatewayHeartbeat() should update lastSeen")
	}
}

func TestServer_UpdateGatewayHeartbeat_NonExistent_Coverage(t *testing.T) {
	server := getTestServer(t)

	// Should not panic
	server.UpdateGatewayHeartbeat("non-existent", "ns1")
}

func TestServer_UpdateGatewayHeartbeat_WrongNamespace(t *testing.T) {
	server := getTestServer(t)

	server.RegisterGateway("gw1", "ns1")

	server.mu.RLock()
	initialLastSeen := server.gateways["ns1/gw1"].lastSeen
	server.mu.RUnlock()

	// Update heartbeat for wrong namespace
	server.UpdateGatewayHeartbeat("gw1", "ns2")

	server.mu.RLock()
	currentLastSeen := server.gateways["ns1/gw1"].lastSeen
	server.mu.RUnlock()

	// lastSeen should not change
	if !currentLastSeen.Equal(initialLastSeen) {
		t.Error("UpdateGatewayHeartbeat() should not affect gateway in different namespace")
	}
}

// ============================================================================
// GetGatewayCount Tests - Comprehensive Coverage
// ============================================================================

func TestServer_GetGatewayCount_Empty(t *testing.T) {
	server := getTestServer(t)

	count := server.GetGatewayCount()
	if count != 0 {
		t.Errorf("GetGatewayCount() = %d, want 0", count)
	}
}

func TestServer_GetGatewayCount_Multiple(t *testing.T) {
	server := getTestServer(t)

	for i := 0; i < 5; i++ {
		server.RegisterGateway("gw"+string(rune('0'+i)), "ns1")
	}

	count := server.GetGatewayCount()
	if count != 5 {
		t.Errorf("GetGatewayCount() = %d, want 5", count)
	}
}

// ============================================================================
// Concurrent Operations Tests
// ============================================================================

func TestServer_ConcurrentDeleteGRPCBackend(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// Add backends
	for i := 0; i < 10; i++ {
		name := "backend-" + string(rune('0'+i))
		_ = server.ApplyGRPCBackend(ctx, name, "default", []byte(`{}`))
	}

	// Delete concurrently
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := "backend-" + string(rune('0'+idx))
			_ = server.DeleteGRPCBackend(ctx, name, "default")
		}(i)
	}
	wg.Wait()

	// Verify all deleted
	server.mu.RLock()
	count := len(server.grpcBackends)
	server.mu.RUnlock()

	if count != 0 {
		t.Errorf("Expected 0 backends, got %d", count)
	}
}

func TestServer_ConcurrentGatewayOperations_Coverage(t *testing.T) {
	server := getTestServer(t)

	var wg sync.WaitGroup

	// Concurrent register/unregister/heartbeat
	for i := 0; i < 10; i++ {
		wg.Add(4)

		go func(idx int) {
			defer wg.Done()
			name := "gw-" + string(rune('0'+idx))
			server.RegisterGateway(name, "ns1")
		}(i)

		go func(idx int) {
			defer wg.Done()
			name := "gw-" + string(rune('0'+idx))
			server.UpdateGatewayHeartbeat(name, "ns1")
		}(i)

		go func(idx int) {
			defer wg.Done()
			_ = server.GetGatewayCount()
		}(i)

		go func(idx int) {
			defer wg.Done()
			name := "gw-" + string(rune('0'+idx))
			server.UnregisterGateway(name, "ns1")
		}(i)
	}

	wg.Wait()
}

// ============================================================================
// DefaultRetryConfig Tests
// ============================================================================

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	if config == nil {
		t.Fatal("DefaultRetryConfig() returned nil")
	}
	if config.MaxAttempts <= 0 {
		t.Error("MaxAttempts should be positive")
	}
	if config.InitialBackoff <= 0 {
		t.Error("InitialBackoff should be positive")
	}
	if config.MaxBackoff <= 0 {
		t.Error("MaxBackoff should be positive")
	}
	if config.Multiplier <= 0 {
		t.Error("Multiplier should be positive")
	}
}

// ============================================================================
// Internal Method Tests for Full Coverage
// ============================================================================

func TestServer_applyAPIRouteInternal_ContextCanceled(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.applyAPIRouteInternal(ctx, "test", "default", []byte(`{}`))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("applyAPIRouteInternal() error = %v, want context.Canceled", err)
	}
}

func TestServer_deleteAPIRouteInternal_ContextCanceled(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.deleteAPIRouteInternal(ctx, "test", "default")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("deleteAPIRouteInternal() error = %v, want context.Canceled", err)
	}
}

func TestServer_applyGRPCRouteInternal_ContextCanceled(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.applyGRPCRouteInternal(ctx, "test", "default", []byte(`{}`))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("applyGRPCRouteInternal() error = %v, want context.Canceled", err)
	}
}

func TestServer_deleteGRPCRouteInternal_ContextCanceled(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.deleteGRPCRouteInternal(ctx, "test", "default")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("deleteGRPCRouteInternal() error = %v, want context.Canceled", err)
	}
}

func TestServer_applyBackendInternal_ContextCanceled(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.applyBackendInternal(ctx, "test", "default", []byte(`{}`))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("applyBackendInternal() error = %v, want context.Canceled", err)
	}
}

func TestServer_deleteBackendInternal_ContextCanceled(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.deleteBackendInternal(ctx, "test", "default")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("deleteBackendInternal() error = %v, want context.Canceled", err)
	}
}

func TestServer_applyGRPCBackendInternal_ContextCanceled(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.applyGRPCBackendInternal(ctx, "test", "default", []byte(`{}`))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("applyGRPCBackendInternal() error = %v, want context.Canceled", err)
	}
}

// ============================================================================
// Table-Driven Tests for All Delete Operations
// ============================================================================

func TestServer_DeleteOperations_AllTypes(t *testing.T) {
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

// ============================================================================
// RetryConfig Tests
// ============================================================================

func TestRetryConfig_Fields(t *testing.T) {
	config := &RetryConfig{
		MaxAttempts:    5,
		InitialBackoff: 200 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		Multiplier:     3.0,
	}

	if config.MaxAttempts != 5 {
		t.Errorf("MaxAttempts = %d, want 5", config.MaxAttempts)
	}
	if config.InitialBackoff != 200*time.Millisecond {
		t.Errorf("InitialBackoff = %v, want 200ms", config.InitialBackoff)
	}
	if config.MaxBackoff != 10*time.Second {
		t.Errorf("MaxBackoff = %v, want 10s", config.MaxBackoff)
	}
	if config.Multiplier != 3.0 {
		t.Errorf("Multiplier = %f, want 3.0", config.Multiplier)
	}
}

// ============================================================================
// ServerConfig Tests
// ============================================================================

func TestServerConfig_AllFields(t *testing.T) {
	config := &ServerConfig{
		Port:                 8443,
		MaxConcurrentStreams: 200,
		MaxRecvMsgSize:       8 * 1024 * 1024,
		MaxSendMsgSize:       8 * 1024 * 1024,
		RetryConfig: &RetryConfig{
			MaxAttempts:    5,
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     5 * time.Second,
			Multiplier:     2.0,
		},
	}

	if config.Port != 8443 {
		t.Errorf("Port = %d, want 8443", config.Port)
	}
	if config.MaxConcurrentStreams != 200 {
		t.Errorf("MaxConcurrentStreams = %d, want 200", config.MaxConcurrentStreams)
	}
	if config.MaxRecvMsgSize != 8*1024*1024 {
		t.Errorf("MaxRecvMsgSize = %d, want 8MB", config.MaxRecvMsgSize)
	}
	if config.MaxSendMsgSize != 8*1024*1024 {
		t.Errorf("MaxSendMsgSize = %d, want 8MB", config.MaxSendMsgSize)
	}
	if config.RetryConfig == nil {
		t.Error("RetryConfig should not be nil")
	}
}

// ============================================================================
// withContextLock Tests
// ============================================================================

func TestServer_withContextLock_Success(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	unlock, err := server.withContextLock(ctx)
	if err != nil {
		t.Errorf("withContextLock() error = %v, want nil", err)
	}
	if unlock == nil {
		t.Error("withContextLock() unlock function should not be nil")
	}

	// Call unlock to release the lock
	unlock()
}

func TestServer_withContextLock_ContextCanceled(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	unlock, err := server.withContextLock(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("withContextLock() error = %v, want context.Canceled", err)
	}
	if unlock != nil {
		t.Error("withContextLock() unlock function should be nil on error")
	}
}

func TestServer_withContextLock_ContextDeadlineExceeded(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	unlock, err := server.withContextLock(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("withContextLock() error = %v, want context.DeadlineExceeded", err)
	}
	if unlock != nil {
		t.Error("withContextLock() unlock function should be nil on error")
	}
}

func TestServer_withContextLock_ConcurrentAccess(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	// Run multiple goroutines trying to acquire the lock
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := server.withContextLock(ctx)
			if err == nil {
				mu.Lock()
				successCount++
				mu.Unlock()
				// Simulate some work
				time.Sleep(1 * time.Millisecond)
				unlock()
			}
		}()
	}

	wg.Wait()

	// All goroutines should have succeeded
	if successCount != 10 {
		t.Errorf("Expected 10 successful lock acquisitions, got %d", successCount)
	}
}

// ============================================================================
// Internal Apply/Delete Methods Tests
// ============================================================================

func TestServer_applyAPIRouteInternal_Success(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.applyAPIRouteInternal(ctx, "test-route", "default", []byte(`{"test": true}`))
	if err != nil {
		t.Errorf("applyAPIRouteInternal() error = %v", err)
	}

	// Verify the route was stored
	server.mu.RLock()
	_, ok := server.apiRoutes["default/test-route"]
	server.mu.RUnlock()
	if !ok {
		t.Error("applyAPIRouteInternal() did not store the route")
	}
}

func TestServer_deleteAPIRouteInternal_Success(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// First add a route
	server.mu.Lock()
	server.apiRoutes["default/test-route"] = []byte(`{}`)
	server.mu.Unlock()

	// Delete it
	err := server.deleteAPIRouteInternal(ctx, "test-route", "default")
	if err != nil {
		t.Errorf("deleteAPIRouteInternal() error = %v", err)
	}

	// Verify the route was deleted
	server.mu.RLock()
	_, ok := server.apiRoutes["default/test-route"]
	server.mu.RUnlock()
	if ok {
		t.Error("deleteAPIRouteInternal() did not delete the route")
	}
}

func TestServer_applyGRPCRouteInternal_Success(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.applyGRPCRouteInternal(ctx, "test-route", "default", []byte(`{"test": true}`))
	if err != nil {
		t.Errorf("applyGRPCRouteInternal() error = %v", err)
	}

	// Verify the route was stored
	server.mu.RLock()
	_, ok := server.grpcRoutes["default/test-route"]
	server.mu.RUnlock()
	if !ok {
		t.Error("applyGRPCRouteInternal() did not store the route")
	}
}

func TestServer_deleteGRPCRouteInternal_Success(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// First add a route
	server.mu.Lock()
	server.grpcRoutes["default/test-route"] = []byte(`{}`)
	server.mu.Unlock()

	// Delete it
	err := server.deleteGRPCRouteInternal(ctx, "test-route", "default")
	if err != nil {
		t.Errorf("deleteGRPCRouteInternal() error = %v", err)
	}

	// Verify the route was deleted
	server.mu.RLock()
	_, ok := server.grpcRoutes["default/test-route"]
	server.mu.RUnlock()
	if ok {
		t.Error("deleteGRPCRouteInternal() did not delete the route")
	}
}

func TestServer_applyBackendInternal_Success(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.applyBackendInternal(ctx, "test-backend", "default", []byte(`{"test": true}`))
	if err != nil {
		t.Errorf("applyBackendInternal() error = %v", err)
	}

	// Verify the backend was stored
	server.mu.RLock()
	_, ok := server.backends["default/test-backend"]
	server.mu.RUnlock()
	if !ok {
		t.Error("applyBackendInternal() did not store the backend")
	}
}

func TestServer_deleteBackendInternal_Success(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// First add a backend
	server.mu.Lock()
	server.backends["default/test-backend"] = []byte(`{}`)
	server.mu.Unlock()

	// Delete it
	err := server.deleteBackendInternal(ctx, "test-backend", "default")
	if err != nil {
		t.Errorf("deleteBackendInternal() error = %v", err)
	}

	// Verify the backend was deleted
	server.mu.RLock()
	_, ok := server.backends["default/test-backend"]
	server.mu.RUnlock()
	if ok {
		t.Error("deleteBackendInternal() did not delete the backend")
	}
}

func TestServer_applyGRPCBackendInternal_Success(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.applyGRPCBackendInternal(ctx, "test-backend", "default", []byte(`{"test": true}`))
	if err != nil {
		t.Errorf("applyGRPCBackendInternal() error = %v", err)
	}

	// Verify the backend was stored
	server.mu.RLock()
	_, ok := server.grpcBackends["default/test-backend"]
	server.mu.RUnlock()
	if !ok {
		t.Error("applyGRPCBackendInternal() did not store the backend")
	}
}

func TestServer_deleteGRPCBackendInternal_Success_Coverage(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// First add a backend
	server.mu.Lock()
	server.grpcBackends["default/test-backend-cov"] = []byte(`{}`)
	server.mu.Unlock()

	// Delete it
	err := server.deleteGRPCBackendInternal(ctx, "test-backend-cov", "default")
	if err != nil {
		t.Errorf("deleteGRPCBackendInternal() error = %v", err)
	}

	// Verify the backend was deleted
	server.mu.RLock()
	_, ok := server.grpcBackends["default/test-backend-cov"]
	server.mu.RUnlock()
	if ok {
		t.Error("deleteGRPCBackendInternal() did not delete the backend")
	}
}

// ============================================================================
// Server Stop with Timeout Tests
// ============================================================================

func TestServer_Stop_WithGRPCServer(t *testing.T) {
	server := getTestServer(t)

	// Reset state
	server.mu.Lock()
	server.started = false
	server.closed = false
	server.mu.Unlock()

	// Stop should work even without a running gRPC server
	server.Stop()

	// Verify server is marked as closed
	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()

	if !closed {
		t.Error("Stop() should mark server as closed")
	}
}

// ============================================================================
// executeWithRetry Edge Cases
// ============================================================================

func TestServer_executeWithRetry_ImmediateSuccess(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	callCount := 0
	err := server.executeWithRetry(ctx, "test", "resource", func() error {
		callCount++
		return nil
	})

	if err != nil {
		t.Errorf("executeWithRetry() error = %v, want nil", err)
	}
	if callCount != 1 {
		t.Errorf("executeWithRetry() called function %d times, want 1", callCount)
	}
}

func TestServer_executeWithRetry_RetryThenSuccess(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	callCount := 0
	err := server.executeWithRetry(ctx, "test", "resource", func() error {
		callCount++
		if callCount < 2 {
			return errors.New("temporary error")
		}
		return nil
	})

	if err != nil {
		t.Errorf("executeWithRetry() error = %v, want nil", err)
	}
	if callCount < 2 {
		t.Errorf("executeWithRetry() should have retried, called %d times", callCount)
	}
}

// ============================================================================
// Metrics Tests
// ============================================================================

func TestServer_Metrics_NotNil(t *testing.T) {
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
	if server.metrics.retryAttempts == nil {
		t.Error("retryAttempts metric should not be nil")
	}
}

// ============================================================================
// Gateway Connection Tests
// ============================================================================

func TestServer_GatewayConnection_AllFields(t *testing.T) {
	server := getTestServer(t)

	// Register a gateway
	server.RegisterGateway("test-gw", "test-ns")

	// Verify all fields
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
// withContextLock Additional Tests
// ============================================================================

func TestServer_withContextLock_ContextCanceledDuringWait(t *testing.T) {
	server := getTestServer(t)

	// Use a separate mutex for this test to avoid interfering with getTestServer
	var testMu sync.Mutex
	testMu.Lock()

	// Create a context that will be canceled
	ctx, cancel := context.WithCancel(context.Background())

	// Start a goroutine that will try to acquire the lock
	done := make(chan error, 1)
	go func() {
		// Wait for the test mutex to be released, then try to acquire server lock
		testMu.Lock()
		testMu.Unlock()
		unlock, err := server.withContextLock(ctx)
		if unlock != nil {
			unlock()
		}
		done <- err
	}()

	// Cancel the context before releasing the test mutex
	cancel()

	// Release the test mutex to let the goroutine proceed
	testMu.Unlock()

	// Wait for the goroutine to finish
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("withContextLock() error = %v, want context.Canceled", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("withContextLock() did not return in time")
	}
}

func TestServer_withContextLock_MultipleSequential(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// Acquire and release the lock multiple times
	for i := 0; i < 5; i++ {
		unlock, err := server.withContextLock(ctx)
		if err != nil {
			t.Errorf("Iteration %d: withContextLock() error = %v", i, err)
			continue
		}
		if unlock == nil {
			t.Errorf("Iteration %d: unlock function should not be nil", i)
			continue
		}
		unlock()
	}
}

// ============================================================================
// Apply/Delete with Retry Error Paths
// ============================================================================

func TestServer_ApplyAPIRoute_WithRetrySuccess(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// This should succeed on first try
	err := server.ApplyAPIRoute(ctx, "retry-test-route", "default", []byte(`{"test": true}`))
	if err != nil {
		t.Errorf("ApplyAPIRoute() error = %v", err)
	}

	// Verify the route was stored
	server.mu.RLock()
	_, ok := server.apiRoutes["default/retry-test-route"]
	server.mu.RUnlock()
	if !ok {
		t.Error("ApplyAPIRoute() did not store the route")
	}
}

func TestServer_DeleteAPIRoute_WithRetrySuccess(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// First add a route
	_ = server.ApplyAPIRoute(ctx, "retry-delete-route", "default", []byte(`{}`))

	// Delete should succeed
	err := server.DeleteAPIRoute(ctx, "retry-delete-route", "default")
	if err != nil {
		t.Errorf("DeleteAPIRoute() error = %v", err)
	}

	// Verify the route was deleted
	server.mu.RLock()
	_, ok := server.apiRoutes["default/retry-delete-route"]
	server.mu.RUnlock()
	if ok {
		t.Error("DeleteAPIRoute() did not delete the route")
	}
}

func TestServer_ApplyGRPCRoute_WithRetrySuccess(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.ApplyGRPCRoute(ctx, "retry-grpc-route", "default", []byte(`{"test": true}`))
	if err != nil {
		t.Errorf("ApplyGRPCRoute() error = %v", err)
	}

	server.mu.RLock()
	_, ok := server.grpcRoutes["default/retry-grpc-route"]
	server.mu.RUnlock()
	if !ok {
		t.Error("ApplyGRPCRoute() did not store the route")
	}
}

func TestServer_DeleteGRPCRoute_WithRetrySuccess(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	_ = server.ApplyGRPCRoute(ctx, "retry-delete-grpc-route", "default", []byte(`{}`))

	err := server.DeleteGRPCRoute(ctx, "retry-delete-grpc-route", "default")
	if err != nil {
		t.Errorf("DeleteGRPCRoute() error = %v", err)
	}

	server.mu.RLock()
	_, ok := server.grpcRoutes["default/retry-delete-grpc-route"]
	server.mu.RUnlock()
	if ok {
		t.Error("DeleteGRPCRoute() did not delete the route")
	}
}

func TestServer_ApplyBackend_WithRetrySuccess(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.ApplyBackend(ctx, "retry-backend", "default", []byte(`{"test": true}`))
	if err != nil {
		t.Errorf("ApplyBackend() error = %v", err)
	}

	server.mu.RLock()
	_, ok := server.backends["default/retry-backend"]
	server.mu.RUnlock()
	if !ok {
		t.Error("ApplyBackend() did not store the backend")
	}
}

func TestServer_DeleteBackend_WithRetrySuccess(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	_ = server.ApplyBackend(ctx, "retry-delete-backend", "default", []byte(`{}`))

	err := server.DeleteBackend(ctx, "retry-delete-backend", "default")
	if err != nil {
		t.Errorf("DeleteBackend() error = %v", err)
	}

	server.mu.RLock()
	_, ok := server.backends["default/retry-delete-backend"]
	server.mu.RUnlock()
	if ok {
		t.Error("DeleteBackend() did not delete the backend")
	}
}

func TestServer_ApplyGRPCBackend_WithRetrySuccess(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.ApplyGRPCBackend(ctx, "retry-grpc-backend", "default", []byte(`{"test": true}`))
	if err != nil {
		t.Errorf("ApplyGRPCBackend() error = %v", err)
	}

	server.mu.RLock()
	_, ok := server.grpcBackends["default/retry-grpc-backend"]
	server.mu.RUnlock()
	if !ok {
		t.Error("ApplyGRPCBackend() did not store the backend")
	}
}

func TestServer_DeleteGRPCBackend_WithRetrySuccess(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	_ = server.ApplyGRPCBackend(ctx, "retry-delete-grpc-backend", "default", []byte(`{}`))

	err := server.DeleteGRPCBackend(ctx, "retry-delete-grpc-backend", "default")
	if err != nil {
		t.Errorf("DeleteGRPCBackend() error = %v", err)
	}

	server.mu.RLock()
	_, ok := server.grpcBackends["default/retry-delete-grpc-backend"]
	server.mu.RUnlock()
	if ok {
		t.Error("DeleteGRPCBackend() did not delete the backend")
	}
}

// ============================================================================
// Start/Stop Tests - Comprehensive Coverage
// ============================================================================

// Note: TestServer_Start_ContextCancellation tests are in server_test.go
// We can't create new servers here due to Prometheus metrics registration conflicts

func TestServer_Stop_WithNilGRPCServer(t *testing.T) {
	server := getTestServer(t)

	// Reset state
	server.mu.Lock()
	server.started = false
	server.closed = false
	server.grpcServer = nil
	server.mu.Unlock()

	// Stop should work without panic
	server.Stop()

	// Verify server is marked as closed
	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()

	if !closed {
		t.Error("Stop() should mark server as closed")
	}

	// Reset for other tests
	server.mu.Lock()
	server.closed = false
	server.mu.Unlock()
}

func TestServer_Stop_MultipleCallsIdempotent(t *testing.T) {
	server := getTestServer(t)

	// Reset state
	server.mu.Lock()
	server.started = false
	server.closed = false
	server.grpcServer = nil
	server.mu.Unlock()

	// Call Stop multiple times - should be idempotent
	server.Stop()
	server.Stop()
	server.Stop()

	// Verify server is marked as closed
	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()

	if !closed {
		t.Error("Stop() should mark server as closed")
	}

	// Reset for other tests
	server.mu.Lock()
	server.closed = false
	server.mu.Unlock()
}

// ============================================================================
// withContextLock Edge Cases - Additional Coverage
// ============================================================================

func TestServer_withContextLock_ContextCanceledAfterLockAcquired(t *testing.T) {
	server := getTestServer(t)

	// Create a context that we'll cancel after acquiring the lock
	ctx, cancel := context.WithCancel(context.Background())

	// Acquire the lock
	unlock, err := server.withContextLock(ctx)
	if err != nil {
		t.Fatalf("withContextLock() error = %v", err)
	}

	// Cancel the context while holding the lock
	cancel()

	// Unlock should still work
	unlock()

	// Verify we can acquire the lock again
	ctx2 := context.Background()
	unlock2, err := server.withContextLock(ctx2)
	if err != nil {
		t.Errorf("withContextLock() after cancel error = %v", err)
	}
	if unlock2 != nil {
		unlock2()
	}
}

func TestServer_withContextLock_RaceCondition(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// Run many goroutines trying to acquire the lock simultaneously
	var wg sync.WaitGroup
	successCount := int32(0)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := server.withContextLock(ctx)
			if err == nil {
				// Increment counter while holding lock
				successCount++
				time.Sleep(1 * time.Microsecond)
				unlock()
			}
		}()
	}

	wg.Wait()

	// All goroutines should have succeeded
	if successCount != 100 {
		t.Errorf("Expected 100 successful lock acquisitions, got %d", successCount)
	}
}

// ============================================================================
// Apply/Delete Context Cancellation - Additional Coverage
// ============================================================================

func TestServer_ApplyGRPCRoute_ContextDeadlineExceeded_Coverage(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err := server.ApplyGRPCRoute(ctx, "test", "default", []byte(`{}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ApplyGRPCRoute() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestServer_DeleteGRPCRoute_ContextDeadlineExceeded_Coverage(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err := server.DeleteGRPCRoute(ctx, "test", "default")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("DeleteGRPCRoute() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestServer_ApplyBackend_ContextDeadlineExceeded_Coverage(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err := server.ApplyBackend(ctx, "test", "default", []byte(`{}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ApplyBackend() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestServer_DeleteBackend_ContextDeadlineExceeded_Coverage(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err := server.DeleteBackend(ctx, "test", "default")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("DeleteBackend() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestServer_ApplyGRPCBackend_ContextDeadlineExceeded_Coverage(t *testing.T) {
	server := getTestServer(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err := server.ApplyGRPCBackend(ctx, "test", "default", []byte(`{}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ApplyGRPCBackend() error = %v, want context.DeadlineExceeded", err)
	}
}
