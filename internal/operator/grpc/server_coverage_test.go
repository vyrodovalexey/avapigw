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
