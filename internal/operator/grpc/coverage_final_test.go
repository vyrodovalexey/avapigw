// Package grpc provides gRPC server and client for operator-gateway communication.
package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Server Configuration Tests - Additional Coverage
// ============================================================================

func TestDefaultRetryConfig_Final(t *testing.T) {
	cfg := DefaultRetryConfig()
	assert.Equal(t, 3, cfg.MaxAttempts)
	assert.Equal(t, 100*time.Millisecond, cfg.InitialBackoff)
	assert.Equal(t, 5*time.Second, cfg.MaxBackoff)
	assert.Equal(t, 2.0, cfg.Multiplier)
}

func TestRetryConfig_CustomValues_Final(t *testing.T) {
	cfg := &RetryConfig{
		MaxAttempts:    5,
		InitialBackoff: 200 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		Multiplier:     3.0,
	}

	assert.Equal(t, 5, cfg.MaxAttempts)
	assert.Equal(t, 200*time.Millisecond, cfg.InitialBackoff)
	assert.Equal(t, 10*time.Second, cfg.MaxBackoff)
	assert.Equal(t, 3.0, cfg.Multiplier)
}

// ============================================================================
// Server Apply/Delete Tests - Additional Coverage
// ============================================================================

func TestServer_ApplyAPIRoute_ContextCanceled_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.ApplyAPIRoute(ctx, "test-route", "test-ns", []byte(`{}`))
	assert.Error(t, err)
}

func TestServer_DeleteAPIRoute_ContextCanceled_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.DeleteAPIRoute(ctx, "test-route", "test-ns")
	assert.Error(t, err)
}

func TestServer_ApplyGRPCRoute_ContextCanceled_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.ApplyGRPCRoute(ctx, "test-route", "test-ns", []byte(`{}`))
	assert.Error(t, err)
}

func TestServer_DeleteGRPCRoute_ContextCanceled_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.DeleteGRPCRoute(ctx, "test-route", "test-ns")
	assert.Error(t, err)
}

func TestServer_ApplyBackend_ContextCanceled_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.ApplyBackend(ctx, "test-backend", "test-ns", []byte(`{}`))
	assert.Error(t, err)
}

func TestServer_DeleteBackend_ContextCanceled_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.DeleteBackend(ctx, "test-backend", "test-ns")
	assert.Error(t, err)
}

func TestServer_ApplyGRPCBackend_ContextCanceled_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.ApplyGRPCBackend(ctx, "test-backend", "test-ns", []byte(`{}`))
	assert.Error(t, err)
}

func TestServer_DeleteGRPCBackend_ContextCanceled_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.DeleteGRPCBackend(ctx, "test-backend", "test-ns")
	assert.Error(t, err)
}

// ============================================================================
// Server Apply/Delete Tests - Success Cases
// ============================================================================

func TestServer_ApplyAPIRoute_Success_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.ApplyAPIRoute(ctx, "test-route", "test-ns", []byte(`{"match":[]}`))
	assert.NoError(t, err)

	// Verify it was stored
	server.mu.RLock()
	_, exists := server.apiRoutes["test-ns/test-route"]
	server.mu.RUnlock()
	assert.True(t, exists)
}

func TestServer_DeleteAPIRoute_Success_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// First apply
	err := server.ApplyAPIRoute(ctx, "test-route", "test-ns", []byte(`{"match":[]}`))
	require.NoError(t, err)

	// Then delete
	err = server.DeleteAPIRoute(ctx, "test-route", "test-ns")
	assert.NoError(t, err)

	// Verify it was deleted
	server.mu.RLock()
	_, exists := server.apiRoutes["test-ns/test-route"]
	server.mu.RUnlock()
	assert.False(t, exists)
}

func TestServer_ApplyGRPCRoute_Success_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.ApplyGRPCRoute(ctx, "test-route", "test-ns", []byte(`{"match":[]}`))
	assert.NoError(t, err)

	// Verify it was stored
	server.mu.RLock()
	_, exists := server.grpcRoutes["test-ns/test-route"]
	server.mu.RUnlock()
	assert.True(t, exists)
}

func TestServer_DeleteGRPCRoute_Success_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// First apply
	err := server.ApplyGRPCRoute(ctx, "test-route", "test-ns", []byte(`{"match":[]}`))
	require.NoError(t, err)

	// Then delete
	err = server.DeleteGRPCRoute(ctx, "test-route", "test-ns")
	assert.NoError(t, err)

	// Verify it was deleted
	server.mu.RLock()
	_, exists := server.grpcRoutes["test-ns/test-route"]
	server.mu.RUnlock()
	assert.False(t, exists)
}

func TestServer_ApplyBackend_Success_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.ApplyBackend(ctx, "test-backend", "test-ns", []byte(`{"hosts":[]}`))
	assert.NoError(t, err)

	// Verify it was stored
	server.mu.RLock()
	_, exists := server.backends["test-ns/test-backend"]
	server.mu.RUnlock()
	assert.True(t, exists)
}

func TestServer_DeleteBackend_Success_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// First apply
	err := server.ApplyBackend(ctx, "test-backend", "test-ns", []byte(`{"hosts":[]}`))
	require.NoError(t, err)

	// Then delete
	err = server.DeleteBackend(ctx, "test-backend", "test-ns")
	assert.NoError(t, err)

	// Verify it was deleted
	server.mu.RLock()
	_, exists := server.backends["test-ns/test-backend"]
	server.mu.RUnlock()
	assert.False(t, exists)
}

func TestServer_ApplyGRPCBackend_Success_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.ApplyGRPCBackend(ctx, "test-backend", "test-ns", []byte(`{"hosts":[]}`))
	assert.NoError(t, err)

	// Verify it was stored
	server.mu.RLock()
	_, exists := server.grpcBackends["test-ns/test-backend"]
	server.mu.RUnlock()
	assert.True(t, exists)
}

func TestServer_DeleteGRPCBackend_Success_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	// First apply
	err := server.ApplyGRPCBackend(ctx, "test-backend", "test-ns", []byte(`{"hosts":[]}`))
	require.NoError(t, err)

	// Then delete
	err = server.DeleteGRPCBackend(ctx, "test-backend", "test-ns")
	assert.NoError(t, err)

	// Verify it was deleted
	server.mu.RLock()
	_, exists := server.grpcBackends["test-ns/test-backend"]
	server.mu.RUnlock()
	assert.False(t, exists)
}

// ============================================================================
// Gateway Registration Tests - Additional Coverage
// ============================================================================

func TestServer_RegisterGateway_Multiple_Final(t *testing.T) {
	server := getTestServer(t)

	server.RegisterGateway("gw1", "ns1")
	server.RegisterGateway("gw2", "ns1")
	server.RegisterGateway("gw3", "ns2")

	assert.Equal(t, 3, server.GetGatewayCount())
}

func TestServer_UnregisterGateway_Multiple_Final(t *testing.T) {
	server := getTestServer(t)

	server.RegisterGateway("gw1", "ns1")
	server.RegisterGateway("gw2", "ns1")
	server.RegisterGateway("gw3", "ns2")

	server.UnregisterGateway("gw1", "ns1")
	assert.Equal(t, 2, server.GetGatewayCount())

	server.UnregisterGateway("gw2", "ns1")
	assert.Equal(t, 1, server.GetGatewayCount())

	server.UnregisterGateway("gw3", "ns2")
	assert.Equal(t, 0, server.GetGatewayCount())
}

func TestServer_UpdateGatewayHeartbeat_Existing_Final(t *testing.T) {
	server := getTestServer(t)

	server.RegisterGateway("gw1", "ns1")

	server.mu.RLock()
	firstLastSeen := server.gateways["ns1/gw1"].lastSeen
	server.mu.RUnlock()

	time.Sleep(10 * time.Millisecond)

	server.UpdateGatewayHeartbeat("gw1", "ns1")

	server.mu.RLock()
	secondLastSeen := server.gateways["ns1/gw1"].lastSeen
	server.mu.RUnlock()

	assert.True(t, secondLastSeen.After(firstLastSeen))
}

// ============================================================================
// GetAllConfigs Tests - Additional Coverage
// ============================================================================

func TestServer_GetAllConfigs_Empty_Final(t *testing.T) {
	server := getTestServer(t)

	configsJSON, err := server.GetAllConfigs()
	assert.NoError(t, err)
	assert.NotEmpty(t, configsJSON)
}

func TestServer_GetAllConfigs_WithData_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	_ = server.ApplyAPIRoute(ctx, "api-route-1", "ns1", []byte(`{"match":[]}`))
	_ = server.ApplyGRPCRoute(ctx, "grpc-route-1", "ns1", []byte(`{"match":[]}`))
	_ = server.ApplyBackend(ctx, "backend-1", "ns1", []byte(`{"hosts":[]}`))
	_ = server.ApplyGRPCBackend(ctx, "grpc-backend-1", "ns1", []byte(`{"hosts":[]}`))

	configsJSON, err := server.GetAllConfigs()
	assert.NoError(t, err)
	assert.NotEmpty(t, configsJSON)
	assert.Contains(t, string(configsJSON), "apiRoutes")
	assert.Contains(t, string(configsJSON), "grpcRoutes")
	assert.Contains(t, string(configsJSON), "backends")
	assert.Contains(t, string(configsJSON), "grpcBackends")
}

// ============================================================================
// withContextLock Tests - Additional Coverage
// ============================================================================

func TestServer_withContextLock_Success_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	unlock, err := server.withContextLock(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, unlock)

	// Should be able to unlock
	unlock()
}

func TestServer_withContextLock_ContextAlreadyCanceled_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	unlock, err := server.withContextLock(ctx)
	assert.Error(t, err)
	assert.Nil(t, unlock)
}

// ============================================================================
// checkContextCancellation Tests - Additional Coverage
// ============================================================================

func TestServer_checkContextCancellation_Valid_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	err := server.checkContextCancellation(ctx, "TestOp")
	assert.NoError(t, err)
}

func TestServer_checkContextCancellation_Canceled_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.checkContextCancellation(ctx, "TestOp")
	assert.Error(t, err)
}

func TestServer_checkContextCancellation_DeadlineExceeded_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err := server.checkContextCancellation(ctx, "TestOp")
	assert.Error(t, err)
}

// ============================================================================
// recordCanceledOperation Tests - Additional Coverage
// ============================================================================

func TestServer_recordCanceledOperation_Canceled_Final(t *testing.T) {
	server := getTestServer(t)

	// Should not panic
	server.recordCanceledOperation("TestOp", context.Canceled)
}

func TestServer_recordCanceledOperation_DeadlineExceeded_Final(t *testing.T) {
	server := getTestServer(t)

	// Should not panic
	server.recordCanceledOperation("TestOp", context.DeadlineExceeded)
}

func TestServer_recordCanceledOperation_Unknown_Final(t *testing.T) {
	server := getTestServer(t)

	// Should not panic
	server.recordCanceledOperation("TestOp", nil)
}

// ============================================================================
// executeWithRetry Tests - Additional Coverage
// ============================================================================

func TestServer_executeWithRetry_Success_Final(t *testing.T) {
	server := getTestServer(t)
	ctx := context.Background()

	callCount := 0
	err := server.executeWithRetry(ctx, "test", "resource", func() error {
		callCount++
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 1, callCount)
}

func TestServer_executeWithRetry_ContextCanceled_Final(t *testing.T) {
	server := getTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := server.executeWithRetry(ctx, "test", "resource", func() error {
		return nil
	})

	assert.Error(t, err)
}

// ============================================================================
// Server Lifecycle Tests - Additional Coverage
// ============================================================================

func TestServer_Stop_NotStarted_Final(t *testing.T) {
	server := getTestServer(t)

	// Should not panic
	server.Stop()

	// Verify closed
	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()

	assert.True(t, closed)
}

func TestServer_Stop_AlreadyClosed_Final(t *testing.T) {
	server := getTestServer(t)

	// Close first time
	server.Stop()

	// Close second time - should not panic
	server.Stop()
}

// ============================================================================
// ServerConfig Tests - Additional Coverage
// ============================================================================

func TestServerConfig_AllFields_Final(t *testing.T) {
	cfg := &ServerConfig{
		Port:                 9444,
		Certificate:          nil,
		CertManager:          nil,
		MaxConcurrentStreams: 100,
		MaxRecvMsgSize:       4 * 1024 * 1024,
		MaxSendMsgSize:       4 * 1024 * 1024,
		RetryConfig: &RetryConfig{
			MaxAttempts:    5,
			InitialBackoff: 200 * time.Millisecond,
			MaxBackoff:     10 * time.Second,
			Multiplier:     3.0,
		},
	}

	assert.Equal(t, 9444, cfg.Port)
	assert.Nil(t, cfg.Certificate)
	assert.Nil(t, cfg.CertManager)
	assert.Equal(t, uint32(100), cfg.MaxConcurrentStreams)
	assert.Equal(t, 4*1024*1024, cfg.MaxRecvMsgSize)
	assert.Equal(t, 4*1024*1024, cfg.MaxSendMsgSize)
	assert.NotNil(t, cfg.RetryConfig)
}

// ============================================================================
// gatewayConnection Tests - Additional Coverage
// ============================================================================

func TestGatewayConnection_Fields_Final(t *testing.T) {
	now := time.Now()
	conn := &gatewayConnection{
		name:        "test-gateway",
		namespace:   "test-namespace",
		connectedAt: now,
		lastSeen:    now,
	}

	assert.Equal(t, "test-gateway", conn.name)
	assert.Equal(t, "test-namespace", conn.namespace)
	assert.Equal(t, now, conn.connectedAt)
	assert.Equal(t, now, conn.lastSeen)
}

// ============================================================================
// withContextLock Tests - Context Cancellation During Lock Acquisition
// NOTE: This test is commented out because it modifies shared server state
// and can cause race conditions with other tests that use getTestServer().
// The withContextLock() function's context cancellation path is tested
// in server_start_stop_test.go.
// ============================================================================

// ============================================================================
// Server Start Tests - TLS Configuration
// NOTE: These tests are commented out because they modify shared server state
// and can cause race conditions with other tests that use getTestServer().
// The Start() function's TLS and listen error paths are tested in isolation
// in server_start_stop_test.go.
// ============================================================================

// ============================================================================
// Server Stop Tests - Graceful Shutdown Timeout
// NOTE: These tests are commented out because they modify shared server state
// and can cause race conditions with other tests that use getTestServer().
// The Stop() function is tested in server_start_stop_test.go.
// ============================================================================
