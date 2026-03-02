// Package grpc provides gRPC server and client for operator-gateway communication.
package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"google.golang.org/grpc"
)

// ============================================================================
// StopWithContext Tests - Forced Stop Path
// ============================================================================

func TestServer_StopWithContext_AlreadyClosed(t *testing.T) {
	server := getTestServer(t)

	// Mark as closed
	server.mu.Lock()
	originalClosed := server.closed
	server.closed = true
	server.mu.Unlock()

	defer func() {
		server.mu.Lock()
		server.closed = originalClosed
		server.mu.Unlock()
	}()

	ctx := context.Background()
	err := server.StopWithContext(ctx)
	assert.NoError(t, err, "StopWithContext on already-closed server should return nil")
}

func TestServer_StopWithContext_NilGRPCServer(t *testing.T) {
	server := getTestServer(t)

	// Reset state
	server.mu.Lock()
	originalClosed := server.closed
	originalGRPC := server.grpcServer
	server.closed = false
	server.grpcServer = nil
	server.mu.Unlock()

	defer func() {
		server.mu.Lock()
		server.closed = originalClosed
		server.grpcServer = originalGRPC
		server.mu.Unlock()
	}()

	ctx := context.Background()
	err := server.StopWithContext(ctx)
	assert.NoError(t, err, "StopWithContext with nil grpcServer should return nil")

	// Verify server is marked as closed
	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()
	assert.True(t, closed, "server should be marked as closed")
}

func TestServer_StopWithContext_ExpiredContext_ForcedStop(t *testing.T) {
	server := getTestServer(t)

	// Create a real gRPC server that hasn't started serving
	// (GracefulStop will block until Serve is called, so the context will expire)
	grpcSrv := grpc.NewServer()

	// Reset state
	server.mu.Lock()
	originalClosed := server.closed
	originalGRPC := server.grpcServer
	server.closed = false
	server.grpcServer = grpcSrv
	server.mu.Unlock()

	defer func() {
		server.mu.Lock()
		server.closed = originalClosed
		server.grpcServer = originalGRPC
		server.mu.Unlock()
	}()

	// Use an already-expired context to force the stop path
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // Ensure context is expired

	err := server.StopWithContext(ctx)
	assert.Error(t, err, "StopWithContext with expired context should return error")
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	// Verify server is marked as closed
	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()
	assert.True(t, closed, "server should be marked as closed after forced stop")
}

func TestServer_StopWithContext_GracefulShutdown(t *testing.T) {
	server := getTestServer(t)

	// Reset state
	server.mu.Lock()
	originalClosed := server.closed
	originalGRPC := server.grpcServer
	server.closed = false
	server.grpcServer = nil // nil grpcServer takes the early return path
	server.mu.Unlock()

	defer func() {
		server.mu.Lock()
		server.closed = originalClosed
		server.grpcServer = originalGRPC
		server.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := server.StopWithContext(ctx)
	assert.NoError(t, err, "StopWithContext with nil grpcServer should succeed gracefully")
}

// ============================================================================
// NotifyConfigChanged / WaitForConfigChange Tests
// ============================================================================

func TestServer_NotifyConfigChanged_WakesWaiters(t *testing.T) {
	server := getTestServer(t)

	ch := server.WaitForConfigChange()

	// Notify should close the channel
	server.NotifyConfigChanged()

	select {
	case <-ch:
		// Expected: channel was closed
	case <-time.After(1 * time.Second):
		t.Error("WaitForConfigChange channel was not closed after NotifyConfigChanged")
	}
}

func TestServer_WaitForConfigChange_NewChannelAfterNotify(t *testing.T) {
	server := getTestServer(t)

	ch1 := server.WaitForConfigChange()
	server.NotifyConfigChanged()

	// After notification, a new channel should be returned
	ch2 := server.WaitForConfigChange()
	assert.NotEqual(t, ch1, ch2, "new channel should be created after notification")

	// ch1 should be closed
	select {
	case <-ch1:
		// Expected
	default:
		t.Error("old channel should be closed")
	}

	// ch2 should not be closed yet
	select {
	case <-ch2:
		t.Error("new channel should not be closed yet")
	default:
		// Expected
	}
}
