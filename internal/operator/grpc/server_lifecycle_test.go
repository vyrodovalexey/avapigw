// Package grpc provides lifecycle tests for the gRPC server Start/Stop methods.
// These tests use NewServerWithRegistry to avoid duplicate Prometheus metric registration.
package grpc

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
)

// newTestServerWithRegistry creates a new server with a fresh Prometheus registry.
func newTestServerWithRegistry(t *testing.T, port int) *Server {
	t.Helper()
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{
		Port: port,
	}, reg)
	require.NoError(t, err)
	return server
}

// getFreePort returns a free TCP port on localhost.
func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// ============================================================================
// Start Tests - Full lifecycle
// ============================================================================

func TestServer_Start_ContextCanceled_Lifecycle(t *testing.T) {
	port := getFreePort(t)
	server := newTestServerWithRegistry(t, port)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err := server.Start(ctx)
	// Should return context.Canceled after graceful stop
	assert.ErrorIs(t, err, context.Canceled)
}

func TestServer_Start_WithTLS_Lifecycle(t *testing.T) {
	// Create a self-signed cert manager
	certManager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer certManager.Close()

	ctx := context.Background()
	serverCert, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)

	port := getFreePort(t)
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{
		Port:        port,
		Certificate: serverCert,
		CertManager: certManager,
	}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err = server.Start(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestServer_Start_WithTLS_NoCertManager_Lifecycle(t *testing.T) {
	// Create a self-signed cert manager just to get a certificate
	certManager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	serverCert, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)
	certManager.Close()

	port := getFreePort(t)
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{
		Port:        port,
		Certificate: serverCert,
		CertManager: nil, // No cert manager - skip client CA
	}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err = server.Start(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestServer_Start_ListenError_Lifecycle(t *testing.T) {
	// Occupy a port first
	port := getFreePort(t)
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	require.NoError(t, err)
	defer listener.Close()

	server := newTestServerWithRegistry(t, port)

	ctx := context.Background()
	err = server.Start(ctx)
	// Should fail because port is already in use
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen")
}

// ============================================================================
// Stop Tests - Full lifecycle
// ============================================================================

func TestServer_Stop_WithRunningServer_Lifecycle(t *testing.T) {
	port := getFreePort(t)
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{
		Port: port,
	}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Stop should work
	server.Stop()

	// Verify closed
	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()
	assert.True(t, closed)

	// Cancel context to clean up
	cancel()
}

func TestServer_Stop_DoubleStop_Lifecycle(t *testing.T) {
	port := getFreePort(t)
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{
		Port: port,
	}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in background
	go func() {
		_ = server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// First stop
	server.Stop()

	// Second stop should be a no-op (already closed)
	server.Stop()

	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()
	assert.True(t, closed)

	cancel()
}

// ============================================================================
// NewServerWithRegistry Tests
// ============================================================================

func TestNewServerWithRegistry_NilConfig(t *testing.T) {
	reg := prometheus.NewRegistry()
	_, err := NewServerWithRegistry(nil, reg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

func TestNewServerWithRegistry_DefaultValues(t *testing.T) {
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	assert.Equal(t, DefaultPort, server.config.Port)
	assert.Equal(t, uint32(DefaultMaxConcurrentStreams), server.config.MaxConcurrentStreams)
	assert.Equal(t, DefaultMaxMessageSize, server.config.MaxRecvMsgSize)
	assert.Equal(t, DefaultMaxMessageSize, server.config.MaxSendMsgSize)
}

func TestNewServerWithRegistry_CustomRetryConfig(t *testing.T) {
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{
		Port: 9444,
		RetryConfig: &RetryConfig{
			MaxAttempts:    5,
			InitialBackoff: 200 * time.Millisecond,
			MaxBackoff:     10 * time.Second,
			Multiplier:     3.0,
		},
	}, reg)
	require.NoError(t, err)

	assert.Equal(t, 5, server.retryConfig.MaxRetries)
	assert.Equal(t, 200*time.Millisecond, server.retryConfig.InitialBackoff)
	assert.Equal(t, 10*time.Second, server.retryConfig.MaxBackoff)
}

func TestNewServerWithRegistry_CustomPort(t *testing.T) {
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{
		Port: 12345,
	}, reg)
	require.NoError(t, err)
	assert.Equal(t, 12345, server.config.Port)
}

func TestNewServerWithRegistry_CustomMessageSizes(t *testing.T) {
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{
		MaxRecvMsgSize:       8 * 1024 * 1024,
		MaxSendMsgSize:       8 * 1024 * 1024,
		MaxConcurrentStreams: 200,
	}, reg)
	require.NoError(t, err)
	assert.Equal(t, 8*1024*1024, server.config.MaxRecvMsgSize)
	assert.Equal(t, 8*1024*1024, server.config.MaxSendMsgSize)
	assert.Equal(t, uint32(200), server.config.MaxConcurrentStreams)
}

// ============================================================================
// withContextLock - context canceled during lock acquisition
// ============================================================================

func TestServer_withContextLock_CanceledDuringAcquisition_Lifecycle(t *testing.T) {
	port := getFreePort(t)
	server := newTestServerWithRegistry(t, port)

	// Hold the lock
	server.mu.Lock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Try to acquire lock - should fail due to timeout while waiting
	unlock, err := server.withContextLock(ctx)

	// Release the lock we held
	server.mu.Unlock()

	assert.Error(t, err)
	assert.Nil(t, unlock)
}

func TestServer_withContextLock_ContextCanceledAfterAcquire_Lifecycle(t *testing.T) {
	port := getFreePort(t)
	server := newTestServerWithRegistry(t, port)

	// This tests the path where context is checked after lock acquisition
	ctx := context.Background()
	unlock, err := server.withContextLock(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, unlock)
	unlock()
}
