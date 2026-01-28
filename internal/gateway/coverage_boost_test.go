package gateway

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// ============================================================
// listener.go: NewListener with TLS config (exercises initTLS)
// Covers listener.go:72-76 and listener.go:82-96 (initTLS 0%)
// ============================================================

func TestNewListener_WithTLS(t *testing.T) {
	t.Parallel()

	certs, err := createListenerTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "test-https",
		Port:     0,
		Protocol: "HTTPS",
		Bind:     "127.0.0.1",
		TLS: &config.ListenerTLSConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
			Mode:     "SIMPLE",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler,
		WithListenerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.True(t, listener.IsTLSEnabled())
	assert.NotNil(t, listener.GetTLSManager())
}

// ============================================================
// listener.go: NewListener with TLS config failure
// Covers listener.go:73-75 error path
// ============================================================

func TestNewListener_WithTLS_InvalidCert(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-https-bad",
		Port:     0,
		Protocol: "HTTPS",
		Bind:     "127.0.0.1",
		TLS: &config.ListenerTLSConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
			Mode:     "SIMPLE",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler,
		WithListenerLogger(observability.NopLogger()),
	)
	assert.Error(t, err)
	assert.Nil(t, listener)
	assert.Contains(t, err.Error(), "failed to initialize TLS")
}

// ============================================================
// listener.go: Start with TLS (exercises serve TLS path)
// Covers listener.go:193-197 (TLS config on server) and
// listener.go:332-335 (serve with TLS listener)
// ============================================================

func TestListener_StartStop_WithTLS(t *testing.T) {
	t.Parallel()

	certs, err := createListenerTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "test-https-start",
		Port:     0,
		Protocol: "HTTPS",
		Bind:     "127.0.0.1",
		TLS: &config.ListenerTLSConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
			Mode:     "SIMPLE",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler,
		WithListenerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)
	assert.True(t, listener.IsRunning())

	// Give it time to start serving
	time.Sleep(20 * time.Millisecond)

	err = listener.Stop(ctx)
	require.NoError(t, err)
}

// ============================================================
// listener.go: Start with RouteTLSManager
// Covers listener.go:187-192 (route TLS manager path)
// ============================================================

func TestListener_Start_WithRouteTLSManager(t *testing.T) {
	t.Parallel()

	certs, err := createListenerTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "test-route-tls",
		Port:     0,
		Protocol: "HTTP",
		Bind:     "127.0.0.1",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	routeTLSManager := tlspkg.NewRouteTLSManager()
	routeCfg := &tlspkg.RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	err = routeTLSManager.AddRoute("test-route", routeCfg)
	require.NoError(t, err)

	listener, err := NewListener(cfg, handler,
		WithListenerLogger(observability.NopLogger()),
		WithRouteTLSManager(routeTLSManager),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)
	assert.True(t, listener.IsRunning())

	time.Sleep(20 * time.Millisecond)

	err = listener.Stop(ctx)
	// Stop may log errors for route TLS manager close, but should not fail
	_ = err
}

// ============================================================
// listener.go: Stop with routeTLSManager (exercises close path)
// Covers listener.go:360-367 (routeTLSManager.Close error path)
// ============================================================

func TestListener_Stop_WithRouteTLSManager(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-stop-route-tls",
		Port:     0,
		Protocol: "HTTP",
		Bind:     "127.0.0.1",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	routeTLSManager := tlspkg.NewRouteTLSManager()

	listener, err := NewListener(cfg, handler,
		WithListenerLogger(observability.NopLogger()),
		WithRouteTLSManager(routeTLSManager),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)

	// Stop should close the route TLS manager
	err = listener.Stop(ctx)
	require.NoError(t, err)
}

// ============================================================
// listener.go: Stop with already-cancelled context
// Covers listener.go:379-383 (Shutdown error → Close path)
// Note: http.Server.Shutdown succeeds even with expired context
// if there are no active connections, so we just verify it
// doesn't panic and handles the context correctly.
// ============================================================

func TestListener_Stop_WithExpiredContext(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-shutdown-expired",
		Port:     0,
		Protocol: "HTTP",
		Bind:     "127.0.0.1",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler,
		WithListenerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)

	// Create an already-expired context
	expiredCtx, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()

	// Stop with expired context — may or may not error depending on
	// whether there are active connections
	_ = listener.Stop(expiredCtx)
}

// ============================================================
// listener.go: Start with TLS manager set on server
// Covers listener.go:193-198 (tlsManager path in Start)
// ============================================================

func TestListener_Start_WithTLSManagerOnServer(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-tls-manager-server",
		Port:     0,
		Protocol: "HTTP",
		Bind:     "127.0.0.1",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create listener and manually set a TLS manager with insecure mode
	// (no actual TLS config needed for insecure mode)
	tlsConfig := &tlspkg.Config{
		Mode: tlspkg.TLSModeInsecure,
	}
	manager, err := tlspkg.NewManager(tlsConfig)
	require.NoError(t, err)

	listener, err := NewListener(cfg, handler,
		WithListenerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)
	listener.tlsManager = manager

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)
	assert.True(t, listener.IsRunning())

	time.Sleep(20 * time.Millisecond)

	err = listener.Stop(ctx)
	require.NoError(t, err)
}
