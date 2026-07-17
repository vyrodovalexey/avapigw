package gateway

// Regression tests for WP14-ctx: cleanupListenersOnError must honor the
// caller's context instead of detaching the rollback onto
// context.Background().

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// newCleanupTestGateway builds a minimal gateway for cleanup tests.
func newCleanupTestGateway(t *testing.T) *Gateway {
	t.Helper()

	gw, err := New(&config.GatewayConfig{
		Metadata: config.Metadata{Name: "cleanup-ctx-gw"},
		Spec:     config.GatewaySpec{},
	}, WithLogger(observability.NopLogger()))
	require.NoError(t, err)
	return gw
}

// newStartedHTTPListener creates and starts an HTTP listener on a random port.
func newStartedHTTPListener(t *testing.T, name string) *Listener {
	t.Helper()

	listener, err := NewListener(
		config.Listener{Name: name, Port: 0, Protocol: config.ProtocolHTTP},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	require.NoError(t, err)
	require.NoError(t, listener.Start(context.Background()))
	require.True(t, listener.IsRunning())
	return listener
}

// TestCleanupListenersOnError_UsesCallerContext verifies that a live caller
// context flows into the rollback Stop calls and the listener shuts down
// gracefully.
func TestCleanupListenersOnError_UsesCallerContext(t *testing.T) {
	t.Parallel()

	gw := newCleanupTestGateway(t)
	listener := newStartedHTTPListener(t, "cleanup-live-ctx")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	gw.cleanupListenersOnError(ctx, []*Listener{listener}, nil)

	assert.False(t, listener.IsRunning(), "listener must be stopped by rollback cleanup")
}

// TestCleanupListenersOnError_CanceledContext verifies that caller
// cancellation propagates into the rollback path: cleanup neither hangs nor
// panics, and the listener is still torn down (graceful shutdown falls back
// to force close on a canceled context).
func TestCleanupListenersOnError_CanceledContext(t *testing.T) {
	t.Parallel()

	gw := newCleanupTestGateway(t)
	listener := newStartedHTTPListener(t, "cleanup-canceled-ctx")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before cleanup: cancellation must propagate.

	done := make(chan struct{})
	go func() {
		gw.cleanupListenersOnError(ctx, []*Listener{listener}, nil)
		close(done)
	}()

	select {
	case <-done:
		// Cleanup returned promptly despite the canceled context.
	case <-time.After(5 * time.Second):
		t.Fatal("cleanupListenersOnError hung on canceled context")
	}

	assert.False(t, listener.IsRunning(),
		"listener must be force-closed when the rollback context is canceled")
}

// TestCreateListeners_UsesCallerContext exercises the createListeners error
// path end to end: the first listener is created, the second fails, and the
// rollback runs under the caller's context without leaking the first
// listener.
func TestCreateListeners_UsesCallerContext(t *testing.T) {
	t.Parallel()

	gw, err := New(&config.GatewayConfig{
		Metadata: config.Metadata{Name: "cleanup-ctx-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "ok-listener", Port: 0, Protocol: config.ProtocolHTTP},
				// Invalid TLS config forces a creation failure -> rollback.
				{
					Name:     "bad-listener",
					Port:     0,
					Protocol: config.ProtocolHTTPS,
					TLS: &config.ListenerTLSConfig{
						Mode:     "SIMPLE",
						CertFile: "/nonexistent/cert.pem",
						KeyFile:  "/nonexistent/key.pem",
					},
				},
			},
		},
	}, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = gw.createListeners(ctx)
	require.Error(t, err, "createListeners must fail on the invalid listener")
	assert.Empty(t, gw.listeners, "no listeners must be retained after rollback")
}
