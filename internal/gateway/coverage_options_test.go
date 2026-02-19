package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================================
// WithGatewayAuthMetrics option
// ============================================================================

func TestWithGatewayAuthMetrics_Option(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec:     config.GatewaySpec{},
	}

	metrics := &auth.Metrics{}
	gw, err := New(cfg, WithGatewayAuthMetrics(metrics))
	require.NoError(t, err)
	assert.Equal(t, metrics, gw.authMetrics)
}

// ============================================================================
// WithGatewayVaultClient option — test that the option function sets the field
// ============================================================================

func TestWithGatewayVaultClient_Option(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec:     config.GatewaySpec{},
	}

	// Pass nil vault client — the option should still set the field
	gw, err := New(cfg, WithGatewayVaultClient(nil))
	require.NoError(t, err)
	assert.Nil(t, gw.vaultClient)
}

// ============================================================================
// WithGRPCAuthMetrics option
// ============================================================================

func TestWithGRPCAuthMetrics_Option(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-grpc",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	metrics := &auth.Metrics{}
	listener, err := NewGRPCListener(cfg, WithGRPCAuthMetrics(metrics))
	require.NoError(t, err)
	assert.Equal(t, metrics, listener.authMetrics)
}

// ============================================================================
// WithGRPCVaultClient option
// ============================================================================

func TestWithGRPCVaultClient_Option(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-grpc",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	// Pass nil vault client — the option should still set the field
	listener, err := NewGRPCListener(cfg, WithGRPCVaultClient(nil))
	require.NoError(t, err)
	assert.Nil(t, listener.vaultClient)
}

// ============================================================================
// cleanupListenersOnError
// ============================================================================

func TestCleanupListenersOnError_EmptyLists(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec:     config.GatewaySpec{},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Should not panic with empty lists
	gw.cleanupListenersOnError(nil, nil)
	gw.cleanupListenersOnError([]*Listener{}, []*GRPCListener{})
}

// ============================================================================
// stopListeners with context cancellation
// ============================================================================

func TestStopListeners_WithCancelledContext(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec:     config.GatewaySpec{},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should not panic or hang with cancelled context and no listeners
	gw.stopListeners(ctx)
}

func TestStopListeners_WithTimeout(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec:     config.GatewaySpec{},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Should complete without hanging
	gw.stopListeners(ctx)
}

// ============================================================================
// Gateway State tests
// ============================================================================

func TestGateway_StateString_Coverage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state    State
		expected string
	}{
		{StateStopped, "stopped"},
		{StateStarting, "starting"},
		{StateRunning, "running"},
		{StateStopping, "stopping"},
		{State(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

// ============================================================================
// GetListeners / GetGRPCListeners
// ============================================================================

func TestGateway_GetListeners_Empty(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec:     config.GatewaySpec{},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	assert.Nil(t, gw.GetListeners())
	assert.Nil(t, gw.GetGRPCListeners())
}
