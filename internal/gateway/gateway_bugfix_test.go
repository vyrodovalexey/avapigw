package gateway

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// ============================================================================
// WithAuditLogger option tests (0% -> 100%)
// ============================================================================

func TestWithAuditLogger(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-audit-logger"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	auditLogger := audit.NewNoopLogger()

	gw, err := New(cfg, WithAuditLogger(auditLogger))
	require.NoError(t, err)
	assert.NotNil(t, gw)
	assert.Equal(t, auditLogger, gw.auditLogger)
}

func TestWithAuditLogger_Nil(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-audit-logger-nil"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg, WithAuditLogger(nil))
	require.NoError(t, err)
	assert.NotNil(t, gw)
	assert.Nil(t, gw.auditLogger)
}

// ============================================================================
// WithMetricsRegistry option tests (0% -> 100%)
// ============================================================================

func TestWithMetricsRegistry(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-metrics-registry"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	registry := prometheus.NewRegistry()

	gw, err := New(cfg, WithMetricsRegistry(registry))
	require.NoError(t, err)
	assert.NotNil(t, gw)
	assert.Equal(t, registry, gw.metricsRegistry)
}

func TestWithMetricsRegistry_Nil(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-metrics-registry-nil"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg, WithMetricsRegistry(nil))
	require.NoError(t, err)
	assert.NotNil(t, gw)
	assert.Nil(t, gw.metricsRegistry)
}

// ============================================================================
// WithGatewayTLSMetrics option tests (0% -> 100%)
// ============================================================================

func TestWithGatewayTLSMetrics(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-tls-metrics"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	tlsMetrics := tlspkg.NewMetrics("test")

	gw, err := New(cfg, WithGatewayTLSMetrics(tlsMetrics))
	require.NoError(t, err)
	assert.NotNil(t, gw)
	assert.Equal(t, tlsMetrics, gw.tlsMetrics)
}

func TestWithGatewayTLSMetrics_Nil(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-tls-metrics-nil"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg, WithGatewayTLSMetrics(nil))
	require.NoError(t, err)
	assert.NotNil(t, gw)
	assert.Nil(t, gw.tlsMetrics)
}

// ============================================================================
// GetGRPCListeners tests
// ============================================================================

func TestGetGRPCListeners_ReturnsCorrectListeners(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-grpc-listeners"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
				{Name: "grpc1", Port: 0, Protocol: config.ProtocolGRPC},
				{Name: "grpc2", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	grpcListeners := gw.GetGRPCListeners()
	assert.Len(t, grpcListeners, 2)

	// Verify names
	names := make([]string, len(grpcListeners))
	for i, l := range grpcListeners {
		names[i] = l.Name()
	}
	assert.Contains(t, names, "grpc1")
	assert.Contains(t, names, "grpc2")
}

func TestGetGRPCListeners_BeforeStart(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-grpc-before-start"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Before Start, grpcListeners is nil
	grpcListeners := gw.GetGRPCListeners()
	assert.Nil(t, grpcListeners)
}

// ============================================================================
// WithGRPCMetricsRegistry option tests (0% -> 100%)
// ============================================================================

func TestWithGRPCMetricsRegistry(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	cfg := config.Listener{
		Name:     "grpc-test",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg, WithGRPCMetricsRegistry(registry))
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, registry, listener.metricsRegistry)
}

func TestWithGRPCMetricsRegistry_Nil(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-test-nil",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg, WithGRPCMetricsRegistry(nil))
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Nil(t, listener.metricsRegistry)
}

// ============================================================================
// getOrCreateGRPCMetrics tests (66.7% -> 100%)
// ============================================================================

func TestGetOrCreateGRPCMetrics_WithRegistry(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-grpc-metrics"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithMetricsRegistry(registry),
	)
	require.NoError(t, err)

	// First call should create metrics
	metrics := gw.getOrCreateGRPCMetrics()
	assert.NotNil(t, metrics)

	// Second call should return same instance (sync.Once)
	metrics2 := gw.getOrCreateGRPCMetrics()
	assert.Equal(t, metrics, metrics2)
}

func TestGetOrCreateGRPCMetrics_WithoutRegistry(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-grpc-metrics-nil"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Without registry, should return nil
	metrics := gw.getOrCreateGRPCMetrics()
	assert.Nil(t, metrics)
}

// ============================================================================
// createGRPCListener with metrics registry (66.7% -> higher)
// ============================================================================

func TestGateway_StartWithGRPCListener_WithMetricsRegistry(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-grpc-with-registry"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithMetricsRegistry(registry),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	assert.Len(t, gw.GetGRPCListeners(), 1)
}

func TestGateway_StartWithGRPCListener_WithAuditLogger(t *testing.T) {
	t.Parallel()

	auditLogger := audit.NewNoopLogger()
	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-grpc-with-audit"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithAuditLogger(auditLogger),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	assert.Len(t, gw.GetGRPCListeners(), 1)
}

// ============================================================================
// cleanupListenersOnError tests (50% -> higher)
// ============================================================================

func TestCleanupListenersOnError_WithGRPCListeners(t *testing.T) {
	t.Parallel()

	// Create a config with an HTTP listener followed by a gRPC listener with invalid TLS
	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-cleanup-grpc"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc-ok", Port: 0, Protocol: config.ProtocolGRPC},
				{
					Name:     "grpc-fail",
					Port:     0,
					Protocol: config.ProtocolGRPC,
					GRPC: &config.GRPCListenerConfig{
						TLS: &config.TLSConfig{
							Enabled:  true,
							Mode:     config.TLSModeSimple,
							CertFile: "/nonexistent/cert.pem",
							KeyFile:  "/nonexistent/key.pem",
						},
					},
				},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	// Should fail because the second gRPC listener has invalid TLS
	assert.Error(t, err)
	assert.Equal(t, StateStopped, gw.State())
}

// ============================================================================
// Gateway with all options combined
// ============================================================================

func TestGateway_WithAllOptions(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-all-options"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	registry := prometheus.NewRegistry()
	auditLogger := audit.NewNoopLogger()
	tlsMetrics := tlspkg.NewMetrics("test_all_opts")

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithAuditLogger(auditLogger),
		WithMetricsRegistry(registry),
		WithGatewayTLSMetrics(tlsMetrics),
	)
	require.NoError(t, err)
	assert.NotNil(t, gw)
	assert.Equal(t, auditLogger, gw.auditLogger)
	assert.Equal(t, registry, gw.metricsRegistry)
	assert.Equal(t, tlsMetrics, gw.tlsMetrics)
}
