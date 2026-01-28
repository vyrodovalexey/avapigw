package gateway

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// dummyVaultProviderFactory is a test factory that records whether it was called.
func dummyVaultProviderFactory(_ *tlspkg.VaultTLSConfig, _ observability.Logger) (tlspkg.CertificateProvider, error) {
	return tlspkg.NewNopProvider(), nil
}

// TestGateway_WithGatewayVaultProviderFactory verifies the option sets the factory on the gateway.
func TestGateway_WithGatewayVaultProviderFactory(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-vault"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	factory := tlspkg.VaultProviderFactory(dummyVaultProviderFactory)

	gw, err := New(cfg, WithGatewayVaultProviderFactory(factory))
	require.NoError(t, err)
	assert.NotNil(t, gw)
	assert.NotNil(t, gw.vaultProviderFactory, "vaultProviderFactory should be set on the gateway")
}

// TestGateway_WithGatewayVaultProviderFactory_Nil verifies nil factory is handled gracefully.
func TestGateway_WithGatewayVaultProviderFactory_Nil(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-vault-nil"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg, WithGatewayVaultProviderFactory(nil))
	require.NoError(t, err)
	assert.NotNil(t, gw)
	assert.Nil(t, gw.vaultProviderFactory, "vaultProviderFactory should be nil when nil is passed")

	// Verify the gateway can still start and stop without a factory
	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	assert.True(t, gw.IsRunning())

	err = gw.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, gw.IsRunning())
}

// TestGateway_CreateListeners_WithVaultFactory verifies factory is propagated to HTTP listeners.
func TestGateway_CreateListeners_WithVaultFactory(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-vault-http"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	factory := tlspkg.VaultProviderFactory(dummyVaultProviderFactory)

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGatewayVaultProviderFactory(factory),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	// Verify HTTP listeners were created
	listeners := gw.GetListeners()
	require.Len(t, listeners, 1)

	// Verify the factory was propagated to the HTTP listener
	assert.NotNil(t, listeners[0].vaultProviderFactory,
		"vaultProviderFactory should be propagated to HTTP listener")
}

// TestGateway_CreateListeners_WithVaultFactory_GRPC verifies factory is propagated to gRPC listeners.
func TestGateway_CreateListeners_WithVaultFactory_GRPC(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-vault-grpc"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	factory := tlspkg.VaultProviderFactory(dummyVaultProviderFactory)

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGatewayVaultProviderFactory(factory),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	// Verify gRPC listeners were created
	grpcListeners := gw.GetGRPCListeners()
	require.Len(t, grpcListeners, 1)

	// Verify the factory was propagated to the gRPC listener
	assert.NotNil(t, grpcListeners[0].vaultProviderFactory,
		"vaultProviderFactory should be propagated to gRPC listener")
}

// TestGateway_CreateListeners_WithoutVaultFactory verifies listeners work without factory (nil case).
func TestGateway_CreateListeners_WithoutVaultFactory(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-no-vault"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	// Create gateway without vault factory
	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)
	assert.Nil(t, gw.vaultProviderFactory, "vaultProviderFactory should be nil by default")

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	// Verify HTTP listeners were created without factory
	listeners := gw.GetListeners()
	require.Len(t, listeners, 1)
	assert.Nil(t, listeners[0].vaultProviderFactory,
		"vaultProviderFactory should be nil on HTTP listener when not set")

	// Verify gRPC listeners were created without factory
	grpcListeners := gw.GetGRPCListeners()
	require.Len(t, grpcListeners, 1)
	assert.Nil(t, grpcListeners[0].vaultProviderFactory,
		"vaultProviderFactory should be nil on gRPC listener when not set")
}

// TestGateway_CreateListeners_WithVaultFactory_MixedListeners verifies factory propagation
// to both HTTP and gRPC listeners in a mixed configuration.
func TestGateway_CreateListeners_WithVaultFactory_MixedListeners(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-vault-mixed"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	factory := tlspkg.VaultProviderFactory(dummyVaultProviderFactory)

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGatewayVaultProviderFactory(factory),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	// Verify both listener types have the factory
	listeners := gw.GetListeners()
	require.Len(t, listeners, 1)
	assert.NotNil(t, listeners[0].vaultProviderFactory)

	grpcListeners := gw.GetGRPCListeners()
	require.Len(t, grpcListeners, 1)
	assert.NotNil(t, grpcListeners[0].vaultProviderFactory)
}
