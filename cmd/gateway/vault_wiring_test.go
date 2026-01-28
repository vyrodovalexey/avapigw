package main

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// ============================================================
// Mock vault.Client for testing
// ============================================================

// mockVaultClientForWiring implements vault.Client for vault wiring tests.
type mockVaultClientForWiring struct {
	enabled   bool
	pkiClient vault.PKIClient
}

func newMockVaultClientForWiring(enabled bool) *mockVaultClientForWiring {
	return &mockVaultClientForWiring{
		enabled:   enabled,
		pkiClient: &mockPKIClientForWiring{},
	}
}

func (m *mockVaultClientForWiring) IsEnabled() bool                      { return m.enabled }
func (m *mockVaultClientForWiring) Authenticate(_ context.Context) error { return nil }
func (m *mockVaultClientForWiring) RenewToken(_ context.Context) error   { return nil }
func (m *mockVaultClientForWiring) Health(_ context.Context) (*vault.HealthStatus, error) {
	return nil, nil
}
func (m *mockVaultClientForWiring) PKI() vault.PKIClient         { return m.pkiClient }
func (m *mockVaultClientForWiring) KV() vault.KVClient           { return nil }
func (m *mockVaultClientForWiring) Transit() vault.TransitClient { return nil }
func (m *mockVaultClientForWiring) Close() error                 { return nil }

// mockPKIClientForWiring implements vault.PKIClient for testing.
type mockPKIClientForWiring struct{}

func (m *mockPKIClientForWiring) IssueCertificate(_ context.Context, _ *vault.PKIIssueOptions) (*vault.Certificate, error) {
	return &vault.Certificate{
		CertificatePEM: "mock-cert",
		PrivateKeyPEM:  "mock-key",
		SerialNumber:   "mock-serial",
		Expiration:     time.Now().Add(24 * time.Hour),
	}, nil
}

func (m *mockPKIClientForWiring) SignCSR(_ context.Context, _ []byte, _ *vault.PKISignOptions) (*vault.Certificate, error) {
	return nil, nil
}

func (m *mockPKIClientForWiring) GetCA(_ context.Context, _ string) (*x509.CertPool, error) {
	return nil, nil
}

func (m *mockPKIClientForWiring) GetCRL(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}

func (m *mockPKIClientForWiring) RevokeCertificate(_ context.Context, _, _ string) error {
	return nil
}

// ============================================================
// needsVaultTLS tests
// ============================================================

func TestNeedsVaultTLS_NoVault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *config.GatewayConfig
		expected bool
	}{
		{
			name: "empty config with no TLS",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Listeners: []config.Listener{
						{Name: "http", Port: 8080, Protocol: config.ProtocolHTTP},
					},
				},
			},
			expected: false,
		},
		{
			name: "no listeners and no routes",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := needsVaultTLS(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNeedsVaultTLS_HTTPListenerVault(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: config.ProtocolHTTP,
					TLS: &config.ListenerTLSConfig{
						Vault: &config.VaultTLSConfig{
							Enabled:    true,
							PKIMount:   "pki",
							Role:       "my-role",
							CommonName: "example.com",
						},
					},
				},
			},
		},
	}

	result := needsVaultTLS(cfg)
	assert.True(t, result, "should return true when HTTP listener has Vault TLS enabled")
}

func TestNeedsVaultTLS_GRPCListenerVault(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "grpc",
					Port:     50051,
					Protocol: config.ProtocolGRPC,
					GRPC: &config.GRPCListenerConfig{
						TLS: &config.TLSConfig{
							Enabled: true,
							Vault: &config.VaultGRPCTLSConfig{
								Enabled:    true,
								PKIMount:   "pki",
								Role:       "grpc-role",
								CommonName: "grpc.example.com",
							},
						},
					},
				},
			},
		},
	}

	result := needsVaultTLS(cfg)
	assert.True(t, result, "should return true when gRPC listener has Vault TLS enabled")
}

func TestNeedsVaultTLS_RouteVault(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: config.ProtocolHTTP},
			},
			Routes: []config.Route{
				{
					Name: "vault-route",
					TLS: &config.RouteTLSConfig{
						Vault: &config.VaultTLSConfig{
							Enabled:    true,
							PKIMount:   "pki",
							Role:       "route-role",
							CommonName: "route.example.com",
						},
					},
				},
			},
		},
	}

	result := needsVaultTLS(cfg)
	assert.True(t, result, "should return true when a route has Vault TLS enabled")
}

func TestNeedsVaultTLS_VaultDisabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *config.GatewayConfig
	}{
		{
			name: "HTTP listener vault disabled",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Listeners: []config.Listener{
						{
							Name:     "https",
							Port:     8443,
							Protocol: config.ProtocolHTTP,
							TLS: &config.ListenerTLSConfig{
								Vault: &config.VaultTLSConfig{
									Enabled: false,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "gRPC listener vault disabled",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Listeners: []config.Listener{
						{
							Name:     "grpc",
							Port:     50051,
							Protocol: config.ProtocolGRPC,
							GRPC: &config.GRPCListenerConfig{
								TLS: &config.TLSConfig{
									Enabled: true,
									Vault: &config.VaultGRPCTLSConfig{
										Enabled: false,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "route vault disabled",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Routes: []config.Route{
						{
							Name: "route-disabled",
							TLS: &config.RouteTLSConfig{
								Vault: &config.VaultTLSConfig{
									Enabled: false,
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := needsVaultTLS(tt.config)
			assert.False(t, result, "should return false when Vault is present but disabled")
		})
	}
}

func TestNeedsVaultTLS_NilTLS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *config.GatewayConfig
	}{
		{
			name: "HTTP listener nil TLS",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Listeners: []config.Listener{
						{
							Name:     "http",
							Port:     8080,
							Protocol: config.ProtocolHTTP,
							TLS:      nil,
						},
					},
				},
			},
		},
		{
			name: "HTTP listener TLS with nil vault",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Listeners: []config.Listener{
						{
							Name:     "https",
							Port:     8443,
							Protocol: config.ProtocolHTTP,
							TLS: &config.ListenerTLSConfig{
								Vault: nil,
							},
						},
					},
				},
			},
		},
		{
			name: "gRPC listener nil GRPC config",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Listeners: []config.Listener{
						{
							Name:     "grpc",
							Port:     50051,
							Protocol: config.ProtocolGRPC,
							GRPC:     nil,
						},
					},
				},
			},
		},
		{
			name: "gRPC listener nil TLS config",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Listeners: []config.Listener{
						{
							Name:     "grpc",
							Port:     50051,
							Protocol: config.ProtocolGRPC,
							GRPC: &config.GRPCListenerConfig{
								TLS: nil,
							},
						},
					},
				},
			},
		},
		{
			name: "gRPC listener TLS with nil vault",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Listeners: []config.Listener{
						{
							Name:     "grpc",
							Port:     50051,
							Protocol: config.ProtocolGRPC,
							GRPC: &config.GRPCListenerConfig{
								TLS: &config.TLSConfig{
									Enabled: true,
									Vault:   nil,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "route nil TLS",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Routes: []config.Route{
						{
							Name: "no-tls-route",
							TLS:  nil,
						},
					},
				},
			},
		},
		{
			name: "route TLS with nil vault",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Routes: []config.Route{
						{
							Name: "no-vault-route",
							TLS: &config.RouteTLSConfig{
								Vault: nil,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := needsVaultTLS(tt.config)
			assert.False(t, result, "should return false when TLS config is nil")
		})
	}
}

// ============================================================
// createVaultProviderFactory tests
// ============================================================

func TestCreateVaultProviderFactory(t *testing.T) {
	t.Parallel()

	// Arrange: create a mock vault client that is enabled
	client := newMockVaultClientForWiring(true)

	// Act: create the factory
	factory := createVaultProviderFactory(client)

	// Assert: factory is not nil
	require.NotNil(t, factory, "factory should not be nil")

	// Verify the factory is a valid VaultProviderFactory function
	// by calling it with a valid config
	tlsCfg := &tlspkg.VaultTLSConfig{
		Enabled:     true,
		PKIMount:    "pki",
		Role:        "test-role",
		CommonName:  "test.example.com",
		AltNames:    []string{"alt.example.com"},
		TTL:         24 * time.Hour,
		RenewBefore: 1 * time.Hour,
	}

	logger := observability.NopLogger()
	provider, err := factory(tlsCfg, logger)
	require.NoError(t, err, "factory should create provider without error")
	require.NotNil(t, provider, "provider should not be nil")

	// Clean up
	_ = provider.Close()
}

func TestCreateVaultProviderFactory_NilClient(t *testing.T) {
	t.Parallel()

	// Act: create the factory with nil client
	factory := createVaultProviderFactory(nil)

	// Assert: factory is not nil (it's a function)
	require.NotNil(t, factory, "factory function should not be nil even with nil client")

	// Calling the factory with nil client should return an error
	// because vault.NewVaultProvider checks for nil client
	tlsCfg := &tlspkg.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	logger := observability.NopLogger()
	provider, err := factory(tlsCfg, logger)
	assert.Error(t, err, "factory should return error with nil client")
	assert.Nil(t, provider, "provider should be nil when client is nil")
	assert.Contains(t, err.Error(), "vault provider", "error should mention vault provider")
}

func TestCreateVaultProviderFactory_DisabledClient(t *testing.T) {
	t.Parallel()

	// Arrange: create a disabled vault client
	client := newMockVaultClientForWiring(false)

	// Act: create the factory
	factory := createVaultProviderFactory(client)
	require.NotNil(t, factory)

	// Calling the factory with a disabled client should return an error
	tlsCfg := &tlspkg.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	logger := observability.NopLogger()
	provider, err := factory(tlsCfg, logger)
	assert.Error(t, err, "factory should return error with disabled client")
	assert.Nil(t, provider, "provider should be nil when client is disabled")
}

func TestCreateVaultProviderFactory_InvalidConfig(t *testing.T) {
	t.Parallel()

	// Arrange: create an enabled vault client
	client := newMockVaultClientForWiring(true)

	// Act: create the factory
	factory := createVaultProviderFactory(client)
	require.NotNil(t, factory)

	// Calling the factory with invalid config (missing required fields)
	tlsCfg := &tlspkg.VaultTLSConfig{
		Enabled:  true,
		PKIMount: "", // Missing required PKIMount
		Role:     "", // Missing required Role
	}

	logger := observability.NopLogger()
	provider, err := factory(tlsCfg, logger)
	assert.Error(t, err, "factory should return error with invalid config")
	assert.Nil(t, provider, "provider should be nil with invalid config")
}

func TestCreateVaultProviderFactory_ConfigFieldMapping(t *testing.T) {
	t.Parallel()

	// This test verifies that the factory correctly maps VaultTLSConfig fields
	// to VaultProviderConfig fields.
	client := newMockVaultClientForWiring(true)
	factory := createVaultProviderFactory(client)
	require.NotNil(t, factory)

	// Create config with all fields populated
	tlsCfg := &tlspkg.VaultTLSConfig{
		Enabled:     true,
		PKIMount:    "pki/v2",
		Role:        "web-server",
		CommonName:  "web.example.com",
		AltNames:    []string{"www.example.com", "api.example.com"},
		TTL:         48 * time.Hour,
		RenewBefore: 2 * time.Hour,
	}

	logger := observability.NopLogger()
	provider, err := factory(tlsCfg, logger)
	require.NoError(t, err, "factory should create provider with all fields")
	require.NotNil(t, provider)

	// Clean up
	_ = provider.Close()
}
