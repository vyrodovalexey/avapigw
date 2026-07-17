package gateway

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// TestConvertVaultTLSConfig covers the listener-level Vault TLS conversion,
// including the previously-dropped vault.ttl mapping (FIX: listener-level
// vault.ttl was documented but silently ignored).
func TestConvertVaultTLSConfig(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	tests := []struct {
		name    string
		src     *config.VaultTLSConfig
		wantNil bool
		wantTTL time.Duration
	}{
		{
			name:    "nil config returns nil",
			src:     nil,
			wantNil: true,
		},
		{
			name:    "disabled config returns nil",
			src:     &config.VaultTLSConfig{Enabled: false, TTL: "24h"},
			wantNil: true,
		},
		{
			name: "ttl parsed into duration",
			src: &config.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "gateway",
				CommonName: "gw.example.com",
				AltNames:   []string{"alt.example.com"},
				TTL:        "24h",
			},
			wantTTL: 24 * time.Hour,
		},
		{
			name:    "empty ttl leaves zero (PKI role default)",
			src:     &config.VaultTLSConfig{Enabled: true, PKIMount: "pki", Role: "r"},
			wantTTL: 0,
		},
		{
			name:    "invalid ttl logged and skipped",
			src:     &config.VaultTLSConfig{Enabled: true, TTL: "notaduration"},
			wantTTL: 0,
		},
		{
			name:    "negative ttl skipped",
			src:     &config.VaultTLSConfig{Enabled: true, TTL: "-5m"},
			wantTTL: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := convertVaultTLSConfig(tt.src, logger)
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.True(t, got.Enabled)
			assert.Equal(t, tt.src.PKIMount, got.PKIMount)
			assert.Equal(t, tt.src.Role, got.Role)
			assert.Equal(t, tt.src.CommonName, got.CommonName)
			assert.Equal(t, tt.src.AltNames, got.AltNames)
			assert.Equal(t, tt.wantTTL, got.TTL)
		})
	}
}

// TestListener_ConvertToTLSConfig_MapsVaultTTL proves the HTTP listener's
// conversion path carries vault.ttl through to the TLS package config that
// feeds the Vault provider factory (and thus the PKI issue request).
func TestListener_ConvertToTLSConfig_MapsVaultTTL(t *testing.T) {
	t.Parallel()

	l := &Listener{logger: observability.NopLogger()}
	got := l.convertToTLSConfig(&config.ListenerTLSConfig{
		Mode: "SIMPLE",
		Vault: &config.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "gateway",
			CommonName: "gw.example.com",
			TTL:        "12h30m",
		},
	})

	require.NotNil(t, got)
	require.NotNil(t, got.Vault)
	assert.Equal(t, 12*time.Hour+30*time.Minute, got.Vault.TTL,
		"listener-level vault.ttl must flow into the TLS manager config")
	require.NotNil(t, got.ServerCertificate)
	assert.Equal(t, tlspkg.CertificateSourceVault, got.ServerCertificate.Source)
}

// TestGRPCListener_CreateTLSManagerFromConfig_MapsVaultTTL proves the gRPC
// listener's conversion path carries vault.ttl as well (VaultGRPCTLSConfig is
// converted through the shared helper).
func TestGRPCListener_CreateTLSManagerFromConfig_MapsVaultTTL(t *testing.T) {
	t.Parallel()

	// Track the Vault config the manager hands to the provider factory.
	var seen *tlspkg.VaultTLSConfig
	factory := func(cfg *tlspkg.VaultTLSConfig, _ observability.Logger) (tlspkg.CertificateProvider, error) {
		seen = cfg
		return nil, assert.AnError // manager construction may fail afterwards; the capture is what matters
	}

	l := &GRPCListener{
		logger:               observability.NopLogger(),
		vaultProviderFactory: factory,
	}
	_, err := l.createTLSManagerFromConfig(&config.TLSConfig{
		Enabled: true,
		Mode:    "SIMPLE",
		Vault: &config.VaultGRPCTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "grpc-gateway",
			CommonName: "grpc.example.com",
			TTL:        "48h",
		},
	})

	// The provider factory error (assert.AnError) surfaces from manager
	// construction; the assertion target is the TTL that reached the factory.
	require.Error(t, err, "factory returning an error must fail manager construction")
	require.NotNil(t, seen, "Vault provider factory must be invoked")
	assert.Equal(t, 48*time.Hour, seen.TTL,
		"gRPC listener vault.ttl must flow into the Vault provider config")
}
