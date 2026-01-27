//go:build functional
// +build functional

package functional

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"
)

func TestFunctional_TLSConfig_VaultEnabled_Validation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		config      *internaltls.VaultTLSConfig
		expectError bool
		errContains string
	}{
		{
			name: "valid vault config",
			config: &internaltls.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.local",
				TTL:        24 * time.Hour,
			},
			expectError: false,
		},
		{
			name: "valid vault config with alt names",
			config: &internaltls.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.local",
				AltNames:   []string{"alt1.local", "alt2.local"},
				TTL:        24 * time.Hour,
			},
			expectError: false,
		},
		{
			name: "valid vault config with renew before",
			config: &internaltls.VaultTLSConfig{
				Enabled:     true,
				PKIMount:    "pki",
				Role:        "test-role",
				CommonName:  "test.local",
				TTL:         24 * time.Hour,
				RenewBefore: 1 * time.Hour,
			},
			expectError: false,
		},
		{
			name: "disabled vault config validates without fields",
			config: &internaltls.VaultTLSConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name:        "nil vault config validates",
			config:      nil,
			expectError: false,
		},
		{
			name: "missing PKI mount",
			config: &internaltls.VaultTLSConfig{
				Enabled:    true,
				Role:       "test-role",
				CommonName: "test.local",
			},
			expectError: true,
			errContains: "PKI mount",
		},
		{
			name: "missing role",
			config: &internaltls.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				CommonName: "test.local",
			},
			expectError: true,
			errContains: "role",
		},
		{
			name: "missing common name",
			config: &internaltls.VaultTLSConfig{
				Enabled:  true,
				PKIMount: "pki",
				Role:     "test-role",
			},
			expectError: true,
			errContains: "common name",
		},
		{
			name: "negative TTL",
			config: &internaltls.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.local",
				TTL:        -1 * time.Hour,
			},
			expectError: true,
			errContains: "TTL",
		},
		{
			name: "negative renewBefore",
			config: &internaltls.VaultTLSConfig{
				Enabled:     true,
				PKIMount:    "pki",
				Role:        "test-role",
				CommonName:  "test.local",
				RenewBefore: -1 * time.Hour,
			},
			expectError: true,
			errContains: "renewBefore",
		},
		{
			name: "renewBefore greater than TTL",
			config: &internaltls.VaultTLSConfig{
				Enabled:     true,
				PKIMount:    "pki",
				Role:        "test-role",
				CommonName:  "test.local",
				TTL:         1 * time.Hour,
				RenewBefore: 2 * time.Hour,
			},
			expectError: true,
			errContains: "renewBefore",
		},
		{
			name: "renewBefore equal to TTL",
			config: &internaltls.VaultTLSConfig{
				Enabled:     true,
				PKIMount:    "pki",
				Role:        "test-role",
				CommonName:  "test.local",
				TTL:         1 * time.Hour,
				RenewBefore: 1 * time.Hour,
			},
			expectError: true,
			errContains: "renewBefore",
		},
		{
			name: "zero TTL is valid",
			config: &internaltls.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.local",
				TTL:        0,
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.config.Validate()
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFunctional_VaultProviderFactory_ConfigMapping(t *testing.T) {
	t.Parallel()

	// Test that VaultProviderFactory type is correctly defined
	// and can be used as a function type
	var factory internaltls.VaultProviderFactory

	// Create a mock factory
	factory = func(config *internaltls.VaultTLSConfig, logger observability.Logger) (internaltls.CertificateProvider, error) {
		// Verify config fields are accessible
		assert.NotNil(t, config)
		assert.Equal(t, "pki", config.PKIMount)
		assert.Equal(t, "test-role", config.Role)
		assert.Equal(t, "test.local", config.CommonName)
		assert.Equal(t, []string{"alt.local"}, config.AltNames)
		assert.Equal(t, 24*time.Hour, config.TTL)
		assert.Equal(t, 1*time.Hour, config.RenewBefore)
		assert.NotNil(t, logger)

		// Return a NopProvider for testing
		return internaltls.NewNopProvider(), nil
	}

	config := &internaltls.VaultTLSConfig{
		Enabled:     true,
		PKIMount:    "pki",
		Role:        "test-role",
		CommonName:  "test.local",
		AltNames:    []string{"alt.local"},
		TTL:         24 * time.Hour,
		RenewBefore: 1 * time.Hour,
	}

	provider, err := factory(config, observability.NopLogger())
	require.NoError(t, err)
	require.NotNil(t, provider)
	assert.NoError(t, provider.Close())
}

func TestFunctional_TLSConfig_VaultEnabled_FullConfig(t *testing.T) {
	t.Parallel()

	// Test full Config validation with Vault enabled
	config := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:     true,
			PKIMount:    "pki",
			Role:        "test-role",
			CommonName:  "test.local",
			AltNames:    []string{"alt.local"},
			TTL:         24 * time.Hour,
			RenewBefore: 1 * time.Hour,
		},
	}

	err := config.Validate()
	assert.NoError(t, err)
}

func TestFunctional_TLSConfig_VaultEnabled_InvalidVault(t *testing.T) {
	t.Parallel()

	// Test Config validation with invalid Vault config
	config := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: &internaltls.VaultTLSConfig{
			Enabled: true,
			// Missing required fields
		},
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PKI mount")
}

func TestFunctional_RouteTLSConfig_VaultEnabled_Validation(t *testing.T) {
	t.Parallel()

	t.Run("validation_errors", func(t *testing.T) {
		t.Parallel()

		errorCases := []struct {
			name        string
			config      *internaltls.RouteTLSConfig
			errContains string
		}{
			{
				name: "missing both file and vault config",
				config: &internaltls.RouteTLSConfig{
					SNIHosts: []string{"test.local"},
				},
				errContains: "either certFile/keyFile or vault configuration is required",
			},
			{
				name: "vault enabled but missing PKI mount",
				config: &internaltls.RouteTLSConfig{
					SNIHosts: []string{"test.local"},
					Vault: &internaltls.VaultTLSConfig{
						Enabled:    true,
						Role:       "test-role",
						CommonName: "test.local",
					},
				},
				errContains: "PKI mount",
			},
			{
				name: "vault enabled but missing role",
				config: &internaltls.RouteTLSConfig{
					SNIHosts: []string{"test.local"},
					Vault: &internaltls.VaultTLSConfig{
						Enabled:    true,
						PKIMount:   "pki",
						CommonName: "test.local",
					},
				},
				errContains: "role",
			},
			{
				name: "vault enabled but missing common name",
				config: &internaltls.RouteTLSConfig{
					SNIHosts: []string{"test.local"},
					Vault: &internaltls.VaultTLSConfig{
						Enabled:  true,
						PKIMount: "pki",
						Role:     "test-role",
					},
				},
				errContains: "common name",
			},
			{
				name: "cert file without key file",
				config: &internaltls.RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					SNIHosts: []string{"test.local"},
				},
				errContains: "keyFile",
			},
			{
				name: "key file without cert file",
				config: &internaltls.RouteTLSConfig{
					KeyFile:  "/path/to/key.pem",
					SNIHosts: []string{"test.local"},
				},
				errContains: "certFile",
			},
		}

		for _, tc := range errorCases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				routeManager := internaltls.NewRouteTLSManager(
					internaltls.WithRouteTLSManagerLogger(observability.NopLogger()),
				)
				defer routeManager.Close()

				err := routeManager.AddRoute("test-route", tc.config)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
			})
		}
	})

	t.Run("valid_vault_route_config_with_factory", func(t *testing.T) {
		t.Parallel()

		// Valid vault route config requires a factory to succeed
		factory := func(_ *internaltls.VaultTLSConfig, _ observability.Logger) (internaltls.CertificateProvider, error) {
			return internaltls.NewNopProvider(), nil
		}

		routeManager := internaltls.NewRouteTLSManager(
			internaltls.WithRouteTLSManagerLogger(observability.NopLogger()),
			internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
		)
		defer routeManager.Close()

		cfg := &internaltls.RouteTLSConfig{
			SNIHosts: []string{"test.local"},
			Vault: &internaltls.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.local",
			},
		}

		err := routeManager.AddRoute("test-route", cfg)
		assert.NoError(t, err)
		assert.True(t, routeManager.HasRoute("test-route"))
	})

	t.Run("nil_config_rejected", func(t *testing.T) {
		t.Parallel()

		routeManager := internaltls.NewRouteTLSManager(
			internaltls.WithRouteTLSManagerLogger(observability.NopLogger()),
		)
		defer routeManager.Close()

		err := routeManager.AddRoute("test-route", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config")
	})

	t.Run("empty_route_name_rejected", func(t *testing.T) {
		t.Parallel()

		routeManager := internaltls.NewRouteTLSManager(
			internaltls.WithRouteTLSManagerLogger(observability.NopLogger()),
		)
		defer routeManager.Close()

		cfg := &internaltls.RouteTLSConfig{
			SNIHosts: []string{"test.local"},
			Vault: &internaltls.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.local",
			},
		}

		err := routeManager.AddRoute("", cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "route name")
	})
}

func TestFunctional_VaultTLSConfig_Clone(t *testing.T) {
	t.Parallel()

	original := &internaltls.VaultTLSConfig{
		Enabled:     true,
		PKIMount:    "pki",
		Role:        "test-role",
		CommonName:  "test.local",
		AltNames:    []string{"alt1.local", "alt2.local"},
		TTL:         24 * time.Hour,
		RenewBefore: 1 * time.Hour,
	}

	clone := original.Clone()

	require.NotNil(t, clone)
	assert.Equal(t, original.Enabled, clone.Enabled)
	assert.Equal(t, original.PKIMount, clone.PKIMount)
	assert.Equal(t, original.Role, clone.Role)
	assert.Equal(t, original.CommonName, clone.CommonName)
	assert.Equal(t, original.AltNames, clone.AltNames)
	assert.Equal(t, original.TTL, clone.TTL)
	assert.Equal(t, original.RenewBefore, clone.RenewBefore)

	// Verify deep copy - modifying clone should not affect original
	clone.PKIMount = "modified-pki"
	assert.NotEqual(t, original.PKIMount, clone.PKIMount)

	if len(clone.AltNames) > 0 {
		clone.AltNames[0] = "modified.local"
		assert.NotEqual(t, original.AltNames[0], clone.AltNames[0])
	}
}

func TestFunctional_VaultTLSConfig_Clone_Nil(t *testing.T) {
	t.Parallel()

	var config *internaltls.VaultTLSConfig
	clone := config.Clone()
	assert.Nil(t, clone)
}

func TestFunctional_Config_VaultEnabled_Clone(t *testing.T) {
	t.Parallel()

	original := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:     true,
			PKIMount:    "pki",
			Role:        "test-role",
			CommonName:  "test.local",
			AltNames:    []string{"alt.local"},
			TTL:         24 * time.Hour,
			RenewBefore: 1 * time.Hour,
		},
	}

	clone := original.Clone()

	require.NotNil(t, clone)
	require.NotNil(t, clone.Vault)
	assert.Equal(t, original.Vault.Enabled, clone.Vault.Enabled)
	assert.Equal(t, original.Vault.PKIMount, clone.Vault.PKIMount)
	assert.Equal(t, original.Vault.Role, clone.Vault.Role)
	assert.Equal(t, original.Vault.CommonName, clone.Vault.CommonName)

	// Verify deep copy
	clone.Vault.PKIMount = "modified"
	assert.NotEqual(t, original.Vault.PKIMount, clone.Vault.PKIMount)
}

func TestFunctional_Manager_VaultEnabled_RequiresFactory(t *testing.T) {
	t.Parallel()

	config := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.local",
		},
	}

	// Without factory, should fail
	_, err := internaltls.NewManager(config,
		internaltls.WithManagerLogger(observability.NopLogger()),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault provider factory is required")
}

func TestFunctional_Manager_VaultEnabled_WithMockFactory(t *testing.T) {
	t.Parallel()

	config := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.local",
		},
	}

	// With a mock factory that returns NopProvider
	factory := func(_ *internaltls.VaultTLSConfig, _ observability.Logger) (internaltls.CertificateProvider, error) {
		return internaltls.NewNopProvider(), nil
	}

	manager, err := internaltls.NewManager(config,
		internaltls.WithManagerLogger(observability.NopLogger()),
		internaltls.WithVaultProviderFactory(factory),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.True(t, manager.IsEnabled())
	assert.Equal(t, internaltls.TLSModeSimple, manager.GetMode())
}

func TestFunctional_RouteTLSManager_VaultEnabled_RequiresFactory(t *testing.T) {
	t.Parallel()

	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(observability.NopLogger()),
	)
	defer routeManager.Close()

	routeCfg := &internaltls.RouteTLSConfig{
		SNIHosts: []string{"test.local"},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.local",
		},
	}

	err := routeManager.AddRoute("test-route", routeCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault provider factory is required")
}

func TestFunctional_RouteTLSManager_VaultEnabled_WithMockFactory(t *testing.T) {
	t.Parallel()

	factory := func(_ *internaltls.VaultTLSConfig, _ observability.Logger) (internaltls.CertificateProvider, error) {
		return internaltls.NewNopProvider(), nil
	}

	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(observability.NopLogger()),
		internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer routeManager.Close()

	routeCfg := &internaltls.RouteTLSConfig{
		SNIHosts: []string{"test.local"},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.local",
		},
	}

	err := routeManager.AddRoute("test-route", routeCfg)
	require.NoError(t, err)
	assert.True(t, routeManager.HasRoute("test-route"))
	assert.Equal(t, 1, routeManager.RouteCount())
}

func TestFunctional_CertificateSource_Vault(t *testing.T) {
	t.Parallel()

	source := internaltls.CertificateSourceVault
	assert.True(t, source.IsValid())
	assert.Equal(t, "vault", source.String())
}

func TestFunctional_TLSConfig_PassthroughMode_IgnoresVault(t *testing.T) {
	t.Parallel()

	// In passthrough mode, vault config should be ignored
	config := &internaltls.Config{
		Mode: internaltls.TLSModePassthrough,
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.local",
		},
	}

	// Passthrough mode doesn't require certificates
	manager, err := internaltls.NewManager(config,
		internaltls.WithManagerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// TLS config should be nil for passthrough
	assert.Nil(t, manager.GetTLSConfig())
}

func TestFunctional_TLSConfig_InsecureMode_IgnoresVault(t *testing.T) {
	t.Parallel()

	config := &internaltls.Config{
		Mode: internaltls.TLSModeInsecure,
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.local",
		},
	}

	manager, err := internaltls.NewManager(config,
		internaltls.WithManagerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// TLS config should be nil for insecure mode
	assert.Nil(t, manager.GetTLSConfig())
}
