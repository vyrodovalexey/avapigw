package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	t.Run("returns NopProvider for nil config", func(t *testing.T) {
		t.Parallel()

		provider, err := NewProvider("test", nil)
		require.NoError(t, err)
		assert.IsType(t, &NopProvider{}, provider)
	})

	t.Run("creates JWT provider when type is jwt", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			Type: AuthTypeJWT,
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: TokenSourceStatic,
				StaticToken: "test-token",
			},
		}

		provider, err := NewProvider("test", cfg)
		require.NoError(t, err)
		assert.IsType(t, &JWTProvider{}, provider)
		assert.Equal(t, "jwt", provider.Type())
	})

	t.Run("creates Basic provider when type is basic", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			Type: AuthTypeBasic,
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
		}

		provider, err := NewProvider("test", cfg)
		require.NoError(t, err)
		assert.IsType(t, &BasicProvider{}, provider)
		assert.Equal(t, "basic", provider.Type())
	})

	t.Run("creates mTLS provider when type is mtls", func(t *testing.T) {
		t.Parallel()

		// Create temp cert files
		tempDir, err := os.MkdirTemp("", "factory-test-*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendAuthConfig{
			Type: AuthTypeMTLS,
			MTLS: &config.BackendMTLSAuthConfig{
				Enabled:  true,
				CertFile: certFile,
				KeyFile:  keyFile,
			},
		}

		provider, err := NewProvider("test", cfg)
		require.NoError(t, err)
		assert.IsType(t, &MTLSProvider{}, provider)
		assert.Equal(t, "mtls", provider.Type())
	})

	t.Run("returns error for unsupported type", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			Type: "unsupported",
		}

		_, err := NewProvider("test", cfg)
		assert.Error(t, err)
	})

	t.Run("returns error when JWT config is missing", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			Type: AuthTypeJWT,
			// JWT config is nil
		}

		_, err := NewProvider("test", cfg)
		assert.Error(t, err)
	})

	t.Run("returns error when Basic config is missing", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			Type: AuthTypeBasic,
			// Basic config is nil
		}

		_, err := NewProvider("test", cfg)
		assert.Error(t, err)
	})

	t.Run("returns error when mTLS config is missing", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			Type: AuthTypeMTLS,
			// MTLS config is nil
		}

		_, err := NewProvider("test", cfg)
		assert.Error(t, err)
	})
}

func TestNewProvider_InferFromConfig(t *testing.T) {
	t.Parallel()

	t.Run("infers JWT provider from enabled config", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			// Type is empty
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: TokenSourceStatic,
				StaticToken: "test-token",
			},
		}

		provider, err := NewProvider("test", cfg)
		require.NoError(t, err)
		assert.IsType(t, &JWTProvider{}, provider)
	})

	t.Run("infers Basic provider from enabled config", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			// Type is empty
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
		}

		provider, err := NewProvider("test", cfg)
		require.NoError(t, err)
		assert.IsType(t, &BasicProvider{}, provider)
	})

	t.Run("infers mTLS provider from enabled config", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendAuthConfig{
			// Type is empty
			MTLS: &config.BackendMTLSAuthConfig{
				Enabled:  true,
				CertFile: certFile,
				KeyFile:  keyFile,
			},
		}

		provider, err := NewProvider("test", cfg)
		require.NoError(t, err)
		assert.IsType(t, &MTLSProvider{}, provider)
	})

	t.Run("returns NopProvider when no config is enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			// Type is empty, all configs are nil or disabled
			JWT: &config.BackendJWTAuthConfig{
				Enabled: false,
			},
		}

		provider, err := NewProvider("test", cfg)
		require.NoError(t, err)
		assert.IsType(t, &NopProvider{}, provider)
	})

	t.Run("prefers JWT over Basic when both enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			// Type is empty
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: TokenSourceStatic,
				StaticToken: "test-token",
			},
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
		}

		provider, err := NewProvider("test", cfg)
		require.NoError(t, err)
		assert.IsType(t, &JWTProvider{}, provider)
	})
}

func TestNewProvider_WithOptions(t *testing.T) {
	t.Parallel()

	t.Run("applies options to JWT provider", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			Type: AuthTypeJWT,
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: TokenSourceStatic,
				StaticToken: "test-token",
			},
		}

		metrics := NopMetrics()
		provider, err := NewProvider("test", cfg, WithMetrics(metrics))
		require.NoError(t, err)

		jwtProvider, ok := provider.(*JWTProvider)
		require.True(t, ok)
		assert.NotNil(t, jwtProvider.metrics)
	})

	t.Run("applies options to Basic provider", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			Type: AuthTypeBasic,
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
		}

		metrics := NopMetrics()
		provider, err := NewProvider("test", cfg, WithMetrics(metrics))
		require.NoError(t, err)

		basicProvider, ok := provider.(*BasicProvider)
		require.True(t, ok)
		assert.NotNil(t, basicProvider.metrics)
	})
}

func TestMustNewProvider(t *testing.T) {
	t.Parallel()

	t.Run("returns provider for valid config", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			Type: AuthTypeJWT,
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: TokenSourceStatic,
				StaticToken: "test-token",
			},
		}

		provider := MustNewProvider("test", cfg)
		assert.NotNil(t, provider)
	})

	t.Run("panics for invalid config", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendAuthConfig{
			Type: "invalid",
		}

		assert.Panics(t, func() {
			MustNewProvider("test", cfg)
		})
	})
}

func TestProviderRegistry(t *testing.T) {
	t.Parallel()

	t.Run("creates new registry", func(t *testing.T) {
		t.Parallel()

		registry := NewProviderRegistry()
		assert.NotNil(t, registry)
		assert.NotNil(t, registry.providers)
	})

	t.Run("registers provider", func(t *testing.T) {
		t.Parallel()

		registry := NewProviderRegistry()
		provider := &NopProvider{}

		err := registry.Register(provider)
		assert.NoError(t, err)
	})

	t.Run("returns error for duplicate registration", func(t *testing.T) {
		t.Parallel()

		registry := NewProviderRegistry()
		provider := &NopProvider{}

		err := registry.Register(provider)
		require.NoError(t, err)

		err = registry.Register(provider)
		assert.Error(t, err)
	})

	t.Run("gets registered provider", func(t *testing.T) {
		t.Parallel()

		registry := NewProviderRegistry()
		provider := &NopProvider{}

		err := registry.Register(provider)
		require.NoError(t, err)

		result, exists := registry.Get("nop")
		assert.True(t, exists)
		assert.Equal(t, provider, result)
	})

	t.Run("returns false for non-existent provider", func(t *testing.T) {
		t.Parallel()

		registry := NewProviderRegistry()

		_, exists := registry.Get("non-existent")
		assert.False(t, exists)
	})

	t.Run("closes all providers", func(t *testing.T) {
		t.Parallel()

		registry := NewProviderRegistry()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "test-token",
		}

		provider, err := NewJWTProvider("test", cfg)
		require.NoError(t, err)

		err = registry.Register(provider)
		require.NoError(t, err)

		err = registry.Close()
		assert.NoError(t, err)
	})
}

func TestAuthTypeConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "jwt", AuthTypeJWT)
	assert.Equal(t, "basic", AuthTypeBasic)
	assert.Equal(t, "mtls", AuthTypeMTLS)
}

// Helper function to create test certificates for factory tests
func createTestCertificatesForFactory(t *testing.T) (certFile, keyFile string, cleanup func()) {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "factory-test-*")
	require.NoError(t, err)

	// Create minimal valid cert and key files
	certFile = filepath.Join(tempDir, "cert.pem")
	keyFile = filepath.Join(tempDir, "key.pem")

	// Use the helper from mtls_test.go
	cert, key, _, cleanupCerts := createTestCertificates(t)

	// Copy files to our temp dir
	certData, err := os.ReadFile(cert)
	require.NoError(t, err)
	err = os.WriteFile(certFile, certData, 0600)
	require.NoError(t, err)

	keyData, err := os.ReadFile(key)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, keyData, 0600)
	require.NoError(t, err)

	cleanup = func() {
		cleanupCerts()
		os.RemoveAll(tempDir)
	}

	return certFile, keyFile, cleanup
}
