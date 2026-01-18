package secrets

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestNewProviderEnv(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	provider, err := NewProvider(ctx, &ProviderConfig{
		Type:      ProviderTypeEnv,
		EnvPrefix: "TEST_",
		Logger:    logger,
	})
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, ProviderTypeEnv, provider.Type())
}

func TestNewProviderLocal(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "factory-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewProvider(ctx, &ProviderConfig{
		Type:          ProviderTypeLocal,
		LocalBasePath: tmpDir,
		Logger:        logger,
	})
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, ProviderTypeLocal, provider.Type())
}

func TestNewProviderInvalidType(t *testing.T) {
	ctx := context.Background()

	_, err := NewProvider(ctx, &ProviderConfig{
		Type: ProviderType("invalid"),
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidProviderType)
}

func TestNewProviderNilConfig(t *testing.T) {
	ctx := context.Background()

	_, err := NewProvider(ctx, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
}

func TestNoopProvider(t *testing.T) {
	logger := zap.NewNop()
	provider := NewNoopProvider(logger)

	ctx := context.Background()

	// Type
	assert.Equal(t, ProviderType("noop"), provider.Type())

	// GetSecret
	_, err := provider.GetSecret(ctx, "test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)

	// ListSecrets
	secrets, err := provider.ListSecrets(ctx, "")
	assert.NoError(t, err)
	assert.Empty(t, secrets)

	// WriteSecret
	err = provider.WriteSecret(ctx, "test", map[string][]byte{"key": []byte("value")})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReadOnly)

	// DeleteSecret
	err = provider.DeleteSecret(ctx, "test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReadOnly)

	// IsReadOnly
	assert.True(t, provider.IsReadOnly())

	// HealthCheck
	err = provider.HealthCheck(ctx)
	assert.NoError(t, err)

	// Close
	err = provider.Close()
	assert.NoError(t, err)
}

func TestProviderManager(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create env provider as primary
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "PM_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	// Create manager
	pm := NewProviderManager(envProvider, logger)
	assert.NotNil(t, pm)
	assert.Equal(t, envProvider, pm.Primary())

	// Get provider by type
	p, ok := pm.GetProvider(ProviderTypeEnv)
	assert.True(t, ok)
	assert.Equal(t, envProvider, p)

	// Get non-existent provider
	_, ok = pm.GetProvider(ProviderTypeVault)
	assert.False(t, ok)

	// Add another provider
	noopProvider := NewNoopProvider(logger)
	pm.AddProvider(noopProvider)

	p, ok = pm.GetProvider(ProviderType("noop"))
	assert.True(t, ok)
	assert.Equal(t, noopProvider, p)

	// GetSecret from primary
	os.Setenv("PM_TEST_MYSECRET", "myvalue")
	defer os.Unsetenv("PM_TEST_MYSECRET")

	secret, err := pm.GetSecret(ctx, "mysecret")
	require.NoError(t, err)
	val, ok := secret.GetString("value")
	assert.True(t, ok)
	assert.Equal(t, "myvalue", val)

	// GetSecretFromProvider
	_, err = pm.GetSecretFromProvider(ctx, ProviderType("noop"), "test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)

	// HealthCheck
	results := pm.HealthCheck(ctx)
	assert.Len(t, results, 2)
	assert.NoError(t, results[ProviderTypeEnv])
	assert.NoError(t, results[ProviderType("noop")])

	// Close
	err = pm.Close()
	assert.NoError(t, err)
}

func TestProviderManagerNilPrimary(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	pm := NewProviderManager(nil, logger)
	assert.Nil(t, pm.Primary())

	_, err := pm.GetSecret(ctx, "test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
}

func TestCachingProvider(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create env provider
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "CACHE_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	// Wrap with caching
	cachingProvider := NewCachingProvider(envProvider, 1*time.Minute, logger)
	assert.NotNil(t, cachingProvider)
	assert.Equal(t, ProviderTypeEnv, cachingProvider.Type())

	// Set env var
	os.Setenv("CACHE_TEST_CACHED", "cached-value")
	defer os.Unsetenv("CACHE_TEST_CACHED")

	// First call - should fetch from provider
	secret, err := cachingProvider.GetSecret(ctx, "cached")
	require.NoError(t, err)
	val, ok := secret.GetString("value")
	assert.True(t, ok)
	assert.Equal(t, "cached-value", val)

	// Second call - should use cache
	secret, err = cachingProvider.GetSecret(ctx, "cached")
	require.NoError(t, err)
	val, ok = secret.GetString("value")
	assert.True(t, ok)
	assert.Equal(t, "cached-value", val)

	// Invalidate cache
	cachingProvider.InvalidateCache("cached")

	// Third call - should fetch from provider again
	secret, err = cachingProvider.GetSecret(ctx, "cached")
	require.NoError(t, err)
	val, ok = secret.GetString("value")
	assert.True(t, ok)
	assert.Equal(t, "cached-value", val)

	// Clear all cache
	cachingProvider.ClearCache()

	// IsReadOnly
	assert.True(t, cachingProvider.IsReadOnly())

	// HealthCheck
	err = cachingProvider.HealthCheck(ctx)
	assert.NoError(t, err)

	// Close
	err = cachingProvider.Close()
	assert.NoError(t, err)
}

func TestNewProviderKubernetes(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	provider, err := NewProvider(ctx, &ProviderConfig{
		Type:       ProviderTypeKubernetes,
		KubeClient: k8sClient,
		Namespace:  "default",
		Logger:     logger,
	})
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, ProviderTypeKubernetes, provider.Type())
}

func TestNewProviderVaultMissingConfig(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	_, err := NewProvider(ctx, &ProviderConfig{
		Type:   ProviderTypeVault,
		Logger: logger,
		// Missing VaultConfig
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
}

func TestProviderManagerSetPrimary(t *testing.T) {
	logger := zap.NewNop()

	pm := NewProviderManager(nil, logger)
	assert.Nil(t, pm.Primary())

	// Create and set a new primary
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "SET_PRIMARY_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	pm.SetPrimary(envProvider)
	assert.Equal(t, envProvider, pm.Primary())

	// Verify it was also added to providers map
	p, ok := pm.GetProvider(ProviderTypeEnv)
	assert.True(t, ok)
	assert.Equal(t, envProvider, p)
}

func TestProviderManagerAddNilProvider(t *testing.T) {
	logger := zap.NewNop()
	pm := NewProviderManager(nil, logger)

	// Adding nil should not panic
	pm.AddProvider(nil)
	assert.Empty(t, pm.providers)
}

func TestProviderManagerGetSecretFromProviderNotFound(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	pm := NewProviderManager(nil, logger)

	_, err := pm.GetSecretFromProvider(ctx, ProviderTypeVault, "test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
}

func TestCachingProviderListSecrets(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create env provider
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "CACHE_LIST_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	// Set env vars
	os.Setenv("CACHE_LIST_TEST_SECRET1", "value1")
	os.Setenv("CACHE_LIST_TEST_SECRET2", "value2")
	defer os.Unsetenv("CACHE_LIST_TEST_SECRET1")
	defer os.Unsetenv("CACHE_LIST_TEST_SECRET2")

	// Wrap with caching
	cachingProvider := NewCachingProvider(envProvider, 1*time.Minute, logger)

	// ListSecrets should delegate to underlying provider
	secrets, err := cachingProvider.ListSecrets(ctx, "")
	require.NoError(t, err)
	assert.Contains(t, secrets, "secret1")
	assert.Contains(t, secrets, "secret2")
}

func TestCachingProviderWriteAndDelete(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create local provider
	tmpDir, err := os.MkdirTemp("", "caching-write-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	localProvider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   logger,
	})
	require.NoError(t, err)

	// Wrap with caching
	cachingProvider := NewCachingProvider(localProvider, 1*time.Minute, logger)

	// Write should invalidate cache
	err = cachingProvider.WriteSecret(ctx, "test-secret", map[string][]byte{
		"key": []byte("value"),
	})
	require.NoError(t, err)

	// Read it back
	secret, err := cachingProvider.GetSecret(ctx, "test-secret")
	require.NoError(t, err)
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)

	// Delete should invalidate cache
	err = cachingProvider.DeleteSecret(ctx, "test-secret")
	require.NoError(t, err)

	// Should not be found anymore
	_, err = cachingProvider.GetSecret(ctx, "test-secret")
	assert.Error(t, err)
}

func TestCachingProviderCacheExpiry(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create env provider
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "CACHE_EXPIRY_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	// Set env var
	os.Setenv("CACHE_EXPIRY_TEST_EXPIRING", "initial-value")
	defer os.Unsetenv("CACHE_EXPIRY_TEST_EXPIRING")

	// Wrap with very short TTL
	cachingProvider := NewCachingProvider(envProvider, 50*time.Millisecond, logger)

	// First call - should fetch from provider
	secret, err := cachingProvider.GetSecret(ctx, "expiring")
	require.NoError(t, err)
	val, ok := secret.GetString("value")
	assert.True(t, ok)
	assert.Equal(t, "initial-value", val)

	// Wait for cache to expire
	time.Sleep(100 * time.Millisecond)

	// Update env var
	os.Setenv("CACHE_EXPIRY_TEST_EXPIRING", "updated-value")

	// Should fetch from provider again due to expiry
	secret, err = cachingProvider.GetSecret(ctx, "expiring")
	require.NoError(t, err)
	val, ok = secret.GetString("value")
	assert.True(t, ok)
	assert.Equal(t, "updated-value", val)
}

func TestNewProviderFromConfig(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	t.Run("default provider (kubernetes)", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.SecretsProvider = ""
		cfg.VaultEnabled = false

		provider, err := NewProviderFromConfig(ctx, cfg, k8sClient, logger)
		require.NoError(t, err)
		assert.Equal(t, ProviderTypeKubernetes, provider.Type())
	})

	t.Run("env provider", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.SecretsProvider = "env"
		cfg.SecretsEnvPrefix = "TEST_PREFIX_"

		provider, err := NewProviderFromConfig(ctx, cfg, k8sClient, logger)
		require.NoError(t, err)
		assert.Equal(t, ProviderTypeEnv, provider.Type())
	})

	t.Run("local provider", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "provider-from-config-test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		cfg := config.DefaultConfig()
		cfg.SecretsProvider = "local"
		cfg.SecretsLocalPath = tmpDir

		provider, err := NewProviderFromConfig(ctx, cfg, k8sClient, logger)
		require.NoError(t, err)
		assert.Equal(t, ProviderTypeLocal, provider.Type())
	})

	t.Run("invalid provider type", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.SecretsProvider = "invalid"

		_, err := NewProviderFromConfig(ctx, cfg, k8sClient, logger)
		assert.Error(t, err)
	})

	t.Run("nil config", func(t *testing.T) {
		_, err := NewProviderFromConfig(ctx, nil, k8sClient, logger)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrProviderNotConfigured)
	})
}

func TestNoopProviderWithNilLogger(t *testing.T) {
	provider := NewNoopProvider(nil)
	assert.NotNil(t, provider)
	assert.NotNil(t, provider.logger)
}

func TestProviderManagerWithNilLogger(t *testing.T) {
	pm := NewProviderManager(nil, nil)
	assert.NotNil(t, pm)
	assert.NotNil(t, pm.logger)
}

func TestCachingProviderWithNilLogger(t *testing.T) {
	envProvider, err := NewEnvProvider(nil)
	require.NoError(t, err)

	cachingProvider := NewCachingProvider(envProvider, 1*time.Minute, nil)
	assert.NotNil(t, cachingProvider)
	assert.NotNil(t, cachingProvider.logger)
}

func TestNewProviderFromConfigWithVaultEnabled(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Test with VaultEnabled but no SecretsProvider set
	cfg := config.DefaultConfig()
	cfg.SecretsProvider = ""
	cfg.VaultEnabled = true
	cfg.VaultAddress = "http://localhost:8200"
	cfg.VaultAuthMethod = "token"

	// This will fail because we can't actually connect to Vault
	// but it tests the code path
	_, err := NewProviderFromConfig(ctx, cfg, k8sClient, logger)
	assert.Error(t, err) // Expected to fail without real Vault
}

func TestNewProviderFromConfigWithNilLogger(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	cfg := config.DefaultConfig()
	cfg.SecretsProvider = "kubernetes"

	// Should work with nil logger
	provider, err := NewProviderFromConfig(ctx, cfg, k8sClient, nil)
	require.NoError(t, err)
	assert.Equal(t, ProviderTypeKubernetes, provider.Type())
}

func TestProviderManagerSetPrimaryNil(t *testing.T) {
	logger := zap.NewNop()

	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	pm := NewProviderManager(envProvider, logger)
	assert.Equal(t, envProvider, pm.Primary())

	// Set primary to nil
	pm.SetPrimary(nil)
	assert.Nil(t, pm.Primary())
}

func TestProviderManagerCloseWithError(t *testing.T) {
	logger := zap.NewNop()

	// Create a provider manager with multiple providers
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "CLOSE_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	pm := NewProviderManager(envProvider, logger)

	// Add noop provider
	noopProvider := NewNoopProvider(logger)
	pm.AddProvider(noopProvider)

	// Close should not error for these providers
	err = pm.Close()
	assert.NoError(t, err)
}

func TestCachingProviderGetSecretError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create env provider
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "CACHE_ERROR_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	// Wrap with caching
	cachingProvider := NewCachingProvider(envProvider, 1*time.Minute, logger)

	// Try to get a non-existent secret
	_, err = cachingProvider.GetSecret(ctx, "nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestCachingProviderWriteSecretError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create env provider (read-only)
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "CACHE_WRITE_ERROR_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	// Wrap with caching
	cachingProvider := NewCachingProvider(envProvider, 1*time.Minute, logger)

	// Write should fail because env provider is read-only
	err = cachingProvider.WriteSecret(ctx, "test", map[string][]byte{"key": []byte("value")})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReadOnly)
}

func TestCachingProviderDeleteSecretError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create env provider (read-only)
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "CACHE_DELETE_ERROR_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	// Wrap with caching
	cachingProvider := NewCachingProvider(envProvider, 1*time.Minute, logger)

	// Delete should fail because env provider is read-only
	err = cachingProvider.DeleteSecret(ctx, "test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReadOnly)
}

func TestBuildVaultConfig(t *testing.T) {
	logger := zap.NewNop()

	cfg := config.DefaultConfig()
	cfg.VaultAddress = "http://vault.example.com:8200"
	cfg.VaultNamespace = "my-namespace"
	cfg.VaultAuthMethod = "kubernetes"
	cfg.VaultRole = "my-role"
	cfg.VaultMountPath = "kubernetes"
	cfg.VaultSecretMountPoint = "kv"
	cfg.VaultTimeout = 60 * time.Second
	cfg.VaultMaxRetries = 5
	cfg.VaultRetryWaitMin = 1 * time.Second
	cfg.VaultRetryWaitMax = 10 * time.Second

	vaultCfg := buildVaultConfig(cfg, logger)

	assert.Equal(t, "http://vault.example.com:8200", vaultCfg.Address)
	assert.Equal(t, "my-namespace", vaultCfg.Namespace)
	assert.Equal(t, "kubernetes", vaultCfg.AuthMethod)
	assert.Equal(t, "my-role", vaultCfg.Role)
	assert.Equal(t, "kubernetes", vaultCfg.MountPath)
	assert.Equal(t, "kv", vaultCfg.SecretMountPoint)
	assert.Equal(t, 60*time.Second, vaultCfg.Timeout)
	assert.Equal(t, 5, vaultCfg.MaxRetries)
	assert.Equal(t, 1*time.Second, vaultCfg.RetryWaitMin)
	assert.Equal(t, 10*time.Second, vaultCfg.RetryWaitMax)
	assert.Equal(t, logger, vaultCfg.Logger)
	assert.Nil(t, vaultCfg.TLSConfig)
}

func TestBuildVaultConfigWithTLS(t *testing.T) {
	logger := zap.NewNop()

	cfg := config.DefaultConfig()
	cfg.VaultAddress = "https://vault.example.com:8200"
	cfg.VaultCACert = "/path/to/ca.crt"
	cfg.VaultClientCert = "/path/to/client.crt"
	cfg.VaultTLSSkipVerify = true

	vaultCfg := buildVaultConfig(cfg, logger)

	assert.NotNil(t, vaultCfg.TLSConfig)
	assert.True(t, vaultCfg.TLSConfig.InsecureSkipVerify)
}

func TestDetermineProviderType(t *testing.T) {
	tests := []struct {
		name         string
		cfg          *config.Config
		expectedType ProviderType
		expectError  bool
	}{
		{
			name: "explicit kubernetes provider",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.SecretsProvider = "kubernetes"
				return c
			}(),
			expectedType: ProviderTypeKubernetes,
			expectError:  false,
		},
		{
			name: "explicit vault provider",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.SecretsProvider = "vault"
				return c
			}(),
			expectedType: ProviderTypeVault,
			expectError:  false,
		},
		{
			name: "explicit local provider",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.SecretsProvider = "local"
				return c
			}(),
			expectedType: ProviderTypeLocal,
			expectError:  false,
		},
		{
			name: "explicit env provider",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.SecretsProvider = "env"
				return c
			}(),
			expectedType: ProviderTypeEnv,
			expectError:  false,
		},
		{
			name: "vault enabled without explicit provider",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.SecretsProvider = ""
				c.VaultEnabled = true
				return c
			}(),
			expectedType: ProviderTypeVault,
			expectError:  false,
		},
		{
			name: "default to kubernetes",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.SecretsProvider = ""
				c.VaultEnabled = false
				return c
			}(),
			expectedType: ProviderTypeKubernetes,
			expectError:  false,
		},
		{
			name: "invalid provider type",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.SecretsProvider = "invalid"
				return c
			}(),
			expectedType: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			providerType, err := determineProviderType(tt.cfg)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedType, providerType)
			}
		})
	}
}

func TestNewProviderWithNilLogger(t *testing.T) {
	ctx := context.Background()

	provider, err := NewProvider(ctx, &ProviderConfig{
		Type:      ProviderTypeEnv,
		EnvPrefix: "TEST_NIL_LOGGER_",
		Logger:    nil, // nil logger
	})
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, ProviderTypeEnv, provider.Type())
}

// mockErrorProvider is a mock provider that returns errors for testing
type mockErrorProvider struct {
	closeErr error
}

func (m *mockErrorProvider) Type() ProviderType {
	return ProviderType("mock-error")
}

func (m *mockErrorProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	return nil, ErrSecretNotFound
}

func (m *mockErrorProvider) ListSecrets(ctx context.Context, path string) ([]string, error) {
	return []string{}, nil
}

func (m *mockErrorProvider) WriteSecret(ctx context.Context, path string, data map[string][]byte) error {
	return ErrReadOnly
}

func (m *mockErrorProvider) DeleteSecret(ctx context.Context, path string) error {
	return ErrReadOnly
}

func (m *mockErrorProvider) IsReadOnly() bool {
	return true
}

func (m *mockErrorProvider) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *mockErrorProvider) Close() error {
	return m.closeErr
}

func TestProviderManagerCloseWithProviderError(t *testing.T) {
	logger := zap.NewNop()

	// Create a mock provider that returns an error on Close
	mockProvider := &mockErrorProvider{
		closeErr: errors.New("mock close error"),
	}

	pm := NewProviderManager(nil, logger)
	pm.AddProvider(mockProvider)

	// Close should return the error
	err := pm.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock close error")
}

func TestProviderManagerCloseWithMultipleProviders(t *testing.T) {
	logger := zap.NewNop()

	// Create providers - one that errors and one that doesn't
	mockProvider := &mockErrorProvider{
		closeErr: errors.New("mock close error"),
	}

	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "MULTI_CLOSE_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	pm := NewProviderManager(envProvider, logger)
	pm.AddProvider(mockProvider)

	// Close should return the last error
	err = pm.Close()
	assert.Error(t, err)
}

// TestCachingProvider_CacheHitAndMiss tests cache hit and miss scenarios
func TestCachingProvider_CacheHitAndMiss(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create env provider
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "CACHE_HIT_MISS_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	// Set env var
	os.Setenv("CACHE_HIT_MISS_TEST_SECRET", "value")
	defer os.Unsetenv("CACHE_HIT_MISS_TEST_SECRET")

	// Wrap with caching
	cachingProvider := NewCachingProvider(envProvider, 1*time.Minute, logger)

	// First call - cache miss
	secret1, err := cachingProvider.GetSecret(ctx, "secret")
	require.NoError(t, err)
	assert.NotNil(t, secret1)

	// Second call - cache hit
	secret2, err := cachingProvider.GetSecret(ctx, "secret")
	require.NoError(t, err)
	assert.NotNil(t, secret2)

	// Should be the same object (from cache)
	assert.Equal(t, secret1.Name, secret2.Name)
}

// TestCachingProvider_CacheInvalidation tests cache invalidation
func TestCachingProvider_CacheInvalidation(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create local provider
	tmpDir, err := os.MkdirTemp("", "cache-invalidation-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	localProvider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   logger,
	})
	require.NoError(t, err)

	// Wrap with caching
	cachingProvider := NewCachingProvider(localProvider, 1*time.Minute, logger)

	// Write initial secret
	err = cachingProvider.WriteSecret(ctx, "invalidation-test", map[string][]byte{
		"key": []byte("initial"),
	})
	require.NoError(t, err)

	// Read it (should be cached)
	secret1, err := cachingProvider.GetSecret(ctx, "invalidation-test")
	require.NoError(t, err)
	val1, _ := secret1.GetString("key")
	assert.Equal(t, "initial", val1)

	// Write new value (should invalidate cache)
	err = cachingProvider.WriteSecret(ctx, "invalidation-test", map[string][]byte{
		"key": []byte("updated"),
	})
	require.NoError(t, err)

	// Read again (should get new value)
	secret2, err := cachingProvider.GetSecret(ctx, "invalidation-test")
	require.NoError(t, err)
	val2, _ := secret2.GetString("key")
	assert.Equal(t, "updated", val2)
}

// TestCachingProvider_DeleteInvalidatesCache tests that delete invalidates cache
func TestCachingProvider_DeleteInvalidatesCache(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create local provider
	tmpDir, err := os.MkdirTemp("", "cache-delete-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	localProvider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   logger,
	})
	require.NoError(t, err)

	// Wrap with caching
	cachingProvider := NewCachingProvider(localProvider, 1*time.Minute, logger)

	// Write secret
	err = cachingProvider.WriteSecret(ctx, "delete-cache-test", map[string][]byte{
		"key": []byte("value"),
	})
	require.NoError(t, err)

	// Read it (should be cached)
	_, err = cachingProvider.GetSecret(ctx, "delete-cache-test")
	require.NoError(t, err)

	// Delete (should invalidate cache)
	err = cachingProvider.DeleteSecret(ctx, "delete-cache-test")
	require.NoError(t, err)

	// Read again (should fail)
	_, err = cachingProvider.GetSecret(ctx, "delete-cache-test")
	assert.Error(t, err)
}

// TestProviderManager_HealthCheckAllProviders tests health check for all providers
func TestProviderManager_HealthCheckAllProviders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create multiple providers
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "HEALTH_ALL_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	noopProvider := NewNoopProvider(logger)

	pm := NewProviderManager(envProvider, logger)
	pm.AddProvider(noopProvider)

	// Health check all
	results := pm.HealthCheck(ctx)
	assert.Len(t, results, 2)
	assert.NoError(t, results[ProviderTypeEnv])
	assert.NoError(t, results[ProviderType("noop")])
}

// TestNewProviderFromConfig_VaultWithTLS tests creating vault provider with TLS config
func TestNewProviderFromConfig_VaultWithTLS(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	cfg := config.DefaultConfig()
	cfg.SecretsProvider = ""
	cfg.VaultEnabled = true
	cfg.VaultAddress = "https://vault.example.com:8200"
	cfg.VaultAuthMethod = "token"
	cfg.VaultCACert = "/path/to/ca.crt"
	cfg.VaultTLSSkipVerify = true

	// This will fail because we can't connect to Vault, but it tests the TLS config path
	_, err := NewProviderFromConfig(ctx, cfg, k8sClient, logger)
	assert.Error(t, err)
}

// TestBuildVaultConfig_AllFields tests buildVaultConfig with all fields
func TestBuildVaultConfig_AllFields(t *testing.T) {
	logger := zap.NewNop()

	cfg := config.DefaultConfig()
	cfg.VaultAddress = "https://vault.example.com:8200"
	cfg.VaultNamespace = "my-namespace"
	cfg.VaultAuthMethod = "kubernetes"
	cfg.VaultRole = "my-role"
	cfg.VaultMountPath = "kubernetes"
	cfg.VaultSecretMountPoint = "kv"
	cfg.VaultTimeout = 60 * time.Second
	cfg.VaultMaxRetries = 5
	cfg.VaultRetryWaitMin = 1 * time.Second
	cfg.VaultRetryWaitMax = 10 * time.Second
	cfg.VaultCACert = "/path/to/ca.crt"
	cfg.VaultClientCert = "/path/to/client.crt"
	cfg.VaultTLSSkipVerify = false

	vaultCfg := buildVaultConfig(cfg, logger)

	assert.Equal(t, "https://vault.example.com:8200", vaultCfg.Address)
	assert.Equal(t, "my-namespace", vaultCfg.Namespace)
	assert.Equal(t, "kubernetes", vaultCfg.AuthMethod)
	assert.Equal(t, "my-role", vaultCfg.Role)
	assert.Equal(t, "kubernetes", vaultCfg.MountPath)
	assert.Equal(t, "kv", vaultCfg.SecretMountPoint)
	assert.Equal(t, 60*time.Second, vaultCfg.Timeout)
	assert.Equal(t, 5, vaultCfg.MaxRetries)
	assert.Equal(t, 1*time.Second, vaultCfg.RetryWaitMin)
	assert.Equal(t, 10*time.Second, vaultCfg.RetryWaitMax)
	assert.NotNil(t, vaultCfg.TLSConfig)
	assert.False(t, vaultCfg.TLSConfig.InsecureSkipVerify)
}

// TestBuildVaultConfig_NoTLS tests buildVaultConfig without TLS
func TestBuildVaultConfig_NoTLS(t *testing.T) {
	logger := zap.NewNop()

	cfg := config.DefaultConfig()
	cfg.VaultAddress = "http://vault.example.com:8200"
	cfg.VaultCACert = ""
	cfg.VaultClientCert = ""
	cfg.VaultTLSSkipVerify = false

	vaultCfg := buildVaultConfig(cfg, logger)

	assert.Nil(t, vaultCfg.TLSConfig)
}

// TestNoopProvider_AllMethods tests all NoopProvider methods
func TestNoopProvider_AllMethods(t *testing.T) {
	logger := zap.NewNop()
	provider := NewNoopProvider(logger)
	ctx := context.Background()

	// Type
	assert.Equal(t, ProviderType("noop"), provider.Type())

	// GetSecret
	secret, err := provider.GetSecret(ctx, "any-path")
	assert.Nil(t, secret)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)

	// ListSecrets
	secrets, err := provider.ListSecrets(ctx, "any-path")
	assert.NoError(t, err)
	assert.Empty(t, secrets)

	// WriteSecret
	err = provider.WriteSecret(ctx, "any-path", map[string][]byte{"key": []byte("value")})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReadOnly)

	// DeleteSecret
	err = provider.DeleteSecret(ctx, "any-path")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReadOnly)

	// IsReadOnly
	assert.True(t, provider.IsReadOnly())

	// HealthCheck
	err = provider.HealthCheck(ctx)
	assert.NoError(t, err)

	// Close
	err = provider.Close()
	assert.NoError(t, err)
}

// TestProviderManager_GetSecretFromProvider_Success tests getting secret from specific provider
func TestProviderManager_GetSecretFromProvider_Success(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create env provider
	envProvider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "GET_FROM_PROVIDER_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	// Set env var
	os.Setenv("GET_FROM_PROVIDER_TEST_SECRET", "value")
	defer os.Unsetenv("GET_FROM_PROVIDER_TEST_SECRET")

	pm := NewProviderManager(envProvider, logger)

	// Get secret from specific provider
	secret, err := pm.GetSecretFromProvider(ctx, ProviderTypeEnv, "secret")
	require.NoError(t, err)
	assert.NotNil(t, secret)
	val, ok := secret.GetString("value")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}
