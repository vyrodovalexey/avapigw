package secrets

import (
	"context"
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
