package secrets

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// ProviderConfig holds configuration for creating providers
type ProviderConfig struct {
	// Type is the provider type
	Type ProviderType
	// KubeClient is the Kubernetes client (required for kubernetes provider)
	KubeClient client.Client
	// Namespace is the default namespace for Kubernetes secrets
	Namespace string
	// LocalBasePath is the base path for local file secrets
	LocalBasePath string
	// EnvPrefix is the prefix for environment variable secrets
	EnvPrefix string
	// VaultConfig holds Vault-specific configuration
	VaultConfig *VaultProviderConfig
	// Logger is the logger instance
	Logger *zap.Logger
}

// NewProvider creates a new secrets provider based on config
func NewProvider(ctx context.Context, cfg *ProviderConfig) (Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: config is required", ErrProviderNotConfigured)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	switch cfg.Type {
	case ProviderTypeKubernetes:
		return NewKubernetesProvider(&KubernetesProviderConfig{
			Client:           cfg.KubeClient,
			DefaultNamespace: cfg.Namespace,
			Logger:           logger,
		})

	case ProviderTypeVault:
		if cfg.VaultConfig == nil {
			return nil, fmt.Errorf("%w: vault config is required for vault provider", ErrProviderNotConfigured)
		}
		cfg.VaultConfig.Logger = logger
		return NewVaultProvider(ctx, cfg.VaultConfig)

	case ProviderTypeLocal:
		return NewLocalProvider(&LocalProviderConfig{
			BasePath: cfg.LocalBasePath,
			Logger:   logger,
		})

	case ProviderTypeEnv:
		return NewEnvProvider(&EnvProviderConfig{
			Prefix: cfg.EnvPrefix,
			Logger: logger,
		})

	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidProviderType, cfg.Type)
	}
}

// determineProviderType determines the provider type from config.
func determineProviderType(cfg *config.Config) (ProviderType, error) {
	if cfg.SecretsProvider != "" {
		return ValidateProviderType(cfg.SecretsProvider)
	}
	if cfg.VaultEnabled {
		return ProviderTypeVault, nil
	}
	return ProviderTypeKubernetes, nil
}

// buildVaultConfig builds the Vault provider configuration from the main config.
func buildVaultConfig(cfg *config.Config, logger *zap.Logger) *VaultProviderConfig {
	vaultCfg := &VaultProviderConfig{
		Address:          cfg.VaultAddress,
		Namespace:        cfg.VaultNamespace,
		AuthMethod:       cfg.VaultAuthMethod,
		Role:             cfg.VaultRole,
		MountPath:        cfg.VaultMountPath,
		SecretMountPoint: cfg.VaultSecretMountPoint,
		Timeout:          cfg.VaultTimeout,
		MaxRetries:       cfg.VaultMaxRetries,
		RetryWaitMin:     cfg.VaultRetryWaitMin,
		RetryWaitMax:     cfg.VaultRetryWaitMax,
		Logger:           logger,
	}

	if cfg.VaultCACert != "" || cfg.VaultClientCert != "" || cfg.VaultTLSSkipVerify {
		vaultCfg.TLSConfig = &vault.TLSConfig{
			InsecureSkipVerify: cfg.VaultTLSSkipVerify,
		}
	}

	return vaultCfg
}

// NewProviderFromConfig creates a provider from the main application config
func NewProviderFromConfig(
	ctx context.Context,
	cfg *config.Config,
	kubeClient client.Client,
	logger *zap.Logger,
) (Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: config is required", ErrProviderNotConfigured)
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	providerType, err := determineProviderType(cfg)
	if err != nil {
		return nil, err
	}

	logger.Info("Creating secrets provider",
		zap.String("type", string(providerType)),
	)

	providerCfg := &ProviderConfig{
		Type:          providerType,
		KubeClient:    kubeClient,
		Namespace:     "default",
		LocalBasePath: cfg.SecretsLocalPath,
		EnvPrefix:     cfg.SecretsEnvPrefix,
		Logger:        logger,
	}

	if providerType == ProviderTypeVault {
		providerCfg.VaultConfig = buildVaultConfig(cfg, logger)
	}

	return NewProvider(ctx, providerCfg)
}

// NoopProvider is a provider that does nothing
// Used when secrets functionality is disabled
type NoopProvider struct {
	logger *zap.Logger
}

// NewNoopProvider creates a new no-op provider
func NewNoopProvider(logger *zap.Logger) *NoopProvider {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &NoopProvider{logger: logger}
}

// Type returns the provider type
func (p *NoopProvider) Type() ProviderType {
	return ProviderType("noop")
}

// GetSecret always returns not found
func (p *NoopProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	p.logger.Debug("NoopProvider.GetSecret called", zap.String("path", path))
	return nil, ErrSecretNotFound
}

// ListSecrets always returns empty list
func (p *NoopProvider) ListSecrets(ctx context.Context, path string) ([]string, error) {
	p.logger.Debug("NoopProvider.ListSecrets called", zap.String("path", path))
	return []string{}, nil
}

// WriteSecret always returns read-only error
func (p *NoopProvider) WriteSecret(ctx context.Context, path string, data map[string][]byte) error {
	p.logger.Debug("NoopProvider.WriteSecret called", zap.String("path", path))
	return ErrReadOnly
}

// DeleteSecret always returns read-only error
func (p *NoopProvider) DeleteSecret(ctx context.Context, path string) error {
	p.logger.Debug("NoopProvider.DeleteSecret called", zap.String("path", path))
	return ErrReadOnly
}

// IsReadOnly returns true
func (p *NoopProvider) IsReadOnly() bool {
	return true
}

// HealthCheck always returns nil
func (p *NoopProvider) HealthCheck(ctx context.Context) error {
	return nil
}

// Close does nothing
func (p *NoopProvider) Close() error {
	return nil
}

// ProviderManager manages multiple secrets providers
type ProviderManager struct {
	providers map[ProviderType]Provider
	primary   Provider
	logger    *zap.Logger
}

// NewProviderManager creates a new provider manager
func NewProviderManager(primary Provider, logger *zap.Logger) *ProviderManager {
	if logger == nil {
		logger = zap.NewNop()
	}

	pm := &ProviderManager{
		providers: make(map[ProviderType]Provider),
		primary:   primary,
		logger:    logger,
	}

	if primary != nil {
		pm.providers[primary.Type()] = primary
	}

	return pm
}

// AddProvider adds a provider to the manager
func (pm *ProviderManager) AddProvider(provider Provider) {
	if provider != nil {
		pm.providers[provider.Type()] = provider
	}
}

// GetProvider returns a provider by type
func (pm *ProviderManager) GetProvider(providerType ProviderType) (Provider, bool) {
	p, ok := pm.providers[providerType]
	return p, ok
}

// Primary returns the primary provider
func (pm *ProviderManager) Primary() Provider {
	return pm.primary
}

// SetPrimary sets the primary provider
func (pm *ProviderManager) SetPrimary(provider Provider) {
	pm.primary = provider
	if provider != nil {
		pm.providers[provider.Type()] = provider
	}
}

// GetSecret retrieves a secret from the primary provider
func (pm *ProviderManager) GetSecret(ctx context.Context, path string) (*Secret, error) {
	if pm.primary == nil {
		return nil, ErrProviderNotConfigured
	}
	return pm.primary.GetSecret(ctx, path)
}

// GetSecretFromProvider retrieves a secret from a specific provider
func (pm *ProviderManager) GetSecretFromProvider(
	ctx context.Context,
	providerType ProviderType,
	path string,
) (*Secret, error) {
	provider, ok := pm.providers[providerType]
	if !ok {
		return nil, fmt.Errorf("%w: provider %s not found", ErrProviderNotConfigured, providerType)
	}
	return provider.GetSecret(ctx, path)
}

// HealthCheck checks all providers
func (pm *ProviderManager) HealthCheck(ctx context.Context) map[ProviderType]error {
	results := make(map[ProviderType]error)
	for providerType, provider := range pm.providers {
		results[providerType] = provider.HealthCheck(ctx)
	}
	return results
}

// Close closes all providers
func (pm *ProviderManager) Close() error {
	var lastErr error
	for _, provider := range pm.providers {
		if err := provider.Close(); err != nil {
			pm.logger.Error("Failed to close provider",
				zap.String("type", string(provider.Type())),
				zap.Error(err),
			)
			lastErr = err
		}
	}
	return lastErr
}

// CachingProvider wraps a provider with caching
type CachingProvider struct {
	provider Provider
	cache    map[string]*cachedSecret
	ttl      time.Duration
	logger   *zap.Logger
}

type cachedSecret struct {
	secret    *Secret
	expiresAt time.Time
}

// NewCachingProvider creates a new caching provider wrapper
func NewCachingProvider(provider Provider, ttl time.Duration, logger *zap.Logger) *CachingProvider {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &CachingProvider{
		provider: provider,
		cache:    make(map[string]*cachedSecret),
		ttl:      ttl,
		logger:   logger,
	}
}

// Type returns the underlying provider type
func (p *CachingProvider) Type() ProviderType {
	return p.provider.Type()
}

// GetSecret retrieves a secret, using cache if available
func (p *CachingProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	// Check cache
	if cached, ok := p.cache[path]; ok {
		if time.Now().Before(cached.expiresAt) {
			p.logger.Debug("Cache hit", zap.String("path", path))
			return cached.secret, nil
		}
		// Expired, remove from cache
		delete(p.cache, path)
	}

	// Fetch from provider
	secret, err := p.provider.GetSecret(ctx, path)
	if err != nil {
		return nil, err
	}

	// Cache the result
	p.cache[path] = &cachedSecret{
		secret:    secret,
		expiresAt: time.Now().Add(p.ttl),
	}

	return secret, nil
}

// ListSecrets delegates to the underlying provider
func (p *CachingProvider) ListSecrets(ctx context.Context, path string) ([]string, error) {
	return p.provider.ListSecrets(ctx, path)
}

// WriteSecret delegates to the underlying provider and invalidates cache
func (p *CachingProvider) WriteSecret(ctx context.Context, path string, data map[string][]byte) error {
	err := p.provider.WriteSecret(ctx, path, data)
	if err == nil {
		delete(p.cache, path)
	}
	return err
}

// DeleteSecret delegates to the underlying provider and invalidates cache
func (p *CachingProvider) DeleteSecret(ctx context.Context, path string) error {
	err := p.provider.DeleteSecret(ctx, path)
	if err == nil {
		delete(p.cache, path)
	}
	return err
}

// IsReadOnly delegates to the underlying provider
func (p *CachingProvider) IsReadOnly() bool {
	return p.provider.IsReadOnly()
}

// HealthCheck delegates to the underlying provider
func (p *CachingProvider) HealthCheck(ctx context.Context) error {
	return p.provider.HealthCheck(ctx)
}

// Close closes the underlying provider
func (p *CachingProvider) Close() error {
	return p.provider.Close()
}

// InvalidateCache removes a path from the cache
func (p *CachingProvider) InvalidateCache(path string) {
	delete(p.cache, path)
}

// ClearCache clears all cached secrets
func (p *CachingProvider) ClearCache() {
	p.cache = make(map[string]*cachedSecret)
}
