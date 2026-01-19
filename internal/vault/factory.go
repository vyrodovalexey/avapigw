package vault

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
)

// FactoryConfig holds configuration for creating Vault clients.
type FactoryConfig struct {
	// Address is the Vault server address.
	Address string

	// Namespace is the Vault namespace (Enterprise only).
	Namespace string

	// AuthMethod is the authentication method (kubernetes, token, approle).
	AuthMethod string

	// Role is the Vault role for Kubernetes auth.
	Role string

	// MountPath is the auth mount path.
	MountPath string

	// Token is the Vault token for token auth.
	Token string

	// AppRoleID is the AppRole role ID.
	AppRoleID string

	// AppRoleSecretID is the AppRole secret ID.
	AppRoleSecretID string

	// TLSConfig holds TLS configuration.
	TLSConfig *TLSConfig

	// Timeout is the request timeout.
	Timeout time.Duration

	// MaxRetries is the maximum number of retries.
	MaxRetries int

	// RetryWaitMin is the minimum wait time between retries.
	RetryWaitMin time.Duration

	// RetryWaitMax is the maximum wait time between retries.
	RetryWaitMax time.Duration

	// CacheEnabled enables secret caching.
	CacheEnabled bool

	// CacheTTL is the cache TTL.
	CacheTTL time.Duration

	// TokenRenewalEnabled enables automatic token renewal.
	TokenRenewalEnabled bool

	// TokenRenewalInterval is the token renewal check interval.
	TokenRenewalInterval time.Duration
}

// Factory creates Vault clients with the specified configuration.
type Factory struct {
	config *FactoryConfig
	logger *zap.Logger
}

// NewFactory creates a new Vault client factory.
func NewFactory(config *FactoryConfig, logger *zap.Logger) *Factory {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Factory{
		config: config,
		logger: logger,
	}
}

// CreateClient creates a new Vault client with authentication.
func (f *Factory) CreateClient(ctx context.Context) (*Client, error) {
	// Create client configuration
	clientConfig := &Config{
		Address:      f.config.Address,
		Namespace:    f.config.Namespace,
		Timeout:      f.config.Timeout,
		MaxRetries:   f.config.MaxRetries,
		RetryWaitMin: f.config.RetryWaitMin,
		RetryWaitMax: f.config.RetryWaitMax,
		TLSConfig:    f.config.TLSConfig,
	}

	// Create client
	client, err := NewClient(clientConfig, f.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Configure authentication
	authMethod, err := f.createAuthMethod()
	if err != nil {
		return nil, fmt.Errorf("failed to create auth method: %w", err)
	}

	client.SetAuthMethod(authMethod)

	// Authenticate
	if err := client.Authenticate(ctx); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	f.logger.Info("Vault client created and authenticated",
		zap.String("address", f.config.Address),
		zap.String("authMethod", f.config.AuthMethod),
	)

	return client, nil
}

// CreateSecretManager creates a new SecretManager with the specified client.
func (f *Factory) CreateSecretManager(client *Client) *SecretManager {
	manager := NewSecretManager(client, f.logger)

	if f.config.CacheEnabled && f.config.CacheTTL > 0 {
		// Replace the default cache with one using the configured TTL
		manager.cache = NewSecretCache(f.config.CacheTTL)
	}

	return manager
}

// CreateKV2Client creates a new KV2Client with the specified client.
func (f *Factory) CreateKV2Client(client *Client, mountPoint string) *KV2Client {
	return NewKV2Client(client, mountPoint, f.logger)
}

// CreateCertificateManager creates a new CertificateManager with the specified client.
func (f *Factory) CreateCertificateManager(client *Client, refreshInterval time.Duration) *CertificateManager {
	return NewCertificateManager(client, refreshInterval, f.logger)
}

// CreateTokenRenewalManager creates a new TokenRenewalManager with the specified client.
func (f *Factory) CreateTokenRenewalManager(client *Client) *TokenRenewalManager {
	config := &TokenRenewalConfig{
		RenewalInterval:  f.config.TokenRenewalInterval,
		RenewalThreshold: f.config.TokenRenewalInterval * 2,
		MaxRetries:       3,
		RetryInterval:    30 * time.Second,
	}

	return NewTokenRenewalManager(client, config, f.logger)
}

// createAuthMethod creates the appropriate authentication method.
func (f *Factory) createAuthMethod() (AuthMethod, error) {
	switch f.config.AuthMethod {
	case "kubernetes":
		return NewKubernetesAuth(f.config.Role, f.config.MountPath)

	case "token":
		token := f.config.Token
		if token == "" {
			// Try to get token from environment
			token = os.Getenv("VAULT_TOKEN")
		}
		if token == "" {
			return nil, fmt.Errorf("token is required for token auth")
		}
		return NewTokenAuth(token)

	case "approle":
		if f.config.AppRoleID == "" {
			return nil, fmt.Errorf("role_id is required for approle auth")
		}
		secretID := f.config.AppRoleSecretID
		if secretID == "" {
			// Try to get secret ID from environment
			secretID = os.Getenv("VAULT_APPROLE_SECRET_ID")
		}
		return NewAppRoleAuth(f.config.AppRoleID, secretID, f.config.MountPath)

	default:
		return nil, fmt.Errorf("unsupported auth method: %s", f.config.AuthMethod)
	}
}

// VaultService provides a high-level interface for Vault operations.
type VaultService struct {
	client         *Client
	secretManager  *SecretManager
	kv2Client      *KV2Client
	certManager    *CertificateManager
	renewalManager *TokenRenewalManager
	logger         *zap.Logger
	stopCh         chan struct{}
}

// NewVaultService creates a new VaultService from the factory configuration.
func NewVaultService(ctx context.Context, config *FactoryConfig, logger *zap.Logger) (*VaultService, error) {
	factory := NewFactory(config, logger)

	// Create client
	client, err := factory.CreateClient(ctx)
	if err != nil {
		return nil, err
	}

	service := &VaultService{
		client:        client,
		secretManager: factory.CreateSecretManager(client),
		logger:        logger,
		stopCh:        make(chan struct{}),
	}

	// Create KV2 client if mount point is configured
	service.kv2Client = factory.CreateKV2Client(client, "secret")

	// Create certificate manager
	service.certManager = factory.CreateCertificateManager(client, 5*time.Minute)

	// Start token renewal if enabled
	if config.TokenRenewalEnabled {
		service.renewalManager = factory.CreateTokenRenewalManager(client)
		service.renewalManager.Start(ctx)
	}

	return service, nil
}

// Client returns the underlying Vault client.
func (s *VaultService) Client() *Client {
	return s.client
}

// SecretManager returns the secret manager.
func (s *VaultService) SecretManager() *SecretManager {
	return s.secretManager
}

// KV2Client returns the KV2 client.
func (s *VaultService) KV2Client() *KV2Client {
	return s.kv2Client
}

// CertificateManager returns the certificate manager.
func (s *VaultService) CertificateManager() *CertificateManager {
	return s.certManager
}

// Close closes the Vault service and releases resources.
func (s *VaultService) Close() error {
	close(s.stopCh)

	if s.renewalManager != nil {
		s.renewalManager.Stop()
	}

	if s.certManager != nil {
		_ = s.certManager.Close()
	}

	if s.secretManager != nil {
		_ = s.secretManager.Close()
	}

	if s.client != nil {
		_ = s.client.Close()
	}

	s.logger.Info("Vault service closed")
	return nil
}
