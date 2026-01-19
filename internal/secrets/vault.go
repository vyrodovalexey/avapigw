package secrets

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// VaultProviderConfig holds configuration for the Vault secrets provider
type VaultProviderConfig struct {
	// Address is the Vault server address
	Address string
	// Namespace is the Vault namespace (Enterprise only)
	Namespace string
	// AuthMethod is the authentication method (kubernetes, token, approle)
	AuthMethod string
	// Role is the Vault role for Kubernetes auth
	Role string
	// MountPath is the auth mount path
	MountPath string
	// Token is the Vault token for token auth
	Token string
	// AppRoleID is the AppRole role ID
	AppRoleID string
	// AppRoleSecretID is the AppRole secret ID
	AppRoleSecretID string
	// SecretMountPoint is the KV secrets engine mount point
	SecretMountPoint string
	// TLSConfig holds TLS configuration
	TLSConfig *vault.TLSConfig
	// Timeout is the request timeout
	Timeout time.Duration
	// MaxRetries is the maximum number of retries
	MaxRetries int
	// RetryWaitMin is the minimum wait time between retries
	RetryWaitMin time.Duration
	// RetryWaitMax is the maximum wait time between retries
	RetryWaitMax time.Duration
	// Logger is the logger instance
	Logger *zap.Logger
}

// VaultProvider implements the Provider interface using HashiCorp Vault
type VaultProvider struct {
	client           *vault.Client
	kv2Client        *vault.KV2Client
	secretMountPoint string
	logger           *zap.Logger
}

// vaultProviderDefaults holds the default values for Vault provider configuration.
type vaultProviderDefaults struct {
	secretMountPoint string
	timeout          time.Duration
	maxRetries       int
	retryWaitMin     time.Duration
	retryWaitMax     time.Duration
}

// applyVaultProviderDefaults applies default values to the configuration.
func applyVaultProviderDefaults(cfg *VaultProviderConfig) vaultProviderDefaults {
	defaults := vaultProviderDefaults{
		secretMountPoint: cfg.SecretMountPoint,
		timeout:          cfg.Timeout,
		maxRetries:       cfg.MaxRetries,
		retryWaitMin:     cfg.RetryWaitMin,
		retryWaitMax:     cfg.RetryWaitMax,
	}

	if defaults.secretMountPoint == "" {
		defaults.secretMountPoint = "secret"
	}
	if defaults.timeout == 0 {
		defaults.timeout = 30 * time.Second
	}
	if defaults.maxRetries == 0 {
		defaults.maxRetries = 3
	}
	if defaults.retryWaitMin == 0 {
		defaults.retryWaitMin = 500 * time.Millisecond
	}
	if defaults.retryWaitMax == 0 {
		defaults.retryWaitMax = 5 * time.Second
	}

	return defaults
}

// createVaultClientFromConfig creates a Vault client from the configuration.
func createVaultClientFromConfig(
	ctx context.Context,
	cfg *VaultProviderConfig,
	defaults vaultProviderDefaults,
	logger *zap.Logger,
) (*vault.Client, error) {
	clientConfig := &vault.Config{
		Address:      cfg.Address,
		Namespace:    cfg.Namespace,
		TLSConfig:    cfg.TLSConfig,
		Timeout:      defaults.timeout,
		MaxRetries:   defaults.maxRetries,
		RetryWaitMin: defaults.retryWaitMin,
		RetryWaitMax: defaults.retryWaitMax,
	}

	client, err := vault.NewClient(clientConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	authMethod, err := createVaultAuthMethod(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth method: %w", err)
	}

	client.SetAuthMethod(authMethod)

	if err := client.Authenticate(ctx); err != nil {
		return nil, fmt.Errorf("failed to authenticate with vault: %w", err)
	}

	return client, nil
}

// NewVaultProvider creates a new Vault secrets provider
func NewVaultProvider(ctx context.Context, cfg *VaultProviderConfig) (*VaultProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: config is required", ErrProviderNotConfigured)
	}
	if cfg.Address == "" {
		return nil, fmt.Errorf("%w: vault address is required", ErrProviderNotConfigured)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	defaults := applyVaultProviderDefaults(cfg)

	client, err := createVaultClientFromConfig(ctx, cfg, defaults, logger)
	if err != nil {
		return nil, err
	}

	kv2Client := vault.NewKV2Client(client, defaults.secretMountPoint, logger)

	logger.Info("Vault secrets provider initialized",
		zap.String("address", cfg.Address),
		zap.String("authMethod", cfg.AuthMethod),
		zap.String("mountPoint", defaults.secretMountPoint),
	)

	return &VaultProvider{
		client:           client,
		kv2Client:        kv2Client,
		secretMountPoint: defaults.secretMountPoint,
		logger:           logger,
	}, nil
}

// createVaultAuthMethod creates the appropriate authentication method
func createVaultAuthMethod(cfg *VaultProviderConfig) (vault.AuthMethod, error) {
	switch cfg.AuthMethod {
	case "kubernetes":
		mountPath := cfg.MountPath
		if mountPath == "" {
			mountPath = "kubernetes"
		}
		return vault.NewKubernetesAuth(cfg.Role, mountPath)

	case "token":
		if cfg.Token == "" {
			return nil, fmt.Errorf("token is required for token auth")
		}
		return vault.NewTokenAuth(cfg.Token)

	case "approle":
		if cfg.AppRoleID == "" {
			return nil, fmt.Errorf("role_id is required for approle auth")
		}
		mountPath := cfg.MountPath
		if mountPath == "" {
			mountPath = "approle"
		}
		return vault.NewAppRoleAuth(cfg.AppRoleID, cfg.AppRoleSecretID, mountPath)

	default:
		return nil, fmt.Errorf("unsupported auth method: %s", cfg.AuthMethod)
	}
}

// Type returns the provider type
func (p *VaultProvider) Type() ProviderType {
	return ProviderTypeVault
}

// GetSecret retrieves a secret from Vault
func (p *VaultProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "get", time.Since(start), nil)
	}()

	if path == "" {
		RecordOperation(p.Type(), "get", time.Since(start), ErrInvalidPath)
		return nil, ErrInvalidPath
	}

	p.logger.Debug("Getting secret from Vault",
		zap.String("path", path),
	)

	// Read secret using KV2 client
	vaultSecret, err := p.kv2Client.Get(ctx, path)
	if err != nil {
		p.logger.Error("Failed to read secret from Vault",
			zap.String("path", path),
			zap.Error(err),
		)
		RecordOperation(p.Type(), "get", time.Since(start), err)
		return nil, fmt.Errorf("failed to read secret from vault: %w", err)
	}

	if vaultSecret == nil {
		RecordOperation(p.Type(), "get", time.Since(start), ErrSecretNotFound)
		return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, path)
	}

	// Convert Vault secret to our Secret type
	data := make(map[string][]byte)
	for k, v := range vaultSecret.Data {
		if strVal, ok := v.(string); ok {
			data[k] = []byte(strVal)
		}
	}

	secret := &Secret{
		Name:     path,
		Data:     data,
		Metadata: make(map[string]string),
	}

	// Add metadata if available
	if vaultSecret.Metadata != nil {
		secret.Version = fmt.Sprintf("%d", vaultSecret.Metadata.Version)
		createdAt := vaultSecret.Metadata.CreatedTime
		secret.CreatedAt = &createdAt
	}

	p.logger.Debug("Successfully retrieved secret from Vault",
		zap.String("path", path),
		zap.Int("keys", len(data)),
	)

	return secret, nil
}

// ListSecrets lists secrets at a path in Vault
func (p *VaultProvider) ListSecrets(ctx context.Context, path string) ([]string, error) {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "list", time.Since(start), nil)
	}()

	p.logger.Debug("Listing secrets from Vault",
		zap.String("path", path),
	)

	secrets, err := p.kv2Client.List(ctx, path)
	if err != nil {
		p.logger.Error("Failed to list secrets from Vault",
			zap.String("path", path),
			zap.Error(err),
		)
		RecordOperation(p.Type(), "list", time.Since(start), err)
		return nil, fmt.Errorf("failed to list secrets from vault: %w", err)
	}

	p.logger.Debug("Successfully listed secrets from Vault",
		zap.String("path", path),
		zap.Int("count", len(secrets)),
	)

	return secrets, nil
}

// WriteSecret writes a secret to Vault
func (p *VaultProvider) WriteSecret(ctx context.Context, path string, data map[string][]byte) error {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "write", time.Since(start), nil)
	}()

	if path == "" {
		RecordOperation(p.Type(), "write", time.Since(start), ErrInvalidPath)
		return ErrInvalidPath
	}

	p.logger.Debug("Writing secret to Vault",
		zap.String("path", path),
	)

	// Convert byte data to interface map
	secretData := make(map[string]interface{})
	for k, v := range data {
		secretData[k] = string(v)
	}

	if err := p.kv2Client.Put(ctx, path, secretData); err != nil {
		p.logger.Error("Failed to write secret to Vault",
			zap.String("path", path),
			zap.Error(err),
		)
		RecordOperation(p.Type(), "write", time.Since(start), err)
		return fmt.Errorf("failed to write secret to vault: %w", err)
	}

	p.logger.Info("Wrote secret to Vault",
		zap.String("path", path),
	)

	return nil
}

// DeleteSecret deletes a secret from Vault
func (p *VaultProvider) DeleteSecret(ctx context.Context, path string) error {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "delete", time.Since(start), nil)
	}()

	if path == "" {
		RecordOperation(p.Type(), "delete", time.Since(start), ErrInvalidPath)
		return ErrInvalidPath
	}

	p.logger.Debug("Deleting secret from Vault",
		zap.String("path", path),
	)

	if err := p.kv2Client.Delete(ctx, path); err != nil {
		p.logger.Error("Failed to delete secret from Vault",
			zap.String("path", path),
			zap.Error(err),
		)
		RecordOperation(p.Type(), "delete", time.Since(start), err)
		return fmt.Errorf("failed to delete secret from vault: %w", err)
	}

	p.logger.Info("Deleted secret from Vault",
		zap.String("path", path),
	)

	return nil
}

// IsReadOnly returns false as Vault supports writes
func (p *VaultProvider) IsReadOnly() bool {
	return false
}

// HealthCheck checks Vault connectivity
func (p *VaultProvider) HealthCheck(ctx context.Context) error {
	start := time.Now()

	// Check if client is authenticated
	if !p.client.IsAuthenticated() {
		if err := p.client.Authenticate(ctx); err != nil {
			p.logger.Error("Vault provider health check failed - authentication error", zap.Error(err))
			RecordHealthStatus(p.Type(), false)
			RecordOperation(p.Type(), "health_check", time.Since(start), err)
			return fmt.Errorf("vault authentication failed: %w", err)
		}
	}

	RecordHealthStatus(p.Type(), true)
	RecordOperation(p.Type(), "health_check", time.Since(start), nil)
	return nil
}

// Close cleans up provider resources
func (p *VaultProvider) Close() error {
	p.logger.Debug("Closing Vault secrets provider")
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}

// GetVaultClient returns the underlying Vault client
// Use with caution - prefer using the Provider interface methods
func (p *VaultProvider) GetVaultClient() *vault.Client {
	return p.client
}

// GetKV2Client returns the underlying KV2 client
// Use with caution - prefer using the Provider interface methods
func (p *VaultProvider) GetKV2Client() *vault.KV2Client {
	return p.kv2Client
}
