package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// Default configuration values for Vault client.
// These constants provide sensible defaults for production use and
// can be overridden via Config struct.
const (
	// DefaultVaultAddress is the default Vault server address.
	// Used when no address is explicitly configured.
	DefaultVaultAddress = "http://localhost:8200"

	// DefaultTimeout is the default request timeout for Vault operations.
	// 30 seconds provides a reasonable balance between allowing slow operations
	// and failing fast on network issues.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxRetries is the default maximum number of retries for failed requests.
	// 5 retries with exponential backoff provides good resilience against transient failures.
	DefaultMaxRetries = 5

	// DefaultRetryWaitMin is the default minimum wait time between retries.
	// 500ms provides a reasonable starting point for exponential backoff.
	DefaultRetryWaitMin = 500 * time.Millisecond

	// DefaultRetryWaitMax is the default maximum wait time between retries.
	// 60 seconds caps the backoff to prevent excessively long waits.
	DefaultRetryWaitMax = 60 * time.Second

	// DefaultBackoffMultiplier is the default multiplier for exponential backoff.
	// 2.0 doubles the wait time on each retry attempt.
	DefaultBackoffMultiplier = 2.0

	// DefaultJitter is the default jitter factor (0.0 to 1.0) for exponential backoff.
	// 0.2 (20%) adds randomness to prevent thundering herd problems.
	DefaultJitter = 0.2

	// DefaultTLSMinVersion is the minimum TLS version for secure connections.
	// TLS 1.2 is the minimum recommended version for security.
	DefaultTLSMinVersion = tls.VersionTLS12
)

// Config holds the configuration for the Vault client.
type Config struct {
	// Address is the Vault server address.
	Address string

	// Namespace is the Vault namespace (Enterprise only).
	Namespace string

	// TLSConfig holds TLS configuration.
	TLSConfig *TLSConfig

	// Timeout is the request timeout.
	Timeout time.Duration

	// MaxRetries is the maximum number of retries for failed requests.
	MaxRetries int

	// RetryWaitMin is the minimum wait time between retries.
	RetryWaitMin time.Duration

	// RetryWaitMax is the maximum wait time between retries.
	RetryWaitMax time.Duration

	// BackoffType is the type of backoff strategy to use.
	// Defaults to decorrelated jitter for best thundering herd prevention.
	BackoffType BackoffType

	// BackoffMultiplier is the multiplier for exponential backoff.
	// Default is 2.0.
	BackoffMultiplier float64

	// Jitter is the jitter factor (0.0 to 1.0) for exponential backoff.
	// Default is 0.2.
	Jitter float64
}

// TLSConfig holds TLS configuration for Vault connection.
type TLSConfig struct {
	// CACert is the CA certificate PEM data.
	CACert []byte

	// ClientCert is the client certificate PEM data.
	ClientCert []byte

	// ClientKey is the client key PEM data.
	ClientKey []byte

	// InsecureSkipVerify skips TLS certificate verification.
	InsecureSkipVerify bool

	// ServerName is the expected server name for TLS verification.
	ServerName string
}

// DefaultConfig returns a Config with default values.
// Uses decorrelated jitter backoff which is recommended for preventing
// thundering herd problems in distributed systems.
func DefaultConfig() *Config {
	return &Config{
		Address:           DefaultVaultAddress,
		Timeout:           DefaultTimeout,
		MaxRetries:        DefaultMaxRetries,
		RetryWaitMin:      DefaultRetryWaitMin,
		RetryWaitMax:      DefaultRetryWaitMax,
		BackoffType:       BackoffTypeDecorrelatedJitter,
		BackoffMultiplier: DefaultBackoffMultiplier,
		Jitter:            DefaultJitter,
	}
}

// GetRetryConfig returns a RetryConfig based on the client configuration.
func (c *Config) GetRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:        c.MaxRetries,
		WaitMin:           c.RetryWaitMin,
		WaitMax:           c.RetryWaitMax,
		BackoffType:       c.BackoffType,
		BackoffMultiplier: c.BackoffMultiplier,
		Jitter:            c.Jitter,
		OperationName:     "vault_client",
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.Address == "" {
		return fmt.Errorf("%w: address is required", ErrInvalidConfig)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("%w: timeout must be positive", ErrInvalidConfig)
	}
	if c.MaxRetries < 0 {
		return fmt.Errorf("%w: max retries must be non-negative", ErrInvalidConfig)
	}
	return nil
}

// Client is a Vault client with authentication and retry support.
type Client struct {
	vaultClient *vault.Client
	config      *Config
	authMethod  AuthMethod
	token       string
	tokenExpiry time.Time
	mu          sync.RWMutex
	logger      *zap.Logger
	closed      bool
}

// NewClient creates a new Vault client.
func NewClient(config *Config, logger *zap.Logger) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	// Create Vault client configuration
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = config.Address
	vaultConfig.Timeout = config.Timeout
	vaultConfig.MaxRetries = config.MaxRetries
	vaultConfig.MinRetryWait = config.RetryWaitMin
	vaultConfig.MaxRetryWait = config.RetryWaitMax

	// Configure TLS if provided
	if config.TLSConfig != nil {
		tlsConfig, err := createTLSConfig(config.TLSConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		vaultConfig.HttpClient = &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}

	// Create Vault client
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Set namespace if provided
	if config.Namespace != "" {
		vaultClient.SetNamespace(config.Namespace)
	}

	client := &Client{
		vaultClient: vaultClient,
		config:      config,
		logger:      logger,
	}

	logger.Info("Vault client created",
		zap.String("address", config.Address),
		zap.String("namespace", config.Namespace),
	)

	return client, nil
}

// createTLSConfig creates a TLS configuration from the provided TLSConfig.
func createTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	//nolint:gosec // G402: InsecureSkipVerify is intentionally configurable for dev/test environments
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ServerName:         cfg.ServerName,
		MinVersion:         DefaultTLSMinVersion,
	}

	// Add CA certificate
	if len(cfg.CACert) > 0 {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(cfg.CACert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Add client certificate
	if len(cfg.ClientCert) > 0 && len(cfg.ClientKey) > 0 {
		cert, err := tls.X509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// SetAuthMethod sets the authentication method for the client.
func (c *Client) SetAuthMethod(auth AuthMethod) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authMethod = auth
}

// Authenticate authenticates the client with Vault.
func (c *Client) Authenticate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.authMethod == nil {
		return fmt.Errorf("%w: no authentication method configured", ErrAuthenticationFailed)
	}

	c.logger.Info("Authenticating with Vault",
		zap.String("method", c.authMethod.Name()),
	)

	secret, err := c.authMethod.Authenticate(ctx, c.vaultClient)
	if err != nil {
		c.logger.Error("Vault authentication failed",
			zap.String("method", c.authMethod.Name()),
			zap.Error(err),
		)
		RecordAuthentication(c.authMethod.Name(), false)
		return fmt.Errorf("%w: %w", ErrAuthenticationFailed, err)
	}

	if secret == nil || secret.Auth == nil {
		c.logger.Error("Vault authentication returned no auth info")
		RecordAuthentication(c.authMethod.Name(), false)
		return fmt.Errorf("%w: no auth info returned", ErrAuthenticationFailed)
	}

	// Set the token
	c.token = secret.Auth.ClientToken
	c.vaultClient.SetToken(c.token)

	// Calculate token expiry
	if secret.Auth.LeaseDuration > 0 {
		c.tokenExpiry = time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second)
	} else {
		// Token doesn't expire
		c.tokenExpiry = time.Time{}
	}

	c.logger.Info("Vault authentication successful",
		zap.String("method", c.authMethod.Name()),
		zap.Bool("renewable", secret.Auth.Renewable),
		zap.Int("leaseDuration", secret.Auth.LeaseDuration),
	)

	RecordAuthentication(c.authMethod.Name(), true)
	return nil
}

// IsAuthenticated returns true if the client is authenticated and the token is valid.
func (c *Client) IsAuthenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.token == "" {
		return false
	}

	// Check if token has expired
	if !c.tokenExpiry.IsZero() && time.Now().After(c.tokenExpiry) {
		return false
	}

	return true
}

// ensureAuthenticated ensures the client is authenticated.
func (c *Client) ensureAuthenticated(ctx context.Context) error {
	if c.IsAuthenticated() {
		return nil
	}
	return c.Authenticate(ctx)
}

// ReadSecret reads a secret from Vault at the specified path.
func (c *Client) ReadSecret(ctx context.Context, path string) (*Secret, error) {
	if path == "" {
		return nil, NewVaultError("read", path, ErrInvalidPath)
	}

	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, err
	}

	c.logger.Debug("Reading secret from Vault", zap.String("path", path))

	start := time.Now()
	secret, err := c.vaultClient.Logical().ReadWithContext(ctx, path)
	duration := time.Since(start)

	RecordRequest("read", duration, err == nil)

	if err != nil {
		c.logger.Error("Failed to read secret from Vault",
			zap.String("path", path),
			zap.Error(err),
		)
		return nil, NewVaultError("read", path, err)
	}

	if secret == nil {
		c.logger.Debug("Secret not found in Vault", zap.String("path", path))
		return nil, NewVaultError("read", path, ErrSecretNotFound)
	}

	c.logger.Debug("Successfully read secret from Vault",
		zap.String("path", path),
		zap.Duration("duration", duration),
	)

	return convertSecret(secret), nil
}

// ReadSecretWithRetry reads a secret from Vault with exponential backoff retry.
// This is useful for operations that may fail due to transient errors.
func (c *Client) ReadSecretWithRetry(ctx context.Context, path string) (*Secret, error) {
	retryConfig := c.config.GetRetryConfig()
	retryConfig.OperationName = "vault_read_secret"
	retryConfig.Logger = c.logger

	return DoWithResult(ctx, retryConfig, func() (*Secret, error) {
		return c.ReadSecret(ctx, path)
	})
}

// WriteSecretWithRetry writes a secret to Vault with exponential backoff retry.
// This is useful for operations that may fail due to transient errors.
func (c *Client) WriteSecretWithRetry(ctx context.Context, path string, data map[string]interface{}) error {
	retryConfig := c.config.GetRetryConfig()
	retryConfig.OperationName = "vault_write_secret"
	retryConfig.Logger = c.logger

	return WithRetry(ctx, retryConfig, func() error {
		return c.WriteSecret(ctx, path, data)
	})
}

// AuthenticateWithRetry authenticates with Vault using exponential backoff retry.
// This is useful for initial connection establishment.
func (c *Client) AuthenticateWithRetry(ctx context.Context) error {
	retryConfig := c.config.GetRetryConfig()
	retryConfig.OperationName = "vault_authenticate"
	retryConfig.Logger = c.logger

	return WithRetry(ctx, retryConfig, func() error {
		return c.Authenticate(ctx)
	})
}

// WriteSecret writes a secret to Vault at the specified path.
func (c *Client) WriteSecret(ctx context.Context, path string, data map[string]interface{}) error {
	if path == "" {
		return NewVaultError("write", path, ErrInvalidPath)
	}

	if err := c.ensureAuthenticated(ctx); err != nil {
		return err
	}

	c.logger.Debug("Writing secret to Vault", zap.String("path", path))

	start := time.Now()
	_, err := c.vaultClient.Logical().WriteWithContext(ctx, path, data)
	duration := time.Since(start)

	RecordRequest("write", duration, err == nil)

	if err != nil {
		c.logger.Error("Failed to write secret to Vault",
			zap.String("path", path),
			zap.Error(err),
		)
		return NewVaultError("write", path, err)
	}

	c.logger.Debug("Successfully wrote secret to Vault",
		zap.String("path", path),
		zap.Duration("duration", duration),
	)

	return nil
}

// DeleteSecret deletes a secret from Vault at the specified path.
func (c *Client) DeleteSecret(ctx context.Context, path string) error {
	if path == "" {
		return NewVaultError("delete", path, ErrInvalidPath)
	}

	if err := c.ensureAuthenticated(ctx); err != nil {
		return err
	}

	c.logger.Debug("Deleting secret from Vault", zap.String("path", path))

	start := time.Now()
	_, err := c.vaultClient.Logical().DeleteWithContext(ctx, path)
	duration := time.Since(start)

	RecordRequest("delete", duration, err == nil)

	if err != nil {
		c.logger.Error("Failed to delete secret from Vault",
			zap.String("path", path),
			zap.Error(err),
		)
		return NewVaultError("delete", path, err)
	}

	c.logger.Debug("Successfully deleted secret from Vault",
		zap.String("path", path),
		zap.Duration("duration", duration),
	)

	return nil
}

// ListSecrets lists secrets at the specified path.
func (c *Client) ListSecrets(ctx context.Context, path string) ([]string, error) {
	if path == "" {
		return nil, NewVaultError("list", path, ErrInvalidPath)
	}

	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, err
	}

	c.logger.Debug("Listing secrets from Vault", zap.String("path", path))

	start := time.Now()
	secret, err := c.vaultClient.Logical().ListWithContext(ctx, path)
	duration := time.Since(start)

	RecordRequest("list", duration, err == nil)

	if err != nil {
		c.logger.Error("Failed to list secrets from Vault",
			zap.String("path", path),
			zap.Error(err),
		)
		return nil, NewVaultError("list", path, err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if s, ok := key.(string); ok {
			result = append(result, s)
		}
	}

	c.logger.Debug("Successfully listed secrets from Vault",
		zap.String("path", path),
		zap.Int("count", len(result)),
		zap.Duration("duration", duration),
	)

	return result, nil
}

// RenewToken renews the current token.
func (c *Client) RenewToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token == "" {
		return ErrNotAuthenticated
	}

	c.logger.Debug("Renewing Vault token")

	start := time.Now()
	secret, err := c.vaultClient.Auth().Token().RenewSelfWithContext(ctx, 0)
	duration := time.Since(start)

	RecordRequest("renew_token", duration, err == nil)

	if err != nil {
		c.logger.Error("Failed to renew Vault token", zap.Error(err))
		return fmt.Errorf("failed to renew token: %w", err)
	}

	if secret != nil && secret.Auth != nil && secret.Auth.LeaseDuration > 0 {
		c.tokenExpiry = time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second)
	}

	c.logger.Debug("Successfully renewed Vault token",
		zap.Duration("duration", duration),
	)

	return nil
}

// GetVaultClient returns the underlying Vault client.
// Use with caution - prefer using the Client methods.
func (c *Client) GetVaultClient() *vault.Client {
	return c.vaultClient
}

// Close closes the client and releases resources.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	c.token = ""
	c.logger.Info("Vault client closed")

	return nil
}

// convertSecret converts a Vault secret to our Secret type.
func convertSecret(s *vault.Secret) *Secret {
	if s == nil {
		return nil
	}

	secret := &Secret{
		Data:          s.Data,
		LeaseID:       s.LeaseID,
		LeaseDuration: s.LeaseDuration,
		Renewable:     s.Renewable,
	}

	// Extract metadata for KV v2
	if metadata, ok := s.Data["metadata"].(map[string]interface{}); ok {
		secret.Metadata = extractMetadata(metadata)
	}

	// For KV v2, the actual data is in the "data" field
	if data, ok := s.Data["data"].(map[string]interface{}); ok {
		secret.Data = data
	}

	return secret
}

// extractMetadata extracts metadata from a KV v2 secret.
func extractMetadata(metadata map[string]interface{}) *SecretMetadata {
	m := &SecretMetadata{}

	if createdTime, ok := metadata["created_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, createdTime); err == nil {
			m.CreatedTime = t
		}
	}

	// Handle version as both float64 (from direct map creation) and json.Number (from Vault API)
	switch v := metadata["version"].(type) {
	case float64:
		m.Version = int(v)
	case json.Number:
		if intVal, err := v.Int64(); err == nil {
			m.Version = int(intVal)
		}
	}

	if deletedTime, ok := metadata["deletion_time"].(string); ok && deletedTime != "" {
		if t, err := time.Parse(time.RFC3339Nano, deletedTime); err == nil {
			m.DeletedTime = &t
		}
	}

	if destroyed, ok := metadata["destroyed"].(bool); ok {
		m.Destroyed = destroyed
	}

	return m
}
