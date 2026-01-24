package vault

import (
	"fmt"
	"time"
)

// AuthMethod specifies the Vault authentication method.
type AuthMethod string

// Authentication method constants.
const (
	// AuthMethodToken uses direct token authentication.
	AuthMethodToken AuthMethod = "token"

	// AuthMethodKubernetes uses Kubernetes ServiceAccount JWT authentication.
	AuthMethodKubernetes AuthMethod = "kubernetes"

	// AuthMethodAppRole uses AppRole authentication with RoleID and SecretID.
	AuthMethodAppRole AuthMethod = "approle"
)

// String returns the string representation of the auth method.
func (m AuthMethod) String() string {
	return string(m)
}

// IsValid returns true if the auth method is valid.
func (m AuthMethod) IsValid() bool {
	switch m {
	case AuthMethodToken, AuthMethodKubernetes, AuthMethodAppRole:
		return true
	default:
		return false
	}
}

// Config represents Vault client configuration.
type Config struct {
	// Enabled enables Vault integration.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Address is the Vault server address.
	Address string `yaml:"address" json:"address"`

	// Namespace is the Vault namespace (Enterprise feature).
	Namespace string `yaml:"namespace,omitempty" json:"namespace,omitempty"`

	// AuthMethod specifies the authentication method.
	AuthMethod AuthMethod `yaml:"authMethod" json:"authMethod"`

	// Token for token authentication.
	Token string `yaml:"token,omitempty" json:"token,omitempty"`

	// Kubernetes auth configuration.
	Kubernetes *KubernetesAuthConfig `yaml:"kubernetes,omitempty" json:"kubernetes,omitempty"`

	// AppRole auth configuration.
	AppRole *AppRoleAuthConfig `yaml:"appRole,omitempty" json:"appRole,omitempty"`

	// TLS configuration for Vault connection.
	TLS *VaultTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// Cache configuration.
	Cache *CacheConfig `yaml:"cache,omitempty" json:"cache,omitempty"`

	// Retry configuration.
	Retry *RetryConfig `yaml:"retry,omitempty" json:"retry,omitempty"`
}

// KubernetesAuthConfig configures Kubernetes authentication.
type KubernetesAuthConfig struct {
	// Role is the Vault role to authenticate as.
	Role string `yaml:"role" json:"role"`

	// MountPath is the mount path for the Kubernetes auth method.
	// Defaults to "kubernetes".
	MountPath string `yaml:"mountPath,omitempty" json:"mountPath,omitempty"`

	// TokenPath is the path to the ServiceAccount token file.
	// Defaults to "/var/run/secrets/kubernetes.io/serviceaccount/token".
	TokenPath string `yaml:"tokenPath,omitempty" json:"tokenPath,omitempty"`
}

// AppRoleAuthConfig configures AppRole authentication.
type AppRoleAuthConfig struct {
	// RoleID is the AppRole role ID.
	RoleID string `yaml:"roleId" json:"roleId"`

	// SecretID is the AppRole secret ID.
	SecretID string `yaml:"secretId" json:"secretId"`

	// MountPath is the mount path for the AppRole auth method.
	// Defaults to "approle".
	MountPath string `yaml:"mountPath,omitempty" json:"mountPath,omitempty"`
}

// VaultTLSConfig configures TLS for Vault connection.
type VaultTLSConfig struct {
	// CACert is the path to the CA certificate file.
	CACert string `yaml:"caCert,omitempty" json:"caCert,omitempty"`

	// CAPath is the path to a directory of CA certificates.
	CAPath string `yaml:"caPath,omitempty" json:"caPath,omitempty"`

	// ClientCert is the path to the client certificate file.
	ClientCert string `yaml:"clientCert,omitempty" json:"clientCert,omitempty"`

	// ClientKey is the path to the client private key file.
	ClientKey string `yaml:"clientKey,omitempty" json:"clientKey,omitempty"`

	// SkipVerify skips TLS certificate verification (insecure).
	SkipVerify bool `yaml:"skipVerify,omitempty" json:"skipVerify,omitempty"`
}

// CacheConfig configures secret caching.
type CacheConfig struct {
	// Enabled enables secret caching.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TTL is the cache time-to-live.
	// Defaults to 5 minutes.
	TTL time.Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// MaxSize is the maximum number of cached entries.
	// Defaults to 1000.
	MaxSize int `yaml:"maxSize,omitempty" json:"maxSize,omitempty"`
}

// RetryConfig configures retry behavior.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts.
	// Defaults to 3.
	MaxRetries int `yaml:"maxRetries,omitempty" json:"maxRetries,omitempty"`

	// BackoffBase is the base duration for exponential backoff.
	// Defaults to 100ms.
	BackoffBase time.Duration `yaml:"backoffBase,omitempty" json:"backoffBase,omitempty"`

	// BackoffMax is the maximum backoff duration.
	// Defaults to 5 seconds.
	BackoffMax time.Duration `yaml:"backoffMax,omitempty" json:"backoffMax,omitempty"`
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		Enabled:    false,
		AuthMethod: AuthMethodToken,
		Cache:      DefaultCacheConfig(),
		Retry:      DefaultRetryConfig(),
	}
}

// DefaultCacheConfig returns a CacheConfig with default values.
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Enabled: true,
		TTL:     5 * time.Minute,
		MaxSize: 1000,
	}
}

// DefaultRetryConfig returns a RetryConfig with default values.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:  3,
		BackoffBase: 100 * time.Millisecond,
		BackoffMax:  5 * time.Second,
	}
}

// Validate validates the Vault configuration.
func (c *Config) Validate() error {
	if c == nil {
		return NewConfigurationError("", "configuration is nil")
	}

	// If not enabled, no further validation needed
	if !c.Enabled {
		return nil
	}

	if err := c.validateBasicConfig(); err != nil {
		return err
	}

	if err := c.validateAuthMethodConfig(); err != nil {
		return err
	}

	return c.validateOptionalConfigs()
}

// validateBasicConfig validates basic configuration fields.
func (c *Config) validateBasicConfig() error {
	if c.Address == "" {
		return NewConfigurationError("address", "vault address is required")
	}

	if !c.AuthMethod.IsValid() {
		return NewConfigurationError("authMethod", fmt.Sprintf("invalid auth method: %s", c.AuthMethod))
	}

	return nil
}

// validateAuthMethodConfig validates auth method specific configuration.
func (c *Config) validateAuthMethodConfig() error {
	switch c.AuthMethod {
	case AuthMethodToken:
		if c.Token == "" {
			return NewConfigurationError("token", "token is required for token authentication")
		}
	case AuthMethodKubernetes:
		return c.validateKubernetesConfig()
	case AuthMethodAppRole:
		return c.validateAppRoleConfig()
	}
	return nil
}

// validateOptionalConfigs validates optional configuration sections.
func (c *Config) validateOptionalConfigs() error {
	if c.TLS != nil {
		if err := c.TLS.Validate(); err != nil {
			return err
		}
	}

	if c.Cache != nil {
		if err := c.Cache.Validate(); err != nil {
			return err
		}
	}

	if c.Retry != nil {
		if err := c.Retry.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// validateKubernetesConfig validates Kubernetes auth configuration.
func (c *Config) validateKubernetesConfig() error {
	if c.Kubernetes == nil {
		return NewConfigurationError("kubernetes", "kubernetes configuration is required for kubernetes authentication")
	}
	if c.Kubernetes.Role == "" {
		return NewConfigurationError("kubernetes.role", "role is required for kubernetes authentication")
	}
	return nil
}

// validateAppRoleConfig validates AppRole auth configuration.
func (c *Config) validateAppRoleConfig() error {
	if c.AppRole == nil {
		return NewConfigurationError("appRole", "appRole configuration is required for approle authentication")
	}
	if c.AppRole.RoleID == "" {
		return NewConfigurationError("appRole.roleId", "roleId is required for approle authentication")
	}
	if c.AppRole.SecretID == "" {
		return NewConfigurationError("appRole.secretId", "secretId is required for approle authentication")
	}
	return nil
}

// Validate validates the TLS configuration.
func (c *VaultTLSConfig) Validate() error {
	if c == nil {
		return nil
	}

	// If client cert is provided, key must also be provided
	if c.ClientCert != "" && c.ClientKey == "" {
		return NewConfigurationError("tls.clientKey", "client key is required when client cert is provided")
	}
	if c.ClientKey != "" && c.ClientCert == "" {
		return NewConfigurationError("tls.clientCert", "client cert is required when client key is provided")
	}

	return nil
}

// Validate validates the cache configuration.
func (c *CacheConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.Enabled {
		if c.TTL < 0 {
			return NewConfigurationError("cache.ttl", "TTL cannot be negative")
		}
		if c.MaxSize < 0 {
			return NewConfigurationError("cache.maxSize", "maxSize cannot be negative")
		}
	}

	return nil
}

// Validate validates the retry configuration.
func (c *RetryConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.MaxRetries < 0 {
		return NewConfigurationError("retry.maxRetries", "maxRetries cannot be negative")
	}
	if c.BackoffBase < 0 {
		return NewConfigurationError("retry.backoffBase", "backoffBase cannot be negative")
	}
	if c.BackoffMax < 0 {
		return NewConfigurationError("retry.backoffMax", "backoffMax cannot be negative")
	}
	if c.BackoffBase > 0 && c.BackoffMax > 0 && c.BackoffBase > c.BackoffMax {
		return NewConfigurationError("retry.backoffBase", "backoffBase cannot be greater than backoffMax")
	}

	return nil
}

// GetMountPath returns the effective mount path for Kubernetes auth.
func (c *KubernetesAuthConfig) GetMountPath() string {
	if c.MountPath != "" {
		return c.MountPath
	}
	return "kubernetes"
}

// GetTokenPath returns the effective token path for Kubernetes auth.
func (c *KubernetesAuthConfig) GetTokenPath() string {
	if c.TokenPath != "" {
		return c.TokenPath
	}
	return "/var/run/secrets/kubernetes.io/serviceaccount/token"
}

// GetMountPath returns the effective mount path for AppRole auth.
func (c *AppRoleAuthConfig) GetMountPath() string {
	if c.MountPath != "" {
		return c.MountPath
	}
	return "approle"
}

// GetTTL returns the effective cache TTL.
func (c *CacheConfig) GetTTL() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return 5 * time.Minute
}

// GetMaxSize returns the effective cache max size.
func (c *CacheConfig) GetMaxSize() int {
	if c.MaxSize > 0 {
		return c.MaxSize
	}
	return 1000
}

// GetMaxRetries returns the effective max retries.
func (c *RetryConfig) GetMaxRetries() int {
	if c.MaxRetries > 0 {
		return c.MaxRetries
	}
	return 3
}

// GetBackoffBase returns the effective backoff base duration.
func (c *RetryConfig) GetBackoffBase() time.Duration {
	if c.BackoffBase > 0 {
		return c.BackoffBase
	}
	return 100 * time.Millisecond
}

// GetBackoffMax returns the effective backoff max duration.
func (c *RetryConfig) GetBackoffMax() time.Duration {
	if c.BackoffMax > 0 {
		return c.BackoffMax
	}
	return 5 * time.Second
}

// Clone creates a deep copy of the Config.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	clone := &Config{
		Enabled:    c.Enabled,
		Address:    c.Address,
		Namespace:  c.Namespace,
		AuthMethod: c.AuthMethod,
		Token:      c.Token,
	}

	if c.Kubernetes != nil {
		clone.Kubernetes = &KubernetesAuthConfig{
			Role:      c.Kubernetes.Role,
			MountPath: c.Kubernetes.MountPath,
			TokenPath: c.Kubernetes.TokenPath,
		}
	}

	if c.AppRole != nil {
		clone.AppRole = &AppRoleAuthConfig{
			RoleID:    c.AppRole.RoleID,
			SecretID:  c.AppRole.SecretID,
			MountPath: c.AppRole.MountPath,
		}
	}

	if c.TLS != nil {
		clone.TLS = &VaultTLSConfig{
			CACert:     c.TLS.CACert,
			CAPath:     c.TLS.CAPath,
			ClientCert: c.TLS.ClientCert,
			ClientKey:  c.TLS.ClientKey,
			SkipVerify: c.TLS.SkipVerify,
		}
	}

	if c.Cache != nil {
		clone.Cache = &CacheConfig{
			Enabled: c.Cache.Enabled,
			TTL:     c.Cache.TTL,
			MaxSize: c.Cache.MaxSize,
		}
	}

	if c.Retry != nil {
		clone.Retry = &RetryConfig{
			MaxRetries:  c.Retry.MaxRetries,
			BackoffBase: c.Retry.BackoffBase,
			BackoffMax:  c.Retry.BackoffMax,
		}
	}

	return clone
}
