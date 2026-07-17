package config

// Vault client authentication method names accepted by spec.vault.authMethod.
// They mirror internal/vault.AuthMethod values; the config package keeps its
// own string constants so it does not depend on the vault package.
const (
	// VaultAuthMethodToken is the direct token authentication method.
	VaultAuthMethodToken = "token"

	// VaultAuthMethodKubernetes is the Kubernetes ServiceAccount JWT
	// authentication method.
	VaultAuthMethodKubernetes = "kubernetes"

	// VaultAuthMethodAppRole is the AppRole (roleId/secretId)
	// authentication method.
	VaultAuthMethodAppRole = "approle"
)

// VaultConfig configures the gateway-wide Vault CLIENT CONNECTION
// (spec.vault): how the gateway reaches and authenticates against the Vault
// server. It is distinct from the per-listener/route/backend `tls.vault`
// blocks, which configure PKI certificate ISSUANCE and require this client.
//
// Environment variables (VAULT_ADDR, VAULT_TOKEN, ...) override these values
// per-field: ENV > config file > defaults. The overlay is applied by
// cmd/gateway before validation, so the validated configuration is always the
// effective one.
type VaultConfig struct {
	// Enabled turns the Vault client on. Tri-state via pointer semantics is
	// NOT used here; absence of the whole section preserves the legacy
	// env-only gating (VAULT_ADDR set, or PKI tls.vault usage).
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Address is the Vault server address (e.g. "https://vault:8200").
	// Required when enabled; VAULT_ADDR overrides it.
	Address string `yaml:"address,omitempty" json:"address,omitempty"`

	// Namespace is the Vault namespace (Enterprise feature).
	Namespace string `yaml:"namespace,omitempty" json:"namespace,omitempty"`

	// AuthMethod selects the authentication method:
	// token|kubernetes|approle. Empty defaults to token.
	AuthMethod string `yaml:"authMethod,omitempty" json:"authMethod,omitempty"`

	// Token is an inline Vault token for token authentication. Discouraged
	// in configuration files (validation WARNING); prefer TokenFile or the
	// VAULT_TOKEN environment variable (Secret-mounted).
	Token string `yaml:"token,omitempty" json:"token,omitempty"`

	// TokenFile is the path to a file containing the Vault token (preferred
	// file reference for token auth). Mutually exclusive with Token.
	TokenFile string `yaml:"tokenFile,omitempty" json:"tokenFile,omitempty"`

	// Kubernetes configures Kubernetes ServiceAccount authentication.
	Kubernetes *VaultKubernetesAuthConfig `yaml:"kubernetes,omitempty" json:"kubernetes,omitempty"`

	// AppRole configures AppRole authentication.
	AppRole *VaultAppRoleAuthConfig `yaml:"appRole,omitempty" json:"appRole,omitempty"`

	// TLS configures TLS for the connection TO the Vault server.
	TLS *VaultClientTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// Cache configures client-side secret caching.
	Cache *VaultClientCacheConfig `yaml:"cache,omitempty" json:"cache,omitempty"`

	// Retry configures request retry behavior of the Vault client.
	Retry *VaultClientRetryConfig `yaml:"retry,omitempty" json:"retry,omitempty"`

	// Auth bounds the startup Authenticate retry loop (defaults: 3 retries,
	// 1s..10s backoff, 30s overall timeout). Optional.
	Auth *VaultAuthRetryConfig `yaml:"auth,omitempty" json:"auth,omitempty"`
}

// VaultKubernetesAuthConfig configures Kubernetes ServiceAccount JWT
// authentication for the gateway Vault client (spec.vault.kubernetes).
type VaultKubernetesAuthConfig struct {
	// Role is the Vault role to authenticate as. Required.
	Role string `yaml:"role" json:"role"`

	// MountPath is the mount path of the Kubernetes auth method.
	// Defaults to "kubernetes" downstream.
	MountPath string `yaml:"mountPath,omitempty" json:"mountPath,omitempty"`

	// TokenPath is the path to the ServiceAccount token file. Defaults to
	// "/var/run/secrets/kubernetes.io/serviceaccount/token" downstream.
	TokenPath string `yaml:"tokenPath,omitempty" json:"tokenPath,omitempty"`
}

// VaultAppRoleAuthConfig configures AppRole authentication for the gateway
// Vault client (spec.vault.appRole).
type VaultAppRoleAuthConfig struct {
	// RoleID is the AppRole role ID. Required.
	RoleID string `yaml:"roleId" json:"roleId"`

	// SecretID is the inline AppRole secret ID. Discouraged in configuration
	// files (validation WARNING); prefer SecretIDFile or the
	// VAULT_APPROLE_SECRET_ID environment variable.
	SecretID string `yaml:"secretId,omitempty" json:"secretId,omitempty"`

	// SecretIDFile is the path to a file containing the AppRole secret ID
	// (preferred file reference). Mutually exclusive with SecretID.
	SecretIDFile string `yaml:"secretIdFile,omitempty" json:"secretIdFile,omitempty"`

	// MountPath is the mount path of the AppRole auth method.
	// Defaults to "approle" downstream.
	MountPath string `yaml:"mountPath,omitempty" json:"mountPath,omitempty"`
}

// VaultClientTLSConfig configures TLS for the connection TO the Vault server
// (file paths). It intentionally does not reuse the listener TLSConfig or the
// PKI-issuance VaultTLSConfig/VaultBackendTLSConfig/VaultGRPCTLSConfig types,
// whose semantics differ (they configure certificates the gateway serves or
// requests, not how it trusts Vault).
type VaultClientTLSConfig struct {
	// CACert is the path to a PEM-encoded CA certificate file used to verify
	// the Vault server certificate.
	CACert string `yaml:"caCert,omitempty" json:"caCert,omitempty"`

	// CAPath is the path to a directory of PEM-encoded CA certificate files.
	CAPath string `yaml:"caPath,omitempty" json:"caPath,omitempty"`

	// ClientCert is the path to the client certificate for mTLS to Vault.
	ClientCert string `yaml:"clientCert,omitempty" json:"clientCert,omitempty"`

	// ClientKey is the path to the client private key for mTLS to Vault.
	ClientKey string `yaml:"clientKey,omitempty" json:"clientKey,omitempty"`

	// ServerName overrides the TLS server name (SNI) used to verify the
	// Vault server certificate. Empty uses the host from Address.
	ServerName string `yaml:"serverName,omitempty" json:"serverName,omitempty"`

	// SkipVerify disables TLS certificate verification (insecure; testing
	// only). VAULT_SKIP_VERIFY overrides it.
	SkipVerify bool `yaml:"skipVerify,omitempty" json:"skipVerify,omitempty"`
}

// VaultClientCacheConfig configures client-side secret caching
// (spec.vault.cache).
type VaultClientCacheConfig struct {
	// Enabled enables secret caching.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TTL is the cache time-to-live (e.g. "5m"). Defaults to 5 minutes
	// downstream.
	TTL Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// MaxSize is the maximum number of cached entries. Defaults to 1000
	// downstream.
	MaxSize int `yaml:"maxSize,omitempty" json:"maxSize,omitempty"`
}

// VaultClientRetryConfig configures request retry behavior of the Vault
// client (spec.vault.retry).
type VaultClientRetryConfig struct {
	// MaxRetries is the maximum number of retry attempts. Defaults to 3
	// downstream.
	MaxRetries int `yaml:"maxRetries,omitempty" json:"maxRetries,omitempty"`

	// BackoffBase is the base duration for exponential backoff (e.g.
	// "100ms"). Defaults to 100ms downstream.
	BackoffBase Duration `yaml:"backoffBase,omitempty" json:"backoffBase,omitempty"`

	// BackoffMax is the maximum backoff duration (e.g. "5s"). Defaults to 5s
	// downstream.
	BackoffMax Duration `yaml:"backoffMax,omitempty" json:"backoffMax,omitempty"`
}

// VaultAuthRetryConfig bounds the startup Authenticate retry loop
// (spec.vault.auth).
type VaultAuthRetryConfig struct {
	// MaxRetries is the maximum number of authentication retries.
	// Defaults to 3.
	MaxRetries int `yaml:"maxRetries,omitempty" json:"maxRetries,omitempty"`

	// InitialBackoff is the initial backoff between retries. Defaults to 1s.
	InitialBackoff Duration `yaml:"initialBackoff,omitempty" json:"initialBackoff,omitempty"`

	// MaxBackoff is the maximum backoff between retries. Defaults to 10s.
	MaxBackoff Duration `yaml:"maxBackoff,omitempty" json:"maxBackoff,omitempty"`

	// Timeout bounds the whole authentication retry loop. Defaults to 30s.
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// EffectiveAuthMethod returns the configured auth method, defaulting to
// token when unset (mirrors the legacy VAULT_AUTH_METHOD default).
func (c *VaultConfig) EffectiveAuthMethod() string {
	if c == nil || c.AuthMethod == "" {
		return VaultAuthMethodToken
	}
	return c.AuthMethod
}

// Clone creates a deep copy of the VaultConfig. Every pointer sub-block is
// copied independently so mutations of the clone (e.g. by the environment
// overlay in cmd/gateway) never leak into the original configuration.
func (c *VaultConfig) Clone() *VaultConfig {
	if c == nil {
		return nil
	}

	clone := *c
	clone.Kubernetes = c.Kubernetes.clone()
	clone.AppRole = c.AppRole.clone()
	clone.TLS = c.TLS.clone()
	clone.Cache = c.Cache.clone()
	clone.Retry = c.Retry.clone()
	clone.Auth = c.Auth.clone()
	return &clone
}

// clone returns a copy of the Kubernetes auth block (nil-safe).
func (c *VaultKubernetesAuthConfig) clone() *VaultKubernetesAuthConfig {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// clone returns a copy of the AppRole auth block (nil-safe).
func (c *VaultAppRoleAuthConfig) clone() *VaultAppRoleAuthConfig {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// clone returns a copy of the client TLS block (nil-safe).
func (c *VaultClientTLSConfig) clone() *VaultClientTLSConfig {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// clone returns a copy of the cache block (nil-safe).
func (c *VaultClientCacheConfig) clone() *VaultClientCacheConfig {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// clone returns a copy of the retry block (nil-safe).
func (c *VaultClientRetryConfig) clone() *VaultClientRetryConfig {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// clone returns a copy of the auth retry block (nil-safe).
func (c *VaultAuthRetryConfig) clone() *VaultAuthRetryConfig {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// RequiresVaultTLS reports whether any listener or route in the spec enables
// Vault-issued TLS certificates (tls.vault PKI issuance), which requires the
// gateway-wide Vault client. cmd/gateway gating and the validator both use
// this single implementation.
func (s *GatewaySpec) RequiresVaultTLS() bool {
	for i := range s.Listeners {
		l := &s.Listeners[i]
		if l.TLS != nil && l.TLS.Vault != nil && l.TLS.Vault.Enabled {
			return true
		}
		if l.GRPC != nil && l.GRPC.TLS != nil && l.GRPC.TLS.Vault != nil && l.GRPC.TLS.Vault.Enabled {
			return true
		}
	}
	for i := range s.Routes {
		r := &s.Routes[i]
		if r.TLS != nil && r.TLS.Vault != nil && r.TLS.Vault.Enabled {
			return true
		}
	}
	return false
}
