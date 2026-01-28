package config

import "fmt"

// Backend represents a backend service configuration.
type Backend struct {
	Name         string            `yaml:"name" json:"name"`
	Hosts        []BackendHost     `yaml:"hosts" json:"hosts"`
	HealthCheck  *HealthCheck      `yaml:"healthCheck,omitempty" json:"healthCheck,omitempty"`
	LoadBalancer *LoadBalancer     `yaml:"loadBalancer,omitempty" json:"loadBalancer,omitempty"`
	TLS          *BackendTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// CircuitBreaker configures circuit breaker for this backend.
	CircuitBreaker *CircuitBreakerConfig `yaml:"circuitBreaker,omitempty" json:"circuitBreaker,omitempty"`

	// Authentication configures authentication for backend connections.
	Authentication *BackendAuthConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// MaxSessions configures maximum concurrent sessions for this backend.
	MaxSessions *MaxSessionsConfig `yaml:"maxSessions,omitempty" json:"maxSessions,omitempty"`

	// RateLimit configures rate limiting for this backend.
	RateLimit *RateLimitConfig `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`
}

// BackendHost represents a single backend host.
type BackendHost struct {
	Address string `yaml:"address" json:"address"`
	Port    int    `yaml:"port" json:"port"`
	Weight  int    `yaml:"weight,omitempty" json:"weight,omitempty"`
}

// BackendTLSConfig contains TLS configuration for backend connections.
type BackendTLSConfig struct {
	// Enabled enables TLS for backend connections.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// Mode specifies the TLS mode (SIMPLE, MUTUAL).
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`

	// CAFile is the path to the CA certificate for server verification.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// CertFile is the path to the client certificate (for mTLS).
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the client private key (for mTLS).
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// ServerName overrides the server name for TLS verification.
	ServerName string `yaml:"serverName,omitempty" json:"serverName,omitempty"`

	// InsecureSkipVerify skips server certificate verification (dev only).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`

	// MinVersion is the minimum TLS version (TLS12, TLS13).
	MinVersion string `yaml:"minVersion,omitempty" json:"minVersion,omitempty"`

	// MaxVersion is the maximum TLS version.
	MaxVersion string `yaml:"maxVersion,omitempty" json:"maxVersion,omitempty"`

	// CipherSuites is the list of allowed cipher suites.
	CipherSuites []string `yaml:"cipherSuites,omitempty" json:"cipherSuites,omitempty"`

	// ALPN protocols for negotiation.
	ALPN []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`

	// Vault configures Vault-based client certificate management.
	Vault *VaultBackendTLSConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
}

// VaultBackendTLSConfig configures Vault-based TLS for backend connections.
type VaultBackendTLSConfig struct {
	// Enabled enables Vault integration for client certificates.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// PKIMount is the Vault PKI mount path.
	PKIMount string `yaml:"pkiMount,omitempty" json:"pkiMount,omitempty"`

	// Role is the Vault PKI role name.
	Role string `yaml:"role,omitempty" json:"role,omitempty"`

	// CommonName for certificate requests.
	CommonName string `yaml:"commonName,omitempty" json:"commonName,omitempty"`

	// AltNames for certificate requests.
	AltNames []string `yaml:"altNames,omitempty" json:"altNames,omitempty"`

	// TTL for certificate requests.
	TTL string `yaml:"ttl,omitempty" json:"ttl,omitempty"`
}

// BackendTLSMode constants for backend TLS configuration.
const (
	// BackendTLSModeSimple enables TLS with server certificate verification only.
	BackendTLSModeSimple = "SIMPLE"

	// BackendTLSModeMutual enables mutual TLS (mTLS) with client certificates.
	BackendTLSModeMutual = "MUTUAL"
)

// Validate validates the backend TLS configuration.
func (c *BackendTLSConfig) Validate() error {
	if c == nil {
		return nil
	}

	if err := c.validateMode(); err != nil {
		return err
	}
	if err := c.validateMutualTLS(); err != nil {
		return err
	}
	if err := c.validateVersions(); err != nil {
		return err
	}
	if err := c.validateVault(); err != nil {
		return err
	}

	return nil
}

// validateMode validates the TLS mode.
func (c *BackendTLSConfig) validateMode() error {
	validModes := map[string]bool{
		"": true, BackendTLSModeSimple: true, BackendTLSModeMutual: true, TLSModeInsecure: true,
	}
	if !validModes[c.Mode] {
		return fmt.Errorf("invalid backend TLS mode: %s (must be SIMPLE, MUTUAL, or INSECURE)", c.Mode)
	}
	return nil
}

// validateMutualTLS validates mTLS configuration.
func (c *BackendTLSConfig) validateMutualTLS() error {
	if c.Mode != BackendTLSModeMutual {
		return nil
	}
	vaultEnabled := c.Vault != nil && c.Vault.Enabled
	if c.CertFile == "" && !vaultEnabled {
		return fmt.Errorf("certFile is required for MUTUAL TLS mode (or enable Vault)")
	}
	if c.KeyFile == "" && !vaultEnabled {
		return fmt.Errorf("keyFile is required for MUTUAL TLS mode (or enable Vault)")
	}
	return nil
}

// validateVersions validates TLS version configuration.
func (c *BackendTLSConfig) validateVersions() error {
	validVersions := map[string]bool{
		"": true, "TLS10": true, "TLS11": true, "TLS12": true, "TLS13": true,
	}
	if !validVersions[c.MinVersion] {
		return fmt.Errorf("invalid minVersion: %s", c.MinVersion)
	}
	if !validVersions[c.MaxVersion] {
		return fmt.Errorf("invalid maxVersion: %s", c.MaxVersion)
	}
	return nil
}

// validateVault validates Vault configuration.
func (c *BackendTLSConfig) validateVault() error {
	if c.Vault != nil && c.Vault.Enabled {
		return c.Vault.Validate()
	}
	return nil
}

// Validate validates the Vault backend TLS configuration.
func (c *VaultBackendTLSConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if c.PKIMount == "" {
		return fmt.Errorf("vault.pkiMount is required")
	}
	if c.Role == "" {
		return fmt.Errorf("vault.role is required")
	}
	if c.CommonName == "" {
		return fmt.Errorf("vault.commonName is required")
	}

	return nil
}

// IsEnabled returns true if TLS is enabled for backend connections.
func (c *BackendTLSConfig) IsEnabled() bool {
	return c != nil && c.Enabled
}

// IsMutual returns true if mutual TLS is configured.
func (c *BackendTLSConfig) IsMutual() bool {
	return c != nil && c.Mode == BackendTLSModeMutual
}

// GetEffectiveMode returns the effective TLS mode.
func (c *BackendTLSConfig) GetEffectiveMode() string {
	if c == nil || !c.Enabled {
		return TLSModeInsecure
	}
	if c.Mode == "" {
		return BackendTLSModeSimple
	}
	return c.Mode
}

// GetEffectiveMinVersion returns the effective minimum TLS version.
func (c *BackendTLSConfig) GetEffectiveMinVersion() string {
	if c == nil || c.MinVersion == "" {
		return "TLS12" // Default to TLS 1.2
	}
	return c.MinVersion
}

// HealthCheck represents health check configuration.
type HealthCheck struct {
	Path               string   `yaml:"path" json:"path"`
	Interval           Duration `yaml:"interval,omitempty" json:"interval,omitempty"`
	Timeout            Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	HealthyThreshold   int      `yaml:"healthyThreshold,omitempty" json:"healthyThreshold,omitempty"`
	UnhealthyThreshold int      `yaml:"unhealthyThreshold,omitempty" json:"unhealthyThreshold,omitempty"`
}

// LoadBalancer represents load balancer configuration.
type LoadBalancer struct {
	Algorithm string `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`
}

// LoadBalancerAlgorithm constants.
const (
	LoadBalancerRoundRobin = "roundRobin"
	LoadBalancerWeighted   = "weighted"
	LoadBalancerLeastConn  = "leastConn"
	LoadBalancerRandom     = "random"
)

// BackendAuthConfig configures authentication for backend connections.
type BackendAuthConfig struct {
	// Type specifies the authentication type (jwt, basic, mtls).
	Type string `yaml:"type" json:"type"`

	// JWT configures JWT authentication for backend.
	JWT *BackendJWTAuthConfig `yaml:"jwt,omitempty" json:"jwt,omitempty"`

	// Basic configures Basic authentication for backend.
	Basic *BackendBasicAuthConfig `yaml:"basic,omitempty" json:"basic,omitempty"`

	// MTLS configures mTLS authentication for backend.
	MTLS *BackendMTLSAuthConfig `yaml:"mtls,omitempty" json:"mtls,omitempty"`
}

// BackendJWTAuthConfig configures JWT authentication for backend connections.
type BackendJWTAuthConfig struct {
	// Enabled enables JWT authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TokenSource specifies where to get the token (static, vault, oidc).
	TokenSource string `yaml:"tokenSource" json:"tokenSource"`

	// StaticToken is a static JWT token (for development only).
	StaticToken string `yaml:"staticToken,omitempty" json:"staticToken,omitempty"`

	// VaultPath is the Vault path for JWT token.
	VaultPath string `yaml:"vaultPath,omitempty" json:"vaultPath,omitempty"`

	// OIDC configures OIDC token acquisition.
	OIDC *BackendOIDCConfig `yaml:"oidc,omitempty" json:"oidc,omitempty"`

	// HeaderName is the header name for the token (default: Authorization).
	HeaderName string `yaml:"headerName,omitempty" json:"headerName,omitempty"`

	// HeaderPrefix is the prefix for the token (default: Bearer).
	HeaderPrefix string `yaml:"headerPrefix,omitempty" json:"headerPrefix,omitempty"`
}

// BackendOIDCConfig configures OIDC token acquisition for backend auth.
type BackendOIDCConfig struct {
	// IssuerURL is the OIDC issuer URL.
	IssuerURL string `yaml:"issuerUrl" json:"issuerUrl"`

	// ClientID is the OIDC client ID.
	ClientID string `yaml:"clientId" json:"clientId"`

	// ClientSecret is the OIDC client secret.
	ClientSecret string `yaml:"clientSecret,omitempty" json:"clientSecret,omitempty"`

	// ClientSecretVaultPath is the Vault path for client secret.
	ClientSecretVaultPath string `yaml:"clientSecretVaultPath,omitempty" json:"clientSecretVaultPath,omitempty"`

	// Scopes are the scopes to request.
	Scopes []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`

	// TokenCacheTTL is the TTL for cached tokens.
	TokenCacheTTL Duration `yaml:"tokenCacheTTL,omitempty" json:"tokenCacheTTL,omitempty"`
}

// BackendBasicAuthConfig configures Basic authentication for backend connections.
type BackendBasicAuthConfig struct {
	// Enabled enables Basic authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Username is the username for Basic auth.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`

	// Password is the password for Basic auth.
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// VaultPath is the Vault path for credentials.
	VaultPath string `yaml:"vaultPath,omitempty" json:"vaultPath,omitempty"`

	// UsernameKey is the key in Vault for username (default: username).
	UsernameKey string `yaml:"usernameKey,omitempty" json:"usernameKey,omitempty"`

	// PasswordKey is the key in Vault for password (default: password).
	PasswordKey string `yaml:"passwordKey,omitempty" json:"passwordKey,omitempty"`
}

// BackendMTLSAuthConfig configures mTLS authentication for backend connections.
type BackendMTLSAuthConfig struct {
	// Enabled enables mTLS authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// CertFile is the path to the client certificate.
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the client private key.
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// CAFile is the path to the CA certificate for server verification.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// Vault configures Vault-based certificate management.
	Vault *VaultBackendTLSConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
}

// Validate validates the backend authentication configuration.
func (c *BackendAuthConfig) Validate() error {
	if c == nil {
		return nil
	}

	validTypes := map[string]bool{"": true, "jwt": true, "basic": true, "mtls": true}
	if !validTypes[c.Type] {
		return fmt.Errorf("invalid backend auth type: %s (must be jwt, basic, or mtls)", c.Type)
	}

	if c.JWT != nil && c.JWT.Enabled {
		if err := c.JWT.Validate(); err != nil {
			return fmt.Errorf("jwt auth config: %w", err)
		}
	}

	if c.Basic != nil && c.Basic.Enabled {
		if err := c.Basic.Validate(); err != nil {
			return fmt.Errorf("basic auth config: %w", err)
		}
	}

	if c.MTLS != nil && c.MTLS.Enabled {
		if err := c.MTLS.Validate(); err != nil {
			return fmt.Errorf("mtls auth config: %w", err)
		}
	}

	return nil
}

// Validate validates the JWT authentication configuration.
func (c *BackendJWTAuthConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	validSources := map[string]bool{"static": true, "vault": true, "oidc": true}
	if !validSources[c.TokenSource] {
		return fmt.Errorf("invalid token source: %s (must be static, vault, or oidc)", c.TokenSource)
	}

	switch c.TokenSource {
	case "static":
		if c.StaticToken == "" {
			return fmt.Errorf("staticToken is required for static token source")
		}
	case "vault":
		if c.VaultPath == "" {
			return fmt.Errorf("vaultPath is required for vault token source")
		}
	case "oidc":
		if c.OIDC == nil {
			return fmt.Errorf("oidc config is required for oidc token source")
		}
		if err := c.OIDC.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates the OIDC configuration.
func (c *BackendOIDCConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.IssuerURL == "" {
		return fmt.Errorf("issuerUrl is required")
	}
	if c.ClientID == "" {
		return fmt.Errorf("clientId is required")
	}
	if c.ClientSecret == "" && c.ClientSecretVaultPath == "" {
		return fmt.Errorf("either clientSecret or clientSecretVaultPath is required")
	}

	return nil
}

// Validate validates the Basic authentication configuration.
func (c *BackendBasicAuthConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	hasStatic := c.Username != "" && c.Password != ""
	hasVault := c.VaultPath != ""

	if !hasStatic && !hasVault {
		return fmt.Errorf("either username/password or vaultPath is required")
	}

	return nil
}

// Validate validates the mTLS authentication configuration.
func (c *BackendMTLSAuthConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	hasFiles := c.CertFile != "" && c.KeyFile != ""
	hasVault := c.Vault != nil && c.Vault.Enabled

	if !hasFiles && !hasVault {
		return fmt.Errorf("either certFile/keyFile or vault config is required")
	}

	if hasVault {
		if err := c.Vault.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// GetEffectiveHeaderName returns the effective header name for JWT.
func (c *BackendJWTAuthConfig) GetEffectiveHeaderName() string {
	if c == nil || c.HeaderName == "" {
		return "Authorization"
	}
	return c.HeaderName
}

// GetEffectiveHeaderPrefix returns the effective header prefix for JWT.
func (c *BackendJWTAuthConfig) GetEffectiveHeaderPrefix() string {
	if c == nil || c.HeaderPrefix == "" {
		return "Bearer"
	}
	return c.HeaderPrefix
}

// GetEffectiveUsernameKey returns the effective username key for Vault.
func (c *BackendBasicAuthConfig) GetEffectiveUsernameKey() string {
	if c == nil || c.UsernameKey == "" {
		return "username"
	}
	return c.UsernameKey
}

// GetEffectivePasswordKey returns the effective password key for Vault.
func (c *BackendBasicAuthConfig) GetEffectivePasswordKey() string {
	if c == nil || c.PasswordKey == "" {
		return "password"
	}
	return c.PasswordKey
}
