package jwt

import (
	"errors"
	"fmt"
	"time"
)

// Config represents JWT authentication configuration.
type Config struct {
	// Enabled enables JWT authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Algorithms is the list of allowed signing algorithms.
	Algorithms []string `yaml:"algorithms,omitempty" json:"algorithms,omitempty"`

	// JWKSUrl is the URL to fetch JWKS from.
	JWKSUrl string `yaml:"jwksUrl,omitempty" json:"jwksUrl,omitempty"`

	// JWKSCacheTTL is the TTL for JWKS cache.
	JWKSCacheTTL time.Duration `yaml:"jwksCacheTTL,omitempty" json:"jwksCacheTTL,omitempty"`

	// Issuer is the expected token issuer.
	Issuer string `yaml:"issuer,omitempty" json:"issuer,omitempty"`

	// Issuers is a list of allowed issuers (alternative to single Issuer).
	Issuers []string `yaml:"issuers,omitempty" json:"issuers,omitempty"`

	// Audience is the expected token audience.
	Audience []string `yaml:"audience,omitempty" json:"audience,omitempty"`

	// ClockSkew is the allowed clock skew for token validation.
	ClockSkew time.Duration `yaml:"clockSkew,omitempty" json:"clockSkew,omitempty"`

	// RequiredClaims is a list of claims that must be present.
	RequiredClaims []string `yaml:"requiredClaims,omitempty" json:"requiredClaims,omitempty"`

	// ClaimMapping maps JWT claims to identity fields.
	ClaimMapping *ClaimMapping `yaml:"claimMapping,omitempty" json:"claimMapping,omitempty"`

	// StaticKeys configures static signing keys.
	StaticKeys []StaticKey `yaml:"staticKeys,omitempty" json:"staticKeys,omitempty"`

	// Vault configures Vault integration for JWT signing.
	Vault *VaultConfig `yaml:"vault,omitempty" json:"vault,omitempty"`

	// RevocationCheck configures token revocation checking.
	RevocationCheck *RevocationCheckConfig `yaml:"revocationCheck,omitempty" json:"revocationCheck,omitempty"`
}

// ClaimMapping configures how JWT claims are mapped to identity fields.
type ClaimMapping struct {
	// Subject is the claim path for the subject.
	Subject string `yaml:"subject,omitempty" json:"subject,omitempty"`

	// Roles is the claim path for roles.
	Roles string `yaml:"roles,omitempty" json:"roles,omitempty"`

	// Permissions is the claim path for permissions.
	Permissions string `yaml:"permissions,omitempty" json:"permissions,omitempty"`

	// Groups is the claim path for groups.
	Groups string `yaml:"groups,omitempty" json:"groups,omitempty"`

	// Scopes is the claim path for scopes.
	Scopes string `yaml:"scopes,omitempty" json:"scopes,omitempty"`

	// Email is the claim path for email.
	Email string `yaml:"email,omitempty" json:"email,omitempty"`

	// Name is the claim path for name.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`

	// TenantID is the claim path for tenant ID.
	TenantID string `yaml:"tenantId,omitempty" json:"tenantId,omitempty"`

	// ClientID is the claim path for client ID.
	ClientID string `yaml:"clientId,omitempty" json:"clientId,omitempty"`
}

// StaticKey represents a static signing key.
type StaticKey struct {
	// KeyID is the key identifier.
	KeyID string `yaml:"keyId" json:"keyId"`

	// Algorithm is the signing algorithm.
	Algorithm string `yaml:"algorithm" json:"algorithm"`

	// Key is the key value (base64 encoded for symmetric, PEM for asymmetric).
	Key string `yaml:"key" json:"key"`

	// KeyFile is the path to the key file.
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`
}

// VaultConfig configures Vault integration for JWT.
type VaultConfig struct {
	// Enabled enables Vault integration.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TransitMount is the Vault Transit mount path.
	TransitMount string `yaml:"transitMount,omitempty" json:"transitMount,omitempty"`

	// KeyName is the Transit key name for signing.
	KeyName string `yaml:"keyName,omitempty" json:"keyName,omitempty"`

	// KeyVersion is the key version to use (0 for latest).
	KeyVersion int `yaml:"keyVersion,omitempty" json:"keyVersion,omitempty"`
}

// RevocationCheckConfig configures token revocation checking.
type RevocationCheckConfig struct {
	// Enabled enables revocation checking.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Type is the revocation check type (introspection, jti-cache).
	Type string `yaml:"type,omitempty" json:"type,omitempty"`

	// IntrospectionURL is the token introspection endpoint.
	IntrospectionURL string `yaml:"introspectionUrl,omitempty" json:"introspectionUrl,omitempty"`

	// ClientID is the client ID for introspection.
	ClientID string `yaml:"clientId,omitempty" json:"clientId,omitempty"`

	// ClientSecret is the client secret for introspection.
	ClientSecret string `yaml:"clientSecret,omitempty" json:"clientSecret,omitempty"`

	// CacheTTL is the TTL for caching revocation status.
	CacheTTL time.Duration `yaml:"cacheTtl,omitempty" json:"cacheTtl,omitempty"`
}

// Validate validates the JWT configuration.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	// Validate algorithms
	if len(c.Algorithms) > 0 {
		for _, alg := range c.Algorithms {
			if !isValidAlgorithm(alg) {
				return fmt.Errorf("invalid algorithm: %s", alg)
			}
		}
	}

	// Validate key source
	if !c.hasKeySource() {
		return errors.New("at least one key source must be configured (jwksUrl, staticKeys, or vault)")
	}

	// Validate JWKS URL
	if c.JWKSUrl != "" {
		if c.JWKSCacheTTL < 0 {
			return errors.New("jwksCacheTTL must be non-negative")
		}
	}

	// Validate static keys
	for i, key := range c.StaticKeys {
		if err := validateStaticKey(key); err != nil {
			return fmt.Errorf("staticKeys[%d]: %w", i, err)
		}
	}

	// Validate Vault configuration
	if c.Vault != nil && c.Vault.Enabled {
		if err := c.Vault.Validate(); err != nil {
			return fmt.Errorf("vault: %w", err)
		}
	}

	// Validate clock skew
	if c.ClockSkew < 0 {
		return errors.New("clockSkew must be non-negative")
	}

	return nil
}

// hasKeySource checks if at least one key source is configured.
func (c *Config) hasKeySource() bool {
	if c.JWKSUrl != "" {
		return true
	}
	if len(c.StaticKeys) > 0 {
		return true
	}
	if c.Vault != nil && c.Vault.Enabled {
		return true
	}
	return false
}

// validateStaticKey validates a static key configuration.
func validateStaticKey(key StaticKey) error {
	if key.KeyID == "" {
		return errors.New("keyId is required")
	}
	if key.Algorithm == "" {
		return errors.New("algorithm is required")
	}
	if !isValidAlgorithm(key.Algorithm) {
		return fmt.Errorf("invalid algorithm: %s", key.Algorithm)
	}
	if key.Key == "" && key.KeyFile == "" {
		return errors.New("key or keyFile is required")
	}
	return nil
}

// Validate validates the Vault configuration.
func (c *VaultConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if c.TransitMount == "" {
		return errors.New("transitMount is required")
	}
	if c.KeyName == "" {
		return errors.New("keyName is required")
	}
	return nil
}

// isValidAlgorithm checks if an algorithm is valid.
func isValidAlgorithm(alg string) bool {
	validAlgorithms := map[string]bool{
		"RS256":   true,
		"RS384":   true,
		"RS512":   true,
		"ES256":   true,
		"ES384":   true,
		"ES512":   true,
		"HS256":   true,
		"HS384":   true,
		"HS512":   true,
		"EdDSA":   true,
		"Ed25519": true,
		"PS256":   true,
		"PS384":   true,
		"PS512":   true,
	}
	return validAlgorithms[alg]
}

// DefaultConfig returns a default JWT configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:      false,
		Algorithms:   []string{"RS256", "ES256"},
		JWKSCacheTTL: time.Hour,
		ClockSkew:    5 * time.Minute,
		ClaimMapping: &ClaimMapping{
			Subject: "sub",
			Roles:   "roles",
			Email:   "email",
			Name:    "name",
		},
	}
}

// GetAllowedIssuers returns all allowed issuers.
func (c *Config) GetAllowedIssuers() []string {
	if len(c.Issuers) > 0 {
		return c.Issuers
	}
	if c.Issuer != "" {
		return []string{c.Issuer}
	}
	return nil
}

// GetEffectiveClockSkew returns the effective clock skew.
func (c *Config) GetEffectiveClockSkew() time.Duration {
	if c.ClockSkew > 0 {
		return c.ClockSkew
	}
	return 5 * time.Minute
}

// GetEffectiveJWKSCacheTTL returns the effective JWKS cache TTL.
func (c *Config) GetEffectiveJWKSCacheTTL() time.Duration {
	if c.JWKSCacheTTL > 0 {
		return c.JWKSCacheTTL
	}
	return time.Hour
}
