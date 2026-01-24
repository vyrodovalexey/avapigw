package oidc

import (
	"errors"
	"fmt"
	"time"
)

// Config represents OIDC authentication configuration.
type Config struct {
	// Enabled enables OIDC authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Providers is a list of OIDC providers.
	Providers []ProviderConfig `yaml:"providers,omitempty" json:"providers,omitempty"`

	// DefaultProvider is the name of the default provider.
	DefaultProvider string `yaml:"defaultProvider,omitempty" json:"defaultProvider,omitempty"`

	// DiscoveryCacheTTL is the TTL for discovery document caching.
	DiscoveryCacheTTL time.Duration `yaml:"discoveryCacheTTL,omitempty" json:"discoveryCacheTTL,omitempty"`

	// TokenValidation configures token validation.
	TokenValidation *TokenValidationConfig `yaml:"tokenValidation,omitempty" json:"tokenValidation,omitempty"`
}

// ProviderConfig represents an OIDC provider configuration.
type ProviderConfig struct {
	// Name is the unique name for this provider.
	Name string `yaml:"name" json:"name"`

	// Issuer is the OIDC issuer URL.
	Issuer string `yaml:"issuer" json:"issuer"`

	// DiscoveryURL is the OIDC discovery URL (defaults to issuer + /.well-known/openid-configuration).
	DiscoveryURL string `yaml:"discoveryUrl,omitempty" json:"discoveryUrl,omitempty"`

	// ClientID is the OAuth client ID.
	ClientID string `yaml:"clientId" json:"clientId"`

	// ClientSecret is the OAuth client secret.
	ClientSecret string `yaml:"clientSecret,omitempty" json:"clientSecret,omitempty"`

	// Scopes is the list of OAuth scopes to request.
	Scopes []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`

	// Audience is the expected token audience.
	Audience []string `yaml:"audience,omitempty" json:"audience,omitempty"`

	// ClaimMapping configures how OIDC claims are mapped to identity fields.
	ClaimMapping *ClaimMapping `yaml:"claimMapping,omitempty" json:"claimMapping,omitempty"`

	// Introspection configures token introspection.
	Introspection *IntrospectionConfig `yaml:"introspection,omitempty" json:"introspection,omitempty"`

	// Type is the provider type (generic, keycloak, auth0, okta, azure).
	Type string `yaml:"type,omitempty" json:"type,omitempty"`

	// Keycloak contains Keycloak-specific configuration.
	Keycloak *KeycloakConfig `yaml:"keycloak,omitempty" json:"keycloak,omitempty"`
}

// ClaimMapping configures how OIDC claims are mapped to identity fields.
type ClaimMapping struct {
	// Subject is the claim path for the subject.
	Subject string `yaml:"subject,omitempty" json:"subject,omitempty"`

	// Roles is the claim path for roles.
	Roles string `yaml:"roles,omitempty" json:"roles,omitempty"`

	// Permissions is the claim path for permissions.
	Permissions string `yaml:"permissions,omitempty" json:"permissions,omitempty"`

	// Groups is the claim path for groups.
	Groups string `yaml:"groups,omitempty" json:"groups,omitempty"`

	// Email is the claim path for email.
	Email string `yaml:"email,omitempty" json:"email,omitempty"`

	// Name is the claim path for name.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`

	// TenantID is the claim path for tenant ID.
	TenantID string `yaml:"tenantId,omitempty" json:"tenantId,omitempty"`
}

// IntrospectionConfig configures token introspection.
type IntrospectionConfig struct {
	// Enabled enables token introspection.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// URL is the introspection endpoint URL.
	URL string `yaml:"url,omitempty" json:"url,omitempty"`

	// ClientID is the client ID for introspection.
	ClientID string `yaml:"clientId,omitempty" json:"clientId,omitempty"`

	// ClientSecret is the client secret for introspection.
	ClientSecret string `yaml:"clientSecret,omitempty" json:"clientSecret,omitempty"`

	// CacheTTL is the TTL for caching introspection results.
	CacheTTL time.Duration `yaml:"cacheTtl,omitempty" json:"cacheTtl,omitempty"`
}

// KeycloakConfig contains Keycloak-specific configuration.
type KeycloakConfig struct {
	// Realm is the Keycloak realm.
	Realm string `yaml:"realm,omitempty" json:"realm,omitempty"`

	// UseRealmRoles uses realm roles instead of client roles.
	UseRealmRoles bool `yaml:"useRealmRoles,omitempty" json:"useRealmRoles,omitempty"`

	// ClientRolesPath is the claim path for client roles.
	ClientRolesPath string `yaml:"clientRolesPath,omitempty" json:"clientRolesPath,omitempty"`

	// RealmRolesPath is the claim path for realm roles.
	RealmRolesPath string `yaml:"realmRolesPath,omitempty" json:"realmRolesPath,omitempty"`
}

// TokenValidationConfig configures token validation.
type TokenValidationConfig struct {
	// ClockSkew is the allowed clock skew for token validation.
	ClockSkew time.Duration `yaml:"clockSkew,omitempty" json:"clockSkew,omitempty"`

	// RequiredClaims is a list of claims that must be present.
	RequiredClaims []string `yaml:"requiredClaims,omitempty" json:"requiredClaims,omitempty"`

	// ValidateNonce validates the nonce claim for ID tokens.
	ValidateNonce bool `yaml:"validateNonce,omitempty" json:"validateNonce,omitempty"`
}

// Validate validates the OIDC configuration.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if len(c.Providers) == 0 {
		return errors.New("at least one provider must be configured")
	}

	for i, provider := range c.Providers {
		if err := provider.Validate(); err != nil {
			return fmt.Errorf("providers[%d]: %w", i, err)
		}
	}

	// Validate default provider exists
	if c.DefaultProvider != "" {
		found := false
		for _, p := range c.Providers {
			if p.Name == c.DefaultProvider {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("default provider %s not found", c.DefaultProvider)
		}
	}

	return nil
}

// Validate validates the provider configuration.
func (c *ProviderConfig) Validate() error {
	if c.Name == "" {
		return errors.New("name is required")
	}
	if c.Issuer == "" {
		return errors.New("issuer is required")
	}
	if c.ClientID == "" {
		return errors.New("clientId is required")
	}

	// Validate provider type
	if c.Type != "" {
		validTypes := map[string]bool{
			"generic":  true,
			"keycloak": true,
			"auth0":    true,
			"okta":     true,
			"azure":    true,
		}
		if !validTypes[c.Type] {
			return fmt.Errorf("invalid provider type: %s", c.Type)
		}
	}

	// Validate introspection configuration
	if c.Introspection != nil && c.Introspection.Enabled {
		if c.Introspection.URL == "" && c.DiscoveryURL == "" {
			return errors.New("introspection URL is required when introspection is enabled")
		}
	}

	return nil
}

// DefaultConfig returns a default OIDC configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:           false,
		DiscoveryCacheTTL: time.Hour,
		TokenValidation: &TokenValidationConfig{
			ClockSkew: 5 * time.Minute,
		},
	}
}

// GetDiscoveryURL returns the discovery URL for a provider.
func (c *ProviderConfig) GetDiscoveryURL() string {
	if c.DiscoveryURL != "" {
		return c.DiscoveryURL
	}
	return c.Issuer + "/.well-known/openid-configuration"
}

// GetEffectiveClaimMapping returns the effective claim mapping.
func (c *ProviderConfig) GetEffectiveClaimMapping() *ClaimMapping {
	if c.ClaimMapping != nil {
		return c.ClaimMapping
	}

	// Default claim mapping based on provider type
	switch c.Type {
	case "keycloak":
		return &ClaimMapping{
			Subject: "sub",
			Roles:   "realm_access.roles",
			Email:   "email",
			Name:    "name",
			Groups:  "groups",
		}
	case "auth0":
		return &ClaimMapping{
			Subject:     "sub",
			Roles:       "https://auth0.com/roles",
			Permissions: "permissions",
			Email:       "email",
			Name:        "name",
		}
	default:
		return &ClaimMapping{
			Subject: "sub",
			Roles:   "roles",
			Email:   "email",
			Name:    "name",
		}
	}
}

// GetProvider returns a provider by name.
func (c *Config) GetProvider(name string) *ProviderConfig {
	for i := range c.Providers {
		if c.Providers[i].Name == name {
			return &c.Providers[i]
		}
	}
	return nil
}

// GetDefaultProvider returns the default provider.
func (c *Config) GetDefaultProvider() *ProviderConfig {
	if c.DefaultProvider != "" {
		return c.GetProvider(c.DefaultProvider)
	}
	if len(c.Providers) > 0 {
		return &c.Providers[0]
	}
	return nil
}
