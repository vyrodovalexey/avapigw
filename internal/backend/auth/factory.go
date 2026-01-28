package auth

import (
	"fmt"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// Authentication type constants.
const (
	AuthTypeJWT   = "jwt"
	AuthTypeBasic = "basic"
	AuthTypeMTLS  = "mtls"
)

// NewProvider creates a new authentication provider from configuration.
func NewProvider(name string, cfg *config.BackendAuthConfig, opts ...ProviderOption) (Provider, error) {
	if cfg == nil {
		return &NopProvider{}, nil
	}

	switch cfg.Type {
	case AuthTypeJWT:
		return newJWTProviderFromConfig(name, cfg, opts...)
	case AuthTypeBasic:
		return newBasicProviderFromConfig(name, cfg, opts...)
	case AuthTypeMTLS:
		return newMTLSProviderFromConfig(name, cfg, opts...)
	case "":
		// No auth type specified, try to infer from enabled configs
		return inferProviderFromConfig(name, cfg, opts...)
	default:
		return nil, NewConfigError("type", fmt.Sprintf("unsupported authentication type: %s", cfg.Type))
	}
}

// newJWTProviderFromConfig creates a JWT provider from configuration.
func newJWTProviderFromConfig(name string, cfg *config.BackendAuthConfig, opts ...ProviderOption) (Provider, error) {
	if cfg.JWT == nil {
		return nil, NewConfigError("jwt", "JWT configuration is required when type is 'jwt'")
	}

	return NewJWTProvider(name, cfg.JWT, opts...)
}

// newBasicProviderFromConfig creates a Basic provider from configuration.
func newBasicProviderFromConfig(name string, cfg *config.BackendAuthConfig, opts ...ProviderOption) (Provider, error) {
	if cfg.Basic == nil {
		return nil, NewConfigError("basic", "Basic configuration is required when type is 'basic'")
	}

	return NewBasicProvider(name, cfg.Basic, opts...)
}

// newMTLSProviderFromConfig creates an mTLS provider from configuration.
func newMTLSProviderFromConfig(name string, cfg *config.BackendAuthConfig, opts ...ProviderOption) (Provider, error) {
	if cfg.MTLS == nil {
		return nil, NewConfigError("mtls", "mTLS configuration is required when type is 'mtls'")
	}

	return NewMTLSProvider(name, cfg.MTLS, opts...)
}

// inferProviderFromConfig infers the provider type from enabled configurations.
func inferProviderFromConfig(name string, cfg *config.BackendAuthConfig, opts ...ProviderOption) (Provider, error) {
	// Check JWT first
	if cfg.JWT != nil && cfg.JWT.Enabled {
		return NewJWTProvider(name, cfg.JWT, opts...)
	}

	// Check Basic
	if cfg.Basic != nil && cfg.Basic.Enabled {
		return NewBasicProvider(name, cfg.Basic, opts...)
	}

	// Check mTLS
	if cfg.MTLS != nil && cfg.MTLS.Enabled {
		return NewMTLSProvider(name, cfg.MTLS, opts...)
	}

	// No authentication configured
	return &NopProvider{}, nil
}

// MustNewProvider creates a new provider and panics on error.
// This is useful for initialization code where errors should be fatal.
func MustNewProvider(name string, cfg *config.BackendAuthConfig, opts ...ProviderOption) Provider {
	provider, err := NewProvider(name, cfg, opts...)
	if err != nil {
		panic(fmt.Sprintf("failed to create auth provider: %v", err))
	}
	return provider
}

// ProviderRegistry manages multiple authentication providers.
type ProviderRegistry struct {
	providers map[string]Provider
}

// NewProviderRegistry creates a new provider registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]Provider),
	}
}

// Register registers a provider.
func (r *ProviderRegistry) Register(provider Provider) error {
	name := provider.Name()
	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("provider already registered: %s", name)
	}
	r.providers[name] = provider
	return nil
}

// Get returns a provider by name.
func (r *ProviderRegistry) Get(name string) (Provider, bool) {
	provider, exists := r.providers[name]
	return provider, exists
}

// Close closes all providers.
func (r *ProviderRegistry) Close() error {
	var lastErr error
	for _, provider := range r.providers {
		if err := provider.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
