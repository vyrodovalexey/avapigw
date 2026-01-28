package oidc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Provider represents an OIDC provider.
type Provider interface {
	// Name returns the provider name.
	Name() string

	// ValidateToken validates an access or ID token.
	ValidateToken(ctx context.Context, token string) (*TokenInfo, error)

	// GetUserInfo fetches user information using an access token.
	GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error)

	// IntrospectToken introspects a token.
	IntrospectToken(ctx context.Context, token string) (*IntrospectionResult, error)

	// Close closes the provider.
	Close() error
}

// TokenInfo contains information about a validated token.
type TokenInfo struct {
	// Subject is the token subject.
	Subject string `json:"sub"`

	// Issuer is the token issuer.
	Issuer string `json:"iss"`

	// Audience is the token audience.
	Audience []string `json:"aud,omitempty"`

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time `json:"exp,omitempty"`

	// IssuedAt is when the token was issued.
	IssuedAt time.Time `json:"iat,omitempty"`

	// Scopes is the list of scopes.
	Scopes []string `json:"scopes,omitempty"`

	// Roles is the list of roles.
	Roles []string `json:"roles,omitempty"`

	// Permissions is the list of permissions.
	Permissions []string `json:"permissions,omitempty"`

	// Groups is the list of groups.
	Groups []string `json:"groups,omitempty"`

	// Email is the user's email.
	Email string `json:"email,omitempty"`

	// EmailVerified indicates if the email is verified.
	EmailVerified bool `json:"email_verified,omitempty"`

	// Name is the user's name.
	Name string `json:"name,omitempty"`

	// Claims contains all token claims.
	Claims map[string]interface{} `json:"claims,omitempty"`

	// TokenType is the type of token (access_token, id_token).
	TokenType string `json:"token_type,omitempty"`
}

// UserInfo contains user information from the userinfo endpoint.
type UserInfo struct {
	// Subject is the user subject.
	Subject string `json:"sub"`

	// Name is the user's full name.
	Name string `json:"name,omitempty"`

	// GivenName is the user's given name.
	GivenName string `json:"given_name,omitempty"`

	// FamilyName is the user's family name.
	FamilyName string `json:"family_name,omitempty"`

	// Email is the user's email.
	Email string `json:"email,omitempty"`

	// EmailVerified indicates if the email is verified.
	EmailVerified bool `json:"email_verified,omitempty"`

	// Picture is the URL of the user's profile picture.
	Picture string `json:"picture,omitempty"`

	// Locale is the user's locale.
	Locale string `json:"locale,omitempty"`

	// Claims contains all userinfo claims.
	Claims map[string]interface{} `json:"claims,omitempty"`
}

// IntrospectionResult contains the result of token introspection.
type IntrospectionResult struct {
	// Active indicates if the token is active.
	Active bool `json:"active"`

	// Scope is the token scope.
	Scope string `json:"scope,omitempty"`

	// ClientID is the client ID.
	ClientID string `json:"client_id,omitempty"`

	// Username is the username.
	Username string `json:"username,omitempty"`

	// TokenType is the token type.
	TokenType string `json:"token_type,omitempty"`

	// ExpiresAt is when the token expires.
	ExpiresAt *time.Time `json:"exp,omitempty"`

	// IssuedAt is when the token was issued.
	IssuedAt *time.Time `json:"iat,omitempty"`

	// Subject is the token subject.
	Subject string `json:"sub,omitempty"`

	// Audience is the token audience.
	Audience []string `json:"aud,omitempty"`

	// Issuer is the token issuer.
	Issuer string `json:"iss,omitempty"`
}

// provider implements the Provider interface.
type provider struct {
	config          *ProviderConfig
	discoveryClient DiscoveryClient
	jwtValidator    jwt.Validator
	logger          observability.Logger
	metrics         *Metrics
}

// ProviderOption is a functional option for the provider.
type ProviderOption func(*provider)

// WithProviderLogger sets the logger.
func WithProviderLogger(logger observability.Logger) ProviderOption {
	return func(p *provider) {
		p.logger = logger
	}
}

// WithProviderMetrics sets the metrics.
func WithProviderMetrics(metrics *Metrics) ProviderOption {
	return func(p *provider) {
		p.metrics = metrics
	}
}

// WithDiscoveryClient sets the discovery client.
func WithDiscoveryClient(client DiscoveryClient) ProviderOption {
	return func(p *provider) {
		p.discoveryClient = client
	}
}

// NewProvider creates a new OIDC provider.
func NewProvider(config *ProviderConfig, globalConfig *Config, opts ...ProviderOption) (Provider, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	p := &provider{
		config: config,
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(p)
	}

	if p.metrics == nil {
		p.metrics = NewMetrics("gateway")
	}

	// Create discovery client if not provided
	if p.discoveryClient == nil {
		dc, err := NewDiscoveryClient(globalConfig, WithDiscoveryLogger(p.logger), WithDiscoveryMetrics(p.metrics))
		if err != nil {
			return nil, fmt.Errorf("failed to create discovery client: %w", err)
		}
		p.discoveryClient = dc
	}

	return p, nil
}

// Name returns the provider name.
func (p *provider) Name() string {
	return p.config.Name
}

// ValidateToken validates an access or ID token.
func (p *provider) ValidateToken(ctx context.Context, token string) (*TokenInfo, error) {
	start := time.Now()

	// Get discovery document
	discovery, err := p.discoveryClient.GetDiscovery(ctx, p.config.Name)
	if err != nil {
		p.metrics.RecordTokenValidation("error", p.config.Name, time.Since(start))
		return nil, fmt.Errorf("failed to get discovery document: %w", err)
	}

	// Create JWT validator if needed
	if p.jwtValidator == nil {
		jwtConfig := &jwt.Config{
			Enabled:      true,
			JWKSUrl:      discovery.JWKSUri,
			Issuer:       p.config.Issuer,
			Audience:     p.config.Audience,
			JWKSCacheTTL: time.Hour,
		}

		validator, err := jwt.NewValidator(jwtConfig, jwt.WithValidatorLogger(p.logger))
		if err != nil {
			p.metrics.RecordTokenValidation("error", p.config.Name, time.Since(start))
			return nil, fmt.Errorf("failed to create JWT validator: %w", err)
		}
		p.jwtValidator = validator
	}

	// Validate the token
	claims, err := p.jwtValidator.Validate(ctx, token)
	if err != nil {
		p.metrics.RecordTokenValidation("error", p.config.Name, time.Since(start))
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Extract token info
	tokenInfo := p.extractTokenInfo(claims)

	p.metrics.RecordTokenValidation("success", p.config.Name, time.Since(start))
	p.logger.Debug("token validated",
		observability.String("provider", p.config.Name),
		observability.String("subject", tokenInfo.Subject),
	)

	return tokenInfo, nil
}

// extractTokenInfo extracts token information from claims.
func (p *provider) extractTokenInfo(claims *jwt.Claims) *TokenInfo {
	info := &TokenInfo{
		Subject:  claims.Subject,
		Issuer:   claims.Issuer,
		Audience: []string(claims.Audience),
		Claims:   claims.ToMap(),
	}

	if claims.ExpiresAt != nil {
		info.ExpiresAt = claims.ExpiresAt.Time
	}
	if claims.IssuedAt != nil {
		info.IssuedAt = claims.IssuedAt.Time
	}

	// Extract additional claims based on mapping
	mapping := p.config.GetEffectiveClaimMapping()

	if mapping.Roles != "" {
		info.Roles = claims.GetNestedStringSliceClaim(mapping.Roles)
	}
	if mapping.Permissions != "" {
		info.Permissions = claims.GetNestedStringSliceClaim(mapping.Permissions)
	}
	if mapping.Groups != "" {
		info.Groups = claims.GetNestedStringSliceClaim(mapping.Groups)
	}
	if mapping.Email != "" {
		info.Email = claims.GetStringClaim(mapping.Email)
	}
	if mapping.Name != "" {
		info.Name = claims.GetStringClaim(mapping.Name)
	}

	// Extract scopes
	if scope := claims.GetStringClaim("scope"); scope != "" {
		info.Scopes = strings.Fields(scope)
	}

	// Extract email_verified
	if emailVerified, ok := claims.GetClaim("email_verified"); ok {
		if verified, ok := emailVerified.(bool); ok {
			info.EmailVerified = verified
		}
	}

	return info
}

// GetUserInfo fetches user information using an access token.
func (p *provider) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	// Get discovery document
	discovery, err := p.discoveryClient.GetDiscovery(ctx, p.config.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get discovery document: %w", err)
	}

	if discovery.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("userinfo endpoint not available")
	}

	// Fetch userinfo - implementation would go here
	// This is a placeholder
	return nil, fmt.Errorf("userinfo endpoint not yet implemented")
}

// IntrospectToken introspects a token.
func (p *provider) IntrospectToken(ctx context.Context, token string) (*IntrospectionResult, error) {
	if p.config.Introspection == nil || !p.config.Introspection.Enabled {
		return nil, fmt.Errorf("token introspection is not enabled")
	}

	// Get discovery document for introspection endpoint
	discovery, err := p.discoveryClient.GetDiscovery(ctx, p.config.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get discovery document: %w", err)
	}

	introspectionURL := p.config.Introspection.URL
	if introspectionURL == "" {
		introspectionURL = discovery.IntrospectionEndpoint
	}

	if introspectionURL == "" {
		return nil, fmt.Errorf("introspection endpoint not available")
	}

	// Introspect token - implementation would go here
	// This is a placeholder
	return nil, fmt.Errorf("token introspection not yet implemented")
}

// Close closes the provider.
func (p *provider) Close() error {
	if p.discoveryClient != nil {
		return p.discoveryClient.Close()
	}
	return nil
}

// Ensure provider implements Provider.
var _ Provider = (*provider)(nil)
