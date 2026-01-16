package core

import (
	"context"
	"errors"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/basic"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/authz"
	"go.uber.org/zap"
)

// Authentication errors.
var (
	ErrNoJWTValidator    = errors.New("no JWT validator configured")
	ErrNoAPIKeyValidator = errors.New("no API key validator configured")
	ErrNoBasicValidator  = errors.New("no basic validator configured")
)

// JWTValidator defines the interface for JWT validation.
type JWTValidator interface {
	Validate(ctx context.Context, token string) (*jwt.Claims, error)
}

// APIKeyValidator defines the interface for API key validation.
type APIKeyValidator interface {
	Validate(ctx context.Context, key string) (*apikey.APIKey, error)
}

// BasicValidator defines the interface for basic auth validation.
type BasicValidator interface {
	Validate(ctx context.Context, username, password string) (*basic.User, error)
	Realm() string
}

// AuthResult represents the result of an authentication attempt.
type AuthResult struct {
	// Authenticated indicates whether authentication was successful.
	Authenticated bool

	// Subject is the authorization subject extracted from the credentials.
	Subject *authz.Subject

	// Method is the authentication method used ("jwt", "apikey", "basic").
	Method string

	// Error is the error that occurred during authentication, if any.
	Error error

	// JWTClaims contains the JWT claims if JWT authentication was used.
	JWTClaims *jwt.Claims

	// APIKey contains the API key if API key authentication was used.
	APIKey *apikey.APIKey

	// User contains the user if basic authentication was used.
	User *basic.User
}

// BasicCredentials holds basic authentication credentials.
type BasicCredentials struct {
	Username string
	Password string
}

// AuthCredentials holds all possible authentication credentials.
type AuthCredentials struct {
	// BearerToken is the JWT bearer token.
	BearerToken string

	// APIKey is the API key.
	APIKey string

	// BasicAuth contains basic authentication credentials.
	BasicAuth *BasicCredentials
}

// HasCredentials returns true if any credentials are present.
func (c AuthCredentials) HasCredentials() bool {
	return c.BearerToken != "" || c.APIKey != "" || c.BasicAuth != nil
}

// AuthCore provides protocol-agnostic authentication functionality.
type AuthCore struct {
	jwtValidator    JWTValidator
	apiKeyValidator APIKeyValidator
	basicValidator  BasicValidator
	logger          *zap.Logger
	skipPaths       map[string]bool
	anonymousPaths  map[string]bool
	config          AuthCoreConfig
}

// NewAuthCore creates a new AuthCore with the given configuration.
func NewAuthCore(config AuthCoreConfig) *AuthCore {
	config.InitSkipPaths()
	config.InitAnonymousPaths()

	return &AuthCore{
		logger:         config.GetLogger(),
		skipPaths:      config.skipPathMap,
		anonymousPaths: config.anonymousPathMap,
		config:         config,
	}
}

// WithJWTValidator sets the JWT validator.
func (c *AuthCore) WithJWTValidator(validator JWTValidator) *AuthCore {
	c.jwtValidator = validator
	return c
}

// WithAPIKeyValidator sets the API key validator.
func (c *AuthCore) WithAPIKeyValidator(validator APIKeyValidator) *AuthCore {
	c.apiKeyValidator = validator
	return c
}

// WithBasicValidator sets the basic auth validator.
func (c *AuthCore) WithBasicValidator(validator BasicValidator) *AuthCore {
	c.basicValidator = validator
	return c
}

// Authenticate attempts to authenticate using the provided credentials.
// It tries each enabled authentication method in order: JWT, API Key, Basic.
func (c *AuthCore) Authenticate(ctx context.Context, credentials AuthCredentials) *AuthResult {
	result := &AuthResult{}

	// Try JWT authentication
	if c.config.JWTEnabled && c.jwtValidator != nil && credentials.BearerToken != "" {
		claims, err := c.jwtValidator.Validate(ctx, credentials.BearerToken)
		if err == nil {
			result.Authenticated = true
			result.Method = "jwt"
			result.JWTClaims = claims
			result.Subject = claimsToSubject(claims)
			return result
		}
		c.logger.Debug("JWT authentication failed", zap.Error(err))
	}

	// Try API Key authentication
	if c.config.APIKeyEnabled && c.apiKeyValidator != nil && credentials.APIKey != "" {
		key, err := c.apiKeyValidator.Validate(ctx, credentials.APIKey)
		if err == nil {
			result.Authenticated = true
			result.Method = "apikey"
			result.APIKey = key
			result.Subject = apiKeyToSubject(key)
			return result
		}
		c.logger.Debug("API key authentication failed", zap.Error(err))
	}

	// Try Basic authentication
	if c.config.BasicEnabled && c.basicValidator != nil && credentials.BasicAuth != nil {
		user, err := c.basicValidator.Validate(ctx, credentials.BasicAuth.Username, credentials.BasicAuth.Password)
		if err == nil {
			result.Authenticated = true
			result.Method = "basic"
			result.User = user
			result.Subject = userToSubject(user)
			return result
		}
		c.logger.Debug("Basic authentication failed", zap.Error(err))
	}

	return result
}

// AuthenticateJWT attempts JWT authentication only.
func (c *AuthCore) AuthenticateJWT(ctx context.Context, token string) *AuthResult {
	result := &AuthResult{}

	if c.jwtValidator == nil {
		result.Error = ErrNoJWTValidator
		return result
	}

	claims, err := c.jwtValidator.Validate(ctx, token)
	if err != nil {
		result.Error = err
		return result
	}

	result.Authenticated = true
	result.Method = "jwt"
	result.JWTClaims = claims
	result.Subject = claimsToSubject(claims)
	return result
}

// AuthenticateAPIKey attempts API key authentication only.
func (c *AuthCore) AuthenticateAPIKey(ctx context.Context, key string) *AuthResult {
	result := &AuthResult{}

	if c.apiKeyValidator == nil {
		result.Error = ErrNoAPIKeyValidator
		return result
	}

	apiKey, err := c.apiKeyValidator.Validate(ctx, key)
	if err != nil {
		result.Error = err
		return result
	}

	result.Authenticated = true
	result.Method = "apikey"
	result.APIKey = apiKey
	result.Subject = apiKeyToSubject(apiKey)
	return result
}

// AuthenticateBasic attempts basic authentication only.
func (c *AuthCore) AuthenticateBasic(ctx context.Context, username, password string) *AuthResult {
	result := &AuthResult{}

	if c.basicValidator == nil {
		result.Error = ErrNoBasicValidator
		return result
	}

	user, err := c.basicValidator.Validate(ctx, username, password)
	if err != nil {
		result.Error = err
		return result
	}

	result.Authenticated = true
	result.Method = "basic"
	result.User = user
	result.Subject = userToSubject(user)
	return result
}

// ShouldSkip checks if the given path should skip authentication.
func (c *AuthCore) ShouldSkip(path string) bool {
	if c.skipPaths == nil {
		return false
	}
	return c.skipPaths[path]
}

// IsAnonymousPath checks if the given path allows anonymous access.
func (c *AuthCore) IsAnonymousPath(path string) bool {
	if !c.config.AllowAnonymous {
		return false
	}
	if c.anonymousPaths == nil {
		return false
	}
	return c.anonymousPaths[path]
}

// RequireAuth returns whether authentication is required.
func (c *AuthCore) RequireAuth() bool {
	return c.config.RequireAuth
}

// AllowAnonymous returns whether anonymous access is allowed.
func (c *AuthCore) AllowAnonymous() bool {
	return c.config.AllowAnonymous
}

// BasicRealm returns the basic auth realm if basic auth is configured.
func (c *AuthCore) BasicRealm() string {
	if c.basicValidator != nil {
		return c.basicValidator.Realm()
	}
	return "Restricted"
}

// IsOnlyBasicAuth returns true if basic auth is the only enabled method.
func (c *AuthCore) IsOnlyBasicAuth() bool {
	return c.config.BasicEnabled && !c.config.JWTEnabled && !c.config.APIKeyEnabled
}

// claimsToSubject converts JWT claims to an authorization subject.
func claimsToSubject(claims *jwt.Claims) *authz.Subject {
	return ClaimsToSubject(claims)
}

// apiKeyToSubject converts an API key to an authorization subject.
func apiKeyToSubject(key *apikey.APIKey) *authz.Subject {
	return APIKeyToSubject(key)
}

// userToSubject converts a basic auth user to an authorization subject.
func userToSubject(user *basic.User) *authz.Subject {
	return UserToSubject(user)
}

// ClaimsToSubject converts JWT claims to an authorization subject.
// This is the exported version for external use.
func ClaimsToSubject(claims *jwt.Claims) *authz.Subject {
	return &authz.Subject{
		User:   claims.Subject,
		Groups: claims.Groups,
		Roles:  claims.Roles,
		Scopes: claims.GetScopes(),
		Claims: claims.Raw(),
	}
}

// APIKeyToSubject converts an API key to an authorization subject.
// This is the exported version for external use.
func APIKeyToSubject(key *apikey.APIKey) *authz.Subject {
	return &authz.Subject{
		User:   key.ID,
		Scopes: key.Scopes,
		Metadata: map[string]string{
			"api_key_name": key.Name,
		},
	}
}

// UserToSubject converts a basic auth user to an authorization subject.
// This is the exported version for external use.
func UserToSubject(user *basic.User) *authz.Subject {
	return &authz.Subject{
		User:     user.Username,
		Groups:   user.Groups,
		Roles:    user.Roles,
		Metadata: user.Metadata,
	}
}
