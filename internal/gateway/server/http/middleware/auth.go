package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/basic"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/authz"
)

// AuthConfig holds configuration for the auth middleware.
type AuthConfig struct {
	// JWT configuration
	JWTEnabled   bool
	JWTValidator *jwt.Validator
	JWTExtractor jwt.TokenExtractor
	JWTClaimsKey string
	JWTSkipPaths []string

	// API Key configuration
	APIKeyEnabled   bool
	APIKeyValidator *apikey.Validator
	APIKeyExtractor apikey.Extractor
	APIKeyKey       string
	APIKeySkipPaths []string

	// Basic Auth configuration
	BasicEnabled   bool
	BasicValidator *basic.Validator
	BasicSkipPaths []string

	// Authorization configuration
	AuthzEnabled   bool
	Authorizer     authz.Authorizer
	AuthzSkipPaths []string

	// General configuration
	Logger            *zap.Logger
	RequireAuth       bool
	AllowAnonymous    bool
	AnonymousPaths    []string
	ForwardAuthHeader bool
}

// DefaultAuthConfig returns an AuthConfig with default values.
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		JWTClaimsKey:      "jwt_claims",
		APIKeyKey:         "api_key",
		RequireAuth:       true,
		AllowAnonymous:    false,
		ForwardAuthHeader: true,
	}
}

// Auth returns a middleware that handles authentication.
func Auth(config *AuthConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultAuthConfig()
	}

	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	// Build skip paths maps
	jwtSkipPaths := make(map[string]bool)
	for _, path := range config.JWTSkipPaths {
		jwtSkipPaths[path] = true
	}

	apiKeySkipPaths := make(map[string]bool)
	for _, path := range config.APIKeySkipPaths {
		apiKeySkipPaths[path] = true
	}

	basicSkipPaths := make(map[string]bool)
	for _, path := range config.BasicSkipPaths {
		basicSkipPaths[path] = true
	}

	authzSkipPaths := make(map[string]bool)
	for _, path := range config.AuthzSkipPaths {
		authzSkipPaths[path] = true
	}

	anonymousPaths := make(map[string]bool)
	for _, path := range config.AnonymousPaths {
		anonymousPaths[path] = true
	}

	return func(c *gin.Context) {
		path := c.Request.URL.Path
		ctx := c.Request.Context()

		// Check if path allows anonymous access
		if config.AllowAnonymous && anonymousPaths[path] {
			c.Next()
			return
		}

		var authenticated bool
		var subject *authz.Subject

		// Try JWT authentication
		if config.JWTEnabled && config.JWTValidator != nil && !jwtSkipPaths[path] {
			if claims, err := authenticateJWT(ctx, c.Request, config); err == nil {
				authenticated = true
				subject = claimsToSubject(claims)
				c.Set(config.JWTClaimsKey, claims)

				// Store claims in context
				ctx = context.WithValue(ctx, jwt.ClaimsContextKey{}, claims)
				c.Request = c.Request.WithContext(ctx)
			}
		}

		// Try API Key authentication if JWT didn't succeed
		if !authenticated && config.APIKeyEnabled && config.APIKeyValidator != nil && !apiKeySkipPaths[path] {
			if apiKey, err := authenticateAPIKey(ctx, c.Request, config); err == nil {
				authenticated = true
				subject = apiKeyToSubject(apiKey)
				c.Set(config.APIKeyKey, apiKey)

				// Store API key in context
				ctx = apikey.ContextWithAPIKey(ctx, apiKey)
				c.Request = c.Request.WithContext(ctx)
			}
		}

		// Try Basic authentication if others didn't succeed
		if !authenticated && config.BasicEnabled && config.BasicValidator != nil && !basicSkipPaths[path] {
			if user, err := authenticateBasic(ctx, c.Request, config); err == nil {
				authenticated = true
				subject = userToSubject(user)

				// Store user in context
				ctx = basic.ContextWithUser(ctx, user)
				c.Request = c.Request.WithContext(ctx)
			} else if config.RequireAuth && !config.APIKeyEnabled && !config.JWTEnabled {
				// Only send WWW-Authenticate if basic auth is the only method
				c.Header("WWW-Authenticate", `Basic realm="`+config.BasicValidator.Realm()+`"`)
			}
		}

		// Check if authentication is required
		if config.RequireAuth && !authenticated {
			config.Logger.Debug("authentication required but not provided",
				zap.String("path", path),
				zap.String("method", c.Request.Method),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "authentication required",
			})
			return
		}

		// Store subject in context for authorization
		if subject != nil {
			ctx = authz.ContextWithSubject(ctx, subject)
			c.Request = c.Request.WithContext(ctx)
		}

		// Perform authorization if enabled
		if config.AuthzEnabled && config.Authorizer != nil && !authzSkipPaths[path] {
			resource := authz.NewResourceFromRequest(c.Request)

			decision, err := config.Authorizer.Authorize(ctx, subject, resource)
			if err != nil {
				config.Logger.Error("authorization error",
					zap.Error(err),
					zap.String("path", path),
				)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error":   "internal_error",
					"message": "authorization error",
				})
				return
			}

			if !decision.Allowed {
				config.Logger.Debug("authorization denied",
					zap.String("path", path),
					zap.String("method", c.Request.Method),
					zap.String("reason", decision.Reason),
					zap.String("rule", decision.Rule),
				)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "forbidden",
					"message": "access denied",
				})
				return
			}
		}

		c.Next()
	}
}

// authenticateJWT authenticates using JWT.
func authenticateJWT(ctx context.Context, r *http.Request, config *AuthConfig) (*jwt.Claims, error) {
	extractor := config.JWTExtractor
	if extractor == nil {
		extractor = jwt.DefaultExtractor()
	}

	token, err := extractor.Extract(r)
	if err != nil {
		return nil, err
	}

	return config.JWTValidator.Validate(ctx, token)
}

// authenticateAPIKey authenticates using API key.
func authenticateAPIKey(ctx context.Context, r *http.Request, config *AuthConfig) (*apikey.APIKey, error) {
	extractor := config.APIKeyExtractor
	if extractor == nil {
		extractor = apikey.DefaultExtractor()
	}

	key, err := extractor.Extract(r)
	if err != nil {
		return nil, err
	}

	return config.APIKeyValidator.Validate(ctx, key)
}

// authenticateBasic authenticates using basic auth.
func authenticateBasic(ctx context.Context, r *http.Request, config *AuthConfig) (*basic.User, error) {
	return config.BasicValidator.ValidateRequest(ctx, r)
}

// claimsToSubject converts JWT claims to an authorization subject.
func claimsToSubject(claims *jwt.Claims) *authz.Subject {
	subject := &authz.Subject{
		User:   claims.Subject,
		Groups: claims.Groups,
		Roles:  claims.Roles,
		Scopes: claims.GetScopes(),
		Claims: claims.Raw(),
	}

	return subject
}

// apiKeyToSubject converts an API key to an authorization subject.
func apiKeyToSubject(key *apikey.APIKey) *authz.Subject {
	return &authz.Subject{
		User:   key.ID,
		Scopes: key.Scopes,
		Metadata: map[string]string{
			"api_key_name": key.Name,
		},
	}
}

// userToSubject converts a basic auth user to an authorization subject.
func userToSubject(user *basic.User) *authz.Subject {
	return &authz.Subject{
		User:     user.Username,
		Groups:   user.Groups,
		Roles:    user.Roles,
		Metadata: user.Metadata,
	}
}

// JWTAuth returns a middleware that handles JWT authentication only.
func JWTAuth(validator *jwt.Validator, extractor jwt.TokenExtractor, logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}

	if extractor == nil {
		extractor = jwt.DefaultExtractor()
	}

	return func(c *gin.Context) {
		token, err := extractor.Extract(c.Request)
		if err != nil {
			logger.Debug("failed to extract JWT token", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "missing or invalid token",
			})
			return
		}

		claims, err := validator.Validate(c.Request.Context(), token)
		if err != nil {
			logger.Debug("JWT validation failed", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "invalid token",
			})
			return
		}

		// Store claims in context
		c.Set("jwt_claims", claims)
		ctx := context.WithValue(c.Request.Context(), jwt.ClaimsContextKey{}, claims)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// APIKeyAuth returns a middleware that handles API key authentication only.
func APIKeyAuth(validator *apikey.Validator, extractor apikey.Extractor, logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}

	if extractor == nil {
		extractor = apikey.DefaultExtractor()
	}

	return func(c *gin.Context) {
		key, err := extractor.Extract(c.Request)
		if err != nil {
			logger.Debug("failed to extract API key", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "missing or invalid API key",
			})
			return
		}

		apiKey, err := validator.Validate(c.Request.Context(), key)
		if err != nil {
			logger.Debug("API key validation failed", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "invalid API key",
			})
			return
		}

		// Store API key in context
		c.Set("api_key", apiKey)
		ctx := apikey.ContextWithAPIKey(c.Request.Context(), apiKey)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// BasicAuth returns a middleware that handles basic authentication only.
func BasicAuth(validator *basic.Validator, logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}

	return func(c *gin.Context) {
		user, err := validator.ValidateRequest(c.Request.Context(), c.Request)
		if err != nil {
			logger.Debug("basic auth validation failed", zap.Error(err))
			c.Header("WWW-Authenticate", `Basic realm="`+validator.Realm()+`"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "invalid credentials",
			})
			return
		}

		// Store user in context
		ctx := basic.ContextWithUser(c.Request.Context(), user)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// Authorization returns a middleware that handles authorization only.
func Authorization(authorizer authz.Authorizer, logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}

	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Get subject from context
		subject, _ := authz.GetSubjectFromContext(ctx)

		// Create resource from request
		resource := authz.NewResourceFromRequest(c.Request)

		// Authorize
		decision, err := authorizer.Authorize(ctx, subject, resource)
		if err != nil {
			logger.Error("authorization error", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "authorization error",
			})
			return
		}

		if !decision.Allowed {
			logger.Debug("authorization denied",
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method),
				zap.String("reason", decision.Reason),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "access denied",
			})
			return
		}

		c.Next()
	}
}

// RequireRoles returns a middleware that requires specific roles.
func RequireRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, ok := authz.GetSubjectFromContext(c.Request.Context())
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "authentication required",
			})
			return
		}

		if !subject.HasAnyRole(roles...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "insufficient permissions",
			})
			return
		}

		c.Next()
	}
}

// RequireScopes returns a middleware that requires specific scopes.
func RequireScopes(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, ok := authz.GetSubjectFromContext(c.Request.Context())
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "authentication required",
			})
			return
		}

		for _, scope := range scopes {
			if !subject.HasScope(scope) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "forbidden",
					"message": "insufficient scope",
				})
				return
			}
		}

		c.Next()
	}
}

// RequireGroups returns a middleware that requires specific groups.
func RequireGroups(groups ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, ok := authz.GetSubjectFromContext(c.Request.Context())
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "authentication required",
			})
			return
		}

		for _, group := range groups {
			if subject.HasGroup(group) {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":   "forbidden",
			"message": "insufficient permissions",
		})
	}
}

// OptionalAuth returns a middleware that attempts authentication but doesn't require it.
func OptionalAuth(config *AuthConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultAuthConfig()
	}
	config.RequireAuth = false
	config.AllowAnonymous = true

	return Auth(config)
}

// GetJWTClaims returns the JWT claims from the context.
func GetJWTClaims(c *gin.Context) (*jwt.Claims, bool) {
	claims, exists := c.Get("jwt_claims")
	if !exists {
		return nil, false
	}
	jwtClaims, ok := claims.(*jwt.Claims)
	return jwtClaims, ok
}

// GetAPIKey returns the API key from the context.
func GetAPIKey(c *gin.Context) (*apikey.APIKey, bool) {
	key, exists := c.Get("api_key")
	if !exists {
		return nil, false
	}
	apiKey, ok := key.(*apikey.APIKey)
	return apiKey, ok
}

// GetSubject returns the authorization subject from the context.
func GetSubject(c *gin.Context) (*authz.Subject, bool) {
	return authz.GetSubjectFromContext(c.Request.Context())
}

// SkipAuth returns a middleware that marks the request to skip authentication.
func SkipAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("skip_auth", true)
		c.Next()
	}
}

// ShouldSkipAuth checks if authentication should be skipped.
func ShouldSkipAuth(c *gin.Context) bool {
	skip, exists := c.Get("skip_auth")
	if !exists {
		return false
	}
	return skip.(bool)
}

// ExtractBearerToken extracts a bearer token from the Authorization header.
func ExtractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}

	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}

	return strings.TrimSpace(auth[len(prefix):]), true
}
