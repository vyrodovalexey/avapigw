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
	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
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

// authMiddlewareContext holds the context for auth middleware processing.
type authMiddlewareContext struct {
	config         *AuthConfig
	authCore       *core.AuthCore
	authzSkipPaths map[string]bool
}

// newAuthMiddlewareContext creates and initializes the auth middleware context.
func newAuthMiddlewareContext(config *AuthConfig) *authMiddlewareContext {
	if config == nil {
		config = DefaultAuthConfig()
	}
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	// Create core auth configuration
	coreConfig := core.AuthCoreConfig{
		BaseConfig: core.BaseConfig{
			Logger: config.Logger,
		},
		JWTEnabled:     config.JWTEnabled,
		APIKeyEnabled:  config.APIKeyEnabled,
		BasicEnabled:   config.BasicEnabled,
		RequireAuth:    config.RequireAuth,
		AllowAnonymous: config.AllowAnonymous,
		AnonymousPaths: config.AnonymousPaths,
	}

	authCore := core.NewAuthCore(coreConfig)
	configureAuthValidators(authCore, config)

	return &authMiddlewareContext{
		config:         config,
		authCore:       authCore,
		authzSkipPaths: buildSkipPathsMap(config.AuthzSkipPaths),
	}
}

// configureAuthValidators sets up validators on the auth core.
func configureAuthValidators(authCore *core.AuthCore, config *AuthConfig) {
	if config.JWTValidator != nil {
		authCore.WithJWTValidator(config.JWTValidator)
	}
	if config.APIKeyValidator != nil {
		authCore.WithAPIKeyValidator(config.APIKeyValidator)
	}
	if config.BasicValidator != nil {
		authCore.WithBasicValidator(config.BasicValidator)
	}
}

// buildSkipPathsMap creates a map from a slice of paths for O(1) lookup.
func buildSkipPathsMap(paths []string) map[string]bool {
	skipPaths := make(map[string]bool)
	for _, path := range paths {
		skipPaths[path] = true
	}
	return skipPaths
}

// storeAuthResultInContext stores authentication results in the gin and request context.
func storeAuthResultInContext(c *gin.Context, result *core.AuthResult, config *AuthConfig) context.Context {
	ctx := c.Request.Context()
	if !result.Authenticated {
		return ctx
	}

	switch result.Method {
	case "jwt":
		if result.JWTClaims != nil {
			c.Set(config.JWTClaimsKey, result.JWTClaims)
			ctx = context.WithValue(ctx, jwt.ClaimsContextKey{}, result.JWTClaims)
		}
	case "apikey":
		if result.APIKey != nil {
			c.Set(config.APIKeyKey, result.APIKey)
			ctx = apikey.ContextWithAPIKey(ctx, result.APIKey)
		}
	case "basic":
		if result.User != nil {
			ctx = basic.ContextWithUser(ctx, result.User)
		}
	}
	return ctx
}

// handleAuthRequired handles the case when authentication is required but not provided.
func handleAuthRequired(c *gin.Context, authCore *core.AuthCore, logger *zap.Logger, path string) {
	if authCore.IsOnlyBasicAuth() {
		c.Header("WWW-Authenticate", `Basic realm="`+authCore.BasicRealm()+`"`)
	}

	logger.Debug("authentication required but not provided",
		zap.String("path", path),
		zap.String("method", c.Request.Method),
	)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":   "unauthorized",
		"message": "authentication required",
	})
}

// performAuthorization performs authorization check and returns true if request should continue.
func performAuthorization(
	c *gin.Context,
	ctx context.Context,
	authorizer authz.Authorizer,
	subject *authz.Subject,
	logger *zap.Logger,
) bool {
	resource := authz.NewResourceFromRequest(c.Request)
	path := c.Request.URL.Path

	decision, err := authorizer.Authorize(ctx, subject, resource)
	if err != nil {
		logger.Error("authorization error",
			zap.Error(err),
			zap.String("path", path),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "authorization error",
		})
		return false
	}

	if !decision.Allowed {
		logger.Debug("authorization denied",
			zap.String("path", path),
			zap.String("method", c.Request.Method),
			zap.String("reason", decision.Reason),
			zap.String("rule", decision.Rule),
		)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":   "forbidden",
			"message": "access denied",
		})
		return false
	}
	return true
}

// Auth returns a middleware that handles authentication.
func Auth(config *AuthConfig) gin.HandlerFunc {
	mctx := newAuthMiddlewareContext(config)

	return func(c *gin.Context) {
		path := c.Request.URL.Path
		ctx := c.Request.Context()

		// Check if path allows anonymous access
		if mctx.authCore.IsAnonymousPath(path) {
			c.Next()
			return
		}

		// Extract credentials and authenticate
		credentials := extractCredentialsFromRequest(c.Request, mctx.config)
		result := mctx.authCore.Authenticate(ctx, credentials)

		// Store authentication results in context
		ctx = storeAuthResultInContext(c, result, mctx.config)
		c.Request = c.Request.WithContext(ctx)

		// Check if authentication is required
		if mctx.authCore.RequireAuth() && !result.Authenticated {
			handleAuthRequired(c, mctx.authCore, mctx.config.Logger, path)
			return
		}

		// Store subject in context for authorization
		if result.Subject != nil {
			ctx = authz.ContextWithSubject(ctx, result.Subject)
			c.Request = c.Request.WithContext(ctx)
		}

		// Perform authorization if enabled
		if mctx.config.AuthzEnabled && mctx.config.Authorizer != nil && !mctx.authzSkipPaths[path] {
			if !performAuthorization(c, ctx, mctx.config.Authorizer, result.Subject, mctx.config.Logger) {
				return
			}
		}

		c.Next()
	}
}

// extractCredentialsFromRequest extracts authentication credentials from an HTTP request.
func extractCredentialsFromRequest(r *http.Request, config *AuthConfig) core.AuthCredentials {
	credentials := core.AuthCredentials{}

	// Extract JWT token
	if config.JWTEnabled {
		extractor := config.JWTExtractor
		if extractor == nil {
			extractor = jwt.DefaultExtractor()
		}
		if token, err := extractor.Extract(r); err == nil {
			credentials.BearerToken = token
		}
	}

	// Extract API key
	if config.APIKeyEnabled {
		extractor := config.APIKeyExtractor
		if extractor == nil {
			extractor = apikey.DefaultExtractor()
		}
		if key, err := extractor.Extract(r); err == nil {
			credentials.APIKey = key
		}
	}

	// Extract basic auth
	if config.BasicEnabled {
		if username, password, ok := r.BasicAuth(); ok {
			credentials.BasicAuth = &core.BasicCredentials{
				Username: username,
				Password: password,
			}
		}
	}

	return credentials
}

// authenticateWithCore performs authentication and returns the result with updated context.
func authenticateWithCore(c *gin.Context, authCore *core.AuthCore, logger *zap.Logger) (*core.AuthResult, bool) {
	path := c.Request.URL.Path
	ctx := c.Request.Context()

	// Check if path allows anonymous access
	if authCore.IsAnonymousPath(path) {
		return nil, true
	}

	// Extract credentials and authenticate
	credentials := extractCredentialsFromHTTPRequest(c.Request)
	result := authCore.Authenticate(ctx, credentials)

	// Check if authentication is required
	if authCore.RequireAuth() && !result.Authenticated {
		handleAuthRequired(c, authCore, logger, path)
		return nil, false
	}

	// Store subject in context for authorization
	if result.Subject != nil {
		ctx = authz.ContextWithSubject(ctx, result.Subject)
		c.Request = c.Request.WithContext(ctx)
	}

	return result, true
}

// AuthWithCore returns a middleware that handles authentication using the core package directly.
func AuthWithCore(authCore *core.AuthCore, authorizer authz.Authorizer, logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		result, shouldContinue := authenticateWithCore(c, authCore, logger)
		if !shouldContinue {
			return
		}
		// Anonymous path - continue without authorization
		if result == nil {
			c.Next()
			return
		}

		// Perform authorization if enabled
		if authorizer != nil && !authCore.ShouldSkip(path) {
			if !performAuthorization(c, c.Request.Context(), authorizer, result.Subject, logger) {
				return
			}
		}

		c.Next()
	}
}

// extractCredentialsFromHTTPRequest extracts authentication credentials from an HTTP request.
func extractCredentialsFromHTTPRequest(r *http.Request) core.AuthCredentials {
	credentials := core.AuthCredentials{}

	// Extract bearer token
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			credentials.BearerToken = strings.TrimPrefix(auth, "Bearer ")
			credentials.BearerToken = strings.TrimPrefix(credentials.BearerToken, "bearer ")
		}
	}

	// Extract API key
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		credentials.APIKey = apiKey
	}

	// Extract basic auth
	if username, password, ok := r.BasicAuth(); ok {
		credentials.BasicAuth = &core.BasicCredentials{
			Username: username,
			Password: password,
		}
	}

	return credentials
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
