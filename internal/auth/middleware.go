package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/auth/mtls"
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Authenticator handles authentication for HTTP requests.
type Authenticator interface {
	// Authenticate authenticates an HTTP request.
	Authenticate(r *http.Request) (*Identity, error)

	// HTTPMiddleware returns an HTTP middleware for authentication.
	HTTPMiddleware() func(http.Handler) http.Handler
}

// authenticator implements the Authenticator interface.
type authenticator struct {
	config          *Config
	extractor       Extractor
	jwtValidator    jwt.Validator
	apiKeyValidator apikey.Validator
	mtlsValidator   mtls.Validator
	oidcProviders   map[string]oidc.Provider
	logger          observability.Logger
	metrics         *Metrics
}

// AuthenticatorOption is a functional option for the authenticator.
type AuthenticatorOption func(*authenticator)

// WithAuthenticatorLogger sets the logger.
func WithAuthenticatorLogger(logger observability.Logger) AuthenticatorOption {
	return func(a *authenticator) {
		a.logger = logger
	}
}

// WithAuthenticatorMetrics sets the metrics.
func WithAuthenticatorMetrics(metrics *Metrics) AuthenticatorOption {
	return func(a *authenticator) {
		a.metrics = metrics
	}
}

// WithJWTValidator sets the JWT validator.
func WithJWTValidator(validator jwt.Validator) AuthenticatorOption {
	return func(a *authenticator) {
		a.jwtValidator = validator
	}
}

// WithAPIKeyValidator sets the API key validator.
func WithAPIKeyValidator(validator apikey.Validator) AuthenticatorOption {
	return func(a *authenticator) {
		a.apiKeyValidator = validator
	}
}

// WithMTLSValidator sets the mTLS validator.
func WithMTLSValidator(validator mtls.Validator) AuthenticatorOption {
	return func(a *authenticator) {
		a.mtlsValidator = validator
	}
}

// NewAuthenticator creates a new authenticator.
func NewAuthenticator(config *Config, opts ...AuthenticatorOption) (Authenticator, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}

	a := &authenticator{
		config:        config,
		extractor:     NewExtractor(config.Extraction),
		oidcProviders: make(map[string]oidc.Provider),
		logger:        observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(a)
	}

	// Initialize metrics if not provided
	if a.metrics == nil {
		a.metrics = NewMetrics("gateway")
	}

	// Initialize validators
	if err := a.initializeValidators(config); err != nil {
		return nil, err
	}

	return a, nil
}

// initializeValidators initializes all authentication validators.
func (a *authenticator) initializeValidators(config *Config) error {
	if err := a.initJWTValidator(config); err != nil {
		return err
	}
	if err := a.initAPIKeyValidator(config); err != nil {
		return err
	}
	if err := a.initMTLSValidator(config); err != nil {
		return err
	}
	return a.initOIDCProviders(config)
}

// initJWTValidator initializes the JWT validator if enabled.
func (a *authenticator) initJWTValidator(config *Config) error {
	if !config.IsJWTEnabled() || a.jwtValidator != nil {
		return nil
	}
	validator, err := jwt.NewValidator(config.JWT, jwt.WithValidatorLogger(a.logger))
	if err != nil {
		return err
	}
	a.jwtValidator = validator
	return nil
}

// initAPIKeyValidator initializes the API key validator if enabled.
func (a *authenticator) initAPIKeyValidator(config *Config) error {
	if !config.IsAPIKeyEnabled() || a.apiKeyValidator != nil {
		return nil
	}
	validator, err := apikey.NewValidator(config.APIKey, apikey.WithValidatorLogger(a.logger))
	if err != nil {
		return err
	}
	a.apiKeyValidator = validator
	return nil
}

// initMTLSValidator initializes the mTLS validator if enabled.
func (a *authenticator) initMTLSValidator(config *Config) error {
	if !config.IsMTLSEnabled() || a.mtlsValidator != nil {
		return nil
	}
	validator, err := mtls.NewValidator(config.MTLS, mtls.WithValidatorLogger(a.logger))
	if err != nil {
		return err
	}
	a.mtlsValidator = validator
	return nil
}

// initOIDCProviders initializes OIDC providers if enabled.
func (a *authenticator) initOIDCProviders(config *Config) error {
	if !config.IsOIDCEnabled() {
		return nil
	}
	for _, providerConfig := range config.OIDC.Providers {
		provider, err := oidc.NewProvider(&providerConfig, config.OIDC, oidc.WithProviderLogger(a.logger))
		if err != nil {
			return err
		}
		a.oidcProviders[providerConfig.Name] = provider
	}
	return nil
}

// Authenticate authenticates an HTTP request.
func (a *authenticator) Authenticate(r *http.Request) (*Identity, error) {
	start := time.Now()
	ctx := r.Context()

	// Check if path should be skipped
	if a.config.ShouldSkipPath(r.URL.Path) {
		return AnonymousIdentity(), nil
	}

	var identity *Identity
	var authErr error

	// Try mTLS first if enabled
	if a.config.IsMTLSEnabled() && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		identity, authErr = a.authenticateMTLS(ctx, r)
		if authErr == nil {
			a.metrics.RecordRequest("http", string(AuthTypeMTLS), "success", time.Since(start))
			a.metrics.RecordSuccess(string(AuthTypeMTLS))
			return identity, nil
		}
		a.logger.Debug("mTLS authentication failed", observability.Error(authErr))
	}

	// Try JWT authentication
	if a.config.IsJWTEnabled() {
		identity, authErr = a.authenticateJWT(ctx, r)
		if authErr == nil {
			a.metrics.RecordRequest("http", string(AuthTypeJWT), "success", time.Since(start))
			a.metrics.RecordSuccess(string(AuthTypeJWT))
			return identity, nil
		}
		if !errors.Is(authErr, ErrNoCredentials) {
			a.logger.Debug("JWT authentication failed", observability.Error(authErr))
		}
	}

	// Try API key authentication
	if a.config.IsAPIKeyEnabled() {
		identity, authErr = a.authenticateAPIKey(ctx, r)
		if authErr == nil {
			a.metrics.RecordRequest("http", string(AuthTypeAPIKey), "success", time.Since(start))
			a.metrics.RecordSuccess(string(AuthTypeAPIKey))
			return identity, nil
		}
		if !errors.Is(authErr, ErrNoCredentials) {
			a.logger.Debug("API key authentication failed", observability.Error(authErr))
		}
	}

	// If no credentials were provided and anonymous access is allowed
	if a.config.AllowAnonymous && errors.Is(authErr, ErrNoCredentials) {
		return AnonymousIdentity(), nil
	}

	// Authentication failed
	if authErr == nil {
		authErr = ErrNoCredentials
	}

	a.metrics.RecordRequest("http", "unknown", "failure", time.Since(start))
	a.metrics.RecordFailure("unknown", "no_valid_credentials")

	return nil, authErr
}

// authenticateJWT authenticates using JWT.
func (a *authenticator) authenticateJWT(ctx context.Context, r *http.Request) (*Identity, error) {
	creds, err := a.extractor.ExtractJWT(r)
	if err != nil {
		return nil, err
	}

	claims, err := a.jwtValidator.Validate(ctx, creds.Value)
	if err != nil {
		return nil, WrapAuthError(err, string(AuthTypeJWT))
	}

	return a.claimsToIdentity(claims, AuthTypeJWT), nil
}

// authenticateAPIKey authenticates using API key.
func (a *authenticator) authenticateAPIKey(ctx context.Context, r *http.Request) (*Identity, error) {
	creds, err := a.extractor.ExtractAPIKey(r)
	if err != nil {
		return nil, err
	}

	keyInfo, err := a.apiKeyValidator.Validate(ctx, creds.Value)
	if err != nil {
		return nil, WrapAuthError(err, string(AuthTypeAPIKey))
	}

	return a.keyInfoToIdentity(keyInfo), nil
}

// authenticateMTLS authenticates using mTLS.
func (a *authenticator) authenticateMTLS(ctx context.Context, r *http.Request) (*Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrNoCredentials
	}

	cert := r.TLS.PeerCertificates[0]
	chain := r.TLS.PeerCertificates[1:]

	certInfo, err := a.mtlsValidator.Validate(ctx, cert, chain)
	if err != nil {
		return nil, WrapAuthError(err, string(AuthTypeMTLS))
	}

	return a.certInfoToIdentity(certInfo), nil
}

// claimsToIdentity converts JWT claims to an identity.
func (a *authenticator) claimsToIdentity(claims *jwt.Claims, authType AuthType) *Identity {
	identity := &Identity{
		Subject:  claims.Subject,
		Issuer:   claims.Issuer,
		Audience: []string(claims.Audience),
		AuthType: authType,
		AuthTime: time.Now(),
		Claims:   claims.ToMap(),
	}

	if claims.ExpiresAt != nil {
		identity.ExpiresAt = claims.ExpiresAt.Time
	}

	// Extract additional fields from claims
	if a.config.JWT != nil && a.config.JWT.ClaimMapping != nil {
		mapping := a.config.JWT.ClaimMapping
		if mapping.Roles != "" {
			identity.Roles = claims.GetNestedStringSliceClaim(mapping.Roles)
		}
		if mapping.Permissions != "" {
			identity.Permissions = claims.GetNestedStringSliceClaim(mapping.Permissions)
		}
		if mapping.Groups != "" {
			identity.Groups = claims.GetNestedStringSliceClaim(mapping.Groups)
		}
		if mapping.Scopes != "" {
			identity.Scopes = claims.GetNestedStringSliceClaim(mapping.Scopes)
		}
		if mapping.Email != "" {
			identity.Email = claims.GetStringClaim(mapping.Email)
		}
		if mapping.Name != "" {
			identity.Name = claims.GetStringClaim(mapping.Name)
		}
	}

	return identity
}

// keyInfoToIdentity converts API key info to an identity.
func (a *authenticator) keyInfoToIdentity(keyInfo *apikey.KeyInfo) *Identity {
	identity := &Identity{
		Subject:  keyInfo.ID,
		AuthType: AuthTypeAPIKey,
		AuthTime: time.Now(),
		Roles:    keyInfo.Roles,
		Scopes:   keyInfo.Scopes,
		Metadata: keyInfo.Metadata,
		ClientID: keyInfo.ID,
	}

	if keyInfo.ExpiresAt != nil {
		identity.ExpiresAt = *keyInfo.ExpiresAt
	}

	return identity
}

// certInfoToIdentity converts certificate info to an identity.
func (a *authenticator) certInfoToIdentity(certInfo *mtls.CertificateInfo) *Identity {
	identity := &Identity{
		Subject:  certInfo.GetIdentity(a.config.MTLS.ExtractIdentity),
		AuthType: AuthTypeMTLS,
		AuthTime: time.Now(),
		CertificateInfo: &CertificateInfo{
			SubjectDN:      certInfo.SubjectDN,
			IssuerDN:       certInfo.IssuerDN,
			SerialNumber:   certInfo.SerialNumber,
			NotBefore:      certInfo.NotBefore,
			NotAfter:       certInfo.NotAfter,
			DNSNames:       certInfo.DNSNames,
			URIs:           certInfo.URIs,
			EmailAddresses: certInfo.EmailAddresses,
			SPIFFEID:       certInfo.SPIFFEID,
			Fingerprint:    certInfo.Fingerprint,
		},
	}

	identity.ExpiresAt = certInfo.NotAfter

	return identity
}

// HTTPMiddleware returns an HTTP middleware for authentication.
func (a *authenticator) HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, err := a.Authenticate(r)
			if err != nil {
				a.handleAuthError(w, r, err)
				return
			}

			// Add identity to context
			ctx := ContextWithIdentity(r.Context(), identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// handleAuthError handles authentication errors.
func (a *authenticator) handleAuthError(w http.ResponseWriter, r *http.Request, err error) {
	a.logger.Warn("authentication failed",
		observability.String("path", r.URL.Path),
		observability.String("method", r.Method),
		observability.Error(err),
	)

	w.Header().Set(HeaderContentType, ContentTypeJSON)

	var statusCode int
	var message string

	switch {
	case errors.Is(err, ErrNoCredentials):
		statusCode = http.StatusUnauthorized
		message = "authentication required"
		w.Header().Set(HeaderWWWAuthenticate, "Bearer")
	case errors.Is(err, ErrTokenExpired):
		statusCode = http.StatusUnauthorized
		message = "token expired"
	case errors.Is(err, ErrInvalidToken), errors.Is(err, ErrInvalidSignature):
		statusCode = http.StatusUnauthorized
		message = "invalid token"
	case errors.Is(err, ErrInvalidAPIKey):
		statusCode = http.StatusUnauthorized
		message = "invalid API key"
	default:
		statusCode = http.StatusUnauthorized
		message = "authentication failed"
	}

	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

// Ensure authenticator implements Authenticator.
var _ Authenticator = (*authenticator)(nil)
