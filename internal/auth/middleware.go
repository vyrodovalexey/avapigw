package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/auth/mtls"
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
	routepkg "github.com/vyrodovalexey/avapigw/internal/metrics/route"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/util"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// authTracer is the OTEL tracer used for authentication operations.
var authTracer = otel.Tracer("avapigw/auth")

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
	vaultClient     vault.Client
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

// WithVaultClient sets the vault client for API key vault store.
func WithVaultClient(client vault.Client) AuthenticatorOption {
	return func(a *authenticator) {
		a.vaultClient = client
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

	opts := []apikey.ValidatorOption{apikey.WithValidatorLogger(a.logger)}

	// If vault config is present and vault client is available, create vault store.
	// The CRD vaultPath (e.g. "secret/data/apikeys") is stored as-is in
	// config.APIKey.Vault.Path. For the VaultStore we need the KV-relative
	// path with the mount prefix and the KV v2 "data/" segment stripped.
	if config.APIKey.Vault != nil && config.APIKey.Vault.Enabled && a.vaultClient != nil {
		storeCfg := buildVaultStoreConfig(config.APIKey)
		store, err := apikey.NewVaultStore(a.vaultClient, storeCfg, a.logger)
		if err != nil {
			return fmt.Errorf("failed to create vault API key store: %w", err)
		}
		opts = append(opts, apikey.WithStore(store))
		a.logger.Info("using vault store for API key authentication",
			observability.String("kv_mount", storeCfg.Vault.KVMount),
			observability.String("path", storeCfg.Vault.Path),
		)
	}

	validator, err := apikey.NewValidator(config.APIKey, opts...)
	if err != nil {
		return err
	}
	a.apiKeyValidator = validator
	return nil
}

// buildVaultStoreConfig creates a shallow copy of the API key config with
// the Vault path resolved for the KV v2 client. The original CRD path
// (e.g. "secret/data/apikeys") is split so that KVMount = "secret" and
// Path = "apikeys" (the "data/" segment is stripped because the KV v2
// client adds it automatically).
func buildVaultStoreConfig(src *apikey.Config) *apikey.Config {
	cfg := *src
	vc := *src.Vault

	// Strip the mount prefix from the path to get the KV-relative path.
	// e.g. "secret/data/apikeys" → mount="secret", remainder="data/apikeys"
	// Then strip the "data/" prefix → "apikeys".
	raw := vc.Path
	mount := vc.KVMount

	if mount != "" && len(raw) > len(mount)+1 {
		remainder := raw[len(mount)+1:] // strip "<mount>/"
		// Strip the KV v2 "data/" prefix that the client adds automatically.
		if len(remainder) > 5 && remainder[:5] == "data/" {
			remainder = remainder[5:]
		}
		vc.Path = remainder
	}

	cfg.Vault = &vc
	return &cfg
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

// routeNameFromContext extracts the route name from the request
// context, returning "unknown" if no route is set.
func routeNameFromContext(r *http.Request) string {
	routeName := util.RouteFromContext(r.Context())
	if routeName == "" {
		return "unknown"
	}
	return routeName
}

// recordAuthSuccess records authentication success metrics for both
// the existing auth metrics and the new route-level metrics.
func (a *authenticator) recordAuthSuccess(
	r *http.Request,
	span trace.Span,
	authType AuthType,
	identity *Identity,
	start time.Time,
) {
	at := string(authType)
	span.SetAttributes(
		attribute.String("auth.type", at),
		attribute.String("auth.result", "success"),
		attribute.String("auth.subject", identity.Subject),
	)
	a.metrics.RecordRequest("http", at, "success", time.Since(start))
	a.metrics.RecordSuccess(at)
	routepkg.GetRouteMetrics().RecordAuthSuccess(
		routeNameFromContext(r), r.Method, at,
	)
}

// Authenticate authenticates an HTTP request.
func (a *authenticator) Authenticate(r *http.Request) (*Identity, error) {
	start := time.Now()
	ctx := r.Context()

	ctx, span := authTracer.Start(ctx, "auth.authenticate",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("auth.path", r.URL.Path),
			attribute.String("auth.method", r.Method),
		),
	)
	defer span.End()

	// Check if path should be skipped
	if a.config.ShouldSkipPath(r.URL.Path) {
		span.SetAttributes(attribute.String("auth.result", "skipped"))
		return AnonymousIdentity(), nil
	}

	var identity *Identity
	var authErr error

	// Try mTLS first if enabled
	if a.config.IsMTLSEnabled() && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		identity, authErr = a.authenticateMTLS(ctx, r)
		if authErr == nil {
			a.recordAuthSuccess(r, span, AuthTypeMTLS, identity, start)
			return identity, nil
		}
		a.logger.Debug("mTLS authentication failed", observability.Error(authErr))
	}

	// Try JWT authentication
	if a.config.IsJWTEnabled() {
		identity, authErr = a.authenticateJWT(ctx, r)
		if authErr == nil {
			a.recordAuthSuccess(r, span, AuthTypeJWT, identity, start)
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
			a.recordAuthSuccess(r, span, AuthTypeAPIKey, identity, start)
			return identity, nil
		}
		if !errors.Is(authErr, ErrNoCredentials) {
			a.logger.Debug("API key authentication failed", observability.Error(authErr))
		}
	}

	// If no credentials were provided and anonymous access is allowed
	if a.config.AllowAnonymous && errors.Is(authErr, ErrNoCredentials) {
		span.SetAttributes(attribute.String("auth.result", "anonymous"))
		return AnonymousIdentity(), nil
	}

	// Authentication failed
	if authErr == nil {
		authErr = ErrNoCredentials
	}

	span.SetAttributes(
		attribute.String("auth.result", "failure"),
		attribute.String("auth.error", authErr.Error()),
	)

	a.metrics.RecordRequest("http", "unknown", "failure", time.Since(start))
	a.metrics.RecordFailure("unknown", "no_valid_credentials")
	routeName := routeNameFromContext(r)
	routepkg.GetRouteMetrics().RecordAuthFailure(
		routeName, r.Method, "unknown", "no_valid_credentials",
	)

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
	return claimsToIdentity(claims, authType, a.config)
}

// keyInfoToIdentity converts API key info to an identity.
func (a *authenticator) keyInfoToIdentity(keyInfo *apikey.KeyInfo) *Identity {
	return keyInfoToIdentity(keyInfo)
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
