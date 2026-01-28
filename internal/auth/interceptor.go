package auth

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// GRPCAuthenticator handles authentication for gRPC requests.
type GRPCAuthenticator interface {
	// Authenticate authenticates a gRPC request.
	Authenticate(ctx context.Context) (*Identity, error)

	// UnaryInterceptor returns a unary server interceptor for authentication.
	UnaryInterceptor() grpc.UnaryServerInterceptor

	// StreamInterceptor returns a stream server interceptor for authentication.
	StreamInterceptor() grpc.StreamServerInterceptor
}

// grpcAuthenticator implements the GRPCAuthenticator interface.
type grpcAuthenticator struct {
	config          *Config
	extractor       Extractor
	jwtValidator    jwt.Validator
	apiKeyValidator apikey.Validator
	logger          observability.Logger
	metrics         *Metrics
}

// GRPCAuthenticatorOption is a functional option for the gRPC authenticator.
type GRPCAuthenticatorOption func(*grpcAuthenticator)

// WithGRPCAuthenticatorLogger sets the logger.
func WithGRPCAuthenticatorLogger(logger observability.Logger) GRPCAuthenticatorOption {
	return func(a *grpcAuthenticator) {
		a.logger = logger
	}
}

// WithGRPCAuthenticatorMetrics sets the metrics.
func WithGRPCAuthenticatorMetrics(metrics *Metrics) GRPCAuthenticatorOption {
	return func(a *grpcAuthenticator) {
		a.metrics = metrics
	}
}

// WithGRPCJWTValidator sets the JWT validator.
func WithGRPCJWTValidator(validator jwt.Validator) GRPCAuthenticatorOption {
	return func(a *grpcAuthenticator) {
		a.jwtValidator = validator
	}
}

// WithGRPCAPIKeyValidator sets the API key validator.
func WithGRPCAPIKeyValidator(validator apikey.Validator) GRPCAuthenticatorOption {
	return func(a *grpcAuthenticator) {
		a.apiKeyValidator = validator
	}
}

// NewGRPCAuthenticator creates a new gRPC authenticator.
func NewGRPCAuthenticator(config *Config, opts ...GRPCAuthenticatorOption) (GRPCAuthenticator, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}

	a := &grpcAuthenticator{
		config:    config,
		extractor: NewExtractor(config.Extraction),
		logger:    observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(a)
	}

	// Initialize metrics if not provided
	if a.metrics == nil {
		a.metrics = NewMetrics("gateway")
	}

	// Initialize JWT validator if enabled and not provided
	if config.IsJWTEnabled() && a.jwtValidator == nil {
		validator, err := jwt.NewValidator(config.JWT, jwt.WithValidatorLogger(a.logger))
		if err != nil {
			return nil, err
		}
		a.jwtValidator = validator
	}

	// Initialize API key validator if enabled and not provided
	if config.IsAPIKeyEnabled() && a.apiKeyValidator == nil {
		validator, err := apikey.NewValidator(config.APIKey, apikey.WithValidatorLogger(a.logger))
		if err != nil {
			return nil, err
		}
		a.apiKeyValidator = validator
	}

	return a, nil
}

// Authenticate authenticates a gRPC request.
func (a *grpcAuthenticator) Authenticate(ctx context.Context) (*Identity, error) {
	start := time.Now()

	var identity *Identity
	var authErr error

	// Try JWT authentication
	if a.config.IsJWTEnabled() {
		identity, authErr = a.authenticateJWT(ctx)
		if authErr == nil {
			a.metrics.RecordRequest("grpc", string(AuthTypeJWT), "success", time.Since(start))
			a.metrics.RecordSuccess(string(AuthTypeJWT))
			return identity, nil
		}
		if !errors.Is(authErr, ErrNoCredentials) {
			a.logger.Debug("JWT authentication failed", observability.Error(authErr))
		}
	}

	// Try API key authentication
	if a.config.IsAPIKeyEnabled() {
		identity, authErr = a.authenticateAPIKey(ctx)
		if authErr == nil {
			a.metrics.RecordRequest("grpc", string(AuthTypeAPIKey), "success", time.Since(start))
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

	a.metrics.RecordRequest("grpc", "unknown", "failure", time.Since(start))
	a.metrics.RecordFailure("unknown", "no_valid_credentials")

	return nil, authErr
}

// authenticateJWT authenticates using JWT.
func (a *grpcAuthenticator) authenticateJWT(ctx context.Context) (*Identity, error) {
	creds, err := a.extractor.ExtractJWTFromGRPC(ctx)
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
func (a *grpcAuthenticator) authenticateAPIKey(ctx context.Context) (*Identity, error) {
	creds, err := a.extractor.ExtractAPIKeyFromGRPC(ctx)
	if err != nil {
		return nil, err
	}

	keyInfo, err := a.apiKeyValidator.Validate(ctx, creds.Value)
	if err != nil {
		return nil, WrapAuthError(err, string(AuthTypeAPIKey))
	}

	return a.keyInfoToIdentity(keyInfo), nil
}

// claimsToIdentity converts JWT claims to an identity.
func (a *grpcAuthenticator) claimsToIdentity(claims *jwt.Claims, authType AuthType) *Identity {
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
func (a *grpcAuthenticator) keyInfoToIdentity(keyInfo *apikey.KeyInfo) *Identity {
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

// UnaryInterceptor returns a unary server interceptor for authentication.
func (a *grpcAuthenticator) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (interface{}, error) {
		identity, err := a.Authenticate(ctx)
		if err != nil {
			return nil, a.toGRPCError(err)
		}

		// Add identity to context
		ctx = ContextWithIdentity(ctx, identity)
		return handler(ctx, req)
	}
}

// StreamInterceptor returns a stream server interceptor for authentication.
func (a *grpcAuthenticator) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		identity, err := a.Authenticate(ctx)
		if err != nil {
			return a.toGRPCError(err)
		}

		// Wrap the stream with the authenticated context
		wrapped := &authenticatedServerStream{
			ServerStream: ss,
			ctx:          ContextWithIdentity(ctx, identity),
		}

		return handler(srv, wrapped)
	}
}

// toGRPCError converts an authentication error to a gRPC error.
func (a *grpcAuthenticator) toGRPCError(err error) error {
	switch {
	case errors.Is(err, ErrNoCredentials):
		return status.Error(codes.Unauthenticated, "authentication required")
	case errors.Is(err, ErrTokenExpired):
		return status.Error(codes.Unauthenticated, "token expired")
	case errors.Is(err, ErrInvalidToken), errors.Is(err, ErrInvalidSignature):
		return status.Error(codes.Unauthenticated, "invalid token")
	case errors.Is(err, ErrInvalidAPIKey):
		return status.Error(codes.Unauthenticated, "invalid API key")
	default:
		return status.Error(codes.Unauthenticated, "authentication failed")
	}
}

// authenticatedServerStream wraps a grpc.ServerStream with an authenticated context.
type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the authenticated context.
func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}

// Ensure grpcAuthenticator implements GRPCAuthenticator.
var _ GRPCAuthenticator = (*grpcAuthenticator)(nil)
