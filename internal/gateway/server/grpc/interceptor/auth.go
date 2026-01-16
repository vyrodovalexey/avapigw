package interceptor

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthValidator defines the interface for authentication validation.
type AuthValidator interface {
	// Validate validates the request and returns an error if authentication fails.
	Validate(ctx context.Context, method string, md metadata.MD) error
}

// AuthConfig holds configuration for the auth interceptor.
type AuthConfig struct {
	Validator   AuthValidator
	Logger      *zap.Logger
	SkipMethods []string
}

// UnaryAuthInterceptor returns a unary interceptor that validates authentication.
func UnaryAuthInterceptor(validator AuthValidator) grpc.UnaryServerInterceptor {
	return UnaryAuthInterceptorWithConfig(AuthConfig{Validator: validator})
}

// UnaryAuthInterceptorWithConfig returns a unary auth interceptor with custom configuration.
func UnaryAuthInterceptorWithConfig(config AuthConfig) grpc.UnaryServerInterceptor {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	skipMethods := make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip auth for certain methods
		if skipMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Skip if no validator configured
		if config.Validator == nil {
			return handler(ctx, req)
		}

		// Get metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}

		// Validate
		if err := config.Validator.Validate(ctx, info.FullMethod, md); err != nil {
			config.Logger.Debug("authentication failed",
				zap.String("method", info.FullMethod),
				zap.Error(err),
			)
			return nil, err
		}

		return handler(ctx, req)
	}
}

// StreamAuthInterceptor returns a stream interceptor that validates authentication.
func StreamAuthInterceptor(validator AuthValidator) grpc.StreamServerInterceptor {
	return StreamAuthInterceptorWithConfig(AuthConfig{Validator: validator})
}

// StreamAuthInterceptorWithConfig returns a stream auth interceptor with custom configuration.
func StreamAuthInterceptorWithConfig(config AuthConfig) grpc.StreamServerInterceptor {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	skipMethods := make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip auth for certain methods
		if skipMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Skip if no validator configured
		if config.Validator == nil {
			return handler(srv, ss)
		}

		ctx := ss.Context()

		// Get metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}

		// Validate
		if err := config.Validator.Validate(ctx, info.FullMethod, md); err != nil {
			config.Logger.Debug("authentication failed",
				zap.String("method", info.FullMethod),
				zap.Error(err),
			)
			return err
		}

		return handler(srv, ss)
	}
}

// UnaryAuthInterceptorWithCore returns a unary interceptor using the core auth.
func UnaryAuthInterceptorWithCore(authCore *core.AuthCore) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip auth for certain methods
		if authCore.ShouldSkip(info.FullMethod) {
			return handler(ctx, req)
		}

		// Check if anonymous access is allowed for this path
		if authCore.IsAnonymousPath(info.FullMethod) {
			return handler(ctx, req)
		}

		// Get metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}

		// Extract credentials from metadata
		credentials := extractCredentialsFromMetadata(md)

		// Authenticate
		result := authCore.Authenticate(ctx, credentials)

		// Check if authentication is required
		if authCore.RequireAuth() && !result.Authenticated {
			return nil, status.Error(codes.Unauthenticated, "authentication required")
		}

		return handler(ctx, req)
	}
}

// StreamAuthInterceptorWithCore returns a stream interceptor using the core auth.
func StreamAuthInterceptorWithCore(authCore *core.AuthCore) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip auth for certain methods
		if authCore.ShouldSkip(info.FullMethod) {
			return handler(srv, ss)
		}

		// Check if anonymous access is allowed for this path
		if authCore.IsAnonymousPath(info.FullMethod) {
			return handler(srv, ss)
		}

		ctx := ss.Context()

		// Get metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}

		// Extract credentials from metadata
		credentials := extractCredentialsFromMetadata(md)

		// Authenticate
		result := authCore.Authenticate(ctx, credentials)

		// Check if authentication is required
		if authCore.RequireAuth() && !result.Authenticated {
			return status.Error(codes.Unauthenticated, "authentication required")
		}

		return handler(srv, ss)
	}
}

// extractCredentialsFromMetadata extracts authentication credentials from gRPC metadata.
func extractCredentialsFromMetadata(md metadata.MD) core.AuthCredentials {
	credentials := core.AuthCredentials{}

	// Extract bearer token
	if authHeaders := md.Get("authorization"); len(authHeaders) > 0 {
		auth := authHeaders[0]
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			credentials.BearerToken = strings.TrimPrefix(auth, "Bearer ")
			credentials.BearerToken = strings.TrimPrefix(credentials.BearerToken, "bearer ")
		} else if strings.HasPrefix(strings.ToLower(auth), "basic ") {
			// Basic auth - decode and extract
			basicAuth := strings.TrimPrefix(auth, "Basic ")
			basicAuth = strings.TrimPrefix(basicAuth, "basic ")
			if username, password, ok := decodeBasicAuth(basicAuth); ok {
				credentials.BasicAuth = &core.BasicCredentials{
					Username: username,
					Password: password,
				}
			}
		}
	}

	// Extract API key
	if apiKeys := md.Get("x-api-key"); len(apiKeys) > 0 {
		credentials.APIKey = apiKeys[0]
	}

	return credentials
}

// decodeBasicAuth decodes a base64 encoded basic auth string.
func decodeBasicAuth(encoded string) (username, password string, ok bool) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}
	credentials := string(decoded)
	idx := strings.IndexByte(credentials, ':')
	if idx < 0 {
		return "", "", false
	}
	return credentials[:idx], credentials[idx+1:], true
}

// BearerTokenValidator validates bearer tokens.
type BearerTokenValidator struct {
	// ValidateFunc is the function to validate the token.
	ValidateFunc func(ctx context.Context, token string) error
}

// Validate implements AuthValidator.
func (v *BearerTokenValidator) Validate(ctx context.Context, method string, md metadata.MD) error {
	// Get authorization header
	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return status.Error(codes.Unauthenticated, "missing authorization header")
	}

	// Parse bearer token
	auth := authHeaders[0]
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return status.Error(codes.Unauthenticated, "invalid authorization header format")
	}

	token := strings.TrimPrefix(auth, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")

	// Validate token
	if v.ValidateFunc != nil {
		return v.ValidateFunc(ctx, token)
	}

	return nil
}

// APIKeyValidator validates API keys.
type APIKeyValidator struct {
	// HeaderName is the name of the header containing the API key.
	HeaderName string
	// ValidateFunc is the function to validate the API key.
	ValidateFunc func(ctx context.Context, apiKey string) error
}

// Validate implements AuthValidator.
func (v *APIKeyValidator) Validate(ctx context.Context, method string, md metadata.MD) error {
	headerName := v.HeaderName
	if headerName == "" {
		headerName = "x-api-key"
	}

	// Get API key header
	apiKeys := md.Get(headerName)
	if len(apiKeys) == 0 {
		return status.Errorf(codes.Unauthenticated, "missing %s header", headerName)
	}

	// Validate API key
	if v.ValidateFunc != nil {
		return v.ValidateFunc(ctx, apiKeys[0])
	}

	return nil
}

// CompositeValidator validates using multiple validators.
type CompositeValidator struct {
	Validators []AuthValidator
	Mode       CompositeMode
}

// CompositeMode defines how multiple validators are combined.
type CompositeMode int

const (
	// CompositeModeAll requires all validators to pass.
	CompositeModeAll CompositeMode = iota
	// CompositeModeAny requires at least one validator to pass.
	CompositeModeAny
)

// Validate implements AuthValidator.
func (v *CompositeValidator) Validate(ctx context.Context, method string, md metadata.MD) error {
	if len(v.Validators) == 0 {
		return nil
	}

	switch v.Mode {
	case CompositeModeAll:
		for _, validator := range v.Validators {
			if err := validator.Validate(ctx, method, md); err != nil {
				return err
			}
		}
		return nil

	case CompositeModeAny:
		var lastErr error
		for _, validator := range v.Validators {
			if err := validator.Validate(ctx, method, md); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		if lastErr != nil {
			return lastErr
		}
		return status.Error(codes.Unauthenticated, "authentication failed")

	default:
		return status.Error(codes.Internal, "invalid composite mode")
	}
}

// MethodAuthValidator validates based on method-specific rules.
type MethodAuthValidator struct {
	// Rules maps method patterns to validators.
	Rules map[string]AuthValidator
	// DefaultValidator is used when no rule matches.
	DefaultValidator AuthValidator
}

// Validate implements AuthValidator.
func (v *MethodAuthValidator) Validate(ctx context.Context, method string, md metadata.MD) error {
	// Check for exact match
	if validator, ok := v.Rules[method]; ok {
		return validator.Validate(ctx, method, md)
	}

	// Check for prefix match
	for pattern, validator := range v.Rules {
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(method, prefix) {
				return validator.Validate(ctx, method, md)
			}
		}
	}

	// Use default validator
	if v.DefaultValidator != nil {
		return v.DefaultValidator.Validate(ctx, method, md)
	}

	return nil
}

// NoopValidator is a validator that always passes.
type NoopValidator struct{}

// Validate implements AuthValidator.
func (v *NoopValidator) Validate(ctx context.Context, method string, md metadata.MD) error {
	return nil
}
