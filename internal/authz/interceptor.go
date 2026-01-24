package authz

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// GRPCAuthorizer handles authorization for gRPC requests.
type GRPCAuthorizer interface {
	// Authorize authorizes a gRPC request.
	Authorize(ctx context.Context, fullMethod string) (*Decision, error)

	// UnaryInterceptor returns a unary server interceptor for authorization.
	UnaryInterceptor() grpc.UnaryServerInterceptor

	// StreamInterceptor returns a stream server interceptor for authorization.
	StreamInterceptor() grpc.StreamServerInterceptor
}

// grpcAuthorizer implements the GRPCAuthorizer interface.
type grpcAuthorizer struct {
	authorizer Authorizer
	config     *Config
	logger     observability.Logger
	metrics    *Metrics
}

// GRPCAuthorizerOption is a functional option for the gRPC authorizer.
type GRPCAuthorizerOption func(*grpcAuthorizer)

// WithGRPCAuthorizerLogger sets the logger.
func WithGRPCAuthorizerLogger(logger observability.Logger) GRPCAuthorizerOption {
	return func(a *grpcAuthorizer) {
		a.logger = logger
	}
}

// WithGRPCAuthorizerMetrics sets the metrics.
func WithGRPCAuthorizerMetrics(metrics *Metrics) GRPCAuthorizerOption {
	return func(a *grpcAuthorizer) {
		a.metrics = metrics
	}
}

// NewGRPCAuthorizer creates a new gRPC authorizer.
func NewGRPCAuthorizer(authorizer Authorizer, config *Config, opts ...GRPCAuthorizerOption) GRPCAuthorizer {
	a := &grpcAuthorizer{
		authorizer: authorizer,
		config:     config,
		logger:     observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(a)
	}

	if a.metrics == nil {
		a.metrics = NewMetrics("gateway")
	}

	return a
}

// Authorize authorizes a gRPC request.
func (a *grpcAuthorizer) Authorize(ctx context.Context, fullMethod string) (*Decision, error) {
	// Get identity from context
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		return nil, ErrNoIdentity
	}

	// Extract service and method from full method name
	service, method := parseFullMethod(fullMethod)

	// Build authorization request
	req := &Request{
		Identity: identity,
		Resource: fullMethod,
		Action:   method,
		Context:  a.buildRequestContext(ctx, service, method),
	}

	return a.authorizer.Authorize(ctx, req)
}

// buildRequestContext builds the request context for authorization.
func (a *grpcAuthorizer) buildRequestContext(ctx context.Context, service, method string) map[string]interface{} {
	reqCtx := make(map[string]interface{})

	// Add service and method
	reqCtx["service"] = service
	reqCtx["method"] = method

	// Add metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		headers := make(map[string]string)
		for key, values := range md {
			if !isSensitiveMetadata(key) && len(values) > 0 {
				headers[key] = values[0]
			}
		}
		reqCtx["metadata"] = headers
	}

	// Add peer information
	if p, ok := peer.FromContext(ctx); ok {
		reqCtx["peer_addr"] = p.Addr.String()
	}

	return reqCtx
}

// UnaryInterceptor returns a unary server interceptor for authorization.
func (a *grpcAuthorizer) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		decision, err := a.Authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, a.toGRPCError(err)
		}

		if !decision.Allowed {
			a.logger.Warn("access denied",
				observability.String("method", info.FullMethod),
				observability.String("reason", decision.Reason),
				observability.String("policy", decision.Policy),
			)
			return nil, status.Error(codes.PermissionDenied, "access denied: "+decision.Reason)
		}

		return handler(ctx, req)
	}
}

// StreamInterceptor returns a stream server interceptor for authorization.
func (a *grpcAuthorizer) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		decision, err := a.Authorize(ctx, info.FullMethod)
		if err != nil {
			return a.toGRPCError(err)
		}

		if !decision.Allowed {
			a.logger.Warn("access denied",
				observability.String("method", info.FullMethod),
				observability.String("reason", decision.Reason),
				observability.String("policy", decision.Policy),
			)
			return status.Error(codes.PermissionDenied, "access denied: "+decision.Reason)
		}

		return handler(srv, ss)
	}
}

// toGRPCError converts an authorization error to a gRPC error.
func (a *grpcAuthorizer) toGRPCError(err error) error {
	switch {
	case errors.Is(err, ErrNoIdentity):
		return status.Error(codes.Unauthenticated, "authentication required")
	case errors.Is(err, ErrAccessDenied):
		return status.Error(codes.PermissionDenied, "access denied")
	case errors.Is(err, ErrExternalAuthzTimeout):
		return status.Error(codes.DeadlineExceeded, "authorization timeout")
	case errors.Is(err, ErrExternalAuthzUnavailable):
		return status.Error(codes.Unavailable, "authorization service unavailable")
	default:
		return status.Error(codes.Internal, "authorization error")
	}
}

// parseFullMethod parses a gRPC full method name into service and method.
func parseFullMethod(fullMethod string) (service, method string) {
	// Full method format: /package.Service/Method
	if fullMethod == "" || fullMethod[0] != '/' {
		return "", fullMethod
	}

	// Find the last slash (excluding the leading slash)
	lastSlash := -1
	for i := len(fullMethod) - 1; i > 0; i-- {
		if fullMethod[i] == '/' {
			lastSlash = i
			break
		}
	}

	// If no second slash found, return empty service and the full method
	if lastSlash <= 0 {
		return "", fullMethod
	}

	return fullMethod[1:lastSlash], fullMethod[lastSlash+1:]
}

// isSensitiveMetadata checks if a metadata key is sensitive.
func isSensitiveMetadata(key string) bool {
	sensitiveKeys := map[string]bool{
		"authorization": true,
		"x-api-key":     true,
		"x-auth-token":  true,
		"cookie":        true,
	}
	return sensitiveKeys[key]
}

// Ensure grpcAuthorizer implements GRPCAuthorizer.
var _ GRPCAuthorizer = (*grpcAuthorizer)(nil)
