package interceptor

import (
	"context"

	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"github.com/vyrodovalexey/avapigw/internal/ratelimit"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// RateLimiter defines the interface for rate limiting.
// This interface is compatible with core.LimiterAdapter.
type RateLimiter interface {
	// Allow checks if the request is allowed based on the key.
	Allow(ctx context.Context, key string) (bool, error)
}

// RateLimitConfig holds configuration for the rate limit interceptor.
type RateLimitConfig struct {
	Limiter     RateLimiter
	Logger      *zap.Logger
	KeyFunc     func(ctx context.Context, method string, md metadata.MD) string
	SkipMethods []string
}

// UnaryRateLimitInterceptor returns a unary interceptor that applies rate limiting.
func UnaryRateLimitInterceptor(limiter RateLimiter) grpc.UnaryServerInterceptor {
	return UnaryRateLimitInterceptorWithConfig(RateLimitConfig{Limiter: limiter})
}

// UnaryRateLimitInterceptorWithConfig returns a unary rate limit interceptor with custom configuration.
func UnaryRateLimitInterceptorWithConfig(config RateLimitConfig) grpc.UnaryServerInterceptor {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	if config.KeyFunc == nil {
		config.KeyFunc = defaultKeyFunc
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
		// Skip rate limiting for certain methods
		if skipMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Skip if no limiter configured
		if config.Limiter == nil {
			return handler(ctx, req)
		}

		// Get metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}

		// Get rate limit key
		key := config.KeyFunc(ctx, info.FullMethod, md)

		// Check rate limit
		allowed, err := config.Limiter.Allow(ctx, key)
		if err != nil {
			config.Logger.Error("rate limit check failed",
				zap.String("method", info.FullMethod),
				zap.String("key", key),
				zap.Error(err),
			)
			// Allow request on error to avoid blocking
			return handler(ctx, req)
		}

		if !allowed {
			config.Logger.Debug("rate limit exceeded",
				zap.String("method", info.FullMethod),
				zap.String("key", key),
			)
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

// StreamRateLimitInterceptor returns a stream interceptor that applies rate limiting.
func StreamRateLimitInterceptor(limiter RateLimiter) grpc.StreamServerInterceptor {
	return StreamRateLimitInterceptorWithConfig(RateLimitConfig{Limiter: limiter})
}

// StreamRateLimitInterceptorWithConfig returns a stream rate limit interceptor with custom configuration.
func StreamRateLimitInterceptorWithConfig(config RateLimitConfig) grpc.StreamServerInterceptor {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	if config.KeyFunc == nil {
		config.KeyFunc = defaultKeyFunc
	}

	skipMethods := make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip rate limiting for certain methods
		if skipMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Skip if no limiter configured
		if config.Limiter == nil {
			return handler(srv, ss)
		}

		ctx := ss.Context()

		// Get metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}

		// Get rate limit key
		key := config.KeyFunc(ctx, info.FullMethod, md)

		// Check rate limit
		allowed, err := config.Limiter.Allow(ctx, key)
		if err != nil {
			config.Logger.Error("rate limit check failed",
				zap.String("method", info.FullMethod),
				zap.String("key", key),
				zap.Error(err),
			)
			// Allow request on error to avoid blocking
			return handler(srv, ss)
		}

		if !allowed {
			config.Logger.Debug("rate limit exceeded",
				zap.String("method", info.FullMethod),
				zap.String("key", key),
			)
			return status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(srv, ss)
	}
}

// defaultKeyFunc returns the default rate limit key based on peer IP.
func defaultKeyFunc(ctx context.Context, method string, md metadata.MD) string {
	// Try to get client IP from metadata
	if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
		return ips[0]
	}
	if ips := md.Get("x-real-ip"); len(ips) > 0 {
		return ips[0]
	}

	// Fall back to peer address
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}

	return "unknown"
}

// UnaryRateLimitInterceptorWithCore returns a unary interceptor using the core rate limiter.
func UnaryRateLimitInterceptorWithCore(coreConfig core.RateLimitCoreConfig) grpc.UnaryServerInterceptor {
	rateLimitCore := core.NewRateLimitCore(coreConfig)

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip rate limiting for certain methods
		if rateLimitCore.ShouldSkip(info.FullMethod) {
			return handler(ctx, req)
		}

		// Get metadata for key extraction
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}

		// Get rate limit key
		key := defaultKeyFunc(ctx, info.FullMethod, md)

		// Check rate limit using core
		result, err := rateLimitCore.Check(ctx, key)
		if err != nil {
			// Allow request on error to avoid blocking
			return handler(ctx, req)
		}

		if !result.Allowed {
			rateLimitCore.LogExceeded(key, result.Limit)
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

// StreamRateLimitInterceptorWithCore returns a stream interceptor using the core rate limiter.
func StreamRateLimitInterceptorWithCore(coreConfig core.RateLimitCoreConfig) grpc.StreamServerInterceptor {
	rateLimitCore := core.NewRateLimitCore(coreConfig)

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip rate limiting for certain methods
		if rateLimitCore.ShouldSkip(info.FullMethod) {
			return handler(srv, ss)
		}

		ctx := ss.Context()

		// Get metadata for key extraction
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}

		// Get rate limit key
		key := defaultKeyFunc(ctx, info.FullMethod, md)

		// Check rate limit using core
		result, err := rateLimitCore.Check(ctx, key)
		if err != nil {
			// Allow request on error to avoid blocking
			return handler(srv, ss)
		}

		if !result.Allowed {
			rateLimitCore.LogExceeded(key, result.Limit)
			return status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(srv, ss)
	}
}

// NewLimiterFromRatelimit creates a RateLimiter from the internal ratelimit.Limiter.
// This is the recommended way to create a rate limiter for gRPC interceptors.
func NewLimiterFromRatelimit(limiter ratelimit.Limiter) RateLimiter {
	return core.NewLimiterAdapter(limiter)
}

// MethodRateLimiter applies different rate limits based on method.
type MethodRateLimiter struct {
	// Limiters maps method patterns to rate limiters.
	Limiters map[string]RateLimiter
	// DefaultLimiter is used when no pattern matches.
	DefaultLimiter RateLimiter
}

// Allow implements RateLimiter.
func (l *MethodRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	// The key should include the method for method-based limiting
	// This is a simplified implementation
	if l.DefaultLimiter != nil {
		return l.DefaultLimiter.Allow(ctx, key)
	}
	return true, nil
}

// NoopLimiter is a rate limiter that always allows requests.
type NoopLimiter struct{}

// Allow implements RateLimiter.
func (l *NoopLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return true, nil
}
