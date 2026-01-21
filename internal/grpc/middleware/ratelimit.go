package middleware

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// GRPCRateLimiter provides rate limiting for gRPC requests.
type GRPCRateLimiter struct {
	limiter   *rate.Limiter
	perClient bool
	clients   map[string]*rate.Limiter
	mu        sync.RWMutex
	rps       int
	burst     int
	logger    observability.Logger
}

// RateLimiterOption is a functional option for configuring the rate limiter.
type RateLimiterOption func(*GRPCRateLimiter)

// WithRateLimiterLogger sets the logger for the rate limiter.
func WithRateLimiterLogger(logger observability.Logger) RateLimiterOption {
	return func(rl *GRPCRateLimiter) {
		rl.logger = logger
	}
}

// NewGRPCRateLimiter creates a new gRPC rate limiter.
func NewGRPCRateLimiter(rps, burst int, perClient bool, opts ...RateLimiterOption) *GRPCRateLimiter {
	rl := &GRPCRateLimiter{
		limiter:   rate.NewLimiter(rate.Limit(rps), burst),
		perClient: perClient,
		clients:   make(map[string]*rate.Limiter),
		rps:       rps,
		burst:     burst,
		logger:    observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(rl)
	}

	return rl
}

// Allow checks if a request is allowed.
func (rl *GRPCRateLimiter) Allow(clientAddr string) bool {
	if rl.perClient {
		return rl.allowPerClient(clientAddr)
	}
	return rl.limiter.Allow()
}

// allowPerClient checks rate limit per client.
func (rl *GRPCRateLimiter) allowPerClient(clientAddr string) bool {
	rl.mu.RLock()
	limiter, exists := rl.clients[clientAddr]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		limiter, exists = rl.clients[clientAddr]
		if !exists {
			limiter = rate.NewLimiter(rate.Limit(rl.rps), rl.burst)
			rl.clients[clientAddr] = limiter
		}
		rl.mu.Unlock()
	}

	return limiter.Allow()
}

// CleanupOldClients removes old client limiters to prevent memory leaks.
func (rl *GRPCRateLimiter) CleanupOldClients() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Simple cleanup: clear all clients if too many
	if len(rl.clients) > 10000 {
		rl.clients = make(map[string]*rate.Limiter)
	}
}

// UnaryRateLimitInterceptor returns a unary server interceptor that applies rate limiting.
func UnaryRateLimitInterceptor(limiter *GRPCRateLimiter) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		clientAddr := getClientAddrFromContext(ctx)

		if !limiter.Allow(clientAddr) {
			limiter.logger.Warn("rate limit exceeded",
				observability.String("client_addr", clientAddr),
				observability.String("method", info.FullMethod),
			)
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

// StreamRateLimitInterceptor returns a stream server interceptor that applies rate limiting.
func StreamRateLimitInterceptor(limiter *GRPCRateLimiter) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := stream.Context()
		clientAddr := getClientAddrFromContext(ctx)

		if !limiter.Allow(clientAddr) {
			limiter.logger.Warn("rate limit exceeded",
				observability.String("client_addr", clientAddr),
				observability.String("method", info.FullMethod),
			)
			return status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(srv, stream)
	}
}

// getClientAddrFromContext extracts the client address from context.
func getClientAddrFromContext(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return "unknown"
}
