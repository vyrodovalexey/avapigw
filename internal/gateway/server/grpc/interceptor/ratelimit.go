package interceptor

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// RateLimiter defines the interface for rate limiting.
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

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
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

// TokenBucketLimiter implements a simple token bucket rate limiter.
type TokenBucketLimiter struct {
	rate       float64
	burst      int
	buckets    map[string]*bucket
	mu         sync.Mutex
	cleanupInt time.Duration
}

type bucket struct {
	tokens     float64
	lastUpdate time.Time
}

// NewTokenBucketLimiter creates a new token bucket rate limiter.
func NewTokenBucketLimiter(rate float64, burst int) *TokenBucketLimiter {
	limiter := &TokenBucketLimiter{
		rate:       rate,
		burst:      burst,
		buckets:    make(map[string]*bucket),
		cleanupInt: 5 * time.Minute,
	}

	// Start cleanup goroutine
	go limiter.cleanup()

	return limiter
}

// Allow implements RateLimiter.
func (l *TokenBucketLimiter) Allow(ctx context.Context, key string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	b, exists := l.buckets[key]
	if !exists {
		b = &bucket{
			tokens:     float64(l.burst),
			lastUpdate: now,
		}
		l.buckets[key] = b
	}

	// Add tokens based on elapsed time
	elapsed := now.Sub(b.lastUpdate).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastUpdate = now

	// Check if we have tokens
	if b.tokens >= 1 {
		b.tokens--
		return true, nil
	}

	return false, nil
}

// cleanup removes stale buckets.
func (l *TokenBucketLimiter) cleanup() {
	ticker := time.NewTicker(l.cleanupInt)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for key, b := range l.buckets {
			if now.Sub(b.lastUpdate) > l.cleanupInt {
				delete(l.buckets, key)
			}
		}
		l.mu.Unlock()
	}
}

// SlidingWindowLimiter implements a sliding window rate limiter.
type SlidingWindowLimiter struct {
	limit      int
	window     time.Duration
	requests   map[string][]time.Time
	mu         sync.Mutex
	cleanupInt time.Duration
}

// NewSlidingWindowLimiter creates a new sliding window rate limiter.
func NewSlidingWindowLimiter(limit int, window time.Duration) *SlidingWindowLimiter {
	limiter := &SlidingWindowLimiter{
		limit:      limit,
		window:     window,
		requests:   make(map[string][]time.Time),
		cleanupInt: window * 2,
	}

	// Start cleanup goroutine
	go limiter.cleanup()

	return limiter
}

// Allow implements RateLimiter.
func (l *SlidingWindowLimiter) Allow(ctx context.Context, key string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-l.window)

	// Get or create request list
	requests, exists := l.requests[key]
	if !exists {
		requests = make([]time.Time, 0)
	}

	// Remove old requests
	validRequests := make([]time.Time, 0, len(requests))
	for _, t := range requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	// Check limit
	if len(validRequests) >= l.limit {
		l.requests[key] = validRequests
		return false, nil
	}

	// Add new request
	validRequests = append(validRequests, now)
	l.requests[key] = validRequests

	return true, nil
}

// cleanup removes stale entries.
func (l *SlidingWindowLimiter) cleanup() {
	ticker := time.NewTicker(l.cleanupInt)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		windowStart := now.Add(-l.window)

		for key, requests := range l.requests {
			validRequests := make([]time.Time, 0, len(requests))
			for _, t := range requests {
				if t.After(windowStart) {
					validRequests = append(validRequests, t)
				}
			}
			if len(validRequests) == 0 {
				delete(l.requests, key)
			} else {
				l.requests[key] = validRequests
			}
		}
		l.mu.Unlock()
	}
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
