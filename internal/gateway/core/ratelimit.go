package core

import (
	"context"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/ratelimit"
	"go.uber.org/zap"
)

// RateLimitResult represents the result of a rate limit check.
type RateLimitResult struct {
	// Allowed indicates whether the request is allowed.
	Allowed bool

	// Limit is the maximum number of requests allowed.
	Limit int

	// Remaining is the number of requests remaining in the current window.
	Remaining int

	// ResetAfter is the duration until the rate limit resets.
	ResetAfter time.Duration

	// RetryAfter is the duration to wait before retrying (when not allowed).
	RetryAfter time.Duration
}

// RateLimitCore provides protocol-agnostic rate limiting functionality.
type RateLimitCore struct {
	limiter        ratelimit.Limiter
	logger         *zap.Logger
	skipPaths      map[string]bool
	keyFunc        func(identifier string) string
	includeHeaders bool
}

// NewRateLimitCore creates a new RateLimitCore with the given configuration.
func NewRateLimitCore(config RateLimitCoreConfig) *RateLimitCore {
	config.InitSkipPaths()

	limiter := config.Limiter
	if limiter == nil {
		limiter = ratelimit.NewNoopLimiter()
	}

	return &RateLimitCore{
		limiter:        limiter,
		logger:         config.GetLogger(),
		skipPaths:      config.skipPathMap,
		keyFunc:        config.KeyFunc,
		includeHeaders: config.IncludeHeaders,
	}
}

// Check performs a rate limit check for the given key.
// Returns the result of the check and any error that occurred.
func (c *RateLimitCore) Check(ctx context.Context, key string) (*RateLimitResult, error) {
	// Apply key function if provided
	if c.keyFunc != nil {
		key = c.keyFunc(key)
	}

	// Check rate limit using the internal limiter
	result, err := c.limiter.Allow(ctx, key)
	if err != nil {
		c.logger.Error("rate limit check failed",
			zap.String("key", key),
			zap.Error(err),
		)
		// Return allowed on error to avoid blocking
		return &RateLimitResult{
			Allowed: true,
		}, err
	}

	return &RateLimitResult{
		Allowed:    result.Allowed,
		Limit:      result.Limit,
		Remaining:  result.Remaining,
		ResetAfter: result.ResetAfter,
		RetryAfter: result.RetryAfter,
	}, nil
}

// ShouldSkip checks if the given identifier should skip rate limiting.
func (c *RateLimitCore) ShouldSkip(identifier string) bool {
	if c.skipPaths == nil {
		return false
	}
	return c.skipPaths[identifier]
}

// IncludeHeaders returns whether rate limit headers should be included.
func (c *RateLimitCore) IncludeHeaders() bool {
	return c.includeHeaders
}

// LogExceeded logs a rate limit exceeded event.
func (c *RateLimitCore) LogExceeded(key string, limit int) {
	c.logger.Debug("rate limit exceeded",
		zap.String("key", key),
		zap.Int("limit", limit),
	)
}

// Limiter returns the underlying rate limiter.
func (c *RateLimitCore) Limiter() ratelimit.Limiter {
	return c.limiter
}

// LimiterAdapter adapts the internal ratelimit.Limiter to the gRPC interceptor's
// RateLimiter interface. This allows the gRPC interceptor to use the same
// rate limiter implementation as the HTTP middleware.
type LimiterAdapter struct {
	limiter ratelimit.Limiter
}

// NewLimiterAdapter creates a new LimiterAdapter wrapping the given limiter.
func NewLimiterAdapter(limiter ratelimit.Limiter) *LimiterAdapter {
	if limiter == nil {
		limiter = ratelimit.NewNoopLimiter()
	}
	return &LimiterAdapter{limiter: limiter}
}

// Allow checks if the request is allowed based on the key.
// This implements the gRPC interceptor's RateLimiter interface.
func (a *LimiterAdapter) Allow(ctx context.Context, key string) (bool, error) {
	result, err := a.limiter.Allow(ctx, key)
	if err != nil {
		return true, err // Allow on error
	}
	return result.Allowed, nil
}

// Limiter returns the underlying rate limiter.
func (a *LimiterAdapter) Limiter() ratelimit.Limiter {
	return a.limiter
}
