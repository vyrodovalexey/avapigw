// Package ratelimit provides rate limiting functionality for the API Gateway.
// It supports multiple algorithms including token bucket, sliding window, and fixed window.
package ratelimit

import (
	"context"
	"time"
)

// Limiter defines the interface for rate limiting.
type Limiter interface {
	// Allow checks if a single request is allowed for the given key.
	Allow(ctx context.Context, key string) (*Result, error)

	// AllowN checks if n requests are allowed for the given key.
	AllowN(ctx context.Context, key string, n int) (*Result, error)

	// GetLimit returns the limit configuration for the given key.
	GetLimit(key string) *Limit

	// Reset resets the rate limit state for the given key.
	Reset(ctx context.Context, key string) error
}

// Limit represents rate limit configuration.
type Limit struct {
	// Requests is the maximum number of requests allowed in the window.
	Requests int

	// Window is the time window for the rate limit.
	Window time.Duration

	// Burst is the maximum burst size (for token bucket algorithm).
	Burst int
}

// Result represents the result of a rate limit check.
type Result struct {
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

// Algorithm represents the rate limiting algorithm type.
type Algorithm string

const (
	// AlgorithmTokenBucket uses the token bucket algorithm.
	AlgorithmTokenBucket Algorithm = "token_bucket"

	// AlgorithmSlidingWindow uses the sliding window algorithm.
	AlgorithmSlidingWindow Algorithm = "sliding_window"

	// AlgorithmFixedWindow uses the fixed window algorithm.
	AlgorithmFixedWindow Algorithm = "fixed_window"
)

// Config holds configuration for creating a rate limiter.
type Config struct {
	// Algorithm is the rate limiting algorithm to use.
	Algorithm Algorithm

	// Requests is the maximum number of requests allowed in the window.
	Requests int

	// Window is the time window for the rate limit.
	Window time.Duration

	// Burst is the maximum burst size (for token bucket algorithm).
	Burst int

	// Precision is the number of sub-windows (for sliding window algorithm).
	Precision int
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		Algorithm: AlgorithmTokenBucket,
		Requests:  100,
		Window:    time.Minute,
		Burst:     10,
		Precision: 10,
	}
}

// NoopLimiter is a rate limiter that always allows requests.
type NoopLimiter struct{}

// NewNoopLimiter creates a new noop limiter.
func NewNoopLimiter() *NoopLimiter {
	return &NoopLimiter{}
}

// Allow implements Limiter.
func (l *NoopLimiter) Allow(ctx context.Context, key string) (*Result, error) {
	return &Result{
		Allowed:    true,
		Limit:      0,
		Remaining:  0,
		ResetAfter: 0,
		RetryAfter: 0,
	}, nil
}

// AllowN implements Limiter.
func (l *NoopLimiter) AllowN(ctx context.Context, key string, n int) (*Result, error) {
	return l.Allow(ctx, key)
}

// GetLimit implements Limiter.
func (l *NoopLimiter) GetLimit(key string) *Limit {
	return nil
}

// Reset implements Limiter.
func (l *NoopLimiter) Reset(ctx context.Context, key string) error {
	return nil
}
