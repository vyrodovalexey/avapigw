package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/ratelimit"
	"go.uber.org/zap"
)

func TestNewRateLimitCore(t *testing.T) {
	t.Parallel()

	t.Run("creates with default limiter when nil", func(t *testing.T) {
		core := NewRateLimitCore(RateLimitCoreConfig{})

		assert.NotNil(t, core)
		assert.NotNil(t, core.limiter)
	})

	t.Run("creates with provided limiter", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 10, 10, nil)
		defer limiter.Close()

		core := NewRateLimitCore(RateLimitCoreConfig{
			Limiter: limiter,
		})

		assert.NotNil(t, core)
		assert.Equal(t, limiter, core.limiter)
	})

	t.Run("initializes skip paths", func(t *testing.T) {
		core := NewRateLimitCore(RateLimitCoreConfig{
			BaseConfig: BaseConfig{
				SkipPaths: []string{"/health", "/ready"},
			},
		})

		assert.True(t, core.ShouldSkip("/health"))
		assert.True(t, core.ShouldSkip("/ready"))
		assert.False(t, core.ShouldSkip("/api/v1/users"))
	})
}

func TestRateLimitCore_Check(t *testing.T) {
	t.Parallel()

	t.Run("allows requests within limit", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 10, 10, nil)
		defer limiter.Close()

		core := NewRateLimitCore(RateLimitCoreConfig{
			Limiter: limiter,
		})

		ctx := context.Background()
		result, err := core.Check(ctx, "test-key")

		assert.NoError(t, err)
		assert.True(t, result.Allowed)
		assert.Equal(t, 10, result.Limit)
	})

	t.Run("denies requests over limit", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 1, 1, nil)
		defer limiter.Close()

		core := NewRateLimitCore(RateLimitCoreConfig{
			Limiter: limiter,
		})

		ctx := context.Background()

		// First request should be allowed
		result, err := core.Check(ctx, "test-key")
		assert.NoError(t, err)
		assert.True(t, result.Allowed)

		// Second request should be denied
		result, err = core.Check(ctx, "test-key")
		assert.NoError(t, err)
		assert.False(t, result.Allowed)
	})

	t.Run("applies key function", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 10, 10, nil)
		defer limiter.Close()

		core := NewRateLimitCore(RateLimitCoreConfig{
			Limiter: limiter,
			KeyFunc: func(identifier string) string {
				return "prefix:" + identifier
			},
		})

		ctx := context.Background()
		result, err := core.Check(ctx, "test-key")

		assert.NoError(t, err)
		assert.True(t, result.Allowed)
	})
}

func TestRateLimitCore_ShouldSkip(t *testing.T) {
	t.Parallel()

	t.Run("returns false when no skip paths", func(t *testing.T) {
		core := NewRateLimitCore(RateLimitCoreConfig{})

		assert.False(t, core.ShouldSkip("/any/path"))
	})

	t.Run("returns true for skip paths", func(t *testing.T) {
		core := NewRateLimitCore(RateLimitCoreConfig{
			BaseConfig: BaseConfig{
				SkipPaths: []string{"/health", "/ready"},
			},
		})

		assert.True(t, core.ShouldSkip("/health"))
		assert.True(t, core.ShouldSkip("/ready"))
		assert.False(t, core.ShouldSkip("/api"))
	})
}

func TestRateLimitCore_IncludeHeaders(t *testing.T) {
	t.Parallel()

	t.Run("returns configured value", func(t *testing.T) {
		core := NewRateLimitCore(RateLimitCoreConfig{
			IncludeHeaders: true,
		})
		assert.True(t, core.IncludeHeaders())

		core = NewRateLimitCore(RateLimitCoreConfig{
			IncludeHeaders: false,
		})
		assert.False(t, core.IncludeHeaders())
	})
}

func TestLimiterAdapter(t *testing.T) {
	t.Parallel()

	t.Run("adapts limiter interface", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 10, 10, nil)
		defer limiter.Close()

		adapter := NewLimiterAdapter(limiter)

		ctx := context.Background()
		allowed, err := adapter.Allow(ctx, "test-key")

		assert.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("handles nil limiter", func(t *testing.T) {
		adapter := NewLimiterAdapter(nil)

		ctx := context.Background()
		allowed, err := adapter.Allow(ctx, "test-key")

		assert.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("returns underlying limiter", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 10, 10, nil)
		defer limiter.Close()

		adapter := NewLimiterAdapter(limiter)

		assert.Equal(t, limiter, adapter.Limiter())
	})
}

func TestRateLimitResult(t *testing.T) {
	t.Parallel()

	result := &RateLimitResult{
		Allowed:    true,
		Limit:      100,
		Remaining:  99,
		ResetAfter: time.Minute,
		RetryAfter: 0,
	}

	assert.True(t, result.Allowed)
	assert.Equal(t, 100, result.Limit)
	assert.Equal(t, 99, result.Remaining)
	assert.Equal(t, time.Minute, result.ResetAfter)
	assert.Equal(t, time.Duration(0), result.RetryAfter)
}

func TestRateLimitCore_LogExceeded(t *testing.T) {
	t.Parallel()

	// Just ensure it doesn't panic
	core := NewRateLimitCore(RateLimitCoreConfig{
		BaseConfig: BaseConfig{
			Logger: zap.NewNop(),
		},
	})

	core.LogExceeded("test-key", 100)
}
