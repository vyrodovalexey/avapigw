// Package webhook provides admission webhooks for CRD validation and defaulting.
package webhook

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultWebhookRateLimiterConfig(t *testing.T) {
	config := DefaultWebhookRateLimiterConfig()

	assert.True(t, config.Enabled)
	assert.Equal(t, 100.0, config.Rate)
	assert.Equal(t, 200, config.Burst)
}

func TestNewWebhookRateLimiter(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		limiter := NewWebhookRateLimiter(nil)

		require.NotNil(t, limiter)
		assert.Equal(t, 100.0, limiter.rate)
		assert.Equal(t, 200, limiter.burst)
		assert.True(t, limiter.enabled)
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &WebhookRateLimiterConfig{
			Enabled: true,
			Rate:    50.0,
			Burst:   100,
		}
		limiter := NewWebhookRateLimiter(config)

		require.NotNil(t, limiter)
		assert.Equal(t, 50.0, limiter.rate)
		assert.Equal(t, 100, limiter.burst)
		assert.True(t, limiter.enabled)
	})

	t.Run("with disabled config", func(t *testing.T) {
		config := &WebhookRateLimiterConfig{
			Enabled: false,
			Rate:    50.0,
			Burst:   100,
		}
		limiter := NewWebhookRateLimiter(config)

		require.NotNil(t, limiter)
		assert.False(t, limiter.enabled)
	})
}

func TestWebhookRateLimiter_Allow(t *testing.T) {
	t.Run("allows when disabled", func(t *testing.T) {
		config := &WebhookRateLimiterConfig{
			Enabled: false,
			Rate:    1.0,
			Burst:   1,
		}
		limiter := NewWebhookRateLimiter(config)

		ctx := context.Background()
		// Should always allow when disabled
		for i := 0; i < 10; i++ {
			assert.True(t, limiter.Allow(ctx, "Gateway"))
		}
	})

	t.Run("allows within burst", func(t *testing.T) {
		config := &WebhookRateLimiterConfig{
			Enabled: true,
			Rate:    10.0,
			Burst:   5,
		}
		limiter := NewWebhookRateLimiter(config)

		ctx := context.Background()
		// Should allow up to burst limit
		for i := 0; i < 5; i++ {
			assert.True(t, limiter.Allow(ctx, "Gateway"))
		}
	})

	t.Run("denies when burst exceeded", func(t *testing.T) {
		config := &WebhookRateLimiterConfig{
			Enabled: true,
			Rate:    0.1, // Very slow refill
			Burst:   2,
		}
		limiter := NewWebhookRateLimiter(config)

		ctx := context.Background()
		// Use up all tokens
		assert.True(t, limiter.Allow(ctx, "Gateway"))
		assert.True(t, limiter.Allow(ctx, "Gateway"))
		// Should be denied now
		assert.False(t, limiter.Allow(ctx, "Gateway"))
	})

	t.Run("refills tokens over time", func(t *testing.T) {
		config := &WebhookRateLimiterConfig{
			Enabled: true,
			Rate:    100.0, // 100 tokens per second
			Burst:   10,
		}
		limiter := NewWebhookRateLimiter(config)

		ctx := context.Background()
		// Use up all tokens
		for i := 0; i < 10; i++ {
			limiter.Allow(ctx, "Gateway")
		}

		// Wait for refill
		time.Sleep(100 * time.Millisecond)

		// Should have some tokens now
		assert.True(t, limiter.Allow(ctx, "Gateway"))
	})
}

func TestWebhookRateLimiter_CheckRateLimit(t *testing.T) {
	t.Run("returns nil when allowed", func(t *testing.T) {
		config := &WebhookRateLimiterConfig{
			Enabled: true,
			Rate:    100.0,
			Burst:   10,
		}
		limiter := NewWebhookRateLimiter(config)

		ctx := context.Background()
		err := limiter.CheckRateLimit(ctx, "Gateway")
		assert.NoError(t, err)
	})

	t.Run("returns error when denied", func(t *testing.T) {
		config := &WebhookRateLimiterConfig{
			Enabled: true,
			Rate:    0.1,
			Burst:   1,
		}
		limiter := NewWebhookRateLimiter(config)

		ctx := context.Background()
		// Use up all tokens
		limiter.Allow(ctx, "Gateway")

		// Should return error
		err := limiter.CheckRateLimit(ctx, "Gateway")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "rate limit exceeded")
		assert.Contains(t, err.Error(), "Gateway")
	})
}

func TestWebhookRateLimiter_IsEnabled(t *testing.T) {
	t.Run("returns true when enabled", func(t *testing.T) {
		config := &WebhookRateLimiterConfig{
			Enabled: true,
			Rate:    100.0,
			Burst:   10,
		}
		limiter := NewWebhookRateLimiter(config)

		assert.True(t, limiter.IsEnabled())
	})

	t.Run("returns false when disabled", func(t *testing.T) {
		config := &WebhookRateLimiterConfig{
			Enabled: false,
			Rate:    100.0,
			Burst:   10,
		}
		limiter := NewWebhookRateLimiter(config)

		assert.False(t, limiter.IsEnabled())
	})
}

func TestWebhookRateLimiter_SetEnabled(t *testing.T) {
	config := &WebhookRateLimiterConfig{
		Enabled: true,
		Rate:    100.0,
		Burst:   10,
	}
	limiter := NewWebhookRateLimiter(config)

	assert.True(t, limiter.IsEnabled())

	limiter.SetEnabled(false)
	assert.False(t, limiter.IsEnabled())

	limiter.SetEnabled(true)
	assert.True(t, limiter.IsEnabled())
}

func TestWebhookRateLimiter_GetTokens(t *testing.T) {
	config := &WebhookRateLimiterConfig{
		Enabled: true,
		Rate:    100.0,
		Burst:   10,
	}
	limiter := NewWebhookRateLimiter(config)

	// Initially should have burst tokens
	tokens := limiter.GetTokens()
	assert.Equal(t, 10.0, tokens)

	// After using some tokens
	ctx := context.Background()
	limiter.Allow(ctx, "Gateway")
	limiter.Allow(ctx, "Gateway")

	tokens = limiter.GetTokens()
	assert.Less(t, tokens, 10.0)
}

func TestWebhookRateLimiter_Reset(t *testing.T) {
	config := &WebhookRateLimiterConfig{
		Enabled: true,
		Rate:    0.1, // Very slow refill
		Burst:   10,
	}
	limiter := NewWebhookRateLimiter(config)

	ctx := context.Background()
	// Use up all tokens
	for i := 0; i < 10; i++ {
		limiter.Allow(ctx, "Gateway")
	}

	// Tokens should be depleted
	assert.Less(t, limiter.GetTokens(), 1.0)

	// Reset
	limiter.Reset()

	// Should have full tokens again
	assert.Equal(t, 10.0, limiter.GetTokens())
}

func TestGetGlobalWebhookRateLimiter(t *testing.T) {
	// Note: This test may be affected by other tests that initialize the global limiter
	limiter := GetGlobalWebhookRateLimiter()
	require.NotNil(t, limiter)

	// Should return the same instance
	limiter2 := GetGlobalWebhookRateLimiter()
	assert.Equal(t, limiter, limiter2)
}

func TestWebhookRateLimiter_ConcurrentAccess(t *testing.T) {
	config := &WebhookRateLimiterConfig{
		Enabled: true,
		Rate:    1000.0,
		Burst:   100,
	}
	limiter := NewWebhookRateLimiter(config)

	ctx := context.Background()
	done := make(chan bool)

	// Run multiple goroutines accessing the limiter
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				limiter.Allow(ctx, "Gateway")
				limiter.GetTokens()
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not panic or deadlock
}

func TestWebhookRateLimiter_TokenRefillCap(t *testing.T) {
	config := &WebhookRateLimiterConfig{
		Enabled: true,
		Rate:    1000.0, // Very fast refill
		Burst:   10,
	}
	limiter := NewWebhookRateLimiter(config)

	// Wait for potential over-refill
	time.Sleep(100 * time.Millisecond)

	ctx := context.Background()
	// Trigger refill calculation
	limiter.Allow(ctx, "Gateway")

	// Tokens should be capped at burst
	tokens := limiter.GetTokens()
	assert.LessOrEqual(t, tokens, 10.0)
}
