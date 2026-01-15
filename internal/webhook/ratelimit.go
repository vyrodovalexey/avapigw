// Package webhook provides admission webhooks for CRD validation and defaulting.
package webhook

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// WebhookRateLimiter provides rate limiting for webhook validation requests.
// It uses a token bucket algorithm to limit the rate of requests.
type WebhookRateLimiter struct {
	// rate is the number of requests allowed per second
	rate float64
	// burst is the maximum number of requests allowed in a burst
	burst int
	// tokens is the current number of available tokens
	tokens float64
	// lastRefill is the last time tokens were refilled
	lastRefill time.Time
	// mu protects the token bucket state
	mu sync.Mutex
	// enabled indicates if rate limiting is enabled
	enabled bool
}

// WebhookRateLimiterConfig holds configuration for the webhook rate limiter.
type WebhookRateLimiterConfig struct {
	// Enabled indicates if rate limiting is enabled
	Enabled bool
	// Rate is the number of requests allowed per second
	Rate float64
	// Burst is the maximum number of requests allowed in a burst
	Burst int
}

// DefaultWebhookRateLimiterConfig returns the default rate limiter configuration.
func DefaultWebhookRateLimiterConfig() *WebhookRateLimiterConfig {
	return &WebhookRateLimiterConfig{
		Enabled: true,
		Rate:    100.0, // 100 requests per second
		Burst:   200,   // Allow bursts of up to 200 requests
	}
}

// Prometheus metrics for webhook rate limiting
var (
	webhookRateLimitAllowed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "webhook",
			Name:      "ratelimit_allowed_total",
			Help:      "Total number of webhook requests allowed by rate limiter",
		},
		[]string{"resource"},
	)

	webhookRateLimitDenied = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "webhook",
			Name:      "ratelimit_denied_total",
			Help:      "Total number of webhook requests denied by rate limiter",
		},
		[]string{"resource"},
	)

	webhookRateLimitTokens = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "avapigw",
			Subsystem: "webhook",
			Name:      "ratelimit_tokens_available",
			Help:      "Current number of tokens available in the rate limiter",
		},
		[]string{},
	)
)

func init() {
	prometheus.MustRegister(webhookRateLimitAllowed, webhookRateLimitDenied, webhookRateLimitTokens)
}

// NewWebhookRateLimiter creates a new webhook rate limiter.
func NewWebhookRateLimiter(config *WebhookRateLimiterConfig) *WebhookRateLimiter {
	if config == nil {
		config = DefaultWebhookRateLimiterConfig()
	}

	return &WebhookRateLimiter{
		rate:       config.Rate,
		burst:      config.Burst,
		tokens:     float64(config.Burst),
		lastRefill: time.Now(),
		enabled:    config.Enabled,
	}
}

// Allow checks if a request should be allowed based on the rate limit.
// Returns true if the request is allowed, false otherwise.
// The resourceType parameter is used for metrics labeling.
func (r *WebhookRateLimiter) Allow(ctx context.Context, resourceType string) bool {
	if !r.enabled {
		webhookRateLimitAllowed.WithLabelValues(resourceType).Inc()
		return true
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.tokens += elapsed * r.rate
	if r.tokens > float64(r.burst) {
		r.tokens = float64(r.burst)
	}
	r.lastRefill = now

	// Update metrics
	webhookRateLimitTokens.WithLabelValues().Set(r.tokens)

	// Check if we have tokens available
	if r.tokens >= 1.0 {
		r.tokens--
		webhookRateLimitAllowed.WithLabelValues(resourceType).Inc()
		return true
	}

	webhookRateLimitDenied.WithLabelValues(resourceType).Inc()
	return false
}

// CheckRateLimit checks the rate limit and returns an error if exceeded.
// This is a convenience method that wraps Allow() and returns an appropriate error.
func (r *WebhookRateLimiter) CheckRateLimit(ctx context.Context, resourceType string) error {
	if !r.Allow(ctx, resourceType) {
		return fmt.Errorf("rate limit exceeded for %s webhook validation", resourceType)
	}
	return nil
}

// IsEnabled returns whether rate limiting is enabled.
func (r *WebhookRateLimiter) IsEnabled() bool {
	return r.enabled
}

// SetEnabled enables or disables rate limiting.
func (r *WebhookRateLimiter) SetEnabled(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = enabled
}

// GetTokens returns the current number of available tokens.
func (r *WebhookRateLimiter) GetTokens() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tokens
}

// Reset resets the rate limiter to its initial state.
func (r *WebhookRateLimiter) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens = float64(r.burst)
	r.lastRefill = time.Now()
}

// globalWebhookRateLimiter is the global rate limiter instance for webhooks.
var globalWebhookRateLimiter *WebhookRateLimiter
var globalWebhookRateLimiterOnce sync.Once

// GetGlobalWebhookRateLimiter returns the global webhook rate limiter instance.
// It initializes the rate limiter with default configuration on first call.
func GetGlobalWebhookRateLimiter() *WebhookRateLimiter {
	globalWebhookRateLimiterOnce.Do(func() {
		globalWebhookRateLimiter = NewWebhookRateLimiter(DefaultWebhookRateLimiterConfig())
	})
	return globalWebhookRateLimiter
}

// InitGlobalWebhookRateLimiter initializes the global webhook rate limiter with custom configuration.
// This should be called before any webhooks are registered.
// If called after GetGlobalWebhookRateLimiter(), this function has no effect.
func InitGlobalWebhookRateLimiter(config *WebhookRateLimiterConfig) {
	globalWebhookRateLimiterOnce.Do(func() {
		globalWebhookRateLimiter = NewWebhookRateLimiter(config)
	})
}
