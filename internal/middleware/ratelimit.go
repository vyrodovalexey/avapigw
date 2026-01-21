package middleware

import (
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// RateLimiter provides rate limiting functionality.
type RateLimiter struct {
	limiter   *rate.Limiter
	perClient bool
	clients   map[string]*rate.Limiter
	mu        sync.RWMutex
	rps       int
	burst     int
	logger    observability.Logger
}

// RateLimiterOption is a functional option for configuring the rate limiter.
type RateLimiterOption func(*RateLimiter)

// WithRateLimiterLogger sets the logger for the rate limiter.
func WithRateLimiterLogger(logger observability.Logger) RateLimiterOption {
	return func(rl *RateLimiter) {
		rl.logger = logger
	}
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(rps, burst int, perClient bool, opts ...RateLimiterOption) *RateLimiter {
	rl := &RateLimiter{
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
func (rl *RateLimiter) Allow(clientIP string) bool {
	if rl.perClient {
		return rl.allowPerClient(clientIP)
	}
	return rl.limiter.Allow()
}

// allowPerClient checks rate limit per client.
func (rl *RateLimiter) allowPerClient(clientIP string) bool {
	rl.mu.RLock()
	limiter, exists := rl.clients[clientIP]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		limiter, exists = rl.clients[clientIP]
		if !exists {
			limiter = rate.NewLimiter(rate.Limit(rl.rps), rl.burst)
			rl.clients[clientIP] = limiter
		}
		rl.mu.Unlock()
	}

	return limiter.Allow()
}

// RateLimit returns a middleware that applies rate limiting.
func RateLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)

			if !rl.Allow(clientIP) {
				rl.logger.Warn("rate limit exceeded",
					observability.String("client_ip", clientIP),
					observability.String("path", r.URL.Path),
				)

				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, `{"error":"rate limit exceeded"}`)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitFromConfig creates rate limit middleware from gateway config.
func RateLimitFromConfig(cfg *config.RateLimitConfig, logger observability.Logger) func(http.Handler) http.Handler {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	rl := NewRateLimiter(cfg.RequestsPerSecond, cfg.Burst, cfg.PerClient, WithRateLimiterLogger(logger))
	return RateLimit(rl)
}

// CleanupOldClients removes old client limiters to prevent memory leaks.
func (rl *RateLimiter) CleanupOldClients(maxAge time.Duration) {
	// This is a simplified cleanup - in production, track last access time
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// For now, just clear all clients periodically
	// In production, track last access time per client
	if len(rl.clients) > 10000 {
		rl.clients = make(map[string]*rate.Limiter)
	}
}

// StartCleanup starts a goroutine to periodically clean up old clients.
func (rl *RateLimiter) StartCleanup(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				rl.CleanupOldClients(interval)
			case <-stopCh:
				return
			}
		}
	}()
}
