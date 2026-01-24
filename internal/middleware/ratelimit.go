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

// clientEntry holds a rate limiter and its last access time for TTL-based cleanup.
type clientEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// RateLimiter provides rate limiting functionality.
type RateLimiter struct {
	limiter   *rate.Limiter
	perClient bool
	clients   map[string]*clientEntry
	mu        sync.RWMutex
	rps       int
	burst     int
	logger    observability.Logger
	clientTTL time.Duration
	stopCh    chan struct{}
	stopped   bool
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
		clients:   make(map[string]*clientEntry),
		rps:       rps,
		burst:     burst,
		logger:    observability.NopLogger(),
		clientTTL: 10 * time.Minute, // Default TTL for client entries
		stopCh:    make(chan struct{}),
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
	now := time.Now()

	rl.mu.RLock()
	entry, exists := rl.clients[clientIP]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		entry, exists = rl.clients[clientIP]
		if !exists {
			entry = &clientEntry{
				limiter:    rate.NewLimiter(rate.Limit(rl.rps), rl.burst),
				lastAccess: now,
			}
			rl.clients[clientIP] = entry
		}
		rl.mu.Unlock()
	} else {
		// Update last access time
		rl.mu.Lock()
		entry.lastAccess = now
		rl.mu.Unlock()
	}

	return entry.limiter.Allow()
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

				w.Header().Set(HeaderContentType, ContentTypeJSON)
				w.Header().Set(HeaderRetryAfter, "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, ErrRateLimitExceeded)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitFromConfig creates rate limit middleware from gateway config.
// Returns the middleware and the rate limiter for lifecycle management.
// The caller should call Stop() on the rate limiter during shutdown.
func RateLimitFromConfig(
	cfg *config.RateLimitConfig,
	logger observability.Logger,
) (func(http.Handler) http.Handler, *RateLimiter) {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}, nil
	}

	rl := NewRateLimiter(cfg.RequestsPerSecond, cfg.Burst, cfg.PerClient, WithRateLimiterLogger(logger))

	// Start automatic cleanup for per-client rate limiting to prevent memory leaks
	if cfg.PerClient {
		rl.StartAutoCleanup()
	}

	return RateLimit(rl), rl
}

// CleanupOldClients removes old client limiters to prevent memory leaks.
// It removes entries that haven't been accessed within the TTL period.
func (rl *RateLimiter) CleanupOldClients(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	expiredClients := make([]string, 0)

	// Find expired entries
	for clientIP, entry := range rl.clients {
		if now.Sub(entry.lastAccess) > maxAge {
			expiredClients = append(expiredClients, clientIP)
		}
	}

	// Remove expired entries
	for _, clientIP := range expiredClients {
		delete(rl.clients, clientIP)
	}

	if len(expiredClients) > 0 {
		rl.logger.Debug("cleaned up expired rate limiter entries",
			observability.Int("removed", len(expiredClients)),
			observability.Int("remaining", len(rl.clients)),
		)
	}
}

// StartCleanup starts a goroutine to periodically clean up old clients.
// Uses the internal stopCh for graceful shutdown.
func (rl *RateLimiter) StartCleanup(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				rl.CleanupOldClients(rl.clientTTL)
			case <-stopCh:
				return
			case <-rl.stopCh:
				return
			}
		}
	}()
}

// StartAutoCleanup starts automatic cleanup using the rate limiter's internal stop channel.
// This should be called after creating the rate limiter to enable TTL-based cleanup.
func (rl *RateLimiter) StartAutoCleanup() {
	rl.mu.Lock()
	if rl.stopped {
		rl.mu.Unlock()
		return
	}
	rl.mu.Unlock()

	go func() {
		// Run cleanup every minute or at half the TTL, whichever is smaller
		cleanupInterval := rl.clientTTL / 2
		if cleanupInterval > time.Minute {
			cleanupInterval = time.Minute
		}
		if cleanupInterval < 10*time.Second {
			cleanupInterval = 10 * time.Second
		}

		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				rl.CleanupOldClients(rl.clientTTL)
			case <-rl.stopCh:
				return
			}
		}
	}()
}

// Stop stops the rate limiter cleanup goroutine.
func (rl *RateLimiter) Stop() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if !rl.stopped {
		rl.stopped = true
		close(rl.stopCh)
	}
}

// SetClientTTL sets the TTL for client entries.
func (rl *RateLimiter) SetClientTTL(ttl time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.clientTTL = ttl
}
