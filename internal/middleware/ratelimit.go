package middleware

import (
	"io"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// rlTracer is the OTEL tracer used for rate limiting operations.
var rlTracer = otel.Tracer("avapigw/ratelimit")

// Rate limiter default configuration constants.
const (
	// DefaultClientTTL is the default TTL for client rate limiter entries.
	DefaultClientTTL = 10 * time.Minute

	// DefaultMaxClients is the default maximum number of client entries.
	// This prevents unbounded memory growth from malicious or high-cardinality clients.
	DefaultMaxClients = 100000

	// MinCleanupInterval is the minimum interval for cleanup operations.
	MinCleanupInterval = 10 * time.Second

	// MaxCleanupInterval is the maximum interval for cleanup operations.
	MaxCleanupInterval = time.Minute
)

// clientEntry holds a rate limiter and its last access time for TTL-based cleanup.
type clientEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// RateLimiter provides rate limiting functionality.
type RateLimiter struct {
	limiter     *rate.Limiter
	perClient   bool
	clients     map[string]*clientEntry
	mu          sync.RWMutex
	rps         int
	burst       int
	logger      observability.Logger
	clientTTL   time.Duration
	maxClients  int
	stopCh      chan struct{}
	stopped     bool
	hitCallback RateLimitHitFunc
}

// RateLimitHitFunc is called when a rate limit hit occurs.
type RateLimitHitFunc func(route string)

// RateLimiterOption is a functional option for configuring the rate limiter.
type RateLimiterOption func(*RateLimiter)

// WithRateLimiterLogger sets the logger for the rate limiter.
func WithRateLimiterLogger(logger observability.Logger) RateLimiterOption {
	return func(rl *RateLimiter) {
		rl.logger = logger
	}
}

// WithClientTTL sets the TTL for client entries.
func WithClientTTL(ttl time.Duration) RateLimiterOption {
	return func(rl *RateLimiter) {
		rl.clientTTL = ttl
	}
}

// WithMaxClients sets the maximum number of client entries.
func WithMaxClients(maxClients int) RateLimiterOption {
	return func(rl *RateLimiter) {
		rl.maxClients = maxClients
	}
}

// WithRateLimitHitCallback sets a callback invoked when a rate limit hit occurs.
func WithRateLimitHitCallback(fn RateLimitHitFunc) RateLimiterOption {
	return func(rl *RateLimiter) {
		rl.hitCallback = fn
	}
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(rps, burst int, perClient bool, opts ...RateLimiterOption) *RateLimiter {
	rl := &RateLimiter{
		limiter:    rate.NewLimiter(rate.Limit(rps), burst),
		perClient:  perClient,
		clients:    make(map[string]*clientEntry),
		rps:        rps,
		burst:      burst,
		logger:     observability.NopLogger(),
		clientTTL:  DefaultClientTTL,
		maxClients: DefaultMaxClients,
		stopCh:     make(chan struct{}),
	}

	for _, opt := range opts {
		opt(rl)
	}

	return rl
}

// Allow checks if a request is allowed.
func (rl *RateLimiter) Allow(clientIP string) bool {
	rl.mu.RLock()
	perClient := rl.perClient
	limiter := rl.limiter
	rl.mu.RUnlock()

	if perClient {
		return rl.allowPerClient(clientIP)
	}
	return limiter.Allow()
}

// allowPerClient checks rate limit per client.
// Uses a single critical section to avoid race conditions between
// checking existence and updating lastAccess time.
func (rl *RateLimiter) allowPerClient(clientIP string) bool {
	now := time.Now()

	rl.mu.Lock()
	entry, exists := rl.clients[clientIP]
	if !exists {
		// Check if we've hit the max clients limit before adding a new entry
		if len(rl.clients) >= rl.maxClients {
			// Evict oldest entries to make room
			rl.evictOldestLocked()
		}
		entry = &clientEntry{
			limiter:    rate.NewLimiter(rate.Limit(rl.rps), rl.burst),
			lastAccess: now,
		}
		rl.clients[clientIP] = entry
	} else {
		// Update last access time within the same critical section
		entry.lastAccess = now
	}
	// Get the limiter reference while holding the lock
	limiter := entry.limiter
	rl.mu.Unlock()

	// Allow() is thread-safe on the limiter itself
	return limiter.Allow()
}

// evictOldestLocked evicts the oldest entries to make room for new ones.
// Must be called with the mutex held.
func (rl *RateLimiter) evictOldestLocked() {
	// First, remove expired entries
	now := time.Now()
	for clientIP, entry := range rl.clients {
		if now.Sub(entry.lastAccess) > rl.clientTTL {
			delete(rl.clients, clientIP)
		}
	}

	// If still over capacity, remove oldest entries until we're at 90% capacity
	targetSize := rl.maxClients * 9 / 10
	for len(rl.clients) > targetSize {
		var oldestKey string
		var oldestTime time.Time

		for key, entry := range rl.clients {
			if oldestKey == "" || entry.lastAccess.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.lastAccess
			}
		}

		if oldestKey != "" {
			delete(rl.clients, oldestKey)
		} else {
			break
		}
	}

	rl.logger.Debug("evicted old rate limiter entries",
		observability.Int("remaining", len(rl.clients)),
		observability.Int("max_clients", rl.maxClients),
	)
}

// RateLimit returns a middleware that applies rate limiting.
func RateLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := rlTracer.Start(r.Context(), "ratelimit.check",
				trace.WithSpanKind(trace.SpanKindInternal),
				trace.WithAttributes(
					attribute.String("ratelimit.path", r.URL.Path),
				),
			)
			defer span.End()
			r = r.WithContext(ctx)

			clientIP := getClientIP(r)
			span.SetAttributes(attribute.String("ratelimit.client_ip", clientIP))

			// Use route name from context for bounded Prometheus label cardinality.
			// Raw URL paths would create unbounded cardinality (DoS vector).
			routeName := util.RouteFromContext(ctx)
			if routeName == "" {
				routeName = "unknown"
			}

			if !rl.Allow(clientIP) {
				span.SetAttributes(
					attribute.Bool("ratelimit.allowed", false),
					attribute.String("ratelimit.decision", "rejected"),
				)

				rl.logger.Warn("rate limit exceeded",
					observability.String("client_ip", clientIP),
					observability.String("path", r.URL.Path),
				)

				if rl.hitCallback != nil {
					rl.hitCallback(routeName)
				}

				mm := GetMiddlewareMetrics()
				mm.rateLimitRejected.WithLabelValues(
					routeName,
				).Inc()

				w.Header().Set(HeaderContentType, ContentTypeJSON)
				w.Header().Set(HeaderRetryAfter, "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, ErrRateLimitExceeded)
				return
			}

			span.SetAttributes(
				attribute.Bool("ratelimit.allowed", true),
				attribute.String("ratelimit.decision", "allowed"),
			)

			GetMiddlewareMetrics().rateLimitAllowed.WithLabelValues(
				routeName,
			).Inc()

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitFromConfig creates rate limit middleware from gateway config.
// Returns the middleware and the rate limiter for lifecycle management.
// The caller should call Stop() on the rate limiter during shutdown.
// Additional RateLimiterOption values are forwarded to NewRateLimiter.
func RateLimitFromConfig(
	cfg *config.RateLimitConfig,
	logger observability.Logger,
	opts ...RateLimiterOption,
) (func(http.Handler) http.Handler, *RateLimiter) {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}, nil
	}

	allOpts := append(
		[]RateLimiterOption{WithRateLimiterLogger(logger)},
		opts...,
	)
	rl := NewRateLimiter(cfg.RequestsPerSecond, cfg.Burst, cfg.PerClient, allOpts...)

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
		if cleanupInterval > MaxCleanupInterval {
			cleanupInterval = MaxCleanupInterval
		}
		if cleanupInterval < MinCleanupInterval {
			cleanupInterval = MinCleanupInterval
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

// UpdateConfig updates the rate limiter with new configuration.
// It replaces the global limiter and clears all per-client entries
// so they are recreated with the new RPS/burst values.
func (rl *RateLimiter) UpdateConfig(cfg *config.RateLimitConfig) {
	if cfg == nil {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.rps = cfg.RequestsPerSecond
	rl.burst = cfg.Burst
	rl.perClient = cfg.PerClient
	rl.limiter = rate.NewLimiter(rate.Limit(cfg.RequestsPerSecond), cfg.Burst)

	// Clear per-client entries so they are recreated with new values
	rl.clients = make(map[string]*clientEntry)

	rl.logger.Info("rate limiter configuration updated",
		observability.Int("rps", cfg.RequestsPerSecond),
		observability.Int("burst", cfg.Burst),
		observability.Bool("perClient", cfg.PerClient),
	)
}

// SetClientTTL sets the TTL for client entries.
func (rl *RateLimiter) SetClientTTL(ttl time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.clientTTL = ttl
}

// SetMaxClients sets the maximum number of client entries.
func (rl *RateLimiter) SetMaxClients(maxClients int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maxClients = maxClients
}

// ClientCount returns the current number of client entries.
func (rl *RateLimiter) ClientCount() int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return len(rl.clients)
}
