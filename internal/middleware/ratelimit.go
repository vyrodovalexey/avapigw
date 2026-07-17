package middleware

import (
	"container/list"
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"

	"github.com/vyrodovalexey/avapigw/internal/config"
	routepkg "github.com/vyrodovalexey/avapigw/internal/metrics/route"
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

// clientEntry holds a rate limiter and its last access time for TTL-based
// cleanup. Each entry is linked into the RateLimiter's LRU list so the
// least-recently-used entry can be located and evicted in O(1).
type clientEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
	key        string        // client key, needed for map removal on eviction
	elem       *list.Element // position in the LRU list
}

// RateLimiter provides rate limiting functionality.
type RateLimiter struct {
	limiter   *rate.Limiter
	perClient bool
	clients   map[string]*clientEntry
	// lru keeps client entries in access order (front = most recently
	// used). Because every access refreshes both lastAccess and the list
	// position, the back of the list is always the entry with the oldest
	// lastAccess, which makes TTL sweeps and capacity eviction
	// proportional to the number of removed entries instead of O(n²).
	lru         *list.List
	mu          sync.RWMutex
	rps         int
	burst       int
	logger      observability.Logger
	clientTTL   time.Duration
	maxClients  int
	stopCh      chan struct{}
	stopped     bool
	hitCallback RateLimitHitFunc
	// nowFunc returns the current time. It exists as a seam for
	// deterministic TTL-eviction tests and defaults to time.Now.
	nowFunc func() time.Time
	// evictionScans counts entries examined by eviction/cleanup loops.
	// It is reported in debug logs and lets tests assert that eviction
	// work stays bounded under high client churn.
	evictionScans int64
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
		lru:        list.New(),
		rps:        rps,
		burst:      burst,
		logger:     observability.NopLogger(),
		clientTTL:  DefaultClientTTL,
		maxClients: DefaultMaxClients,
		stopCh:     make(chan struct{}),
		nowFunc:    time.Now,
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
// checking existence and updating lastAccess time. The current time is
// taken inside the critical section so that LRU list order always
// matches lastAccess order.
func (rl *RateLimiter) allowPerClient(clientIP string) bool {
	rl.mu.Lock()
	now := rl.nowFunc()
	entry, exists := rl.clients[clientIP]
	if exists {
		// Refresh recency within the same critical section.
		entry.lastAccess = now
		rl.lru.MoveToFront(entry.elem)
	} else {
		// Check if we've hit the max clients limit before adding a new entry
		if len(rl.clients) >= rl.maxClients {
			// Evict oldest entries to make room
			rl.evictOldestLocked()
		}
		entry = &clientEntry{
			limiter:    rate.NewLimiter(rate.Limit(rl.rps), rl.burst),
			lastAccess: now,
			key:        clientIP,
		}
		entry.elem = rl.lru.PushFront(entry)
		rl.clients[clientIP] = entry
	}
	// Get the limiter reference while holding the lock
	limiter := entry.limiter
	rl.mu.Unlock()

	// Allow() is thread-safe on the limiter itself
	return limiter.Allow()
}

// evictOldestLocked evicts entries to make room for a new client.
// It first drops entries whose TTL expired, then — if the map is still
// over capacity — trims the least-recently-used entries until the map is
// at 90% of maxClients. Both phases pop from the back of the LRU list,
// so the total work is proportional to the number of evicted entries
// (amortized O(1) per insert) instead of the previous full-map rescan
// per evicted entry (O(n²)).
// Must be called with the mutex held.
func (rl *RateLimiter) evictOldestLocked() {
	now := rl.nowFunc()

	// Phase 1: drop expired entries from the LRU tail.
	rl.removeExpiredFromTailLocked(now, rl.clientTTL)

	// Phase 2: if still over capacity, trim LRU entries to 90% of maxClients.
	targetSize := rl.maxClients * 9 / 10
	for len(rl.clients) > targetSize {
		back := rl.lru.Back()
		if back == nil {
			break
		}
		rl.evictionScans++
		rl.removeEntryLocked(back.Value.(*clientEntry))
	}

	rl.logger.Debug("evicted old rate limiter entries",
		observability.Int("remaining", len(rl.clients)),
		observability.Int("max_clients", rl.maxClients),
		observability.Int64("eviction_scans_total", rl.evictionScans),
	)
}

// removeExpiredFromTailLocked pops entries older than maxAge off the LRU
// tail and returns the number of removed entries. Because the list is
// ordered by lastAccess, the sweep stops at the first non-expired entry.
// Must be called with the mutex held.
func (rl *RateLimiter) removeExpiredFromTailLocked(now time.Time, maxAge time.Duration) int {
	removed := 0
	for {
		back := rl.lru.Back()
		if back == nil {
			break
		}
		rl.evictionScans++
		entry := back.Value.(*clientEntry)
		if now.Sub(entry.lastAccess) <= maxAge {
			break
		}
		rl.removeEntryLocked(entry)
		removed++
	}
	return removed
}

// removeEntryLocked removes an entry from both the map and the LRU list.
// Must be called with the mutex held.
func (rl *RateLimiter) removeEntryLocked(entry *clientEntry) {
	rl.lru.Remove(entry.elem)
	delete(rl.clients, entry.key)
}

// httpRateLimiter is the shared surface of the in-memory and redis-backed
// rate limiters used by the HTTP middleware implementation.
type httpRateLimiter interface {
	// allowHTTP reports whether the request from clientIP is allowed.
	allowHTTP(ctx context.Context, clientIP string) bool

	// middlewareLogger returns the logger for rejection logging.
	middlewareLogger() observability.Logger

	// hitFunc returns the optional rate limit hit callback.
	hitFunc() RateLimitHitFunc

	// storeLabel returns the store name recorded in OTEL span attributes.
	storeLabel() string
}

// allowHTTP implements httpRateLimiter for the in-memory limiter.
func (rl *RateLimiter) allowHTTP(_ context.Context, clientIP string) bool {
	return rl.Allow(clientIP)
}

// middlewareLogger implements httpRateLimiter.
func (rl *RateLimiter) middlewareLogger() observability.Logger { return rl.logger }

// hitFunc implements httpRateLimiter.
func (rl *RateLimiter) hitFunc() RateLimitHitFunc { return rl.hitCallback }

// storeLabel implements httpRateLimiter.
func (rl *RateLimiter) storeLabel() string { return config.RateLimitStoreMemory }

// RateLimit returns a middleware that applies rate limiting.
func RateLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return rateLimitHTTPMiddleware(rl)
}

// rateLimitHTTPMiddleware builds the HTTP middleware shared by the
// in-memory and redis-backed rate limiters: tracing, decision, metrics,
// and the 429 rejection response.
func rateLimitHTTPMiddleware(limiter httpRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := rlTracer.Start(r.Context(), "ratelimit.check",
				trace.WithSpanKind(trace.SpanKindInternal),
				trace.WithAttributes(
					attribute.String("ratelimit.path", r.URL.Path),
					attribute.String("ratelimit.store", limiter.storeLabel()),
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
				routeName = unknownRoute
			}

			if !limiter.allowHTTP(ctx, clientIP) {
				span.SetAttributes(
					attribute.Bool("ratelimit.allowed", false),
					attribute.String("ratelimit.decision", "rejected"),
				)
				rejectRateLimited(w, r, limiter, routeName, clientIP)
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

// rejectRateLimited records rejection telemetry and writes the 429 response.
func rejectRateLimited(
	w http.ResponseWriter, r *http.Request, limiter httpRateLimiter, routeName, clientIP string,
) {
	limiter.middlewareLogger().Warn("rate limit exceeded",
		observability.String("client_ip", clientIP),
		observability.String("path", r.URL.Path),
		observability.String("store", limiter.storeLabel()),
	)

	if hit := limiter.hitFunc(); hit != nil {
		hit(routeName)
	}

	GetMiddlewareMetrics().rateLimitRejected.WithLabelValues(
		routeName,
	).Inc()

	// Record route-level rate limit hit
	routepkg.GetRouteMetrics().RecordRateLimitHit(
		routeName, r.Method, "default",
	)

	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.Header().Set(HeaderRetryAfter, "1")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = io.WriteString(w, ErrRateLimitExceeded)
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
// Expired entries are popped from the LRU tail (oldest lastAccess first),
// so the cost is proportional to the number of removed entries.
func (rl *RateLimiter) CleanupOldClients(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	removed := rl.removeExpiredFromTailLocked(rl.nowFunc(), maxAge)

	if removed > 0 {
		rl.logger.Debug("cleaned up expired rate limiter entries",
			observability.Int("removed", removed),
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

// validRateLimitParams reports whether the rate limiting parameters are
// usable by a token bucket. A non-positive rps or a burst below 1 turns
// the bucket into a permanent silent deny (it can never hold a whole
// token), so configuration updates carrying such values are rejected.
func validRateLimitParams(cfg *config.RateLimitConfig) bool {
	return cfg.RequestsPerSecond > 0 && cfg.Burst >= 1
}

// logInvalidRateLimitUpdate logs a rejected rate limiter configuration
// update, keeping the previously applied parameters in effect.
func logInvalidRateLimitUpdate(logger observability.Logger, scope string, cfg *config.RateLimitConfig) {
	logger.Error("rejecting rate limiter config update with invalid parameters, keeping previous values",
		observability.String("scope", scope),
		observability.Int("rps", cfg.RequestsPerSecond),
		observability.Int("burst", cfg.Burst),
	)
}

// UpdateConfig updates the rate limiter with new configuration.
// It replaces the global limiter and clears all per-client entries
// so they are recreated with the new RPS/burst values.
// Invalid parameters (rps < 1 or burst < 1) are rejected with a logged
// error and the previous configuration stays in effect.
func (rl *RateLimiter) UpdateConfig(cfg *config.RateLimitConfig) {
	if cfg == nil {
		return
	}
	if !validRateLimitParams(cfg) {
		logInvalidRateLimitUpdate(rl.logger, config.RateLimitStoreMemory, cfg)
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.rps = cfg.RequestsPerSecond
	rl.burst = cfg.Burst
	rl.perClient = cfg.PerClient
	rl.limiter = rate.NewLimiter(rate.Limit(cfg.RequestsPerSecond), cfg.Burst)

	// Clear per-client entries so they are recreated with new values.
	// The LRU list is reset together with the map to keep both in sync.
	rl.clients = make(map[string]*clientEntry)
	rl.lru.Init()

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
