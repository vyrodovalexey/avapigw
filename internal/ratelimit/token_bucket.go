package ratelimit

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/ratelimit/store"
	"go.uber.org/zap"
)

// Ensure TokenBucketLimiter implements io.Closer for proper resource cleanup
var _ io.Closer = (*TokenBucketLimiter)(nil)

// TokenBucketLimiter implements the token bucket rate limiting algorithm.
// Tokens are added to the bucket at a fixed rate, and each request consumes tokens.
// Implements io.Closer - call Close() when done to stop the background cleanup goroutine.
type TokenBucketLimiter struct {
	store  store.Store
	rate   float64 // tokens per second
	burst  int     // maximum bucket size
	logger *zap.Logger

	// In-memory state for local rate limiting
	buckets sync.Map

	// Cleanup configuration
	cleanupInterval time.Duration
	bucketTTL       time.Duration
	stopCleanup     chan struct{}
	cleanupOnce     sync.Once
}

// bucket represents a token bucket for a single key.
type bucket struct {
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewTokenBucketLimiter creates a new token bucket rate limiter.
// Starts a background cleanup goroutine to prevent memory leaks from stale buckets.
func NewTokenBucketLimiter(s store.Store, rate float64, burst int, logger *zap.Logger) *TokenBucketLimiter {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Default cleanup interval and TTL
	cleanupInterval := 5 * time.Minute
	bucketTTL := 10 * time.Minute

	l := &TokenBucketLimiter{
		store:           s,
		rate:            rate,
		burst:           burst,
		logger:          logger,
		cleanupInterval: cleanupInterval,
		bucketTTL:       bucketTTL,
		stopCleanup:     make(chan struct{}),
	}

	// Start background cleanup goroutine
	go l.startCleanupLoop()

	return l
}

// NewTokenBucketLimiterWithTTL creates a new token bucket rate limiter with custom TTL settings.
func NewTokenBucketLimiterWithTTL(s store.Store, rate float64, burst int, cleanupInterval, bucketTTL time.Duration, logger *zap.Logger) *TokenBucketLimiter {
	if logger == nil {
		logger = zap.NewNop()
	}

	l := &TokenBucketLimiter{
		store:           s,
		rate:            rate,
		burst:           burst,
		logger:          logger,
		cleanupInterval: cleanupInterval,
		bucketTTL:       bucketTTL,
		stopCleanup:     make(chan struct{}),
	}

	// Start background cleanup goroutine
	go l.startCleanupLoop()

	return l
}

// startCleanupLoop runs the periodic cleanup of stale buckets.
func (l *TokenBucketLimiter) startCleanupLoop() {
	ticker := time.NewTicker(l.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.Cleanup(l.bucketTTL)
		case <-l.stopCleanup:
			return
		}
	}
}

// Stop stops the background cleanup goroutine.
// Should be called when the limiter is no longer needed to prevent goroutine leaks.
// Deprecated: Use Close() instead for io.Closer compatibility.
func (l *TokenBucketLimiter) Stop() {
	_ = l.Close()
}

// Close implements io.Closer interface for proper resource cleanup.
// Stops the background cleanup goroutine. Safe to call multiple times.
func (l *TokenBucketLimiter) Close() error {
	l.cleanupOnce.Do(func() {
		close(l.stopCleanup)
	})
	return nil
}

// Allow implements Limiter.
func (l *TokenBucketLimiter) Allow(ctx context.Context, key string) (*Result, error) {
	return l.AllowN(ctx, key, 1)
}

// AllowN implements Limiter.
func (l *TokenBucketLimiter) AllowN(ctx context.Context, key string, n int) (*Result, error) {
	if l.store == nil {
		return l.allowLocal(key, n)
	}

	return l.allowDistributed(ctx, key, n)
}

// allowLocal performs rate limiting using in-memory storage.
func (l *TokenBucketLimiter) allowLocal(key string, n int) (*Result, error) {
	now := time.Now()

	// Get or create bucket
	value, _ := l.buckets.LoadOrStore(key, &bucket{
		tokens:     float64(l.burst),
		lastUpdate: now,
	})
	b := value.(*bucket)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Calculate tokens to add based on elapsed time
	elapsed := now.Sub(b.lastUpdate).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastUpdate = now

	// Check if we have enough tokens
	allowed := b.tokens >= float64(n)
	if allowed {
		b.tokens -= float64(n)
	}

	// Calculate remaining and reset time
	remaining := int(b.tokens)
	if remaining < 0 {
		remaining = 0
	}

	// Time until bucket is full
	tokensNeeded := float64(l.burst) - b.tokens
	resetAfter := time.Duration(tokensNeeded/l.rate) * time.Second

	// Time until we have at least 1 token
	var retryAfter time.Duration
	if !allowed {
		tokensNeeded := float64(n) - b.tokens
		retryAfter = time.Duration(tokensNeeded/l.rate) * time.Second
	}

	return &Result{
		Allowed:    allowed,
		Limit:      l.burst,
		Remaining:  remaining,
		ResetAfter: resetAfter,
		RetryAfter: retryAfter,
	}, nil
}

// allowDistributed performs rate limiting using distributed storage.
// Properly checks context cancellation between store operations.
func (l *TokenBucketLimiter) allowDistributed(ctx context.Context, key string, n int) (*Result, error) {
	// For distributed rate limiting with Redis, we use a simplified approach
	// that stores tokens and last update time

	now := time.Now()
	nowMs := now.UnixMilli()

	// Try to get current state
	stateKey := "tb:" + key
	tokens := float64(l.burst)
	lastUpdate := nowMs

	// Check context cancellation before first store operation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Get current tokens
	currentTokens, err := l.store.Get(ctx, stateKey+":tokens")
	if err == nil {
		tokens = float64(currentTokens) / 1000.0 // Store as millis for precision
	} else if !store.IsKeyNotFound(err) {
		return nil, err
	}

	// Check context cancellation between store operations
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Get last update time
	lastUpdateVal, err := l.store.Get(ctx, stateKey+":time")
	if err == nil {
		lastUpdate = lastUpdateVal
	} else if !store.IsKeyNotFound(err) {
		return nil, err
	}

	// Calculate tokens to add based on elapsed time
	elapsed := float64(nowMs-lastUpdate) / 1000.0
	tokens += elapsed * l.rate
	if tokens > float64(l.burst) {
		tokens = float64(l.burst)
	}

	// Check if we have enough tokens
	allowed := tokens >= float64(n)
	if allowed {
		tokens -= float64(n)
	}

	// Check context cancellation before write operations
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Store updated state
	expiration := time.Duration(float64(l.burst)/l.rate+1) * time.Second
	if err := l.store.Set(ctx, stateKey+":tokens", int64(tokens*1000), expiration); err != nil {
		l.logger.Warn("failed to store tokens", zap.Error(err))
	}

	// Check context cancellation between write operations
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if err := l.store.Set(ctx, stateKey+":time", nowMs, expiration); err != nil {
		l.logger.Warn("failed to store time", zap.Error(err))
	}

	// Calculate remaining and reset time
	remaining := int(tokens)
	if remaining < 0 {
		remaining = 0
	}

	tokensNeeded := float64(l.burst) - tokens
	resetAfter := time.Duration(tokensNeeded/l.rate) * time.Second

	var retryAfter time.Duration
	if !allowed {
		tokensNeeded := float64(n) - tokens
		retryAfter = time.Duration(tokensNeeded/l.rate) * time.Second
	}

	return &Result{
		Allowed:    allowed,
		Limit:      l.burst,
		Remaining:  remaining,
		ResetAfter: resetAfter,
		RetryAfter: retryAfter,
	}, nil
}

// GetLimit implements Limiter.
func (l *TokenBucketLimiter) GetLimit(key string) *Limit {
	return &Limit{
		Requests: int(l.rate),
		Window:   time.Second,
		Burst:    l.burst,
	}
}

// Reset implements Limiter.
func (l *TokenBucketLimiter) Reset(ctx context.Context, key string) error {
	// Reset local bucket
	l.buckets.Delete(key)

	// Reset distributed state
	if l.store != nil {
		stateKey := "tb:" + key
		if err := l.store.Delete(ctx, stateKey+":tokens"); err != nil {
			return err
		}
		if err := l.store.Delete(ctx, stateKey+":time"); err != nil {
			return err
		}
	}

	return nil
}

// Cleanup removes stale buckets from memory.
func (l *TokenBucketLimiter) Cleanup(maxAge time.Duration) {
	now := time.Now()

	l.buckets.Range(func(key, value interface{}) bool {
		b := value.(*bucket)
		b.mu.Lock()
		if now.Sub(b.lastUpdate) > maxAge {
			l.buckets.Delete(key)
		}
		b.mu.Unlock()
		return true
	})
}
