package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/ratelimit/store"
	"go.uber.org/zap"
)

// FixedWindowLimiter implements the fixed window rate limiting algorithm.
// It divides time into fixed windows and counts requests within each window.
type FixedWindowLimiter struct {
	store  store.Store
	limit  int
	window time.Duration
	logger *zap.Logger

	// In-memory state for local rate limiting
	counters sync.Map
}

// windowCounter represents a counter for a fixed window.
type windowCounter struct {
	count       int
	windowStart time.Time
	mu          sync.Mutex
}

// NewFixedWindowLimiter creates a new fixed window rate limiter.
func NewFixedWindowLimiter(s store.Store, limit int, window time.Duration, logger *zap.Logger) *FixedWindowLimiter {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &FixedWindowLimiter{
		store:  s,
		limit:  limit,
		window: window,
		logger: logger,
	}
}

// Allow implements Limiter.
func (l *FixedWindowLimiter) Allow(ctx context.Context, key string) (*Result, error) {
	return l.AllowN(ctx, key, 1)
}

// AllowN implements Limiter.
func (l *FixedWindowLimiter) AllowN(ctx context.Context, key string, n int) (*Result, error) {
	if l.store == nil {
		return l.allowLocal(key, n)
	}

	return l.allowDistributed(ctx, key, n)
}

// getWindowStart returns the start time of the current window.
func (l *FixedWindowLimiter) getWindowStart(t time.Time) time.Time {
	windowNanos := l.window.Nanoseconds()
	return time.Unix(0, (t.UnixNano()/windowNanos)*windowNanos)
}

// allowLocal performs rate limiting using in-memory storage.
func (l *FixedWindowLimiter) allowLocal(key string, n int) (*Result, error) {
	now := time.Now()
	windowStart := l.getWindowStart(now)

	// Get or create counter
	value, _ := l.counters.LoadOrStore(key, &windowCounter{
		count:       0,
		windowStart: windowStart,
	})
	wc := value.(*windowCounter)

	wc.mu.Lock()
	defer wc.mu.Unlock()

	// Check if we're in a new window
	if !wc.windowStart.Equal(windowStart) {
		wc.count = 0
		wc.windowStart = windowStart
	}

	// Check if we can allow the request
	allowed := wc.count+n <= l.limit

	if allowed {
		wc.count += n
	}

	// Calculate remaining
	remaining := l.limit - wc.count
	if remaining < 0 {
		remaining = 0
	}

	// Calculate reset time (end of current window)
	resetAfter := windowStart.Add(l.window).Sub(now)
	if resetAfter < 0 {
		resetAfter = 0
	}

	// Calculate retry time
	var retryAfter time.Duration
	if !allowed {
		retryAfter = resetAfter
	}

	return &Result{
		Allowed:    allowed,
		Limit:      l.limit,
		Remaining:  remaining,
		ResetAfter: resetAfter,
		RetryAfter: retryAfter,
	}, nil
}

// allowDistributed performs rate limiting using distributed storage.
func (l *FixedWindowLimiter) allowDistributed(ctx context.Context, key string, n int) (*Result, error) {
	now := time.Now()
	windowStart := l.getWindowStart(now)

	// Create window key
	windowKey := fmt.Sprintf("%s:fw:%d", key, windowStart.UnixNano())

	// Get current count
	currentCount, err := l.store.Get(ctx, windowKey)
	if err != nil && !store.IsKeyNotFound(err) {
		return nil, err
	}

	// Check if we can allow the request
	allowed := int(currentCount)+n <= l.limit

	if allowed {
		// Increment counter with expiration
		expiration := l.window + time.Second // Add buffer for clock skew
		newCount, err := l.store.IncrementWithExpiry(ctx, windowKey, int64(n), expiration)
		if err != nil {
			l.logger.Warn("failed to increment counter", zap.Error(err))
		}
		currentCount = newCount
	}

	// Calculate remaining
	remaining := l.limit - int(currentCount)
	if remaining < 0 {
		remaining = 0
	}

	// Calculate reset time
	resetAfter := windowStart.Add(l.window).Sub(now)
	if resetAfter < 0 {
		resetAfter = 0
	}

	// Calculate retry time
	var retryAfter time.Duration
	if !allowed {
		retryAfter = resetAfter
	}

	return &Result{
		Allowed:    allowed,
		Limit:      l.limit,
		Remaining:  remaining,
		ResetAfter: resetAfter,
		RetryAfter: retryAfter,
	}, nil
}

// GetLimit implements Limiter.
func (l *FixedWindowLimiter) GetLimit(key string) *Limit {
	return &Limit{
		Requests: l.limit,
		Window:   l.window,
		Burst:    l.limit,
	}
}

// Reset implements Limiter.
func (l *FixedWindowLimiter) Reset(ctx context.Context, key string) error {
	// Reset local state
	l.counters.Delete(key)

	// Reset distributed state
	if l.store != nil {
		now := time.Now()
		windowStart := l.getWindowStart(now)
		windowKey := fmt.Sprintf("%s:fw:%d", key, windowStart.UnixNano())
		if err := l.store.Delete(ctx, windowKey); err != nil {
			l.logger.Warn("failed to delete window counter", zap.Error(err))
		}
	}

	return nil
}

// Cleanup removes stale counters from memory.
func (l *FixedWindowLimiter) Cleanup() {
	now := time.Now()
	windowStart := l.getWindowStart(now)

	l.counters.Range(func(key, value interface{}) bool {
		wc := value.(*windowCounter)
		wc.mu.Lock()

		// Remove if counter is from an old window
		if wc.windowStart.Before(windowStart) {
			l.counters.Delete(key)
		}

		wc.mu.Unlock()
		return true
	})
}
