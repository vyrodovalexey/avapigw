package ratelimit

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/ratelimit/store"
	"go.uber.org/zap"
)

// SlidingWindowLimiter implements the sliding window rate limiting algorithm.
// It provides more accurate rate limiting than fixed window by considering
// requests from the previous window proportionally.
type SlidingWindowLimiter struct {
	store     store.Store
	limit     int
	window    time.Duration
	precision int // number of sub-windows for sliding calculation
	logger    *zap.Logger

	// In-memory state for local rate limiting
	windows sync.Map
}

// windowState represents the state for a sliding window.
type windowState struct {
	requests []time.Time
	mu       sync.Mutex
}

// NewSlidingWindowLimiter creates a new sliding window rate limiter.
func NewSlidingWindowLimiter(s store.Store, limit int, window time.Duration, logger *zap.Logger) *SlidingWindowLimiter {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &SlidingWindowLimiter{
		store:     s,
		limit:     limit,
		window:    window,
		precision: 10, // default precision
		logger:    logger,
	}
}

// NewSlidingWindowLimiterWithPrecision creates a new sliding window rate limiter with custom precision.
func NewSlidingWindowLimiterWithPrecision(
	s store.Store,
	limit int,
	window time.Duration,
	precision int,
	logger *zap.Logger,
) *SlidingWindowLimiter {
	if logger == nil {
		logger = zap.NewNop()
	}
	if precision < 1 {
		precision = 10
	}

	return &SlidingWindowLimiter{
		store:     s,
		limit:     limit,
		window:    window,
		precision: precision,
		logger:    logger,
	}
}

// Allow implements Limiter.
func (l *SlidingWindowLimiter) Allow(ctx context.Context, key string) (*Result, error) {
	return l.AllowN(ctx, key, 1)
}

// AllowN implements Limiter.
func (l *SlidingWindowLimiter) AllowN(ctx context.Context, key string, n int) (*Result, error) {
	if l.store == nil {
		return l.allowLocal(key, n)
	}

	return l.allowDistributed(ctx, key, n)
}

// allowLocal performs rate limiting using in-memory storage.
func (l *SlidingWindowLimiter) allowLocal(key string, n int) (*Result, error) {
	now := time.Now()
	ws := l.getOrCreateWindowState(key)

	ws.mu.Lock()
	defer ws.mu.Unlock()

	l.cleanupOldRequests(ws, now)
	currentCount, allowed := l.processLocalRequest(ws, now, n)
	remaining := l.calculateRemaining(currentCount)
	resetAfter := l.calculateResetAfter(ws, now)
	retryAfter := l.calculateRetryAfter(ws, now, currentCount, n, allowed)

	return &Result{
		Allowed:    allowed,
		Limit:      l.limit,
		Remaining:  remaining,
		ResetAfter: resetAfter,
		RetryAfter: retryAfter,
	}, nil
}

// getOrCreateWindowState retrieves or creates a window state for the given key.
func (l *SlidingWindowLimiter) getOrCreateWindowState(key string) *windowState {
	value, _ := l.windows.LoadOrStore(key, &windowState{
		requests: make([]time.Time, 0),
	})
	return value.(*windowState)
}

// cleanupOldRequests removes requests outside the current window.
func (l *SlidingWindowLimiter) cleanupOldRequests(ws *windowState, now time.Time) {
	windowStart := now.Add(-l.window)
	validRequests := make([]time.Time, 0, len(ws.requests))
	for _, t := range ws.requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}
	ws.requests = validRequests
}

// processLocalRequest checks if request is allowed and updates state.
// Returns current count and whether the request was allowed.
func (l *SlidingWindowLimiter) processLocalRequest(ws *windowState, now time.Time, n int) (int, bool) {
	currentCount := len(ws.requests)
	allowed := currentCount+n <= l.limit

	if allowed {
		for i := 0; i < n; i++ {
			ws.requests = append(ws.requests, now)
		}
		currentCount += n
	}

	return currentCount, allowed
}

// calculateRemaining calculates remaining requests in the window.
func (l *SlidingWindowLimiter) calculateRemaining(currentCount int) int {
	remaining := l.limit - currentCount
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

// calculateResetAfter calculates time until the window resets.
func (l *SlidingWindowLimiter) calculateResetAfter(ws *windowState, now time.Time) time.Duration {
	if len(ws.requests) == 0 {
		return l.window
	}

	oldestRequest := ws.requests[0]
	resetAfter := oldestRequest.Add(l.window).Sub(now)
	if resetAfter < 0 {
		resetAfter = 0
	}
	return resetAfter
}

// calculateRetryAfter calculates time until retry is possible.
func (l *SlidingWindowLimiter) calculateRetryAfter(
	ws *windowState,
	now time.Time,
	currentCount, n int,
	allowed bool,
) time.Duration {
	if allowed || len(ws.requests) == 0 {
		return 0
	}

	excessRequests := currentCount + n - l.limit
	if excessRequests <= 0 || excessRequests > len(ws.requests) {
		return 0
	}

	oldestToExpire := ws.requests[excessRequests-1]
	retryAfter := oldestToExpire.Add(l.window).Sub(now)
	if retryAfter < 0 {
		retryAfter = 0
	}
	return retryAfter
}

// allowDistributed performs rate limiting using distributed storage.
func (l *SlidingWindowLimiter) allowDistributed(ctx context.Context, key string, n int) (*Result, error) {
	now := time.Now()
	nowMs := now.UnixMilli()
	windowMs := l.window.Milliseconds()

	// Use a simplified sliding window counter approach
	// We divide the window into sub-windows and count requests in each

	subWindowSize := windowMs / int64(l.precision)
	currentSubWindow := nowMs / subWindowSize

	// Count requests in the current window
	// Fix: Use strconv.FormatInt instead of string(rune()) which doesn't work for numbers > 127
	totalCount := int64(0)
	for i := 0; i < l.precision; i++ {
		subWindowKey := key + ":sw:" + strconv.FormatInt(currentSubWindow-int64(i), 10)
		count, err := l.store.Get(ctx, subWindowKey)
		if err != nil && !store.IsKeyNotFound(err) {
			return nil, err
		}
		totalCount += count
	}

	// Check if we can allow the request
	allowed := int(totalCount)+n <= l.limit

	if allowed {
		// Increment current sub-window
		currentKey := key + ":sw:" + strconv.FormatInt(currentSubWindow, 10)
		expiration := l.window + time.Duration(subWindowSize)*time.Millisecond
		_, err := l.store.IncrementWithExpiry(ctx, currentKey, int64(n), expiration)
		if err != nil {
			l.logger.Warn("failed to increment counter", zap.Error(err))
		}
		totalCount += int64(n)
	}

	// Calculate remaining
	remaining := l.limit - int(totalCount)
	if remaining < 0 {
		remaining = 0
	}

	// Calculate reset time
	resetAfter := l.window

	// Calculate retry time
	var retryAfter time.Duration
	if !allowed {
		// Approximate time until oldest sub-window expires
		retryAfter = time.Duration(subWindowSize) * time.Millisecond
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
func (l *SlidingWindowLimiter) GetLimit(key string) *Limit {
	return &Limit{
		Requests: l.limit,
		Window:   l.window,
		Burst:    l.limit,
	}
}

// Reset implements Limiter.
func (l *SlidingWindowLimiter) Reset(ctx context.Context, key string) error {
	// Reset local state
	l.windows.Delete(key)

	// Reset distributed state
	if l.store != nil {
		now := time.Now()
		nowMs := now.UnixMilli()
		windowMs := l.window.Milliseconds()
		subWindowSize := windowMs / int64(l.precision)
		currentSubWindow := nowMs / subWindowSize

		for i := 0; i < l.precision; i++ {
			// Fix: Use strconv.FormatInt instead of string(rune()) which doesn't work for numbers > 127
			subWindowKey := key + ":sw:" + strconv.FormatInt(currentSubWindow-int64(i), 10)
			if err := l.store.Delete(ctx, subWindowKey); err != nil {
				l.logger.Warn("failed to delete sub-window", zap.Error(err))
			}
		}
	}

	return nil
}

// Cleanup removes stale window states from memory.
func (l *SlidingWindowLimiter) Cleanup(maxAge time.Duration) {
	now := time.Now()
	windowStart := now.Add(-maxAge)

	l.windows.Range(func(key, value interface{}) bool {
		ws := value.(*windowState)
		ws.mu.Lock()

		// Check if all requests are old
		allOld := true
		for _, t := range ws.requests {
			if t.After(windowStart) {
				allOld = false
				break
			}
		}

		if allOld {
			l.windows.Delete(key)
		}

		ws.mu.Unlock()
		return true
	})
}
