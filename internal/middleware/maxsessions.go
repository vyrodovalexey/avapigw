// Package middleware provides HTTP middleware components for the API Gateway.
package middleware

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// MaxSessionsLimiter provides maximum concurrent sessions limiting.
type MaxSessionsLimiter struct {
	maxConcurrent atomic.Int64
	current       atomic.Int64
	queueSize     int
	queueTimeout  time.Duration
	queue         chan struct{}
	logger        observability.Logger
	mu            sync.RWMutex
	stopped       bool
	stopCh        chan struct{}
}

// MaxSessionsOption is a functional option for configuring the max sessions limiter.
type MaxSessionsOption func(*MaxSessionsLimiter)

// WithMaxSessionsLogger sets the logger for the max sessions limiter.
func WithMaxSessionsLogger(logger observability.Logger) MaxSessionsOption {
	return func(msl *MaxSessionsLimiter) {
		msl.logger = logger
	}
}

// NewMaxSessionsLimiter creates a new max sessions limiter.
func NewMaxSessionsLimiter(
	maxConcurrent, queueSize int,
	queueTimeout time.Duration,
	opts ...MaxSessionsOption,
) *MaxSessionsLimiter {
	msl := &MaxSessionsLimiter{
		queueSize:    queueSize,
		queueTimeout: queueTimeout,
		logger:       observability.NopLogger(),
		stopCh:       make(chan struct{}),
	}
	msl.maxConcurrent.Store(int64(maxConcurrent))

	// Initialize queue if queueSize > 0
	if queueSize > 0 {
		msl.queue = make(chan struct{}, queueSize)
	}

	for _, opt := range opts {
		opt(msl)
	}

	return msl
}

// Acquire attempts to acquire a session slot.
// Returns true if a slot was acquired, false otherwise.
func (msl *MaxSessionsLimiter) Acquire(ctx context.Context) bool {
	// Try to acquire immediately
	if msl.tryAcquire() {
		return true
	}

	// If no queue, reject immediately
	if msl.queueSize == 0 {
		return false
	}

	// Try to enter the queue
	select {
	case msl.queue <- struct{}{}:
		// Successfully entered queue, now wait for a slot
		defer func() { <-msl.queue }()
		return msl.waitForSlot(ctx)
	default:
		// Queue is full
		return false
	}
}

// tryAcquire attempts to acquire a slot without waiting.
func (msl *MaxSessionsLimiter) tryAcquire() bool {
	for {
		current := msl.current.Load()
		if current >= msl.maxConcurrent.Load() {
			return false
		}
		if msl.current.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// waitForSlot waits for a slot to become available.
func (msl *MaxSessionsLimiter) waitForSlot(ctx context.Context) bool {
	timeout := msl.queueTimeout
	if timeout <= 0 {
		timeout = config.DefaultMaxSessionsQueueTimeout
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCtx.Done():
			return false
		case <-msl.stopCh:
			return false
		case <-ticker.C:
			if msl.tryAcquire() {
				return true
			}
		}
	}
}

// Release releases a session slot.
func (msl *MaxSessionsLimiter) Release() {
	msl.current.Add(-1)
}

// Current returns the current number of active sessions.
func (msl *MaxSessionsLimiter) Current() int64 {
	return msl.current.Load()
}

// MaxConcurrent returns the maximum concurrent sessions limit.
func (msl *MaxSessionsLimiter) MaxConcurrent() int64 {
	return msl.maxConcurrent.Load()
}

// QueueLength returns the current queue length.
func (msl *MaxSessionsLimiter) QueueLength() int {
	if msl.queue == nil {
		return 0
	}
	return len(msl.queue)
}

// UpdateConfig updates the max sessions limiter configuration.
// Only maxConcurrent is updated atomically; queueSize and
// queueTimeout cannot be changed at runtime because the queue
// channel is fixed at creation time.
func (msl *MaxSessionsLimiter) UpdateConfig(
	cfg *config.MaxSessionsConfig,
) {
	if cfg == nil {
		return
	}

	msl.mu.Lock()
	defer msl.mu.Unlock()

	msl.maxConcurrent.Store(int64(cfg.MaxConcurrent))
	msl.queueTimeout = cfg.GetEffectiveQueueTimeout()

	msl.logger.Info("max sessions configuration updated",
		observability.Int("maxConcurrent", cfg.MaxConcurrent),
		observability.Duration("queueTimeout", msl.queueTimeout),
	)
}

// Stop stops the max sessions limiter.
func (msl *MaxSessionsLimiter) Stop() {
	msl.mu.Lock()
	defer msl.mu.Unlock()

	if !msl.stopped {
		msl.stopped = true
		close(msl.stopCh)
	}
}

// MaxSessions returns a middleware that limits maximum concurrent sessions.
func MaxSessions(msl *MaxSessionsLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mm := GetMiddlewareMetrics()

			if !msl.Acquire(r.Context()) {
				msl.logger.Warn("max sessions exceeded",
					observability.String("path", r.URL.Path),
					observability.String("method", r.Method),
					observability.Int64("current", msl.Current()),
					observability.Int64("max", msl.MaxConcurrent()),
				)

				mm.maxSessionsRejected.Inc()

				w.Header().Set(HeaderContentType, ContentTypeJSON)
				w.Header().Set(HeaderRetryAfter, "1")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, ErrMaxSessionsExceeded)
				return
			}

			mm.maxSessionsCurrent.Set(
				float64(msl.Current()),
			)

			defer func() {
				msl.Release()
				mm.maxSessionsCurrent.Set(
					float64(msl.Current()),
				)
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// MaxSessionsFromConfig creates max sessions middleware from gateway config.
// Returns the middleware and the limiter for lifecycle management.
// The caller should call Stop() on the limiter during shutdown.
func MaxSessionsFromConfig(
	cfg *config.MaxSessionsConfig,
	logger observability.Logger,
) (func(http.Handler) http.Handler, *MaxSessionsLimiter) {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}, nil
	}

	queueTimeout := cfg.GetEffectiveQueueTimeout()
	msl := NewMaxSessionsLimiter(
		cfg.MaxConcurrent,
		cfg.QueueSize,
		queueTimeout,
		WithMaxSessionsLogger(logger),
	)

	logger.Info("max sessions limiter initialized",
		observability.Int("maxConcurrent", cfg.MaxConcurrent),
		observability.Int("queueSize", cfg.QueueSize),
		observability.Duration("queueTimeout", queueTimeout),
	)

	return MaxSessions(msl), msl
}
