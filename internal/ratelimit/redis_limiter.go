// Package ratelimit provides rate limiting functionality for the API Gateway.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
	"github.com/vyrodovalexey/avapigw/internal/ratelimit/store"
	"go.uber.org/zap"
)

// Ensure RedisRateLimiter implements Limiter and io.Closer interfaces
var (
	_ Limiter   = (*RedisRateLimiter)(nil)
	_ io.Closer = (*RedisRateLimiter)(nil)
)

// Redis rate limiter errors
var (
	// ErrRedisUnavailable indicates Redis is not available.
	ErrRedisUnavailable = errors.New("redis is unavailable")

	// ErrFallbackUsed indicates the fallback limiter was used.
	ErrFallbackUsed = errors.New("fallback rate limiter used")
)

// RedisRateLimiterConfig holds configuration for the Redis rate limiter.
type RedisRateLimiterConfig struct {
	// Algorithm is the rate limiting algorithm to use.
	Algorithm Algorithm

	// Requests is the maximum number of requests allowed in the window.
	Requests int

	// Window is the time window for the rate limit.
	Window time.Duration

	// Burst is the maximum burst size (for token bucket algorithm).
	Burst int

	// Precision is the number of sub-windows (for sliding window algorithm).
	Precision int

	// Redis configuration
	RedisConfig *store.RedisConfig

	// Circuit breaker configuration
	CircuitBreakerConfig *circuitbreaker.Config

	// FallbackEnabled enables local fallback when Redis is unavailable.
	FallbackEnabled bool

	// HealthCheckInterval is the interval for Redis health checks.
	HealthCheckInterval time.Duration

	// Logger for the rate limiter.
	Logger *zap.Logger
}

// DefaultRedisRateLimiterConfig returns a RedisRateLimiterConfig with default values.
func DefaultRedisRateLimiterConfig() *RedisRateLimiterConfig {
	return &RedisRateLimiterConfig{
		Algorithm:            AlgorithmTokenBucket,
		Requests:             100,
		Window:               time.Minute,
		Burst:                10,
		Precision:            10,
		RedisConfig:          store.DefaultRedisConfig(),
		CircuitBreakerConfig: circuitbreaker.DefaultConfig(),
		FallbackEnabled:      true,
		HealthCheckInterval:  5 * time.Second,
	}
}

// Prometheus metrics for Redis rate limiter operations
var (
	redisRateLimitOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_ratelimit_operations_total",
			Help: "Total number of Redis rate limit operations",
		},
		[]string{"operation", "status"},
	)

	redisRateLimitOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "redis_ratelimit_operation_duration_seconds",
			Help:    "Duration of Redis rate limit operations in seconds",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		},
		[]string{"operation", "algorithm"},
	)

	redisRateLimitFallbackTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "redis_ratelimit_fallback_total",
			Help: "Total number of times fallback rate limiter was used",
		},
	)

	redisRateLimitConnectionErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "redis_ratelimit_connection_errors_total",
			Help: "Total number of Redis connection errors in rate limiter",
		},
	)

	redisRateLimitHealthy = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "redis_ratelimit_healthy",
			Help: "Whether Redis rate limiter is healthy (1) or not (0)",
		},
	)
)

// RedisRateLimiter implements distributed rate limiting using Redis.
// It supports token bucket, sliding window, and fixed window algorithms
// using atomic Lua scripts for consistency.
type RedisRateLimiter struct {
	config          *RedisRateLimiterConfig
	redisStore      *store.RedisStore
	circuitBreaker  *circuitbreaker.CircuitBreaker
	fallbackLimiter Limiter
	logger          *zap.Logger

	// Health check state
	healthy         atomic.Bool
	stopHealthCheck chan struct{}
	healthCheckOnce sync.Once
}

// NewRedisRateLimiter creates a new Redis-based rate limiter.
func NewRedisRateLimiter(config *RedisRateLimiterConfig) (*RedisRateLimiter, error) {
	if config == nil {
		config = DefaultRedisRateLimiterConfig()
	}

	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	if config.RedisConfig == nil {
		config.RedisConfig = store.DefaultRedisConfig()
	}

	// Create Redis store
	redisStore, err := store.NewRedisStoreWithConfig(config.RedisConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis store: %w", err)
	}

	// Create circuit breaker for Redis operations
	cbConfig := config.CircuitBreakerConfig
	if cbConfig == nil {
		cbConfig = circuitbreaker.DefaultConfig()
	}
	cb := circuitbreaker.NewCircuitBreaker("redis-ratelimit", cbConfig, config.Logger)

	limiter := &RedisRateLimiter{
		config:          config,
		redisStore:      redisStore,
		circuitBreaker:  cb,
		logger:          config.Logger,
		stopHealthCheck: make(chan struct{}),
	}

	// Set initial health state
	limiter.healthy.Store(true)
	redisRateLimitHealthy.Set(1)

	// Create fallback limiter if enabled
	if config.FallbackEnabled {
		limiter.fallbackLimiter = limiter.createFallbackLimiter()
	}

	// Start health check goroutine
	go limiter.startHealthCheck()

	config.Logger.Info("Redis rate limiter created",
		zap.String("algorithm", string(config.Algorithm)),
		zap.Int("requests", config.Requests),
		zap.Duration("window", config.Window),
		zap.Int("burst", config.Burst),
		zap.Bool("fallback_enabled", config.FallbackEnabled),
	)

	return limiter, nil
}

// createFallbackLimiter creates a local in-memory fallback limiter.
func (r *RedisRateLimiter) createFallbackLimiter() Limiter {
	switch r.config.Algorithm {
	case AlgorithmTokenBucket:
		rate := float64(r.config.Requests) / r.config.Window.Seconds()
		return NewTokenBucketLimiter(nil, rate, r.config.Burst, r.logger)
	case AlgorithmSlidingWindow:
		return NewSlidingWindowLimiterWithPrecision(
			nil, r.config.Requests, r.config.Window, r.config.Precision, r.logger)
	case AlgorithmFixedWindow:
		return NewFixedWindowLimiter(nil, r.config.Requests, r.config.Window, r.logger)
	default:
		rate := float64(r.config.Requests) / r.config.Window.Seconds()
		return NewTokenBucketLimiter(nil, rate, r.config.Burst, r.logger)
	}
}

// startHealthCheck runs periodic health checks on Redis connection.
func (r *RedisRateLimiter) startHealthCheck() {
	ticker := time.NewTicker(r.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.checkHealth()
		case <-r.stopHealthCheck:
			return
		}
	}
}

// checkHealth checks the Redis connection health.
func (r *RedisRateLimiter) checkHealth() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := r.redisStore.Client().Ping(ctx).Err()
	wasHealthy := r.healthy.Load()

	if err != nil {
		r.healthy.Store(false)
		redisRateLimitHealthy.Set(0)
		redisRateLimitConnectionErrors.Inc()

		if wasHealthy {
			r.logger.Warn("Redis rate limiter health check failed",
				zap.Error(err),
			)
		}
	} else {
		r.healthy.Store(true)
		redisRateLimitHealthy.Set(1)

		if !wasHealthy {
			r.logger.Info("Redis rate limiter recovered")
		}
	}
}

// IsHealthy returns whether the Redis connection is healthy.
func (r *RedisRateLimiter) IsHealthy() bool {
	return r.healthy.Load()
}

// Allow implements Limiter.
func (r *RedisRateLimiter) Allow(ctx context.Context, key string) (*Result, error) {
	return r.AllowN(ctx, key, 1)
}

// AllowN implements Limiter.
func (r *RedisRateLimiter) AllowN(ctx context.Context, key string, n int) (*Result, error) {
	start := time.Now()

	// Try Redis first with circuit breaker protection
	var result *Result
	var err error

	cbErr := r.circuitBreaker.Execute(ctx, func() error {
		result, err = r.allowRedis(ctx, key, n)
		return err
	})

	duration := time.Since(start)

	// Handle circuit breaker open or Redis error
	if cbErr != nil || err != nil {
		actualErr := cbErr
		if actualErr == nil {
			actualErr = err
		}

		// Record error metrics
		redisRateLimitOperationsTotal.WithLabelValues("allow", "error").Inc()
		redisRateLimitOperationDuration.WithLabelValues("allow", string(r.config.Algorithm)).Observe(duration.Seconds())

		// Use fallback if enabled
		if r.config.FallbackEnabled && r.fallbackLimiter != nil {
			r.logger.Debug("Using fallback rate limiter",
				zap.String("key", key),
				zap.Error(actualErr),
			)
			redisRateLimitFallbackTotal.Inc()
			return r.fallbackLimiter.AllowN(ctx, key, n)
		}

		return nil, fmt.Errorf("redis rate limit failed: %w", actualErr)
	}

	// Record success metrics
	redisRateLimitOperationsTotal.WithLabelValues("allow", "success").Inc()
	redisRateLimitOperationDuration.WithLabelValues("allow", string(r.config.Algorithm)).Observe(duration.Seconds())

	return result, nil
}

// allowRedis performs rate limiting using Redis Lua scripts.
func (r *RedisRateLimiter) allowRedis(ctx context.Context, key string, n int) (*Result, error) {
	switch r.config.Algorithm {
	case AlgorithmTokenBucket:
		return r.tokenBucketAllow(ctx, key, n)
	case AlgorithmSlidingWindow:
		return r.slidingWindowAllow(ctx, key, n)
	case AlgorithmFixedWindow:
		return r.fixedWindowAllow(ctx, key, n)
	default:
		return r.tokenBucketAllow(ctx, key, n)
	}
}

// tokenBucketAllow performs token bucket rate limiting using Redis.
func (r *RedisRateLimiter) tokenBucketAllow(ctx context.Context, key string, n int) (*Result, error) {
	now := time.Now().UnixMilli()
	rate := float64(r.config.Requests) / r.config.Window.Seconds()

	result, err := store.TokenBucketScript.Run(ctx, r.redisStore.Client(),
		[]string{r.prefixKey(key)},
		rate,
		r.config.Burst,
		now,
		n,
	).Result()

	if err != nil {
		return nil, fmt.Errorf("token bucket script error: %w", err)
	}

	return r.parseScriptResult(result, r.config.Burst)
}

// slidingWindowAllow performs sliding window rate limiting using Redis.
func (r *RedisRateLimiter) slidingWindowAllow(ctx context.Context, key string, n int) (*Result, error) {
	now := time.Now().UnixMilli()
	windowMs := r.config.Window.Milliseconds()

	result, err := store.SlidingWindowScript.Run(ctx, r.redisStore.Client(),
		[]string{r.prefixKey(key)},
		r.config.Requests,
		windowMs,
		now,
		n,
	).Result()

	if err != nil {
		return nil, fmt.Errorf("sliding window script error: %w", err)
	}

	return r.parseScriptResult(result, r.config.Requests)
}

// fixedWindowAllow performs fixed window rate limiting using Redis.
func (r *RedisRateLimiter) fixedWindowAllow(ctx context.Context, key string, n int) (*Result, error) {
	now := time.Now().UnixMilli()
	windowMs := r.config.Window.Milliseconds()

	result, err := store.FixedWindowScript.Run(ctx, r.redisStore.Client(),
		[]string{r.prefixKey(key)},
		r.config.Requests,
		windowMs,
		now,
		n,
	).Result()

	if err != nil {
		return nil, fmt.Errorf("fixed window script error: %w", err)
	}

	return r.parseScriptResult(result, r.config.Requests)
}

// parseScriptResult parses the result from Lua scripts.
// All scripts return: [allowed (0 or 1), remaining, reset_ms]
func (r *RedisRateLimiter) parseScriptResult(result interface{}, limit int) (*Result, error) {
	values, ok := result.([]interface{})
	if !ok || len(values) < 3 {
		return nil, fmt.Errorf("unexpected script result format: %v", result)
	}

	allowed := false
	if v, ok := values[0].(int64); ok && v == 1 {
		allowed = true
	}

	remaining := 0
	if v, ok := values[1].(int64); ok {
		remaining = int(v)
		if remaining < 0 {
			remaining = 0
		}
	}

	resetMs := int64(0)
	if v, ok := values[2].(int64); ok {
		resetMs = v
	}

	resetAfter := time.Duration(resetMs) * time.Millisecond
	var retryAfter time.Duration
	if !allowed {
		retryAfter = resetAfter
	}

	return &Result{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		ResetAfter: resetAfter,
		RetryAfter: retryAfter,
	}, nil
}

// prefixKey adds the rate limit prefix to the key.
func (r *RedisRateLimiter) prefixKey(key string) string {
	return r.config.RedisConfig.Prefix + key
}

// GetLimit implements Limiter.
func (r *RedisRateLimiter) GetLimit(key string) *Limit {
	return &Limit{
		Requests: r.config.Requests,
		Window:   r.config.Window,
		Burst:    r.config.Burst,
	}
}

// Reset implements Limiter.
func (r *RedisRateLimiter) Reset(ctx context.Context, key string) error {
	start := time.Now()

	err := r.circuitBreaker.Execute(ctx, func() error {
		return r.redisStore.Delete(ctx, r.prefixKey(key))
	})

	duration := time.Since(start)

	if err != nil {
		redisRateLimitOperationsTotal.WithLabelValues("reset", "error").Inc()
		redisRateLimitOperationDuration.WithLabelValues("reset", string(r.config.Algorithm)).Observe(duration.Seconds())

		// Also reset fallback limiter if available
		if r.fallbackLimiter != nil {
			_ = r.fallbackLimiter.Reset(ctx, key)
		}

		return fmt.Errorf("failed to reset rate limit: %w", err)
	}

	redisRateLimitOperationsTotal.WithLabelValues("reset", "success").Inc()
	redisRateLimitOperationDuration.WithLabelValues("reset", string(r.config.Algorithm)).Observe(duration.Seconds())

	// Also reset fallback limiter if available
	if r.fallbackLimiter != nil {
		_ = r.fallbackLimiter.Reset(ctx, key)
	}

	return nil
}

// Close implements io.Closer.
func (r *RedisRateLimiter) Close() error {
	r.healthCheckOnce.Do(func() {
		close(r.stopHealthCheck)
	})

	// Close fallback limiter if it implements io.Closer
	if closer, ok := r.fallbackLimiter.(io.Closer); ok {
		_ = closer.Close()
	}

	// Close Redis store
	if r.redisStore != nil {
		return r.redisStore.Close()
	}

	return nil
}

// GetCircuitBreakerState returns the current circuit breaker state.
func (r *RedisRateLimiter) GetCircuitBreakerState() circuitbreaker.State {
	return r.circuitBreaker.State()
}

// GetCircuitBreakerStats returns the circuit breaker statistics.
func (r *RedisRateLimiter) GetCircuitBreakerStats() circuitbreaker.Stats {
	return r.circuitBreaker.Stats()
}

// ResetCircuitBreaker resets the circuit breaker to closed state.
func (r *RedisRateLimiter) ResetCircuitBreaker() {
	r.circuitBreaker.Reset()
}
