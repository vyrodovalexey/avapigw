package ratelimit

import (
	"fmt"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/ratelimit/store"
	"go.uber.org/zap"
)

// FactoryConfig holds configuration for creating rate limiters.
type FactoryConfig struct {
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

	// StoreType is the type of store to use (memory, redis, redis_distributed).
	// - "memory": In-memory rate limiting (single instance only)
	// - "redis": Redis-backed rate limiting using basic store operations
	// - "redis_distributed": Redis-backed rate limiting using atomic Lua scripts
	//   with circuit breaker and fallback support (recommended for production)
	StoreType string

	// Redis configuration (if StoreType is redis or redis_distributed)
	RedisAddress  string
	RedisPassword string
	RedisDB       int
	RedisPrefix   string

	// FallbackEnabled enables local fallback when Redis is unavailable.
	// Only applicable when StoreType is "redis_distributed".
	FallbackEnabled bool

	// HealthCheckInterval is the interval for Redis health checks.
	// Only applicable when StoreType is "redis_distributed".
	HealthCheckInterval time.Duration

	// Logger for the rate limiter.
	Logger *zap.Logger
}

// DefaultFactoryConfig returns a FactoryConfig with default values.
func DefaultFactoryConfig() *FactoryConfig {
	return &FactoryConfig{
		Algorithm:           AlgorithmTokenBucket,
		Requests:            100,
		Window:              time.Minute,
		Burst:               10,
		Precision:           10,
		StoreType:           "memory",
		RedisPrefix:         "ratelimit:",
		FallbackEnabled:     true,
		HealthCheckInterval: 5 * time.Second,
	}
}

// NewLimiter creates a new rate limiter based on the configuration.
func NewLimiter(config *FactoryConfig) (Limiter, error) {
	if config == nil {
		config = DefaultFactoryConfig()
	}

	// For redis_distributed, use the RedisRateLimiter with Lua scripts
	if config.StoreType == "redis_distributed" {
		return NewRedisDistributedLimiter(config)
	}

	// Create store for other store types
	var s store.Store
	var err error

	switch config.StoreType {
	case "memory", "":
		s = store.NewMemoryStore()
	case "redis":
		s, err = store.NewRedisStore(
			config.RedisAddress,
			config.RedisPassword,
			config.RedisDB,
			config.RedisPrefix,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create Redis store: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown store type: %s", config.StoreType)
	}

	// Create limiter based on algorithm
	switch config.Algorithm {
	case AlgorithmTokenBucket, "":
		rate := float64(config.Requests) / config.Window.Seconds()
		return NewTokenBucketLimiter(s, rate, config.Burst, config.Logger), nil

	case AlgorithmSlidingWindow:
		return NewSlidingWindowLimiterWithPrecision(s, config.Requests, config.Window, config.Precision, config.Logger), nil

	case AlgorithmFixedWindow:
		return NewFixedWindowLimiter(s, config.Requests, config.Window, config.Logger), nil

	default:
		return nil, fmt.Errorf("unknown algorithm: %s", config.Algorithm)
	}
}

// NewRedisDistributedLimiter creates a Redis-based distributed rate limiter
// using atomic Lua scripts with circuit breaker and fallback support.
func NewRedisDistributedLimiter(config *FactoryConfig) (Limiter, error) {
	redisConfig := &RedisRateLimiterConfig{
		Algorithm: config.Algorithm,
		Requests:  config.Requests,
		Window:    config.Window,
		Burst:     config.Burst,
		Precision: config.Precision,
		RedisConfig: &store.RedisConfig{
			Address:  config.RedisAddress,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
			Prefix:   config.RedisPrefix,
		},
		FallbackEnabled:     config.FallbackEnabled,
		HealthCheckInterval: config.HealthCheckInterval,
		Logger:              config.Logger,
	}

	return NewRedisRateLimiter(redisConfig)
}

// NewLimiterFromEnv creates a rate limiter from environment-based configuration.
func NewLimiterFromEnv(
	algorithm string,
	requests int,
	window time.Duration,
	burst int,
	storeType string,
	redisAddr string,
	redisPassword string,
	redisDB int,
	logger *zap.Logger,
) (Limiter, error) {
	config := &FactoryConfig{
		Algorithm:     Algorithm(algorithm),
		Requests:      requests,
		Window:        window,
		Burst:         burst,
		StoreType:     storeType,
		RedisAddress:  redisAddr,
		RedisPassword: redisPassword,
		RedisDB:       redisDB,
		Logger:        logger,
	}

	return NewLimiter(config)
}

// MustNewLimiter creates a new rate limiter and panics on error.
func MustNewLimiter(config *FactoryConfig) Limiter {
	limiter, err := NewLimiter(config)
	if err != nil {
		panic(err)
	}
	return limiter
}
