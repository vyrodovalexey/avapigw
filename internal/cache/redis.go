// Package cache provides caching capabilities for the API Gateway.
package cache

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Retry configuration constants for Redis operations.
const (
	// redisMaxRetries is the maximum number of retry attempts for Redis operations.
	redisMaxRetries = 3

	// redisBaseDelay is the base delay for exponential backoff.
	redisBaseDelay = 100 * time.Millisecond

	// redisMaxDelay is the maximum delay between retries.
	redisMaxDelay = 2 * time.Second
)

// isRetryableError checks if the error is retryable (network/connection errors).
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	// Don't retry on cache miss or context errors
	if errors.Is(err, redis.Nil) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// Retry on connection/network errors
	return true
}

// calculateBackoff calculates the delay for exponential backoff with jitter.
func calculateBackoff(attempt int) time.Duration {
	delay := time.Duration(float64(redisBaseDelay) * math.Pow(2, float64(attempt)))
	if delay > redisMaxDelay {
		delay = redisMaxDelay
	}
	return delay
}

// redisCache implements a Redis-based cache.
type redisCache struct {
	logger     observability.Logger
	client     *redis.Client
	keyPrefix  string
	defaultTTL time.Duration

	hits   int64
	misses int64
}

// newRedisCache creates a new Redis cache.
func newRedisCache(cfg *config.CacheConfig, logger observability.Logger) (*redisCache, error) {
	if cfg.Redis == nil || cfg.Redis.URL == "" {
		return nil, errors.New("redis URL is required")
	}

	opts, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		return nil, errors.New("invalid redis URL: " + err.Error())
	}

	// Apply configuration overrides
	if cfg.Redis.PoolSize > 0 {
		opts.PoolSize = cfg.Redis.PoolSize
	}

	if cfg.Redis.ConnectTimeout > 0 {
		opts.DialTimeout = cfg.Redis.ConnectTimeout.Duration()
	}

	if cfg.Redis.ReadTimeout > 0 {
		opts.ReadTimeout = cfg.Redis.ReadTimeout.Duration()
	}

	if cfg.Redis.WriteTimeout > 0 {
		opts.WriteTimeout = cfg.Redis.WriteTimeout.Duration()
	}

	// Configure TLS if enabled
	if cfg.Redis.TLS != nil && cfg.Redis.TLS.Enabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.Redis.TLS.InsecureSkipVerify, //nolint:gosec // User-configurable
		}
		opts.TLSConfig = tlsConfig
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close() // Ignore close error during initialization failure
		return nil, errors.New("redis connection failed: " + err.Error())
	}

	keyPrefix := cfg.Redis.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "avapigw:"
	}

	c := &redisCache{
		logger:     logger,
		client:     client,
		keyPrefix:  keyPrefix,
		defaultTTL: cfg.TTL.Duration(),
	}

	logger.Info("redis cache initialized",
		observability.String("keyPrefix", keyPrefix),
		observability.Duration("defaultTTL", c.defaultTTL))

	return c, nil
}

// Get retrieves a value from the cache with exponential backoff retry.
func (c *redisCache) Get(ctx context.Context, key string) ([]byte, error) {
	// Check for context cancellation before proceeding
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	fullKey := c.keyPrefix + key

	var result []byte
	var lastErr error

	for attempt := 0; attempt <= redisMaxRetries; attempt++ {
		if attempt > 0 {
			// Wait with exponential backoff before retry
			delay := calculateBackoff(attempt - 1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
			c.logger.Debug("retrying redis get",
				observability.String("key", key),
				observability.Int("attempt", attempt))
		}

		result, lastErr = c.client.Get(ctx, fullKey).Bytes()
		if lastErr == nil {
			atomic.AddInt64(&c.hits, 1)
			c.logger.Debug("cache hit",
				observability.String("key", key),
				observability.Int("size", len(result)))
			return result, nil
		}

		if errors.Is(lastErr, redis.Nil) {
			atomic.AddInt64(&c.misses, 1)
			return nil, ErrCacheMiss
		}

		if !isRetryableError(lastErr) {
			break
		}
	}

	c.logger.Error("redis get failed",
		observability.String("key", key),
		observability.Error(lastErr))
	return nil, lastErr
}

// Set stores a value in the cache with exponential backoff retry.
func (c *redisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	// Check for context cancellation before proceeding
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	fullKey := c.keyPrefix + key

	var lastErr error

	for attempt := 0; attempt <= redisMaxRetries; attempt++ {
		if attempt > 0 {
			// Wait with exponential backoff before retry
			delay := calculateBackoff(attempt - 1)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			c.logger.Debug("retrying redis set",
				observability.String("key", key),
				observability.Int("attempt", attempt))
		}

		lastErr = c.client.Set(ctx, fullKey, value, ttl).Err()
		if lastErr == nil {
			c.logger.Debug("cache set",
				observability.String("key", key),
				observability.Duration("ttl", ttl),
				observability.Int("size", len(value)))
			return nil
		}

		if !isRetryableError(lastErr) {
			break
		}
	}

	c.logger.Error("redis set failed",
		observability.String("key", key),
		observability.Error(lastErr))
	return lastErr
}

// Delete removes a value from the cache with exponential backoff retry.
func (c *redisCache) Delete(ctx context.Context, key string) error {
	// Check for context cancellation before proceeding
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	fullKey := c.keyPrefix + key

	var lastErr error

	for attempt := 0; attempt <= redisMaxRetries; attempt++ {
		if attempt > 0 {
			// Wait with exponential backoff before retry
			delay := calculateBackoff(attempt - 1)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			c.logger.Debug("retrying redis delete",
				observability.String("key", key),
				observability.Int("attempt", attempt))
		}

		lastErr = c.client.Del(ctx, fullKey).Err()
		if lastErr == nil {
			c.logger.Debug("cache deleted",
				observability.String("key", key))
			return nil
		}

		if !isRetryableError(lastErr) {
			break
		}
	}

	c.logger.Error("redis delete failed",
		observability.String("key", key),
		observability.Error(lastErr))
	return lastErr
}

// Exists checks if a key exists in the cache with exponential backoff retry.
func (c *redisCache) Exists(ctx context.Context, key string) (bool, error) {
	// Check for context cancellation before proceeding
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	fullKey := c.keyPrefix + key

	var result int64
	var lastErr error

	for attempt := 0; attempt <= redisMaxRetries; attempt++ {
		if attempt > 0 {
			// Wait with exponential backoff before retry
			delay := calculateBackoff(attempt - 1)
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(delay):
			}
			c.logger.Debug("retrying redis exists",
				observability.String("key", key),
				observability.Int("attempt", attempt))
		}

		result, lastErr = c.client.Exists(ctx, fullKey).Result()
		if lastErr == nil {
			return result > 0, nil
		}

		if !isRetryableError(lastErr) {
			break
		}
	}

	c.logger.Error("redis exists failed",
		observability.String("key", key),
		observability.Error(lastErr))
	return false, lastErr
}

// Close closes the Redis connection.
func (c *redisCache) Close() error {
	c.logger.Info("redis cache closing")
	return c.client.Close()
}

// Stats returns cache statistics.
func (c *redisCache) Stats() CacheStats {
	return CacheStats{
		Hits:   atomic.LoadInt64(&c.hits),
		Misses: atomic.LoadInt64(&c.misses),
	}
}

// GetWithTTL retrieves a value and its remaining TTL from the cache.
func (c *redisCache) GetWithTTL(ctx context.Context, key string) ([]byte, time.Duration, error) {
	// Check for context cancellation before proceeding
	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	default:
	}

	fullKey := c.keyPrefix + key

	// Use pipeline to get value and TTL in one round trip
	pipe := c.client.Pipeline()
	getCmd := pipe.Get(ctx, fullKey)
	ttlCmd := pipe.TTL(ctx, fullKey)

	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		c.logger.Error("redis pipeline failed",
			observability.String("key", key),
			observability.Error(err))
		return nil, 0, err
	}

	value, err := getCmd.Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			atomic.AddInt64(&c.misses, 1)
			return nil, 0, ErrCacheMiss
		}
		return nil, 0, err
	}

	ttl := ttlCmd.Val()
	if ttl < 0 {
		ttl = 0
	}

	atomic.AddInt64(&c.hits, 1)

	return value, ttl, nil
}

// SetNX sets a value only if the key does not exist.
func (c *redisCache) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	// Check for context cancellation before proceeding
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	fullKey := c.keyPrefix + key

	result, err := c.client.SetNX(ctx, fullKey, value, ttl).Result()
	if err != nil {
		c.logger.Error("redis setnx failed",
			observability.String("key", key),
			observability.Error(err))
		return false, err
	}

	if result {
		c.logger.Debug("cache setnx succeeded",
			observability.String("key", key),
			observability.Duration("ttl", ttl))
	}

	return result, nil
}

// Expire updates the TTL of an existing key.
func (c *redisCache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	// Check for context cancellation before proceeding
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	fullKey := c.keyPrefix + key

	err := c.client.Expire(ctx, fullKey, ttl).Err()
	if err != nil {
		c.logger.Error("redis expire failed",
			observability.String("key", key),
			observability.Error(err))
		return err
	}

	return nil
}
