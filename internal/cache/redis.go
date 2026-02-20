// Package cache provides caching capabilities for the API Gateway.
package cache

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// redisRetryConfig returns the retry configuration for Redis operations.
func redisRetryConfig() *retry.Config {
	return &retry.Config{
		MaxRetries:     3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     2 * time.Second,
		JitterFactor:   retry.DefaultJitterFactor,
	}
}

// isRetryableRedisError checks if the error is retryable (network/connection errors).
func isRetryableRedisError(err error) bool {
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

// redisCache implements a Redis-based cache.
type redisCache struct {
	logger     observability.Logger
	client     *redis.Client
	keyPrefix  string
	defaultTTL time.Duration
	ttlJitter  float64
	hashKeys   bool

	hits   int64
	misses int64
}

// applyTTLJitter adds random jitter to a TTL value to prevent thundering herd.
// The jitterFactor controls the maximum percentage of variation (0.0 to 1.0).
// For example, a jitterFactor of 0.1 means the TTL will vary by ±10%.
func applyTTLJitter(ttl time.Duration, jitterFactor float64) time.Duration {
	if jitterFactor <= 0 || ttl <= 0 {
		return ttl
	}
	// Clamp jitter factor to [0, 1]
	if jitterFactor > 1.0 {
		jitterFactor = 1.0
	}
	// Add random jitter: ttl * (1 ± jitterFactor)
	//nolint:gosec // G404: math/rand is acceptable here - TTL jitter does not require cryptographic randomness
	jitter := time.Duration(float64(ttl) * jitterFactor * (2*rand.Float64() - 1))
	result := ttl + jitter
	if result <= 0 {
		return ttl // Safety: never return non-positive TTL
	}
	return result
}

// resolveKey applies key prefix and optional SHA256 hashing.
func (c *redisCache) resolveKey(key string) string {
	if c.hashKeys {
		return c.keyPrefix + HashKey(key)
	}
	return c.keyPrefix + key
}

// hasVaultPasswordPaths checks if any vault password paths are configured.
func hasVaultPasswordPaths(cfg *config.RedisCacheConfig) bool {
	if cfg.PasswordVaultPath != "" {
		return true
	}
	if cfg.Sentinel == nil {
		return false
	}
	return cfg.Sentinel.PasswordVaultPath != "" ||
		cfg.Sentinel.SentinelPasswordVaultPath != ""
}

// resolveRedisPasswords resolves Redis passwords from Vault if vault paths are configured.
// It reads secrets from the Vault KV engine and updates the config with the retrieved passwords.
func resolveRedisPasswords(
	cfg *config.RedisCacheConfig, vaultClient vault.Client, logger observability.Logger,
) error {
	if !hasVaultPasswordPaths(cfg) {
		return nil
	}

	if vaultClient == nil || !vaultClient.IsEnabled() {
		logger.Warn("redis vault paths configured but vault client is not available")
		return nil
	}

	// Resolve standalone password from vault
	if cfg.PasswordVaultPath != "" {
		if err := resolveStandalonePassword(cfg, vaultClient, logger); err != nil {
			return err
		}
	}

	// Resolve sentinel passwords from vault
	if cfg.Sentinel != nil {
		if err := resolveSentinelPasswords(cfg.Sentinel, vaultClient, logger); err != nil {
			return err
		}
	}

	return nil
}

// resolveStandalonePassword resolves the standalone Redis password from Vault.
func resolveStandalonePassword(
	cfg *config.RedisCacheConfig, vaultClient vault.Client, logger observability.Logger,
) error {
	pw, err := readVaultPassword(vaultClient, cfg.PasswordVaultPath)
	if err != nil {
		return fmt.Errorf("failed to read redis password from vault path %s: %w",
			cfg.PasswordVaultPath, err)
	}
	if err := applyPasswordToRedisURL(cfg, pw); err != nil {
		return fmt.Errorf("failed to apply vault password to redis URL: %w", err)
	}
	logger.Info("redis password resolved from vault",
		observability.String("vaultPath", cfg.PasswordVaultPath))
	return nil
}

// resolveSentinelPasswords resolves sentinel passwords from Vault.
func resolveSentinelPasswords(
	sentinel *config.RedisSentinelConfig, vaultClient vault.Client, logger observability.Logger,
) error {
	if sentinel.PasswordVaultPath != "" {
		pw, err := readVaultPassword(vaultClient, sentinel.PasswordVaultPath)
		if err != nil {
			return fmt.Errorf("failed to read redis master password from vault: %w", err)
		}
		sentinel.Password = pw
		logger.Info("redis sentinel master password resolved from vault",
			observability.String("vaultPath", sentinel.PasswordVaultPath))
	}
	if sentinel.SentinelPasswordVaultPath != "" {
		pw, err := readVaultPassword(vaultClient, sentinel.SentinelPasswordVaultPath)
		if err != nil {
			return fmt.Errorf("failed to read sentinel password from vault: %w", err)
		}
		sentinel.SentinelPassword = pw
		logger.Info("redis sentinel password resolved from vault",
			observability.String("vaultPath", sentinel.SentinelPasswordVaultPath))
	}
	return nil
}

// readVaultPassword reads a password from a Vault KV path.
// The path format is "mount/path" and the secret must contain a "password" key.
func readVaultPassword(vaultClient vault.Client, vaultPath string) (string, error) {
	parts := strings.SplitN(vaultPath, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid vault path format %q, expected mount/path", vaultPath)
	}

	mount, path := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	data, err := vaultClient.KV().Read(ctx, mount, path)
	if err != nil {
		return "", fmt.Errorf("vault read failed: %w", err)
	}

	pw, ok := data["password"].(string)
	if !ok || pw == "" {
		return "", fmt.Errorf("vault secret at %q does not contain a valid 'password' key", vaultPath)
	}

	return pw, nil
}

// applyPasswordToRedisURL updates the Redis URL with the given password.
func applyPasswordToRedisURL(cfg *config.RedisCacheConfig, password string) error {
	if cfg.URL == "" {
		return nil
	}

	parsedURL, err := url.Parse(cfg.URL)
	if err != nil {
		return fmt.Errorf("failed to parse redis URL: %w", err)
	}

	var username string
	if parsedURL.User != nil {
		username = parsedURL.User.Username()
	}
	parsedURL.User = url.UserPassword(username, password)
	cfg.URL = parsedURL.String()

	return nil
}

// newRedisCache creates a new Redis cache.
// It dispatches between standalone and Sentinel modes based on configuration.
func newRedisCache(cfg *config.CacheConfig, logger observability.Logger, opts *cacheOptions) (*redisCache, error) {
	if cfg.Redis == nil {
		return nil, errors.New("redis configuration is required")
	}

	// Resolve passwords from Vault before connecting
	var vaultClient vault.Client
	if opts != nil {
		vaultClient = opts.vaultClient
	}
	if err := resolveRedisPasswords(cfg.Redis, vaultClient, logger); err != nil {
		return nil, fmt.Errorf("failed to resolve redis passwords: %w", err)
	}

	// Sentinel mode takes precedence when configured
	if cfg.Redis.Sentinel != nil && cfg.Redis.Sentinel.MasterName != "" {
		return newRedisSentinelCache(cfg, logger, opts)
	}

	// Standalone mode requires a URL
	if cfg.Redis.URL == "" {
		return nil, errors.New("redis URL is required for standalone mode")
	}

	return newRedisStandaloneCache(cfg, logger)
}

// newRedisStandaloneCache creates a new Redis cache using standalone mode.
func newRedisStandaloneCache(cfg *config.CacheConfig, logger observability.Logger) (*redisCache, error) {
	opts, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		return nil, errors.New("invalid redis URL: " + err.Error())
	}

	applyRedisPoolOptions(opts, cfg.Redis)

	// Configure TLS if enabled
	if cfg.Redis.TLS != nil && cfg.Redis.TLS.Enabled {
		opts.TLSConfig = &tls.Config{
			InsecureSkipVerify: cfg.Redis.TLS.InsecureSkipVerify, //nolint:gosec // User-configurable
		}
	}

	client := redis.NewClient(opts)

	if err := pingRedis(client); err != nil {
		_ = client.Close()
		return nil, errors.New("redis connection failed: " + err.Error())
	}

	keyPrefix := resolveKeyPrefix(cfg.Redis.KeyPrefix)

	c := &redisCache{
		logger:     logger,
		client:     client,
		keyPrefix:  keyPrefix,
		defaultTTL: cfg.TTL.Duration(),
		ttlJitter:  cfg.Redis.TTLJitter,
		hashKeys:   cfg.Redis.HashKeys,
	}

	logger.Info("redis standalone cache initialized",
		observability.String("keyPrefix", keyPrefix),
		observability.Duration("defaultTTL", c.defaultTTL),
		observability.Float64("ttlJitter", c.ttlJitter),
		observability.Bool("hashKeys", c.hashKeys))

	return c, nil
}

// newRedisSentinelCache creates a new Redis cache using Sentinel mode for high availability.
func newRedisSentinelCache(
	cfg *config.CacheConfig, logger observability.Logger, cacheOpts *cacheOptions,
) (*redisCache, error) {
	sentinel := cfg.Redis.Sentinel
	if len(sentinel.SentinelAddrs) == 0 {
		return nil, errors.New("at least one sentinel address is required")
	}

	opts := &redis.FailoverOptions{
		MasterName:       sentinel.MasterName,
		SentinelAddrs:    sentinel.SentinelAddrs,
		SentinelPassword: sentinel.SentinelPassword,
		Password:         sentinel.Password,
		DB:               sentinel.DB,
	}

	// Apply custom dialer if provided (used in tests for Docker networking)
	if cacheOpts != nil && cacheOpts.redisDialer != nil {
		opts.Dialer = cacheOpts.redisDialer
	}

	// Apply pool/timeout overrides from shared Redis config
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
		opts.TLSConfig = &tls.Config{
			InsecureSkipVerify: cfg.Redis.TLS.InsecureSkipVerify, //nolint:gosec // User-configurable
		}
	}

	client := redis.NewFailoverClient(opts)

	if err := pingRedis(client); err != nil {
		_ = client.Close()
		return nil, errors.New("redis sentinel connection failed: " + err.Error())
	}

	keyPrefix := resolveKeyPrefix(cfg.Redis.KeyPrefix)

	c := &redisCache{
		logger:     logger,
		client:     client,
		keyPrefix:  keyPrefix,
		defaultTTL: cfg.TTL.Duration(),
		ttlJitter:  cfg.Redis.TTLJitter,
		hashKeys:   cfg.Redis.HashKeys,
	}

	logger.Info("redis sentinel cache initialized",
		observability.String("masterName", sentinel.MasterName),
		observability.Int("sentinelCount", len(sentinel.SentinelAddrs)),
		observability.String("keyPrefix", keyPrefix),
		observability.Duration("defaultTTL", c.defaultTTL),
		observability.Float64("ttlJitter", c.ttlJitter),
		observability.Bool("hashKeys", c.hashKeys))

	return c, nil
}

// applyRedisPoolOptions applies pool and timeout configuration overrides to Redis options.
func applyRedisPoolOptions(opts *redis.Options, redisCfg *config.RedisCacheConfig) {
	if redisCfg.PoolSize > 0 {
		opts.PoolSize = redisCfg.PoolSize
	}
	if redisCfg.ConnectTimeout > 0 {
		opts.DialTimeout = redisCfg.ConnectTimeout.Duration()
	}
	if redisCfg.ReadTimeout > 0 {
		opts.ReadTimeout = redisCfg.ReadTimeout.Duration()
	}
	if redisCfg.WriteTimeout > 0 {
		opts.WriteTimeout = redisCfg.WriteTimeout.Duration()
	}
}

// pingRedis tests the Redis connection with a timeout.
func pingRedis(client *redis.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return client.Ping(ctx).Err()
}

// resolveKeyPrefix returns the key prefix, defaulting to "avapigw:" if empty.
func resolveKeyPrefix(prefix string) string {
	if prefix == "" {
		return "avapigw:"
	}
	return prefix
}

// Get retrieves a value from the cache with exponential backoff retry.
func (c *redisCache) Get(ctx context.Context, key string) ([]byte, error) {
	ctx, span := otel.Tracer(cacheTracerName).Start(ctx, "cache.Get",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.backend", "redis"),
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		GetCacheMetrics().operationDuration.WithLabelValues(
			"redis", "get",
		).Observe(time.Since(start).Seconds())
	}()

	fullKey := c.resolveKey(key)

	var result []byte

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		val, getErr := c.client.Get(ctx, fullKey).Bytes()
		if getErr == nil {
			result = val
			return nil
		}
		if errors.Is(getErr, redis.Nil) {
			// Cache miss is not retryable — return immediately
			return getErr
		}
		return getErr
	}, &retry.Options{
		ShouldRetry: isRetryableRedisError,
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			c.logger.Debug("retrying redis get",
				observability.String("key", key),
				observability.Int("attempt", attempt))
		},
	})

	if err == nil {
		atomic.AddInt64(&c.hits, 1)
		GetCacheMetrics().hitsTotal.WithLabelValues("redis").Inc()
		span.SetAttributes(
			attribute.Bool("cache.hit", true),
			attribute.Int("cache.value_size", len(result)),
		)
		c.logger.Debug("cache hit",
			observability.String("key", key),
			observability.Int("size", len(result)))
		return result, nil
	}

	if errors.Is(err, redis.Nil) {
		atomic.AddInt64(&c.misses, 1)
		GetCacheMetrics().missesTotal.WithLabelValues("redis").Inc()
		span.SetAttributes(attribute.Bool("cache.hit", false))
		return nil, ErrCacheMiss
	}

	GetCacheMetrics().errorsTotal.WithLabelValues("redis", "get").Inc()
	span.SetStatus(codes.Error, err.Error())
	span.RecordError(err)
	c.logger.Error("redis get failed",
		observability.String("key", key),
		observability.Error(err))
	return nil, err
}

// Set stores a value in the cache with exponential backoff retry.
func (c *redisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	ctx, span := otel.Tracer(cacheTracerName).Start(ctx, "cache.Set",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.backend", "redis"),
			attribute.String("cache.key", key),
			attribute.Int("cache.value_size", len(value)),
		),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		GetCacheMetrics().operationDuration.WithLabelValues(
			"redis", "set",
		).Observe(time.Since(start).Seconds())
	}()

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	// Apply TTL jitter to prevent thundering herd
	ttl = applyTTLJitter(ttl, c.ttlJitter)

	fullKey := c.resolveKey(key)

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		return c.client.Set(ctx, fullKey, value, ttl).Err()
	}, &retry.Options{
		ShouldRetry: isRetryableRedisError,
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			c.logger.Debug("retrying redis set",
				observability.String("key", key),
				observability.Int("attempt", attempt))
		},
	})

	if err == nil {
		c.logger.Debug("cache set",
			observability.String("key", key),
			observability.Duration("ttl", ttl),
			observability.Int("size", len(value)))
		return nil
	}

	GetCacheMetrics().errorsTotal.WithLabelValues("redis", "set").Inc()
	span.SetStatus(codes.Error, err.Error())
	span.RecordError(err)
	c.logger.Error("redis set failed",
		observability.String("key", key),
		observability.Error(err))
	return err
}

// Delete removes a value from the cache with exponential backoff retry.
func (c *redisCache) Delete(ctx context.Context, key string) error {
	ctx, span := otel.Tracer(cacheTracerName).Start(ctx, "cache.Delete",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.backend", "redis"),
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		GetCacheMetrics().operationDuration.WithLabelValues(
			"redis", "delete",
		).Observe(time.Since(start).Seconds())
	}()

	fullKey := c.resolveKey(key)

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		return c.client.Del(ctx, fullKey).Err()
	}, &retry.Options{
		ShouldRetry: isRetryableRedisError,
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			c.logger.Debug("retrying redis delete",
				observability.String("key", key),
				observability.Int("attempt", attempt))
		},
	})

	if err == nil {
		c.logger.Debug("cache deleted",
			observability.String("key", key))
		return nil
	}

	GetCacheMetrics().errorsTotal.WithLabelValues("redis", "delete").Inc()
	span.SetStatus(codes.Error, err.Error())
	span.RecordError(err)
	c.logger.Error("redis delete failed",
		observability.String("key", key),
		observability.Error(err))
	return err
}

// Exists checks if a key exists in the cache with exponential backoff retry.
func (c *redisCache) Exists(ctx context.Context, key string) (bool, error) {
	ctx, span := otel.Tracer(cacheTracerName).Start(ctx, "cache.Exists",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.backend", "redis"),
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		GetCacheMetrics().operationDuration.WithLabelValues(
			"redis", "exists",
		).Observe(time.Since(start).Seconds())
	}()

	fullKey := c.resolveKey(key)

	var result int64

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		var existsErr error
		result, existsErr = c.client.Exists(ctx, fullKey).Result()
		return existsErr
	}, &retry.Options{
		ShouldRetry: isRetryableRedisError,
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			c.logger.Debug("retrying redis exists",
				observability.String("key", key),
				observability.Int("attempt", attempt))
		},
	})

	if err == nil {
		span.SetAttributes(attribute.Bool("cache.exists", result > 0))
		return result > 0, nil
	}

	GetCacheMetrics().errorsTotal.WithLabelValues("redis", "exists").Inc()
	span.SetStatus(codes.Error, err.Error())
	span.RecordError(err)
	c.logger.Error("redis exists failed",
		observability.String("key", key),
		observability.Error(err))
	return false, err
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

// GetWithTTL retrieves a value and its remaining TTL from the cache with retry.
func (c *redisCache) GetWithTTL(ctx context.Context, key string) ([]byte, time.Duration, error) {
	ctx, span := otel.Tracer(cacheTracerName).Start(ctx, "cache.GetWithTTL",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.backend", "redis"),
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	fullKey := c.resolveKey(key)

	var value []byte
	var ttl time.Duration

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		// Use pipeline to get value and TTL in one round trip
		pipe := c.client.Pipeline()
		getCmd := pipe.Get(ctx, fullKey)
		ttlCmd := pipe.TTL(ctx, fullKey)

		_, pipeErr := pipe.Exec(ctx)
		if pipeErr != nil && !errors.Is(pipeErr, redis.Nil) {
			return pipeErr
		}

		val, getErr := getCmd.Bytes()
		if getErr != nil {
			return getErr
		}

		value = val
		ttl = ttlCmd.Val()
		if ttl < 0 {
			ttl = 0
		}
		return nil
	}, &retry.Options{
		ShouldRetry: isRetryableRedisError,
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			c.logger.Debug("retrying redis getWithTTL",
				observability.String("key", key),
				observability.Int("attempt", attempt))
		},
	})

	if err == nil {
		atomic.AddInt64(&c.hits, 1)
		span.SetAttributes(
			attribute.Bool("cache.hit", true),
			attribute.Int("cache.value_size", len(value)),
		)
		return value, ttl, nil
	}

	if errors.Is(err, redis.Nil) {
		atomic.AddInt64(&c.misses, 1)
		span.SetAttributes(attribute.Bool("cache.hit", false))
		return nil, 0, ErrCacheMiss
	}

	c.logger.Error("redis getWithTTL failed",
		observability.String("key", key),
		observability.Error(err))
	span.SetStatus(codes.Error, err.Error())
	span.RecordError(err)
	return nil, 0, err
}

// SetNX sets a value only if the key does not exist, with retry.
func (c *redisCache) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	ctx, span := otel.Tracer(cacheTracerName).Start(ctx, "cache.SetNX",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.backend", "redis"),
			attribute.String("cache.key", key),
			attribute.Int("cache.value_size", len(value)),
		),
	)
	defer span.End()

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	// Apply TTL jitter to prevent thundering herd
	ttl = applyTTLJitter(ttl, c.ttlJitter)

	fullKey := c.resolveKey(key)

	var result bool

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		var setErr error
		result, setErr = c.client.SetNX(ctx, fullKey, value, ttl).Result()
		return setErr
	}, &retry.Options{
		ShouldRetry: isRetryableRedisError,
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			c.logger.Debug("retrying redis setnx",
				observability.String("key", key),
				observability.Int("attempt", attempt))
		},
	})

	if err != nil {
		c.logger.Error("redis setnx failed",
			observability.String("key", key),
			observability.Error(err))
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		return false, err
	}

	if result {
		c.logger.Debug("cache setnx succeeded",
			observability.String("key", key),
			observability.Duration("ttl", ttl))
	}

	span.SetAttributes(attribute.Bool("cache.setnx_acquired", result))
	return result, nil
}

// Expire updates the TTL of an existing key with retry.
func (c *redisCache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	ctx, span := otel.Tracer(cacheTracerName).Start(ctx, "cache.Expire",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.backend", "redis"),
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	fullKey := c.resolveKey(key)

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		return c.client.Expire(ctx, fullKey, ttl).Err()
	}, &retry.Options{
		ShouldRetry: isRetryableRedisError,
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			c.logger.Debug("retrying redis expire",
				observability.String("key", key),
				observability.Int("attempt", attempt))
		},
	})

	if err != nil {
		c.logger.Error("redis expire failed",
			observability.String("key", key),
			observability.Error(err))
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		return err
	}

	return nil
}
