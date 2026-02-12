// Package cache provides caching capabilities for the API Gateway.
package cache

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
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
	// Use math/rand (not crypto/rand) since this is not security-sensitive
	//nolint:gosec // G404: jitter for cache TTL is not security-sensitive
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

	parsedURL.User = url.UserPassword(parsedURL.User.Username(), password)
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
	// Check for context cancellation before proceeding
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	fullKey := c.resolveKey(key)

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

	// Apply TTL jitter to prevent thundering herd
	ttl = applyTTLJitter(ttl, c.ttlJitter)

	fullKey := c.resolveKey(key)

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

	fullKey := c.resolveKey(key)

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

	fullKey := c.resolveKey(key)

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

	fullKey := c.resolveKey(key)

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

	// Apply TTL jitter to prevent thundering herd
	ttl = applyTTLJitter(ttl, c.ttlJitter)

	fullKey := c.resolveKey(key)

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

	fullKey := c.resolveKey(key)

	err := c.client.Expire(ctx, fullKey, ttl).Err()
	if err != nil {
		c.logger.Error("redis expire failed",
			observability.String("key", key),
			observability.Error(err))
		return err
	}

	return nil
}
