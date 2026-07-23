// Package cache provides caching capabilities for the API Gateway.
package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/redisclient"
	"github.com/vyrodovalexey/avapigw/internal/retry"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// redisBackend is the backend label used in metrics and span attributes.
const redisBackend = "redis"

// Operation label values used in metrics for redis cache operations.
const (
	opGet        = "get"
	opSet        = "set"
	opDelete     = "delete"
	opExists     = "exists"
	opGetWithTTL = "get_with_ttl"
	opSetNX      = "setnx"
	opExpire     = "expire"
)

// Initialization timeouts for redis cache construction.
const (
	// vaultReadTimeout bounds a single Vault KV read during password resolution.
	vaultReadTimeout = 10 * time.Second

	// redisPingTimeout bounds the connectivity check performed at start-up.
	redisPingTimeout = 5 * time.Second

	// redisInitTimeout bounds the whole redis cache initialization: up to
	// three Vault password reads (vaultReadTimeout each) plus the
	// connectivity ping (redisPingTimeout). It is used by the public
	// constructor, which has no context parameter.
	redisInitTimeout = 45 * time.Second
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

// transientRedisReplyPrefixes lists Redis server reply prefixes that describe
// a transient server state and are therefore safe to retry:
//
//   - LOADING: the server is loading its dataset (start-up or failover);
//   - READONLY: a replica rejects writes during a failover window;
//   - CLUSTERDOWN / TRYAGAIN / MASTERDOWN: transient cluster/sentinel states;
//   - ERR max number of clients reached: momentary server saturation.
//
// Every other server reply (WRONGTYPE, OOM, NOAUTH, ERR <syntax>, MOVED, ...)
// is permanent: retrying cannot change the outcome and only adds latency.
var transientRedisReplyPrefixes = []string{
	"LOADING",
	"READONLY",
	"CLUSTERDOWN",
	"TRYAGAIN",
	"MASTERDOWN",
	"ERR max number of clients reached",
}

// transientNetworkErrorSubstrings is a last-resort fallback for errors that
// lost their concrete type through wrapping but clearly describe a transient
// network failure.
var transientNetworkErrorSubstrings = []string{
	"connection refused",
	"connection reset",
	"broken pipe",
	"i/o timeout",
	"no route to host",
	"network is unreachable",
	"pool timeout",
}

// isRetryableRedisError reports whether err is transient and worth retrying
// with exponential backoff.
//
// Retryable (transient):
//   - network-level failures: net.Error timeouts, refused/reset connections,
//     io.EOF / io.ErrUnexpectedEOF (connections dropped mid-flight);
//   - transient Redis server states: LOADING, READONLY (failover window),
//     CLUSTERDOWN, TRYAGAIN, MASTERDOWN.
//
// NOT retryable (permanent):
//   - redis.Nil (cache miss) and context cancellation / deadline expiry;
//   - permanent Redis server replies such as WRONGTYPE, OOM, NOAUTH,
//     ERR <syntax> and MOVED.
func isRetryableRedisError(err error) bool {
	if err == nil {
		return false
	}
	// Cache misses and caller cancellation are never retryable.
	if errors.Is(err, redis.Nil) || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// Redis server replies are permanent unless they describe a transient
	// server state (LOADING, READONLY, ...).
	var serverErr redis.Error
	if errors.As(err, &serverErr) {
		return isTransientRedisReply(serverErr.Error())
	}
	return isTransientNetworkError(err)
}

// isTransientRedisReply reports whether a Redis server reply indicates a
// transient server state that may succeed on a later attempt.
func isTransientRedisReply(reply string) bool {
	for _, prefix := range transientRedisReplyPrefixes {
		if strings.HasPrefix(reply, prefix) {
			return true
		}
	}
	return false
}

// isTransientNetworkError reports whether err represents a transient
// network-level failure such as a timeout, a refused or reset connection, or
// a connection dropped mid-flight.
func isTransientNetworkError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Any net.OpError (dial, read, write) is a network-level failure.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	// Dropped connections surface as EOF or syscall-level errors.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ETIMEDOUT) {
		return true
	}
	return matchesTransientNetworkSubstring(err.Error())
}

// matchesTransientNetworkSubstring is a fallback classification for errors
// that lost their concrete type through wrapping.
func matchesTransientNetworkSubstring(msg string) bool {
	for _, substr := range transientNetworkErrorSubstrings {
		if strings.Contains(msg, substr) {
			return true
		}
	}
	return false
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

// effectiveTTL substitutes the default TTL for zero values and applies jitter
// to spread expirations and avoid a thundering herd.
func (c *redisCache) effectiveTTL(ttl time.Duration) time.Duration {
	if ttl == 0 {
		ttl = c.defaultTTL
	}
	return applyTTLJitter(ttl, c.ttlJitter)
}

// resolveKey applies key prefix and optional SHA256 hashing.
func (c *redisCache) resolveKey(key string) string {
	if c.hashKeys {
		return c.keyPrefix + HashKey(key)
	}
	return c.keyPrefix + key
}

// loggableKey returns a privacy-safe representation of key for span
// attributes and log fields. When key hashing is enabled the raw key may
// embed sensitive request material (headers, tokens, query parameters), so
// its SHA-256 form is recorded instead of the raw value.
func (c *redisCache) loggableKey(key string) string {
	if c.hashKeys {
		return HashKey(key)
	}
	return key
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
	ctx context.Context, cfg *config.RedisCacheConfig, vaultClient vault.Client, logger observability.Logger,
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
		if err := resolveStandalonePassword(ctx, cfg, vaultClient, logger); err != nil {
			return err
		}
	}

	// Resolve sentinel passwords from vault
	if cfg.Sentinel != nil {
		if err := resolveSentinelPasswords(ctx, cfg.Sentinel, vaultClient, logger); err != nil {
			return err
		}
	}

	return nil
}

// resolveStandalonePassword resolves the standalone Redis password from Vault.
func resolveStandalonePassword(
	ctx context.Context, cfg *config.RedisCacheConfig, vaultClient vault.Client, logger observability.Logger,
) error {
	pw, err := readVaultPassword(ctx, vaultClient, cfg.PasswordVaultPath)
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
	ctx context.Context, sentinel *config.RedisSentinelConfig, vaultClient vault.Client, logger observability.Logger,
) error {
	if sentinel.PasswordVaultPath != "" {
		pw, err := readVaultPassword(ctx, vaultClient, sentinel.PasswordVaultPath)
		if err != nil {
			return fmt.Errorf("failed to read redis master password from vault: %w", err)
		}
		sentinel.Password = pw
		logger.Info("redis sentinel master password resolved from vault",
			observability.String("vaultPath", sentinel.PasswordVaultPath))
	}
	if sentinel.SentinelPasswordVaultPath != "" {
		pw, err := readVaultPassword(ctx, vaultClient, sentinel.SentinelPasswordVaultPath)
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
// The read honors the caller's context and is additionally bounded by
// vaultReadTimeout.
func readVaultPassword(ctx context.Context, vaultClient vault.Client, vaultPath string) (string, error) {
	parts := strings.SplitN(vaultPath, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid vault path format %q, expected mount/path", vaultPath)
	}

	mount, path := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, vaultReadTimeout)
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
// The context bounds initialization (Vault password reads and the
// connectivity ping) and honors caller cancellation.
//
// Copy-on-resolve (mirrors internal/redisclient): the caller's cfg is never
// mutated — Vault-resolved passwords are injected into a private deep copy
// so secrets never leak back into the shared GatewayConfig tree (where they
// would surface in config serializations and spurious reload diffs).
func newRedisCache(
	ctx context.Context, cfg *config.CacheConfig, logger observability.Logger, opts *cacheOptions,
) (*redisCache, error) {
	if cfg.Redis == nil {
		return nil, errors.New("redis configuration is required")
	}

	// Resolve passwords from Vault into a private copy before connecting.
	var vaultClient vault.Client
	if opts != nil {
		vaultClient = opts.vaultClient
	}
	effective := *cfg
	effective.Redis = cfg.Redis.Clone()
	if err := resolveRedisPasswords(ctx, effective.Redis, vaultClient, logger); err != nil {
		return nil, fmt.Errorf("failed to resolve redis passwords: %w", err)
	}

	// Sentinel mode takes precedence when configured
	if effective.Redis.Sentinel != nil && effective.Redis.Sentinel.MasterName != "" {
		return newRedisSentinelCache(ctx, &effective, logger, opts)
	}

	// Standalone mode requires a URL
	if effective.Redis.URL == "" {
		return nil, errors.New("redis URL is required for standalone mode")
	}

	return newRedisStandaloneCache(ctx, &effective, logger)
}

// newRedisStandaloneCache creates a new Redis cache using standalone mode.
func newRedisStandaloneCache(
	ctx context.Context, cfg *config.CacheConfig, logger observability.Logger,
) (*redisCache, error) {
	opts, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		return nil, errors.New("invalid redis URL: " + err.Error())
	}

	applyRedisPoolOptions(opts, cfg.Redis)

	// Configure TLS if enabled (honors certFile/keyFile/caFile/versions via
	// the shared redisclient builder; unreadable files fail construction).
	if tlsErr := applyRedisTLSConfig(opts, cfg.Redis); tlsErr != nil {
		return nil, tlsErr
	}

	client := redis.NewClient(opts)

	if err := pingRedis(ctx, client); err != nil {
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
	ctx context.Context, cfg *config.CacheConfig, logger observability.Logger, cacheOpts *cacheOptions,
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

	// Configure TLS if enabled (honors certFile/keyFile/caFile/versions via
	// the shared redisclient builder; unreadable files fail construction).
	if cfg.Redis.TLS != nil && cfg.Redis.TLS.Enabled {
		tlsCfg, tlsErr := redisclient.NewTLSConfig(cfg.Redis.TLS)
		if tlsErr != nil {
			return nil, tlsErr
		}
		opts.TLSConfig = tlsCfg
	}

	client := redis.NewFailoverClient(opts)

	if err := pingRedis(ctx, client); err != nil {
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

// applyRedisTLSConfig builds and applies the TLS client configuration for
// standalone Redis when TLS is enabled, honoring the full certificate
// material (mTLS client keypair, private CA, protocol versions).
func applyRedisTLSConfig(opts *redis.Options, redisCfg *config.RedisCacheConfig) error {
	if redisCfg.TLS == nil || !redisCfg.TLS.Enabled {
		return nil
	}
	tlsCfg, err := redisclient.NewTLSConfig(redisCfg.TLS)
	if err != nil {
		return err
	}
	opts.TLSConfig = tlsCfg
	return nil
}

// pingRedis tests the Redis connection. It honors the caller's context and
// is additionally bounded by redisPingTimeout.
func pingRedis(ctx context.Context, client *redis.Client) error {
	ctx, cancel := context.WithTimeout(ctx, redisPingTimeout)
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

// redisOpTelemetry carries the tracing, metrics and logging state of a single
// redis cache operation so that every operation reports observability data
// uniformly (span, duration histogram, error counter, hit/miss counters).
type redisOpTelemetry struct {
	cache  *redisCache
	op     string
	logKey string
	span   trace.Span
	start  time.Time
}

// beginRedisOp starts the client span and the duration timer for a redis
// cache operation. spanName is the OpenTelemetry span name (e.g. "cache.Get")
// and op is the Prometheus operation label (e.g. "get"). The recorded
// cache.key span attribute uses the privacy-safe loggable key. The caller
// must invoke finish() when the operation completes.
func (c *redisCache) beginRedisOp(
	ctx context.Context, spanName, op, key string, extraAttrs ...attribute.KeyValue,
) (context.Context, *redisOpTelemetry) {
	logKey := c.loggableKey(key)

	attrs := make([]attribute.KeyValue, 0, 2+len(extraAttrs))
	attrs = append(attrs,
		attribute.String("cache.backend", redisBackend),
		attribute.String("cache.key", logKey),
	)
	attrs = append(attrs, extraAttrs...)

	ctx, span := otel.Tracer(cacheTracerName).Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)

	return ctx, &redisOpTelemetry{
		cache:  c,
		op:     op,
		logKey: logKey,
		span:   span,
		start:  time.Now(),
	}
}

// finish records the operation duration metric and ends the span.
func (o *redisOpTelemetry) finish() {
	GetCacheMetrics().operationDuration.WithLabelValues(
		redisBackend, o.op,
	).Observe(time.Since(o.start).Seconds())
	o.span.End()
}

// retryOptions returns the retry options shared by redis operations:
// transient-only error classification plus debug logging on each retry
// attempt (using the privacy-safe key).
func (o *redisOpTelemetry) retryOptions() *retry.Options {
	return &retry.Options{
		ShouldRetry: isRetryableRedisError,
		OnRetry: func(attempt int, err error, _ time.Duration) {
			o.cache.logger.Debug("retrying redis "+o.op,
				observability.String("key", o.logKey),
				observability.Int("attempt", attempt),
				observability.Error(err))
		},
	}
}

// fail records the error metric, marks the span as failed and logs the error.
func (o *redisOpTelemetry) fail(err error) {
	GetCacheMetrics().errorsTotal.WithLabelValues(redisBackend, o.op).Inc()
	o.span.SetStatus(codes.Error, err.Error())
	o.span.RecordError(err)
	o.cache.logger.Error("redis "+o.op+" failed",
		observability.String("key", o.logKey),
		observability.Error(err))
}

// hit records a cache hit in the package Prometheus counters, the internal
// stats and the span attributes.
func (o *redisOpTelemetry) hit(valueSize int) {
	atomic.AddInt64(&o.cache.hits, 1)
	GetCacheMetrics().hitsTotal.WithLabelValues(redisBackend).Inc()
	o.span.SetAttributes(
		attribute.Bool("cache.hit", true),
		attribute.Int("cache.value_size", valueSize),
	)
}

// miss records a cache miss in the package Prometheus counters, the internal
// stats and the span attributes.
func (o *redisOpTelemetry) miss() {
	atomic.AddInt64(&o.cache.misses, 1)
	GetCacheMetrics().missesTotal.WithLabelValues(redisBackend).Inc()
	o.span.SetAttributes(attribute.Bool("cache.hit", false))
}

// Get retrieves a value from the cache with exponential backoff retry.
func (c *redisCache) Get(ctx context.Context, key string) ([]byte, error) {
	ctx, ot := c.beginRedisOp(ctx, "cache.Get", opGet, key)
	defer ot.finish()

	fullKey := c.resolveKey(key)

	var result []byte

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		val, getErr := c.client.Get(ctx, fullKey).Bytes()
		if getErr != nil {
			// redis.Nil (cache miss) is classified as non-retryable
			// and returned immediately by the retry helper.
			return getErr
		}
		result = val
		return nil
	}, ot.retryOptions())

	if err == nil {
		ot.hit(len(result))
		c.logger.Debug("cache hit",
			observability.String("key", ot.logKey),
			observability.Int("size", len(result)))
		return result, nil
	}

	if errors.Is(err, redis.Nil) {
		ot.miss()
		return nil, ErrCacheMiss
	}

	ot.fail(err)
	return nil, err
}

// Set stores a value in the cache with exponential backoff retry.
func (c *redisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	ctx, ot := c.beginRedisOp(ctx, "cache.Set", opSet, key,
		attribute.Int("cache.value_size", len(value)))
	defer ot.finish()

	ttl = c.effectiveTTL(ttl)
	fullKey := c.resolveKey(key)

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		return c.client.Set(ctx, fullKey, value, ttl).Err()
	}, ot.retryOptions())

	if err != nil {
		ot.fail(err)
		return err
	}

	c.logger.Debug("cache set",
		observability.String("key", ot.logKey),
		observability.Duration("ttl", ttl),
		observability.Int("size", len(value)))
	return nil
}

// Delete removes a value from the cache with exponential backoff retry.
func (c *redisCache) Delete(ctx context.Context, key string) error {
	ctx, ot := c.beginRedisOp(ctx, "cache.Delete", opDelete, key)
	defer ot.finish()

	fullKey := c.resolveKey(key)

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		return c.client.Del(ctx, fullKey).Err()
	}, ot.retryOptions())

	if err != nil {
		ot.fail(err)
		return err
	}

	c.logger.Debug("cache deleted",
		observability.String("key", ot.logKey))
	return nil
}

// Exists checks if a key exists in the cache with exponential backoff retry.
func (c *redisCache) Exists(ctx context.Context, key string) (bool, error) {
	ctx, ot := c.beginRedisOp(ctx, "cache.Exists", opExists, key)
	defer ot.finish()

	fullKey := c.resolveKey(key)

	var result int64

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		var existsErr error
		result, existsErr = c.client.Exists(ctx, fullKey).Result()
		return existsErr
	}, ot.retryOptions())

	if err != nil {
		ot.fail(err)
		return false, err
	}

	ot.span.SetAttributes(attribute.Bool("cache.exists", result > 0))
	return result > 0, nil
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
	ctx, ot := c.beginRedisOp(ctx, "cache.GetWithTTL", opGetWithTTL, key)
	defer ot.finish()

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
	}, ot.retryOptions())

	if err == nil {
		ot.hit(len(value))
		c.logger.Debug("cache hit",
			observability.String("key", ot.logKey),
			observability.Int("size", len(value)))
		return value, ttl, nil
	}

	if errors.Is(err, redis.Nil) {
		ot.miss()
		return nil, 0, ErrCacheMiss
	}

	ot.fail(err)
	return nil, 0, err
}

// SetNX sets a value only if the key does not exist, with retry.
func (c *redisCache) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	ctx, ot := c.beginRedisOp(ctx, "cache.SetNX", opSetNX, key,
		attribute.Int("cache.value_size", len(value)))
	defer ot.finish()

	ttl = c.effectiveTTL(ttl)
	fullKey := c.resolveKey(key)

	var acquired bool

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		setErr := c.client.SetArgs(ctx, fullKey, value, redis.SetArgs{
			Mode: "NX",
			TTL:  ttl,
		}).Err()
		if errors.Is(setErr, redis.Nil) {
			acquired = false
			return nil
		}
		if setErr != nil {
			return setErr
		}
		acquired = true
		return nil
	}, ot.retryOptions())

	if err != nil {
		ot.fail(err)
		return false, err
	}

	if acquired {
		c.logger.Debug("cache setnx succeeded",
			observability.String("key", ot.logKey),
			observability.Duration("ttl", ttl))
	}

	ot.span.SetAttributes(attribute.Bool("cache.setnx_acquired", acquired))
	return acquired, nil
}

// Expire updates the TTL of an existing key with retry.
func (c *redisCache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	ctx, ot := c.beginRedisOp(ctx, "cache.Expire", opExpire, key)
	defer ot.finish()

	fullKey := c.resolveKey(key)

	err := retry.Do(ctx, redisRetryConfig(), func() error {
		return c.client.Expire(ctx, fullKey, ttl).Err()
	}, ot.retryOptions())

	if err != nil {
		ot.fail(err)
		return err
	}

	return nil
}
