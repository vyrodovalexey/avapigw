package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/redisclient"
	"github.com/vyrodovalexey/avapigw/internal/util"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Redis rate limiter defaults.
const (
	// defaultRedisRateLimitOpTimeout bounds a single rate limit decision
	// so Redis latency never adds unbounded delay to requests. It is
	// overridden by the configured readTimeout.
	defaultRedisRateLimitOpTimeout = 100 * time.Millisecond

	// defaultRedisRateLimitKeyPrefix is the default key prefix, aligned
	// with the redis cache default prefix.
	defaultRedisRateLimitKeyPrefix = "avapigw:"

	// redisRateLimitIdleTTLMargin is added to the full-refill time when
	// computing the idle-bucket expiry. Any bucket idle longer than its
	// full-refill time behaves as a fresh full bucket, so expiring it is
	// semantically lossless while bounding Redis memory.
	redisRateLimitIdleTTLMargin = time.Minute

	// redisOutageWarnInterval rate-limits the WARN log emitted on Redis
	// outages: one warning per interval, remaining failures log at DEBUG.
	// This prevents per-request log spam during an outage window.
	redisOutageWarnInterval = 30 * time.Second
)

// redisTokenBucketScript is an atomic token-bucket implementation.
//
// KEYS[1] - bucket key
// ARGV[1] - refill rate in tokens per second
// ARGV[2] - bucket capacity (burst)
// ARGV[3] - current time in microseconds (supplied by the gateway)
// ARGV[4] - idle bucket expiry in milliseconds
//
// Returns 1 when the request is allowed, 0 otherwise.
//
// The gateway passes "now" instead of calling the Redis TIME command so
// the script stays deterministic (EVALSHA-friendly on every Redis
// deployment, including miniredis in tests, and safe under script
// replication). Negative elapsed time (clock skew between gateway
// replicas) never refills backwards. Idle buckets self-expire via
// PEXPIRE, which bounds memory for per-client buckets.
//
//nolint:gosec // G101: Lua rate limiting script, not credentials
const redisTokenBucketScript = `
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now_us = tonumber(ARGV[3])
local ttl_ms = tonumber(ARGV[4])

local bucket = redis.call('HMGET', KEYS[1], 't', 'ts')
local tokens = tonumber(bucket[1])
local ts = tonumber(bucket[2])

if tokens == nil or ts == nil then
  tokens = burst
  ts = now_us
end

local elapsed = now_us - ts
if elapsed < 0 then
  elapsed = 0
end

tokens = tokens + (elapsed * rate / 1000000.0)
if tokens > burst then
  tokens = burst
end

local allowed = 0
if tokens >= 1.0 then
  tokens = tokens - 1.0
  allowed = 1
end

redis.call('HSET', KEYS[1], 't', tostring(tokens), 'ts', tostring(now_us))
redis.call('PEXPIRE', KEYS[1], ttl_ms)

return allowed
`

// RateLimiterHandle is the lifecycle surface the gateway keeps for the
// active rate limiter regardless of its store (in-memory or redis).
type RateLimiterHandle interface {
	// Stop releases limiter resources (cleanup goroutines, connections).
	Stop()

	// UpdateConfig applies new rate limiting parameters.
	UpdateConfig(cfg *config.RateLimitConfig)
}

// Compile-time assertions: both limiters satisfy the lifecycle handle.
var (
	_ RateLimiterHandle = (*RateLimiter)(nil)
	_ RateLimiterHandle = (*RedisRateLimiter)(nil)
)

// RedisRateLimiter is a distributed token-bucket rate limiter backed by
// Redis (standalone or Sentinel). Token buckets are shared across gateway
// instances, honoring RequestsPerSecond, Burst and PerClient semantics.
type RedisRateLimiter struct {
	client      redis.UniversalClient
	script      *redis.Script
	scope       string
	keyPrefix   string
	failOpen    bool
	opTimeout   time.Duration
	logger      observability.Logger
	hitCallback RateLimitHitFunc

	// mu guards the mutable limiting parameters below (hot-reload).
	mu        sync.RWMutex
	rps       int
	burst     int
	perClient bool

	// nowFunc returns the current time. It exists as a seam for
	// deterministic refill tests and defaults to time.Now.
	nowFunc func() time.Time

	// lastOutageWarn holds the unix-nano timestamp of the last outage
	// WARN log for rate-limited outage logging.
	lastOutageWarn atomic.Int64

	// stopped prevents double Close on the redis client.
	stopped atomic.Bool
}

// RedisRateLimiterOption is a functional option for the redis rate limiter.
type RedisRateLimiterOption func(*redisRateLimiterOptions)

// redisRateLimiterOptions holds optional constructor dependencies.
type redisRateLimiterOptions struct {
	vaultClient vault.Client
	hitCallback RateLimitHitFunc
	client      redis.UniversalClient
	nowFunc     func() time.Time
}

// WithRedisRateLimiterVaultClient supplies a Vault client for resolving
// Redis passwords referenced by Vault paths.
func WithRedisRateLimiterVaultClient(client vault.Client) RedisRateLimiterOption {
	return func(o *redisRateLimiterOptions) {
		o.vaultClient = client
	}
}

// WithRedisRateLimiterHitCallback sets a callback invoked on rate limit hits.
func WithRedisRateLimiterHitCallback(fn RateLimitHitFunc) RedisRateLimiterOption {
	return func(o *redisRateLimiterOptions) {
		o.hitCallback = fn
	}
}

// WithRedisRateLimiterClient injects a pre-built Redis client, bypassing
// connection construction. Used in tests with miniredis.
func WithRedisRateLimiterClient(client redis.UniversalClient) RedisRateLimiterOption {
	return func(o *redisRateLimiterOptions) {
		o.client = client
	}
}

// WithRedisRateLimiterNowFunc overrides the time source for deterministic
// refill tests.
func WithRedisRateLimiterNowFunc(now func() time.Time) RedisRateLimiterOption {
	return func(o *redisRateLimiterOptions) {
		o.nowFunc = now
	}
}

// NewRedisRateLimiter creates a distributed rate limiter from configuration.
// scope isolates bucket key spaces (e.g. "global" or a route name).
//
// Construction fails on configuration errors (missing redis block, invalid
// URL, Vault resolution failures) regardless of the failure policy. Initial
// connectivity failures are fatal only when failOpen is false; with
// failOpen=true (default) the limiter starts degraded, allows traffic, and
// recovers transparently once Redis becomes reachable.
func NewRedisRateLimiter(
	ctx context.Context,
	cfg *config.RateLimitConfig,
	scope string,
	logger observability.Logger,
	opts ...RedisRateLimiterOption,
) (*RedisRateLimiter, error) {
	if cfg == nil || cfg.Redis.IsEmpty() {
		return nil, errors.New("redis rate limiter requires redis configuration with url or sentinel")
	}
	if logger == nil {
		logger = observability.NopLogger()
	}

	o := &redisRateLimiterOptions{}
	for _, opt := range opts {
		opt(o)
	}

	failOpen := cfg.Redis.GetEffectiveFailOpen()

	client := o.client
	if client == nil {
		built, err := buildRateLimitRedisClient(ctx, cfg.Redis, failOpen, logger, o.vaultClient)
		if err != nil {
			return nil, err
		}
		client = built
	}

	rl := &RedisRateLimiter{
		client:      client,
		script:      redis.NewScript(redisTokenBucketScript),
		scope:       scope,
		keyPrefix:   resolveRateLimitKeyPrefix(cfg.Redis.KeyPrefix),
		failOpen:    failOpen,
		opTimeout:   resolveRateLimitOpTimeout(cfg.Redis.ReadTimeout.Duration()),
		logger:      logger,
		hitCallback: o.hitCallback,
		rps:         cfg.RequestsPerSecond,
		burst:       cfg.Burst,
		perClient:   cfg.PerClient,
		nowFunc:     time.Now,
	}
	if o.nowFunc != nil {
		rl.nowFunc = o.nowFunc
	}

	logger.Info("redis rate limiter initialized",
		observability.String("scope", scope),
		observability.Int("rps", rl.rps),
		observability.Int("burst", rl.burst),
		observability.Bool("perClient", rl.perClient),
		observability.Bool("failOpen", rl.failOpen),
		observability.Bool("sentinel", !cfg.Redis.Sentinel.IsEmpty()),
		observability.Duration("opTimeout", rl.opTimeout),
	)

	return rl, nil
}

// buildRateLimitRedisClient constructs the Redis client through the shared
// redisclient package. The ping mode follows the failure policy: fail-open
// limiters must not couple gateway startup to Redis availability.
func buildRateLimitRedisClient(
	ctx context.Context,
	redisCfg *config.RateLimitRedisConfig,
	failOpen bool,
	logger observability.Logger,
	vaultClient vault.Client,
) (redis.UniversalClient, error) {
	pingMode := redisclient.PingRequired
	if failOpen {
		pingMode = redisclient.PingBestEffort
	}

	clientOpts := []redisclient.Option{redisclient.WithPingMode(pingMode)}
	if vaultClient != nil {
		clientOpts = append(clientOpts, redisclient.WithVaultClient(vaultClient))
	}

	client, err := redisclient.New(ctx, redisclient.FromRateLimitRedisConfig(redisCfg), logger, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to build redis rate limiter client: %w", err)
	}
	return client, nil
}

// resolveRateLimitKeyPrefix returns the key prefix, defaulting to "avapigw:".
func resolveRateLimitKeyPrefix(prefix string) string {
	if prefix == "" {
		return defaultRedisRateLimitKeyPrefix
	}
	return prefix
}

// resolveRateLimitOpTimeout returns the per-decision timeout, defaulting
// to 100ms so Redis latency never adds unbounded delay.
func resolveRateLimitOpTimeout(readTimeout time.Duration) time.Duration {
	if readTimeout > 0 {
		return readTimeout
	}
	return defaultRedisRateLimitOpTimeout
}

// Allow reports whether the request identified by clientIP is allowed.
// Redis failures resolve according to the failure policy: fail-open allows
// the request and records the failure; fail-closed denies it. Either way
// the decision is bounded by the per-operation timeout.
func (rl *RedisRateLimiter) Allow(ctx context.Context, clientIP string) bool {
	rl.mu.RLock()
	rps, burst, perClient := rl.rps, rl.burst, rl.perClient
	rl.mu.RUnlock()

	key := rl.bucketKey(clientIP, perClient)
	routeName := routeLabelFromContext(ctx)

	opCtx, cancel := context.WithTimeout(ctx, rl.opTimeout)
	defer cancel()

	start := time.Now()
	allowed, err := rl.runTokenBucket(opCtx, key, rps, burst)
	GetMiddlewareMetrics().redisRateLimitDuration.WithLabelValues(routeName).
		Observe(time.Since(start).Seconds())

	if err != nil {
		return rl.resolveFailure(err, key, routeName)
	}

	if allowed {
		GetMiddlewareMetrics().redisRateLimitAllowed.WithLabelValues(routeName).Inc()
	} else {
		GetMiddlewareMetrics().redisRateLimitDenied.WithLabelValues(routeName).Inc()
	}
	return allowed
}

// runTokenBucket executes the atomic token bucket script. go-redis Script
// uses EVALSHA and transparently falls back to SCRIPT LOAD + EVAL when the
// script is not cached (NOSCRIPT), e.g. after a failover.
func (rl *RedisRateLimiter) runTokenBucket(
	ctx context.Context, key string, rps, burst int,
) (bool, error) {
	nowMicros := rl.nowFunc().UnixMicro()
	idleTTL := idleBucketTTL(rps, burst)

	res, err := rl.script.Run(ctx, rl.client,
		[]string{key},
		rps, burst, nowMicros, idleTTL.Milliseconds(),
	).Int()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

// bucketKey builds the Redis key for the bucket. Per-client limiting
// appends the client identity so every client gets its own bucket.
func (rl *RedisRateLimiter) bucketKey(clientIP string, perClient bool) string {
	key := rl.keyPrefix + "ratelimit:" + rl.scope
	if perClient {
		key += ":client:" + clientIP
	}
	return key
}

// idleBucketTTL computes the idle-bucket expiry: the time to fully refill
// the bucket plus a safety margin. Expired buckets restart full, which is
// exactly the state a fully refilled bucket would be in.
func idleBucketTTL(rps, burst int) time.Duration {
	if rps <= 0 {
		return redisRateLimitIdleTTLMargin
	}
	refill := time.Duration(burst) * time.Second / time.Duration(rps)
	return refill + redisRateLimitIdleTTLMargin
}

// resolveFailure applies the failure policy to a Redis error, records the
// failure metric, and emits rate-limited outage logging (one WARN per
// outage window, DEBUG otherwise).
func (rl *RedisRateLimiter) resolveFailure(err error, key, routeName string) bool {
	policy := failPolicyClosed
	if rl.failOpen {
		policy = failPolicyOpen
	}
	GetMiddlewareMetrics().redisRateLimitErrors.WithLabelValues(routeName, policy).Inc()

	fields := []observability.Field{
		observability.String("scope", rl.scope),
		observability.String("key", key),
		observability.Bool("failOpen", rl.failOpen),
		observability.Error(err),
	}
	if rl.shouldWarnOutage() {
		rl.logger.Warn("redis rate limiter unavailable, applying failure policy", fields...)
	} else {
		rl.logger.Debug("redis rate limiter unavailable, applying failure policy", fields...)
	}

	return rl.failOpen
}

// shouldWarnOutage reports whether an outage WARN should be emitted now,
// allowing at most one WARN per redisOutageWarnInterval. The timestamp is
// advanced with CompareAndSwap so concurrent failures elect a single warner
// (no TOCTOU race between reading and updating the timestamp).
func (rl *RedisRateLimiter) shouldWarnOutage() bool {
	now := rl.nowFunc().UnixNano()
	last := rl.lastOutageWarn.Load()
	if now-last < redisOutageWarnInterval.Nanoseconds() {
		return false
	}
	return rl.lastOutageWarn.CompareAndSwap(last, now)
}

// Stop closes the Redis client. It is safe to call multiple times.
func (rl *RedisRateLimiter) Stop() {
	if rl.stopped.CompareAndSwap(false, true) {
		if err := rl.client.Close(); err != nil {
			rl.logger.Warn("failed to close redis rate limiter client",
				observability.Error(err),
			)
		}
	}
}

// UpdateConfig applies new rate limiting parameters. Connection settings
// (URL, Sentinel, pool, timeouts) are intentionally not hot-swapped; the
// new rps/burst values take effect on the next decision because they are
// script arguments rather than stored bucket state.
// Invalid parameters (rps < 1 or burst < 1) are rejected with a logged
// error: a zero burst would make the Lua token bucket start empty and
// silently deny every request, so the previous configuration stays in
// effect instead.
func (rl *RedisRateLimiter) UpdateConfig(cfg *config.RateLimitConfig) {
	if cfg == nil {
		return
	}
	if !validRateLimitParams(cfg) {
		logInvalidRateLimitUpdate(rl.logger, rl.scope, cfg)
		return
	}

	rl.mu.Lock()
	rl.rps = cfg.RequestsPerSecond
	rl.burst = cfg.Burst
	rl.perClient = cfg.PerClient
	rl.mu.Unlock()

	rl.logger.Info("redis rate limiter configuration updated",
		observability.String("scope", rl.scope),
		observability.Int("rps", cfg.RequestsPerSecond),
		observability.Int("burst", cfg.Burst),
		observability.Bool("perClient", cfg.PerClient),
	)
}

// allowHTTP implements httpRateLimiter.
func (rl *RedisRateLimiter) allowHTTP(ctx context.Context, clientIP string) bool {
	return rl.Allow(ctx, clientIP)
}

// middlewareLogger implements httpRateLimiter.
func (rl *RedisRateLimiter) middlewareLogger() observability.Logger { return rl.logger }

// hitFunc implements httpRateLimiter.
func (rl *RedisRateLimiter) hitFunc() RateLimitHitFunc { return rl.hitCallback }

// storeLabel implements httpRateLimiter.
func (rl *RedisRateLimiter) storeLabel() string { return config.RateLimitStoreRedis }

// RedisRateLimit returns a middleware that applies distributed rate
// limiting through the redis-backed limiter.
func RedisRateLimit(rl *RedisRateLimiter) func(http.Handler) http.Handler {
	return rateLimitHTTPMiddleware(rl)
}

// routeLabelFromContext returns the bounded route label for metrics.
func routeLabelFromContext(ctx context.Context) string {
	if route := util.RouteFromContext(ctx); route != "" {
		return route
	}
	return unknownRoute
}

// RateLimitDeps carries optional dependencies for store-aware rate limiter
// construction.
type RateLimitDeps struct {
	// VaultClient resolves Redis passwords referenced by Vault paths.
	VaultClient vault.Client

	// HitCallback is invoked when a rate limit hit occurs.
	HitCallback RateLimitHitFunc
}

// NewRateLimitMiddleware builds rate limit middleware from configuration,
// selecting the store backend (in-memory token bucket or redis-backed
// distributed limiter). scope isolates redis bucket key spaces (e.g.
// "global" or a route name). It returns the middleware, a lifecycle handle
// for Stop/UpdateConfig (nil when rate limiting is disabled), and an error
// when a redis-backed limiter cannot be constructed.
//
// The in-memory store is the default: existing configurations without a
// store field keep their exact previous behavior.
func NewRateLimitMiddleware(
	ctx context.Context,
	cfg *config.RateLimitConfig,
	scope string,
	logger observability.Logger,
	deps RateLimitDeps,
) (func(http.Handler) http.Handler, RateLimiterHandle, error) {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}, nil, nil
	}

	if cfg.GetEffectiveStore() == config.RateLimitStoreRedis {
		opts := []RedisRateLimiterOption{}
		if deps.VaultClient != nil {
			opts = append(opts, WithRedisRateLimiterVaultClient(deps.VaultClient))
		}
		if deps.HitCallback != nil {
			opts = append(opts, WithRedisRateLimiterHitCallback(deps.HitCallback))
		}
		rrl, err := NewRedisRateLimiter(ctx, cfg, scope, logger, opts...)
		if err != nil {
			return nil, nil, err
		}
		return RedisRateLimit(rrl), rrl, nil
	}

	memOpts := []RateLimiterOption{}
	if deps.HitCallback != nil {
		memOpts = append(memOpts, WithRateLimitHitCallback(deps.HitCallback))
	}
	mw, rl := RateLimitFromConfig(cfg, logger, memOpts...)
	if rl == nil {
		return mw, nil, nil
	}
	return mw, rl, nil
}
