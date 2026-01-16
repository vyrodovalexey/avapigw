package store

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Prometheus metrics for Redis store operations
var (
	redisStoreOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_store_operations_total",
			Help: "Total number of Redis store operations",
		},
		[]string{"operation", "status"},
	)

	redisStoreOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "redis_store_operation_duration_seconds",
			Help:    "Duration of Redis store operations in seconds",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		},
		[]string{"operation"},
	)

	redisStoreConnectionRetries = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "redis_store_connection_retries_total",
			Help: "Total number of Redis connection retry attempts",
		},
	)

	redisStoreConnectionErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "redis_store_connection_errors_total",
			Help: "Total number of Redis connection errors",
		},
	)
)

// incrementWithExpiryScript is the Lua script for atomic increment with expiry.
// KEYS[1] = key
// ARGV[1] = delta
// ARGV[2] = expiration in seconds
var incrementWithExpiryScript = redis.NewScript(`
	local current = redis.call('INCRBY', KEYS[1], ARGV[1])
	if current == tonumber(ARGV[1]) then
		redis.call('EXPIRE', KEYS[1], ARGV[2])
	end
	return current
`)

// RedisStore implements Store using Redis.
type RedisStore struct {
	client *redis.Client
	prefix string
	logger *zap.Logger
	closed bool
	mu     sync.Mutex
}

// RedisConfig holds configuration for Redis store.
type RedisConfig struct {
	Address  string
	Password string
	DB       int
	Prefix   string

	// Connection pool settings
	PoolSize     int
	MinIdleConns int
	MaxRetries   int

	// Timeouts
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// Backoff configuration for connection retries
	// InitialBackoff is the initial backoff duration for connection retries.
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration for connection retries.
	MaxBackoff time.Duration

	// ConnectionRetries is the number of connection retry attempts.
	ConnectionRetries int

	// Logger for the Redis store.
	Logger *zap.Logger
}

// DefaultRedisConfig returns a RedisConfig with default values.
func DefaultRedisConfig() *RedisConfig {
	return &RedisConfig{
		Address:           "localhost:6379",
		Password:          "",
		DB:                0,
		Prefix:            "ratelimit:",
		PoolSize:          10,
		MinIdleConns:      2,
		MaxRetries:        3,
		DialTimeout:       5 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        10 * time.Second,
		ConnectionRetries: 5,
	}
}

// NewRedisStore creates a new Redis store.
func NewRedisStore(addr, password string, db int, prefix string) (*RedisStore, error) {
	config := DefaultRedisConfig()
	config.Address = addr
	config.Password = password
	config.DB = db
	if prefix != "" {
		config.Prefix = prefix
	}

	return NewRedisStoreWithConfig(config)
}

// NewRedisStoreWithConfig creates a new Redis store with custom configuration.
// Uses exponential backoff with decorrelated jitter for connection retries
// to prevent thundering herd problems.
func NewRedisStoreWithConfig(config *RedisConfig) (*RedisStore, error) {
	config, logger := normalizeRedisConfig(config)
	client := createRedisClient(config)
	connConfig := buildConnectionConfig(config)

	store, err := connectWithRetry(client, config, connConfig, logger)
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	return store, nil
}

// redisConnectionConfig holds normalized connection retry settings.
type redisConnectionConfig struct {
	maxRetries     int
	initialBackoff time.Duration
	maxBackoff     time.Duration
	totalTimeout   time.Duration
}

// normalizeRedisConfig ensures config has all required defaults.
func normalizeRedisConfig(config *RedisConfig) (*RedisConfig, *zap.Logger) {
	if config == nil {
		config = DefaultRedisConfig()
	}

	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return config, logger
}

// createRedisClient creates a new Redis client with the given configuration.
func createRedisClient(config *RedisConfig) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:         config.Address,
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
		MaxRetries:   config.MaxRetries,
		DialTimeout:  config.DialTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	})
}

// buildConnectionConfig creates normalized connection retry settings.
func buildConnectionConfig(config *RedisConfig) *redisConnectionConfig {
	maxRetries := config.ConnectionRetries
	if maxRetries <= 0 {
		maxRetries = 5
	}

	initialBackoff := config.InitialBackoff
	if initialBackoff <= 0 {
		initialBackoff = 100 * time.Millisecond
	}

	maxBackoff := config.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 10 * time.Second
	}

	totalTimeout := time.Duration(maxRetries+1) * config.DialTimeout
	if totalTimeout > 2*time.Minute {
		totalTimeout = 2 * time.Minute
	}

	return &redisConnectionConfig{
		maxRetries:     maxRetries,
		initialBackoff: initialBackoff,
		maxBackoff:     maxBackoff,
		totalTimeout:   totalTimeout,
	}
}

// connectWithRetry attempts to connect to Redis with exponential backoff.
func connectWithRetry(
	client *redis.Client,
	config *RedisConfig,
	connConfig *redisConnectionConfig,
	logger *zap.Logger,
) (*RedisStore, error) {
	backoff := newDecorrelatedJitterBackoff(connConfig.initialBackoff, connConfig.maxBackoff)

	overallCtx, overallCancel := context.WithTimeout(context.Background(), connConfig.totalTimeout)
	defer overallCancel()

	var lastErr error
	for attempt := 0; attempt <= connConfig.maxRetries; attempt++ {
		if err := overallCtx.Err(); err != nil {
			return nil, fmt.Errorf("connection timeout exceeded: %w", err)
		}

		if store := tryConnect(overallCtx, client, config, logger, attempt); store != nil {
			return store, nil
		}

		ctx, cancel := context.WithTimeout(overallCtx, config.DialTimeout)
		lastErr = client.Ping(ctx).Err()
		cancel()

		redisStoreConnectionErrors.Inc()

		if attempt >= connConfig.maxRetries {
			break
		}

		retryErr := waitForConnectionRetry(
			overallCtx, backoff, logger, config.Address, attempt, connConfig.maxRetries, lastErr,
		)
		if retryErr != nil {
			return nil, retryErr
		}
	}

	return nil, fmt.Errorf("failed to connect to Redis after %d attempts: %w", connConfig.maxRetries+1, lastErr)
}

// tryConnect attempts a single connection to Redis.
func tryConnect(
	ctx context.Context,
	client *redis.Client,
	config *RedisConfig,
	logger *zap.Logger,
	attempt int,
) *RedisStore {
	pingCtx, cancel := context.WithTimeout(ctx, config.DialTimeout)
	err := client.Ping(pingCtx).Err()
	cancel()

	if err != nil {
		return nil
	}

	if attempt > 0 {
		logger.Info("Redis connection established after retry",
			zap.String("address", config.Address),
			zap.Int("attempt", attempt+1),
		)
	}

	return &RedisStore{
		client: client,
		prefix: config.Prefix,
		logger: logger,
	}
}

// waitForConnectionRetry waits before the next connection attempt.
func waitForConnectionRetry(
	ctx context.Context,
	backoff *decorrelatedJitterBackoff,
	logger *zap.Logger,
	address string,
	attempt, maxRetries int,
	err error,
) error {
	wait := backoff.next(attempt)

	logger.Debug("Redis connection failed, retrying",
		zap.String("address", address),
		zap.Int("attempt", attempt+1),
		zap.Int("max_retries", maxRetries),
		zap.Duration("backoff", wait),
		zap.Error(err),
	)

	redisStoreConnectionRetries.Inc()

	select {
	case <-ctx.Done():
		return fmt.Errorf("connection timeout exceeded during backoff: %w", ctx.Err())
	case <-time.After(wait):
		return nil
	}
}

// decorrelatedJitterBackoff implements AWS-style decorrelated jitter backoff
// for preventing thundering herd problems.
type decorrelatedJitterBackoff struct {
	initial time.Duration
	max     time.Duration
	current time.Duration
}

// newDecorrelatedJitterBackoff creates a new decorrelated jitter backoff.
func newDecorrelatedJitterBackoff(initial, maxDuration time.Duration) *decorrelatedJitterBackoff {
	return &decorrelatedJitterBackoff{
		initial: initial,
		max:     maxDuration,
		current: initial,
	}
}

// next returns the next backoff duration using decorrelated jitter.
// Formula: sleep = min(cap, random_between(base, sleep * 3))
func (b *decorrelatedJitterBackoff) next(attempt int) time.Duration {
	if attempt == 0 {
		b.current = b.initial
		return b.current
	}

	// Decorrelated jitter formula: sleep = min(cap, random_between(base, sleep * 3))
	minBackoff := float64(b.initial)
	maxBackoff := float64(b.current) * 3

	//nolint:gosec // weak random is acceptable for jitter
	backoff := minBackoff + float64(time.Now().UnixNano()%1000)/1000.0*(maxBackoff-minBackoff)

	if backoff > float64(b.max) {
		backoff = float64(b.max)
	}

	b.current = time.Duration(backoff)
	return b.current
}

// prefixKey adds the prefix to the key.
func (s *RedisStore) prefixKey(key string) string {
	return s.prefix + key
}

// Get implements Store.
func (s *RedisStore) Get(ctx context.Context, key string) (int64, error) {
	start := time.Now()

	// Check for context cancellation before performing the operation
	// to fail fast and avoid unnecessary work.
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("context error before redis get: %w", err)
	}

	val, err := s.client.Get(ctx, s.prefixKey(key)).Result()

	// Record metrics
	duration := time.Since(start)
	redisStoreOperationDuration.WithLabelValues("get").Observe(duration.Seconds())

	if err == redis.Nil {
		redisStoreOperationsTotal.WithLabelValues("get", "not_found").Inc()
		return 0, &ErrKeyNotFound{Key: key}
	}
	if err != nil {
		redisStoreOperationsTotal.WithLabelValues("get", "error").Inc()
		return 0, fmt.Errorf("redis get error: %w", err)
	}

	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		redisStoreOperationsTotal.WithLabelValues("get", "error").Inc()
		return 0, fmt.Errorf("failed to parse value: %w", err)
	}

	redisStoreOperationsTotal.WithLabelValues("get", "success").Inc()
	return n, nil
}

// Set implements Store.
func (s *RedisStore) Set(ctx context.Context, key string, value int64, expiration time.Duration) error {
	start := time.Now()

	// Check for context cancellation before performing the operation
	// to fail fast and avoid unnecessary work.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error before redis set: %w", err)
	}

	err := s.client.Set(ctx, s.prefixKey(key), value, expiration).Err()

	// Record metrics
	duration := time.Since(start)
	redisStoreOperationDuration.WithLabelValues("set").Observe(duration.Seconds())

	if err != nil {
		redisStoreOperationsTotal.WithLabelValues("set", "error").Inc()
		return fmt.Errorf("redis set error: %w", err)
	}

	redisStoreOperationsTotal.WithLabelValues("set", "success").Inc()
	return nil
}

// Increment implements Store.
func (s *RedisStore) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	start := time.Now()

	// Check for context cancellation before performing the operation
	// to fail fast and avoid unnecessary work.
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("context error before redis incr: %w", err)
	}

	val, err := s.client.IncrBy(ctx, s.prefixKey(key), delta).Result()

	// Record metrics
	duration := time.Since(start)
	redisStoreOperationDuration.WithLabelValues("increment").Observe(duration.Seconds())

	if err != nil {
		redisStoreOperationsTotal.WithLabelValues("increment", "error").Inc()
		return 0, fmt.Errorf("redis incr error: %w", err)
	}

	redisStoreOperationsTotal.WithLabelValues("increment", "success").Inc()
	return val, nil
}

// IncrementWithExpiry implements Store using a Lua script for atomicity.
func (s *RedisStore) IncrementWithExpiry(
	ctx context.Context,
	key string,
	delta int64,
	expiration time.Duration,
) (int64, error) {
	start := time.Now()

	// Check for context cancellation before performing the operation
	// to fail fast and avoid unnecessary work.
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("context error before redis incr with expiry: %w", err)
	}

	prefixedKey := s.prefixKey(key)
	expirationSecs := int64(expiration.Seconds())
	if expirationSecs < 1 {
		expirationSecs = 1
	}

	result, err := incrementWithExpiryScript.Run(ctx, s.client, []string{prefixedKey}, delta, expirationSecs).Result()

	// Record metrics
	duration := time.Since(start)
	redisStoreOperationDuration.WithLabelValues("increment_with_expiry").Observe(duration.Seconds())

	if err != nil {
		redisStoreOperationsTotal.WithLabelValues("increment_with_expiry", "error").Inc()
		return 0, fmt.Errorf("redis script error: %w", err)
	}

	// Safe type assertion to prevent panic
	val, ok := result.(int64)
	if !ok {
		redisStoreOperationsTotal.WithLabelValues("increment_with_expiry", "error").Inc()
		return 0, fmt.Errorf("redis script returned unexpected type: %T", result)
	}

	redisStoreOperationsTotal.WithLabelValues("increment_with_expiry", "success").Inc()
	return val, nil
}

// Delete implements Store.
func (s *RedisStore) Delete(ctx context.Context, key string) error {
	start := time.Now()

	// Check for context cancellation before performing the operation
	// to fail fast and avoid unnecessary work.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error before redis del: %w", err)
	}

	err := s.client.Del(ctx, s.prefixKey(key)).Err()

	// Record metrics
	duration := time.Since(start)
	redisStoreOperationDuration.WithLabelValues("delete").Observe(duration.Seconds())

	if err != nil {
		redisStoreOperationsTotal.WithLabelValues("delete", "error").Inc()
		return fmt.Errorf("redis del error: %w", err)
	}

	redisStoreOperationsTotal.WithLabelValues("delete", "success").Inc()
	return nil
}

// Close implements Store.
// Close is idempotent - calling it multiple times is safe.
func (s *RedisStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	return s.client.Close()
}

// Client returns the underlying Redis client.
func (s *RedisStore) Client() *redis.Client {
	return s.client
}

// TokenBucketScript is a Lua script for token bucket rate limiting.
// Returns: allowed (0 or 1), remaining tokens, reset time in ms
var TokenBucketScript = redis.NewScript(`
	local key = KEYS[1]
	local rate = tonumber(ARGV[1])
	local burst = tonumber(ARGV[2])
	local now = tonumber(ARGV[3])
	local requested = tonumber(ARGV[4])
	
	local data = redis.call('HMGET', key, 'tokens', 'last_update')
	local tokens = tonumber(data[1])
	local last_update = tonumber(data[2])
	
	if tokens == nil then
		tokens = burst
		last_update = now
	end
	
	-- Calculate tokens to add based on elapsed time
	local elapsed = (now - last_update) / 1000.0
	tokens = math.min(burst, tokens + (elapsed * rate))
	
	local allowed = 0
	if tokens >= requested then
		tokens = tokens - requested
		allowed = 1
	end
	
	-- Update state
	redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)
	redis.call('EXPIRE', key, math.ceil(burst / rate) + 1)
	
	-- Calculate reset time (time until bucket is full)
	local reset_ms = math.ceil((burst - tokens) / rate * 1000)
	
	return {allowed, math.floor(tokens), reset_ms}
`)

// SlidingWindowScript is a Lua script for sliding window rate limiting.
// Returns: allowed (0 or 1), current count, reset time in ms
var SlidingWindowScript = redis.NewScript(`
	local key = KEYS[1]
	local limit = tonumber(ARGV[1])
	local window_ms = tonumber(ARGV[2])
	local now = tonumber(ARGV[3])
	local requested = tonumber(ARGV[4])
	
	-- Remove old entries
	local window_start = now - window_ms
	redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
	
	-- Count current entries
	local count = redis.call('ZCARD', key)
	
	local allowed = 0
	if count + requested <= limit then
		-- Add new entries
		for i = 1, requested do
			redis.call('ZADD', key, now, now .. ':' .. i .. ':' .. math.random())
		end
		count = count + requested
		allowed = 1
	end
	
	-- Set expiry
	redis.call('EXPIRE', key, math.ceil(window_ms / 1000) + 1)
	
	-- Calculate reset time
	local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
	local reset_ms = window_ms
	if #oldest > 0 then
		reset_ms = tonumber(oldest[2]) + window_ms - now
	end
	
	return {allowed, limit - count, reset_ms}
`)

// FixedWindowScript is a Lua script for fixed window rate limiting.
// Returns: allowed (0 or 1), remaining count, reset time in ms
var FixedWindowScript = redis.NewScript(`
	local key = KEYS[1]
	local limit = tonumber(ARGV[1])
	local window_ms = tonumber(ARGV[2])
	local now = tonumber(ARGV[3])
	local requested = tonumber(ARGV[4])
	
	-- Calculate window key
	local window_start = math.floor(now / window_ms) * window_ms
	local window_key = key .. ':' .. window_start
	
	-- Get current count
	local count = tonumber(redis.call('GET', window_key) or '0')
	
	local allowed = 0
	if count + requested <= limit then
		count = redis.call('INCRBY', window_key, requested)
		-- Set expiry on first request in window
		if count == requested then
			redis.call('PEXPIRE', window_key, window_ms)
		end
		allowed = 1
	end
	
	-- Calculate reset time
	local reset_ms = window_start + window_ms - now
	
	return {allowed, limit - count, reset_ms}
`)
