// Package config provides configuration types and loading for the API Gateway.
package config

import "time"

// Default timeout constants for HTTP listeners.
const (
	// DefaultReadTimeout is the default maximum duration for reading the entire request.
	DefaultReadTimeout = 30 * time.Second

	// DefaultReadHeaderTimeout is the default maximum duration for reading request headers.
	DefaultReadHeaderTimeout = 10 * time.Second

	// DefaultWriteTimeout is the default maximum duration before timing out writes of the response.
	DefaultWriteTimeout = 30 * time.Second

	// DefaultIdleTimeout is the default maximum duration to wait for the next request.
	DefaultIdleTimeout = 120 * time.Second
)

// Default retry configuration constants.
const (
	// DefaultRetryMaxRetries is the default maximum number of retry attempts.
	DefaultRetryMaxRetries = 3

	// DefaultRetryInitialBackoff is the default initial backoff duration between retries.
	DefaultRetryInitialBackoff = 100 * time.Millisecond

	// DefaultRetryMaxBackoff is the default maximum backoff duration between retries.
	DefaultRetryMaxBackoff = 30 * time.Second

	// DefaultRetryJitterFactor is the default jitter factor for retry backoff.
	DefaultRetryJitterFactor = 0.25
)

// Default Redis cache configuration constants.
const (
	// DefaultRedisPoolSize is the default Redis connection pool size.
	DefaultRedisPoolSize = 10

	// DefaultRedisConnectTimeout is the default Redis connection timeout.
	DefaultRedisConnectTimeout = 5 * time.Second

	// DefaultRedisReadTimeout is the default Redis read timeout.
	DefaultRedisReadTimeout = 3 * time.Second

	// DefaultRedisWriteTimeout is the default Redis write timeout.
	DefaultRedisWriteTimeout = 3 * time.Second

	// DefaultRedisKeyPrefix is the default Redis key prefix.
	DefaultRedisKeyPrefix = "avapigw:"
)

// Default cache configuration constants.
const (
	// DefaultCacheTTL is the default cache TTL.
	DefaultCacheTTL = 5 * time.Minute

	// DefaultCacheMaxEntries is the default maximum number of cache entries.
	DefaultCacheMaxEntries = 10000
)

// Default request limits constants.
const (
	// DefaultMaxBodySize is the default maximum request body size (10MB).
	DefaultMaxBodySize = 10 << 20

	// DefaultMaxHeaderSize is the default maximum header size (1MB).
	DefaultMaxHeaderSize = 1 << 20
)

// Default gRPC configuration constants.
const (
	// DefaultGRPCKeepaliveTime is the default gRPC keepalive time.
	DefaultGRPCKeepaliveTime = 30 * time.Second

	// DefaultGRPCKeepaliveTimeout is the default gRPC keepalive timeout.
	DefaultGRPCKeepaliveTimeout = 10 * time.Second

	// DefaultGRPCMaxConnectionIdle is the default gRPC max connection idle time.
	DefaultGRPCMaxConnectionIdle = 5 * time.Minute

	// DefaultGRPCMaxConnectionAge is the default gRPC max connection age.
	DefaultGRPCMaxConnectionAge = 30 * time.Minute

	// DefaultGRPCMaxConnectionAgeGrace is the default gRPC max connection age grace period.
	DefaultGRPCMaxConnectionAgeGrace = 5 * time.Second

	// DefaultGRPCHealthCheckInterval is the default gRPC health check interval.
	DefaultGRPCHealthCheckInterval = 10 * time.Second

	// DefaultGRPCHealthCheckTimeout is the default gRPC health check timeout.
	DefaultGRPCHealthCheckTimeout = 5 * time.Second

	// DefaultGRPCRetryPerTryTimeout is the default gRPC per-try timeout.
	DefaultGRPCRetryPerTryTimeout = 10 * time.Second

	// DefaultGRPCRetryBackoffBase is the default gRPC retry backoff base interval.
	DefaultGRPCRetryBackoffBase = 100 * time.Millisecond

	// DefaultGRPCRetryBackoffMax is the default gRPC retry backoff max interval.
	DefaultGRPCRetryBackoffMax = 1 * time.Second
)

// Default watcher configuration constants.
const (
	// DefaultWatcherDebounceDelay is the default debounce delay for config watcher.
	DefaultWatcherDebounceDelay = 100 * time.Millisecond
)

// Default max sessions configuration constants.
const (
	// DefaultMaxSessionsQueueTimeout is the default timeout for waiting in the queue.
	DefaultMaxSessionsQueueTimeout = 30 * time.Second

	// DefaultMaxSessionsQueueSize is the default queue size (0 = reject immediately).
	DefaultMaxSessionsQueueSize = 0
)

// TLS version constants.
const (
	// TLSVersion12 represents TLS 1.2.
	TLSVersion12 = "TLS12"

	// TLSVersion13 represents TLS 1.3.
	TLSVersion13 = "TLS13"

	// DefaultTLSMinVersion is the default minimum TLS version.
	DefaultTLSMinVersion = TLSVersion12
)
