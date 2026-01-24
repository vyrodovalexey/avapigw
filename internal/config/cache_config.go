// Package config provides configuration types and loading for the API Gateway.
package config

// CacheConfig represents caching configuration for a route.
type CacheConfig struct {
	// Enabled indicates whether caching is enabled.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Type is the cache backend type: "memory" or "redis".
	Type string `yaml:"type" json:"type"`

	// TTL is the default time-to-live for cached entries.
	TTL Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// MaxEntries is the maximum number of entries for memory cache.
	MaxEntries int `yaml:"maxEntries,omitempty" json:"maxEntries,omitempty"`

	// Redis contains Redis-specific configuration.
	Redis *RedisCacheConfig `yaml:"redis,omitempty" json:"redis,omitempty"`

	// KeyConfig contains cache key generation configuration.
	KeyConfig *CacheKeyConfig `yaml:"keyConfig,omitempty" json:"keyConfig,omitempty"`

	// HonorCacheControl when true, respects Cache-Control headers.
	HonorCacheControl bool `yaml:"honorCacheControl,omitempty" json:"honorCacheControl,omitempty"`

	// StaleWhileRevalidate allows serving stale content while revalidating.
	StaleWhileRevalidate Duration `yaml:"staleWhileRevalidate,omitempty" json:"staleWhileRevalidate,omitempty"`

	// NegativeCacheTTL is the TTL for caching error responses.
	NegativeCacheTTL Duration `yaml:"negativeCacheTTL,omitempty" json:"negativeCacheTTL,omitempty"`
}

// RedisCacheConfig contains Redis-specific cache configuration.
type RedisCacheConfig struct {
	// URL is the Redis connection URL.
	// Format: redis://[user:password@]host:port[/db]
	URL string `yaml:"url" json:"url"`

	// PoolSize is the maximum number of connections in the pool.
	PoolSize int `yaml:"poolSize,omitempty" json:"poolSize,omitempty"`

	// ConnectTimeout is the timeout for establishing connections.
	ConnectTimeout Duration `yaml:"connectTimeout,omitempty" json:"connectTimeout,omitempty"`

	// ReadTimeout is the timeout for read operations.
	ReadTimeout Duration `yaml:"readTimeout,omitempty" json:"readTimeout,omitempty"`

	// WriteTimeout is the timeout for write operations.
	WriteTimeout Duration `yaml:"writeTimeout,omitempty" json:"writeTimeout,omitempty"`

	// KeyPrefix is a prefix added to all cache keys.
	KeyPrefix string `yaml:"keyPrefix,omitempty" json:"keyPrefix,omitempty"`

	// TLS contains TLS configuration for Redis connections.
	TLS *TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// Retry contains retry configuration for initial connection.
	Retry *RedisRetryConfig `yaml:"retry,omitempty" json:"retry,omitempty"`
}

// RedisRetryConfig contains retry configuration for Redis connections.
type RedisRetryConfig struct {
	// MaxRetries is the maximum number of retry attempts for initial connection.
	// Default is 3.
	MaxRetries int `yaml:"maxRetries,omitempty" json:"maxRetries,omitempty"`

	// InitialBackoff is the initial backoff duration between retries.
	// Default is 100ms.
	InitialBackoff Duration `yaml:"initialBackoff,omitempty" json:"initialBackoff,omitempty"`

	// MaxBackoff is the maximum backoff duration between retries.
	// Default is 30s.
	MaxBackoff Duration `yaml:"maxBackoff,omitempty" json:"maxBackoff,omitempty"`
}

// GetMaxRetries returns the effective max retries.
func (c *RedisRetryConfig) GetMaxRetries() int {
	if c == nil || c.MaxRetries <= 0 {
		return DefaultRetryMaxRetries
	}
	return c.MaxRetries
}

// GetInitialBackoff returns the effective initial backoff.
func (c *RedisRetryConfig) GetInitialBackoff() Duration {
	if c == nil || c.InitialBackoff <= 0 {
		return Duration(DefaultRetryInitialBackoff)
	}
	return c.InitialBackoff
}

// GetMaxBackoff returns the effective max backoff.
func (c *RedisRetryConfig) GetMaxBackoff() Duration {
	if c == nil || c.MaxBackoff <= 0 {
		return Duration(DefaultRetryMaxBackoff)
	}
	return c.MaxBackoff
}

// CacheKeyConfig contains configuration for cache key generation.
type CacheKeyConfig struct {
	// IncludeMethod when true, includes HTTP method in the cache key.
	IncludeMethod bool `yaml:"includeMethod,omitempty" json:"includeMethod,omitempty"`

	// IncludePath when true, includes request path in the cache key.
	IncludePath bool `yaml:"includePath,omitempty" json:"includePath,omitempty"`

	// IncludeQueryParams specifies query parameters to include in the cache key.
	IncludeQueryParams []string `yaml:"includeQueryParams,omitempty" json:"includeQueryParams,omitempty"`

	// IncludeHeaders specifies headers to include in the cache key.
	IncludeHeaders []string `yaml:"includeHeaders,omitempty" json:"includeHeaders,omitempty"`

	// IncludeBodyHash when true, includes a hash of the request body.
	IncludeBodyHash bool `yaml:"includeBodyHash,omitempty" json:"includeBodyHash,omitempty"`

	// KeyTemplate is a custom template for generating cache keys.
	// Supports placeholders: {{.Method}}, {{.Path}}, {{.Query.param}}, {{.Header.name}}
	KeyTemplate string `yaml:"keyTemplate,omitempty" json:"keyTemplate,omitempty"`
}

// CacheType constants for cache backend types.
const (
	// CacheTypeMemory uses in-memory caching.
	CacheTypeMemory = "memory"

	// CacheTypeRedis uses Redis for caching.
	CacheTypeRedis = "redis"
)

// DefaultCacheConfig returns default cache configuration.
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Enabled:    false,
		Type:       CacheTypeMemory,
		TTL:        Duration(DefaultCacheTTL),
		MaxEntries: DefaultCacheMaxEntries,
		KeyConfig: &CacheKeyConfig{
			IncludeMethod: true,
			IncludePath:   true,
		},
	}
}

// DefaultRedisCacheConfig returns default Redis cache configuration.
func DefaultRedisCacheConfig() *RedisCacheConfig {
	return &RedisCacheConfig{
		PoolSize:       DefaultRedisPoolSize,
		ConnectTimeout: Duration(DefaultRedisConnectTimeout),
		ReadTimeout:    Duration(DefaultRedisReadTimeout),
		WriteTimeout:   Duration(DefaultRedisWriteTimeout),
		KeyPrefix:      DefaultRedisKeyPrefix,
	}
}

// IsEmpty returns true if the CacheConfig has no meaningful configuration.
func (cc *CacheConfig) IsEmpty() bool {
	if cc == nil {
		return true
	}
	return !cc.Enabled
}

// IsEmpty returns true if the RedisCacheConfig has no configuration.
func (rcc *RedisCacheConfig) IsEmpty() bool {
	if rcc == nil {
		return true
	}
	return rcc.URL == ""
}

// IsEmpty returns true if the CacheKeyConfig has no configuration.
func (ckc *CacheKeyConfig) IsEmpty() bool {
	if ckc == nil {
		return true
	}
	return !ckc.IncludeMethod &&
		!ckc.IncludePath &&
		len(ckc.IncludeQueryParams) == 0 &&
		len(ckc.IncludeHeaders) == 0 &&
		!ckc.IncludeBodyHash &&
		ckc.KeyTemplate == ""
}
