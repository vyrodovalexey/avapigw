// Package cache provides caching capabilities for the API Gateway.
package cache

import (
	"context"
	"errors"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Common cache errors.
var (
	// ErrCacheMiss indicates that the key was not found in the cache.
	ErrCacheMiss = errors.New("cache miss")

	// ErrCacheDisabled indicates that caching is disabled.
	ErrCacheDisabled = errors.New("cache disabled")

	// ErrInvalidConfig indicates that the cache configuration is invalid.
	ErrInvalidConfig = errors.New("invalid cache configuration")

	// ErrConnectionFailed indicates that the cache connection failed.
	ErrConnectionFailed = errors.New("cache connection failed")

	// ErrKeyTooLong indicates that the cache key is too long.
	ErrKeyTooLong = errors.New("cache key too long")
)

// Cache is the main interface for caching.
type Cache interface {
	// Get retrieves a value from the cache.
	// Returns ErrCacheMiss if the key is not found.
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores a value in the cache with the given TTL.
	// A TTL of 0 means the entry never expires.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes a value from the cache.
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists in the cache.
	Exists(ctx context.Context, key string) (bool, error)

	// Close closes the cache connection.
	Close() error
}

// CacheWithStats extends Cache with statistics.
type CacheWithStats interface {
	Cache

	// Stats returns cache statistics.
	Stats() CacheStats
}

// CacheStats contains cache statistics.
type CacheStats struct {
	// Hits is the number of cache hits.
	Hits int64

	// Misses is the number of cache misses.
	Misses int64

	// Size is the current number of entries in the cache.
	Size int64

	// Bytes is the current size in bytes (if available).
	Bytes int64
}

// HitRate returns the cache hit rate as a percentage.
func (s CacheStats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0
	}
	return float64(s.Hits) / float64(total) * 100
}

// New creates a new cache based on the configuration.
func New(cfg *config.CacheConfig, logger observability.Logger) (Cache, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}

	if !cfg.Enabled {
		return newDisabledCache(), nil
	}

	if logger == nil {
		logger = observability.NopLogger()
	}

	switch cfg.Type {
	case config.CacheTypeMemory, "":
		return newMemoryCache(cfg, logger)
	case config.CacheTypeRedis:
		return newRedisCache(cfg, logger)
	default:
		return nil, errors.New("unknown cache type: " + cfg.Type)
	}
}

// disabledCache is a cache that always returns ErrCacheDisabled.
type disabledCache struct{}

func newDisabledCache() Cache {
	return &disabledCache{}
}

func (c *disabledCache) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, ErrCacheDisabled
}

func (c *disabledCache) Set(_ context.Context, _ string, _ []byte, _ time.Duration) error {
	return ErrCacheDisabled
}

func (c *disabledCache) Delete(_ context.Context, _ string) error {
	return ErrCacheDisabled
}

func (c *disabledCache) Exists(_ context.Context, _ string) (bool, error) {
	return false, ErrCacheDisabled
}

func (c *disabledCache) Close() error {
	return nil
}

// CacheEntry represents a cached entry with metadata.
type CacheEntry struct {
	// Value is the cached value.
	Value []byte

	// CreatedAt is when the entry was created.
	CreatedAt time.Time

	// ExpiresAt is when the entry expires.
	ExpiresAt time.Time

	// Stale indicates if the entry is stale but still usable.
	Stale bool
}

// IsExpired returns true if the entry has expired.
func (e *CacheEntry) IsExpired() bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(e.ExpiresAt)
}

// TTL returns the remaining time-to-live.
func (e *CacheEntry) TTL() time.Duration {
	if e.ExpiresAt.IsZero() {
		return 0
	}
	ttl := time.Until(e.ExpiresAt)
	if ttl < 0 {
		return 0
	}
	return ttl
}
