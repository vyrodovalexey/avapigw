// Package cache provides caching capabilities for the API Gateway.
package cache

import (
	"container/list"
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// memoryCache implements an in-memory LRU cache.
type memoryCache struct {
	logger     observability.Logger
	maxEntries int
	defaultTTL time.Duration

	mu       sync.RWMutex
	items    map[string]*list.Element
	eviction *list.List

	hits   int64
	misses int64

	// stopCh is used to signal the cleanup goroutine to stop
	stopCh chan struct{}
}

// memoryCacheEntry represents an entry in the memory cache.
type memoryCacheEntry struct {
	key       string
	value     []byte
	expiresAt time.Time
}

// newMemoryCache creates a new in-memory cache.
//
//nolint:unparam // error return is for interface consistency with other cache implementations
func newMemoryCache(cfg *config.CacheConfig, logger observability.Logger) (*memoryCache, error) {
	maxEntries := cfg.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 10000
	}

	c := &memoryCache{
		logger:     logger,
		maxEntries: maxEntries,
		defaultTTL: cfg.TTL.Duration(),
		items:      make(map[string]*list.Element),
		eviction:   list.New(),
		stopCh:     make(chan struct{}),
	}

	// Start background cleanup goroutine
	go c.cleanupLoop()

	logger.Info("memory cache initialized",
		observability.Int("maxEntries", maxEntries),
		observability.Duration("defaultTTL", c.defaultTTL))

	return c, nil
}

// cacheTracerName is the OpenTelemetry tracer name for cache operations.
const cacheTracerName = "avapigw/cache"

// Get retrieves a value from the cache.
func (c *memoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	_, span := otel.Tracer(cacheTracerName).Start(ctx, "cache.Get",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("cache.backend", "memory"),
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		GetCacheMetrics().operationDuration.WithLabelValues(
			"memory", "get",
		).Observe(time.Since(start).Seconds())
	}()

	c.mu.Lock()
	defer c.mu.Unlock()

	elem, exists := c.items[key]
	if !exists {
		atomic.AddInt64(&c.misses, 1)
		GetCacheMetrics().missesTotal.WithLabelValues(
			"memory",
		).Inc()
		span.SetAttributes(attribute.Bool("cache.hit", false))
		return nil, ErrCacheMiss
	}

	entry := elem.Value.(*memoryCacheEntry)

	// Check if expired
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		c.removeElement(elem)
		atomic.AddInt64(&c.misses, 1)
		GetCacheMetrics().missesTotal.WithLabelValues(
			"memory",
		).Inc()
		span.SetAttributes(attribute.Bool("cache.hit", false))
		return nil, ErrCacheMiss
	}

	// Move to front (most recently used)
	c.eviction.MoveToFront(elem)

	atomic.AddInt64(&c.hits, 1)
	GetCacheMetrics().hitsTotal.WithLabelValues(
		"memory",
	).Inc()

	span.SetAttributes(
		attribute.Bool("cache.hit", true),
		attribute.Int("cache.value_size", len(entry.value)),
	)

	c.logger.Debug("cache hit",
		observability.String("key", key))

	return entry.value, nil
}

// Set stores a value in the cache.
func (c *memoryCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	_, span := otel.Tracer(cacheTracerName).Start(ctx, "cache.Set",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("cache.backend", "memory"),
			attribute.String("cache.key", key),
			attribute.Int("cache.value_size", len(value)),
		),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		GetCacheMetrics().operationDuration.WithLabelValues(
			"memory", "set",
		).Observe(time.Since(start).Seconds())
	}()

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	entry := &memoryCacheEntry{
		key:       key,
		value:     value,
		expiresAt: expiresAt,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key already exists
	if elem, exists := c.items[key]; exists {
		c.eviction.MoveToFront(elem)
		elem.Value = entry
		c.logger.Debug("cache updated",
			observability.String("key", key),
			observability.Duration("ttl", ttl))
		return nil
	}

	// Add new entry
	elem := c.eviction.PushFront(entry)
	c.items[key] = elem

	// Evict oldest entries if over capacity
	for c.eviction.Len() > c.maxEntries {
		c.evictOldest()
	}

	GetCacheMetrics().sizeGauge.WithLabelValues(
		"memory",
	).Set(float64(c.eviction.Len()))

	c.logger.Debug("cache set",
		observability.String("key", key),
		observability.Duration("ttl", ttl),
		observability.Int("size", c.eviction.Len()))

	return nil
}

// Delete removes a value from the cache.
func (c *memoryCache) Delete(ctx context.Context, key string) error {
	_, span := otel.Tracer(cacheTracerName).Start(ctx, "cache.Delete",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("cache.backend", "memory"),
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		GetCacheMetrics().operationDuration.WithLabelValues(
			"memory", "delete",
		).Observe(time.Since(start).Seconds())
	}()

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, exists := c.items[key]; exists {
		c.removeElement(elem)
		c.logger.Debug("cache deleted",
			observability.String("key", key))
	}

	return nil
}

// Exists checks if a key exists in the cache.
func (c *memoryCache) Exists(ctx context.Context, key string) (bool, error) {
	_, span := otel.Tracer(cacheTracerName).Start(ctx, "cache.Exists",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("cache.backend", "memory"),
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	c.mu.Lock()
	defer c.mu.Unlock()

	elem, exists := c.items[key]
	if !exists {
		span.SetAttributes(attribute.Bool("cache.exists", false))
		return false, nil
	}

	entry := elem.Value.(*memoryCacheEntry)

	// Check if expired
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		c.removeElement(elem)
		span.SetAttributes(attribute.Bool("cache.exists", false))
		return false, nil
	}

	span.SetAttributes(attribute.Bool("cache.exists", true))
	return true, nil
}

// Close closes the cache and stops the cleanup goroutine.
func (c *memoryCache) Close() error {
	// Signal the cleanup goroutine to stop
	close(c.stopCh)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*list.Element)
	c.eviction.Init()

	c.logger.Info("memory cache closed")

	return nil
}

// Stats returns cache statistics.
func (c *memoryCache) Stats() CacheStats {
	c.mu.RLock()
	size := int64(c.eviction.Len())
	c.mu.RUnlock()

	return CacheStats{
		Hits:   atomic.LoadInt64(&c.hits),
		Misses: atomic.LoadInt64(&c.misses),
		Size:   size,
	}
}

// evictOldest removes the oldest entry from the cache.
// Must be called with lock held.
func (c *memoryCache) evictOldest() {
	elem := c.eviction.Back()
	if elem != nil {
		c.removeElement(elem)
		GetCacheMetrics().evictionsTotal.WithLabelValues(
			"memory",
		).Inc()
		c.logger.Debug("cache evicted oldest entry")
	}
}

// removeElement removes an element from the cache.
// Must be called with lock held.
func (c *memoryCache) removeElement(elem *list.Element) {
	c.eviction.Remove(elem)
	entry := elem.Value.(*memoryCacheEntry)
	delete(c.items, entry.key)
}

// cleanupLoop periodically removes expired entries.
func (c *memoryCache) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCh:
			return
		}
	}
}

// cleanup removes expired entries.
// Uses a single write lock for the entire operation to prevent race conditions
// where entries could be modified between identifying expired entries and removing them.
func (c *memoryCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var toRemove []*list.Element

	for elem := c.eviction.Back(); elem != nil; elem = elem.Prev() {
		entry := elem.Value.(*memoryCacheEntry)
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			toRemove = append(toRemove, elem)
		}
	}

	for _, elem := range toRemove {
		c.removeElement(elem)
	}

	if len(toRemove) > 0 {
		c.logger.Debug("cache cleanup completed",
			observability.Int("removed", len(toRemove)))
	}
}
