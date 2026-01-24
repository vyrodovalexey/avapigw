package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// DecisionCache caches authorization decisions.
type DecisionCache interface {
	// Get retrieves a cached decision.
	Get(ctx context.Context, key *CacheKey) (*CachedDecision, bool)

	// Set stores a decision in the cache.
	Set(ctx context.Context, key *CacheKey, decision *CachedDecision)

	// Delete removes a decision from the cache.
	Delete(ctx context.Context, key *CacheKey)

	// Clear clears all cached decisions.
	Clear(ctx context.Context)

	// Close closes the cache.
	Close() error
}

// CacheKey represents a cache key for authorization decisions.
type CacheKey struct {
	// Subject is the subject identifier.
	Subject string

	// Resource is the resource being accessed.
	Resource string

	// Action is the action being performed.
	Action string

	// Roles are the subject's roles.
	Roles []string

	// Groups are the subject's groups.
	Groups []string
}

// String returns a string representation of the cache key.
func (k *CacheKey) String() string {
	h := sha256.New()
	h.Write([]byte(k.Subject))
	h.Write([]byte(":"))
	h.Write([]byte(k.Resource))
	h.Write([]byte(":"))
	h.Write([]byte(k.Action))
	for _, role := range k.Roles {
		h.Write([]byte(":r:"))
		h.Write([]byte(role))
	}
	for _, group := range k.Groups {
		h.Write([]byte(":g:"))
		h.Write([]byte(group))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CachedDecision represents a cached authorization decision.
type CachedDecision struct {
	// Allowed indicates if the request was allowed.
	Allowed bool `json:"allowed"`

	// Reason is the reason for the decision.
	Reason string `json:"reason,omitempty"`

	// Policy is the policy that made the decision.
	Policy string `json:"policy,omitempty"`

	// CachedAt is when the decision was cached.
	CachedAt time.Time `json:"cached_at"`

	// ExpiresAt is when the cached decision expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired returns true if the cached decision has expired.
func (d *CachedDecision) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

// memoryDecisionCache implements DecisionCache using an in-memory cache.
type memoryDecisionCache struct {
	mu       sync.RWMutex
	entries  map[string]*CachedDecision
	ttl      time.Duration
	maxSize  int
	logger   observability.Logger
	metrics  *Metrics
	stopChan chan struct{}
}

// MemoryCacheOption is a functional option for the memory cache.
type MemoryCacheOption func(*memoryDecisionCache)

// WithMemoryCacheLogger sets the logger.
func WithMemoryCacheLogger(logger observability.Logger) MemoryCacheOption {
	return func(c *memoryDecisionCache) {
		c.logger = logger
	}
}

// WithMemoryCacheMetrics sets the metrics.
func WithMemoryCacheMetrics(metrics *Metrics) MemoryCacheOption {
	return func(c *memoryDecisionCache) {
		c.metrics = metrics
	}
}

// NewMemoryDecisionCache creates a new in-memory decision cache.
func NewMemoryDecisionCache(ttl time.Duration, maxSize int, opts ...MemoryCacheOption) DecisionCache {
	c := &memoryDecisionCache{
		entries:  make(map[string]*CachedDecision),
		ttl:      ttl,
		maxSize:  maxSize,
		logger:   observability.NopLogger(),
		stopChan: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(c)
	}

	// Start cleanup goroutine
	go c.cleanupLoop()

	return c
}

// Get retrieves a cached decision.
func (c *memoryDecisionCache) Get(ctx context.Context, key *CacheKey) (*CachedDecision, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keyStr := key.String()
	decision, ok := c.entries[keyStr]
	if !ok {
		if c.metrics != nil {
			c.metrics.RecordCacheMiss()
		}
		return nil, false
	}

	if decision.IsExpired() {
		if c.metrics != nil {
			c.metrics.RecordCacheMiss()
		}
		return nil, false
	}

	if c.metrics != nil {
		c.metrics.RecordCacheHit()
	}

	return decision, true
}

// Set stores a decision in the cache.
func (c *memoryDecisionCache) Set(ctx context.Context, key *CacheKey, decision *CachedDecision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict entries
	if c.maxSize > 0 && len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	keyStr := key.String()
	decision.CachedAt = time.Now()
	decision.ExpiresAt = time.Now().Add(c.ttl)
	c.entries[keyStr] = decision
}

// Delete removes a decision from the cache.
func (c *memoryDecisionCache) Delete(ctx context.Context, key *CacheKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, key.String())
}

// Clear clears all cached decisions.
func (c *memoryDecisionCache) Clear(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CachedDecision)
}

// Close closes the cache.
func (c *memoryDecisionCache) Close() error {
	close(c.stopChan)
	return nil
}

// evictOldest evicts the oldest entries to make room for new ones.
func (c *memoryDecisionCache) evictOldest() {
	// Find and remove expired entries first
	for key, decision := range c.entries {
		if decision.IsExpired() {
			delete(c.entries, key)
		}
	}

	// If still over capacity, remove oldest entries
	if len(c.entries) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time

		for key, decision := range c.entries {
			if oldestKey == "" || decision.CachedAt.Before(oldestTime) {
				oldestKey = key
				oldestTime = decision.CachedAt
			}
		}

		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
}

// cleanupLoop periodically removes expired entries.
func (c *memoryDecisionCache) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopChan:
			return
		}
	}
}

// cleanup removes expired entries.
func (c *memoryDecisionCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, decision := range c.entries {
		if decision.IsExpired() {
			delete(c.entries, key)
		}
	}
}

// externalDecisionCache implements DecisionCache using an external cache.
type externalDecisionCache struct {
	cache   cache.Cache
	ttl     time.Duration
	prefix  string
	logger  observability.Logger
	metrics *Metrics
}

// ExternalCacheOption is a functional option for the external cache.
type ExternalCacheOption func(*externalDecisionCache)

// WithExternalCacheLogger sets the logger.
func WithExternalCacheLogger(logger observability.Logger) ExternalCacheOption {
	return func(c *externalDecisionCache) {
		c.logger = logger
	}
}

// WithExternalCacheMetrics sets the metrics.
func WithExternalCacheMetrics(metrics *Metrics) ExternalCacheOption {
	return func(c *externalDecisionCache) {
		c.metrics = metrics
	}
}

// WithExternalCachePrefix sets the key prefix.
func WithExternalCachePrefix(prefix string) ExternalCacheOption {
	return func(c *externalDecisionCache) {
		c.prefix = prefix
	}
}

// NewExternalDecisionCache creates a new external decision cache.
func NewExternalDecisionCache(c cache.Cache, ttl time.Duration, opts ...ExternalCacheOption) DecisionCache {
	ec := &externalDecisionCache{
		cache:  c,
		ttl:    ttl,
		prefix: "authz:",
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(ec)
	}

	return ec
}

// Get retrieves a cached decision.
func (c *externalDecisionCache) Get(ctx context.Context, key *CacheKey) (*CachedDecision, bool) {
	cacheKey := c.prefix + key.String()

	data, err := c.cache.Get(ctx, cacheKey)
	if err != nil {
		if !errors.Is(err, cache.ErrCacheMiss) {
			c.logger.Warn("failed to get from cache",
				observability.String("key", cacheKey),
				observability.Error(err),
			)
		}
		if c.metrics != nil {
			c.metrics.RecordCacheMiss()
		}
		return nil, false
	}

	var decision CachedDecision
	if err := json.Unmarshal(data, &decision); err != nil {
		c.logger.Warn("failed to unmarshal cached decision",
			observability.String("key", cacheKey),
			observability.Error(err),
		)
		if c.metrics != nil {
			c.metrics.RecordCacheMiss()
		}
		return nil, false
	}

	if decision.IsExpired() {
		if c.metrics != nil {
			c.metrics.RecordCacheMiss()
		}
		return nil, false
	}

	if c.metrics != nil {
		c.metrics.RecordCacheHit()
	}

	return &decision, true
}

// Set stores a decision in the cache.
func (c *externalDecisionCache) Set(ctx context.Context, key *CacheKey, decision *CachedDecision) {
	cacheKey := c.prefix + key.String()

	decision.CachedAt = time.Now()
	decision.ExpiresAt = time.Now().Add(c.ttl)

	data, err := json.Marshal(decision)
	if err != nil {
		c.logger.Warn("failed to marshal decision",
			observability.String("key", cacheKey),
			observability.Error(err),
		)
		return
	}

	if err := c.cache.Set(ctx, cacheKey, data, c.ttl); err != nil {
		c.logger.Warn("failed to set cache",
			observability.String("key", cacheKey),
			observability.Error(err),
		)
	}
}

// Delete removes a decision from the cache.
func (c *externalDecisionCache) Delete(ctx context.Context, key *CacheKey) {
	cacheKey := c.prefix + key.String()

	if err := c.cache.Delete(ctx, cacheKey); err != nil {
		c.logger.Warn("failed to delete from cache",
			observability.String("key", cacheKey),
			observability.Error(err),
		)
	}
}

// Clear clears all cached decisions.
// Note: This is a no-op for external caches as we can't efficiently clear by prefix.
func (c *externalDecisionCache) Clear(ctx context.Context) {
	c.logger.Warn("clear operation not supported for external cache")
}

// Close closes the cache.
func (c *externalDecisionCache) Close() error {
	return c.cache.Close()
}

// noopDecisionCache is a no-op cache that doesn't cache anything.
type noopDecisionCache struct{}

// NewNoopDecisionCache creates a new no-op decision cache.
func NewNoopDecisionCache() DecisionCache {
	return &noopDecisionCache{}
}

// Get always returns false.
func (c *noopDecisionCache) Get(ctx context.Context, key *CacheKey) (*CachedDecision, bool) {
	return nil, false
}

// Set does nothing.
func (c *noopDecisionCache) Set(ctx context.Context, key *CacheKey, decision *CachedDecision) {}

// Delete does nothing.
func (c *noopDecisionCache) Delete(ctx context.Context, key *CacheKey) {}

// Clear does nothing.
func (c *noopDecisionCache) Clear(ctx context.Context) {}

// Close does nothing.
func (c *noopDecisionCache) Close() error {
	return nil
}

// Ensure implementations satisfy the interface.
var (
	_ DecisionCache = (*memoryDecisionCache)(nil)
	_ DecisionCache = (*externalDecisionCache)(nil)
	_ DecisionCache = (*noopDecisionCache)(nil)
)
