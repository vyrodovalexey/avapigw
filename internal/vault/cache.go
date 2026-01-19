package vault

import (
	"container/list"
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CacheConfig holds configuration for the SecretCache.
type CacheConfig struct {
	// MaxSize is the maximum number of entries in the cache.
	// If 0, the cache is unbounded (not recommended for production).
	MaxSize int

	// DefaultTTL is the default time-to-live for cache entries.
	DefaultTTL time.Duration

	// CleanupInterval is how often to run the cleanup routine.
	CleanupInterval time.Duration
}

// DefaultCacheConfig returns a CacheConfig with sensible defaults.
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		MaxSize:         1000,
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	}
}

// CacheEntry represents a cached secret entry.
type CacheEntry struct {
	// Secret is the cached secret.
	Secret *Secret

	// ExpiresAt is when the cache entry expires.
	ExpiresAt time.Time

	// key is the cache key for this entry (used for LRU eviction).
	key string

	// element is the list element for LRU tracking.
	element *list.Element
}

// IsExpired returns true if the cache entry has expired.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// SecretCache provides caching for Vault secrets with LRU eviction and TTL support.
// It is thread-safe and supports bounded size with automatic cleanup.
type SecretCache struct {
	mu       sync.RWMutex
	entries  map[string]*CacheEntry
	lruList  *list.List // Front = most recently used, Back = least recently used
	config   *CacheConfig
	stopCh   chan struct{}
	stopOnce sync.Once
	logger   *zap.Logger
}

// NewSecretCache creates a new SecretCache with the specified default TTL.
// This is a convenience constructor that uses default configuration.
func NewSecretCache(ttl time.Duration) *SecretCache {
	config := DefaultCacheConfig()
	config.DefaultTTL = ttl
	return NewSecretCacheWithConfig(config, nil)
}

// NewSecretCacheWithConfig creates a new SecretCache with the specified configuration.
func NewSecretCacheWithConfig(config *CacheConfig, logger *zap.Logger) *SecretCache {
	if config == nil {
		config = DefaultCacheConfig()
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	cache := &SecretCache{
		entries: make(map[string]*CacheEntry),
		lruList: list.New(),
		config:  config,
		stopCh:  make(chan struct{}),
		logger:  logger,
	}

	// Update initial size metric
	UpdateCacheSize(0)

	return cache
}

// Get retrieves a secret from the cache.
// Returns the secret and true if found and not expired, nil and false otherwise.
func (c *SecretCache) Get(path string) (*Secret, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[path]
	if !ok {
		RecordCacheMiss()
		return nil, false
	}

	// Check if expired
	if entry.IsExpired() {
		c.removeEntryLocked(path)
		RecordCacheMiss()
		return nil, false
	}

	// Move to front of LRU list (most recently used)
	c.lruList.MoveToFront(entry.element)

	RecordCacheHit()
	return entry.Secret, true
}

// Set stores a secret in the cache with the default TTL.
func (c *SecretCache) Set(path string, secret *Secret) {
	c.SetWithTTL(path, secret, c.config.DefaultTTL)
}

// SetWithTTL stores a secret in the cache with a specific TTL.
func (c *SecretCache) SetWithTTL(path string, secret *Secret, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if entry already exists
	if existing, ok := c.entries[path]; ok {
		// Update existing entry
		existing.Secret = secret
		existing.ExpiresAt = time.Now().Add(ttl)
		c.lruList.MoveToFront(existing.element)
		return
	}

	// Evict entries if cache is full
	c.evictIfNeededLocked()

	// Create new entry
	entry := &CacheEntry{
		Secret:    secret,
		ExpiresAt: time.Now().Add(ttl),
		key:       path,
	}

	// Add to LRU list (front = most recently used)
	entry.element = c.lruList.PushFront(entry)
	c.entries[path] = entry

	// Update size metric
	UpdateCacheSize(len(c.entries))
}

// Delete removes a secret from the cache.
func (c *SecretCache) Delete(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.removeEntryLocked(path)
}

// Clear removes all secrets from the cache.
func (c *SecretCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CacheEntry)
	c.lruList.Init()

	// Update size metric
	UpdateCacheSize(0)
}

// Size returns the number of entries in the cache.
func (c *SecretCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

// MaxSize returns the maximum size of the cache.
func (c *SecretCache) MaxSize() int {
	return c.config.MaxSize
}

// Cleanup removes expired entries from the cache.
// Returns the number of entries removed.
func (c *SecretCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	now := time.Now()

	// Iterate through all entries and remove expired ones
	for path, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			c.removeEntryLocked(path)
			removed++
		}
	}

	if removed > 0 {
		c.logger.Debug("Cleaned up expired cache entries",
			zap.Int("removed", removed),
			zap.Int("remaining", len(c.entries)),
		)
	}

	return removed
}

// StartCleanupRoutine starts a background routine to clean up expired entries.
// The routine runs until the stopCh is closed or Stop() is called.
func (c *SecretCache) StartCleanupRoutine(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.Cleanup()
			case <-stopCh:
				return
			case <-c.stopCh:
				return
			}
		}
	}()
}

// Start starts the cache's internal cleanup routine using the configured interval.
func (c *SecretCache) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(c.config.CleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.Cleanup()
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			}
		}
	}()

	c.logger.Info("Secret cache started",
		zap.Int("maxSize", c.config.MaxSize),
		zap.Duration("defaultTTL", c.config.DefaultTTL),
		zap.Duration("cleanupInterval", c.config.CleanupInterval),
	)
}

// Stop stops the cache's internal cleanup routine.
func (c *SecretCache) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		c.logger.Info("Secret cache stopped")
	})
}

// evictIfNeededLocked evicts entries if the cache is at capacity.
// Must be called with the lock held.
func (c *SecretCache) evictIfNeededLocked() {
	// If MaxSize is 0, cache is unbounded
	if c.config.MaxSize <= 0 {
		return
	}

	// Evict entries until we have room
	for len(c.entries) >= c.config.MaxSize {
		// First, try to evict expired entries
		evicted := false
		now := time.Now()
		for path, entry := range c.entries {
			if now.After(entry.ExpiresAt) {
				c.removeEntryLocked(path)
				evicted = true
				break
			}
		}

		if evicted {
			continue
		}

		// No expired entries, evict the least recently used entry
		if c.lruList.Len() > 0 {
			oldest := c.lruList.Back()
			if oldest != nil {
				entry := oldest.Value.(*CacheEntry)
				c.removeEntryLocked(entry.key)
				RecordCacheEviction()
				c.logger.Debug("Evicted LRU cache entry",
					zap.String("key", entry.key),
					zap.Int("cacheSize", len(c.entries)),
				)
			}
		}
	}
}

// removeEntryLocked removes an entry from the cache.
// Must be called with the lock held.
func (c *SecretCache) removeEntryLocked(path string) {
	entry, ok := c.entries[path]
	if !ok {
		return
	}

	// Remove from LRU list
	if entry.element != nil {
		c.lruList.Remove(entry.element)
	}

	// Remove from map
	delete(c.entries, path)

	// Update size metric
	UpdateCacheSize(len(c.entries))
}

// GetStats returns cache statistics.
func (c *SecretCache) GetStats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var expiredCount int
	now := time.Now()
	for _, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			expiredCount++
		}
	}

	return CacheStats{
		Size:         len(c.entries),
		MaxSize:      c.config.MaxSize,
		ExpiredCount: expiredCount,
	}
}

// CacheStats holds cache statistics.
type CacheStats struct {
	// Size is the current number of entries in the cache.
	Size int

	// MaxSize is the maximum number of entries allowed.
	MaxSize int

	// ExpiredCount is the number of expired entries (not yet cleaned up).
	ExpiredCount int
}

// VaultClientCache provides caching for Vault clients with LRU eviction and TTL support.
// This is used by the controller to cache Vault clients per address/namespace combination.
type VaultClientCache struct {
	mu       sync.RWMutex
	entries  map[string]*VaultClientEntry
	lruList  *list.List
	maxSize  int
	ttl      time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
	logger   *zap.Logger
}

// VaultClientEntry represents a cached Vault client entry.
type VaultClientEntry struct {
	// Client is the cached Vault client.
	Client *Client

	// Address is the Vault address for this client.
	Address string

	// CreatedAt is when the client was created.
	CreatedAt time.Time

	// LastUsedAt is when the client was last used.
	LastUsedAt time.Time

	// key is the cache key for this entry.
	key string

	// element is the list element for LRU tracking.
	element *list.Element
}

// IsExpired returns true if the client entry has exceeded its TTL.
func (e *VaultClientEntry) IsExpired(ttl time.Duration) bool {
	return time.Since(e.LastUsedAt) > ttl
}

// VaultClientCacheConfig holds configuration for the VaultClientCache.
type VaultClientCacheConfig struct {
	// MaxSize is the maximum number of clients in the cache.
	MaxSize int

	// TTL is the time-to-live for unused clients.
	TTL time.Duration

	// CleanupInterval is how often to run the cleanup routine.
	CleanupInterval time.Duration
}

// DefaultVaultClientCacheConfig returns a VaultClientCacheConfig with sensible defaults.
func DefaultVaultClientCacheConfig() *VaultClientCacheConfig {
	return &VaultClientCacheConfig{
		MaxSize:         100,
		TTL:             30 * time.Minute,
		CleanupInterval: 5 * time.Minute,
	}
}

// NewVaultClientCache creates a new VaultClientCache with the specified configuration.
func NewVaultClientCache(config *VaultClientCacheConfig, logger *zap.Logger) *VaultClientCache {
	if config == nil {
		config = DefaultVaultClientCacheConfig()
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	cache := &VaultClientCache{
		entries: make(map[string]*VaultClientEntry),
		lruList: list.New(),
		maxSize: config.MaxSize,
		ttl:     config.TTL,
		stopCh:  make(chan struct{}),
		logger:  logger,
	}

	// Update initial size metric
	UpdateVaultClientCacheSize(0)

	return cache
}

// Get retrieves a Vault client from the cache.
// Returns the client and true if found, nil and false otherwise.
func (c *VaultClientCache) Get(key string) (*Client, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		RecordVaultClientCacheMiss()
		return nil, false
	}

	// Check if expired
	if entry.IsExpired(c.ttl) {
		c.removeEntryLocked(key)
		RecordVaultClientCacheMiss()
		return nil, false
	}

	// Update last used time and move to front of LRU list
	entry.LastUsedAt = time.Now()
	c.lruList.MoveToFront(entry.element)

	RecordVaultClientCacheHit()
	return entry.Client, true
}

// GetOrCreate retrieves a Vault client from the cache or creates a new one.
// The createFunc is called if the client is not in the cache.
// Returns the client and any error from createFunc.
func (c *VaultClientCache) GetOrCreate(
	key string,
	address string,
	createFunc func() (*Client, error),
) (*Client, error) {
	// Try to get existing client first
	if client, ok := c.Get(key); ok {
		return client, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if entry, ok := c.entries[key]; ok && !entry.IsExpired(c.ttl) {
		entry.LastUsedAt = time.Now()
		c.lruList.MoveToFront(entry.element)
		RecordVaultClientCacheHit()
		return entry.Client, nil
	}

	// Create new client
	client, err := createFunc()
	if err != nil {
		return nil, err
	}

	// Evict if needed
	c.evictIfNeededLocked()

	// Store the new client
	now := time.Now()
	entry := &VaultClientEntry{
		Client:     client,
		Address:    address,
		CreatedAt:  now,
		LastUsedAt: now,
		key:        key,
	}
	entry.element = c.lruList.PushFront(entry)
	c.entries[key] = entry

	// Update size metric
	UpdateVaultClientCacheSize(len(c.entries))

	c.logger.Debug("Created and cached new Vault client",
		zap.String("key", key),
		zap.String("address", address),
		zap.Int("cacheSize", len(c.entries)),
	)

	return client, nil
}

// Set stores a Vault client in the cache.
func (c *VaultClientCache) Set(key string, client *Client, address string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if entry already exists
	if existing, ok := c.entries[key]; ok {
		// Close old client if address changed
		if existing.Address != address {
			if existing.Client != nil {
				_ = existing.Client.Close() // Ignore error on cleanup
			}
			RecordVaultClientCacheEviction()
		}
		// Update existing entry
		existing.Client = client
		existing.Address = address
		existing.LastUsedAt = time.Now()
		c.lruList.MoveToFront(existing.element)
		return
	}

	// Evict if needed
	c.evictIfNeededLocked()

	// Create new entry
	now := time.Now()
	entry := &VaultClientEntry{
		Client:     client,
		Address:    address,
		CreatedAt:  now,
		LastUsedAt: now,
		key:        key,
	}
	entry.element = c.lruList.PushFront(entry)
	c.entries[key] = entry

	// Update size metric
	UpdateVaultClientCacheSize(len(c.entries))
}

// Delete removes a Vault client from the cache and closes it.
func (c *VaultClientCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.removeEntryLocked(key)
}

// DeleteByAddress removes all Vault clients with the specified address.
// This is useful when a Vault address changes and old clients need to be cleaned up.
func (c *VaultClientCache) DeleteByAddress(address string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	for key, entry := range c.entries {
		if entry.Address == address {
			c.removeEntryLocked(key)
			removed++
		}
	}

	if removed > 0 {
		c.logger.Debug("Removed Vault clients by address",
			zap.String("address", address),
			zap.Int("removed", removed),
		)
	}

	return removed
}

// Clear removes all Vault clients from the cache and closes them.
func (c *VaultClientCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close all clients
	for _, entry := range c.entries {
		if entry.Client != nil {
			_ = entry.Client.Close() // Ignore error on cleanup
		}
	}

	c.entries = make(map[string]*VaultClientEntry)
	c.lruList.Init()

	// Update size metric
	UpdateVaultClientCacheSize(0)
}

// Size returns the number of clients in the cache.
func (c *VaultClientCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

// Cleanup removes expired clients from the cache.
// Returns the number of clients removed.
func (c *VaultClientCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0

	for key, entry := range c.entries {
		if entry.IsExpired(c.ttl) {
			c.removeEntryLocked(key)
			removed++
		}
	}

	if removed > 0 {
		c.logger.Debug("Cleaned up expired Vault clients",
			zap.Int("removed", removed),
			zap.Int("remaining", len(c.entries)),
		)
	}

	return removed
}

// Start starts the cache's internal cleanup routine.
func (c *VaultClientCache) Start(ctx context.Context, cleanupInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.Cleanup()
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			}
		}
	}()

	c.logger.Info("Vault client cache started",
		zap.Int("maxSize", c.maxSize),
		zap.Duration("ttl", c.ttl),
		zap.Duration("cleanupInterval", cleanupInterval),
	)
}

// Stop stops the cache's internal cleanup routine and closes all clients.
func (c *VaultClientCache) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		c.Clear()
		c.logger.Info("Vault client cache stopped")
	})
}

// evictIfNeededLocked evicts entries if the cache is at capacity.
// Must be called with the lock held.
func (c *VaultClientCache) evictIfNeededLocked() {
	if c.maxSize <= 0 {
		return
	}

	for len(c.entries) >= c.maxSize {
		// First, try to evict expired entries
		evicted := false
		for key, entry := range c.entries {
			if entry.IsExpired(c.ttl) {
				c.removeEntryLocked(key)
				evicted = true
				break
			}
		}

		if evicted {
			continue
		}

		// No expired entries, evict the least recently used entry
		if c.lruList.Len() > 0 {
			oldest := c.lruList.Back()
			if oldest != nil {
				entry := oldest.Value.(*VaultClientEntry)
				c.removeEntryLocked(entry.key)
				RecordVaultClientCacheEviction()
				c.logger.Debug("Evicted LRU Vault client",
					zap.String("key", entry.key),
					zap.String("address", entry.Address),
					zap.Int("cacheSize", len(c.entries)),
				)
			}
		}
	}
}

// removeEntryLocked removes an entry from the cache and closes the client.
// Must be called with the lock held.
func (c *VaultClientCache) removeEntryLocked(key string) {
	entry, ok := c.entries[key]
	if !ok {
		return
	}

	// Close the client
	if entry.Client != nil {
		_ = entry.Client.Close() // Ignore error on cleanup
	}

	// Remove from LRU list
	if entry.element != nil {
		c.lruList.Remove(entry.element)
	}

	// Remove from map
	delete(c.entries, key)

	// Update size metric
	UpdateVaultClientCacheSize(len(c.entries))
}

// GetStats returns cache statistics.
func (c *VaultClientCache) GetStats() VaultClientCacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var expiredCount int
	for _, entry := range c.entries {
		if entry.IsExpired(c.ttl) {
			expiredCount++
		}
	}

	return VaultClientCacheStats{
		Size:         len(c.entries),
		MaxSize:      c.maxSize,
		ExpiredCount: expiredCount,
	}
}

// VaultClientCacheStats holds cache statistics.
type VaultClientCacheStats struct {
	// Size is the current number of clients in the cache.
	Size int

	// MaxSize is the maximum number of clients allowed.
	MaxSize int

	// ExpiredCount is the number of expired clients (not yet cleaned up).
	ExpiredCount int
}
