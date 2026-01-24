package vault

import (
	"container/list"
	"sync"
	"time"
)

// secretCache provides thread-safe in-memory caching for secrets.
type secretCache struct {
	mu        sync.RWMutex
	items     map[string]*cacheItem
	lru       *list.List
	maxSize   int
	ttl       time.Duration
	stopCh    chan struct{}
	stoppedCh chan struct{}
}

// cacheItem represents a cached item.
type cacheItem struct {
	key       string
	value     interface{}
	expiresAt time.Time
	element   *list.Element
}

// newSecretCache creates a new secret cache.
func newSecretCache(maxSize int, ttl time.Duration) *secretCache {
	if maxSize <= 0 {
		maxSize = 1000
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	c := &secretCache{
		items:     make(map[string]*cacheItem),
		lru:       list.New(),
		maxSize:   maxSize,
		ttl:       ttl,
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
	}

	// Start background cleanup goroutine
	go c.cleanupLoop()

	return c
}

// get retrieves a value from the cache.
func (c *secretCache) get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	item, ok := c.items[key]
	if !ok {
		return nil, false
	}

	// Check if expired
	if time.Now().After(item.expiresAt) {
		// Remove expired item while holding the lock
		c.lru.Remove(item.element)
		delete(c.items, key)
		return nil, false
	}

	// Move to front of LRU list
	c.lru.MoveToFront(item.element)

	return item.value, true
}

// set stores a value in the cache.
func (c *secretCache) set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key already exists
	if item, ok := c.items[key]; ok {
		item.value = value
		item.expiresAt = time.Now().Add(c.ttl)
		c.lru.MoveToFront(item.element)
		return
	}

	// Evict if at capacity
	for c.lru.Len() >= c.maxSize {
		c.evictOldest()
	}

	// Add new item
	item := &cacheItem{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
	item.element = c.lru.PushFront(item)
	c.items[key] = item
}

// delete removes a value from the cache.
func (c *secretCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if item, ok := c.items[key]; ok {
		c.lru.Remove(item.element)
		delete(c.items, key)
	}
}

// evictOldest removes the oldest item from the cache.
// Must be called with lock held.
func (c *secretCache) evictOldest() {
	elem := c.lru.Back()
	if elem == nil {
		return
	}

	item := elem.Value.(*cacheItem)
	c.lru.Remove(elem)
	delete(c.items, item.key)
}

// cleanupLoop periodically removes expired items.
func (c *secretCache) cleanupLoop() {
	defer close(c.stoppedCh)

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.removeExpired()
		}
	}
}

// removeExpired removes all expired items from the cache.
func (c *secretCache) removeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, item := range c.items {
		if now.After(item.expiresAt) {
			c.lru.Remove(item.element)
			delete(c.items, key)
		}
	}
}

// stop stops the cache cleanup goroutine and waits for it to finish.
func (c *secretCache) stop() {
	close(c.stopCh)
	<-c.stoppedCh
}
