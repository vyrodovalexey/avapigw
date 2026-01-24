package apikey

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Store is the interface for API key storage.
type Store interface {
	// Get retrieves an API key by its value.
	Get(ctx context.Context, key string) (*StaticKey, error)

	// GetByID retrieves an API key by its ID.
	GetByID(ctx context.Context, id string) (*StaticKey, error)

	// List lists all API keys.
	List(ctx context.Context) ([]*StaticKey, error)

	// Close closes the store.
	Close() error
}

// NewStore creates a new API key store based on configuration.
func NewStore(config *Config, logger observability.Logger) (Store, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	storeType := "memory"
	if config.Store != nil && config.Store.Type != "" {
		storeType = config.Store.Type
	}

	switch storeType {
	case "memory":
		return NewMemoryStore(config, logger)
	case "vault":
		return nil, fmt.Errorf("vault store requires vault client - use NewVaultStore")
	case "file":
		return nil, fmt.Errorf("file store not yet implemented")
	default:
		return nil, fmt.Errorf("unknown store type: %s", storeType)
	}
}

// MemoryStore implements Store using in-memory storage.
type MemoryStore struct {
	logger observability.Logger
	mu     sync.RWMutex
	keys   map[string]*StaticKey // key value -> key info
	byID   map[string]*StaticKey // key ID -> key info
}

// NewMemoryStore creates a new in-memory API key store.
func NewMemoryStore(config *Config, logger observability.Logger) (*MemoryStore, error) {
	store := &MemoryStore{
		logger: logger,
		keys:   make(map[string]*StaticKey),
		byID:   make(map[string]*StaticKey),
	}

	// Load static keys from configuration
	if config.Store != nil {
		for _, key := range config.Store.Keys {
			keyCopy := key
			store.keys[key.Key] = &keyCopy
			store.byID[key.ID] = &keyCopy
		}
	}

	logger.Info("memory API key store initialized",
		observability.Int("key_count", len(store.keys)),
	)

	return store, nil
}

// Get retrieves an API key by its value.
func (s *MemoryStore) Get(_ context.Context, key string) (*StaticKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	storedKey, ok := s.keys[key]
	if !ok {
		return nil, ErrAPIKeyNotFound
	}

	return storedKey, nil
}

// GetByID retrieves an API key by its ID.
func (s *MemoryStore) GetByID(_ context.Context, id string) (*StaticKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	storedKey, ok := s.byID[id]
	if !ok {
		return nil, ErrAPIKeyNotFound
	}

	return storedKey, nil
}

// List lists all API keys.
func (s *MemoryStore) List(_ context.Context) ([]*StaticKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]*StaticKey, 0, len(s.byID))
	for _, key := range s.byID {
		keys = append(keys, key)
	}

	return keys, nil
}

// Close closes the store.
func (s *MemoryStore) Close() error {
	return nil
}

// Add adds an API key to the store.
func (s *MemoryStore) Add(key *StaticKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.keys[key.Key] = key
	s.byID[key.ID] = key
}

// Remove removes an API key from the store.
func (s *MemoryStore) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if key, ok := s.byID[id]; ok {
		delete(s.keys, key.Key)
		delete(s.byID, id)
	}
}

// VaultStore implements Store using Vault KV.
type VaultStore struct {
	client vault.Client
	config *Config
	logger observability.Logger
	cache  *keyCache
}

// keyCache provides caching for Vault-stored keys.
type keyCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	key       *StaticKey
	expiresAt time.Time
}

// NewVaultStore creates a new Vault-based API key store.
func NewVaultStore(client vault.Client, config *Config, logger observability.Logger) (*VaultStore, error) {
	if client == nil || !client.IsEnabled() {
		return nil, fmt.Errorf("vault client is required and must be enabled")
	}

	if config.Vault == nil || !config.Vault.Enabled {
		return nil, fmt.Errorf("vault configuration is required")
	}

	store := &VaultStore{
		client: client,
		config: config,
		logger: logger,
	}

	// Initialize cache if enabled
	if config.Cache != nil && config.Cache.Enabled {
		store.cache = &keyCache{
			entries: make(map[string]*cacheEntry),
			ttl:     config.Cache.TTL,
		}
	}

	logger.Info("vault API key store initialized",
		observability.String("kv_mount", config.Vault.KVMount),
		observability.String("path", config.Vault.Path),
	)

	return store, nil
}

// Get retrieves an API key by its value.
func (s *VaultStore) Get(ctx context.Context, key string) (*StaticKey, error) {
	// Check cache first
	if s.cache != nil {
		if cached := s.cache.get(key); cached != nil {
			return cached, nil
		}
	}

	// Look up in Vault
	// We need to hash the key to look it up
	keyHash, err := HashKey(key, s.config.GetEffectiveHashAlgorithm())
	if err != nil {
		return nil, fmt.Errorf("failed to hash key: %w", err)
	}

	path := s.config.Vault.Path
	if path != "" {
		path += "/"
	}
	path += keyHash

	data, err := s.client.KV().Read(ctx, s.config.Vault.KVMount, path)
	if err != nil {
		return nil, ErrAPIKeyNotFound
	}

	storedKey, err := parseKeyFromVault(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key from Vault: %w", err)
	}

	// Cache the result
	if s.cache != nil {
		s.cache.set(key, storedKey)
	}

	return storedKey, nil
}

// GetByID retrieves an API key by its ID.
func (s *VaultStore) GetByID(ctx context.Context, id string) (*StaticKey, error) {
	path := s.config.Vault.Path
	if path != "" {
		path += "/"
	}
	path += "by-id/" + id

	data, err := s.client.KV().Read(ctx, s.config.Vault.KVMount, path)
	if err != nil {
		return nil, ErrAPIKeyNotFound
	}

	return parseKeyFromVault(data)
}

// List lists all API keys.
func (s *VaultStore) List(ctx context.Context) ([]*StaticKey, error) {
	path := s.config.Vault.Path
	if path != "" {
		path += "/"
	}
	path += "by-id"

	ids, err := s.client.KV().List(ctx, s.config.Vault.KVMount, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	keys := make([]*StaticKey, 0, len(ids))
	for _, id := range ids {
		key, err := s.GetByID(ctx, id)
		if err != nil {
			s.logger.Warn("failed to get key by ID",
				observability.String("id", id),
				observability.Error(err),
			)
			continue
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// Close closes the store.
func (s *VaultStore) Close() error {
	return nil
}

// parseKeyFromVault parses a StaticKey from Vault data.
func parseKeyFromVault(data map[string]interface{}) (*StaticKey, error) {
	key := &StaticKey{
		Enabled: true,
	}

	if id, ok := data["id"].(string); ok {
		key.ID = id
	}
	if name, ok := data["name"].(string); ok {
		key.Name = name
	}
	if hash, ok := data["hash"].(string); ok {
		key.Hash = hash
	}
	if keyVal, ok := data["key"].(string); ok {
		key.Key = keyVal
	}
	if scopes, ok := data["scopes"].([]interface{}); ok {
		key.Scopes = make([]string, 0, len(scopes))
		for _, s := range scopes {
			if str, ok := s.(string); ok {
				key.Scopes = append(key.Scopes, str)
			}
		}
	}
	if roles, ok := data["roles"].([]interface{}); ok {
		key.Roles = make([]string, 0, len(roles))
		for _, r := range roles {
			if str, ok := r.(string); ok {
				key.Roles = append(key.Roles, str)
			}
		}
	}
	if enabled, ok := data["enabled"].(bool); ok {
		key.Enabled = enabled
	}

	return key, nil
}

// get retrieves a key from the cache.
func (c *keyCache) get(key string) *StaticKey {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.key
}

// set stores a key in the cache.
func (c *keyCache) set(key string, storedKey *StaticKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		key:       storedKey,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Ensure implementations satisfy the interface.
var (
	_ Store = (*MemoryStore)(nil)
	_ Store = (*VaultStore)(nil)
)
