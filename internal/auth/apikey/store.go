package apikey

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// ErrStoreUnavailable indicates that the backing API key store could not be
// reached (for example a Vault transport, permission, or availability
// failure). It is intentionally distinct from ErrAPIKeyNotFound so that
// callers can differentiate an infrastructure outage from a genuine miss
// and surface the correct metric label ("store_error" vs "not_found").
var ErrStoreUnavailable = errors.New("API key store unavailable")

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

	storeType := storeTypeMemory
	if config.Store != nil && config.Store.Type != "" {
		storeType = config.Store.Type
	}

	switch storeType {
	case storeTypeMemory:
		return NewMemoryStore(config, logger)
	case storeTypeVault:
		return nil, fmt.Errorf("vault store requires vault client - use NewVaultStore")
	case storeTypeFile:
		return nil, fmt.Errorf("file store not yet implemented")
	default:
		return nil, fmt.Errorf("unknown store type: %s", storeType)
	}
}

// MemoryStore implements Store using in-memory storage.
//
// Keys are indexed by a deterministic digest of the raw key value — never
// by the raw key itself — which supports hash-only static keys (Key empty,
// Hash set) and avoids retaining plaintext key material as map keys.
// bcrypt entries are not digest-addressable (the embedded random salt makes
// hashes non-deterministic), so they are indexed by key ID and verified
// individually on lookup.
type MemoryStore struct {
	logger    observability.Logger
	algorithm string
	mu        sync.RWMutex
	byDigest  map[string]*StaticKey // deterministic digest -> key info
	byID      map[string]*StaticKey // key ID -> key info
	byBcrypt  map[string]*StaticKey // key ID -> bcrypt-hashed key info
}

// NewMemoryStore creates a new in-memory API key store.
func NewMemoryStore(config *Config, logger observability.Logger) (*MemoryStore, error) {
	store := &MemoryStore{
		logger:    logger,
		algorithm: config.GetEffectiveHashAlgorithm(),
		byDigest:  make(map[string]*StaticKey),
		byID:      make(map[string]*StaticKey),
		byBcrypt:  make(map[string]*StaticKey),
	}

	// Load static keys from configuration
	if config.Store != nil {
		for i := range config.Store.Keys {
			keyCopy := config.Store.Keys[i]
			store.Add(&keyCopy)
		}
	}

	logger.Info("memory API key store initialized",
		observability.Int("key_count", len(store.byID)),
		observability.String("hash_algorithm", store.algorithm),
	)

	return store, nil
}

// Get retrieves an API key by its (presented) value.
func (s *MemoryStore) Get(_ context.Context, key string) (*StaticKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.algorithm == HashAlgBcrypt {
		return s.findBcryptLocked(key)
	}

	// The presented key is hashed before lookup: raw keys are never used
	// as map keys and hash-only entries resolve by their configured hash.
	storedKey, ok := s.byDigest[lookupDigest(key, s.algorithm)]
	if !ok {
		return nil, ErrAPIKeyNotFound
	}

	return storedKey, nil
}

// findBcryptLocked scans bcrypt entries and verifies the presented key
// against each stored bcrypt hash. Callers must hold at least a read lock.
func (s *MemoryStore) findBcryptLocked(presented string) (*StaticKey, error) {
	for _, storedKey := range s.byBcrypt {
		if bcryptMatches(presented, storedKey) {
			return storedKey, nil
		}
	}
	return nil, ErrAPIKeyNotFound
}

// bcryptMatches verifies a presented key against the bcrypt hash of the
// stored entry. Hash takes precedence over Key, matching validator logic.
func bcryptMatches(presented string, storedKey *StaticKey) bool {
	storedHash := storedKey.Hash
	if storedHash == "" {
		storedHash = storedKey.Key
	}
	return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(presented)) == nil
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

	s.byID[key.ID] = key

	if s.algorithm == HashAlgBcrypt {
		s.byBcrypt[key.ID] = key
		return
	}

	digests := s.indexDigests(key)
	if len(digests) == 0 {
		s.logger.Warn("static API key entry is not addressable by key lookup",
			observability.String("key_id", key.ID),
			observability.String("hash_algorithm", s.algorithm),
		)
	}
	for _, digest := range digests {
		s.byDigest[digest] = key
	}
}

// indexDigests returns the deterministic digests under which a static key
// entry is addressable. An entry with a raw key is indexed by the digest of
// that raw value; an entry with an algorithm-compatible pre-computed hash
// (hash-only support) is additionally indexed by the normalized hash.
func (s *MemoryStore) indexDigests(key *StaticKey) []string {
	digests := make([]string, 0, 2)
	if key.Key != "" {
		digests = append(digests, lookupDigest(key.Key, s.algorithm))
	}
	if key.Hash != "" && isAlgorithmCompatibleHash(key.Hash, s.algorithm) {
		digests = append(digests, normalizeHexDigest(key.Hash))
	}
	return digests
}

// Remove removes an API key from the store.
func (s *MemoryStore) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, ok := s.byID[id]
	if !ok {
		return
	}

	for _, digest := range s.indexDigests(key) {
		delete(s.byDigest, digest)
	}
	delete(s.byBcrypt, id)
	delete(s.byID, id)
}

// lookupDigest computes the deterministic digest used to index and look up
// raw API keys. sha512 keeps the configured algorithm so digests match
// pre-computed hashes; every other algorithm (including plaintext) uses
// sha256 so raw keys are never used as map keys directly.
func lookupDigest(raw, algorithm string) string {
	if algorithm == HashAlgSHA512 {
		return sha512Hex(raw)
	}
	return sha256Hex(raw)
}

// VaultStore implements Store using Vault KV.
//
// Secrets are addressed by the deterministic digest of the raw key
// (sha256/sha512). bcrypt is not supported: its hashes embed a random
// salt, so the hash of a presented key can never be recomputed to derive
// the storage path and every lookup would miss. Config.Validate enforces
// the same rule at load time (WP4 Strategy A).
type VaultStore struct {
	client vault.Client
	config *Config
	logger observability.Logger
	cache  *keyCache
}

// NewVaultStore creates a new Vault-based API key store.
func NewVaultStore(client vault.Client, config *Config, logger observability.Logger) (*VaultStore, error) {
	if client == nil || !client.IsEnabled() {
		return nil, fmt.Errorf("vault client is required and must be enabled")
	}

	if config.Vault == nil || !config.Vault.Enabled {
		return nil, fmt.Errorf("vault configuration is required")
	}

	if algorithm := config.GetEffectiveHashAlgorithm(); algorithm == HashAlgBcrypt {
		return nil, fmt.Errorf(
			"hash algorithm %q is not supported by the vault store: "+
				"bcrypt hashes are salted and cannot address vault paths (use sha256 or sha512)",
			algorithm)
	}

	store := &VaultStore{
		client: client,
		config: config,
		logger: logger,
	}

	// Initialize cache if enabled
	if config.Cache != nil && config.Cache.Enabled {
		store.cache = newKeyCache(config.Cache.TTL, config.Cache.MaxSize)
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

	data, err := s.client.KV().Read(ctx, s.config.Vault.KVMount, s.vaultPath(keyHash))
	if err != nil {
		return nil, classifyVaultReadError(err)
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
	data, err := s.client.KV().Read(ctx, s.config.Vault.KVMount, s.vaultPath("by-id/"+id))
	if err != nil {
		return nil, classifyVaultReadError(err)
	}

	return parseKeyFromVault(data)
}

// List lists all API keys.
func (s *VaultStore) List(ctx context.Context) ([]*StaticKey, error) {
	ids, err := s.client.KV().List(ctx, s.config.Vault.KVMount, s.vaultPath("by-id"))
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

// vaultPath builds the KV-relative path for the given suffix.
func (s *VaultStore) vaultPath(suffix string) string {
	path := s.config.Vault.Path
	if path != "" {
		path += "/"
	}
	return path + suffix
}

// classifyVaultReadError maps a Vault read failure to a package error.
// Genuine not-found responses become ErrAPIKeyNotFound; every other
// failure (transport, permission, sealed Vault, ...) is wrapped in
// ErrStoreUnavailable so callers do not mistake an outage for a miss.
func classifyVaultReadError(err error) error {
	if errors.Is(err, vault.ErrSecretNotFound) {
		return ErrAPIKeyNotFound
	}
	return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
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

// keyCache provides bounded, TTL-based caching for Vault-stored keys.
//
// Entries are keyed by the SHA-256 digest of the raw API key so raw key
// material is never retained as a map key. MaxSize is enforced with LRU
// eviction and expired entries are removed eagerly on access.
type keyCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List // front = most recently used
	ttl     time.Duration
	maxSize int
}

// cacheEntry is the value stored in the keyCache LRU list.
type cacheEntry struct {
	cacheKey  string
	key       *StaticKey
	expiresAt time.Time
}

// newKeyCache creates a key cache. maxSize <= 0 disables the size bound.
func newKeyCache(ttl time.Duration, maxSize int) *keyCache {
	return &keyCache{
		entries: make(map[string]*list.Element),
		lru:     list.New(),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// cacheKeyFor derives the cache map key from a raw API key. The raw key is
// digested so it is never stored verbatim as a map key.
func cacheKeyFor(rawKey string) string {
	return sha256Hex(rawKey)
}

// get retrieves a key from the cache. Expired entries are deleted eagerly.
func (c *keyCache) get(rawKey string) *StaticKey {
	cacheKey := cacheKeyFor(rawKey)

	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.entries[cacheKey]
	if !ok {
		return nil
	}

	entry, ok := elem.Value.(*cacheEntry)
	if !ok {
		c.removeElementLocked(elem, cacheKey)
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		c.removeElementLocked(elem, cacheKey)
		return nil
	}

	c.lru.MoveToFront(elem)
	return entry.key
}

// set stores a key in the cache, evicting least-recently-used entries when
// the configured maximum size is exceeded.
func (c *keyCache) set(rawKey string, storedKey *StaticKey) {
	cacheKey := cacheKeyFor(rawKey)
	expiresAt := time.Now().Add(c.ttl)

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[cacheKey]; ok {
		if entry, ok := elem.Value.(*cacheEntry); ok {
			entry.key = storedKey
			entry.expiresAt = expiresAt
			c.lru.MoveToFront(elem)
			return
		}
		c.removeElementLocked(elem, cacheKey)
	}

	c.entries[cacheKey] = c.lru.PushFront(&cacheEntry{
		cacheKey:  cacheKey,
		key:       storedKey,
		expiresAt: expiresAt,
	})
	c.evictLocked()
}

// evictLocked drops least-recently-used entries until the cache fits within
// maxSize. Callers must hold the cache mutex.
func (c *keyCache) evictLocked() {
	if c.maxSize <= 0 {
		return
	}
	for c.lru.Len() > c.maxSize {
		oldest := c.lru.Back()
		if oldest == nil {
			return
		}
		entry, ok := oldest.Value.(*cacheEntry)
		if !ok {
			c.lru.Remove(oldest)
			continue
		}
		c.removeElementLocked(oldest, entry.cacheKey)
	}
}

// removeElementLocked removes an element from both the LRU list and the
// entries index. Callers must hold the cache mutex.
func (c *keyCache) removeElementLocked(elem *list.Element, cacheKey string) {
	c.lru.Remove(elem)
	delete(c.entries, cacheKey)
}

// Ensure implementations satisfy the interface.
var (
	_ Store = (*MemoryStore)(nil)
	_ Store = (*VaultStore)(nil)
)
