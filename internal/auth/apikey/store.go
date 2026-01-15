// Package apikey provides API key validation for the API Gateway.
package apikey

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory implementation of the Store interface.
type MemoryStore struct {
	keys map[string]*APIKey
	mu   sync.RWMutex
}

// NewMemoryStore creates a new in-memory API key store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		keys: make(map[string]*APIKey),
	}
}

// Get retrieves an API key by its hash.
func (s *MemoryStore) Get(ctx context.Context, keyHash string) (*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[keyHash]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return key, nil
}

// List returns all API keys.
func (s *MemoryStore) List(ctx context.Context) ([]*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]*APIKey, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, key)
	}

	return keys, nil
}

// Create creates a new API key.
func (s *MemoryStore) Create(ctx context.Context, key *APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[key.KeyHash]; exists {
		return ErrKeyInvalid
	}

	s.keys[key.KeyHash] = key
	return nil
}

// Delete deletes an API key by its hash.
func (s *MemoryStore) Delete(ctx context.Context, keyHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[keyHash]; !exists {
		return ErrKeyNotFound
	}

	delete(s.keys, keyHash)
	return nil
}

// Validate validates an API key hash exists and is valid.
func (s *MemoryStore) Validate(ctx context.Context, keyHash string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[keyHash]
	if !ok {
		return false, nil
	}

	return key.IsValid(), nil
}

// Update updates an existing API key.
func (s *MemoryStore) Update(ctx context.Context, key *APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[key.KeyHash]; !exists {
		return ErrKeyNotFound
	}

	s.keys[key.KeyHash] = key
	return nil
}

// Count returns the number of API keys in the store.
func (s *MemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}

// Clear removes all API keys from the store.
func (s *MemoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = make(map[string]*APIKey)
}

// LoadFromMap loads API keys from a map of key hash to API key.
func (s *MemoryStore) LoadFromMap(keys map[string]*APIKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for hash, key := range keys {
		s.keys[hash] = key
	}
}

// LoadFromSecretData loads API keys from Kubernetes secret data.
// The secret data is expected to be a map of key names to key values.
// Each key value is hashed and stored.
func (s *MemoryStore) LoadFromSecretData(data map[string][]byte, hasher Hasher) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if hasher == nil {
		hasher = &SHA256Hasher{}
	}

	for name, value := range data {
		keyValue := string(value)
		keyHash := hasher.Hash(keyValue)

		s.keys[keyHash] = &APIKey{
			ID:        name,
			Name:      name,
			KeyHash:   keyHash,
			Enabled:   true,
			CreatedAt: time.Now(),
		}
	}
}

// SecretStore wraps a MemoryStore and provides methods for loading from secrets.
type SecretStore struct {
	*MemoryStore
	hasher Hasher
}

// NewSecretStore creates a new secret-backed API key store.
func NewSecretStore(hasher Hasher) *SecretStore {
	if hasher == nil {
		hasher = &SHA256Hasher{}
	}

	return &SecretStore{
		MemoryStore: NewMemoryStore(),
		hasher:      hasher,
	}
}

// LoadSecret loads API keys from secret data.
func (s *SecretStore) LoadSecret(data map[string][]byte) {
	s.LoadFromSecretData(data, s.hasher)
}

// AddKey adds a new API key to the store.
func (s *SecretStore) AddKey(name, key string, scopes []string, expiresAt *time.Time) error {
	keyHash := s.hasher.Hash(key)

	apiKey := &APIKey{
		ID:        name,
		Name:      name,
		KeyHash:   keyHash,
		Scopes:    scopes,
		Enabled:   true,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	return s.Create(context.Background(), apiKey)
}

// RemoveKey removes an API key from the store by its raw value.
func (s *SecretStore) RemoveKey(key string) error {
	keyHash := s.hasher.Hash(key)
	return s.Delete(context.Background(), keyHash)
}

// ValidateKey validates a raw API key.
func (s *SecretStore) ValidateKey(ctx context.Context, key string) (*APIKey, error) {
	keyHash := s.hasher.Hash(key)
	return s.Get(ctx, keyHash)
}

// StaticStore is a simple store that validates against a static list of keys.
type StaticStore struct {
	keys   map[string]bool
	hasher Hasher
}

// NewStaticStore creates a new static API key store.
func NewStaticStore(keys []string, hasher Hasher) *StaticStore {
	if hasher == nil {
		hasher = &SHA256Hasher{}
	}

	store := &StaticStore{
		keys:   make(map[string]bool),
		hasher: hasher,
	}

	for _, key := range keys {
		hash := hasher.Hash(key)
		store.keys[hash] = true
	}

	return store
}

// Get retrieves an API key by its hash.
func (s *StaticStore) Get(ctx context.Context, keyHash string) (*APIKey, error) {
	if !s.keys[keyHash] {
		return nil, ErrKeyNotFound
	}

	return &APIKey{
		ID:        keyHash,
		Name:      "static-key",
		KeyHash:   keyHash,
		Enabled:   true,
		CreatedAt: time.Now(),
	}, nil
}

// List returns all API keys.
func (s *StaticStore) List(ctx context.Context) ([]*APIKey, error) {
	keys := make([]*APIKey, 0, len(s.keys))
	for hash := range s.keys {
		keys = append(keys, &APIKey{
			ID:        hash,
			Name:      "static-key",
			KeyHash:   hash,
			Enabled:   true,
			CreatedAt: time.Now(),
		})
	}
	return keys, nil
}

// Create creates a new API key.
func (s *StaticStore) Create(ctx context.Context, key *APIKey) error {
	s.keys[key.KeyHash] = true
	return nil
}

// Delete deletes an API key by its hash.
func (s *StaticStore) Delete(ctx context.Context, keyHash string) error {
	delete(s.keys, keyHash)
	return nil
}

// Validate validates an API key hash exists and is valid.
func (s *StaticStore) Validate(ctx context.Context, keyHash string) (bool, error) {
	return s.keys[keyHash], nil
}

// AddKey adds a raw key to the store.
func (s *StaticStore) AddKey(key string) {
	hash := s.hasher.Hash(key)
	s.keys[hash] = true
}

// RemoveKey removes a raw key from the store.
func (s *StaticStore) RemoveKey(key string) {
	hash := s.hasher.Hash(key)
	delete(s.keys, hash)
}

// ValidateRawKey validates a raw API key.
func (s *StaticStore) ValidateRawKey(key string) bool {
	hash := s.hasher.Hash(key)
	return s.keys[hash]
}
