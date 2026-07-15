package apikey

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// size returns the number of cached entries (test-only helper).
func (c *keyCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// memoryStoreConfig builds a memory-store config with the given algorithm
// and static keys.
func memoryStoreConfig(algorithm string, keys ...StaticKey) *Config {
	return &Config{
		Enabled:       true,
		HashAlgorithm: algorithm,
		Store: &StoreConfig{
			Type: storeTypeMemory,
			Keys: keys,
		},
	}
}

func TestMemoryStore_HashOnly_SHA256(t *testing.T) {
	t.Parallel()

	rawKey := "hash-only-sha256-key"
	config := memoryStoreConfig(HashAlgSHA256, StaticKey{
		ID:      "key1",
		Hash:    sha256Hex(rawKey), // Key intentionally empty
		Enabled: true,
	})

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	// Correct presented key resolves via digest indexing.
	found, err := store.Get(context.Background(), rawKey)
	require.NoError(t, err)
	assert.Equal(t, "key1", found.ID)

	// Wrong presented key is rejected.
	missing, err := store.Get(context.Background(), "wrong-key")
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
	assert.Nil(t, missing)
}

func TestMemoryStore_HashOnly_SHA512(t *testing.T) {
	t.Parallel()

	rawKey := "hash-only-sha512-key"
	config := memoryStoreConfig(HashAlgSHA512, StaticKey{
		ID:      "key1",
		Hash:    sha512Hex(rawKey),
		Enabled: true,
	})

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	found, err := store.Get(context.Background(), rawKey)
	require.NoError(t, err)
	assert.Equal(t, "key1", found.ID)

	_, err = store.Get(context.Background(), "wrong-key")
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
}

func TestMemoryStore_HashOnly_UppercaseHashNormalized(t *testing.T) {
	t.Parallel()

	rawKey := "uppercase-hash-key"
	config := memoryStoreConfig(HashAlgSHA256, StaticKey{
		ID:      "key1",
		Hash:    strings.ToUpper(sha256Hex(rawKey)),
		Enabled: true,
	})

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	found, err := store.Get(context.Background(), rawKey)
	require.NoError(t, err)
	assert.Equal(t, "key1", found.ID)
}

func TestMemoryStore_RawKeyNeverUsedAsMapKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm string
	}{
		{name: "sha256", algorithm: HashAlgSHA256},
		{name: "sha512", algorithm: HashAlgSHA512},
		{name: "plaintext", algorithm: HashAlgPlaintext},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rawKey := "raw-api-key-material"
			config := memoryStoreConfig(tt.algorithm, StaticKey{
				ID:      "key1",
				Key:     rawKey,
				Enabled: true,
			})

			store, err := NewMemoryStore(config, observability.NopLogger())
			require.NoError(t, err)

			// The raw key must never appear as a map key.
			_, rawIndexed := store.byDigest[rawKey]
			assert.False(t, rawIndexed, "raw key must not be used as a map key")

			// The digest of the raw key is the index.
			_, digestIndexed := store.byDigest[lookupDigest(rawKey, tt.algorithm)]
			assert.True(t, digestIndexed, "digest of the raw key must be the index")

			// Lookup by presented key still works (back-compat).
			found, err := store.Get(context.Background(), rawKey)
			require.NoError(t, err)
			assert.Equal(t, "key1", found.ID)
		})
	}
}

func TestMemoryStore_Bcrypt_LookupByVerification(t *testing.T) {
	t.Parallel()

	rawKey := "bcrypt-protected-key"
	hash, err := bcrypt.GenerateFromPassword([]byte(rawKey), bcrypt.MinCost)
	require.NoError(t, err)

	config := memoryStoreConfig(HashAlgBcrypt, StaticKey{
		ID:      "key1",
		Hash:    string(hash), // hash-only bcrypt entry
		Enabled: true,
	})

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	// bcrypt entries are not digest-addressable.
	assert.Empty(t, store.byDigest)

	found, err := store.Get(context.Background(), rawKey)
	require.NoError(t, err)
	assert.Equal(t, "key1", found.ID)

	_, err = store.Get(context.Background(), "wrong-key")
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
}

func TestMemoryStore_Bcrypt_HashInKeyField(t *testing.T) {
	t.Parallel()

	rawKey := "bcrypt-key-in-key-field"
	hash, err := bcrypt.GenerateFromPassword([]byte(rawKey), bcrypt.MinCost)
	require.NoError(t, err)

	// Legacy layout: bcrypt hash stored in Key, Hash empty.
	config := memoryStoreConfig(HashAlgBcrypt, StaticKey{
		ID:      "key1",
		Key:     string(hash),
		Enabled: true,
	})

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	found, err := store.Get(context.Background(), rawKey)
	require.NoError(t, err)
	assert.Equal(t, "key1", found.ID)
}

func TestMemoryStore_Remove_HashOnlyEntry(t *testing.T) {
	t.Parallel()

	rawKey := "removable-key"
	config := memoryStoreConfig(HashAlgSHA256, StaticKey{
		ID:      "key1",
		Hash:    sha256Hex(rawKey),
		Enabled: true,
	})

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	store.Remove("key1")

	_, err = store.Get(context.Background(), rawKey)
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
	_, err = store.GetByID(context.Background(), "key1")
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
	assert.Empty(t, store.byDigest)
}

func TestMemoryStore_Remove_BcryptEntry(t *testing.T) {
	t.Parallel()

	rawKey := "bcrypt-removable"
	hash, err := bcrypt.GenerateFromPassword([]byte(rawKey), bcrypt.MinCost)
	require.NoError(t, err)

	config := memoryStoreConfig(HashAlgBcrypt, StaticKey{
		ID:      "key1",
		Hash:    string(hash),
		Enabled: true,
	})

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	store.Remove("key1")

	_, err = store.Get(context.Background(), rawKey)
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
	assert.Empty(t, store.byBcrypt)
}

func TestMemoryStore_UnaddressableEntry_WarnsAndIsByIDOnly(t *testing.T) {
	t.Parallel()

	// Entry with neither key nor usable hash: rejected by Config.Validate,
	// but the store must stay defensive when fed an unvalidated config.
	config := memoryStoreConfig(HashAlgSHA256, StaticKey{
		ID:      "broken",
		Hash:    "not-a-hex-digest",
		Enabled: true,
	})

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	assert.Empty(t, store.byDigest)

	byID, err := store.GetByID(context.Background(), "broken")
	require.NoError(t, err)
	assert.Equal(t, "broken", byID.ID)
}

func TestVaultStore_Get_UnsupportedAlgorithmHashError(t *testing.T) {
	t.Parallel()

	// NewVaultStore only rejects bcrypt; an unknown algorithm surfaces as a
	// hashing error at lookup time (Config.Validate rejects it earlier in
	// the normal flow).
	client := &mockVaultClient{enabled: true, kv: newMockKVClient()}
	config := &Config{
		Enabled:       true,
		HashAlgorithm: "unsupported",
		Vault: &VaultConfig{
			Enabled: true,
			KVMount: "secret",
			Path:    "api-keys",
		},
	}

	store, err := NewVaultStore(client, config, observability.NopLogger())
	require.NoError(t, err)

	result, err := store.Get(context.Background(), "some-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to hash key")
	assert.Nil(t, result)
}

func TestNewVaultStore_RejectsBcrypt(t *testing.T) {
	t.Parallel()

	client := &mockVaultClient{enabled: true, kv: newMockKVClient()}
	config := &Config{
		Enabled:       true,
		HashAlgorithm: HashAlgBcrypt,
		Vault: &VaultConfig{
			Enabled: true,
			KVMount: "secret",
			Path:    "api-keys",
		},
	}

	store, err := NewVaultStore(client, config, observability.NopLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported by the vault store")
	assert.Nil(t, store)
}

func TestKeyCache_LRUEviction(t *testing.T) {
	t.Parallel()

	cache := newKeyCache(time.Minute, 2)

	cache.set("key-a", &StaticKey{ID: "a"})
	cache.set("key-b", &StaticKey{ID: "b"})

	// Touch key-a so key-b becomes the least recently used entry.
	require.NotNil(t, cache.get("key-a"))

	cache.set("key-c", &StaticKey{ID: "c"})

	assert.Equal(t, 2, cache.size(), "MaxSize must be enforced")
	assert.Nil(t, cache.get("key-b"), "least recently used entry must be evicted")
	assert.NotNil(t, cache.get("key-a"))
	assert.NotNil(t, cache.get("key-c"))
}

func TestKeyCache_LRUEviction_MaxSizeOne(t *testing.T) {
	t.Parallel()

	cache := newKeyCache(time.Minute, 1)

	cache.set("key-a", &StaticKey{ID: "a"})
	cache.set("key-b", &StaticKey{ID: "b"})

	assert.Equal(t, 1, cache.size())
	assert.Nil(t, cache.get("key-a"))
	assert.NotNil(t, cache.get("key-b"))
}

func TestKeyCache_ExpiredEntryDeletedOnGet(t *testing.T) {
	t.Parallel()

	cache := newKeyCache(5*time.Millisecond, 0)
	cache.set("key-a", &StaticKey{ID: "a"})
	require.Equal(t, 1, cache.size())

	time.Sleep(20 * time.Millisecond)

	assert.Nil(t, cache.get("key-a"))
	assert.Equal(t, 0, cache.size(), "expired entry must be deleted on get, not shadowed")
}

func TestKeyCache_SetUpdatesExistingEntry(t *testing.T) {
	t.Parallel()

	cache := newKeyCache(time.Minute, 2)

	cache.set("key-a", &StaticKey{ID: "a1"})
	cache.set("key-a", &StaticKey{ID: "a2"})

	assert.Equal(t, 1, cache.size())
	got := cache.get("key-a")
	require.NotNil(t, got)
	assert.Equal(t, "a2", got.ID)
}

func TestKeyCache_RawKeyNeverUsedAsMapKey(t *testing.T) {
	t.Parallel()

	rawKey := "raw-cache-key-material"
	cache := newKeyCache(time.Minute, 0)
	cache.set(rawKey, &StaticKey{ID: "a"})

	_, rawIndexed := cache.entries[rawKey]
	assert.False(t, rawIndexed, "raw key must not be a cache map key")

	_, digestIndexed := cache.entries[sha256Hex(rawKey)]
	assert.True(t, digestIndexed, "cache must be keyed by sha256 of the raw key")
}

func TestVaultStore_CacheKeyedByDigest(t *testing.T) {
	t.Parallel()

	kvClient := newMockKVClient()
	client := &mockVaultClient{enabled: true, kv: kvClient}
	config := &Config{
		HashAlgorithm: HashAlgSHA256,
		Vault: &VaultConfig{
			Enabled: true,
			KVMount: "secret",
			Path:    "api-keys",
		},
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     time.Minute,
			MaxSize: 10,
		},
	}

	store, err := NewVaultStore(client, config, observability.NopLogger())
	require.NoError(t, err)

	rawKey := "cached-vault-key"
	kvClient.SetData("secret", "api-keys/"+sha256Hex(rawKey), map[string]interface{}{
		"id":      "key1",
		"hash":    sha256Hex(rawKey),
		"enabled": true,
	})

	_, err = store.Get(context.Background(), rawKey)
	require.NoError(t, err)

	_, rawIndexed := store.cache.entries[rawKey]
	assert.False(t, rawIndexed, "vault store cache must not retain the raw key as map key")
	_, digestIndexed := store.cache.entries[sha256Hex(rawKey)]
	assert.True(t, digestIndexed)
}
