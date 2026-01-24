package apikey

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewStore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config is required",
		},
		{
			name: "memory store",
			config: &Config{
				Enabled: true,
				Store: &StoreConfig{
					Type: "memory",
				},
			},
			wantErr: false,
		},
		{
			name: "default store (memory)",
			config: &Config{
				Enabled: true,
			},
			wantErr: false,
		},
		{
			name: "vault store without client",
			config: &Config{
				Enabled: true,
				Store: &StoreConfig{
					Type: "vault",
				},
			},
			wantErr: true,
			errMsg:  "vault store requires vault client",
		},
		{
			name: "file store not implemented",
			config: &Config{
				Enabled: true,
				Store: &StoreConfig{
					Type: "file",
				},
			},
			wantErr: true,
			errMsg:  "file store not yet implemented",
		},
		{
			name: "unknown store type",
			config: &Config{
				Enabled: true,
				Store: &StoreConfig{
					Type: "unknown",
				},
			},
			wantErr: true,
			errMsg:  "unknown store type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, err := NewStore(tt.config, observability.NopLogger())
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, store)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, store)
			}
		})
	}
}

func TestNewMemoryStore(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Store: &StoreConfig{
			Type: "memory",
			Keys: []StaticKey{
				{
					ID:      "key1",
					Key:     "api-key-1",
					Name:    "Key 1",
					Enabled: true,
					Scopes:  []string{"read"},
				},
				{
					ID:      "key2",
					Key:     "api-key-2",
					Name:    "Key 2",
					Enabled: true,
					Roles:   []string{"admin"},
				},
			},
		},
	}

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)
	assert.NotNil(t, store)

	// Verify keys were loaded
	key1, err := store.Get(context.Background(), "api-key-1")
	require.NoError(t, err)
	assert.Equal(t, "key1", key1.ID)
	assert.Equal(t, "Key 1", key1.Name)
	assert.Equal(t, []string{"read"}, key1.Scopes)

	key2, err := store.GetByID(context.Background(), "key2")
	require.NoError(t, err)
	assert.Equal(t, "api-key-2", key2.Key)
	assert.Equal(t, []string{"admin"}, key2.Roles)
}

func TestMemoryStore_Get(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Store: &StoreConfig{
			Type: "memory",
			Keys: []StaticKey{
				{
					ID:      "key1",
					Key:     "api-key-1",
					Enabled: true,
				},
			},
		},
	}

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	// Test existing key
	key, err := store.Get(context.Background(), "api-key-1")
	require.NoError(t, err)
	assert.Equal(t, "key1", key.ID)

	// Test non-existing key
	key, err = store.Get(context.Background(), "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, key)
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
}

func TestMemoryStore_GetByID(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Store: &StoreConfig{
			Type: "memory",
			Keys: []StaticKey{
				{
					ID:      "key1",
					Key:     "api-key-1",
					Enabled: true,
				},
			},
		},
	}

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	// Test existing key
	key, err := store.GetByID(context.Background(), "key1")
	require.NoError(t, err)
	assert.Equal(t, "api-key-1", key.Key)

	// Test non-existing key
	key, err = store.GetByID(context.Background(), "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, key)
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
}

func TestMemoryStore_List(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Store: &StoreConfig{
			Type: "memory",
			Keys: []StaticKey{
				{ID: "key1", Key: "api-key-1", Enabled: true},
				{ID: "key2", Key: "api-key-2", Enabled: true},
				{ID: "key3", Key: "api-key-3", Enabled: true},
			},
		},
	}

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	keys, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

func TestMemoryStore_Add(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Store: &StoreConfig{
			Type: "memory",
		},
	}

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	// Add a key
	store.Add(&StaticKey{
		ID:      "new-key",
		Key:     "new-api-key",
		Enabled: true,
	})

	// Verify it was added
	key, err := store.Get(context.Background(), "new-api-key")
	require.NoError(t, err)
	assert.Equal(t, "new-key", key.ID)

	key, err = store.GetByID(context.Background(), "new-key")
	require.NoError(t, err)
	assert.Equal(t, "new-api-key", key.Key)
}

func TestMemoryStore_Remove(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Store: &StoreConfig{
			Type: "memory",
			Keys: []StaticKey{
				{ID: "key1", Key: "api-key-1", Enabled: true},
			},
		},
	}

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	// Verify key exists
	_, err = store.Get(context.Background(), "api-key-1")
	require.NoError(t, err)

	// Remove the key
	store.Remove("key1")

	// Verify it was removed
	_, err = store.Get(context.Background(), "api-key-1")
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)

	_, err = store.GetByID(context.Background(), "key1")
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
}

func TestMemoryStore_Remove_NonExistent(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Store: &StoreConfig{
			Type: "memory",
		},
	}

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	// Should not panic when removing non-existent key
	store.Remove("nonexistent")
}

func TestMemoryStore_Close(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Store: &StoreConfig{
			Type: "memory",
		},
	}

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	err = store.Close()
	assert.NoError(t, err)
}

func TestMemoryStore_EmptyConfig(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
	}

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	keys, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestKeyCache_GetSet(t *testing.T) {
	t.Parallel()

	cache := &keyCache{
		entries: make(map[string]*cacheEntry),
		ttl:     time.Minute,
	}

	key := &StaticKey{
		ID:      "key1",
		Key:     "api-key-1",
		Enabled: true,
	}

	// Set a key
	cache.set("api-key-1", key)

	// Get the key
	result := cache.get("api-key-1")
	require.NotNil(t, result)
	assert.Equal(t, "key1", result.ID)

	// Get non-existent key
	result = cache.get("nonexistent")
	assert.Nil(t, result)
}

func TestKeyCache_Expiration(t *testing.T) {
	t.Parallel()

	cache := &keyCache{
		entries: make(map[string]*cacheEntry),
		ttl:     10 * time.Millisecond,
	}

	key := &StaticKey{
		ID:      "key1",
		Key:     "api-key-1",
		Enabled: true,
	}

	// Set a key
	cache.set("api-key-1", key)

	// Key should be available immediately
	result := cache.get("api-key-1")
	require.NotNil(t, result)

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Key should be expired
	result = cache.get("api-key-1")
	assert.Nil(t, result)
}

func TestParseKeyFromVault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     map[string]interface{}
		expected *StaticKey
	}{
		{
			name: "full data",
			data: map[string]interface{}{
				"id":      "key1",
				"name":    "Test Key",
				"hash":    "abc123",
				"key":     "api-key-1",
				"scopes":  []interface{}{"read", "write"},
				"roles":   []interface{}{"admin"},
				"enabled": true,
			},
			expected: &StaticKey{
				ID:      "key1",
				Name:    "Test Key",
				Hash:    "abc123",
				Key:     "api-key-1",
				Scopes:  []string{"read", "write"},
				Roles:   []string{"admin"},
				Enabled: true,
			},
		},
		{
			name: "minimal data",
			data: map[string]interface{}{
				"id": "key1",
			},
			expected: &StaticKey{
				ID:      "key1",
				Enabled: true, // Default
			},
		},
		{
			name:     "empty data",
			data:     map[string]interface{}{},
			expected: &StaticKey{Enabled: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := parseKeyFromVault(tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.Hash, result.Hash)
			assert.Equal(t, tt.expected.Key, result.Key)
			assert.Equal(t, tt.expected.Scopes, result.Scopes)
			assert.Equal(t, tt.expected.Roles, result.Roles)
			assert.Equal(t, tt.expected.Enabled, result.Enabled)
		})
	}
}

func TestMemoryStore_Concurrency(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Store: &StoreConfig{
			Type: "memory",
		},
	}

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	// Add initial keys
	for i := 0; i < 100; i++ {
		store.Add(&StaticKey{
			ID:      "key" + string(rune(i)),
			Key:     "api-key-" + string(rune(i)),
			Enabled: true,
		})
	}

	// Concurrent reads and writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				_, _ = store.List(context.Background())
				_, _ = store.Get(context.Background(), "api-key-"+string(rune(id)))
				_, _ = store.GetByID(context.Background(), "key"+string(rune(id)))
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
