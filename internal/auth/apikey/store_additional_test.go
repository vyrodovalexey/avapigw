package apikey

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// mockVaultClient implements vault.Client for testing VaultStore.
type mockVaultClient struct {
	enabled bool
	kv      *mockKVClient
}

func (m *mockVaultClient) IsEnabled() bool {
	return m.enabled
}

func (m *mockVaultClient) Authenticate(_ context.Context) error {
	return nil
}

func (m *mockVaultClient) RenewToken(_ context.Context) error {
	return nil
}

func (m *mockVaultClient) Health(_ context.Context) (*vault.HealthStatus, error) {
	return &vault.HealthStatus{Initialized: true, Sealed: false}, nil
}

func (m *mockVaultClient) KV() vault.KVClient {
	return m.kv
}

func (m *mockVaultClient) Transit() vault.TransitClient {
	return nil
}

func (m *mockVaultClient) PKI() vault.PKIClient {
	return nil
}

func (m *mockVaultClient) Close() error {
	return nil
}

// mockKVClient implements vault.KVClient for testing.
type mockKVClient struct {
	data      map[string]map[string]interface{}
	listData  map[string][]string
	readErr   error
	listErr   error
	writeErr  error
	deleteErr error
}

func newMockKVClient() *mockKVClient {
	return &mockKVClient{
		data:     make(map[string]map[string]interface{}),
		listData: make(map[string][]string),
	}
}

func (m *mockKVClient) Read(_ context.Context, mount, path string) (map[string]interface{}, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	key := mount + "/" + path
	data, ok := m.data[key]
	if !ok {
		return nil, errors.New("key not found")
	}
	return data, nil
}

func (m *mockKVClient) Write(_ context.Context, mount, path string, data map[string]interface{}) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	key := mount + "/" + path
	m.data[key] = data
	return nil
}

func (m *mockKVClient) Delete(_ context.Context, _, _ string) error {
	return m.deleteErr
}

func (m *mockKVClient) List(_ context.Context, mount, path string) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	key := mount + "/" + path
	return m.listData[key], nil
}

func (m *mockKVClient) SetData(mount, path string, data map[string]interface{}) {
	key := mount + "/" + path
	m.data[key] = data
}

func (m *mockKVClient) SetListData(mount, path string, ids []string) {
	key := mount + "/" + path
	m.listData[key] = ids
}

// TestNewVaultStore tests VaultStore creation.
func TestNewVaultStore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		client  vault.Client
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil client",
			client:  nil,
			config:  &Config{Vault: &VaultConfig{Enabled: true, KVMount: "secret"}},
			wantErr: true,
			errMsg:  "vault client is required",
		},
		{
			name:    "disabled client",
			client:  &mockVaultClient{enabled: false, kv: newMockKVClient()},
			config:  &Config{Vault: &VaultConfig{Enabled: true, KVMount: "secret"}},
			wantErr: true,
			errMsg:  "vault client is required and must be enabled",
		},
		{
			name:    "nil vault config",
			client:  &mockVaultClient{enabled: true, kv: newMockKVClient()},
			config:  &Config{},
			wantErr: true,
			errMsg:  "vault configuration is required",
		},
		{
			name:    "disabled vault config",
			client:  &mockVaultClient{enabled: true, kv: newMockKVClient()},
			config:  &Config{Vault: &VaultConfig{Enabled: false}},
			wantErr: true,
			errMsg:  "vault configuration is required",
		},
		{
			name:   "valid config without cache",
			client: &mockVaultClient{enabled: true, kv: newMockKVClient()},
			config: &Config{
				Vault: &VaultConfig{
					Enabled: true,
					KVMount: "secret",
					Path:    "api-keys",
				},
			},
			wantErr: false,
		},
		{
			name:   "valid config with cache",
			client: &mockVaultClient{enabled: true, kv: newMockKVClient()},
			config: &Config{
				Vault: &VaultConfig{
					Enabled: true,
					KVMount: "secret",
					Path:    "api-keys",
				},
				Cache: &CacheConfig{
					Enabled: true,
					TTL:     5 * time.Minute,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, err := NewVaultStore(tt.client, tt.config, observability.NopLogger())
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, store)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, store)
			}
		})
	}
}

// TestVaultStore_Get tests VaultStore.Get method.
func TestVaultStore_Get(t *testing.T) {
	t.Parallel()

	t.Run("key found", func(t *testing.T) {
		t.Parallel()

		kvClient := newMockKVClient()
		client := &mockVaultClient{enabled: true, kv: kvClient}
		config := &Config{
			HashAlgorithm: "sha256",
			Vault: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
		}

		store, err := NewVaultStore(client, config, observability.NopLogger())
		require.NoError(t, err)

		// Set up test data - hash the key to create the path
		testKey := "test-api-key"
		keyHash, _ := HashKey(testKey, "sha256")
		kvClient.SetData("secret", "api-keys/"+keyHash, map[string]interface{}{
			"id":      "key1",
			"name":    "Test Key",
			"key":     testKey,
			"enabled": true,
			"scopes":  []interface{}{"read", "write"},
			"roles":   []interface{}{"admin"},
		})

		result, err := store.Get(context.Background(), testKey)
		require.NoError(t, err)
		assert.Equal(t, "key1", result.ID)
		assert.Equal(t, "Test Key", result.Name)
		assert.Equal(t, []string{"read", "write"}, result.Scopes)
		assert.Equal(t, []string{"admin"}, result.Roles)
	})

	t.Run("key not found", func(t *testing.T) {
		t.Parallel()

		kvClient := newMockKVClient()
		kvClient.readErr = errors.New("not found")
		client := &mockVaultClient{enabled: true, kv: kvClient}
		config := &Config{
			HashAlgorithm: "sha256",
			Vault: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
		}

		store, err := NewVaultStore(client, config, observability.NopLogger())
		require.NoError(t, err)

		result, err := store.Get(context.Background(), "nonexistent")
		assert.ErrorIs(t, err, ErrAPIKeyNotFound)
		assert.Nil(t, result)
	})

	t.Run("with cache hit", func(t *testing.T) {
		t.Parallel()

		kvClient := newMockKVClient()
		client := &mockVaultClient{enabled: true, kv: kvClient}
		config := &Config{
			HashAlgorithm: "sha256",
			Vault: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
			Cache: &CacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
			},
		}

		store, err := NewVaultStore(client, config, observability.NopLogger())
		require.NoError(t, err)

		// Set up test data
		testKey := "test-api-key"
		keyHash, _ := HashKey(testKey, "sha256")
		kvClient.SetData("secret", "api-keys/"+keyHash, map[string]interface{}{
			"id":      "key1",
			"name":    "Test Key",
			"enabled": true,
		})

		// First call - should hit Vault
		result1, err := store.Get(context.Background(), testKey)
		require.NoError(t, err)
		assert.Equal(t, "key1", result1.ID)

		// Second call - should hit cache
		result2, err := store.Get(context.Background(), testKey)
		require.NoError(t, err)
		assert.Equal(t, "key1", result2.ID)
	})

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()

		kvClient := newMockKVClient()
		client := &mockVaultClient{enabled: true, kv: kvClient}
		config := &Config{
			HashAlgorithm: "sha256",
			Vault: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "", // Empty path
			},
		}

		store, err := NewVaultStore(client, config, observability.NopLogger())
		require.NoError(t, err)

		testKey := "test-api-key"
		keyHash, _ := HashKey(testKey, "sha256")
		kvClient.SetData("secret", keyHash, map[string]interface{}{
			"id":      "key1",
			"enabled": true,
		})

		result, err := store.Get(context.Background(), testKey)
		require.NoError(t, err)
		assert.Equal(t, "key1", result.ID)
	})
}

// TestVaultStore_GetByID tests VaultStore.GetByID method.
func TestVaultStore_GetByID(t *testing.T) {
	t.Parallel()

	t.Run("key found", func(t *testing.T) {
		t.Parallel()

		kvClient := newMockKVClient()
		client := &mockVaultClient{enabled: true, kv: kvClient}
		config := &Config{
			Vault: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
		}

		store, err := NewVaultStore(client, config, observability.NopLogger())
		require.NoError(t, err)

		kvClient.SetData("secret", "api-keys/by-id/key1", map[string]interface{}{
			"id":      "key1",
			"name":    "Test Key",
			"enabled": true,
		})

		result, err := store.GetByID(context.Background(), "key1")
		require.NoError(t, err)
		assert.Equal(t, "key1", result.ID)
		assert.Equal(t, "Test Key", result.Name)
	})

	t.Run("key not found", func(t *testing.T) {
		t.Parallel()

		kvClient := newMockKVClient()
		kvClient.readErr = errors.New("not found")
		client := &mockVaultClient{enabled: true, kv: kvClient}
		config := &Config{
			Vault: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
		}

		store, err := NewVaultStore(client, config, observability.NopLogger())
		require.NoError(t, err)

		result, err := store.GetByID(context.Background(), "nonexistent")
		assert.ErrorIs(t, err, ErrAPIKeyNotFound)
		assert.Nil(t, result)
	})

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()

		kvClient := newMockKVClient()
		client := &mockVaultClient{enabled: true, kv: kvClient}
		config := &Config{
			Vault: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "",
			},
		}

		store, err := NewVaultStore(client, config, observability.NopLogger())
		require.NoError(t, err)

		kvClient.SetData("secret", "by-id/key1", map[string]interface{}{
			"id":      "key1",
			"enabled": true,
		})

		result, err := store.GetByID(context.Background(), "key1")
		require.NoError(t, err)
		assert.Equal(t, "key1", result.ID)
	})
}

// TestVaultStore_List tests VaultStore.List method.
func TestVaultStore_List(t *testing.T) {
	t.Parallel()

	t.Run("list keys", func(t *testing.T) {
		t.Parallel()

		kvClient := newMockKVClient()
		client := &mockVaultClient{enabled: true, kv: kvClient}
		config := &Config{
			Vault: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
		}

		store, err := NewVaultStore(client, config, observability.NopLogger())
		require.NoError(t, err)

		// Set up list data
		kvClient.SetListData("secret", "api-keys/by-id", []string{"key1", "key2"})
		kvClient.SetData("secret", "api-keys/by-id/key1", map[string]interface{}{
			"id":      "key1",
			"enabled": true,
		})
		kvClient.SetData("secret", "api-keys/by-id/key2", map[string]interface{}{
			"id":      "key2",
			"enabled": true,
		})

		keys, err := store.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, keys, 2)
	})

	t.Run("list error", func(t *testing.T) {
		t.Parallel()

		kvClient := newMockKVClient()
		kvClient.listErr = errors.New("list failed")
		client := &mockVaultClient{enabled: true, kv: kvClient}
		config := &Config{
			Vault: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
		}

		store, err := NewVaultStore(client, config, observability.NopLogger())
		require.NoError(t, err)

		keys, err := store.List(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to list keys")
		assert.Nil(t, keys)
	})

	t.Run("partial failure - some keys not found", func(t *testing.T) {
		t.Parallel()

		kvClient := newMockKVClient()
		client := &mockVaultClient{enabled: true, kv: kvClient}
		config := &Config{
			Vault: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
		}

		store, err := NewVaultStore(client, config, observability.NopLogger())
		require.NoError(t, err)

		// Set up list data with one valid key
		kvClient.SetListData("secret", "api-keys/by-id", []string{"key1", "key2"})
		kvClient.SetData("secret", "api-keys/by-id/key1", map[string]interface{}{
			"id":      "key1",
			"enabled": true,
		})
		// key2 is not set, so it will fail

		keys, err := store.List(context.Background())
		require.NoError(t, err)
		// Should return only the successful key
		assert.Len(t, keys, 1)
		assert.Equal(t, "key1", keys[0].ID)
	})

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()

		kvClient := newMockKVClient()
		client := &mockVaultClient{enabled: true, kv: kvClient}
		config := &Config{
			Vault: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "",
			},
		}

		store, err := NewVaultStore(client, config, observability.NopLogger())
		require.NoError(t, err)

		kvClient.SetListData("secret", "by-id", []string{"key1"})
		kvClient.SetData("secret", "by-id/key1", map[string]interface{}{
			"id":      "key1",
			"enabled": true,
		})

		keys, err := store.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, keys, 1)
	})
}

// TestVaultStore_Close tests VaultStore.Close method.
func TestVaultStore_Close(t *testing.T) {
	t.Parallel()

	kvClient := newMockKVClient()
	client := &mockVaultClient{enabled: true, kv: kvClient}
	config := &Config{
		Vault: &VaultConfig{
			Enabled: true,
			KVMount: "secret",
			Path:    "api-keys",
		},
	}

	store, err := NewVaultStore(client, config, observability.NopLogger())
	require.NoError(t, err)

	err = store.Close()
	assert.NoError(t, err)
}

// TestParseKeyFromVault_EdgeCases tests edge cases for parseKeyFromVault.
func TestParseKeyFromVault_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     map[string]interface{}
		expected *StaticKey
	}{
		{
			name: "non-string scopes elements",
			data: map[string]interface{}{
				"id":     "key1",
				"scopes": []interface{}{"read", 123, true}, // Mixed types
			},
			expected: &StaticKey{
				ID:      "key1",
				Scopes:  []string{"read"}, // Only string elements
				Enabled: true,
			},
		},
		{
			name: "non-string roles elements",
			data: map[string]interface{}{
				"id":    "key1",
				"roles": []interface{}{"admin", nil, 456},
			},
			expected: &StaticKey{
				ID:      "key1",
				Roles:   []string{"admin"},
				Enabled: true,
			},
		},
		{
			name: "enabled false",
			data: map[string]interface{}{
				"id":      "key1",
				"enabled": false,
			},
			expected: &StaticKey{
				ID:      "key1",
				Enabled: false,
			},
		},
		{
			name: "wrong type for id",
			data: map[string]interface{}{
				"id": 123, // Not a string
			},
			expected: &StaticKey{
				ID:      "",
				Enabled: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := parseKeyFromVault(tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.Enabled, result.Enabled)
			if tt.expected.Scopes != nil {
				assert.Equal(t, tt.expected.Scopes, result.Scopes)
			}
			if tt.expected.Roles != nil {
				assert.Equal(t, tt.expected.Roles, result.Roles)
			}
		})
	}
}

// TestKeyCache_Concurrent tests concurrent access to keyCache.
func TestKeyCache_Concurrent(t *testing.T) {
	t.Parallel()

	cache := &keyCache{
		entries: make(map[string]*cacheEntry),
		ttl:     time.Minute,
	}

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := &StaticKey{
				ID:      "key" + string(rune(id)),
				Enabled: true,
			}
			cache.set("api-key-"+string(rune(id)), key)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_ = cache.get("api-key-" + string(rune(id)))
		}(i)
	}

	wg.Wait()
}

// TestMemoryStore_ConcurrentAddRemove tests concurrent add/remove operations.
func TestMemoryStore_ConcurrentAddRemove(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Store: &StoreConfig{
			Type: "memory",
		},
	}

	store, err := NewMemoryStore(config, observability.NopLogger())
	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent adds
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			store.Add(&StaticKey{
				ID:      "key" + string(rune(id)),
				Key:     "api-key-" + string(rune(id)),
				Enabled: true,
			})
		}(i)
	}

	wg.Wait()

	// Concurrent removes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			store.Remove("key" + string(rune(id)))
		}(i)
	}

	wg.Wait()

	// Verify all keys are removed
	keys, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, keys)
}
