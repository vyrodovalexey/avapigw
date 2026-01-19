package apikey

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMemoryStore(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	assert.NotNil(t, store)
	assert.NotNil(t, store.keys)
	assert.Equal(t, 0, store.Count())
}

func TestMemoryStore_Get(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	// Add a key
	key := &APIKey{
		ID:        "key-1",
		Name:      "Test Key",
		KeyHash:   "hash123",
		Enabled:   true,
		CreatedAt: time.Now(),
	}
	store.keys["hash123"] = key

	tests := []struct {
		name          string
		keyHash       string
		expectedError error
	}{
		{
			name:          "Existing key",
			keyHash:       "hash123",
			expectedError: nil,
		},
		{
			name:          "Non-existent key",
			keyHash:       "nonexistent",
			expectedError: ErrKeyNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := store.Get(ctx, tt.keyHash)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, key, result)
			}
		})
	}
}

func TestMemoryStore_List(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	// Empty store
	keys, err := store.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Add some keys
	store.keys["hash1"] = &APIKey{ID: "key-1", KeyHash: "hash1"}
	store.keys["hash2"] = &APIKey{ID: "key-2", KeyHash: "hash2"}
	store.keys["hash3"] = &APIKey{ID: "key-3", KeyHash: "hash3"}

	keys, err = store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

func TestMemoryStore_Create(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	key := &APIKey{
		ID:        "key-1",
		Name:      "Test Key",
		KeyHash:   "hash123",
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	// Create new key
	err := store.Create(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, 1, store.Count())

	// Try to create duplicate
	err = store.Create(ctx, key)
	assert.ErrorIs(t, err, ErrKeyInvalid)
}

func TestMemoryStore_Delete(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	// Add a key
	store.keys["hash123"] = &APIKey{ID: "key-1", KeyHash: "hash123"}

	// Delete existing key
	err := store.Delete(ctx, "hash123")
	require.NoError(t, err)
	assert.Equal(t, 0, store.Count())

	// Delete non-existent key
	err = store.Delete(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestMemoryStore_Validate(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	// Add valid key
	store.keys["valid"] = &APIKey{
		ID:      "key-1",
		KeyHash: "valid",
		Enabled: true,
	}

	// Add disabled key
	store.keys["disabled"] = &APIKey{
		ID:      "key-2",
		KeyHash: "disabled",
		Enabled: false,
	}

	// Add expired key
	expiredTime := time.Now().Add(-time.Hour)
	store.keys["expired"] = &APIKey{
		ID:        "key-3",
		KeyHash:   "expired",
		Enabled:   true,
		ExpiresAt: &expiredTime,
	}

	tests := []struct {
		name     string
		keyHash  string
		expected bool
	}{
		{
			name:     "Valid key",
			keyHash:  "valid",
			expected: true,
		},
		{
			name:     "Disabled key",
			keyHash:  "disabled",
			expected: false,
		},
		{
			name:     "Expired key",
			keyHash:  "expired",
			expected: false,
		},
		{
			name:     "Non-existent key",
			keyHash:  "nonexistent",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			valid, err := store.Validate(ctx, tt.keyHash)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, valid)
		})
	}
}

func TestMemoryStore_Update(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	// Add a key
	store.keys["hash123"] = &APIKey{
		ID:      "key-1",
		Name:    "Original Name",
		KeyHash: "hash123",
		Enabled: true,
	}

	// Update existing key
	updatedKey := &APIKey{
		ID:      "key-1",
		Name:    "Updated Name",
		KeyHash: "hash123",
		Enabled: false,
	}
	err := store.Update(ctx, updatedKey)
	require.NoError(t, err)

	// Verify update
	key, err := store.Get(ctx, "hash123")
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", key.Name)
	assert.False(t, key.Enabled)

	// Update non-existent key
	nonExistent := &APIKey{KeyHash: "nonexistent"}
	err = store.Update(ctx, nonExistent)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestMemoryStore_Count(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	assert.Equal(t, 0, store.Count())

	store.keys["hash1"] = &APIKey{ID: "key-1"}
	assert.Equal(t, 1, store.Count())

	store.keys["hash2"] = &APIKey{ID: "key-2"}
	assert.Equal(t, 2, store.Count())
}

func TestMemoryStore_Clear(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	store.keys["hash1"] = &APIKey{ID: "key-1"}
	store.keys["hash2"] = &APIKey{ID: "key-2"}
	assert.Equal(t, 2, store.Count())

	store.Clear()
	assert.Equal(t, 0, store.Count())
}

func TestMemoryStore_LoadFromMap(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	keys := map[string]*APIKey{
		"hash1": {ID: "key-1", KeyHash: "hash1"},
		"hash2": {ID: "key-2", KeyHash: "hash2"},
		"hash3": {ID: "key-3", KeyHash: "hash3"},
	}

	store.LoadFromMap(keys)
	assert.Equal(t, 3, store.Count())

	// Verify keys are loaded
	key, err := store.Get(context.Background(), "hash1")
	require.NoError(t, err)
	assert.Equal(t, "key-1", key.ID)
}

func TestMemoryStore_LoadFromSecretData(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	hasher := &SHA256Hasher{}

	data := map[string][]byte{
		"api-key-1": []byte("secret-value-1"),
		"api-key-2": []byte("secret-value-2"),
	}

	store.LoadFromSecretData(data, hasher)
	assert.Equal(t, 2, store.Count())

	// Verify keys are loaded with correct hashes
	hash1 := hasher.Hash("secret-value-1")
	key, err := store.Get(context.Background(), hash1)
	require.NoError(t, err)
	assert.Equal(t, "api-key-1", key.ID)
	assert.True(t, key.Enabled)
}

func TestMemoryStore_LoadFromSecretData_NilHasher(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	data := map[string][]byte{
		"api-key-1": []byte("secret-value-1"),
	}

	// Should use default SHA256Hasher
	store.LoadFromSecretData(data, nil)
	assert.Equal(t, 1, store.Count())
}

func TestNewSecretStore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		hasher Hasher
	}{
		{
			name:   "With custom hasher",
			hasher: &SHA256Hasher{},
		},
		{
			name:   "With nil hasher",
			hasher: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewSecretStore(tt.hasher)
			assert.NotNil(t, store)
			assert.NotNil(t, store.MemoryStore)
			assert.NotNil(t, store.hasher)
		})
	}
}

func TestSecretStore_LoadSecret(t *testing.T) {
	t.Parallel()

	store := NewSecretStore(nil)

	data := map[string][]byte{
		"key-1": []byte("value-1"),
		"key-2": []byte("value-2"),
	}

	store.LoadSecret(data)
	assert.Equal(t, 2, store.Count())
}

func TestSecretStore_AddKey(t *testing.T) {
	t.Parallel()

	store := NewSecretStore(nil)

	// Add key without expiry
	err := store.AddKey("key-1", "secret-value", []string{"read", "write"}, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, store.Count())

	// Add key with expiry
	expiry := time.Now().Add(time.Hour)
	err = store.AddKey("key-2", "another-secret", []string{"admin"}, &expiry)
	require.NoError(t, err)
	assert.Equal(t, 2, store.Count())

	// Try to add duplicate
	err = store.AddKey("key-1", "secret-value", nil, nil)
	assert.ErrorIs(t, err, ErrKeyInvalid)
}

func TestSecretStore_RemoveKey(t *testing.T) {
	t.Parallel()

	store := NewSecretStore(nil)

	// Add a key
	err := store.AddKey("key-1", "secret-value", nil, nil)
	require.NoError(t, err)

	// Remove the key
	err = store.RemoveKey("secret-value")
	require.NoError(t, err)
	assert.Equal(t, 0, store.Count())

	// Remove non-existent key
	err = store.RemoveKey("nonexistent")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestSecretStore_ValidateKey(t *testing.T) {
	t.Parallel()

	store := NewSecretStore(nil)

	// Add a key
	err := store.AddKey("key-1", "secret-value", []string{"read"}, nil)
	require.NoError(t, err)

	// Validate existing key
	key, err := store.ValidateKey(context.Background(), "secret-value")
	require.NoError(t, err)
	assert.Equal(t, "key-1", key.ID)

	// Validate non-existent key
	_, err = store.ValidateKey(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestNewStaticStore(t *testing.T) {
	t.Parallel()

	keys := []string{"key1", "key2", "key3"}

	tests := []struct {
		name   string
		keys   []string
		hasher Hasher
	}{
		{
			name:   "With keys and hasher",
			keys:   keys,
			hasher: &SHA256Hasher{},
		},
		{
			name:   "With nil hasher",
			keys:   keys,
			hasher: nil,
		},
		{
			name:   "With empty keys",
			keys:   []string{},
			hasher: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewStaticStore(tt.keys, tt.hasher)
			assert.NotNil(t, store)
			assert.NotNil(t, store.hasher)
			assert.Len(t, store.keys, len(tt.keys))
		})
	}
}

func TestStaticStore_Get(t *testing.T) {
	t.Parallel()

	hasher := &SHA256Hasher{}
	store := NewStaticStore([]string{"valid-key"}, hasher)

	ctx := context.Background()

	// Get existing key
	keyHash := hasher.Hash("valid-key")
	key, err := store.Get(ctx, keyHash)
	require.NoError(t, err)
	assert.Equal(t, keyHash, key.ID)
	assert.Equal(t, "static-key", key.Name)
	assert.True(t, key.Enabled)

	// Get non-existent key
	_, err = store.Get(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestStaticStore_List(t *testing.T) {
	t.Parallel()

	store := NewStaticStore([]string{"key1", "key2", "key3"}, nil)

	keys, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

func TestStaticStore_Create(t *testing.T) {
	t.Parallel()

	store := NewStaticStore(nil, nil)

	key := &APIKey{KeyHash: "newhash"}
	err := store.Create(context.Background(), key)
	require.NoError(t, err)

	assert.True(t, store.keys["newhash"])
}

func TestStaticStore_Delete(t *testing.T) {
	t.Parallel()

	store := NewStaticStore([]string{"key1"}, nil)
	hasher := &SHA256Hasher{}
	keyHash := hasher.Hash("key1")

	err := store.Delete(context.Background(), keyHash)
	require.NoError(t, err)

	assert.False(t, store.keys[keyHash])
}

func TestStaticStore_Validate(t *testing.T) {
	t.Parallel()

	hasher := &SHA256Hasher{}
	store := NewStaticStore([]string{"valid-key"}, hasher)

	ctx := context.Background()

	// Validate existing key
	keyHash := hasher.Hash("valid-key")
	valid, err := store.Validate(ctx, keyHash)
	require.NoError(t, err)
	assert.True(t, valid)

	// Validate non-existent key
	valid, err = store.Validate(ctx, "nonexistent")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestStaticStore_AddKey(t *testing.T) {
	t.Parallel()

	store := NewStaticStore(nil, nil)

	store.AddKey("new-key")
	assert.Len(t, store.keys, 1)

	// Verify the key was hashed
	hasher := &SHA256Hasher{}
	keyHash := hasher.Hash("new-key")
	assert.True(t, store.keys[keyHash])
}

func TestStaticStore_RemoveKey(t *testing.T) {
	t.Parallel()

	store := NewStaticStore([]string{"key-to-remove"}, nil)
	hasher := &SHA256Hasher{}
	keyHash := hasher.Hash("key-to-remove")

	assert.True(t, store.keys[keyHash])

	store.RemoveKey("key-to-remove")
	assert.False(t, store.keys[keyHash])
}

func TestStaticStore_ValidateRawKey(t *testing.T) {
	t.Parallel()

	store := NewStaticStore([]string{"valid-key"}, nil)

	assert.True(t, store.ValidateRawKey("valid-key"))
	assert.False(t, store.ValidateRawKey("invalid-key"))
}

// Concurrent access tests
func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	done := make(chan bool)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := &APIKey{
					ID:      "key",
					KeyHash: "hash",
					Enabled: true,
				}
				_ = store.Create(ctx, key)
				_ = store.Delete(ctx, "hash")
			}
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_, _ = store.Get(ctx, "hash")
				_, _ = store.List(ctx)
				_, _ = store.Validate(ctx, "hash")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestSecretStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	store := NewSecretStore(nil)

	done := make(chan bool)

	// Concurrent operations
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				_ = store.AddKey("key", "value", nil, nil)
				_ = store.RemoveKey("value")
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Benchmark tests
func BenchmarkMemoryStore_Get(b *testing.B) {
	store := NewMemoryStore()
	store.keys["hash123"] = &APIKey{ID: "key-1", KeyHash: "hash123"}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Get(ctx, "hash123")
	}
}

func BenchmarkMemoryStore_Create(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store := NewMemoryStore()
		key := &APIKey{ID: "key-1", KeyHash: "hash123"}
		store.Create(ctx, key)
	}
}

func BenchmarkStaticStore_ValidateRawKey(b *testing.B) {
	store := NewStaticStore([]string{"valid-key"}, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.ValidateRawKey("valid-key")
	}
}
