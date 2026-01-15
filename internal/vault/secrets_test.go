package vault

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecret_GetString(t *testing.T) {
	tests := []struct {
		name     string
		secret   *Secret
		key      string
		expected string
		ok       bool
	}{
		{
			name:     "nil secret",
			secret:   nil,
			key:      "key",
			expected: "",
			ok:       false,
		},
		{
			name: "nil data",
			secret: &Secret{
				Data: nil,
			},
			key:      "key",
			expected: "",
			ok:       false,
		},
		{
			name: "key exists",
			secret: &Secret{
				Data: map[string]interface{}{
					"key": "value",
				},
			},
			key:      "key",
			expected: "value",
			ok:       true,
		},
		{
			name: "key not found",
			secret: &Secret{
				Data: map[string]interface{}{
					"other": "value",
				},
			},
			key:      "key",
			expected: "",
			ok:       false,
		},
		{
			name: "non-string value",
			secret: &Secret{
				Data: map[string]interface{}{
					"key": 123,
				},
			},
			key:      "key",
			expected: "",
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := tt.secret.GetString(tt.key)
			assert.Equal(t, tt.expected, result)
			assert.Equal(t, tt.ok, ok)
		})
	}
}

func TestSecret_GetBytes(t *testing.T) {
	tests := []struct {
		name     string
		secret   *Secret
		key      string
		expected []byte
		ok       bool
	}{
		{
			name:     "nil secret",
			secret:   nil,
			key:      "key",
			expected: nil,
			ok:       false,
		},
		{
			name: "key exists",
			secret: &Secret{
				Data: map[string]interface{}{
					"key": "value",
				},
			},
			key:      "key",
			expected: []byte("value"),
			ok:       true,
		},
		{
			name: "key not found",
			secret: &Secret{
				Data: map[string]interface{}{},
			},
			key:      "key",
			expected: nil,
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := tt.secret.GetBytes(tt.key)
			assert.Equal(t, tt.expected, result)
			assert.Equal(t, tt.ok, ok)
		})
	}
}

func TestNewSecretManager(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewSecretManager(client, nil)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.client)
	assert.NotNil(t, manager.cache)
	assert.NotNil(t, manager.watchers)
}

func TestSecretManager_GetWatchedPaths(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewSecretManager(client, nil)

	// Initially empty
	paths := manager.GetWatchedPaths()
	assert.Empty(t, paths)
}

func TestSecretManager_InvalidateCache(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewSecretManager(client, nil)

	// Add to cache
	manager.cache.Set("test/path", &Secret{
		Data: map[string]interface{}{"key": "value"},
	})

	// Verify it's cached
	_, ok := manager.cache.Get("test/path")
	assert.True(t, ok)

	// Invalidate
	manager.InvalidateCache("test/path")

	// Verify it's gone
	_, ok = manager.cache.Get("test/path")
	assert.False(t, ok)
}

func TestSecretManager_ClearCache(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewSecretManager(client, nil)

	// Add multiple entries to cache
	manager.cache.Set("path1", &Secret{})
	manager.cache.Set("path2", &Secret{})
	manager.cache.Set("path3", &Secret{})

	assert.Equal(t, 3, manager.cache.Size())

	// Clear
	manager.ClearCache()

	assert.Equal(t, 0, manager.cache.Size())
}

func TestSecretManager_Close(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewSecretManager(client, nil)

	// Add to cache
	manager.cache.Set("test/path", &Secret{})

	// Close
	err = manager.Close()
	assert.NoError(t, err)

	// Cache should be cleared
	assert.Equal(t, 0, manager.cache.Size())
}

func TestSecretMetadata(t *testing.T) {
	now := time.Now()
	deletedTime := now.Add(-1 * time.Hour)

	metadata := &SecretMetadata{
		CreatedTime: now,
		Version:     5,
		DeletedTime: &deletedTime,
		Destroyed:   false,
	}

	assert.Equal(t, now, metadata.CreatedTime)
	assert.Equal(t, 5, metadata.Version)
	assert.NotNil(t, metadata.DeletedTime)
	assert.Equal(t, deletedTime, *metadata.DeletedTime)
	assert.False(t, metadata.Destroyed)
}
