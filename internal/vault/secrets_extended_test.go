package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// SecretManager GetSecret Tests
// ============================================================================

func TestSecretManager_GetSecret_WithMockServer(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		serverHandler  http.HandlerFunc
		wantErr        bool
		errContains    string
		validateResult func(t *testing.T, secret *Secret)
	}{
		{
			name: "successful get secret",
			path: "secret/data/myapp",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/secret/data/myapp" {
					response := map[string]interface{}{
						"data": map[string]interface{}{
							"data": map[string]interface{}{
								"username": "admin",
								"password": "secret123",
							},
						},
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(response)
				}
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *Secret) {
				require.NotNil(t, secret)
				username, ok := secret.GetString("username")
				assert.True(t, ok)
				assert.Equal(t, "admin", username)
			},
		},
		{
			name: "get secret failure",
			path: "secret/data/nonexistent",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			config := &Config{
				Address:      server.URL,
				Timeout:      30 * time.Second,
				MaxRetries:   0,
				RetryWaitMin: 100 * time.Millisecond,
				RetryWaitMax: 1 * time.Second,
			}

			client, err := NewClient(config, zap.NewNop())
			require.NoError(t, err)

			// Set up authentication
			client.mu.Lock()
			client.token = "test-token"
			client.tokenExpiry = time.Now().Add(1 * time.Hour)
			client.mu.Unlock()
			client.vaultClient.SetToken("test-token")

			manager := NewSecretManager(client, zap.NewNop())

			ctx := context.Background()
			secret, err := manager.GetSecret(ctx, tt.path)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			if tt.validateResult != nil {
				tt.validateResult(t, secret)
			}
		})
	}
}

// ============================================================================
// SecretManager GetSecretWithCache Tests
// ============================================================================

func TestSecretManager_GetSecretWithCache(t *testing.T) {
	t.Run("returns cached secret on second call", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"key": "value",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		config := &Config{
			Address:      server.URL,
			Timeout:      30 * time.Second,
			MaxRetries:   0,
			RetryWaitMin: 100 * time.Millisecond,
			RetryWaitMax: 1 * time.Second,
		}

		client, err := NewClient(config, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		manager := NewSecretManager(client, zap.NewNop())

		ctx := context.Background()

		// First call - should hit the server
		secret1, err := manager.GetSecretWithCache(ctx, "secret/data/test", 5*time.Minute)
		require.NoError(t, err)
		require.NotNil(t, secret1)
		assert.Equal(t, 1, callCount)

		// Second call - should return cached value
		secret2, err := manager.GetSecretWithCache(ctx, "secret/data/test", 5*time.Minute)
		require.NoError(t, err)
		require.NotNil(t, secret2)
		assert.Equal(t, 1, callCount) // Server should not be called again
	})

	t.Run("fetches from vault when cache miss", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"username": "admin",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		config := &Config{
			Address:      server.URL,
			Timeout:      30 * time.Second,
			MaxRetries:   0,
			RetryWaitMin: 100 * time.Millisecond,
			RetryWaitMax: 1 * time.Second,
		}

		client, err := NewClient(config, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		manager := NewSecretManager(client, zap.NewNop())

		ctx := context.Background()
		secret, err := manager.GetSecretWithCache(ctx, "secret/data/newpath", 5*time.Minute)
		require.NoError(t, err)
		require.NotNil(t, secret)

		username, ok := secret.GetString("username")
		assert.True(t, ok)
		assert.Equal(t, "admin", username)
	})

	t.Run("returns error when vault fetch fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		config := &Config{
			Address:      server.URL,
			Timeout:      30 * time.Second,
			MaxRetries:   0,
			RetryWaitMin: 100 * time.Millisecond,
			RetryWaitMax: 1 * time.Second,
		}

		client, err := NewClient(config, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		manager := NewSecretManager(client, zap.NewNop())

		ctx := context.Background()
		_, err = manager.GetSecretWithCache(ctx, "secret/data/error", 5*time.Minute)
		require.Error(t, err)
	})
}

// ============================================================================
// SecretManager WatchSecret Tests
// ============================================================================

func TestSecretManager_WatchSecret(t *testing.T) {
	t.Run("starts watching a secret", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"key": "value",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		config := &Config{
			Address:      server.URL,
			Timeout:      30 * time.Second,
			MaxRetries:   0,
			RetryWaitMin: 100 * time.Millisecond,
			RetryWaitMax: 1 * time.Second,
		}

		client, err := NewClient(config, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		manager := NewSecretManager(client, zap.NewNop())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		callbackCalled := make(chan struct{}, 1)
		callback := func(secret *Secret, err error) {
			select {
			case callbackCalled <- struct{}{}:
			default:
			}
		}

		err = manager.WatchSecret(ctx, "secret/data/test", 100*time.Millisecond, callback)
		require.NoError(t, err)

		// Verify the path is being watched
		paths := manager.GetWatchedPaths()
		assert.Contains(t, paths, "secret/data/test")

		// Wait for callback to be called
		select {
		case <-callbackCalled:
			// Good - callback was called
		case <-time.After(500 * time.Millisecond):
			// Timeout is acceptable - the watcher may not have triggered yet
		}

		// Stop watching
		manager.StopWatching("secret/data/test")
		paths = manager.GetWatchedPaths()
		assert.NotContains(t, paths, "secret/data/test")
	})

	t.Run("does not duplicate watchers for same path", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"key": "value",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		config := &Config{
			Address:      server.URL,
			Timeout:      30 * time.Second,
			MaxRetries:   0,
			RetryWaitMin: 100 * time.Millisecond,
			RetryWaitMax: 1 * time.Second,
		}

		client, err := NewClient(config, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		manager := NewSecretManager(client, zap.NewNop())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		callback := func(secret *Secret, err error) {}

		// Start watching the same path twice
		err = manager.WatchSecret(ctx, "secret/data/test", 100*time.Millisecond, callback)
		require.NoError(t, err)

		err = manager.WatchSecret(ctx, "secret/data/test", 100*time.Millisecond, callback)
		require.NoError(t, err)

		// Should only have one watcher
		paths := manager.GetWatchedPaths()
		assert.Len(t, paths, 1)

		manager.StopAllWatchers()
	})
}

// ============================================================================
// SecretManager StopWatching Tests
// ============================================================================

func TestSecretManager_StopWatching(t *testing.T) {
	t.Run("stops watching a specific path", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		manager := NewSecretManager(client, zap.NewNop())

		// Manually add watchers for testing
		manager.mu.Lock()
		manager.watchers["path1"] = NewSecretWatcher("path1", time.Minute, nil, nil)
		manager.watchers["path2"] = NewSecretWatcher("path2", time.Minute, nil, nil)
		manager.mu.Unlock()

		// Stop watching path1
		manager.StopWatching("path1")

		paths := manager.GetWatchedPaths()
		assert.NotContains(t, paths, "path1")
		assert.Contains(t, paths, "path2")
	})

	t.Run("does nothing for non-existent path", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		manager := NewSecretManager(client, zap.NewNop())

		// Should not panic
		manager.StopWatching("nonexistent/path")

		paths := manager.GetWatchedPaths()
		assert.Empty(t, paths)
	})
}

// ============================================================================
// SecretManager StopAllWatchers Tests
// ============================================================================

func TestSecretManager_StopAllWatchers(t *testing.T) {
	t.Run("stops all watchers", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		manager := NewSecretManager(client, zap.NewNop())

		// Manually add watchers for testing
		manager.mu.Lock()
		manager.watchers["path1"] = NewSecretWatcher("path1", time.Minute, nil, nil)
		manager.watchers["path2"] = NewSecretWatcher("path2", time.Minute, nil, nil)
		manager.watchers["path3"] = NewSecretWatcher("path3", time.Minute, nil, nil)
		manager.mu.Unlock()

		assert.Len(t, manager.GetWatchedPaths(), 3)

		manager.StopAllWatchers()

		assert.Empty(t, manager.GetWatchedPaths())
	})
}

// ============================================================================
// SecretManager GetWatchedPaths Tests
// ============================================================================

func TestSecretManager_GetWatchedPaths_Concurrent(t *testing.T) {
	client, err := NewClient(nil, zap.NewNop())
	require.NoError(t, err)

	manager := NewSecretManager(client, zap.NewNop())

	// Add some watchers
	manager.mu.Lock()
	manager.watchers["path1"] = NewSecretWatcher("path1", time.Minute, nil, nil)
	manager.watchers["path2"] = NewSecretWatcher("path2", time.Minute, nil, nil)
	manager.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			paths := manager.GetWatchedPaths()
			assert.Len(t, paths, 2)
		}()
	}
	wg.Wait()
}
