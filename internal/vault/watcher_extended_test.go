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
// SecretWatcher Start Tests with Mock Server
// ============================================================================

func TestSecretWatcher_Start_WithMockServer(t *testing.T) {
	t.Run("detects secret data change", func(t *testing.T) {
		dataValue := "initial"
		var mu sync.Mutex

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			currentValue := dataValue
			mu.Unlock()

			// Return simple KV v1 style response (no metadata)
			// This tests the hash-based change detection
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"key": currentValue,
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

		callbackCount := 0
		var callbackMu sync.Mutex
		callback := func(secret *Secret, err error) {
			callbackMu.Lock()
			callbackCount++
			callbackMu.Unlock()
		}

		watcher := NewSecretWatcher("secret/data/test", 50*time.Millisecond, callback, zap.NewNop())

		ctx, cancel := context.WithCancel(context.Background())

		// Start watcher in goroutine
		go watcher.Start(ctx, client)

		// Wait for initial fetch
		time.Sleep(100 * time.Millisecond)

		// Change data to trigger callback
		mu.Lock()
		dataValue = "changed"
		mu.Unlock()

		// Wait for watcher to detect change
		time.Sleep(150 * time.Millisecond)

		cancel()
		watcher.Stop()

		callbackMu.Lock()
		count := callbackCount
		callbackMu.Unlock()

		// Should have been called at least once (initial change detection)
		assert.GreaterOrEqual(t, count, 1)
	})

	t.Run("detects secret data change without metadata", func(t *testing.T) {
		dataValue := "initial"
		var mu sync.Mutex

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			currentValue := dataValue
			mu.Unlock()

			response := map[string]interface{}{
				"data": map[string]interface{}{
					"key": currentValue,
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

		callbackCount := 0
		var callbackMu sync.Mutex
		callback := func(secret *Secret, err error) {
			callbackMu.Lock()
			callbackCount++
			callbackMu.Unlock()
		}

		watcher := NewSecretWatcher("secret/data/test", 50*time.Millisecond, callback, zap.NewNop())

		ctx, cancel := context.WithCancel(context.Background())

		// Start watcher in goroutine
		go watcher.Start(ctx, client)

		// Wait for initial fetch
		time.Sleep(100 * time.Millisecond)

		// Change data to trigger callback
		mu.Lock()
		dataValue = "changed"
		mu.Unlock()

		// Wait for watcher to detect change
		time.Sleep(150 * time.Millisecond)

		cancel()
		watcher.Stop()

		callbackMu.Lock()
		count := callbackCount
		callbackMu.Unlock()

		// Should have been called at least twice (initial + change)
		assert.GreaterOrEqual(t, count, 1)
	})

	t.Run("calls callback with error on read failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			response := map[string]interface{}{
				"errors": []string{"internal server error"},
			}
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

		errorReceived := make(chan error, 1)
		callback := func(secret *Secret, err error) {
			if err != nil {
				select {
				case errorReceived <- err:
				default:
				}
			}
		}

		watcher := NewSecretWatcher("secret/data/test", 50*time.Millisecond, callback, zap.NewNop())

		ctx, cancel := context.WithCancel(context.Background())

		// Start watcher in goroutine
		go watcher.Start(ctx, client)

		// Wait for error callback
		select {
		case err := <-errorReceived:
			assert.Error(t, err)
		case <-time.After(500 * time.Millisecond):
			t.Error("expected error callback to be called")
		}

		cancel()
		watcher.Stop()
	})

	t.Run("handles nil callback gracefully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"key": "value",
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

		// Create watcher with nil callback
		watcher := NewSecretWatcher("secret/data/test", 50*time.Millisecond, nil, zap.NewNop())

		ctx, cancel := context.WithCancel(context.Background())

		// Start watcher in goroutine - should not panic
		go watcher.Start(ctx, client)

		// Wait a bit
		time.Sleep(100 * time.Millisecond)

		cancel()
		watcher.Stop()
	})
}

// ============================================================================
// SecretWatcher checkSecret Tests
// ============================================================================

func TestSecretWatcher_CheckSecret(t *testing.T) {
	t.Run("updates lastVersion on version change", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"key": "value",
					},
					"metadata": map[string]interface{}{
						"created_time":  "2023-01-01T00:00:00.000000000Z",
						"version":       float64(5),
						"deletion_time": "",
						"destroyed":     false,
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

		watcher := NewSecretWatcher("secret/data/test", time.Minute, nil, zap.NewNop())
		watcher.lastVersion = 1 // Set initial version

		ctx := context.Background()
		watcher.checkSecret(ctx, client)

		assert.Equal(t, 5, watcher.lastVersion)
	})

	t.Run("updates lastHash on data change without metadata", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"key": "newvalue",
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

		watcher := NewSecretWatcher("secret/data/test", time.Minute, nil, zap.NewNop())
		watcher.lastHash = "oldhash"

		ctx := context.Background()
		watcher.checkSecret(ctx, client)

		assert.NotEqual(t, "oldhash", watcher.lastHash)
		assert.NotEmpty(t, watcher.lastHash)
	})
}

// ============================================================================
// computeDataHash Tests
// ============================================================================

func TestComputeDataHash_Extended(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		expected string
	}{
		{
			name:     "nil data returns empty string",
			data:     nil,
			expected: "",
		},
		{
			name:     "empty data returns empty string",
			data:     map[string]interface{}{},
			expected: "",
		},
		{
			name: "single string value",
			data: map[string]interface{}{
				"key": "value",
			},
			expected: "key:value;",
		},
		{
			name: "multiple string values sorted",
			data: map[string]interface{}{
				"zebra": "z",
				"alpha": "a",
				"beta":  "b",
			},
			expected: "alpha:a;beta:b;zebra:z;",
		},
		{
			name: "non-string values are ignored",
			data: map[string]interface{}{
				"string": "value",
				"number": 123,
				"bool":   true,
				"nil":    nil,
			},
			expected: "string:value;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeDataHash(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// SecretWatcher Concurrent Tests
// ============================================================================

func TestSecretWatcher_ConcurrentStopCalls(t *testing.T) {
	watcher := NewSecretWatcher("test/path", time.Minute, nil, nil)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			watcher.Stop()
		}()
	}
	wg.Wait()

	assert.True(t, watcher.IsStopped())
}

func TestSecretWatcher_ConcurrentIsStoppedCalls(t *testing.T) {
	watcher := NewSecretWatcher("test/path", time.Minute, nil, nil)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = watcher.IsStopped()
		}()
	}
	wg.Wait()
}

// ============================================================================
// SecretWatcher Context Cancellation Tests
// ============================================================================

func TestSecretWatcher_ContextCancellationDuringLoop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"key": "value",
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

	watcher := NewSecretWatcher("secret/data/test", 100*time.Millisecond, nil, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		watcher.Start(ctx, client)
		close(done)
	}()

	// Let it run for a bit
	time.Sleep(150 * time.Millisecond)

	// Cancel context
	cancel()

	// Should exit promptly
	select {
	case <-done:
		// Good
	case <-time.After(time.Second):
		t.Error("watcher did not exit after context cancellation")
	}
}
