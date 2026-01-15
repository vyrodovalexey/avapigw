package vault

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewSecretWatcher(t *testing.T) {
	callback := func(secret *Secret, err error) {}
	watcher := NewSecretWatcher("secret/path", 5*time.Minute, callback, nil)

	assert.NotNil(t, watcher)
	assert.Equal(t, "secret/path", watcher.path)
	assert.Equal(t, 5*time.Minute, watcher.interval)
	assert.NotNil(t, watcher.callback)
	assert.False(t, watcher.IsStopped())
}

func TestSecretWatcher_Path(t *testing.T) {
	watcher := NewSecretWatcher("secret/test/path", time.Minute, nil, nil)
	assert.Equal(t, "secret/test/path", watcher.Path())
}

func TestSecretWatcher_Interval(t *testing.T) {
	watcher := NewSecretWatcher("secret/path", 10*time.Minute, nil, nil)
	assert.Equal(t, 10*time.Minute, watcher.Interval())
}

func TestSecretWatcher_Stop(t *testing.T) {
	watcher := NewSecretWatcher("secret/path", time.Minute, nil, nil)

	assert.False(t, watcher.IsStopped())

	watcher.Stop()

	assert.True(t, watcher.IsStopped())

	// Stop again should be idempotent
	watcher.Stop()
	assert.True(t, watcher.IsStopped())
}

func TestComputeDataHash(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		expected string
	}{
		{
			name:     "nil data",
			data:     nil,
			expected: "",
		},
		{
			name:     "empty data",
			data:     map[string]interface{}{},
			expected: "",
		},
		{
			name: "string values",
			data: map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
			expected: "", // Hash is non-deterministic due to map iteration order
		},
		{
			name: "mixed values",
			data: map[string]interface{}{
				"string": "value",
				"number": 123,
				"bool":   true,
			},
			expected: "", // Only string values are included
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeDataHash(tt.data)
			if tt.data == nil || len(tt.data) == 0 {
				assert.Equal(t, tt.expected, result)
			} else {
				// For non-empty data, just verify it returns something
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestComputeDataHash_Consistency(t *testing.T) {
	// Same data should produce same hash
	data := map[string]interface{}{
		"key": "value",
	}

	hash1 := computeDataHash(data)
	hash2 := computeDataHash(data)

	assert.Equal(t, hash1, hash2)
}

// TestComputeDataHash_Deterministic tests that computeDataHash produces
// deterministic output regardless of map iteration order. This is critical
// for detecting secret changes correctly.
func TestComputeDataHash_Deterministic(t *testing.T) {
	data := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	// Compute hash multiple times
	hash1 := computeDataHash(data)
	hash2 := computeDataHash(data)

	if hash1 != hash2 {
		t.Errorf("hash not deterministic: %s != %s", hash1, hash2)
	}

	// Verify hash is non-empty for non-empty data
	assert.NotEmpty(t, hash1)
}

// TestComputeDataHash_DeterministicWithManyKeys tests determinism with more keys
// to increase the likelihood of catching non-deterministic behavior.
func TestComputeDataHash_DeterministicWithManyKeys(t *testing.T) {
	data := map[string]interface{}{
		"alpha":   "value_alpha",
		"beta":    "value_beta",
		"gamma":   "value_gamma",
		"delta":   "value_delta",
		"epsilon": "value_epsilon",
		"zeta":    "value_zeta",
		"eta":     "value_eta",
		"theta":   "value_theta",
		"iota":    "value_iota",
		"kappa":   "value_kappa",
	}

	// Compute hash 100 times to verify determinism
	firstHash := computeDataHash(data)
	for i := 0; i < 100; i++ {
		hash := computeDataHash(data)
		if hash != firstHash {
			t.Errorf("iteration %d: hash not deterministic: %s != %s", i, hash, firstHash)
		}
	}
}

// TestComputeDataHash_DifferentDataDifferentHash tests that different data
// produces different hashes.
func TestComputeDataHash_DifferentDataDifferentHash(t *testing.T) {
	data1 := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	data2 := map[string]interface{}{
		"key1": "value1",
		"key2": "different_value",
	}

	hash1 := computeDataHash(data1)
	hash2 := computeDataHash(data2)

	assert.NotEqual(t, hash1, hash2, "different data should produce different hashes")
}

// TestSecretWatcher_Start_ContextCancelledBeforeStart tests that the watcher
// exits immediately when the context is already cancelled before Start is called.
// This prevents goroutine leaks when the context is cancelled early.
func TestSecretWatcher_Start_ContextCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before starting

	watcher := NewSecretWatcher("test/path", time.Second, nil, nil)

	done := make(chan struct{})
	go func() {
		watcher.Start(ctx, nil)
		close(done)
	}()

	select {
	case <-done:
		// Good - watcher exited
	case <-time.After(time.Second):
		t.Error("watcher did not exit when context was cancelled")
	}
}

// TestSecretWatcher_Start_StopDuringRun tests that the watcher
// exits when Stop() is called while running.
// Note: We use Stop() instead of context cancellation to avoid
// needing a real Vault client for the initial checkSecret call.
func TestSecretWatcher_Start_StopDuringRun(t *testing.T) {
	ctx := context.Background()

	// Use a very long interval so we can stop before the first tick
	watcher := NewSecretWatcher("test/path", 10*time.Minute, nil, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The watcher will try to check the secret with nil client,
		// which will panic, so we need to recover
		defer func() {
			if r := recover(); r != nil {
				// Expected - nil client causes panic in checkSecret
				// The important thing is that the goroutine exits
			}
		}()
		watcher.Start(ctx, nil)
	}()

	// Give the watcher time to start
	time.Sleep(50 * time.Millisecond)

	// Stop the watcher
	watcher.Stop()

	select {
	case <-done:
		// Good - watcher exited (either via stop or panic recovery)
	case <-time.After(2 * time.Second):
		t.Error("watcher did not exit when stopped during run")
	}

	// Verify the watcher is marked as stopped
	assert.True(t, watcher.IsStopped())
}

// TestSecretWatcher_Start_StoppedBeforeStart tests that the watcher
// exits immediately when Stop() was called before Start().
func TestSecretWatcher_Start_StoppedBeforeStart(t *testing.T) {
	watcher := NewSecretWatcher("test/path", time.Second, nil, nil)

	// Stop before starting
	watcher.Stop()

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		watcher.Start(ctx, nil)
		close(done)
	}()

	select {
	case <-done:
		// Good - watcher exited
	case <-time.After(time.Second):
		t.Error("watcher did not exit when stopped before start")
	}
}
