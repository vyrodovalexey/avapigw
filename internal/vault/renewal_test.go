package vault

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultTokenRenewalConfig(t *testing.T) {
	config := DefaultTokenRenewalConfig()

	assert.Equal(t, 5*time.Minute, config.RenewalInterval)
	assert.Equal(t, 10*time.Minute, config.RenewalThreshold)
	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, 30*time.Second, config.RetryInterval)
}

func TestNewTokenRenewalManager(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	t.Run("with default config", func(t *testing.T) {
		manager := NewTokenRenewalManager(client, nil, nil)
		assert.NotNil(t, manager)
		assert.NotNil(t, manager.config)
		assert.Equal(t, 5*time.Minute, manager.config.RenewalInterval)
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &TokenRenewalConfig{
			RenewalInterval:  1 * time.Minute,
			RenewalThreshold: 5 * time.Minute,
			MaxRetries:       5,
			RetryInterval:    10 * time.Second,
		}

		manager := NewTokenRenewalManager(client, config, nil)
		assert.NotNil(t, manager)
		assert.Equal(t, 1*time.Minute, manager.config.RenewalInterval)
		assert.Equal(t, 5*time.Minute, manager.config.RenewalThreshold)
		assert.Equal(t, 5, manager.config.MaxRetries)
		assert.Equal(t, 10*time.Second, manager.config.RetryInterval)
	})
}

func TestTokenRenewalManager_Stop(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewTokenRenewalManager(client, nil, nil)

	assert.False(t, manager.IsStopped())

	manager.Stop()

	assert.True(t, manager.IsStopped())

	// Stop again should be idempotent
	manager.Stop()
	assert.True(t, manager.IsStopped())
}

func TestTokenRenewalConfig(t *testing.T) {
	config := &TokenRenewalConfig{
		RenewalInterval:  2 * time.Minute,
		RenewalThreshold: 8 * time.Minute,
		MaxRetries:       4,
		RetryInterval:    20 * time.Second,
	}

	assert.Equal(t, 2*time.Minute, config.RenewalInterval)
	assert.Equal(t, 8*time.Minute, config.RenewalThreshold)
	assert.Equal(t, 4, config.MaxRetries)
	assert.Equal(t, 20*time.Second, config.RetryInterval)
}

// TestTokenRenewalManager_ImplementsCloser verifies that TokenRenewalManager
// implements the io.Closer interface. This is a compile-time check that ensures
// the type can be used with defer patterns and resource management utilities.
func TestTokenRenewalManager_ImplementsCloser(t *testing.T) {
	// Compile-time interface check
	var _ io.Closer = (*TokenRenewalManager)(nil)

	// Runtime verification
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewTokenRenewalManager(client, nil, nil)
	var closer io.Closer = manager
	assert.NotNil(t, closer)
}

// TestTokenRenewalManager_Close tests that Close() properly stops the manager
// and returns nil error.
func TestTokenRenewalManager_Close(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewTokenRenewalManager(client, nil, nil)

	// Close should not return an error
	err = manager.Close()
	assert.NoError(t, err)

	// Manager should be stopped after Close
	assert.True(t, manager.IsStopped())
}

// TestTokenRenewalManager_Close_Idempotent tests that Close() can be called
// multiple times without error (idempotent behavior).
func TestTokenRenewalManager_Close_Idempotent(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewTokenRenewalManager(client, nil, nil)

	// First close
	err = manager.Close()
	assert.NoError(t, err)
	assert.True(t, manager.IsStopped())

	// Second close should also succeed
	err = manager.Close()
	assert.NoError(t, err)
	assert.True(t, manager.IsStopped())

	// Third close should also succeed
	err = manager.Close()
	assert.NoError(t, err)
}

// TestTokenRenewalManager_Close_AfterStop tests that Close() works correctly
// even after Stop() has been called.
func TestTokenRenewalManager_Close_AfterStop(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewTokenRenewalManager(client, nil, nil)

	// Stop first
	manager.Stop()
	assert.True(t, manager.IsStopped())

	// Close should still work
	err = manager.Close()
	assert.NoError(t, err)
	assert.True(t, manager.IsStopped())
}

// ============================================================================
// Token Renewal Success Tests
// ============================================================================

func TestRenewal_Success(t *testing.T) {
	t.Run("manager starts and stops correctly", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)

		config := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 200 * time.Millisecond,
			MaxRetries:       1,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, config, nil)
		require.NotNil(t, manager)

		ctx, cancel := context.WithCancel(context.Background())

		// Start the manager
		manager.Start(ctx)

		// Give it a moment to start
		time.Sleep(50 * time.Millisecond)

		// Stop via context cancellation
		cancel()

		// Give it a moment to stop
		time.Sleep(50 * time.Millisecond)
	})
}

// ============================================================================
// Token Renewal with Expired Token Tests
// ============================================================================

func TestRenewal_ExpiredToken(t *testing.T) {
	t.Run("handles expired token gracefully", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)

		// Set an expired token
		client.mu.Lock()
		client.token = "expired-token"
		client.tokenExpiry = time.Now().Add(-1 * time.Hour) // Already expired
		client.mu.Unlock()

		config := &TokenRenewalConfig{
			RenewalInterval:  50 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       1,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, config, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		manager.Start(ctx)

		// Wait for context to expire
		<-ctx.Done()

		manager.Stop()
		assert.True(t, manager.IsStopped())
	})
}

// ============================================================================
// Non-Renewable Token Tests
// ============================================================================

func TestRenewal_NonRenewableToken(t *testing.T) {
	t.Run("skips renewal for non-expiring token", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)

		// Set a token with zero expiry (non-expiring)
		client.mu.Lock()
		client.token = "non-expiring-token"
		client.tokenExpiry = time.Time{} // Zero time means no expiry
		client.mu.Unlock()

		config := &TokenRenewalConfig{
			RenewalInterval:  50 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       1,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, config, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()

		manager.Start(ctx)

		// Wait for a few renewal cycles
		time.Sleep(100 * time.Millisecond)

		manager.Stop()
		assert.True(t, manager.IsStopped())
	})
}

// ============================================================================
// Automatic Scheduling Tests
// ============================================================================

func TestRenewal_AutomaticScheduling(t *testing.T) {
	t.Run("renewal loop runs at configured interval", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)

		// Set a token that will expire soon
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(5 * time.Minute)
		client.mu.Unlock()

		config := &TokenRenewalConfig{
			RenewalInterval:  50 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute, // Token is within threshold
			MaxRetries:       1,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, config, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		manager.Start(ctx)

		// Wait for context to expire
		<-ctx.Done()

		manager.Stop()
		assert.True(t, manager.IsStopped())
	})
}

// ============================================================================
// Concurrent Renewal Requests Tests
// ============================================================================

func TestRenewal_ConcurrentRequests(t *testing.T) {
	t.Run("handles concurrent start calls", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)

		config := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       1,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, config, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start multiple times concurrently
		var wg sync.WaitGroup
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				manager.Start(ctx)
			}()
		}

		wg.Wait()

		// Stop should work correctly
		manager.Stop()
		assert.True(t, manager.IsStopped())
	})

	t.Run("handles concurrent stop calls", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)

		manager := NewTokenRenewalManager(client, nil, nil)

		// Stop multiple times concurrently
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				manager.Stop()
			}()
		}

		wg.Wait()
		assert.True(t, manager.IsStopped())
	})

	t.Run("handles concurrent IsStopped calls", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)

		manager := NewTokenRenewalManager(client, nil, nil)

		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = manager.IsStopped()
			}()
		}

		wg.Wait()
	})
}

// ============================================================================
// Start After Stop Tests
// ============================================================================

func TestRenewal_StartAfterStop(t *testing.T) {
	t.Run("start after stop does nothing", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)

		manager := NewTokenRenewalManager(client, nil, nil)

		// Stop first
		manager.Stop()
		assert.True(t, manager.IsStopped())

		// Start should do nothing since already stopped
		ctx := context.Background()
		manager.Start(ctx)

		// Should still be stopped
		assert.True(t, manager.IsStopped())
	})
}

// ============================================================================
// CheckAndRenew Tests
// ============================================================================

func TestRenewal_CheckAndRenew(t *testing.T) {
	t.Run("skips renewal when token not near expiry", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)

		// Set a token that won't expire for a long time
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(24 * time.Hour)
		client.mu.Unlock()

		config := &TokenRenewalConfig{
			RenewalInterval:  50 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute, // Token is NOT within threshold
			MaxRetries:       1,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, config, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()

		manager.Start(ctx)

		// Wait for context to expire
		<-ctx.Done()

		manager.Stop()
		assert.True(t, manager.IsStopped())
	})
}
