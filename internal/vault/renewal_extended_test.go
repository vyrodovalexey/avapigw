package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// TokenRenewalManager attemptRenewalWithRetries Tests
// ============================================================================

func TestTokenRenewalManager_AttemptRenewalWithRetries(t *testing.T) {
	t.Run("succeeds on first attempt", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/token/renew-self" {
				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "renewed-token",
						"renewable":      true,
						"lease_duration": 7200,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}
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

		// Set up authentication with token expiring soon
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(5 * time.Minute)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       3,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx := context.Background()
		success := manager.attemptRenewalWithRetries(ctx)

		assert.True(t, success)
	})

	t.Run("retries on failure and eventually succeeds", func(t *testing.T) {
		attemptCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/token/renew-self" {
				attemptCount++
				if attemptCount < 3 {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "renewed-token",
						"renewable":      true,
						"lease_duration": 7200,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}
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
		client.tokenExpiry = time.Now().Add(5 * time.Minute)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       5,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx := context.Background()
		success := manager.attemptRenewalWithRetries(ctx)

		assert.True(t, success)
		assert.GreaterOrEqual(t, attemptCount, 3)
	})

	t.Run("fails after max retries exhausted", func(t *testing.T) {
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
		client.tokenExpiry = time.Now().Add(5 * time.Minute)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       2,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx := context.Background()
		success := manager.attemptRenewalWithRetries(ctx)

		assert.False(t, success)
	})

	t.Run("respects context cancellation during retry", func(t *testing.T) {
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
		client.tokenExpiry = time.Now().Add(5 * time.Minute)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       10,
			RetryInterval:    500 * time.Millisecond, // Long retry interval
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx, cancel := context.WithCancel(context.Background())

		// Cancel after a short time
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		success := manager.attemptRenewalWithRetries(ctx)

		assert.False(t, success)
	})
}

// ============================================================================
// TokenRenewalManager attemptReauthentication Tests
// ============================================================================

func TestTokenRenewalManager_AttemptReauthentication(t *testing.T) {
	t.Run("successful reauthentication", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/token/lookup-self" {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"id":        "test-token",
						"ttl":       3600,
						"renewable": true,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}
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

		// Set up token auth
		tokenAuth, err := NewTokenAuth("test-token")
		require.NoError(t, err)
		client.SetAuthMethod(tokenAuth)

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       1,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx := context.Background()
		manager.attemptReauthentication(ctx)

		// Should be authenticated after reauthentication
		assert.True(t, client.IsAuthenticated())
	})

	t.Run("failed reauthentication", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			response := map[string]interface{}{
				"errors": []string{"permission denied"},
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

		// Set up token auth
		tokenAuth, err := NewTokenAuth("invalid-token")
		require.NoError(t, err)
		client.SetAuthMethod(tokenAuth)

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       1,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx := context.Background()
		// Should not panic
		manager.attemptReauthentication(ctx)
	})
}

// ============================================================================
// TokenRenewalManager waitForRetry Tests
// ============================================================================

func TestTokenRenewalManager_WaitForRetry(t *testing.T) {
	t.Run("returns true immediately for first attempt", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       3,
			RetryInterval:    100 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx := context.Background()
		start := time.Now()
		result := manager.waitForRetry(ctx, 0)
		elapsed := time.Since(start)

		assert.True(t, result)
		assert.Less(t, elapsed, 50*time.Millisecond) // Should return immediately
	})

	t.Run("waits for retry interval on subsequent attempts", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       3,
			RetryInterval:    50 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx := context.Background()
		start := time.Now()
		result := manager.waitForRetry(ctx, 1)
		elapsed := time.Since(start)

		assert.True(t, result)
		assert.GreaterOrEqual(t, elapsed, 40*time.Millisecond) // Should wait at least most of the interval
	})

	t.Run("returns false on context cancellation", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       3,
			RetryInterval:    1 * time.Second, // Long interval
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx, cancel := context.WithCancel(context.Background())

		// Cancel after a short time
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		result := manager.waitForRetry(ctx, 1)

		assert.False(t, result)
	})

	t.Run("returns false on stop channel close", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       3,
			RetryInterval:    1 * time.Second, // Long interval
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx := context.Background()

		// Stop after a short time
		go func() {
			time.Sleep(50 * time.Millisecond)
			manager.Stop()
		}()

		result := manager.waitForRetry(ctx, 1)

		assert.False(t, result)
	})
}

// ============================================================================
// TokenRenewalManager shouldRenewToken Tests
// ============================================================================

func TestTokenRenewalManager_ShouldRenewToken(t *testing.T) {
	t.Run("returns false for non-expiring token", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set token with zero expiry (non-expiring)
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Time{}
		client.mu.Unlock()

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       3,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		assert.False(t, manager.shouldRenewToken())
	})

	t.Run("returns false when token not near expiry", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set token expiring in 1 hour
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute, // Token is not within threshold
			MaxRetries:       3,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		assert.False(t, manager.shouldRenewToken())
	})

	t.Run("returns true when token near expiry", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set token expiring in 5 minutes
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(5 * time.Minute)
		client.mu.Unlock()

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute, // Token IS within threshold
			MaxRetries:       3,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		assert.True(t, manager.shouldRenewToken())
	})
}

// ============================================================================
// TokenRenewalManager checkAndRenew Tests
// ============================================================================

func TestTokenRenewalManager_CheckAndRenew(t *testing.T) {
	t.Run("skips renewal when token not near expiry", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set token expiring in 1 hour
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       3,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx := context.Background()
		// Should not panic and should return quickly
		manager.checkAndRenew(ctx)
	})

	t.Run("attempts renewal when token near expiry", func(t *testing.T) {
		renewalAttempted := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/token/renew-self" {
				renewalAttempted = true
				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "renewed-token",
						"renewable":      true,
						"lease_duration": 7200,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}
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

		// Set token expiring soon
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(5 * time.Minute)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		renewalConfig := &TokenRenewalConfig{
			RenewalInterval:  100 * time.Millisecond,
			RenewalThreshold: 10 * time.Minute,
			MaxRetries:       1,
			RetryInterval:    10 * time.Millisecond,
		}

		manager := NewTokenRenewalManager(client, renewalConfig, zap.NewNop())

		ctx := context.Background()
		manager.checkAndRenew(ctx)

		assert.True(t, renewalAttempted)
	})
}
