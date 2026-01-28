package vault

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNew_NilConfig(t *testing.T) {
	logger := observability.NopLogger()
	_, err := New(nil, logger)
	if err == nil {
		t.Error("New() should return error for nil config")
	}
	if !errors.Is(err, &ConfigurationError{}) {
		t.Errorf("New() error = %v, want ConfigurationError", err)
	}
}

func TestNew_DisabledConfig(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled: false,
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Errorf("New() error = %v, want nil", err)
	}
	if client == nil {
		t.Fatal("New() returned nil client")
	}
	if client.IsEnabled() {
		t.Error("IsEnabled() should return false for disabled config")
	}
}

func TestNew_InvalidConfig(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		AuthMethod: AuthMethodToken,
		// Missing Address and Token
	}

	_, err := New(cfg, logger)
	if err == nil {
		t.Error("New() should return error for invalid config")
	}
}

func TestNew_ValidTokenConfig(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Errorf("New() error = %v, want nil", err)
	}
	if client == nil {
		t.Fatal("New() returned nil client")
	}
	if !client.IsEnabled() {
		t.Error("IsEnabled() should return true for enabled config")
	}

	// Clean up
	_ = client.Close()
}

func TestNew_WithCacheConfig(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     10 * time.Minute,
			MaxSize: 500,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Errorf("New() error = %v, want nil", err)
	}
	if client == nil {
		t.Fatal("New() returned nil client")
	}

	// Verify cache was initialized
	vc, ok := client.(*vaultClient)
	if !ok {
		t.Fatal("client should be *vaultClient")
	}
	if vc.cache == nil {
		t.Error("cache should be initialized")
	}

	_ = client.Close()
}

func TestNew_WithRetryConfig(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		Retry: &RetryConfig{
			MaxRetries:  5,
			BackoffBase: 200 * time.Millisecond,
			BackoffMax:  10 * time.Second,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Errorf("New() error = %v, want nil", err)
	}
	if client == nil {
		t.Fatal("New() returned nil client")
	}

	_ = client.Close()
}

func TestNew_WithMetrics(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	metrics := NewMetrics("test")
	client, err := New(cfg, logger, WithMetrics(metrics))
	if err != nil {
		t.Errorf("New() error = %v, want nil", err)
	}
	if client == nil {
		t.Fatal("New() returned nil client")
	}

	vc, ok := client.(*vaultClient)
	if !ok {
		t.Fatal("client should be *vaultClient")
	}
	if vc.metrics != metrics {
		t.Error("metrics should be the provided metrics")
	}

	_ = client.Close()
}

func TestNew_WithNamespace(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		Namespace:  "test-namespace",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Errorf("New() error = %v, want nil", err)
	}
	if client == nil {
		t.Fatal("New() returned nil client")
	}

	_ = client.Close()
}

func TestVaultClient_PKI(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout waiting for stoppedCh
	// In production, Authenticate() would be called first which starts the renewal loop

	pki := client.PKI()
	if pki == nil {
		t.Error("PKI() should not return nil")
	}
}

func TestVaultClient_KV(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	kv := client.KV()
	if kv == nil {
		t.Error("KV() should not return nil")
	}
}

func TestVaultClient_Transit(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	transit := client.Transit()
	if transit == nil {
		t.Error("Transit() should not return nil")
	}
}

func TestVaultClient_Close_Idempotent(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// First close
	err = client.Close()
	if err != nil {
		t.Errorf("First Close() error = %v", err)
	}

	// Second close should not error
	err = client.Close()
	if err != nil {
		t.Errorf("Second Close() error = %v", err)
	}
}

func TestVaultClient_Authenticate_Closed(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_ = client.Close()

	err = client.Authenticate(context.Background())
	if !errors.Is(err, ErrClientClosed) {
		t.Errorf("Authenticate() error = %v, want ErrClientClosed", err)
	}
}

func TestVaultClient_RenewToken_Closed(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_ = client.Close()

	err = client.RenewToken(context.Background())
	if !errors.Is(err, ErrClientClosed) {
		t.Errorf("RenewToken() error = %v, want ErrClientClosed", err)
	}
}

func TestVaultClient_Health_Closed(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_ = client.Close()

	_, err = client.Health(context.Background())
	if !errors.Is(err, ErrClientClosed) {
		t.Errorf("Health() error = %v, want ErrClientClosed", err)
	}
}

func TestVaultClient_GetRetryConfig(t *testing.T) {
	logger := observability.NopLogger()

	t.Run("with retry config", func(t *testing.T) {
		cfg := &Config{
			Enabled:    true,
			Address:    "http://localhost:8200",
			AuthMethod: AuthMethodToken,
			Token:      "test-token",
			Retry: &RetryConfig{
				MaxRetries: 5,
			},
		}

		client, err := New(cfg, logger)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		// Note: Not calling Close() to avoid 5s timeout

		vc := client.(*vaultClient)
		retryCfg := vc.getRetryConfig()
		if retryCfg.MaxRetries != 5 {
			t.Errorf("MaxRetries = %v, want 5", retryCfg.MaxRetries)
		}
	})

	t.Run("without retry config", func(t *testing.T) {
		cfg := &Config{
			Enabled:    true,
			Address:    "http://localhost:8200",
			AuthMethod: AuthMethodToken,
			Token:      "test-token",
		}

		client, err := New(cfg, logger)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		// Note: Not calling Close() to avoid 5s timeout

		vc := client.(*vaultClient)
		retryCfg := vc.getRetryConfig()
		if retryCfg == nil {
			t.Error("getRetryConfig() should return default config")
		}
	})
}

// Test disabled client implementations
func TestDisabledClient(t *testing.T) {
	client := &disabledClient{}

	t.Run("IsEnabled", func(t *testing.T) {
		if client.IsEnabled() {
			t.Error("IsEnabled() should return false")
		}
	})

	t.Run("Authenticate", func(t *testing.T) {
		err := client.Authenticate(context.Background())
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Authenticate() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("RenewToken", func(t *testing.T) {
		err := client.RenewToken(context.Background())
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("RenewToken() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Health", func(t *testing.T) {
		_, err := client.Health(context.Background())
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Health() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("PKI", func(t *testing.T) {
		pki := client.PKI()
		if pki == nil {
			t.Error("PKI() should not return nil")
		}
		_, err := pki.IssueCertificate(context.Background(), nil)
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("PKI().IssueCertificate() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("KV", func(t *testing.T) {
		kv := client.KV()
		if kv == nil {
			t.Error("KV() should not return nil")
		}
		_, err := kv.Read(context.Background(), "mount", "path")
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("KV().Read() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Transit", func(t *testing.T) {
		transit := client.Transit()
		if transit == nil {
			t.Error("Transit() should not return nil")
		}
		_, err := transit.Encrypt(context.Background(), "mount", "key", []byte("data"))
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Transit().Encrypt() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Close", func(t *testing.T) {
		err := client.Close()
		if err != nil {
			t.Errorf("Close() error = %v, want nil", err)
		}
	})
}

func TestDisabledKVClient(t *testing.T) {
	client := &disabledKVClient{}
	ctx := context.Background()

	t.Run("Read", func(t *testing.T) {
		_, err := client.Read(ctx, "mount", "path")
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Read() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Write", func(t *testing.T) {
		err := client.Write(ctx, "mount", "path", map[string]interface{}{"key": "value"})
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Write() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		err := client.Delete(ctx, "mount", "path")
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Delete() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		_, err := client.List(ctx, "mount", "path")
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("List() error = %v, want ErrVaultDisabled", err)
		}
	})
}

func TestDisabledTransitClient(t *testing.T) {
	client := &disabledTransitClient{}
	ctx := context.Background()

	t.Run("Encrypt", func(t *testing.T) {
		_, err := client.Encrypt(ctx, "mount", "key", []byte("data"))
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Encrypt() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Decrypt", func(t *testing.T) {
		_, err := client.Decrypt(ctx, "mount", "key", []byte("ciphertext"))
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Decrypt() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Sign", func(t *testing.T) {
		_, err := client.Sign(ctx, "mount", "key", []byte("data"))
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Sign() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Verify", func(t *testing.T) {
		_, err := client.Verify(ctx, "mount", "key", []byte("data"), []byte("sig"))
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Verify() error = %v, want ErrVaultDisabled", err)
		}
	})
}

func TestVaultClient_CalculateRenewalInterval(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	vc := client.(*vaultClient)

	t.Run("zero TTL", func(t *testing.T) {
		vc.tokenTTL.Store(0)
		interval := vc.calculateRenewalInterval()
		if interval != 0 {
			t.Errorf("calculateRenewalInterval() = %v, want 0", interval)
		}
	})

	t.Run("short TTL", func(t *testing.T) {
		vc.tokenTTL.Store(60) // 60 seconds
		interval := vc.calculateRenewalInterval()
		// 2/3 of 60 = 40 seconds, but minimum is 1 minute
		if interval != time.Minute {
			t.Errorf("calculateRenewalInterval() = %v, want %v", interval, time.Minute)
		}
	})

	t.Run("long TTL", func(t *testing.T) {
		vc.tokenTTL.Store(3600) // 1 hour
		interval := vc.calculateRenewalInterval()
		// 2/3 of 3600 = 2400 seconds = 40 minutes
		expected := time.Duration(2400) * time.Second
		if interval != expected {
			t.Errorf("calculateRenewalInterval() = %v, want %v", interval, expected)
		}
	})
}

func TestVaultClient_IsTokenExpired(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	vc := client.(*vaultClient)

	t.Run("zero expiry", func(t *testing.T) {
		vc.tokenExpiry.Store(0)
		if vc.isTokenExpired() {
			t.Error("isTokenExpired() should return false for zero expiry")
		}
	})

	t.Run("future expiry", func(t *testing.T) {
		vc.tokenExpiry.Store(time.Now().Add(time.Hour).Unix())
		if vc.isTokenExpired() {
			t.Error("isTokenExpired() should return false for future expiry")
		}
	})

	t.Run("past expiry", func(t *testing.T) {
		vc.tokenExpiry.Store(time.Now().Add(-time.Hour).Unix())
		if !vc.isTokenExpired() {
			t.Error("isTokenExpired() should return true for past expiry")
		}
	})
}

func TestWithMetrics(t *testing.T) {
	metrics := NewMetrics("test")
	opt := WithMetrics(metrics)

	client := &vaultClient{}
	opt(client)

	if client.metrics != metrics {
		t.Error("WithMetrics should set the metrics")
	}
}

func TestClientInterface(t *testing.T) {
	// Verify implementations satisfy the interface
	var _ Client = (*vaultClient)(nil)
	var _ Client = (*disabledClient)(nil)
}

func TestKVClientInterface(t *testing.T) {
	// Verify implementations satisfy the interface
	var _ KVClient = (*kvClient)(nil)
	var _ KVClient = (*disabledKVClient)(nil)
}

func TestTransitClientInterface(t *testing.T) {
	// Verify implementations satisfy the interface
	var _ TransitClient = (*transitClient)(nil)
	var _ TransitClient = (*disabledTransitClient)(nil)
}

func TestVaultClient_UpdateRenewalInterval(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	vc := client.(*vaultClient)

	t.Run("no change when interval is same", func(t *testing.T) {
		// Set TTL to 90 seconds -> 2/3 = 60 seconds = 1 minute (minimum)
		vc.tokenTTL.Store(90)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		currentInterval := time.Minute
		newInterval := vc.updateRenewalInterval(ticker, currentInterval)
		// Both should be 1 minute (minimum), so no change
		if newInterval != currentInterval {
			t.Errorf("updateRenewalInterval() = %v, want %v", newInterval, currentInterval)
		}
	})

	t.Run("updates when TTL changes", func(t *testing.T) {
		vc.tokenTTL.Store(3600) // 1 hour -> 40 minutes interval
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		currentInterval := time.Minute
		newInterval := vc.updateRenewalInterval(ticker, currentInterval)
		expected := time.Duration(2400) * time.Second // 2/3 of 3600
		if newInterval != expected {
			t.Errorf("updateRenewalInterval() = %v, want %v", newInterval, expected)
		}
	})

	t.Run("returns current when new interval is zero", func(t *testing.T) {
		vc.tokenTTL.Store(0)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		currentInterval := time.Minute
		newInterval := vc.updateRenewalInterval(ticker, currentInterval)
		if newInterval != currentInterval {
			t.Errorf("updateRenewalInterval() = %v, want %v", newInterval, currentInterval)
		}
	})
}

func TestVaultClient_HandleTokenRenewalError(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	vc := client.(*vaultClient)

	t.Run("does nothing when token not expired", func(t *testing.T) {
		vc.tokenExpiry.Store(time.Now().Add(time.Hour).Unix())
		// Should not panic or error
		vc.handleTokenRenewalError(context.Background())
	})

	t.Run("attempts reauthentication when token expired", func(t *testing.T) {
		vc.tokenExpiry.Store(time.Now().Add(-time.Hour).Unix())
		// Will fail to reauthenticate but should not panic
		vc.handleTokenRenewalError(context.Background())
	})
}

func TestVaultClient_PerformTokenRenewal(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	vc := client.(*vaultClient)

	// Should not panic even when renewal fails
	vc.performTokenRenewal()
}

func TestNew_WithTLSConfig(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "https://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		TLS: &VaultTLSConfig{
			SkipVerify: true,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Errorf("New() error = %v, want nil", err)
	}
	if client == nil {
		t.Fatal("New() returned nil client")
	}
}

func TestNew_WithInvalidTLSConfig(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "https://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		TLS: &VaultTLSConfig{
			CACert: "/nonexistent/path/to/ca.pem",
		},
	}

	_, err := New(cfg, logger)
	if err == nil {
		t.Error("New() should return error for invalid TLS config")
	}
}

func TestVaultClient_Close_WithCache(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 100,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Close should stop the cache cleanup goroutine
	err = client.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}
