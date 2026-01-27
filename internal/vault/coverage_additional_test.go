package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"
)

// ============================================================
// provider.go coverage: GetCertificate (no cert), GetClientCA (no pool),
// calculateRenewalTime (with cert), sendEvent (channel full)
// ============================================================

func TestVaultProvider_GetCertificate_NoCert(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	require.NoError(t, err)
	defer provider.Close()

	// No certificate loaded, should return error
	cert, err := provider.GetCertificate(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, internaltls.ErrCertificateNotFound)
}

func TestVaultProvider_GetClientCA_NoPool(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	require.NoError(t, err)
	defer provider.Close()

	// No CA pool loaded, should return nil pool without error
	pool, err := provider.GetClientCA(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, pool)
}

func TestVaultProvider_CalculateRenewalTime_WithCert(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	require.NoError(t, err)
	defer provider.Close()

	// Set a certificate with a future expiry
	futureExpiry := time.Now().Add(24 * time.Hour)
	tlsCert := &tls.Certificate{
		Leaf: &x509.Certificate{
			NotAfter: futureExpiry,
		},
	}
	provider.cert.Store(tlsCert)

	renewBefore := 1 * time.Hour
	renewAt := provider.calculateRenewalTime(renewBefore)

	// Should be approximately futureExpiry - renewBefore
	expected := futureExpiry.Add(-renewBefore)
	assert.WithinDuration(t, expected, renewAt, 2*time.Second)
}

func TestVaultProvider_CalculateRenewalTime_ExpiredCert(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	require.NoError(t, err)
	defer provider.Close()

	// Set a certificate with a past expiry
	pastExpiry := time.Now().Add(-1 * time.Hour)
	tlsCert := &tls.Certificate{
		Leaf: &x509.Certificate{
			NotAfter: pastExpiry,
		},
	}
	provider.cert.Store(tlsCert)

	renewBefore := 10 * time.Minute
	renewAt := provider.calculateRenewalTime(renewBefore)

	// Should return now since renewal time is in the past
	assert.WithinDuration(t, time.Now(), renewAt, 2*time.Second)
}

func TestVaultProvider_CalculateRenewalTime_NilLeaf(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	require.NoError(t, err)
	defer provider.Close()

	// Set a certificate without leaf
	tlsCert := &tls.Certificate{}
	provider.cert.Store(tlsCert)

	renewAt := provider.calculateRenewalTime(10 * time.Minute)
	assert.WithinDuration(t, time.Now(), renewAt, 2*time.Second)
}

func TestVaultProvider_SendEvent_ChannelFull(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	require.NoError(t, err)
	defer provider.Close()

	// Fill the event channel (capacity is 10)
	for i := 0; i < 10; i++ {
		provider.sendEvent(internaltls.CertificateEvent{
			Type:    internaltls.CertificateEventLoaded,
			Message: "test",
		})
	}

	// This should not block - event should be dropped
	provider.sendEvent(internaltls.CertificateEvent{
		Type:    internaltls.CertificateEventLoaded,
		Message: "dropped",
	})
}

// ============================================================
// client.go coverage: RenewToken (closed), Health (closed),
// calculateRenewalInterval, handleTokenRenewalError,
// isTokenExpired, reauthenticate
// ============================================================

func TestVaultClient_RenewToken_Closed_Coverage(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	vc.mu.Lock()
	vc.closed = true
	vc.mu.Unlock()

	err = client.RenewToken(context.Background())
	assert.ErrorIs(t, err, ErrClientClosed)
}

func TestVaultClient_Health_Closed_Coverage(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	vc.mu.Lock()
	vc.closed = true
	vc.mu.Unlock()

	_, err = client.Health(context.Background())
	assert.ErrorIs(t, err, ErrClientClosed)
}

func TestVaultClient_CalculateRenewalInterval_Coverage(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)

	// Zero TTL should return 0
	vc.tokenTTL.Store(0)
	interval := vc.calculateRenewalInterval()
	assert.Equal(t, time.Duration(0), interval)

	// Small TTL should use MinRenewalInterval
	vc.tokenTTL.Store(10) // 10 seconds
	interval = vc.calculateRenewalInterval()
	assert.Equal(t, MinRenewalInterval, interval)

	// Large TTL should use 2/3 of TTL
	vc.tokenTTL.Store(300) // 5 minutes = 300 seconds
	interval = vc.calculateRenewalInterval()
	expected := time.Duration(300*2/3) * time.Second
	assert.Equal(t, expected, interval)
}

func TestVaultClient_IsTokenExpired_Coverage(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)

	// No expiry set
	vc.tokenExpiry.Store(0)
	assert.False(t, vc.isTokenExpired())

	// Future expiry
	vc.tokenExpiry.Store(time.Now().Add(1 * time.Hour).Unix())
	assert.False(t, vc.isTokenExpired())

	// Past expiry
	vc.tokenExpiry.Store(time.Now().Add(-1 * time.Hour).Unix())
	assert.True(t, vc.isTokenExpired())
}

func TestVaultClient_HandleTokenRenewalError_NotExpired(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)

	// Token not expired - should not attempt re-authentication
	vc.tokenExpiry.Store(time.Now().Add(1 * time.Hour).Unix())
	ctx := context.Background()
	vc.handleTokenRenewalError(ctx) // Should not panic
}

func TestVaultClient_HandleTokenRenewalError_Expired(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)

	// Token expired - should attempt re-authentication (will fail but shouldn't panic)
	vc.tokenExpiry.Store(time.Now().Add(-1 * time.Hour).Unix())
	ctx := context.Background()
	vc.handleTokenRenewalError(ctx) // Should not panic
}

func TestVaultClient_GetRetryConfig_Coverage(t *testing.T) {
	logger := observability.NopLogger()

	// With retry config
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
	require.NoError(t, err)

	vc := client.(*vaultClient)
	retryCfg := vc.getRetryConfig()
	assert.Equal(t, 5, retryCfg.GetMaxRetries())

	// Without retry config
	cfg2 := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client2, err := New(cfg2, logger)
	require.NoError(t, err)

	vc2 := client2.(*vaultClient)
	retryCfg2 := vc2.getRetryConfig()
	assert.NotNil(t, retryCfg2)
}

func TestVaultClient_Authenticate_Closed_Coverage(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	vc.mu.Lock()
	vc.closed = true
	vc.mu.Unlock()

	err = client.Authenticate(context.Background())
	assert.ErrorIs(t, err, ErrClientClosed)
}

func TestVaultClient_Authenticate_CancelledContext(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = client.Authenticate(ctx)
	assert.Error(t, err)
}

func TestVaultClient_Authenticate_UnsupportedMethod(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethod("unsupported"),
	}

	// Validation will fail for unsupported auth method, so we need to bypass
	// by creating the client directly
	client, err := New(&Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	vc.config.AuthMethod = AuthMethod("unsupported")

	err = client.Authenticate(context.Background())
	assert.Error(t, err)
	_ = cfg // suppress unused
}

func TestVaultClient_Reauthenticate_AllMethods(t *testing.T) {
	logger := observability.NopLogger()

	tests := []struct {
		name   string
		method AuthMethod
	}{
		{"token", AuthMethodToken},
		{"kubernetes", AuthMethodKubernetes},
		{"approle", AuthMethodAppRole},
		{"unsupported", AuthMethod("unsupported")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Enabled:    true,
				Address:    "http://localhost:8200",
				AuthMethod: AuthMethodToken,
				Token:      "test-token",
			}

			client, err := New(cfg, logger)
			require.NoError(t, err)

			vc := client.(*vaultClient)
			vc.config.AuthMethod = tt.method

			// reauthenticate will fail for most methods but shouldn't panic
			_ = vc.reauthenticate(context.Background())
		})
	}
}

func TestVaultClient_UpdateRenewalInterval_Coverage(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	// No TTL - should return current interval
	vc.tokenTTL.Store(0)
	result := vc.updateRenewalInterval(ticker, time.Hour)
	assert.Equal(t, time.Hour, result)

	// Same interval - should return current
	vc.tokenTTL.Store(5400) // 90 minutes -> 2/3 = 60 minutes = 1 hour
	result = vc.updateRenewalInterval(ticker, time.Hour)
	assert.Equal(t, time.Hour, result)

	// Different interval - should update
	vc.tokenTTL.Store(300) // 5 minutes -> 2/3 = 200 seconds
	result = vc.updateRenewalInterval(ticker, time.Hour)
	assert.NotEqual(t, time.Hour, result)
}

// ============================================================
// retry.go coverage: executeWithRetry
// ============================================================

func TestVaultClient_ExecuteWithRetry_Success(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		Retry: &RetryConfig{
			MaxRetries:  3,
			BackoffBase: 10 * time.Millisecond,
			BackoffMax:  100 * time.Millisecond,
		},
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)

	attempts := 0
	err = vc.executeWithRetry(context.Background(), func() error {
		attempts++
		if attempts < 2 {
			return ErrVaultUnavailable
		}
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 2, attempts)
}

func TestVaultClient_ExecuteWithRetry_ContextCancelled(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		Retry: &RetryConfig{
			MaxRetries:  10,
			BackoffBase: 100 * time.Millisecond,
			BackoffMax:  1 * time.Second,
		},
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = vc.executeWithRetry(ctx, func() error {
		return ErrVaultUnavailable
	})

	assert.Error(t, err)
}

func TestVaultClient_ExecuteWithRetry_NonRetryable(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		Retry: &RetryConfig{
			MaxRetries:  3,
			BackoffBase: 10 * time.Millisecond,
			BackoffMax:  100 * time.Millisecond,
		},
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)

	attempts := 0
	err = vc.executeWithRetry(context.Background(), func() error {
		attempts++
		return ErrAuthenticationFailed // Non-retryable
	})

	assert.Error(t, err)
	assert.Equal(t, 1, attempts)
}

// ============================================================
// metrics.go coverage: NopMetrics methods
// ============================================================

func TestNopMetrics_AllMethods(t *testing.T) {
	t.Parallel()

	m := NewNopMetrics()

	// All methods should not panic
	m.RecordRequest("read", "success", 100*time.Millisecond)
	m.SetTokenTTL(3600)
	m.RecordCacheHit()
	m.RecordCacheMiss()
	m.RecordAuthAttempt("token", "success")
	m.RecordError("test")
}

// ============================================================
// pki.go coverage: extractCertificatePEM, extractPrivateKeyPEM,
// extractMetadata edge cases
// ============================================================

func TestPKIClient_ExtractCertificatePEM_NoCert(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	pki := vc.pkiClient

	cert := &Certificate{}
	data := map[string]interface{}{
		// No "certificate" key
	}
	pki.extractCertificatePEM(cert, data)
	assert.Empty(t, cert.CertificatePEM)
}

func TestPKIClient_ExtractCertificatePEM_InvalidPEM(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	pki := vc.pkiClient

	cert := &Certificate{}
	data := map[string]interface{}{
		"certificate": "not-valid-pem",
	}
	pki.extractCertificatePEM(cert, data)
	assert.Equal(t, "not-valid-pem", cert.CertificatePEM)
	assert.Nil(t, cert.Certificate) // Should not be parsed
}

func TestPKIClient_ExtractPrivateKeyPEM_NoKey(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	pki := vc.pkiClient

	cert := &Certificate{}
	data := map[string]interface{}{
		// No "private_key" key
	}
	pki.extractPrivateKeyPEM(cert, data)
	assert.Empty(t, cert.PrivateKeyPEM)
}

func TestPKIClient_ExtractPrivateKeyPEM_InvalidPEM(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	pki := vc.pkiClient

	cert := &Certificate{}
	data := map[string]interface{}{
		"private_key": "not-valid-pem",
	}
	pki.extractPrivateKeyPEM(cert, data)
	assert.Equal(t, "not-valid-pem", cert.PrivateKeyPEM)
	assert.Nil(t, cert.PrivateKey)
}

func TestPKIClient_ExtractMetadata_NoSerial(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	pki := vc.pkiClient

	cert := &Certificate{}
	data := map[string]interface{}{
		// No serial_number or expiration
	}
	pki.extractMetadata(cert, data)
	assert.Empty(t, cert.SerialNumber)
}

func TestPKIClient_ExtractMetadata_WithExpiration(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	pki := vc.pkiClient

	cert := &Certificate{}
	expTime := float64(time.Now().Add(24 * time.Hour).Unix())
	data := map[string]interface{}{
		"serial_number": "aa:bb:cc",
		"expiration":    expTime,
	}
	pki.extractMetadata(cert, data)
	assert.Equal(t, "aa:bb:cc", cert.SerialNumber)
	assert.False(t, cert.Expiration.IsZero())
}

func TestPKIClient_ExtractCAChain_WithIssuingCA(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	pki := vc.pkiClient

	cert := &Certificate{}
	data := map[string]interface{}{
		"issuing_ca": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}
	pki.extractCAChain(cert, data)
	assert.NotEmpty(t, cert.CAChainPEM)
}

func TestPKIClient_ExtractCAChain_WithCAChain(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	vc := client.(*vaultClient)
	pki := vc.pkiClient

	cert := &Certificate{}
	data := map[string]interface{}{
		"ca_chain": []interface{}{
			"-----BEGIN CERTIFICATE-----\nca1\n-----END CERTIFICATE-----",
			"-----BEGIN CERTIFICATE-----\nca2\n-----END CERTIFICATE-----",
		},
	}
	pki.extractCAChain(cert, data)
	assert.NotEmpty(t, cert.CAChainPEM)
	assert.Contains(t, cert.CAChainPEM, "ca1")
	assert.Contains(t, cert.CAChainPEM, "ca2")
}

// ============================================================
// kv.go coverage: List with valid data
// ============================================================

func TestDisabledKVClient_AllMethods_Coverage(t *testing.T) {
	t.Parallel()

	kv := &disabledKVClient{}
	ctx := context.Background()

	_, err := kv.Read(ctx, "mount", "path")
	assert.ErrorIs(t, err, ErrVaultDisabled)

	err = kv.Write(ctx, "mount", "path", map[string]interface{}{"key": "value"})
	assert.ErrorIs(t, err, ErrVaultDisabled)

	err = kv.Delete(ctx, "mount", "path")
	assert.ErrorIs(t, err, ErrVaultDisabled)

	_, err = kv.List(ctx, "mount", "path")
	assert.ErrorIs(t, err, ErrVaultDisabled)
}

func TestDisabledTransitClient_AllMethods_Coverage(t *testing.T) {
	t.Parallel()

	transit := &disabledTransitClient{}
	ctx := context.Background()

	_, err := transit.Encrypt(ctx, "mount", "key", []byte("data"))
	assert.ErrorIs(t, err, ErrVaultDisabled)

	_, err = transit.Decrypt(ctx, "mount", "key", []byte("data"))
	assert.ErrorIs(t, err, ErrVaultDisabled)

	_, err = transit.Sign(ctx, "mount", "key", []byte("data"))
	assert.ErrorIs(t, err, ErrVaultDisabled)

	_, err = transit.Verify(ctx, "mount", "key", []byte("data"), []byte("sig"))
	assert.ErrorIs(t, err, ErrVaultDisabled)
}

func TestDisabledPKIClient_AllMethods_Coverage(t *testing.T) {
	t.Parallel()

	pki := &disabledPKIClient{}
	ctx := context.Background()

	_, err := pki.IssueCertificate(ctx, &PKIIssueOptions{})
	assert.ErrorIs(t, err, ErrVaultDisabled)

	_, err = pki.SignCSR(ctx, []byte("csr"), &PKISignOptions{})
	assert.ErrorIs(t, err, ErrVaultDisabled)

	_, err = pki.GetCA(ctx, "mount")
	assert.ErrorIs(t, err, ErrVaultDisabled)

	_, err = pki.GetCRL(ctx, "mount")
	assert.ErrorIs(t, err, ErrVaultDisabled)

	err = pki.RevokeCertificate(ctx, "mount", "serial")
	assert.ErrorIs(t, err, ErrVaultDisabled)
}

func TestDisabledClient_AllMethods(t *testing.T) {
	t.Parallel()

	client := &disabledClient{}
	ctx := context.Background()

	assert.False(t, client.IsEnabled())

	err := client.Authenticate(ctx)
	assert.ErrorIs(t, err, ErrVaultDisabled)

	err = client.RenewToken(ctx)
	assert.ErrorIs(t, err, ErrVaultDisabled)

	_, err = client.Health(ctx)
	assert.ErrorIs(t, err, ErrVaultDisabled)

	assert.NotNil(t, client.PKI())
	assert.NotNil(t, client.KV())
	assert.NotNil(t, client.Transit())

	err = client.Close()
	assert.NoError(t, err)
}
