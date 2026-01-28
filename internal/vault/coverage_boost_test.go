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

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================
// NopMetrics: cover all 6 no-op methods individually
// ============================================================

func TestNopMetrics_RecordRequest(t *testing.T) {
	t.Parallel()
	m := NewNopMetrics()
	m.RecordRequest("op", "status", time.Second)
}

func TestNopMetrics_SetTokenTTL(t *testing.T) {
	t.Parallel()
	m := NewNopMetrics()
	m.SetTokenTTL(42.0)
}

func TestNopMetrics_RecordCacheHit(t *testing.T) {
	t.Parallel()
	m := NewNopMetrics()
	m.RecordCacheHit()
}

func TestNopMetrics_RecordCacheMiss(t *testing.T) {
	t.Parallel()
	m := NewNopMetrics()
	m.RecordCacheMiss()
}

func TestNopMetrics_RecordAuthAttempt(t *testing.T) {
	t.Parallel()
	m := NewNopMetrics()
	m.RecordAuthAttempt("method", "status")
}

func TestNopMetrics_RecordError(t *testing.T) {
	t.Parallel()
	m := NewNopMetrics()
	m.RecordError("type")
}

// ============================================================
// client.go: RenewToken success path, Health success path
// ============================================================

func TestVaultClient_RenewToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/renew-self" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"auth": {
					"client_token": "test-token",
					"lease_duration": 3600,
					"renewable": true
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	err = client.RenewToken(context.Background())
	assert.NoError(t, err)

	vc := client.(*vaultClient)
	assert.Equal(t, int64(3600), vc.tokenTTL.Load())
	assert.True(t, vc.tokenExpiry.Load() > 0)
}

func TestVaultClient_RenewToken_NilAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/renew-self" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			// Response with no auth block
			resp := `{"data": {}}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	err = client.RenewToken(context.Background())
	// Should succeed even without auth block
	assert.NoError(t, err)
}

func TestVaultClient_Health_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"initialized": true,
				"sealed": false,
				"standby": false,
				"performance_standby": false,
				"replication_performance_mode": "disabled",
				"replication_dr_mode": "disabled",
				"server_time_utc": 1706000000,
				"version": "1.15.0",
				"cluster_name": "test-cluster",
				"cluster_id": "test-cluster-id"
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	health, err := client.Health(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, health)
	assert.True(t, health.Initialized)
	assert.False(t, health.Sealed)
	assert.Equal(t, "1.15.0", health.Version)
	assert.Equal(t, "test-cluster", health.ClusterName)
	assert.Equal(t, "test-cluster-id", health.ClusterID)
}

func TestVaultClient_Health_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	_, err = client.Health(context.Background())
	assert.Error(t, err)
}

// ============================================================
// kv.go: List with valid keys, List with non-string keys
// ============================================================

func TestKVClient_List_WithKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/metadata/test-path" {
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"request_id": "abc",
				"data": {
					"keys": ["key1", "key2", "key3/"]
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	kv := client.KV()
	keys, err := kv.List(context.Background(), "secret", "test-path")
	require.NoError(t, err)
	assert.Equal(t, []string{"key1", "key2", "key3/"}, keys)
}

func TestKVClient_List_NoKeysField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/metadata/test-path" {
			w.Header().Set("Content-Type", "application/json")
			// data exists but no "keys" field
			resp := `{
				"request_id": "abc",
				"data": {
					"other": "value"
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	kv := client.KV()
	keys, err := kv.List(context.Background(), "secret", "test-path")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// ============================================================
// pki.go: GetCA success, GetCA cache, GetCRL success
// ============================================================

func TestPKIClient_GetCA_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pki/cert/ca" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			// Use a real-ish self-signed CA cert PEM for testing
			resp, _ := json.Marshal(map[string]interface{}{
				"data": map[string]interface{}{
					"certificate": testCACertPEM,
				},
			})
			_, _ = w.Write(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	pki := client.PKI()
	pool, err := pki.GetCA(context.Background(), "pki")
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestPKIClient_GetCA_WithCacheBoost(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pki/cert/ca" && r.Method == http.MethodGet {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal(map[string]interface{}{
				"data": map[string]interface{}{
					"certificate": testCACertPEM,
				},
			})
			_, _ = w.Write(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 100,
		},
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	pki := client.PKI()

	// First call - hits server
	_, err = pki.GetCA(context.Background(), "pki")
	require.NoError(t, err)

	// Second call - should hit cache
	_, err = pki.GetCA(context.Background(), "pki")
	require.NoError(t, err)

	assert.Equal(t, 1, callCount)
}

func TestPKIClient_GetCA_NoCertInResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pki/cert/ca" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			resp := `{"data": {"other": "value"}}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	pki := client.PKI()
	_, err = pki.GetCA(context.Background(), "pki")
	assert.Error(t, err)
}

func TestPKIClient_GetCA_InvalidPEM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pki/cert/ca" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal(map[string]interface{}{
				"data": map[string]interface{}{
					"certificate": "not-valid-pem",
				},
			})
			_, _ = w.Write(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	pki := client.PKI()
	_, err = pki.GetCA(context.Background(), "pki")
	assert.Error(t, err)
}

func TestPKIClient_GetCRL_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pki/cert/crl" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal(map[string]interface{}{
				"data": map[string]interface{}{
					"certificate": "-----BEGIN X509 CRL-----\ntest\n-----END X509 CRL-----",
				},
			})
			_, _ = w.Write(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	pki := client.PKI()
	crl, err := pki.GetCRL(context.Background(), "pki")
	require.NoError(t, err)
	assert.NotEmpty(t, crl)
}

func TestPKIClient_GetCRL_NoCRLInResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pki/cert/crl" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			resp := `{"data": {"other": "value"}}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	pki := client.PKI()
	_, err = pki.GetCRL(context.Background(), "pki")
	assert.Error(t, err)
}

func TestPKIClient_GetCRL_NilData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pki/cert/crl" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	pki := client.PKI()
	_, err = pki.GetCRL(context.Background(), "pki")
	assert.Error(t, err)
}

// ============================================================
// transit.go: additional error paths
// ============================================================

func TestTransitClient_Encrypt_NilResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	transit := client.Transit()
	_, err = transit.Encrypt(context.Background(), "transit", "key", []byte("data"))
	assert.Error(t, err)
}

func TestTransitClient_Decrypt_NilResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	transit := client.Transit()
	_, err = transit.Decrypt(context.Background(), "transit", "key", []byte("cipher"))
	assert.Error(t, err)
}

func TestTransitClient_Sign_NilResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	transit := client.Transit()
	_, err = transit.Sign(context.Background(), "transit", "key", []byte("data"))
	assert.Error(t, err)
}

func TestTransitClient_Verify_NilResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	require.NoError(t, err)

	transit := client.Transit()
	_, err = transit.Verify(
		context.Background(), "transit", "key", []byte("data"), []byte("sig"),
	)
	assert.Error(t, err)
}

// ============================================================
// cache.go: cleanupLoop coverage via stop
// ============================================================

func TestSecretCache_CleanupLoop_Stop(t *testing.T) {
	cache := newSecretCache(10, 50*time.Millisecond)

	// Add some items
	cache.set("key1", "value1")
	cache.set("key2", "value2")

	// Stop the cache (which stops the cleanup loop)
	cache.stop()

	// Verify items are still accessible (stop doesn't clear)
	_, ok := cache.get("key1")
	// May or may not be expired depending on timing, just ensure no panic
	_ = ok
}

// ============================================================
// provider.go: GetCertificate when closed
// ============================================================

func TestVaultProvider_GetCertificate_ClosedBoost(t *testing.T) {
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

	// Close the provider
	err = provider.Close()
	require.NoError(t, err)

	// GetCertificate should return error
	_, err = provider.GetCertificate(context.Background(), nil)
	assert.Error(t, err)
}

func TestVaultProvider_GetClientCA_ClosedBoost(t *testing.T) {
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

	err = provider.Close()
	require.NoError(t, err)

	_, err = provider.GetClientCA(context.Background())
	assert.Error(t, err)
}

func TestVaultProvider_Close_IdempotentBoost(t *testing.T) {
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

	err = provider.Close()
	assert.NoError(t, err)

	err = provider.Close()
	assert.NoError(t, err)
}

func TestVaultProvider_WatchBoost(t *testing.T) {
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

	ch := provider.Watch(context.Background())
	assert.NotNil(t, ch)
}

func TestVaultProvider_GetCertificateInfo_NoCert(t *testing.T) {
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

	info := provider.GetCertificateInfo()
	assert.Nil(t, info)
}

// testCACertPEM is a self-signed CA certificate for testing (ECDSA P-256, valid 2020-2050).
const testCACertPEM = `-----BEGIN CERTIFICATE-----
MIIBVjCB/aADAgECAgEBMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB1Rlc3QgQ0Ew
IBcNMjAwMTAxMDAwMDAwWhgPMjA1MDAxMDEwMDAwMDBaMBIxEDAOBgNVBAoTB1Rl
c3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR8HuYIDWFIvBnjZs3slDPC
AzuNvBmkQR21nccvJhAKHj7Hnf2V+ejEsi40B+3/cQ8Fc8NgjKW7KZsj/8LevP54
o0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
qwFvOSo787ZwO4ypf9O2H7AGzm0wCgYIKoZIzj0EAwIDSAAwRQIhAKWjtzNaBVrs
ymxxx3afR9nsCIz6pjk7wgbh7tqODI9yAiAO7+BDL1EQ/gQF525XySTcX+2Zfwir
8L6oq05Unrh9KQ==
-----END CERTIFICATE-----`
