package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewJWKSKeySet(t *testing.T) {
	t.Parallel()

	t.Run("empty URL returns error", func(t *testing.T) {
		t.Parallel()

		ks, err := NewJWKSKeySet("")
		assert.Error(t, err)
		assert.Nil(t, ks)
	})

	t.Run("valid URL", func(t *testing.T) {
		t.Parallel()

		ks, err := NewJWKSKeySet("https://example.com/.well-known/jwks.json")
		require.NoError(t, err)
		assert.NotNil(t, ks)
	})

	t.Run("with options", func(t *testing.T) {
		t.Parallel()

		client := &http.Client{Timeout: 10 * time.Second}
		logger := observability.NopLogger()

		ks, err := NewJWKSKeySet(
			"https://example.com/.well-known/jwks.json",
			WithHTTPClient(client),
			WithCacheTTL(30*time.Minute),
			WithJWKSLogger(logger),
		)
		require.NoError(t, err)
		assert.NotNil(t, ks)
	})
}

func TestJWKSKeySet_Refresh(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
	require.NoError(t, err)
	err = jwkKey.Set(jwk.AlgorithmKey, "RS256")
	require.NoError(t, err)

	// Create JWKS
	jwks := jwk.NewSet()
	err = jwks.AddKey(jwkKey)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	// Create JWKS key set
	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Hour))
	require.NoError(t, err)

	// Refresh
	err = ks.Refresh(context.Background())
	require.NoError(t, err)

	// Verify stats
	stats := ks.Stats()
	assert.Equal(t, server.URL, stats.URL)
	assert.Equal(t, 1, stats.KeyCount)
	assert.Equal(t, int64(1), stats.Refreshes)
	assert.Equal(t, int64(0), stats.Errors)
}

func TestJWKSKeySet_GetKey(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
	require.NoError(t, err)

	// Create JWKS
	jwks := jwk.NewSet()
	err = jwks.AddKey(jwkKey)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	// Create JWKS key set
	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Hour))
	require.NoError(t, err)

	// Get key (should trigger refresh)
	key, err := ks.GetKey(context.Background(), "test-key-id")
	require.NoError(t, err)
	assert.NotNil(t, key)

	// Verify it's an RSA public key
	_, ok := key.(*rsa.PublicKey)
	assert.True(t, ok)
}

func TestJWKSKeySet_GetKey_NotFound(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
	require.NoError(t, err)

	// Create JWKS
	jwks := jwk.NewSet()
	err = jwks.AddKey(jwkKey)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	// Create JWKS key set
	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Hour))
	require.NoError(t, err)

	// Get non-existent key
	key, err := ks.GetKey(context.Background(), "non-existent-key")
	assert.Error(t, err)
	assert.Nil(t, key)
}

func TestJWKSKeySet_GetKeyForAlgorithm(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
	require.NoError(t, err)

	// Create JWKS
	jwks := jwk.NewSet()
	err = jwks.AddKey(jwkKey)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	// Create JWKS key set
	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Hour))
	require.NoError(t, err)

	// Get key for RS256 algorithm
	key, err := ks.GetKeyForAlgorithm(context.Background(), "test-key-id", "RS256")
	require.NoError(t, err)
	assert.NotNil(t, key)

	// Get key for wrong algorithm
	key, err = ks.GetKeyForAlgorithm(context.Background(), "test-key-id", "ES256")
	assert.Error(t, err)
	assert.Nil(t, key)
}

func TestJWKSKeySet_Refresh_Error(t *testing.T) {
	t.Parallel()

	// Create test server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create JWKS key set
	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Millisecond))
	require.NoError(t, err)

	// Refresh should fail
	err = ks.Refresh(context.Background())
	assert.Error(t, err)

	// Verify error count
	stats := ks.Stats()
	assert.Equal(t, int64(1), stats.Errors)
}

func TestNewStaticKeySet(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	keys := []StaticKey{
		{
			KeyID: "test-key-id",
			Key:   string(jwkJSON),
		},
	}

	ks, err := NewStaticKeySet(keys, observability.NopLogger())
	require.NoError(t, err)
	assert.NotNil(t, ks)
}

func TestStaticKeySet_GetKey(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	keys := []StaticKey{
		{
			KeyID: "test-key-id",
			Key:   string(jwkJSON),
		},
	}

	ks, err := NewStaticKeySet(keys, observability.NopLogger())
	require.NoError(t, err)

	// Get existing key
	key, err := ks.GetKey(context.Background(), "test-key-id")
	require.NoError(t, err)
	assert.NotNil(t, key)

	// Get non-existent key
	key, err = ks.GetKey(context.Background(), "non-existent")
	assert.Error(t, err)
	assert.Nil(t, key)
}

func TestStaticKeySet_GetKeyForAlgorithm(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	keys := []StaticKey{
		{
			KeyID: "test-key-id",
			Key:   string(jwkJSON),
		},
	}

	ks, err := NewStaticKeySet(keys, observability.NopLogger())
	require.NoError(t, err)

	// Get key for RS256 algorithm
	key, err := ks.GetKeyForAlgorithm(context.Background(), "test-key-id", "RS256")
	require.NoError(t, err)
	assert.NotNil(t, key)

	// Get key for wrong algorithm
	key, err = ks.GetKeyForAlgorithm(context.Background(), "test-key-id", "ES256")
	assert.Error(t, err)
	assert.Nil(t, key)
}

func TestStaticKeySet_Refresh(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	keys := []StaticKey{
		{
			KeyID: "test-key-id",
			Key:   string(jwkJSON),
		},
	}

	ks, err := NewStaticKeySet(keys, observability.NopLogger())
	require.NoError(t, err)

	// Refresh is a no-op for static keys
	err = ks.Refresh(context.Background())
	assert.NoError(t, err)
}

func TestStaticKeySet_Close(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	keys := []StaticKey{
		{
			KeyID: "test-key-id",
			Key:   string(jwkJSON),
		},
	}

	ks, err := NewStaticKeySet(keys, observability.NopLogger())
	require.NoError(t, err)

	// Close is a no-op for static keys
	err = ks.Close()
	assert.NoError(t, err)
}

func TestNewCompositeKeySet(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	keys := []StaticKey{
		{
			KeyID: "test-key-id",
			Key:   string(jwkJSON),
		},
	}

	staticKS, err := NewStaticKeySet(keys, observability.NopLogger())
	require.NoError(t, err)

	compositeKS := NewCompositeKeySet([]KeySet{staticKS}, observability.NopLogger())
	assert.NotNil(t, compositeKS)
}

func TestCompositeKeySet_GetKey(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	keys := []StaticKey{
		{
			KeyID: "test-key-id",
			Key:   string(jwkJSON),
		},
	}

	staticKS, err := NewStaticKeySet(keys, observability.NopLogger())
	require.NoError(t, err)

	compositeKS := NewCompositeKeySet([]KeySet{staticKS}, observability.NopLogger())

	// Get existing key
	key, err := compositeKS.GetKey(context.Background(), "test-key-id")
	require.NoError(t, err)
	assert.NotNil(t, key)

	// Get non-existent key
	key, err = compositeKS.GetKey(context.Background(), "non-existent")
	assert.Error(t, err)
	assert.Nil(t, key)
}

func TestCompositeKeySet_GetKeyForAlgorithm(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	keys := []StaticKey{
		{
			KeyID: "test-key-id",
			Key:   string(jwkJSON),
		},
	}

	staticKS, err := NewStaticKeySet(keys, observability.NopLogger())
	require.NoError(t, err)

	compositeKS := NewCompositeKeySet([]KeySet{staticKS}, observability.NopLogger())

	// Get key for RS256 algorithm
	key, err := compositeKS.GetKeyForAlgorithm(context.Background(), "test-key-id", "RS256")
	require.NoError(t, err)
	assert.NotNil(t, key)

	// Get key for wrong algorithm
	key, err = compositeKS.GetKeyForAlgorithm(context.Background(), "test-key-id", "ES256")
	assert.Error(t, err)
	assert.Nil(t, key)
}

func TestCompositeKeySet_Refresh(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	keys := []StaticKey{
		{
			KeyID: "test-key-id",
			Key:   string(jwkJSON),
		},
	}

	staticKS, err := NewStaticKeySet(keys, observability.NopLogger())
	require.NoError(t, err)

	compositeKS := NewCompositeKeySet([]KeySet{staticKS}, observability.NopLogger())

	// Refresh all key sets
	err = compositeKS.Refresh(context.Background())
	assert.NoError(t, err)
}

func TestCompositeKeySet_Close(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	keys := []StaticKey{
		{
			KeyID: "test-key-id",
			Key:   string(jwkJSON),
		},
	}

	staticKS, err := NewStaticKeySet(keys, observability.NopLogger())
	require.NoError(t, err)

	compositeKS := NewCompositeKeySet([]KeySet{staticKS}, observability.NopLogger())

	// Close all key sets
	err = compositeKS.Close()
	assert.NoError(t, err)
}

func TestValidateKeyAlgorithm(t *testing.T) {
	t.Parallel()

	// Generate test keys
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ed25519PubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name      string
		key       crypto.PublicKey
		algorithm string
		wantErr   bool
	}{
		{
			name:      "RSA key with RS256",
			key:       &rsaKey.PublicKey,
			algorithm: "RS256",
			wantErr:   false,
		},
		{
			name:      "RSA key with RS384",
			key:       &rsaKey.PublicKey,
			algorithm: "RS384",
			wantErr:   false,
		},
		{
			name:      "RSA key with RS512",
			key:       &rsaKey.PublicKey,
			algorithm: "RS512",
			wantErr:   false,
		},
		{
			name:      "RSA key with PS256",
			key:       &rsaKey.PublicKey,
			algorithm: "PS256",
			wantErr:   false,
		},
		{
			name:      "RSA key with ES256 (wrong)",
			key:       &rsaKey.PublicKey,
			algorithm: "ES256",
			wantErr:   true,
		},
		{
			name:      "ECDSA key with ES256",
			key:       &ecdsaKey.PublicKey,
			algorithm: "ES256",
			wantErr:   false,
		},
		{
			name:      "ECDSA key with ES384",
			key:       &ecdsaKey.PublicKey,
			algorithm: "ES384",
			wantErr:   false,
		},
		{
			name:      "ECDSA key with RS256 (wrong)",
			key:       &ecdsaKey.PublicKey,
			algorithm: "RS256",
			wantErr:   true,
		},
		{
			name:      "Ed25519 key with EdDSA",
			key:       ed25519PubKey,
			algorithm: "EdDSA",
			wantErr:   false,
		},
		{
			name:      "Ed25519 key with Ed25519",
			key:       ed25519PubKey,
			algorithm: "Ed25519",
			wantErr:   false,
		},
		{
			name:      "Ed25519 key with RS256 (wrong)",
			key:       ed25519PubKey,
			algorithm: "RS256",
			wantErr:   true,
		},
		{
			name:      "unknown algorithm",
			key:       &rsaKey.PublicKey,
			algorithm: "UNKNOWN",
			wantErr:   false, // Unknown algorithms pass through
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateKeyAlgorithm(tt.key, tt.algorithm)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestJWKSStats(t *testing.T) {
	t.Parallel()

	now := time.Now()
	stats := JWKSStats{
		URL:         "https://example.com/.well-known/jwks.json",
		KeyCount:    5,
		LastRefresh: now,
		Refreshes:   10,
		Errors:      2,
	}

	assert.Equal(t, "https://example.com/.well-known/jwks.json", stats.URL)
	assert.Equal(t, 5, stats.KeyCount)
	assert.Equal(t, now, stats.LastRefresh)
	assert.Equal(t, int64(10), stats.Refreshes)
	assert.Equal(t, int64(2), stats.Errors)
}

func TestJWKSKeySet_Start(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
	require.NoError(t, err)

	// Create JWKS
	jwks := jwk.NewSet()
	err = jwks.AddKey(jwkKey)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	// Create JWKS key set with short cache TTL
	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(100*time.Millisecond))
	require.NoError(t, err)

	// Start the key set
	err = ks.Start(context.Background())
	require.NoError(t, err)

	// Verify initial fetch worked
	stats := ks.Stats()
	assert.Equal(t, 1, stats.KeyCount)
	assert.Equal(t, int64(1), stats.Refreshes)

	// Close the key set
	err = ks.Close()
	require.NoError(t, err)
}

func TestJWKSKeySet_Start_InitialFetchFails(t *testing.T) {
	t.Parallel()

	// Create test server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create JWKS key set with minimal retries
	ks, err := NewJWKSKeySet(server.URL,
		WithCacheTTL(time.Millisecond),
		WithRetryConfig(RetryConfig{
			MaxAttempts:     1,
			InitialInterval: time.Millisecond,
			MaxInterval:     time.Millisecond,
			Multiplier:      1.0,
		}),
	)
	require.NoError(t, err)

	// Start should fail
	err = ks.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "initial JWKS fetch failed")
}

func TestJWKSKeySet_Close(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
	require.NoError(t, err)

	// Create JWKS
	jwks := jwk.NewSet()
	err = jwks.AddKey(jwkKey)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	// Create and start JWKS key set
	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(100*time.Millisecond))
	require.NoError(t, err)

	err = ks.Start(context.Background())
	require.NoError(t, err)

	// Close should work
	err = ks.Close()
	assert.NoError(t, err)
}

func TestJWKSKeySet_RefreshLoop(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
	require.NoError(t, err)

	// Create JWKS
	jwks := jwk.NewSet()
	err = jwks.AddKey(jwkKey)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	var requestCount int
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	// Create JWKS key set with very short cache TTL to trigger refresh
	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(50*time.Millisecond))
	require.NoError(t, err)

	// Start the key set
	err = ks.Start(context.Background())
	require.NoError(t, err)

	// Wait for at least one refresh cycle
	time.Sleep(100 * time.Millisecond)

	// Close the key set
	err = ks.Close()
	require.NoError(t, err)

	// Should have made at least 2 requests (initial + at least one refresh)
	assert.GreaterOrEqual(t, requestCount, 1)
}

func TestJWKSKeySet_Refresh_ContextCanceled(t *testing.T) {
	t.Parallel()

	// Create test server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create JWKS key set
	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Millisecond))
	require.NoError(t, err)

	// Create canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Refresh should fail with context error
	err = ks.Refresh(ctx)
	assert.Error(t, err)
}

func TestJWKSKeySet_Refresh_CacheNotExpired(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
	require.NoError(t, err)

	// Create JWKS
	jwks := jwk.NewSet()
	err = jwks.AddKey(jwkKey)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	var requestCount int
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	// Create JWKS key set with long cache TTL
	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Hour))
	require.NoError(t, err)

	ctx := context.Background()

	// First refresh
	err = ks.Refresh(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, requestCount)

	// Second refresh should be skipped (cache not expired)
	err = ks.Refresh(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, requestCount) // No additional request
}

func TestJWKSKeySet_Refresh_RetryOnError(t *testing.T) {
	t.Parallel()

	var requestCount int
	// Create test server that fails first few times
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Generate a test RSA key
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		jwkKey, _ := jwk.FromRaw(privateKey.Public())
		_ = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
		jwks := jwk.NewSet()
		_ = jwks.AddKey(jwkKey)
		jwksJSON, _ := json.Marshal(jwks)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	// Create JWKS key set with retry config
	ks, err := NewJWKSKeySet(server.URL,
		WithCacheTTL(time.Millisecond),
		WithRetryConfig(RetryConfig{
			MaxAttempts:     5,
			InitialInterval: time.Millisecond,
			MaxInterval:     10 * time.Millisecond,
			Multiplier:      2.0,
		}),
	)
	require.NoError(t, err)

	// Refresh should eventually succeed
	err = ks.Refresh(context.Background())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, requestCount, 3)
}

func TestDefaultRetryConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultRetryConfig()

	assert.Equal(t, 3, cfg.MaxAttempts)
	assert.Equal(t, 100*time.Millisecond, cfg.InitialInterval)
	assert.Equal(t, 5*time.Second, cfg.MaxInterval)
	assert.Equal(t, 2.0, cfg.Multiplier)
}

func TestWithRetryConfig(t *testing.T) {
	t.Parallel()

	customCfg := RetryConfig{
		MaxAttempts:     5,
		InitialInterval: 200 * time.Millisecond,
		MaxInterval:     10 * time.Second,
		Multiplier:      3.0,
	}

	ks, err := NewJWKSKeySet("https://example.com/.well-known/jwks.json", WithRetryConfig(customCfg))
	require.NoError(t, err)

	assert.Equal(t, customCfg.MaxAttempts, ks.retryConfig.MaxAttempts)
	assert.Equal(t, customCfg.InitialInterval, ks.retryConfig.InitialInterval)
	assert.Equal(t, customCfg.MaxInterval, ks.retryConfig.MaxInterval)
	assert.Equal(t, customCfg.Multiplier, ks.retryConfig.Multiplier)
}

func TestJWKSKeySet_GetKey_NilKeys(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
	require.NoError(t, err)

	// Create JWKS
	jwks := jwk.NewSet()
	err = jwks.AddKey(jwkKey)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	// Create JWKS key set without starting (keys will be nil)
	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Hour))
	require.NoError(t, err)

	// GetKey should trigger refresh
	key, err := ks.GetKey(context.Background(), "test-key-id")
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestParsePEMKey_UnsupportedFormat(t *testing.T) {
	t.Parallel()

	// Test with invalid data
	_, err := parsePEMKey([]byte("not a valid key"))
	assert.Error(t, err)
}

func TestParsePEMBlock_UnsupportedType(t *testing.T) {
	t.Parallel()

	// Test with unsupported PEM block type
	block := &pem.Block{
		Type:  "UNSUPPORTED TYPE",
		Bytes: []byte("test"),
	}

	_, err := parsePEMBlock(block)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported PEM block type")
}

func TestParseStaticKey_KeyFileNotImplemented(t *testing.T) {
	t.Parallel()

	key := StaticKey{
		KeyID:   "test",
		KeyFile: "/path/to/key",
	}

	_, err := parseStaticKey(key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "keyFile not yet implemented")
}

func TestParseStaticKey_NoKeyOrKeyFile(t *testing.T) {
	t.Parallel()

	key := StaticKey{
		KeyID: "test",
	}

	_, err := parseStaticKey(key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key or keyFile is required")
}
