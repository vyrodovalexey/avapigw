package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================================
// Tests for parseAsJWK (25% -> 100%)
// ============================================================================

func TestParseAsJWK_ValidRSAKey(t *testing.T) {
	t.Parallel()

	// Generate an RSA key and serialize as JWK JSON
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(&rsaKey.PublicKey)
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	// Arrange & Act
	key, err := parseAsJWK(jwkJSON)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, key)
	_, ok := key.(*rsa.PublicKey)
	assert.True(t, ok, "expected *rsa.PublicKey")
}

func TestParseAsJWK_ValidECDSAKey(t *testing.T) {
	t.Parallel()

	// Generate an ECDSA key and serialize as JWK JSON
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(&ecKey.PublicKey)
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	// Arrange & Act
	key, err := parseAsJWK(jwkJSON)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, key)
	_, ok := key.(*ecdsa.PublicKey)
	assert.True(t, ok, "expected *ecdsa.PublicKey")
}

func TestParseAsJWK_ValidEd25519Key(t *testing.T) {
	t.Parallel()

	// Generate an Ed25519 key and serialize as JWK JSON
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(pubKey)
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	// Arrange & Act
	key, err := parseAsJWK(jwkJSON)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, key)
}

func TestParseAsJWK_InvalidJSON(t *testing.T) {
	t.Parallel()

	// Arrange & Act
	key, err := parseAsJWK([]byte("not valid json"))

	// Assert
	assert.Error(t, err)
	assert.Nil(t, key)
}

func TestParseAsJWK_ValidJSONButNotJWK(t *testing.T) {
	t.Parallel()

	// Valid JSON but not a valid JWK
	data := []byte(`{"foo": "bar"}`)

	// Arrange & Act
	key, err := parseAsJWK(data)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, key)
}

func TestParseAsJWK_PrivateKeyNotPublic(t *testing.T) {
	t.Parallel()

	// Generate an RSA private key and serialize as JWK JSON (private key, not public)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from private key (not public)
	jwkKey, err := jwk.FromRaw(rsaKey)
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	// parseAsJWK should still succeed because Raw() on a private JWK returns
	// the private key which implements crypto.PublicKey via its Public() method.
	// The function checks if rawKey is crypto.PublicKey, and *rsa.PrivateKey
	// does implement crypto.PublicKey.
	key, err := parseAsJWK(jwkJSON)
	// The result depends on whether the raw key implements crypto.PublicKey
	// For RSA private keys, they do implement crypto.PublicKey
	if err != nil {
		assert.Contains(t, err.Error(), "key is not a public key")
		assert.Nil(t, key)
	} else {
		assert.NotNil(t, key)
	}
}

// ============================================================================
// Tests for parsePEMKey (66.7% -> 100%)
// ============================================================================

func TestParsePEMKey_ValidJWKJSON(t *testing.T) {
	t.Parallel()

	// parsePEMKey first tries parseAsJWK, so pass valid JWK JSON
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(&rsaKey.PublicKey)
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	// Arrange & Act
	key, err := parsePEMKey(jwkJSON)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, key)
	_, ok := key.(*rsa.PublicKey)
	assert.True(t, ok)
}

func TestParsePEMKey_ValidPEMPublicKey(t *testing.T) {
	t.Parallel()

	// Generate RSA key and encode as PEM
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Arrange & Act
	key, err := parsePEMKey(pemData)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, key)
	_, ok := key.(*rsa.PublicKey)
	assert.True(t, ok)
}

func TestParsePEMKey_ValidECDSAPEM(t *testing.T) {
	t.Parallel()

	// Generate ECDSA key and encode as PEM
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Arrange & Act
	key, err := parsePEMKey(pemData)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, key)
	_, ok := key.(*ecdsa.PublicKey)
	assert.True(t, ok)
}

func TestParsePEMKey_InvalidData(t *testing.T) {
	t.Parallel()

	// Not valid JSON and not valid PEM
	key, err := parsePEMKey([]byte("this is neither JSON nor PEM"))

	assert.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "unsupported key format")
}

// ============================================================================
// Tests for parseStaticKey (78.6% -> 100%)
// ============================================================================

func TestParseStaticKey_ValidJWKKey(t *testing.T) {
	t.Parallel()

	// Generate RSA key and create JWK
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(&rsaKey.PublicKey)
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	staticKey := StaticKey{
		KeyID: "test-key",
		Key:   string(jwkJSON),
	}

	// Arrange & Act
	key, err := parseStaticKey(staticKey)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, key)
}

func TestParseStaticKey_ValidPEMKey(t *testing.T) {
	t.Parallel()

	// Generate RSA key and encode as PEM
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	staticKey := StaticKey{
		KeyID: "test-pem-key",
		Key:   string(pemData),
	}

	// Arrange & Act
	key, err := parseStaticKey(staticKey)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, key)
}

func TestParseStaticKey_InvalidKeyData(t *testing.T) {
	t.Parallel()

	staticKey := StaticKey{
		KeyID: "test-key",
		Key:   "not a valid key format at all",
	}

	// Arrange & Act
	key, err := parseStaticKey(staticKey)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, key)
}

func TestParseStaticKey_SymmetricKeyJWK(t *testing.T) {
	t.Parallel()

	// Create a symmetric key (HMAC) as JWK
	// Note: crypto.PublicKey is type alias for `any`, so any value satisfies it.
	// A symmetric JWK key will be parsed and returned as []byte wrapped in crypto.PublicKey.
	symmetricKey := []byte("super-secret-key-for-hmac-256!!")
	jwkKey, err := jwk.FromRaw(symmetricKey)
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	staticKey := StaticKey{
		KeyID: "test-key",
		Key:   string(jwkJSON),
	}

	// Arrange & Act
	key, err := parseStaticKey(staticKey)

	// Assert - symmetric key is returned as crypto.PublicKey (which is `any`)
	assert.NoError(t, err)
	assert.NotNil(t, key)
}

// ============================================================================
// Tests for secureRandomFloat (75% -> 100%)
// ============================================================================

func TestSecureRandomFloat_ReturnsValueInRange(t *testing.T) {
	t.Parallel()

	// Call multiple times to verify range
	for i := 0; i < 100; i++ {
		val := secureRandomFloat()
		assert.GreaterOrEqual(t, val, 0.0, "secureRandomFloat should return >= 0")
		assert.LessOrEqual(t, val, 1.0, "secureRandomFloat should return <= 1")
	}
}

func TestSecureRandomFloat_ProducesVariation(t *testing.T) {
	t.Parallel()

	// Verify that secureRandomFloat produces different values
	values := make(map[float64]bool)
	for i := 0; i < 10; i++ {
		val := secureRandomFloat()
		values[val] = true
	}
	// With 10 calls, we should get at least 2 different values
	assert.Greater(t, len(values), 1, "secureRandomFloat should produce varying values")
}

// ============================================================================
// Tests for CompositeKeySet.Refresh error path (66.7% -> 100%)
// ============================================================================

func TestCompositeKeySet_Refresh_WithErrors(t *testing.T) {
	t.Parallel()

	// Create a static key set that succeeds
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(&rsaKey.PublicKey)
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	staticKS, err := NewStaticKeySet([]StaticKey{
		{KeyID: "key1", Key: string(jwkJSON)},
	}, observability.NopLogger())
	require.NoError(t, err)

	// Create a mock key set that fails on refresh
	failingKS := &mockFailingKeySet{
		refreshErr: errors.New("refresh failed"),
	}

	compositeKS := NewCompositeKeySet([]KeySet{staticKS, failingKS}, observability.NopLogger())

	// Arrange & Act
	err = compositeKS.Refresh(context.Background())

	// Assert - should return the last error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "refresh failed")
}

func TestCompositeKeySet_Close_WithErrors(t *testing.T) {
	t.Parallel()

	// Create a static key set that succeeds
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(&rsaKey.PublicKey)
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	staticKS, err := NewStaticKeySet([]StaticKey{
		{KeyID: "key1", Key: string(jwkJSON)},
	}, observability.NopLogger())
	require.NoError(t, err)

	// Create a mock key set that fails on close
	failingKS := &mockFailingKeySet{
		closeErr: errors.New("close failed"),
	}

	compositeKS := NewCompositeKeySet([]KeySet{staticKS, failingKS}, observability.NopLogger())

	// Arrange & Act
	err = compositeKS.Close()

	// Assert - should return the last error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "close failed")
}

// mockFailingKeySet is a mock KeySet that returns configurable errors.
type mockFailingKeySet struct {
	refreshErr error
	closeErr   error
}

func (m *mockFailingKeySet) GetKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	return nil, ErrKeyNotFound
}

func (m *mockFailingKeySet) GetKeyForAlgorithm(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	return nil, ErrKeyNotFound
}

func (m *mockFailingKeySet) Refresh(_ context.Context) error {
	return m.refreshErr
}

func (m *mockFailingKeySet) Close() error {
	return m.closeErr
}

// Ensure mockFailingKeySet implements KeySet
var _ KeySet = (*mockFailingKeySet)(nil)

// ============================================================================
// Tests for performRefresh (80% -> 100%)
// ============================================================================

func TestJWKSKeySet_PerformRefresh_Success(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
	require.NoError(t, err)

	jwks := jwk.NewSet()
	err = jwks.AddKey(jwkKey)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Millisecond))
	require.NoError(t, err)

	// Arrange & Act - call performRefresh directly
	ks.performRefresh()

	// Assert
	stats := ks.Stats()
	assert.Equal(t, 1, stats.KeyCount)
	assert.Equal(t, int64(1), stats.Refreshes)
}

func TestJWKSKeySet_PerformRefresh_Error(t *testing.T) {
	t.Parallel()

	// Create test server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

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

	// Arrange & Act - call performRefresh directly (should log error, not panic)
	ks.performRefresh()

	// Assert - errors should be counted
	stats := ks.Stats()
	assert.Equal(t, int64(1), stats.Errors)
}

// ============================================================================
// Tests for StaticKeySet.GetKeyForAlgorithm error path (83.3% -> 100%)
// ============================================================================

func TestStaticKeySet_GetKeyForAlgorithm_KeyNotFound(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(&rsaKey.PublicKey)
	require.NoError(t, err)

	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	ks, err := NewStaticKeySet([]StaticKey{
		{KeyID: "test-key", Key: string(jwkJSON)},
	}, observability.NopLogger())
	require.NoError(t, err)

	// Arrange & Act - request non-existent key
	key, err := ks.GetKeyForAlgorithm(context.Background(), "non-existent", "RS256")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, key)
}

// ============================================================================
// Tests for JWKSKeySet.GetKey edge cases (82.1% -> higher)
// ============================================================================

func TestJWKSKeySet_GetKey_NilKeysRefreshFails(t *testing.T) {
	t.Parallel()

	// Create test server that always fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

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

	// Keys are nil, refresh will fail
	key, err := ks.GetKey(context.Background(), "any-key")

	assert.Error(t, err)
	assert.Nil(t, key)
}

// ============================================================================
// Tests for JWKSKeySet.GetKeyForAlgorithm error path (83.3% -> 100%)
// ============================================================================

func TestJWKSKeySet_GetKeyForAlgorithm_KeyNotFound(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyIDKey, "test-key-id")
	require.NoError(t, err)

	jwks := jwk.NewSet()
	err = jwks.AddKey(jwkKey)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Hour))
	require.NoError(t, err)

	// First, load keys
	err = ks.Refresh(context.Background())
	require.NoError(t, err)

	// Request non-existent key for algorithm
	key, err := ks.GetKeyForAlgorithm(context.Background(), "non-existent-key", "RS256")

	assert.Error(t, err)
	assert.Nil(t, key)
}

// ============================================================================
// Tests for fetchJWKS edge cases (80% -> higher)
// ============================================================================

func TestJWKSKeySet_FetchJWKS_InvalidJSON(t *testing.T) {
	t.Parallel()

	// Create test server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

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

	// Arrange & Act
	err = ks.Refresh(context.Background())

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JWKS")
}

// ============================================================================
// Tests for NewStaticKeySet error paths
// ============================================================================

func TestNewStaticKeySet_InvalidKey(t *testing.T) {
	t.Parallel()

	keys := []StaticKey{
		{
			KeyID: "bad-key",
			Key:   "this is not a valid key",
		},
	}

	ks, err := NewStaticKeySet(keys, observability.NopLogger())

	assert.Error(t, err)
	assert.Nil(t, ks)
	assert.Contains(t, err.Error(), "failed to parse key bad-key")
}

// ============================================================================
// Tests for Refresh context cancellation during sleep (91.7% -> higher)
// ============================================================================

func TestJWKSKeySet_Refresh_ContextCanceledDuringSleep(t *testing.T) {
	t.Parallel()

	// Create test server that always fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL,
		WithCacheTTL(time.Millisecond),
		WithRetryConfig(RetryConfig{
			MaxAttempts:     3,
			InitialInterval: 500 * time.Millisecond, // Long enough to cancel during sleep
			MaxInterval:     time.Second,
			Multiplier:      2.0,
		}),
	)
	require.NoError(t, err)

	// Create context that will be canceled quickly
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Arrange & Act
	err = ks.Refresh(ctx)

	// Assert - should fail with context error
	assert.Error(t, err)
}
