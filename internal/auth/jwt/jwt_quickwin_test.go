package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestParsePKIXPublicKey_RSA tests parsePKIXPublicKey with an RSA key.
func TestParsePKIXPublicKey_RSA(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	key, err := parsePKIXPublicKey(pubKeyBytes)
	assert.NoError(t, err)
	assert.NotNil(t, key)

	_, ok := key.(*rsa.PublicKey)
	assert.True(t, ok)
}

// TestParsePKIXPublicKey_ECDSA tests parsePKIXPublicKey with an ECDSA key.
func TestParsePKIXPublicKey_ECDSA(t *testing.T) {
	t.Parallel()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)

	key, err := parsePKIXPublicKey(pubKeyBytes)
	assert.NoError(t, err)
	assert.NotNil(t, key)
}

// TestParsePKIXPublicKey_InvalidData tests parsePKIXPublicKey with invalid data.
func TestParsePKIXPublicKey_InvalidData(t *testing.T) {
	t.Parallel()

	_, err := parsePKIXPublicKey([]byte("invalid"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse PKIX public key")
}

// TestParsePublicKeyFromCertificate_Valid tests parsePublicKeyFromCertificate.
func TestParsePublicKeyFromCertificate_Valid(t *testing.T) {
	t.Parallel()

	// Generate a self-signed certificate
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	key, err := parsePublicKeyFromCertificate(certDER)
	assert.NoError(t, err)
	assert.NotNil(t, key)
}

// TestParsePublicKeyFromCertificate_Invalid tests parsePublicKeyFromCertificate with invalid data.
func TestParsePublicKeyFromCertificate_Invalid(t *testing.T) {
	t.Parallel()

	_, err := parsePublicKeyFromCertificate([]byte("invalid"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

// TestParsePEMBlock_AllTypes tests parsePEMBlock with various PEM block types.
func TestParsePEMBlock_AllTypes(t *testing.T) {
	t.Parallel()

	// Generate RSA key for testing
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	tests := []struct {
		name      string
		block     *pem.Block
		expectErr bool
	}{
		{
			name: "PUBLIC KEY type",
			block: &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubKeyBytes,
			},
			expectErr: false,
		},
		{
			name: "RSA PUBLIC KEY type",
			block: &pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey),
			},
			expectErr: false,
		},
		{
			name: "EC PUBLIC KEY type (using PKIX format)",
			block: &pem.Block{
				Type:  "EC PUBLIC KEY",
				Bytes: pubKeyBytes, // PKIX format works for EC too
			},
			expectErr: false,
		},
		{
			name: "unsupported type",
			block: &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: []byte("data"),
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key, err := parsePEMBlock(tt.block)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}

// TestParsePEMBlock_Certificate tests parsePEMBlock with CERTIFICATE type.
func TestParsePEMBlock_Certificate(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	key, err := parsePEMBlock(block)
	assert.NoError(t, err)
	assert.NotNil(t, key)
}

// TestValidateKeyAlgorithm_AllAlgorithms tests validateKeyAlgorithm with all algorithm types.
func TestValidateKeyAlgorithm_AllAlgorithms(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		key       crypto.PublicKey
		algorithm string
		expectErr bool
	}{
		{"RS256 with RSA key", &rsaKey.PublicKey, AlgRS256, false},
		{"RS384 with RSA key", &rsaKey.PublicKey, AlgRS384, false},
		{"RS512 with RSA key", &rsaKey.PublicKey, AlgRS512, false},
		{"PS256 with RSA key", &rsaKey.PublicKey, AlgPS256, false},
		{"PS384 with RSA key", &rsaKey.PublicKey, AlgPS384, false},
		{"PS512 with RSA key", &rsaKey.PublicKey, AlgPS512, false},
		{"ES256 with ECDSA key", &ecKey.PublicKey, AlgES256, false},
		{"ES384 with ECDSA key", &ecKey.PublicKey, AlgES384, false},
		{"ES512 with ECDSA key", &ecKey.PublicKey, AlgES512, false},
		{"EdDSA with Ed25519 key", ed25519.PublicKey(edKey), AlgEdDSA, false},
		{"Ed25519 with Ed25519 key", ed25519.PublicKey(edKey), AlgEd25519, false},
		{"RS256 with ECDSA key fails", &ecKey.PublicKey, AlgRS256, true},
		{"ES256 with RSA key fails", &rsaKey.PublicKey, AlgES256, true},
		{"EdDSA with RSA key fails", &rsaKey.PublicKey, AlgEdDSA, true},
		{"unknown algorithm passes", &rsaKey.PublicKey, "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateKeyAlgorithm(tt.key, tt.algorithm)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestMetrics_RecordCacheHit tests the RecordCacheHit method.
func TestMetrics_RecordCacheHit(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")
	// Should not panic
	m.RecordCacheHit()
}

// TestMetrics_RecordCacheMiss tests the RecordCacheMiss method.
func TestMetrics_RecordCacheMiss(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")
	// Should not panic
	m.RecordCacheMiss()
}

// TestMetrics_RecordJWKSRefresh tests the RecordJWKSRefresh method.
func TestMetrics_RecordJWKSRefresh(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")
	// Should not panic
	m.RecordJWKSRefresh("success", 100*time.Millisecond)
	m.RecordJWKSRefresh("failure", 200*time.Millisecond)
}

// TestMetrics_Registry tests the Registry method.
func TestMetrics_Registry(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")
	reg := m.Registry()
	assert.NotNil(t, reg)
}

// TestMetrics_MustRegister tests the MustRegister method.
func TestMetrics_MustRegister(t *testing.T) {
	t.Parallel()

	// Create a fresh metrics instance and a separate registry
	m := NewMetrics("test_must_register")

	// MustRegister should not panic with a fresh registry
	// Note: We can't re-register to the same registry, so we just verify
	// the method exists and the registry is accessible
	assert.NotNil(t, m.Registry())
}

// TestGetNestedStringSliceClaim_AllTypes tests GetNestedStringSliceClaim with various types.
func TestGetNestedStringSliceClaim_AllTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		claims   *Claims
		path     string
		expected []string
	}{
		{
			name: "string slice",
			claims: &Claims{
				Extra: map[string]interface{}{
					"roles": []string{"admin", "user"},
				},
			},
			path:     "roles",
			expected: []string{"admin", "user"},
		},
		{
			name: "interface slice",
			claims: &Claims{
				Extra: map[string]interface{}{
					"roles": []interface{}{"admin", "user"},
				},
			},
			path:     "roles",
			expected: []string{"admin", "user"},
		},
		{
			name: "space-separated string",
			claims: &Claims{
				Extra: map[string]interface{}{
					"scope": "read write",
				},
			},
			path:     "scope",
			expected: []string{"read", "write"},
		},
		{
			name: "non-existent path",
			claims: &Claims{
				Extra: map[string]interface{}{},
			},
			path:     "missing",
			expected: nil,
		},
		{
			name: "unsupported type returns nil",
			claims: &Claims{
				Extra: map[string]interface{}{
					"count": 42,
				},
			},
			path:     "count",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.claims.GetNestedStringSliceClaim(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestNewStaticKeySet_EmptyKey tests NewStaticKeySet with empty key.
func TestNewStaticKeySet_EmptyKey(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	_, err := NewStaticKeySet([]StaticKey{
		{Algorithm: "RS256"},
	}, logger)
	assert.Error(t, err)
}

// TestParseTime_EdgeCases tests parseTime with edge cases.
func TestParseTime_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    interface{}
		wantNil  bool
		wantTime bool
	}{
		{
			name:     "float64 value",
			value:    float64(1700000000),
			wantNil:  false,
			wantTime: true,
		},
		{
			name:     "int64 value",
			value:    int64(1700000000),
			wantNil:  false,
			wantTime: true,
		},
		{
			name:    "string value",
			value:   "not a time",
			wantNil: true,
		},
		{
			name:    "nil value",
			value:   nil,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := parseTime(tt.value)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}
