package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"hash"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestConvertToASN1 tests the convertToASN1 function with various inputs.
func TestConvertToASN1(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sig     []byte
		keySize int
	}{
		{
			name:    "P-256 signature (32 bytes each)",
			sig:     make([]byte, 64),
			keySize: 32,
		},
		{
			name:    "P-384 signature (48 bytes each)",
			sig:     make([]byte, 96),
			keySize: 48,
		},
		{
			name:    "P-521 signature (66 bytes each)",
			sig:     make([]byte, 132),
			keySize: 66,
		},
		{
			name:    "signature with leading zeros",
			sig:     append(make([]byte, 32), make([]byte, 32)...),
			keySize: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Fill with some non-zero data for realistic test
			for i := range tt.sig {
				tt.sig[i] = byte(i % 256)
			}

			result := convertToASN1(tt.sig, tt.keySize)

			// Verify it's valid ASN.1 DER encoding
			assert.NotNil(t, result)
			assert.True(t, len(result) > 0)

			// First byte should be SEQUENCE tag (0x30)
			assert.Equal(t, byte(0x30), result[0])
		})
	}
}

// TestConvertToASN1_HighBitSet tests convertToASN1 when high bit is set.
func TestConvertToASN1_HighBitSet(t *testing.T) {
	t.Parallel()

	// Create signature where r and s have high bit set
	keySize := 32
	sig := make([]byte, 2*keySize)

	// Set high bit on r
	sig[0] = 0x80

	// Set high bit on s
	sig[keySize] = 0x80

	result := convertToASN1(sig, keySize)

	// Verify it's valid ASN.1 DER encoding
	assert.NotNil(t, result)
	assert.True(t, len(result) > 0)

	// First byte should be SEQUENCE tag (0x30)
	assert.Equal(t, byte(0x30), result[0])

	// The result should be longer due to padding bytes
	// Original: 64 bytes, with padding and ASN.1 overhead should be > 64
	assert.True(t, len(result) > 64)
}

// TestTrimLeadingZeros tests the trimLeadingZeros function.
func TestTrimLeadingZeros(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "no leading zeros",
			input:    []byte{0x01, 0x02, 0x03},
			expected: []byte{0x01, 0x02, 0x03},
		},
		{
			name:     "one leading zero",
			input:    []byte{0x00, 0x01, 0x02},
			expected: []byte{0x01, 0x02},
		},
		{
			name:     "multiple leading zeros",
			input:    []byte{0x00, 0x00, 0x00, 0x01},
			expected: []byte{0x01},
		},
		{
			name:     "all zeros except last",
			input:    []byte{0x00, 0x00, 0x00, 0x00},
			expected: []byte{0x00},
		},
		{
			name:     "single byte",
			input:    []byte{0x42},
			expected: []byte{0x42},
		},
		{
			name:     "single zero byte",
			input:    []byte{0x00},
			expected: []byte{0x00},
		},
		{
			name:     "empty slice",
			input:    []byte{},
			expected: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := trimLeadingZeros(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestValidator_Validate_ECDSA_Proper tests ECDSA validation with proper signature format.
func TestValidator_Validate_ECDSA_Proper(t *testing.T) {
	t.Parallel()

	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := &Config{
		Enabled:    true,
		Algorithms: []string{"ES256"},
	}

	mockKS := newMockKeySet()
	mockKS.AddKey("ec-key", &privateKey.PublicKey)

	validator, err := NewValidator(config,
		WithKeySet(mockKS),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
		"kid": "ec-key",
	}
	claimsData := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// Create ECDSA signature in raw r||s format (what JWT expects)
	signFunc := func(input string) string {
		h := sha256.New()
		h.Write([]byte(input))
		hashed := h.Sum(nil)

		// Sign and get r, s values
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
		require.NoError(t, err)

		// Convert to raw format (r || s), each padded to key size
		keySize := (privateKey.Curve.Params().BitSize + 7) / 8
		rawSig := make([]byte, 2*keySize)

		// Pad r and s to keySize bytes
		rBytes := r.Bytes()
		sBytes := s.Bytes()

		copy(rawSig[keySize-len(rBytes):keySize], rBytes)
		copy(rawSig[2*keySize-len(sBytes):], sBytes)

		return base64.RawURLEncoding.EncodeToString(rawSig)
	}

	token := createTestToken(t, header, claimsData, signFunc)

	claims, err := validator.Validate(context.Background(), token)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, "user123", claims.Subject)
}

// TestValidator_Validate_ECDSA_P384 tests ECDSA validation with P-384 curve.
func TestValidator_Validate_ECDSA_P384(t *testing.T) {
	t.Parallel()

	// Generate ECDSA key pair with P-384
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	config := &Config{
		Enabled:    true,
		Algorithms: []string{"ES384"},
	}

	mockKS := newMockKeySet()
	mockKS.AddKey("ec-key", &privateKey.PublicKey)

	validator, err := NewValidator(config,
		WithKeySet(mockKS),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	header := map[string]interface{}{
		"alg": "ES384",
		"typ": "JWT",
		"kid": "ec-key",
	}
	claimsData := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	signFunc := func(input string) string {
		h := sha512.New384()
		h.Write([]byte(input))
		hashed := h.Sum(nil)

		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
		require.NoError(t, err)

		keySize := (privateKey.Curve.Params().BitSize + 7) / 8
		rawSig := make([]byte, 2*keySize)

		rBytes := r.Bytes()
		sBytes := s.Bytes()

		copy(rawSig[keySize-len(rBytes):keySize], rBytes)
		copy(rawSig[2*keySize-len(sBytes):], sBytes)

		return base64.RawURLEncoding.EncodeToString(rawSig)
	}

	token := createTestToken(t, header, claimsData, signFunc)

	claims, err := validator.Validate(context.Background(), token)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, "user123", claims.Subject)
}

// TestValidator_Validate_ECDSA_InvalidSignatureLength tests ECDSA with invalid signature length.
func TestValidator_Validate_ECDSA_InvalidSignatureLength(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := &Config{
		Enabled:    true,
		Algorithms: []string{"ES256"},
	}

	mockKS := newMockKeySet()
	mockKS.AddKey("ec-key", &privateKey.PublicKey)

	validator, err := NewValidator(config,
		WithKeySet(mockKS),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
		"kid": "ec-key",
	}
	claimsData := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// Create signature with wrong length
	signFunc := func(input string) string {
		// Wrong length - should be 64 bytes for P-256
		wrongSig := make([]byte, 32)
		return base64.RawURLEncoding.EncodeToString(wrongSig)
	}

	token := createTestToken(t, header, claimsData, signFunc)

	claims, err := validator.Validate(context.Background(), token)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, ErrTokenInvalidSignature)
}

// TestValidator_Validate_ECDSA_InvalidKey tests ECDSA with wrong key type.
func TestValidator_Validate_ECDSA_InvalidKey(t *testing.T) {
	t.Parallel()

	// Generate RSA key instead of ECDSA
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled:    true,
		Algorithms: []string{"ES256"},
	}

	mockKS := newMockKeySet()
	// Add RSA key but claim it's for ECDSA
	mockKS.AddKey("ec-key", &rsaKey.PublicKey)

	validator, err := NewValidator(config,
		WithKeySet(mockKS),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
		"kid": "ec-key",
	}
	claimsData := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	signFunc := func(input string) string {
		// Create a dummy signature
		sig := make([]byte, 64)
		return base64.RawURLEncoding.EncodeToString(sig)
	}

	token := createTestToken(t, header, claimsData, signFunc)

	claims, err := validator.Validate(context.Background(), token)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, ErrInvalidKey)
}

// TestValidator_Validate_RSA_PSS tests RSA-PSS signature verification.
func TestValidator_Validate_RSA_PSS(t *testing.T) {
	t.Parallel()

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name    string
		alg     string
		hashAlg crypto.Hash
	}{
		{
			name:    "PS256",
			alg:     "PS256",
			hashAlg: crypto.SHA256,
		},
		{
			name:    "PS384",
			alg:     "PS384",
			hashAlg: crypto.SHA384,
		},
		{
			name:    "PS512",
			alg:     "PS512",
			hashAlg: crypto.SHA512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := &Config{
				Enabled:    true,
				Algorithms: []string{tt.alg},
			}

			mockKS := newMockKeySet()
			mockKS.AddKey("rsa-key", &privateKey.PublicKey)

			validator, err := NewValidator(config,
				WithKeySet(mockKS),
				WithValidatorLogger(observability.NopLogger()),
			)
			require.NoError(t, err)

			header := map[string]interface{}{
				"alg": tt.alg,
				"typ": "JWT",
				"kid": "rsa-key",
			}
			claimsData := map[string]interface{}{
				"sub": "user123",
				"exp": time.Now().Add(time.Hour).Unix(),
			}

			signFunc := func(input string) string {
				h := tt.hashAlg.New()
				h.Write([]byte(input))
				hashed := h.Sum(nil)

				opts := &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
					Hash:       tt.hashAlg,
				}

				signature, err := rsa.SignPSS(rand.Reader, privateKey, tt.hashAlg, hashed, opts)
				require.NoError(t, err)
				return base64.RawURLEncoding.EncodeToString(signature)
			}

			token := createTestToken(t, header, claimsData, signFunc)

			claims, err := validator.Validate(context.Background(), token)
			require.NoError(t, err)
			assert.NotNil(t, claims)
			assert.Equal(t, "user123", claims.Subject)
		})
	}
}

// TestValidator_Validate_RSA_PSS_InvalidKey tests RSA-PSS with wrong key type.
func TestValidator_Validate_RSA_PSS_InvalidKey(t *testing.T) {
	t.Parallel()

	// Generate ECDSA key instead of RSA
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := &Config{
		Enabled:    true,
		Algorithms: []string{"PS256"},
	}

	mockKS := newMockKeySet()
	// Add ECDSA key but claim it's for RSA-PSS
	mockKS.AddKey("rsa-key", &ecKey.PublicKey)

	validator, err := NewValidator(config,
		WithKeySet(mockKS),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	header := map[string]interface{}{
		"alg": "PS256",
		"typ": "JWT",
		"kid": "rsa-key",
	}
	claimsData := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	signFunc := func(input string) string {
		// Create a dummy signature
		sig := make([]byte, 256)
		return base64.RawURLEncoding.EncodeToString(sig)
	}

	token := createTestToken(t, header, claimsData, signFunc)

	claims, err := validator.Validate(context.Background(), token)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, ErrInvalidKey)
}

// TestValidator_Validate_RSA_InvalidKey tests RSA with wrong key type.
func TestValidator_Validate_RSA_InvalidKey(t *testing.T) {
	t.Parallel()

	// Generate ECDSA key instead of RSA
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := &Config{
		Enabled:    true,
		Algorithms: []string{"RS256"},
	}

	mockKS := newMockKeySet()
	// Add ECDSA key but claim it's for RSA
	mockKS.AddKey("rsa-key", &ecKey.PublicKey)

	validator, err := NewValidator(config,
		WithKeySet(mockKS),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "rsa-key",
	}
	claimsData := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	signFunc := func(input string) string {
		sig := make([]byte, 256)
		return base64.RawURLEncoding.EncodeToString(sig)
	}

	token := createTestToken(t, header, claimsData, signFunc)

	claims, err := validator.Validate(context.Background(), token)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, ErrInvalidKey)
}

// TestValidator_Validate_HMAC_InvalidKey tests HMAC with wrong key type.
func TestValidator_Validate_HMAC_InvalidKey(t *testing.T) {
	t.Parallel()

	// Generate RSA key instead of byte slice
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled:    true,
		Algorithms: []string{"HS256"},
	}

	mockKS := newMockKeySet()
	// Add RSA key but claim it's for HMAC
	mockKS.AddKey("hmac-key", &rsaKey.PublicKey)

	validator, err := NewValidator(config,
		WithKeySet(mockKS),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"kid": "hmac-key",
	}
	claimsData := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	signFunc := func(input string) string {
		sig := make([]byte, 32)
		return base64.RawURLEncoding.EncodeToString(sig)
	}

	token := createTestToken(t, header, claimsData, signFunc)

	claims, err := validator.Validate(context.Background(), token)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, ErrInvalidKey)
}

// TestValidator_Validate_EdDSA_InvalidKey tests EdDSA with wrong key type.
func TestValidator_Validate_EdDSA_InvalidKey(t *testing.T) {
	t.Parallel()

	// Generate RSA key instead of Ed25519
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled:    true,
		Algorithms: []string{"EdDSA"},
	}

	mockKS := newMockKeySet()
	// Add RSA key but claim it's for EdDSA
	mockKS.AddKey("ed-key", &rsaKey.PublicKey)

	validator, err := NewValidator(config,
		WithKeySet(mockKS),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	header := map[string]interface{}{
		"alg": "EdDSA",
		"typ": "JWT",
		"kid": "ed-key",
	}
	claimsData := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	signFunc := func(input string) string {
		sig := make([]byte, 64)
		return base64.RawURLEncoding.EncodeToString(sig)
	}

	token := createTestToken(t, header, claimsData, signFunc)

	claims, err := validator.Validate(context.Background(), token)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, ErrInvalidKey)
}

// TestValidator_Validate_UnsupportedAlgorithm tests validation with unsupported algorithm.
func TestValidator_Validate_UnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	secret := []byte("test-secret-key-32-bytes-long!!!")

	config := &Config{
		Enabled:    true,
		Algorithms: []string{}, // Allow all algorithms
	}

	mockKS := newMockKeySet()
	mockKS.AddKey("key1", secret)

	validator, err := NewValidator(config,
		WithKeySet(mockKS),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	header := map[string]interface{}{
		"alg": "UNKNOWN",
		"typ": "JWT",
		"kid": "key1",
	}
	claimsData := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	signFunc := func(input string) string {
		return base64.RawURLEncoding.EncodeToString([]byte("dummy"))
	}

	token := createTestToken(t, header, claimsData, signFunc)

	claims, err := validator.Validate(context.Background(), token)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

// TestValidator_Validate_InvalidSignatureBase64 tests validation with invalid base64 signature.
func TestValidator_Validate_InvalidSignatureBase64(t *testing.T) {
	t.Parallel()

	secret := []byte("test-secret-key-32-bytes-long!!!")

	config := &Config{
		Enabled:    true,
		Algorithms: []string{"HS256"},
	}

	mockKS := newMockKeySet()
	mockKS.AddKey("key1", secret)

	validator, err := NewValidator(config,
		WithKeySet(mockKS),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"kid": "key1",
	}
	claimsData := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// Create token with invalid base64 signature
	signFunc := func(input string) string {
		return "!!!invalid-base64!!!"
	}

	token := createTestToken(t, header, claimsData, signFunc)

	claims, err := validator.Validate(context.Background(), token)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

// TestValidator_Validate_RSA_AllVariants tests all RSA variants.
func TestValidator_Validate_RSA_AllVariants(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name    string
		alg     string
		hashAlg crypto.Hash
	}{
		{
			name:    "RS256",
			alg:     "RS256",
			hashAlg: crypto.SHA256,
		},
		{
			name:    "RS384",
			alg:     "RS384",
			hashAlg: crypto.SHA384,
		},
		{
			name:    "RS512",
			alg:     "RS512",
			hashAlg: crypto.SHA512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := &Config{
				Enabled:    true,
				Algorithms: []string{tt.alg},
			}

			mockKS := newMockKeySet()
			mockKS.AddKey("rsa-key", &privateKey.PublicKey)

			validator, err := NewValidator(config,
				WithKeySet(mockKS),
				WithValidatorLogger(observability.NopLogger()),
			)
			require.NoError(t, err)

			header := map[string]interface{}{
				"alg": tt.alg,
				"typ": "JWT",
				"kid": "rsa-key",
			}
			claimsData := map[string]interface{}{
				"sub": "user123",
				"exp": time.Now().Add(time.Hour).Unix(),
			}

			signFunc := func(input string) string {
				h := tt.hashAlg.New()
				h.Write([]byte(input))
				hashed := h.Sum(nil)

				signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, tt.hashAlg, hashed)
				require.NoError(t, err)
				return base64.RawURLEncoding.EncodeToString(signature)
			}

			token := createTestToken(t, header, claimsData, signFunc)

			claims, err := validator.Validate(context.Background(), token)
			require.NoError(t, err)
			assert.NotNil(t, claims)
			assert.Equal(t, "user123", claims.Subject)
		})
	}
}

// TestValidator_Validate_HMAC_AllVariants tests all HMAC variants.
func TestValidator_Validate_HMAC_AllVariants(t *testing.T) {
	t.Parallel()

	secret := []byte("test-secret-key-32-bytes-long!!!")

	tests := []struct {
		name     string
		alg      string
		hashFunc func() []byte
	}{
		{
			name: "HS256",
			alg:  "HS256",
		},
		{
			name: "HS384",
			alg:  "HS384",
		},
		{
			name: "HS512",
			alg:  "HS512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := &Config{
				Enabled:    true,
				Algorithms: []string{tt.alg},
			}

			mockKS := newMockKeySet()
			mockKS.AddKey("hmac-key", secret)

			validator, err := NewValidator(config,
				WithKeySet(mockKS),
				WithValidatorLogger(observability.NopLogger()),
			)
			require.NoError(t, err)

			header := map[string]interface{}{
				"alg": tt.alg,
				"typ": "JWT",
				"kid": "hmac-key",
			}
			claimsData := map[string]interface{}{
				"sub": "user123",
				"exp": time.Now().Add(time.Hour).Unix(),
			}

			var signFunc func(string) string
			switch tt.alg {
			case "HS256":
				signFunc = createHMACSignature(secret)
			case "HS384":
				signFunc = createHMAC384Signature(secret)
			case "HS512":
				signFunc = createHMAC512Signature(secret)
			}

			token := createTestToken(t, header, claimsData, signFunc)

			claims, err := validator.Validate(context.Background(), token)
			require.NoError(t, err)
			assert.NotNil(t, claims)
			assert.Equal(t, "user123", claims.Subject)
		})
	}
}

// Helper function to create HMAC-SHA384 signature.
func createHMAC384Signature(secret []byte) func(string) string {
	return func(input string) string {
		mac := hmacNew(sha512.New384, secret)
		mac.Write([]byte(input))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
}

// Helper function to create HMAC-SHA512 signature.
func createHMAC512Signature(secret []byte) func(string) string {
	return func(input string) string {
		mac := hmacNew(sha512.New, secret)
		mac.Write([]byte(input))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
}

// hmacNew creates a new HMAC hash using crypto/hmac.
func hmacNew(h func() hash.Hash, key []byte) hash.Hash {
	return hmac.New(h, key)
}

// ecdsaSignature represents an ECDSA signature for ASN.1 parsing.
type ecdsaSignature struct {
	R, S *big.Int
}

// TestConvertToASN1_RoundTrip tests that convertToASN1 produces valid ASN.1.
func TestConvertToASN1_RoundTrip(t *testing.T) {
	t.Parallel()

	// Create a known r and s using string parsing to avoid overflow
	r, _ := new(big.Int).SetString("12345678901234567890", 10)
	s, _ := new(big.Int).SetString("98765432109876543210", 10)

	// Pad to 32 bytes each (P-256 key size)
	keySize := 32
	rawSig := make([]byte, 2*keySize)

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	copy(rawSig[keySize-len(rBytes):keySize], rBytes)
	copy(rawSig[2*keySize-len(sBytes):], sBytes)

	// Convert to ASN.1
	asn1Sig := convertToASN1(rawSig, keySize)

	// Parse the ASN.1 signature
	var sig ecdsaSignature
	_, err := asn1.Unmarshal(asn1Sig, &sig)
	require.NoError(t, err)

	// Verify the values match
	assert.Equal(t, 0, r.Cmp(sig.R))
	assert.Equal(t, 0, s.Cmp(sig.S))
}
