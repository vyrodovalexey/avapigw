package jwt

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Helper function to create a test RSA key pair
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// Helper function to create a test JWKS from an RSA public key
func createTestJWKS(t *testing.T, key *rsa.PublicKey, kid string) []byte {
	t.Helper()
	jwks := JSONWebKeySet{
		Keys: []JSONWebKey{
			{
				Kty: "RSA",
				Kid: kid,
				Alg: "RS256",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			},
		},
	}
	data, err := json.Marshal(jwks)
	require.NoError(t, err)
	return data
}

// Helper function to create a test JWT token
func createTestToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()

	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}

	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64

	// Sign with SHA256
	hash := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	require.NoError(t, err)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	assert.Equal(t, time.Hour, cfg.JWKSCacheTTL)
	assert.Equal(t, []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}, cfg.Algorithms)
	assert.Equal(t, time.Minute, cfg.ClockSkew)
}

func TestNewValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *Config
		logger *zap.Logger
	}{
		{
			name:   "With nil config",
			config: nil,
			logger: zap.NewNop(),
		},
		{
			name:   "With nil logger",
			config: DefaultConfig(),
			logger: nil,
		},
		{
			name: "With custom config",
			config: &Config{
				Issuer:       "https://issuer.example.com",
				Audiences:    []string{"api"},
				Algorithms:   []string{"RS256"},
				ClockSkew:    2 * time.Minute,
				JWKSCacheTTL: 30 * time.Minute,
			},
			logger: zap.NewNop(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			validator, err := NewValidator(tt.config, tt.logger)
			require.NoError(t, err)
			assert.NotNil(t, validator)
		})
	}
}

func TestNewValidator_WithLocalJWKS(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	jwksData := createTestJWKS(t, &key.PublicKey, "test-key")

	config := &Config{
		LocalJWKS:  jwksData,
		Algorithms: []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)
	assert.NotNil(t, validator)
	assert.NotNil(t, validator.localJWKS)
}

func TestNewValidator_WithInvalidLocalJWKS(t *testing.T) {
	t.Parallel()

	config := &Config{
		LocalJWKS:  []byte("invalid json"),
		Algorithms: []string{"RS256"},
	}

	_, err := NewValidator(config, zap.NewNop())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse local JWKS")
}

func TestNewValidator_WithJWKSURL(t *testing.T) {
	t.Parallel()

	config := &Config{
		JWKSURL:      "https://example.com/.well-known/jwks.json",
		JWKSCacheTTL: time.Hour,
		Algorithms:   []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)
	assert.NotNil(t, validator)
	assert.NotNil(t, validator.jwksCache)
}

func TestValidator_parseToken(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator(nil, zap.NewNop())
	require.NoError(t, err)

	// Create a valid base64url encoded signature for testing
	validSig := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))

	tests := []struct {
		name      string
		token     string
		wantError error
	}{
		{
			name:      "Valid token structure",
			token:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + validSig,
			wantError: nil,
		},
		{
			name:      "Missing parts",
			token:     "header.payload",
			wantError: ErrMalformedToken,
		},
		{
			name:      "Too many parts",
			token:     "header.payload.signature.extra",
			wantError: ErrMalformedToken,
		},
		{
			name:      "Invalid header encoding",
			token:     "!!!.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			wantError: ErrMalformedToken,
		},
		{
			name:      "Invalid payload encoding",
			token:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.!!!.signature",
			wantError: ErrMalformedToken,
		},
		{
			name:      "Invalid header JSON",
			token:     base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			wantError: ErrMalformedToken,
		},
		{
			name:      "Invalid payload JSON",
			token:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".signature",
			wantError: ErrMalformedToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, err := validator.parseToken(tt.token)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_validateClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    *Config
		claims    *Claims
		wantError error
	}{
		{
			name: "Valid claims",
			config: &Config{
				Issuer:    "https://issuer.example.com",
				Audiences: []string{"api"},
			},
			claims: &Claims{
				Issuer:    "https://issuer.example.com",
				Audience:  Audience{"api"},
				ExpiresAt: &Time{Time: time.Now().Add(time.Hour)},
				NotBefore: &Time{Time: time.Now().Add(-time.Hour)},
			},
			wantError: nil,
		},
		{
			name: "Expired token",
			config: &Config{
				ClockSkew: time.Minute,
			},
			claims: &Claims{
				ExpiresAt: &Time{Time: time.Now().Add(-2 * time.Minute)},
			},
			wantError: ErrTokenExpired,
		},
		{
			name: "Token not yet valid",
			config: &Config{
				ClockSkew: time.Minute,
			},
			claims: &Claims{
				NotBefore: &Time{Time: time.Now().Add(2 * time.Minute)},
			},
			wantError: ErrTokenNotYetValid,
		},
		{
			name: "Invalid issuer",
			config: &Config{
				Issuer: "https://expected-issuer.example.com",
			},
			claims: &Claims{
				Issuer: "https://wrong-issuer.example.com",
			},
			wantError: ErrInvalidIssuer,
		},
		{
			name: "Invalid audience",
			config: &Config{
				Audiences: []string{"expected-audience"},
			},
			claims: &Claims{
				Audience: Audience{"wrong-audience"},
			},
			wantError: ErrInvalidAudience,
		},
		{
			name: "Valid with multiple audiences",
			config: &Config{
				Audiences: []string{"api", "web"},
			},
			claims: &Claims{
				Audience: Audience{"web"},
			},
			wantError: nil,
		},
		{
			name: "No issuer validation when not configured",
			config: &Config{
				Issuer: "",
			},
			claims: &Claims{
				Issuer: "any-issuer",
			},
			wantError: nil,
		},
		{
			name: "No audience validation when not configured",
			config: &Config{
				Audiences: nil,
			},
			claims: &Claims{
				Audience: Audience{"any-audience"},
			},
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			validator, err := NewValidator(tt.config, zap.NewNop())
			require.NoError(t, err)

			err = validator.validateClaims(tt.claims)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_validateRequiredClaims(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator(nil, zap.NewNop())
	require.NoError(t, err)

	tests := []struct {
		name           string
		claims         *Claims
		requiredClaims map[string][]string
		wantError      error
	}{
		{
			name: "All required claims present",
			claims: &Claims{
				raw: map[string]interface{}{
					"role": "admin",
					"org":  "acme",
				},
			},
			requiredClaims: map[string][]string{
				"role": {"admin", "superadmin"},
				"org":  {"acme"},
			},
			wantError: nil,
		},
		{
			name: "Missing required claim",
			claims: &Claims{
				raw: map[string]interface{}{
					"role": "admin",
				},
			},
			requiredClaims: map[string][]string{
				"role": {"admin"},
				"org":  {"acme"},
			},
			wantError: ErrMissingClaim,
		},
		{
			name: "Invalid claim value",
			claims: &Claims{
				raw: map[string]interface{}{
					"role": "user",
				},
			},
			requiredClaims: map[string][]string{
				"role": {"admin", "superadmin"},
			},
			wantError: ErrInvalidClaimValue,
		},
		{
			name: "Empty allowed values (any value accepted)",
			claims: &Claims{
				raw: map[string]interface{}{
					"role": "anything",
				},
			},
			requiredClaims: map[string][]string{
				"role": {},
			},
			wantError: nil,
		},
		{
			name: "Array claim value",
			claims: &Claims{
				raw: map[string]interface{}{
					"roles": []interface{}{"admin", "user"},
				},
			},
			requiredClaims: map[string][]string{
				"roles": {"admin"},
			},
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validator.validateRequiredClaims(tt.claims, tt.requiredClaims)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_mergeRequiredClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		validator  map[string][]string
		additional map[string][]string
		expected   map[string][]string
	}{
		{
			name:       "Both nil",
			validator:  nil,
			additional: nil,
			expected:   nil,
		},
		{
			name:       "Only validator claims",
			validator:  map[string][]string{"role": {"admin"}},
			additional: nil,
			expected:   map[string][]string{"role": {"admin"}},
		},
		{
			name:       "Only additional claims",
			validator:  nil,
			additional: map[string][]string{"org": {"acme"}},
			expected:   map[string][]string{"org": {"acme"}},
		},
		{
			name:       "Merge different claims",
			validator:  map[string][]string{"role": {"admin"}},
			additional: map[string][]string{"org": {"acme"}},
			expected:   map[string][]string{"role": {"admin"}, "org": {"acme"}},
		},
		{
			name:       "Merge same claim",
			validator:  map[string][]string{"role": {"admin"}},
			additional: map[string][]string{"role": {"superadmin"}},
			expected:   map[string][]string{"role": {"admin", "superadmin"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			config := &Config{RequiredClaims: tt.validator}
			validator, err := NewValidator(config, zap.NewNop())
			require.NoError(t, err)

			result := validator.mergeRequiredClaims(tt.additional)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidator_claimValueMatches(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator(nil, zap.NewNop())
	require.NoError(t, err)

	tests := []struct {
		name          string
		value         interface{}
		allowedValues []string
		expected      bool
	}{
		{
			name:          "String match",
			value:         "admin",
			allowedValues: []string{"admin", "superadmin"},
			expected:      true,
		},
		{
			name:          "String no match",
			value:         "user",
			allowedValues: []string{"admin", "superadmin"},
			expected:      false,
		},
		{
			name:          "Interface slice match",
			value:         []interface{}{"admin", "user"},
			allowedValues: []string{"admin"},
			expected:      true,
		},
		{
			name:          "Interface slice no match",
			value:         []interface{}{"user", "guest"},
			allowedValues: []string{"admin"},
			expected:      false,
		},
		{
			name:          "String slice match",
			value:         []string{"admin", "user"},
			allowedValues: []string{"admin"},
			expected:      true,
		},
		{
			name:          "String slice no match",
			value:         []string{"user", "guest"},
			allowedValues: []string{"admin"},
			expected:      false,
		},
		{
			name:          "Unsupported type",
			value:         123,
			allowedValues: []string{"123"},
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := validator.claimValueMatches(tt.value, tt.allowedValues)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidator_UpdateLocalJWKS(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	initialJWKS := createTestJWKS(t, &key.PublicKey, "key-1")

	config := &Config{
		LocalJWKS:  initialJWKS,
		Algorithms: []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Update with new JWKS
	newKey := generateTestRSAKey(t)
	newJWKS := createTestJWKS(t, &newKey.PublicKey, "key-2")

	err = validator.UpdateLocalJWKS(newJWKS)
	require.NoError(t, err)
}

func TestValidator_UpdateLocalJWKS_NoExisting(t *testing.T) {
	t.Parallel()

	config := &Config{
		Algorithms: []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Update with new JWKS when none exists
	key := generateTestRSAKey(t)
	jwks := createTestJWKS(t, &key.PublicKey, "key-1")

	err = validator.UpdateLocalJWKS(jwks)
	require.NoError(t, err)
	assert.NotNil(t, validator.localJWKS)
}

func TestValidator_UpdateLocalJWKS_InvalidData(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	initialJWKS := createTestJWKS(t, &key.PublicKey, "key-1")

	config := &Config{
		LocalJWKS:  initialJWKS,
		Algorithms: []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	err = validator.UpdateLocalJWKS([]byte("invalid json"))
	assert.Error(t, err)
}

func TestValidator_Stop(t *testing.T) {
	t.Parallel()

	// With JWKS cache
	config := &Config{
		JWKSURL:      "https://example.com/.well-known/jwks.json",
		JWKSCacheTTL: time.Hour,
		Algorithms:   []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Should not panic
	validator.Stop()
}

func TestValidator_Stop_NoCache(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator(nil, zap.NewNop())
	require.NoError(t, err)

	// Should not panic
	validator.Stop()
}

func TestValidator_Validate_InvalidAlgorithm(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	jwksData := createTestJWKS(t, &key.PublicKey, "test-key")

	config := &Config{
		LocalJWKS:  jwksData,
		Algorithms: []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Create a token with unsupported algorithm
	header := map[string]interface{}{
		"alg": "HS256", // Not in allowed algorithms
		"typ": "JWT",
		"kid": "test-key",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claims := map[string]interface{}{"sub": "user"}
	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Use valid base64url encoded signature
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
	token := headerB64 + "." + claimsB64 + "." + sigB64

	_, err = validator.Validate(context.Background(), token)
	assert.ErrorIs(t, err, ErrInvalidAlgorithm)
}

func TestValidator_Validate_MissingAlgorithm(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	jwksData := createTestJWKS(t, &key.PublicKey, "test-key")

	config := &Config{
		LocalJWKS:  jwksData,
		Algorithms: []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Create a token without algorithm
	header := map[string]interface{}{
		"typ": "JWT",
		"kid": "test-key",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claims := map[string]interface{}{"sub": "user"}
	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Use valid base64url encoded signature
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
	token := headerB64 + "." + claimsB64 + "." + sigB64

	_, err = validator.Validate(context.Background(), token)
	assert.ErrorIs(t, err, ErrInvalidAlgorithm)
}

func TestValidator_getSigningKey_NoKeySource(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator(nil, zap.NewNop())
	require.NoError(t, err)

	_, err = validator.getSigningKey("any-kid")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestValidator_getSigningKey_FromLocalJWKS(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	jwksData := createTestJWKS(t, &key.PublicKey, "test-key")

	config := &Config{
		LocalJWKS:  jwksData,
		Algorithms: []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	jwk, err := validator.getSigningKey("test-key")
	require.NoError(t, err)
	assert.Equal(t, "test-key", jwk.Kid)
}

func TestValidator_getSigningKey_FromRemoteJWKS(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	jwksData := createTestJWKS(t, &key.PublicKey, "remote-key")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksData)
	}))
	defer server.Close()

	config := &Config{
		JWKSURL:      server.URL,
		JWKSCacheTTL: time.Hour,
		Algorithms:   []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	jwk, err := validator.getSigningKey("remote-key")
	require.NoError(t, err)
	assert.Equal(t, "remote-key", jwk.Kid)
}

func TestValidator_verifySignature_UnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator(nil, zap.NewNop())
	require.NoError(t, err)

	jwk := &JSONWebKey{
		Kty: "RSA",
		Kid: "test",
	}

	err = validator.verifySignature("header.payload.signature", []byte("sig"), jwk, "ES256")
	assert.ErrorIs(t, err, ErrInvalidAlgorithm)
}

func TestValidator_StartAutoRefresh(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	jwksData := createTestJWKS(t, &key.PublicKey, "test-key")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksData)
	}))
	defer server.Close()

	config := &Config{
		JWKSURL:      server.URL,
		JWKSCacheTTL: time.Hour,
		Algorithms:   []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Should not panic
	validator.StartAutoRefresh(ctx, time.Second)

	// Give it time to do initial fetch
	time.Sleep(100 * time.Millisecond)

	validator.Stop()
}

func TestValidator_StartAutoRefresh_NoCache(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator(nil, zap.NewNop())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Should not panic when no cache
	validator.StartAutoRefresh(ctx, time.Second)
}

// Test error variables are properly defined
func TestErrorVariables(t *testing.T) {
	t.Parallel()

	assert.NotNil(t, ErrTokenExpired)
	assert.NotNil(t, ErrTokenNotYetValid)
	assert.NotNil(t, ErrInvalidIssuer)
	assert.NotNil(t, ErrInvalidAudience)
	assert.NotNil(t, ErrInvalidSignature)
	assert.NotNil(t, ErrInvalidAlgorithm)
	assert.NotNil(t, ErrMissingClaim)
	assert.NotNil(t, ErrInvalidClaimValue)
	assert.NotNil(t, ErrKeyNotFound)
	assert.NotNil(t, ErrMalformedToken)
	assert.NotNil(t, ErrUnsupportedKeyType)

	// Verify error messages
	assert.Equal(t, "token has expired", ErrTokenExpired.Error())
	assert.Equal(t, "token is not yet valid", ErrTokenNotYetValid.Error())
	assert.Equal(t, "invalid issuer", ErrInvalidIssuer.Error())
	assert.Equal(t, "invalid audience", ErrInvalidAudience.Error())
	assert.Equal(t, "invalid signature", ErrInvalidSignature.Error())
	assert.Equal(t, "invalid algorithm", ErrInvalidAlgorithm.Error())
	assert.Equal(t, "missing required claim", ErrMissingClaim.Error())
	assert.Equal(t, "invalid claim value", ErrInvalidClaimValue.Error())
	assert.Equal(t, "signing key not found", ErrKeyNotFound.Error())
	assert.Equal(t, "malformed token", ErrMalformedToken.Error())
	assert.Equal(t, "unsupported key type", ErrUnsupportedKeyType.Error())
}

// Test wrapped errors
func TestWrappedErrors(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	jwksData := createTestJWKS(t, &key.PublicKey, "test-key")

	config := &Config{
		LocalJWKS:  jwksData,
		Algorithms: []string{"RS256"},
		Issuer:     "expected-issuer",
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	claims := &Claims{
		Issuer: "wrong-issuer",
	}

	err = validator.validateClaims(claims)
	assert.ErrorIs(t, err, ErrInvalidIssuer)
	assert.Contains(t, err.Error(), "expected expected-issuer")
	assert.Contains(t, err.Error(), "got wrong-issuer")
}

// Test verifyRSAPKCS1v15 function
func TestVerifyRSAPKCS1v15(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		alg       string
		wantError bool
	}{
		{
			name:      "RS256",
			alg:       "RS256",
			wantError: false,
		},
		{
			name:      "RS384",
			alg:       "RS384",
			wantError: false,
		},
		{
			name:      "RS512",
			alg:       "RS512",
			wantError: false,
		},
		{
			name:      "Unsupported algorithm",
			alg:       "ES256",
			wantError: true,
		},
	}

	key := generateTestRSAKey(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// For unsupported algorithms, we just check the error
			if tt.wantError {
				err := verifyRSAPKCS1v15("test", []byte("sig"), &key.PublicKey, tt.alg)
				assert.ErrorIs(t, err, ErrInvalidAlgorithm)
				return
			}

			// For supported algorithms, we need a valid signature
			// This is a basic test to ensure the function doesn't panic
			err := verifyRSAPKCS1v15("test", []byte("invalid-sig"), &key.PublicKey, tt.alg)
			// Will fail with invalid signature, but shouldn't panic
			assert.Error(t, err)
		})
	}
}

// Test verifyRSASignatureWithHash function
func TestVerifyRSASignatureWithHash(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)

	tests := []struct {
		name      string
		hashFunc  string
		wantError bool
	}{
		{
			name:      "SHA256",
			hashFunc:  "SHA256",
			wantError: false,
		},
		{
			name:      "SHA384",
			hashFunc:  "SHA384",
			wantError: false,
		},
		{
			name:      "SHA512",
			hashFunc:  "SHA512",
			wantError: false,
		},
		{
			name:      "Unsupported hash",
			hashFunc:  "MD5",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := verifyRSASignatureWithHash("test", []byte("sig"), &key.PublicKey, tt.hashFunc)

			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported hash function")
			} else {
				// Will fail with invalid signature, but shouldn't panic
				assert.Error(t, err)
			}
		})
	}
}

// Integration test with a complete flow
func TestValidator_IntegrationWithLocalJWKS(t *testing.T) {
	t.Parallel()

	// Generate key pair
	key := generateTestRSAKey(t)
	jwksData := createTestJWKS(t, &key.PublicKey, "test-key")

	// Create validator
	config := &Config{
		LocalJWKS:       jwksData,
		Algorithms:      []string{"RS256"},
		Issuer:          "https://issuer.example.com",
		Audiences:       []string{"api"},
		ClockSkew:       time.Minute,
		SkipExpiryCheck: true, // Skip for testing
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Create valid claims
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"sub": "user123",
		"aud": "api",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"iat": float64(time.Now().Unix()),
	}

	// Create token
	token := createTestToken(t, key, "test-key", claims)

	// Validate token
	validatedClaims, err := validator.Validate(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user123", validatedClaims.Subject)
	assert.Equal(t, "https://issuer.example.com", validatedClaims.Issuer)
}

// Test ValidateWithClaims
func TestValidator_ValidateWithClaims(t *testing.T) {
	t.Parallel()

	// Generate key pair
	key := generateTestRSAKey(t)
	jwksData := createTestJWKS(t, &key.PublicKey, "test-key")

	// Create validator
	config := &Config{
		LocalJWKS:       jwksData,
		Algorithms:      []string{"RS256"},
		SkipExpiryCheck: true,
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Create token with custom claims
	claims := map[string]interface{}{
		"sub":  "user123",
		"role": "admin",
		"org":  "acme",
	}

	token := createTestToken(t, key, "test-key", claims)

	// Validate with additional required claims
	requiredClaims := map[string][]string{
		"role": {"admin", "superadmin"},
	}

	validatedClaims, err := validator.ValidateWithClaims(context.Background(), token, requiredClaims)
	require.NoError(t, err)
	assert.Equal(t, "user123", validatedClaims.Subject)

	// Test with missing required claim
	requiredClaims = map[string][]string{
		"missing_claim": {"value"},
	}

	_, err = validator.ValidateWithClaims(context.Background(), token, requiredClaims)
	assert.ErrorIs(t, err, ErrMissingClaim)
}

// Benchmark tests
func BenchmarkValidator_parseToken(b *testing.B) {
	validator, _ := NewValidator(nil, zap.NewNop())
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.signature"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.parseToken(token)
	}
}

func BenchmarkValidator_validateClaims(b *testing.B) {
	config := &Config{
		Issuer:    "https://issuer.example.com",
		Audiences: []string{"api"},
		ClockSkew: time.Minute,
	}
	validator, _ := NewValidator(config, zap.NewNop())

	claims := &Claims{
		Issuer:    "https://issuer.example.com",
		Audience:  Audience{"api"},
		ExpiresAt: &Time{Time: time.Now().Add(time.Hour)},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.validateClaims(claims)
	}
}

// Test crypto helper functions
func TestCryptoHelpers(t *testing.T) {
	t.Parallel()

	// Test newSHA256
	h256 := newSHA256()
	assert.NotNil(t, h256)
	h256.Write([]byte("test"))
	sum256 := h256.Sum(nil)
	assert.Len(t, sum256, 32)

	// Test newSHA384
	h384 := newSHA384()
	assert.NotNil(t, h384)
	h384.Write([]byte("test"))
	sum384 := h384.Sum(nil)
	assert.Len(t, sum384, 48)

	// Test newSHA512
	h512 := newSHA512()
	assert.NotNil(t, h512)
	h512.Write([]byte("test"))
	sum512 := h512.Sum(nil)
	assert.Len(t, sum512, 64)
}

// TestRsaVerifyPKCS1v15_ValidHash tests rsaVerifyPKCS1v15 with valid hash types.
// Note: Invalid hash types are now prevented at compile time since crypto.Hash is a type-safe enum.
func TestRsaVerifyPKCS1v15_ValidHash(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)

	// Test with valid hash types - should fail with invalid signature, not panic
	tests := []struct {
		name    string
		hashAlg crypto.Hash
	}{
		{"SHA256", crypto.SHA256},
		{"SHA384", crypto.SHA384},
		{"SHA512", crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Should return an error (invalid signature) but not panic
			err := rsaVerifyPKCS1v15(&key.PublicKey, tt.hashAlg, []byte("hash"), []byte("sig"))
			assert.Error(t, err)
		})
	}
}

// Test for race conditions
func TestValidator_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	jwksData := createTestJWKS(t, &key.PublicKey, "test-key")

	config := &Config{
		LocalJWKS:       jwksData,
		Algorithms:      []string{"RS256"},
		SkipExpiryCheck: true,
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	claims := map[string]interface{}{
		"sub": "user123",
	}
	token := createTestToken(t, key, "test-key", claims)

	// Run concurrent validations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_, _ = validator.Validate(context.Background(), token)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test for concurrent JWKS updates
func TestValidator_ConcurrentJWKSUpdate(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	jwksData := createTestJWKS(t, &key.PublicKey, "test-key")

	config := &Config{
		LocalJWKS:  jwksData,
		Algorithms: []string{"RS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Run concurrent updates
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			newKey := generateTestRSAKey(t)
			newJWKS := createTestJWKS(t, &newKey.PublicKey, fmt.Sprintf("key-%d", id))
			_ = validator.UpdateLocalJWKS(newJWKS)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Helper function to create a test JWT token with PSS signature
func createTestTokenPSS(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]interface{}, alg string) string {
	t.Helper()

	header := map[string]interface{}{
		"alg": alg,
		"typ": "JWT",
		"kid": kid,
	}

	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64

	// Determine hash based on algorithm
	var hash crypto.Hash
	switch alg {
	case "PS256":
		hash = crypto.SHA256
	case "PS384":
		hash = crypto.SHA384
	case "PS512":
		hash = crypto.SHA512
	default:
		t.Fatalf("unsupported PSS algorithm: %s", alg)
	}

	// Compute hash
	h := hash.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	// Sign with PSS
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hash,
	}
	signature, err := rsa.SignPSS(rand.Reader, key, hash, hashed, opts)
	require.NoError(t, err)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64
}

// Helper function to create a test JWKS with PSS algorithm
func createTestJWKSWithAlg(t *testing.T, key *rsa.PublicKey, kid string, alg string) []byte {
	t.Helper()
	jwks := JSONWebKeySet{
		Keys: []JSONWebKey{
			{
				Kty: "RSA",
				Kid: kid,
				Alg: alg,
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			},
		},
	}
	data, err := json.Marshal(jwks)
	require.NoError(t, err)
	return data
}

// TestRsaVerifyPSS tests the rsaVerifyPSS function
func TestRsaVerifyPSS(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)

	tests := []struct {
		name    string
		hashAlg crypto.Hash
	}{
		{"SHA256", crypto.SHA256},
		{"SHA384", crypto.SHA384},
		{"SHA512", crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create a valid PSS signature
			message := []byte("test message")
			h := tt.hashAlg.New()
			h.Write(message)
			hashed := h.Sum(nil)

			opts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       tt.hashAlg,
			}
			signature, err := rsa.SignPSS(rand.Reader, key, tt.hashAlg, hashed, opts)
			require.NoError(t, err)

			// Verify the signature
			err = rsaVerifyPSS(&key.PublicKey, tt.hashAlg, hashed, signature)
			assert.NoError(t, err)
		})
	}
}

// TestRsaVerifyPSS_InvalidSignature tests rsaVerifyPSS with invalid signature
func TestRsaVerifyPSS_InvalidSignature(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)

	// Create a hash
	h := crypto.SHA256.New()
	h.Write([]byte("test message"))
	hashed := h.Sum(nil)

	// Try to verify with invalid signature
	err := rsaVerifyPSS(&key.PublicKey, crypto.SHA256, hashed, []byte("invalid-signature"))
	assert.Error(t, err)
}

// TestVerifyRSAPSS tests the verifyRSAPSS function
func TestVerifyRSAPSS(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)

	tests := []struct {
		name      string
		alg       string
		wantError bool
	}{
		{
			name:      "PS256",
			alg:       "PS256",
			wantError: false,
		},
		{
			name:      "PS384",
			alg:       "PS384",
			wantError: false,
		},
		{
			name:      "PS512",
			alg:       "PS512",
			wantError: false,
		},
		{
			name:      "Unsupported algorithm",
			alg:       "RS256",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.wantError {
				err := verifyRSAPSS("test", []byte("sig"), &key.PublicKey, tt.alg)
				assert.ErrorIs(t, err, ErrInvalidAlgorithm)
				return
			}

			// For supported algorithms, create a valid signature
			var hash crypto.Hash
			switch tt.alg {
			case "PS256":
				hash = crypto.SHA256
			case "PS384":
				hash = crypto.SHA384
			case "PS512":
				hash = crypto.SHA512
			}

			signingInput := "test.payload"
			h := hash.New()
			h.Write([]byte(signingInput))
			hashed := h.Sum(nil)

			opts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			}
			signature, err := rsa.SignPSS(rand.Reader, key, hash, hashed, opts)
			require.NoError(t, err)

			err = verifyRSAPSS(signingInput, signature, &key.PublicKey, tt.alg)
			assert.NoError(t, err)
		})
	}
}

// TestVerifyRSASignatureWithHashPSS tests PSS hash verification
func TestVerifyRSASignatureWithHashPSS(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)

	tests := []struct {
		name      string
		hashFunc  string
		wantError bool
	}{
		{
			name:      "SHA256",
			hashFunc:  "SHA256",
			wantError: false,
		},
		{
			name:      "SHA384",
			hashFunc:  "SHA384",
			wantError: false,
		},
		{
			name:      "SHA512",
			hashFunc:  "SHA512",
			wantError: false,
		},
		{
			name:      "Unsupported hash",
			hashFunc:  "MD5",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.wantError {
				err := verifyRSASignatureWithHashPSS("test", []byte("sig"), &key.PublicKey, tt.hashFunc)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported hash function")
				return
			}

			// For supported hash functions, create a valid signature
			var hash crypto.Hash
			switch tt.hashFunc {
			case "SHA256":
				hash = crypto.SHA256
			case "SHA384":
				hash = crypto.SHA384
			case "SHA512":
				hash = crypto.SHA512
			}

			signingInput := "test.payload"
			h := hash.New()
			h.Write([]byte(signingInput))
			hashed := h.Sum(nil)

			opts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			}
			signature, err := rsa.SignPSS(rand.Reader, key, hash, hashed, opts)
			require.NoError(t, err)

			err = verifyRSASignatureWithHashPSS(signingInput, signature, &key.PublicKey, tt.hashFunc)
			assert.NoError(t, err)
		})
	}
}

// TestComputeHash tests the computeHash helper
func TestComputeHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		hashFunc     string
		expectedLen  int
		expectedHash crypto.Hash
		wantError    bool
	}{
		{
			name:         "SHA256",
			hashFunc:     "SHA256",
			expectedLen:  32,
			expectedHash: crypto.SHA256,
			wantError:    false,
		},
		{
			name:         "SHA384",
			hashFunc:     "SHA384",
			expectedLen:  48,
			expectedHash: crypto.SHA384,
			wantError:    false,
		},
		{
			name:         "SHA512",
			hashFunc:     "SHA512",
			expectedLen:  64,
			expectedHash: crypto.SHA512,
			wantError:    false,
		},
		{
			name:      "Unsupported hash",
			hashFunc:  "MD5",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hashed, cryptoHash, err := computeHash("test input", tt.hashFunc)

			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported hash function")
				return
			}

			require.NoError(t, err)
			assert.Len(t, hashed, tt.expectedLen)
			assert.Equal(t, tt.expectedHash, cryptoHash)
		})
	}
}

// TestValidator_Validate_PSS tests PSS algorithm validation
func TestValidator_Validate_PSS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		alg  string
	}{
		{"PS256", "PS256"},
		{"PS384", "PS384"},
		{"PS512", "PS512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Generate key pair
			key := generateTestRSAKey(t)
			jwksData := createTestJWKSWithAlg(t, &key.PublicKey, "test-key", tt.alg)

			// Create validator
			config := &Config{
				LocalJWKS:       jwksData,
				Algorithms:      []string{tt.alg},
				SkipExpiryCheck: true,
			}

			validator, err := NewValidator(config, zap.NewNop())
			require.NoError(t, err)

			// Create valid claims
			claims := map[string]interface{}{
				"sub": "user123",
				"iat": float64(time.Now().Unix()),
			}

			// Create token with PSS signature
			token := createTestTokenPSS(t, key, "test-key", claims, tt.alg)

			// Validate token
			validatedClaims, err := validator.Validate(context.Background(), token)
			require.NoError(t, err)
			assert.Equal(t, "user123", validatedClaims.Subject)
		})
	}
}

// TestValidator_verifySignature_PSS tests verifySignature with PSS algorithms
func TestValidator_verifySignature_PSS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		alg  string
	}{
		{"PS256", "PS256"},
		{"PS384", "PS384"},
		{"PS512", "PS512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key := generateTestRSAKey(t)
			jwksData := createTestJWKSWithAlg(t, &key.PublicKey, "test-key", tt.alg)

			config := &Config{
				LocalJWKS:  jwksData,
				Algorithms: []string{tt.alg},
			}

			validator, err := NewValidator(config, zap.NewNop())
			require.NoError(t, err)

			// Create a valid PSS signature
			var hash crypto.Hash
			switch tt.alg {
			case "PS256":
				hash = crypto.SHA256
			case "PS384":
				hash = crypto.SHA384
			case "PS512":
				hash = crypto.SHA512
			}

			signingInput := "header.payload"
			h := hash.New()
			h.Write([]byte(signingInput))
			hashed := h.Sum(nil)

			opts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			}
			signature, err := rsa.SignPSS(rand.Reader, key, hash, hashed, opts)
			require.NoError(t, err)

			// Get the key
			jwk, err := validator.getSigningKey("test-key")
			require.NoError(t, err)

			// Verify signature
			tokenString := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
			err = validator.verifySignature(tokenString, signature, jwk, tt.alg)
			assert.NoError(t, err)
		})
	}
}

// TestValidator_verifyRSAPSSSignature tests the verifyRSAPSSSignature method
func TestValidator_verifyRSAPSSSignature(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	jwksData := createTestJWKSWithAlg(t, &key.PublicKey, "test-key", "PS256")

	config := &Config{
		LocalJWKS:  jwksData,
		Algorithms: []string{"PS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Create a valid PSS signature
	signingInput := "header.payload"
	h := crypto.SHA256.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hashed, opts)
	require.NoError(t, err)

	// Get the key
	jwk, err := validator.getSigningKey("test-key")
	require.NoError(t, err)

	// Verify signature using the method
	err = validator.verifyRSAPSSSignature(signingInput, signature, jwk, "PS256")
	assert.NoError(t, err)
}

// TestValidator_verifyRSAPSSSignature_InvalidKey tests verifyRSAPSSSignature with invalid key
func TestValidator_verifyRSAPSSSignature_InvalidKey(t *testing.T) {
	t.Parallel()

	config := &Config{
		Algorithms: []string{"PS256"},
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Create an invalid JWK (non-RSA)
	jwk := &JSONWebKey{
		Kty: "EC",
		Kid: "test-key",
	}

	err = validator.verifyRSAPSSSignature("header.payload", []byte("sig"), jwk, "PS256")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to convert key to RSA")
}

// TestValidator_Validate_PSS_InvalidSignature tests PSS validation with invalid signature
func TestValidator_Validate_PSS_InvalidSignature(t *testing.T) {
	t.Parallel()

	key := generateTestRSAKey(t)
	jwksData := createTestJWKSWithAlg(t, &key.PublicKey, "test-key", "PS256")

	config := &Config{
		LocalJWKS:       jwksData,
		Algorithms:      []string{"PS256"},
		SkipExpiryCheck: true,
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Create a token with invalid signature
	header := map[string]interface{}{
		"alg": "PS256",
		"typ": "JWT",
		"kid": "test-key",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claims := map[string]interface{}{"sub": "user123"}
	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Use invalid signature
	invalidSig := base64.RawURLEncoding.EncodeToString([]byte("invalid-signature"))
	token := headerB64 + "." + claimsB64 + "." + invalidSig

	_, err = validator.Validate(context.Background(), token)
	assert.Error(t, err)
}

// TestValidator_Validate_AllPSSAlgorithms tests all PSS algorithms in a single validator
func TestValidator_Validate_AllPSSAlgorithms(t *testing.T) {
	t.Parallel()

	// Generate key pair
	key := generateTestRSAKey(t)

	// Create JWKS with all PSS algorithms
	jwks := JSONWebKeySet{
		Keys: []JSONWebKey{
			{
				Kty: "RSA",
				Kid: "ps256-key",
				Alg: "PS256",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			},
			{
				Kty: "RSA",
				Kid: "ps384-key",
				Alg: "PS384",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			},
			{
				Kty: "RSA",
				Kid: "ps512-key",
				Alg: "PS512",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			},
		},
	}
	jwksData, err := json.Marshal(jwks)
	require.NoError(t, err)

	// Create validator with all PSS algorithms
	config := &Config{
		LocalJWKS:       jwksData,
		Algorithms:      []string{"PS256", "PS384", "PS512"},
		SkipExpiryCheck: true,
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Test each algorithm
	algorithms := []struct {
		alg string
		kid string
	}{
		{"PS256", "ps256-key"},
		{"PS384", "ps384-key"},
		{"PS512", "ps512-key"},
	}

	for _, tt := range algorithms {
		t.Run(tt.alg, func(t *testing.T) {
			claims := map[string]interface{}{
				"sub": "user123",
				"alg": tt.alg,
			}

			token := createTestTokenPSS(t, key, tt.kid, claims, tt.alg)

			validatedClaims, err := validator.Validate(context.Background(), token)
			require.NoError(t, err)
			assert.Equal(t, "user123", validatedClaims.Subject)
		})
	}
}

// TestValidator_Validate_MixedRSAndPSS tests validator with both RS and PS algorithms
func TestValidator_Validate_MixedRSAndPSS(t *testing.T) {
	t.Parallel()

	// Generate key pair
	key := generateTestRSAKey(t)

	// Create JWKS with both RS256 and PS256
	jwks := JSONWebKeySet{
		Keys: []JSONWebKey{
			{
				Kty: "RSA",
				Kid: "rs256-key",
				Alg: "RS256",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			},
			{
				Kty: "RSA",
				Kid: "ps256-key",
				Alg: "PS256",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			},
		},
	}
	jwksData, err := json.Marshal(jwks)
	require.NoError(t, err)

	// Create validator with both algorithms
	config := &Config{
		LocalJWKS:       jwksData,
		Algorithms:      []string{"RS256", "PS256"},
		SkipExpiryCheck: true,
	}

	validator, err := NewValidator(config, zap.NewNop())
	require.NoError(t, err)

	// Test RS256
	t.Run("RS256", func(t *testing.T) {
		claims := map[string]interface{}{"sub": "user-rs256"}
		token := createTestToken(t, key, "rs256-key", claims)

		validatedClaims, err := validator.Validate(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, "user-rs256", validatedClaims.Subject)
	})

	// Test PS256
	t.Run("PS256", func(t *testing.T) {
		claims := map[string]interface{}{"sub": "user-ps256"}
		token := createTestTokenPSS(t, key, "ps256-key", claims, "PS256")

		validatedClaims, err := validator.Validate(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, "user-ps256", validatedClaims.Subject)
	})
}
