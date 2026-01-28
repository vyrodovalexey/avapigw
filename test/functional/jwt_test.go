//go:build functional
// +build functional

package functional

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestFunctional_JWT_Claims_Parsing(t *testing.T) {
	t.Parallel()

	t.Run("parse standard claims", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		claimsMap := map[string]interface{}{
			"sub": "user-123",
			"iss": "https://issuer.example.com",
			"aud": []interface{}{"api", "web"},
			"exp": float64(now.Add(1 * time.Hour).Unix()),
			"iat": float64(now.Unix()),
			"nbf": float64(now.Unix()),
			"jti": "token-id-123",
		}

		claims, err := jwt.ParseClaims(claimsMap)
		require.NoError(t, err)

		assert.Equal(t, "user-123", claims.Subject)
		assert.Equal(t, "https://issuer.example.com", claims.Issuer)
		assert.Contains(t, claims.Audience, "api")
		assert.Contains(t, claims.Audience, "web")
		assert.Equal(t, "token-id-123", claims.JWTID)
	})

	t.Run("parse custom claims", func(t *testing.T) {
		t.Parallel()

		claimsMap := map[string]interface{}{
			"sub":   "user-123",
			"roles": []interface{}{"admin", "user"},
			"email": "user@example.com",
			"name":  "John Doe",
			"custom_field": map[string]interface{}{
				"nested": "value",
			},
		}

		claims, err := jwt.ParseClaims(claimsMap)
		require.NoError(t, err)

		assert.Equal(t, "user-123", claims.Subject)

		// Check custom claims
		roles, ok := claims.GetClaim("roles")
		require.True(t, ok)
		assert.NotNil(t, roles)

		email, ok := claims.GetClaim("email")
		require.True(t, ok)
		assert.Equal(t, "user@example.com", email)
	})

	t.Run("parse single audience as string", func(t *testing.T) {
		t.Parallel()

		claimsMap := map[string]interface{}{
			"sub": "user-123",
			"aud": "single-audience",
		}

		claims, err := jwt.ParseClaims(claimsMap)
		require.NoError(t, err)

		assert.Contains(t, claims.Audience, "single-audience")
	})
}

func TestFunctional_JWT_Claims_Validation(t *testing.T) {
	t.Parallel()

	t.Run("valid claims", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		claimsMap := map[string]interface{}{
			"sub": "user-123",
			"exp": float64(now.Add(1 * time.Hour).Unix()),
			"iat": float64(now.Unix()),
			"nbf": float64(now.Unix()),
		}

		claims, err := jwt.ParseClaims(claimsMap)
		require.NoError(t, err)

		err = claims.ValidWithSkew(0)
		require.NoError(t, err)
	})

	t.Run("expired token", func(t *testing.T) {
		t.Parallel()

		past := time.Now().Add(-1 * time.Hour)
		claimsMap := map[string]interface{}{
			"sub": "user-123",
			"exp": float64(past.Unix()),
		}

		claims, err := jwt.ParseClaims(claimsMap)
		require.NoError(t, err)

		err = claims.ValidWithSkew(0)
		require.Error(t, err)
	})

	t.Run("not yet valid token", func(t *testing.T) {
		t.Parallel()

		future := time.Now().Add(1 * time.Hour)
		claimsMap := map[string]interface{}{
			"sub": "user-123",
			"nbf": float64(future.Unix()),
			"exp": float64(future.Add(1 * time.Hour).Unix()),
		}

		claims, err := jwt.ParseClaims(claimsMap)
		require.NoError(t, err)

		err = claims.ValidWithSkew(0)
		require.Error(t, err)
	})

	t.Run("clock skew allows slightly expired token", func(t *testing.T) {
		t.Parallel()

		// Token expired 30 seconds ago
		past := time.Now().Add(-30 * time.Second)
		claimsMap := map[string]interface{}{
			"sub": "user-123",
			"exp": float64(past.Unix()),
		}

		claims, err := jwt.ParseClaims(claimsMap)
		require.NoError(t, err)

		// With 1 minute clock skew, should be valid
		err = claims.ValidWithSkew(1 * time.Minute)
		require.NoError(t, err)
	})
}

func TestFunctional_JWT_Claims_AudienceValidation(t *testing.T) {
	t.Parallel()

	t.Run("audience contains expected value", func(t *testing.T) {
		t.Parallel()

		claimsMap := map[string]interface{}{
			"sub": "user-123",
			"aud": []interface{}{"api", "web", "mobile"},
		}

		claims, err := jwt.ParseClaims(claimsMap)
		require.NoError(t, err)

		assert.True(t, claims.Audience.ContainsAny("api"))
		assert.True(t, claims.Audience.ContainsAny("web"))
		assert.True(t, claims.Audience.ContainsAny("mobile"))
		assert.True(t, claims.Audience.ContainsAny("api", "other"))
		assert.False(t, claims.Audience.ContainsAny("other"))
	})
}

func TestFunctional_JWT_Claims_GetMethods(t *testing.T) {
	t.Parallel()

	claimsMap := map[string]interface{}{
		"sub":         "user-123",
		"string_val":  "test",
		"int_val":     42,
		"bool_val":    true,
		"array_val":   []interface{}{"a", "b", "c"},
		"nested_val":  map[string]interface{}{"key": "value"},
		"roles":       []interface{}{"admin", "user"},
		"permissions": []interface{}{"read", "write"},
	}

	claims, err := jwt.ParseClaims(claimsMap)
	require.NoError(t, err)

	t.Run("GetClaim", func(t *testing.T) {
		t.Parallel()

		val, ok := claims.GetClaim("string_val")
		assert.True(t, ok)
		assert.Equal(t, "test", val)

		_, ok = claims.GetClaim("nonexistent")
		assert.False(t, ok)
	})

	t.Run("GetStringClaim", func(t *testing.T) {
		t.Parallel()

		val := claims.GetStringClaim("string_val")
		assert.Equal(t, "test", val)

		val = claims.GetStringClaim("int_val")
		assert.Equal(t, "", val) // Not a string

		val = claims.GetStringClaim("nonexistent")
		assert.Equal(t, "", val)
	})

	t.Run("GetStringSliceClaim", func(t *testing.T) {
		t.Parallel()

		val := claims.GetStringSliceClaim("roles")
		assert.Equal(t, []string{"admin", "user"}, val)

		// Single string values are split on spaces (common for scopes)
		val = claims.GetStringSliceClaim("string_val")
		assert.Equal(t, []string{"test"}, val) // Single word string becomes single-element slice

		val = claims.GetStringSliceClaim("nonexistent")
		assert.Nil(t, val)
	})
}

func TestFunctional_JWT_Validator_Creation(t *testing.T) {
	t.Parallel()

	t.Run("create validator with JWKS URL", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"RS256"},
			JWKSUrl:    "https://example.com/.well-known/jwks.json",
		}

		// Note: This will fail to fetch JWKS, but validator creation should succeed
		// The actual JWKS fetch happens lazily
		validator, err := jwt.NewValidator(cfg)
		require.NoError(t, err)
		require.NotNil(t, validator)
	})

	t.Run("create validator with static key", func(t *testing.T) {
		t.Parallel()

		// Generate a test key
		authSetup := helpers.SetupAuthForTesting(t)
		pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
		require.NoError(t, err)

		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"RS256"},
			StaticKeys: []jwt.StaticKey{
				{
					KeyID:     "test-key",
					Algorithm: "RS256",
					Key:       pubKeyPEM,
				},
			},
		}

		validator, err := jwt.NewValidator(cfg)
		require.NoError(t, err)
		require.NotNil(t, validator)
	})

	t.Run("fail to create validator without key source", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"RS256"},
		}

		_, err := jwt.NewValidator(cfg)
		require.Error(t, err)
	})

	t.Run("fail to create validator with nil config", func(t *testing.T) {
		t.Parallel()

		_, err := jwt.NewValidator(nil)
		require.Error(t, err)
	})
}

func TestFunctional_JWT_TokenCreation(t *testing.T) {
	t.Parallel()

	authSetup := helpers.SetupAuthForTesting(t)

	t.Run("create RS256 token", func(t *testing.T) {
		t.Parallel()

		claims := helpers.CreateJWTClaims(
			"user-123",
			"https://issuer.example.com",
			[]string{"api"},
			[]string{"user"},
			1*time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "test-key")
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Token should have 3 parts
		parts := splitToken(token)
		assert.Len(t, parts, 3)
	})

	t.Run("create ES256 token", func(t *testing.T) {
		t.Parallel()

		claims := helpers.CreateJWTClaims(
			"user-123",
			"https://issuer.example.com",
			[]string{"api"},
			[]string{"user"},
			1*time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.ECDSAPrivateKey, "ES256", "test-key")
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("create HS256 token", func(t *testing.T) {
		t.Parallel()

		claims := helpers.CreateJWTClaims(
			"user-123",
			"https://issuer.example.com",
			[]string{"api"},
			[]string{"user"},
			1*time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.HMACKey, "HS256", "")
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})
}

func TestFunctional_JWT_Validator_Validation(t *testing.T) {
	t.Parallel()

	authSetup := helpers.SetupAuthForTesting(t)
	pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
	require.NoError(t, err)

	cfg := &jwt.Config{
		Enabled:    true,
		Algorithms: []string{"RS256"},
		Issuer:     "https://issuer.example.com",
		Audience:   []string{"api"},
		StaticKeys: []jwt.StaticKey{
			{
				KeyID:     "test-key",
				Algorithm: "RS256",
				Key:       pubKeyPEM,
			},
		},
	}

	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("validate valid token", func(t *testing.T) {
		t.Parallel()

		claims := helpers.CreateJWTClaims(
			"user-123",
			"https://issuer.example.com",
			[]string{"api"},
			[]string{"user"},
			1*time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "test-key")
		require.NoError(t, err)

		validatedClaims, err := validator.Validate(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, "user-123", validatedClaims.Subject)
		assert.Equal(t, "https://issuer.example.com", validatedClaims.Issuer)
	})

	t.Run("reject expired token", func(t *testing.T) {
		t.Parallel()

		claims := helpers.CreateExpiredJWTClaims("user-123", "https://issuer.example.com")

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "test-key")
		require.NoError(t, err)

		_, err = validator.Validate(ctx, token)
		require.Error(t, err)
	})

	t.Run("reject wrong issuer", func(t *testing.T) {
		t.Parallel()

		claims := helpers.CreateJWTClaims(
			"user-123",
			"https://wrong-issuer.example.com",
			[]string{"api"},
			[]string{"user"},
			1*time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "test-key")
		require.NoError(t, err)

		_, err = validator.Validate(ctx, token)
		require.Error(t, err)
	})

	t.Run("reject wrong audience", func(t *testing.T) {
		t.Parallel()

		claims := helpers.CreateJWTClaims(
			"user-123",
			"https://issuer.example.com",
			[]string{"wrong-audience"},
			[]string{"user"},
			1*time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "test-key")
		require.NoError(t, err)

		_, err = validator.Validate(ctx, token)
		require.Error(t, err)
	})

	t.Run("reject empty token", func(t *testing.T) {
		t.Parallel()

		_, err := validator.Validate(ctx, "")
		require.Error(t, err)
	})

	t.Run("reject malformed token", func(t *testing.T) {
		t.Parallel()

		_, err := validator.Validate(ctx, "not.a.valid.token")
		require.Error(t, err)
	})

	t.Run("reject token with invalid signature", func(t *testing.T) {
		t.Parallel()

		claims := helpers.CreateJWTClaims(
			"user-123",
			"https://issuer.example.com",
			[]string{"api"},
			[]string{"user"},
			1*time.Hour,
		)

		// Create token with different key
		otherKey, _, err := helpers.GenerateRSAKeyPair(2048)
		require.NoError(t, err)

		token, err := helpers.CreateTestJWT(claims, otherKey, "RS256", "test-key")
		require.NoError(t, err)

		_, err = validator.Validate(ctx, token)
		require.Error(t, err)
	})
}

func TestFunctional_JWT_Validator_AlgorithmRestriction(t *testing.T) {
	t.Parallel()

	authSetup := helpers.SetupAuthForTesting(t)
	pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
	require.NoError(t, err)

	cfg := &jwt.Config{
		Enabled:    true,
		Algorithms: []string{"RS256"}, // Only RS256 allowed
		StaticKeys: []jwt.StaticKey{
			{
				KeyID:     "test-key",
				Algorithm: "RS256",
				Key:       pubKeyPEM,
			},
		},
	}

	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("accept allowed algorithm", func(t *testing.T) {
		t.Parallel()

		claims := helpers.CreateJWTClaims("user-123", "", nil, nil, 1*time.Hour)
		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "test-key")
		require.NoError(t, err)

		_, err = validator.Validate(ctx, token)
		require.NoError(t, err)
	})
}

func TestFunctional_JWT_Validator_RequiredClaims(t *testing.T) {
	t.Parallel()

	authSetup := helpers.SetupAuthForTesting(t)
	pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
	require.NoError(t, err)

	cfg := &jwt.Config{
		Enabled:        true,
		Algorithms:     []string{"RS256"},
		RequiredClaims: []string{"email", "roles"},
		StaticKeys: []jwt.StaticKey{
			{
				KeyID:     "test-key",
				Algorithm: "RS256",
				Key:       pubKeyPEM,
			},
		},
	}

	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("accept token with required claims", func(t *testing.T) {
		t.Parallel()

		claims := map[string]interface{}{
			"sub":   "user-123",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"email": "user@example.com",
			"roles": []interface{}{"user"},
		}

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "test-key")
		require.NoError(t, err)

		_, err = validator.Validate(ctx, token)
		require.NoError(t, err)
	})

	t.Run("reject token missing required claim", func(t *testing.T) {
		t.Parallel()

		claims := map[string]interface{}{
			"sub":   "user-123",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"email": "user@example.com",
			// Missing "roles"
		}

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "test-key")
		require.NoError(t, err)

		_, err = validator.Validate(ctx, token)
		require.Error(t, err)
	})
}

func TestFunctional_JWT_Config_GetMethods(t *testing.T) {
	t.Parallel()

	t.Run("GetAllowedIssuers", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			Issuer: "https://single.example.com",
		}
		issuers := cfg.GetAllowedIssuers()
		assert.Equal(t, []string{"https://single.example.com"}, issuers)

		cfg = &jwt.Config{
			Issuers: []string{"https://issuer1.example.com", "https://issuer2.example.com"},
		}
		issuers = cfg.GetAllowedIssuers()
		assert.Len(t, issuers, 2)

		cfg = &jwt.Config{}
		issuers = cfg.GetAllowedIssuers()
		assert.Nil(t, issuers)
	})

	t.Run("GetEffectiveClockSkew", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			ClockSkew: 10 * time.Minute,
		}
		assert.Equal(t, 10*time.Minute, cfg.GetEffectiveClockSkew())

		cfg = &jwt.Config{}
		assert.Equal(t, 5*time.Minute, cfg.GetEffectiveClockSkew())
	})

	t.Run("GetEffectiveJWKSCacheTTL", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			JWKSCacheTTL: 30 * time.Minute,
		}
		assert.Equal(t, 30*time.Minute, cfg.GetEffectiveJWKSCacheTTL())

		cfg = &jwt.Config{}
		assert.Equal(t, 1*time.Hour, cfg.GetEffectiveJWKSCacheTTL())
	})
}

// Helper function to split JWT token
func splitToken(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}
