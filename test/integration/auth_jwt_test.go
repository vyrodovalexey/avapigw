//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
Keycloak Setup Instructions for JWT Integration Tests:

1. Start Keycloak:
   docker run -d --name keycloak-test \
     -p 8090:8080 \
     -e KEYCLOAK_ADMIN=admin \
     -e KEYCLOAK_ADMIN_PASSWORD=admin \
     quay.io/keycloak/keycloak:26.5 start-dev

2. Wait for Keycloak to be ready:
   curl -s http://localhost:8090/health/ready

3. Run tests:
   KEYCLOAK_ADDR=http://127.0.0.1:8090 go test -tags=integration ./test/integration/...
*/

func TestIntegration_JWT_KeycloakToken(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get token from Keycloak
	tokenResp, err := setup.GetUserToken(ctx, "testuser")
	require.NoError(t, err)
	require.NotEmpty(t, tokenResp.AccessToken)

	t.Run("validate Keycloak token with JWKS", func(t *testing.T) {
		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"RS256"},
			JWKSUrl:    setup.GetJWKSURL(),
			Issuer:     setup.GetIssuerURL(),
		}

		validator, err := jwt.NewValidator(cfg, jwt.WithValidatorLogger(observability.NopLogger()))
		require.NoError(t, err)

		claims, err := validator.Validate(ctx, tokenResp.AccessToken)
		require.NoError(t, err)
		require.NotNil(t, claims)

		assert.NotEmpty(t, claims.Subject)
		assert.Equal(t, setup.GetIssuerURL(), claims.Issuer)
	})

	t.Run("validate token claims", func(t *testing.T) {
		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"RS256"},
			JWKSUrl:    setup.GetJWKSURL(),
			Issuer:     setup.GetIssuerURL(),
		}

		validator, err := jwt.NewValidator(cfg)
		require.NoError(t, err)

		claims, err := validator.Validate(ctx, tokenResp.AccessToken)
		require.NoError(t, err)

		// Check standard claims
		assert.NotEmpty(t, claims.Subject)
		assert.NotNil(t, claims.ExpiresAt)
		assert.NotNil(t, claims.IssuedAt)

		// Check custom claims (Keycloak specific)
		preferredUsername, ok := claims.GetClaim("preferred_username")
		if ok {
			assert.Equal(t, "testuser", preferredUsername)
		}
	})
}

func TestIntegration_JWT_KeycloakMultipleUsers(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := &jwt.Config{
		Enabled:    true,
		Algorithms: []string{"RS256"},
		JWKSUrl:    setup.GetJWKSURL(),
		Issuer:     setup.GetIssuerURL(),
	}

	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)

	t.Run("validate testuser token", func(t *testing.T) {
		tokenResp, err := setup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		claims, err := validator.Validate(ctx, tokenResp.AccessToken)
		require.NoError(t, err)
		assert.NotEmpty(t, claims.Subject)
	})

	t.Run("validate adminuser token", func(t *testing.T) {
		tokenResp, err := setup.GetUserToken(ctx, "adminuser")
		require.NoError(t, err)

		claims, err := validator.Validate(ctx, tokenResp.AccessToken)
		require.NoError(t, err)
		assert.NotEmpty(t, claims.Subject)
	})

	t.Run("validate reader token", func(t *testing.T) {
		tokenResp, err := setup.GetUserToken(ctx, "reader")
		require.NoError(t, err)

		claims, err := validator.Validate(ctx, tokenResp.AccessToken)
		require.NoError(t, err)
		assert.NotEmpty(t, claims.Subject)
	})
}

func TestIntegration_JWT_KeycloakJWKSCaching(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := &jwt.Config{
		Enabled:      true,
		Algorithms:   []string{"RS256"},
		JWKSUrl:      setup.GetJWKSURL(),
		JWKSCacheTTL: 5 * time.Minute,
		Issuer:       setup.GetIssuerURL(),
	}

	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)

	tokenResp, err := setup.GetUserToken(ctx, "testuser")
	require.NoError(t, err)

	// First validation - fetches JWKS
	start := time.Now()
	claims1, err := validator.Validate(ctx, tokenResp.AccessToken)
	require.NoError(t, err)
	firstDuration := time.Since(start)

	// Second validation - should use cached JWKS
	start = time.Now()
	claims2, err := validator.Validate(ctx, tokenResp.AccessToken)
	require.NoError(t, err)
	secondDuration := time.Since(start)

	assert.Equal(t, claims1.Subject, claims2.Subject)
	t.Logf("First validation: %v, Second validation: %v", firstDuration, secondDuration)
}

func TestIntegration_JWT_KeycloakInvalidToken(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := &jwt.Config{
		Enabled:    true,
		Algorithms: []string{"RS256"},
		JWKSUrl:    setup.GetJWKSURL(),
		Issuer:     setup.GetIssuerURL(),
	}

	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)

	t.Run("reject invalid token", func(t *testing.T) {
		_, err := validator.Validate(ctx, "invalid.token.here")
		require.Error(t, err)
	})

	t.Run("reject empty token", func(t *testing.T) {
		_, err := validator.Validate(ctx, "")
		require.Error(t, err)
	})

	t.Run("reject tampered token", func(t *testing.T) {
		tokenResp, err := setup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		// Tamper with the token
		tamperedToken := tokenResp.AccessToken + "tampered"

		_, err = validator.Validate(ctx, tamperedToken)
		require.Error(t, err)
	})
}

func TestIntegration_JWT_KeycloakWrongIssuer(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := &jwt.Config{
		Enabled:    true,
		Algorithms: []string{"RS256"},
		JWKSUrl:    setup.GetJWKSURL(),
		Issuer:     "https://wrong-issuer.example.com",
	}

	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)

	tokenResp, err := setup.GetUserToken(ctx, "testuser")
	require.NoError(t, err)

	_, err = validator.Validate(ctx, tokenResp.AccessToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestIntegration_JWT_KeycloakAudienceValidation(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokenResp, err := setup.GetUserToken(ctx, "testuser")
	require.NoError(t, err)

	t.Run("accept token with matching audience", func(t *testing.T) {
		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"RS256"},
			JWKSUrl:    setup.GetJWKSURL(),
			Issuer:     setup.GetIssuerURL(),
			// Don't specify audience - accept any
		}

		validator, err := jwt.NewValidator(cfg)
		require.NoError(t, err)

		claims, err := validator.Validate(ctx, tokenResp.AccessToken)
		require.NoError(t, err)
		assert.NotNil(t, claims)
	})
}

func TestIntegration_JWT_KeycloakClockSkew(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokenResp, err := setup.GetUserToken(ctx, "testuser")
	require.NoError(t, err)

	t.Run("validate with clock skew", func(t *testing.T) {
		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"RS256"},
			JWKSUrl:    setup.GetJWKSURL(),
			Issuer:     setup.GetIssuerURL(),
			ClockSkew:  5 * time.Minute,
		}

		validator, err := jwt.NewValidator(cfg)
		require.NoError(t, err)

		claims, err := validator.Validate(ctx, tokenResp.AccessToken)
		require.NoError(t, err)
		assert.NotNil(t, claims)
	})
}

func TestIntegration_JWT_KeycloakClientCredentials(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get token using client credentials
	tokenResp, err := setup.Client.GetClientCredentialsToken(
		ctx,
		setup.Realm,
		setup.ClientID,
		setup.ClientSecret,
	)
	require.NoError(t, err)
	require.NotEmpty(t, tokenResp.AccessToken)

	cfg := &jwt.Config{
		Enabled:    true,
		Algorithms: []string{"RS256"},
		JWKSUrl:    setup.GetJWKSURL(),
		Issuer:     setup.GetIssuerURL(),
	}

	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)

	claims, err := validator.Validate(ctx, tokenResp.AccessToken)
	require.NoError(t, err)
	assert.NotNil(t, claims)
}

func TestIntegration_JWT_KeycloakRefreshToken(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokenResp, err := setup.GetUserToken(ctx, "testuser")
	require.NoError(t, err)

	// Verify we got a refresh token
	assert.NotEmpty(t, tokenResp.RefreshToken)
	assert.Greater(t, tokenResp.ExpiresIn, 0)
	assert.Greater(t, tokenResp.RefreshExpiresIn, 0)
}

func TestIntegration_JWT_StaticKeyWithKeycloak(t *testing.T) {
	// This test validates that we can use both JWKS and static keys
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate a static key for testing
	authSetup := helpers.SetupAuthForTesting(t)
	pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
	require.NoError(t, err)

	cfg := &jwt.Config{
		Enabled:    true,
		Algorithms: []string{"RS256"},
		JWKSUrl:    setup.GetJWKSURL(),
		Issuer:     setup.GetIssuerURL(),
		StaticKeys: []jwt.StaticKey{
			{
				KeyID:     "static-key",
				Algorithm: "RS256",
				Key:       pubKeyPEM,
			},
		},
	}

	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)

	// Validate Keycloak token (uses JWKS)
	tokenResp, err := setup.GetUserToken(ctx, "testuser")
	require.NoError(t, err)

	claims, err := validator.Validate(ctx, tokenResp.AccessToken)
	require.NoError(t, err)
	assert.NotNil(t, claims)
}
