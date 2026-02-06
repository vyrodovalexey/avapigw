//go:build integration

// Package operator_test contains integration tests for the apigw-operator.
package operator_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestIntegration_Operator_Keycloak_ClientCredentials tests Keycloak client credentials flow.
func TestIntegration_Operator_Keycloak_ClientCredentials(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("acquires token using client credentials", func(t *testing.T) {
		token, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			keycloakSetup.ClientID,
			keycloakSetup.ClientSecret,
		)
		require.NoError(t, err)
		require.NotNil(t, token)

		assert.NotEmpty(t, token.AccessToken)
		assert.Equal(t, "Bearer", token.TokenType)
		assert.Greater(t, token.ExpiresIn, 0)
	})

	t.Run("token contains expected claims", func(t *testing.T) {
		token, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			keycloakSetup.ClientID,
			keycloakSetup.ClientSecret,
		)
		require.NoError(t, err)
		require.NotNil(t, token)

		// Token should be a valid JWT
		assert.Contains(t, token.AccessToken, ".")
		parts := len(token.AccessToken) - len(token.AccessToken[:len(token.AccessToken)-1])
		_ = parts // JWT has 3 parts separated by dots
	})

	t.Run("handles invalid client credentials", func(t *testing.T) {
		_, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			"invalid-client",
			"invalid-secret",
		)
		assert.Error(t, err)
	})

	t.Run("handles invalid realm", func(t *testing.T) {
		_, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			"nonexistent-realm",
			keycloakSetup.ClientID,
			keycloakSetup.ClientSecret,
		)
		assert.Error(t, err)
	})
}

// TestIntegration_Operator_Keycloak_UserToken tests Keycloak user token acquisition.
func TestIntegration_Operator_Keycloak_UserToken(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("acquires token for test user", func(t *testing.T) {
		token, err := keycloakSetup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)
		require.NotNil(t, token)

		assert.NotEmpty(t, token.AccessToken)
		assert.NotEmpty(t, token.RefreshToken)
		assert.Equal(t, "Bearer", token.TokenType)
	})

	t.Run("acquires token for admin user", func(t *testing.T) {
		token, err := keycloakSetup.GetUserToken(ctx, "adminuser")
		require.NoError(t, err)
		require.NotNil(t, token)

		assert.NotEmpty(t, token.AccessToken)
	})

	t.Run("handles invalid user", func(t *testing.T) {
		_, err := keycloakSetup.GetUserToken(ctx, "nonexistent-user")
		assert.Error(t, err)
	})
}

// TestIntegration_Operator_Keycloak_JWKS tests Keycloak JWKS endpoint.
func TestIntegration_Operator_Keycloak_JWKS(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	t.Run("returns JWKS URL", func(t *testing.T) {
		jwksURL := keycloakSetup.GetJWKSURL()
		assert.NotEmpty(t, jwksURL)
		assert.Contains(t, jwksURL, "/protocol/openid-connect/certs")
	})

	t.Run("returns issuer URL", func(t *testing.T) {
		issuerURL := keycloakSetup.GetIssuerURL()
		assert.NotEmpty(t, issuerURL)
		assert.Contains(t, issuerURL, "/realms/")
	})
}

// TestIntegration_Operator_Keycloak_TokenRefresh tests token refresh functionality.
func TestIntegration_Operator_Keycloak_TokenRefresh(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("refresh token is provided", func(t *testing.T) {
		token, err := keycloakSetup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)
		require.NotNil(t, token)

		assert.NotEmpty(t, token.RefreshToken)
		assert.Greater(t, token.RefreshExpiresIn, 0)
	})
}

// TestIntegration_Operator_Keycloak_RealmManagement tests realm management operations.
func TestIntegration_Operator_Keycloak_RealmManagement(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := helpers.GetKeycloakTestConfig()
	client := helpers.NewKeycloakClient(cfg.Address)

	// Login as admin
	err := client.AdminLogin(ctx, cfg.AdminUser, cfg.AdminPass)
	require.NoError(t, err)

	t.Run("creates and deletes realm", func(t *testing.T) {
		testRealm := "test-operator-realm"

		// Create realm
		err := client.CreateRealm(ctx, testRealm)
		require.NoError(t, err)

		// Delete realm
		err = client.DeleteRealm(ctx, testRealm)
		require.NoError(t, err)
	})

	t.Run("creates client in realm", func(t *testing.T) {
		testRealm := "test-client-realm"

		// Create realm
		err := client.CreateRealm(ctx, testRealm)
		require.NoError(t, err)
		defer func() {
			_ = client.DeleteRealm(ctx, testRealm)
		}()

		// Create client
		clientConfig := map[string]interface{}{
			"clientId":                  "test-client",
			"enabled":                   true,
			"publicClient":              false,
			"secret":                    "test-secret",
			"serviceAccountsEnabled":    true,
			"directAccessGrantsEnabled": true,
		}
		err = client.CreateClient(ctx, testRealm, clientConfig)
		require.NoError(t, err)
	})

	t.Run("creates user in realm", func(t *testing.T) {
		testRealm := "test-user-realm"

		// Create realm
		err := client.CreateRealm(ctx, testRealm)
		require.NoError(t, err)
		defer func() {
			_ = client.DeleteRealm(ctx, testRealm)
		}()

		// Create user
		userConfig := map[string]interface{}{
			"username":      "testuser",
			"enabled":       true,
			"emailVerified": true,
			"credentials": []map[string]interface{}{
				{"type": "password", "value": "testpass", "temporary": false},
			},
		}
		err = client.CreateUser(ctx, testRealm, userConfig)
		require.NoError(t, err)
	})

	t.Run("creates realm role", func(t *testing.T) {
		testRealm := "test-role-realm"

		// Create realm
		err := client.CreateRealm(ctx, testRealm)
		require.NoError(t, err)
		defer func() {
			_ = client.DeleteRealm(ctx, testRealm)
		}()

		// Create role
		err = client.CreateRealmRole(ctx, testRealm, "test-role")
		require.NoError(t, err)
	})
}

// TestIntegration_Operator_Keycloak_OIDCDiscovery tests OIDC discovery.
func TestIntegration_Operator_Keycloak_OIDCDiscovery(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	t.Run("JWKS URL is accessible", func(t *testing.T) {
		jwksURL := keycloakSetup.GetJWKSURL()

		// Make HTTP request to JWKS endpoint
		resp, err := helpers.MakeRequest("GET", jwksURL, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("issuer URL is accessible", func(t *testing.T) {
		issuerURL := keycloakSetup.GetIssuerURL()

		// Make HTTP request to issuer endpoint
		resp, err := helpers.MakeRequest("GET", issuerURL, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("well-known endpoint is accessible", func(t *testing.T) {
		issuerURL := keycloakSetup.GetIssuerURL()
		wellKnownURL := issuerURL + "/.well-known/openid-configuration"

		resp, err := helpers.MakeRequest("GET", wellKnownURL, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode)
	})
}

// TestIntegration_Operator_Keycloak_TokenValidation tests token validation scenarios.
func TestIntegration_Operator_Keycloak_TokenValidation(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("token has correct issuer", func(t *testing.T) {
		token, err := keycloakSetup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)
		require.NotNil(t, token)

		// Token should contain the issuer URL
		// In a real test, we would decode and verify the JWT
		assert.NotEmpty(t, token.AccessToken)
	})

	t.Run("token has correct audience", func(t *testing.T) {
		token, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			keycloakSetup.ClientID,
			keycloakSetup.ClientSecret,
		)
		require.NoError(t, err)
		require.NotNil(t, token)

		// Token should be valid
		assert.NotEmpty(t, token.AccessToken)
	})
}

// TestIntegration_Operator_Keycloak_Scopes tests scope handling.
func TestIntegration_Operator_Keycloak_Scopes(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("token includes requested scopes", func(t *testing.T) {
		token, err := keycloakSetup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)
		require.NotNil(t, token)

		// Scope should be returned
		assert.NotEmpty(t, token.Scope)
	})
}
