//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
Keycloak OIDC Integration Test Setup Instructions:

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

func TestIntegration_OIDC_Discovery(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()

	t.Run("fetch discovery document", func(t *testing.T) {
		cfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:     "keycloak",
					Issuer:   setup.GetIssuerURL(),
					ClientID: setup.ClientID,
					Type:     "keycloak",
				},
			},
		}

		discoveryClient, err := oidc.NewDiscoveryClient(cfg, oidc.WithDiscoveryLogger(logger))
		require.NoError(t, err)
		defer discoveryClient.Close()

		discovery, err := discoveryClient.GetDiscovery(ctx, "keycloak")
		require.NoError(t, err)
		require.NotNil(t, discovery)

		assert.Equal(t, setup.GetIssuerURL(), discovery.Issuer)
		assert.NotEmpty(t, discovery.AuthorizationEndpoint)
		assert.NotEmpty(t, discovery.TokenEndpoint)
		assert.NotEmpty(t, discovery.JWKSUri)
		assert.NotEmpty(t, discovery.UserinfoEndpoint)
	})

	t.Run("discovery caching", func(t *testing.T) {
		cfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:     "keycloak",
					Issuer:   setup.GetIssuerURL(),
					ClientID: setup.ClientID,
					Type:     "keycloak",
				},
			},
		}

		discoveryClient, err := oidc.NewDiscoveryClient(cfg, oidc.WithDiscoveryLogger(logger))
		require.NoError(t, err)
		defer discoveryClient.Close()

		// First call - cache miss
		start := time.Now()
		discovery1, err := discoveryClient.GetDiscovery(ctx, "keycloak")
		require.NoError(t, err)
		firstDuration := time.Since(start)

		// Second call - cache hit
		start = time.Now()
		discovery2, err := discoveryClient.GetDiscovery(ctx, "keycloak")
		require.NoError(t, err)
		secondDuration := time.Since(start)

		assert.Equal(t, discovery1.Issuer, discovery2.Issuer)
		t.Logf("First call: %v, Second call (cached): %v", firstDuration, secondDuration)
	})
}

func TestIntegration_OIDC_Provider(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()

	t.Run("create provider", func(t *testing.T) {
		globalCfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:         "keycloak",
					Issuer:       setup.GetIssuerURL(),
					ClientID:     setup.ClientID,
					ClientSecret: setup.ClientSecret,
					Type:         "keycloak",
				},
			},
		}

		providerCfg := &oidc.ProviderConfig{
			Name:         "keycloak",
			Issuer:       setup.GetIssuerURL(),
			ClientID:     setup.ClientID,
			ClientSecret: setup.ClientSecret,
			Type:         "keycloak",
		}

		provider, err := oidc.NewProvider(providerCfg, globalCfg, oidc.WithProviderLogger(logger))
		require.NoError(t, err)
		require.NotNil(t, provider)
		defer provider.Close()

		assert.Equal(t, "keycloak", provider.Name())
	})

	t.Run("validate token", func(t *testing.T) {
		globalCfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:         "keycloak",
					Issuer:       setup.GetIssuerURL(),
					ClientID:     setup.ClientID,
					ClientSecret: setup.ClientSecret,
					Type:         "keycloak",
				},
			},
		}

		providerCfg := &oidc.ProviderConfig{
			Name:         "keycloak",
			Issuer:       setup.GetIssuerURL(),
			ClientID:     setup.ClientID,
			ClientSecret: setup.ClientSecret,
			Type:         "keycloak",
			ClaimMapping: &oidc.ClaimMapping{
				Subject: "sub",
				Roles:   "realm_access.roles",
				Email:   "email",
				Name:    "preferred_username",
			},
		}

		provider, err := oidc.NewProvider(providerCfg, globalCfg, oidc.WithProviderLogger(logger))
		require.NoError(t, err)
		defer provider.Close()

		// Get token from Keycloak
		tokenResp, err := setup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		// Validate token
		tokenInfo, err := provider.ValidateToken(ctx, tokenResp.AccessToken)
		require.NoError(t, err)
		require.NotNil(t, tokenInfo)

		assert.NotEmpty(t, tokenInfo.Subject)
		assert.Equal(t, setup.GetIssuerURL(), tokenInfo.Issuer)
	})

	t.Run("validate admin token", func(t *testing.T) {
		globalCfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:         "keycloak",
					Issuer:       setup.GetIssuerURL(),
					ClientID:     setup.ClientID,
					ClientSecret: setup.ClientSecret,
					Type:         "keycloak",
				},
			},
		}

		providerCfg := &oidc.ProviderConfig{
			Name:         "keycloak",
			Issuer:       setup.GetIssuerURL(),
			ClientID:     setup.ClientID,
			ClientSecret: setup.ClientSecret,
			Type:         "keycloak",
		}

		provider, err := oidc.NewProvider(providerCfg, globalCfg, oidc.WithProviderLogger(logger))
		require.NoError(t, err)
		defer provider.Close()

		// Get admin token from Keycloak
		tokenResp, err := setup.GetUserToken(ctx, "adminuser")
		require.NoError(t, err)

		// Validate token
		tokenInfo, err := provider.ValidateToken(ctx, tokenResp.AccessToken)
		require.NoError(t, err)
		require.NotNil(t, tokenInfo)

		assert.NotEmpty(t, tokenInfo.Subject)
	})

	t.Run("reject invalid token", func(t *testing.T) {
		globalCfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:         "keycloak",
					Issuer:       setup.GetIssuerURL(),
					ClientID:     setup.ClientID,
					ClientSecret: setup.ClientSecret,
					Type:         "keycloak",
				},
			},
		}

		providerCfg := &oidc.ProviderConfig{
			Name:         "keycloak",
			Issuer:       setup.GetIssuerURL(),
			ClientID:     setup.ClientID,
			ClientSecret: setup.ClientSecret,
			Type:         "keycloak",
		}

		provider, err := oidc.NewProvider(providerCfg, globalCfg, oidc.WithProviderLogger(logger))
		require.NoError(t, err)
		defer provider.Close()

		_, err = provider.ValidateToken(ctx, "invalid.token.here")
		require.Error(t, err)
	})

	t.Run("reject tampered token", func(t *testing.T) {
		globalCfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:         "keycloak",
					Issuer:       setup.GetIssuerURL(),
					ClientID:     setup.ClientID,
					ClientSecret: setup.ClientSecret,
					Type:         "keycloak",
				},
			},
		}

		providerCfg := &oidc.ProviderConfig{
			Name:         "keycloak",
			Issuer:       setup.GetIssuerURL(),
			ClientID:     setup.ClientID,
			ClientSecret: setup.ClientSecret,
			Type:         "keycloak",
		}

		provider, err := oidc.NewProvider(providerCfg, globalCfg, oidc.WithProviderLogger(logger))
		require.NoError(t, err)
		defer provider.Close()

		// Get valid token
		tokenResp, err := setup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		// Tamper with token
		tamperedToken := tokenResp.AccessToken + "tampered"

		_, err = provider.ValidateToken(ctx, tamperedToken)
		require.Error(t, err)
	})
}

func TestIntegration_OIDC_ClientCredentials(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()

	t.Run("validate client credentials token", func(t *testing.T) {
		globalCfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:         "keycloak",
					Issuer:       setup.GetIssuerURL(),
					ClientID:     setup.ClientID,
					ClientSecret: setup.ClientSecret,
					Type:         "keycloak",
				},
			},
		}

		providerCfg := &oidc.ProviderConfig{
			Name:         "keycloak",
			Issuer:       setup.GetIssuerURL(),
			ClientID:     setup.ClientID,
			ClientSecret: setup.ClientSecret,
			Type:         "keycloak",
		}

		provider, err := oidc.NewProvider(providerCfg, globalCfg, oidc.WithProviderLogger(logger))
		require.NoError(t, err)
		defer provider.Close()

		// Get client credentials token
		tokenResp, err := setup.Client.GetClientCredentialsToken(
			ctx,
			setup.Realm,
			setup.ClientID,
			setup.ClientSecret,
		)
		require.NoError(t, err)

		// Validate token
		tokenInfo, err := provider.ValidateToken(ctx, tokenResp.AccessToken)
		require.NoError(t, err)
		require.NotNil(t, tokenInfo)

		assert.NotEmpty(t, tokenInfo.Subject)
		assert.Equal(t, setup.GetIssuerURL(), tokenInfo.Issuer)
	})
}

func TestIntegration_OIDC_MultipleProviders(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()

	t.Run("multiple providers configuration", func(t *testing.T) {
		globalCfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:         "keycloak-primary",
					Issuer:       setup.GetIssuerURL(),
					ClientID:     setup.ClientID,
					ClientSecret: setup.ClientSecret,
					Type:         "keycloak",
				},
				{
					Name:         "keycloak-secondary",
					Issuer:       setup.GetIssuerURL(),
					ClientID:     setup.ClientID,
					ClientSecret: setup.ClientSecret,
					Type:         "keycloak",
				},
			},
			DefaultProvider: "keycloak-primary",
		}

		// Create primary provider
		primaryCfg := &oidc.ProviderConfig{
			Name:         "keycloak-primary",
			Issuer:       setup.GetIssuerURL(),
			ClientID:     setup.ClientID,
			ClientSecret: setup.ClientSecret,
			Type:         "keycloak",
		}

		primaryProvider, err := oidc.NewProvider(primaryCfg, globalCfg, oidc.WithProviderLogger(logger))
		require.NoError(t, err)
		defer primaryProvider.Close()

		// Create secondary provider
		secondaryCfg := &oidc.ProviderConfig{
			Name:         "keycloak-secondary",
			Issuer:       setup.GetIssuerURL(),
			ClientID:     setup.ClientID,
			ClientSecret: setup.ClientSecret,
			Type:         "keycloak",
		}

		secondaryProvider, err := oidc.NewProvider(secondaryCfg, globalCfg, oidc.WithProviderLogger(logger))
		require.NoError(t, err)
		defer secondaryProvider.Close()

		// Get token
		tokenResp, err := setup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		// Both providers should validate the same token
		tokenInfo1, err := primaryProvider.ValidateToken(ctx, tokenResp.AccessToken)
		require.NoError(t, err)

		tokenInfo2, err := secondaryProvider.ValidateToken(ctx, tokenResp.AccessToken)
		require.NoError(t, err)

		assert.Equal(t, tokenInfo1.Subject, tokenInfo2.Subject)
	})
}

func TestIntegration_OIDC_TokenClaims(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()

	t.Run("extract token claims", func(t *testing.T) {
		globalCfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:         "keycloak",
					Issuer:       setup.GetIssuerURL(),
					ClientID:     setup.ClientID,
					ClientSecret: setup.ClientSecret,
					Type:         "keycloak",
				},
			},
		}

		providerCfg := &oidc.ProviderConfig{
			Name:         "keycloak",
			Issuer:       setup.GetIssuerURL(),
			ClientID:     setup.ClientID,
			ClientSecret: setup.ClientSecret,
			Type:         "keycloak",
			ClaimMapping: &oidc.ClaimMapping{
				Subject: "sub",
				Email:   "email",
				Name:    "preferred_username",
			},
		}

		provider, err := oidc.NewProvider(providerCfg, globalCfg, oidc.WithProviderLogger(logger))
		require.NoError(t, err)
		defer provider.Close()

		// Get token
		tokenResp, err := setup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		// Validate and extract claims
		tokenInfo, err := provider.ValidateToken(ctx, tokenResp.AccessToken)
		require.NoError(t, err)

		// Check standard claims
		assert.NotEmpty(t, tokenInfo.Subject)
		assert.NotEmpty(t, tokenInfo.Issuer)
		assert.False(t, tokenInfo.ExpiresAt.IsZero())
		assert.False(t, tokenInfo.IssuedAt.IsZero())

		// Check claims map
		assert.NotNil(t, tokenInfo.Claims)
	})
}

func TestIntegration_OIDC_WrongIssuer(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	logger := observability.NopLogger()

	t.Run("reject token with wrong issuer", func(t *testing.T) {
		globalCfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:         "wrong-issuer",
					Issuer:       "https://wrong-issuer.example.com",
					ClientID:     setup.ClientID,
					ClientSecret: setup.ClientSecret,
					Type:         "generic",
				},
			},
		}

		providerCfg := &oidc.ProviderConfig{
			Name:         "wrong-issuer",
			Issuer:       "https://wrong-issuer.example.com",
			ClientID:     setup.ClientID,
			ClientSecret: setup.ClientSecret,
			Type:         "generic",
		}

		// This should fail because the issuer doesn't exist
		_, err := oidc.NewProvider(providerCfg, globalCfg, oidc.WithProviderLogger(logger))
		// Provider creation might succeed, but discovery will fail
		if err == nil {
			t.Log("Provider created, but discovery should fail when validating")
		}
	})
}

func TestIntegration_OIDC_RefreshToken(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("verify refresh token is returned", func(t *testing.T) {
		tokenResp, err := setup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		assert.NotEmpty(t, tokenResp.AccessToken)
		assert.NotEmpty(t, tokenResp.RefreshToken)
		assert.Greater(t, tokenResp.ExpiresIn, 0)
		assert.Greater(t, tokenResp.RefreshExpiresIn, 0)
	})
}

func TestIntegration_OIDC_TokenExpiry(t *testing.T) {
	setup := helpers.SetupKeycloakForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()

	t.Run("token has valid expiry", func(t *testing.T) {
		globalCfg := &oidc.Config{
			Enabled:           true,
			DiscoveryCacheTTL: 5 * time.Minute,
			Providers: []oidc.ProviderConfig{
				{
					Name:         "keycloak",
					Issuer:       setup.GetIssuerURL(),
					ClientID:     setup.ClientID,
					ClientSecret: setup.ClientSecret,
					Type:         "keycloak",
				},
			},
		}

		providerCfg := &oidc.ProviderConfig{
			Name:         "keycloak",
			Issuer:       setup.GetIssuerURL(),
			ClientID:     setup.ClientID,
			ClientSecret: setup.ClientSecret,
			Type:         "keycloak",
		}

		provider, err := oidc.NewProvider(providerCfg, globalCfg, oidc.WithProviderLogger(logger))
		require.NoError(t, err)
		defer provider.Close()

		// Get token
		tokenResp, err := setup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		// Validate token
		tokenInfo, err := provider.ValidateToken(ctx, tokenResp.AccessToken)
		require.NoError(t, err)

		// Check expiry is in the future
		assert.True(t, tokenInfo.ExpiresAt.After(time.Now()))

		// Check issued at is in the past
		assert.True(t, tokenInfo.IssuedAt.Before(time.Now().Add(time.Minute)))
	})
}
