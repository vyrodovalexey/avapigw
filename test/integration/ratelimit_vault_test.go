//go:build integration
// +build integration

// Package integration contains integration tests for the API Gateway.
// This file verifies that the redis-backed route rate limiter resolves the
// Redis password from Vault (passwordVaultPath), mirroring the existing
// cache Vault-password integration pattern, through the FULL production
// route chain.
package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestIntegration_RateLimit_RedisStore_VaultPassword verifies that a route
// rate limiter with store=redis and passwordVaultPath connects to the
// password-protected sentinel master using the password resolved from
// Vault, and enforces the configured limits through the full route chain.
func TestIntegration_RateLimit_RedisStore_VaultPassword(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	helpers.SkipIfVaultUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("it_rl_vaultpw")

	// Store the master password in Vault (same pattern as the cache
	// Vault-password integration test).
	vaultSetup := helpers.SetupVaultForTesting(t)
	require.NoError(t, vaultSetup.WriteSecret("redis/ratelimit", map[string]interface{}{
		"password": helpers.GetRedisMasterPassword(),
	}), "should write redis password to vault")
	t.Cleanup(func() { _ = vaultSetup.DeleteSecret("redis/ratelimit") })

	// Cleanup bucket keys on the master.
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
		_ = sentinelClient.Close()
	})

	// Vault client for the gateway (token auth against the dev Vault).
	vaultCfg := &vault.Config{
		Enabled:    true,
		Address:    helpers.GetVaultAddr(),
		AuthMethod: vault.AuthMethodToken,
		Token:      helpers.GetVaultToken(),
	}
	vc, err := vault.New(vaultCfg, logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = vc.Close() })
	require.NoError(t, vc.Authenticate(ctx))

	// URL deliberately carries NO password: it must come from Vault.
	const routeName = "rl-vault-password"
	masterURL := fmt.Sprintf("redis://default@127.0.0.1:%s", helpers.GetRedisSentinelMasterPort())
	failOpen := false

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "rl-vaultpw-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 18435, Protocol: config.ProtocolHTTP, Bind: "127.0.0.1"},
			},
			Routes: []config.Route{
				{
					Name: "health-check",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Exact: "/health"}, Methods: []string{"GET"}},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status: 200, Body: `{"status":"healthy"}`,
						Headers: map[string]string{"Content-Type": "application/json"},
					},
				},
				{
					Name: routeName,
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/"}, Methods: []string{"GET"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}, Weight: 100},
					},
					Timeout: config.Duration(15 * time.Second),
					RateLimit: &config.RateLimitConfig{
						Enabled:           true,
						RequestsPerSecond: 1,
						Burst:             3,
						Store:             config.RateLimitStoreRedis,
						Redis: &config.RateLimitRedisConfig{
							URL:               masterURL,
							KeyPrefix:         keyPrefix,
							PasswordVaultPath: helpers.GetVaultKVMount() + "/redis/ratelimit",
							ReadTimeout:       config.Duration(250 * time.Millisecond),
							// Fail closed: if the Vault password were not
							// resolved, requests would be rejected instead
							// of silently unlimited, failing the test.
							FailOpen: &failOpen,
							Retry: &config.RedisRetryConfig{
								MaxRetries:     2,
								InitialBackoff: config.Duration(50 * time.Millisecond),
								MaxBackoff:     config.Duration(200 * time.Millisecond),
							},
						},
					},
				},
			},
		},
	}

	gi, err := helpers.StartGatewayWithRouteMiddleware(ctx, cfg,
		helpers.WithRouteMiddlewareGatewayVaultClient(vc))
	require.NoError(t, err)
	t.Cleanup(func() { _ = gi.Stop(context.Background()) })
	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second))

	// The limiter authenticated with the Vault-resolved password: within
	// burst requests pass, past-burst requests are throttled (a password
	// failure with failOpen=false would reject everything with 429).
	allowed, denied := sentinelFireRequests(t, gi.BaseURL+"/api/v1/items", 8)
	t.Logf("vault-password limiter split: allowed=%d denied=%d (burst=3)", allowed, denied)

	assert.GreaterOrEqual(t, allowed, 3, "burst must be admitted with the vault-resolved password")
	assert.LessOrEqual(t, allowed, 4, "admitted requests must stay within burst plus refill slack")
	assert.GreaterOrEqual(t, denied, 4, "past-burst requests must be denied")

	bucketKey := keyPrefix + "ratelimit:" + routeName
	exists, err := sentinelClient.Exists(ctx, bucketKey).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), exists,
		"bucket key %s must exist on the password-protected master", bucketKey)
}
