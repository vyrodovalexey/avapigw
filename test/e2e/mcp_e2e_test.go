//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
MCP E2E Test Setup Instructions:

These tests drive the full gateway MCP hub lifecycle against the docker-compose
ENV: the MCP mock upstreams, Keycloak (gateway-test realm) and Redis Sentinel.

Run:
  TEST_MCP_BACKEND1_URL=http://127.0.0.1:8821/mcp \
  TEST_MCP_BACKEND2_URL=http://127.0.0.1:8822/mcp \
  TEST_REDIS_SENTINEL_ADDRS=127.0.0.1:26379,127.0.0.1:26380,127.0.0.1:26381 \
  TEST_REDIS_SENTINEL_MASTER_NAME=mymaster \
  TEST_REDIS_MASTER_PASSWORD=password \
  KEYCLOAK_ADDR=http://127.0.0.1:8090 \
  GOTOOLCHAIN=local go test -tags=e2e ./test/e2e/ -run MCP

The downstream MCP route is the OAuth 2.1 resource server: the gateway validates
a Keycloak-minted bearer at the MCP route (route-level JWT via the realm JWKS).
Rate limiting is enforced on the same route via the Redis Sentinel store.

NOTE (mock Phase-1 limitation): the docker MCP mock validates SHORT _meta keys
(protocolVersion/clientCapabilities) while the gateway emits the vendor-prefixed
io.modelcontextprotocol/* keys upstream, so a fully authorized request that
reaches the mock returns HTTP 400 -> 502 at the gateway. These e2e tests
therefore assert the DOWNSTREAM policy outcomes (401 unauth, 200/authorized past
auth, 429 throttled) which are decided BEFORE the upstream call, and do not
depend on a successful upstream round-trip. See test/integration/mcp_test.go for
the full explanation.
*/

// mcpJWTAuth builds route-level JWT authentication validating tokens against the
// Keycloak realm JWKS (the gateway acts as the MCP resource server).
func mcpJWTAuth(kc *helpers.KeycloakTestSetup) *config.AuthenticationConfig {
	return &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled:   true,
			Algorithm: "RS256",
			JWKSURL:   kc.GetJWKSURL(),
			Issuer:    kc.GetIssuerURL(),
		},
	}
}

// mcpSentinelRateLimit builds a route-level Redis-backed rate limit against the
// Sentinel-managed master. The config-driven route middleware cannot inject the
// Docker-aware dialer that host-side tests need (sentinel discovers the master
// at an unreachable Docker-internal IP), so — exactly like the passing
// TestE2E_FullConfig_* redis rate-limit test — this targets the master's
// host-mapped port directly. It is the same Sentinel-managed master, exercising
// the real distributed Redis token bucket on the MCP route.
func mcpSentinelRateLimit(keyPrefix string, burst int) *config.RateLimitConfig {
	masterURL := fmt.Sprintf("redis://default:%s@127.0.0.1:%s",
		helpers.GetRedisMasterPassword(), helpers.GetRedisSentinelMasterPort())
	return &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             burst,
		Store:             config.RateLimitStoreRedis,
		Redis: &config.RateLimitRedisConfig{
			URL:         masterURL,
			KeyPrefix:   keyPrefix,
			ReadTimeout: config.Duration(250 * time.Millisecond),
		},
	}
}

// mcpCallBody builds a valid tools/call echo request body.
func mcpCallBody() []byte {
	return helpers.MCPRequestBody{
		Method:    helpers.MCPMethodToolsCall,
		Name:      "m1.echo",
		Arguments: map[string]any{"message": "e2e"},
	}.MustBuild()
}

// TestE2E_MCP_HTTP_OIDC_And_RateLimit drives the HTTP MCP hub with OIDC auth and
// Redis Sentinel rate limiting on the downstream MCP route.
func TestE2E_MCP_HTTP_OIDC_And_RateLimit(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)
	helpers.SkipIfRedisSentinelUnavailable(t)
	mcpCfg := helpers.GetMCPTestConfig()
	helpers.SkipIfMCPMockUnavailable(t, mcpCfg.Backend1URL)

	kc := helpers.SetupKeycloakForTesting(t)
	defer kc.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	rlPrefix := helpers.GenerateTestKeyPrefix("e2e_mcp_rl")
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = helpers.CleanupRedis(sentinelClient, rlPrefix)
		_ = sentinelClient.Close()
	})

	port, err := helpers.GetFreeTCPPort()
	require.NoError(t, err)

	be, err := helpers.MCPBackendFromURL("m1", mcpCfg.Backend1URL)
	require.NoError(t, err)

	const burst = 5
	cfg := helpers.BuildMCPGatewayConfig(helpers.MCPGatewayConfigOptions{
		Name:           "e2e-mcp-http-gw",
		Port:           port,
		Backends:       []config.MCPBackend{be},
		RouteName:      "mcp-secure",
		Authentication: mcpJWTAuth(kc),
		RateLimit:      mcpSentinelRateLimit(rlPrefix, burst),
	})

	gi, err := helpers.StartMCPGateway(ctx, cfg, helpers.WithMCPRouteMiddleware())
	require.NoError(t, err)
	t.Cleanup(func() { _ = gi.Stop(context.Background()) })

	tokenResp, err := kc.GetUserToken(ctx, "testuser")
	require.NoError(t, err)
	bearer := "Bearer " + tokenResp.AccessToken

	t.Run("1. request without a token is rejected with 401", func(t *testing.T) {
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, mcpCallBody(), helpers.MCPRequestOptions{
			Method: helpers.MCPMethodToolsCall,
			Name:   "m1.echo",
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.NotEmpty(t, resp.Header.Get("WWW-Authenticate"),
			"401 must carry a WWW-Authenticate challenge")
	})

	t.Run("2. request with an invalid token is rejected with 401", func(t *testing.T) {
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, mcpCallBody(), helpers.MCPRequestOptions{
			Method:        helpers.MCPMethodToolsCall,
			Name:          "m1.echo",
			Authorization: "Bearer invalid.token.value",
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("3. a valid token passes authentication (not 401)", func(t *testing.T) {
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, mcpCallBody(), helpers.MCPRequestOptions{
			Method:        helpers.MCPMethodToolsCall,
			Name:          "m1.echo",
			Authorization: bearer,
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		// The request passes auth; the upstream mock rejects the vendored _meta
		// (Phase-1) so the outcome is 200 (success) or 502/500 (upstream error),
		// never 401.
		assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode,
			"a valid Keycloak bearer must pass the MCP route auth")
	})

	t.Run("4. exceeding the burst is throttled with 429", func(t *testing.T) {
		var throttled bool
		for i := 0; i < burst+5; i++ {
			resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, mcpCallBody(), helpers.MCPRequestOptions{
				Method:        helpers.MCPMethodToolsCall,
				Name:          "m1.echo",
				Authorization: bearer,
			})
			require.NoError(t, err)
			resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests {
				throttled = true
				break
			}
		}
		assert.True(t, throttled, "the MCP route rate limit must eventually return 429")
	})

	t.Run("5. a sentinel-backed rate-limit bucket exists on the master", func(t *testing.T) {
		keys, err := sentinelClient.Keys(ctx, rlPrefix+"*").Result()
		require.NoError(t, err)
		assert.NotEmpty(t, keys,
			"the MCP route rate limiter must create at least one bucket key under %q", rlPrefix)
	})
}

// TestE2E_MCP_TLS_OIDC_And_RateLimit drives the HTTPS MCP hub (gateway
// terminates TLS; the upstream mock stays plain HTTP) with OIDC + rate limiting.
func TestE2E_MCP_TLS_OIDC_And_RateLimit(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)
	helpers.SkipIfRedisSentinelUnavailable(t)
	mcpCfg := helpers.GetMCPTestConfig()
	helpers.SkipIfMCPMockUnavailable(t, mcpCfg.Backend1URL)

	kc := helpers.SetupKeycloakForTesting(t)
	defer kc.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// TLS certificates for the HTTPS listener.
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	t.Cleanup(certs.Cleanup)

	rlPrefix := helpers.GenerateTestKeyPrefix("e2e_mcp_tls_rl")
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = helpers.CleanupRedis(sentinelClient, rlPrefix)
		_ = sentinelClient.Close()
	})

	port, err := helpers.GetFreeTCPPort()
	require.NoError(t, err)

	be, err := helpers.MCPBackendFromURL("m1", mcpCfg.Backend1URL)
	require.NoError(t, err)

	const burst = 5
	cfg := helpers.BuildMCPGatewayConfig(helpers.MCPGatewayConfigOptions{
		Name:           "e2e-mcp-tls-gw",
		Port:           port,
		Certs:          certs,
		Backends:       []config.MCPBackend{be},
		RouteName:      "mcp-tls-secure",
		Authentication: mcpJWTAuth(kc),
		RateLimit:      mcpSentinelRateLimit(rlPrefix, burst),
	})

	gi, err := helpers.StartMCPGateway(ctx, cfg, helpers.WithMCPRouteMiddleware())
	require.NoError(t, err)
	t.Cleanup(func() { _ = gi.Stop(context.Background()) })

	// TLS client trusting the test CA.
	clientTLS, err := certs.GetClientTLSConfig()
	require.NoError(t, err)
	tlsClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: clientTLS},
	}

	tokenResp, err := kc.GetUserToken(ctx, "testuser")
	require.NoError(t, err)
	bearer := "Bearer " + tokenResp.AccessToken

	t.Run("1. HTTPS request without a token is rejected with 401", func(t *testing.T) {
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, mcpCallBody(), helpers.MCPRequestOptions{
			Method: helpers.MCPMethodToolsCall,
			Name:   "m1.echo",
			Client: tlsClient,
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("2. HTTPS request with a valid token passes auth over TLS", func(t *testing.T) {
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, mcpCallBody(), helpers.MCPRequestOptions{
			Method:        helpers.MCPMethodToolsCall,
			Name:          "m1.echo",
			Authorization: bearer,
			Client:        tlsClient,
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		// Confirm the connection was actually over TLS (>= TLS 1.2).
		require.NotNil(t, resp.TLS, "response must have been served over TLS")
		assert.GreaterOrEqual(t, resp.TLS.Version, uint16(tls.VersionTLS12),
			"MCP over HTTPS must negotiate at least TLS 1.2")
		assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode,
			"a valid Keycloak bearer must pass the MCP route auth over TLS")
	})

	t.Run("3. HTTPS burst exhaustion is throttled with 429", func(t *testing.T) {
		var throttled bool
		for i := 0; i < burst+5; i++ {
			resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, mcpCallBody(), helpers.MCPRequestOptions{
				Method:        helpers.MCPMethodToolsCall,
				Name:          "m1.echo",
				Authorization: bearer,
				Client:        tlsClient,
			})
			require.NoError(t, err)
			resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests {
				throttled = true
				break
			}
		}
		assert.True(t, throttled, "the MCP route rate limit must eventually return 429 over TLS")
	})
}
