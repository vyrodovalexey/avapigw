//go:build integration
// +build integration

// Package integration contains integration tests for the API Gateway.
//
// Live backend-auth tests drive a REAL gateway against the LIVE
// docker-compose auth backends:
//
//	rest_api_4 (:8804)  mTLS     — client certs issued by the live Vault PKI
//	rest_api_3 (:8803)  OIDC     — service-to-service client_credentials
//	                                against the live Keycloak backend-test realm
//	rest_api_5 (:8805)  basic    — credentials read from the live Vault KV
//
// Every test is guarded: it skips cleanly when Vault/Keycloak/the backend is
// not reachable (env vars in helpers.GetLiveAuthBackendConfig control all
// endpoints).
package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// liveAuthGatewayPort is the listener port base for live-backend gateways.
const liveAuthGatewayPort = 18481

// buildLiveBackendGatewayConfig builds a single-route gateway config
// proxying /api/v1/items (GET) and /health to the named backend.
func buildLiveBackendGatewayConfig(port int, backendCfg config.Backend) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "live-backend-auth-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     port,
					Protocol: config.ProtocolHTTP,
					Bind:     "127.0.0.1",
				},
			},
			Routes: []config.Route{
				{
					// Gateway-local readiness probe: must not depend on the
					// (possibly auth-rejecting) live backend.
					Name: "gateway-health",
					Match: []config.RouteMatch{
						{
							URI:     &config.URIMatch{Exact: "/gw-health"},
							Methods: []string{http.MethodGet},
						},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status: http.StatusOK,
						Body:   `{"status":"ready"}`,
					},
				},
				{
					Name: "live-backend-route",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/"}},
					},
					Route: []config.RouteDestination{
						{
							// Destination host references the backend by NAME
							// so the registry's TLS transport + auth provider
							// are applied by the reverse proxy.
							Destination: config.Destination{
								Host: backendCfg.Name,
								Port: backendCfg.Hosts[0].Port,
							},
						},
					},
					Timeout: config.Duration(15 * time.Second),
				},
			},
			Backends: []config.Backend{backendCfg},
		},
	}
}

// requestThroughGateway GETs the path through the gateway and returns the
// response status.
func requestThroughGateway(t *testing.T, baseURL, path string) int {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
	require.NoError(t, err)

	resp, err := helpers.HTTPClient().Do(req)
	require.NoError(t, err, "request through gateway failed")
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestIntegration_LiveBackend_MTLS_VaultPKIFileCerts verifies the gateway
// route -> rest_api_4 journey with backend mTLS using client certificates
// issued at test runtime by the LIVE Vault PKI (client-role), configured
// file-based on the backend TLS block.
func TestIntegration_LiveBackend_MTLS_VaultPKIFileCerts(t *testing.T) {
	live := helpers.GetLiveAuthBackendConfig()
	helpers.SkipIfVaultUnavailable(t)
	helpers.SkipIfTCPUnreachable(t, live.MTLSRestAddr, "rest_api_4 (mTLS)")

	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	// Issue a fresh client certificate from the live Vault PKI client role.
	clientCert := helpers.IssueVaultClientCert(
		t, vaultSetup, live.VaultClientCertRole, "avapigw-live-test-client")

	host, port := splitHostPortOrFatal(t, live.MTLSRestAddr)

	backendCfg := config.Backend{
		Name:  "rest-mtls-backend",
		Hosts: []config.BackendHost{{Address: host, Port: port, Weight: 1}},
		TLS: &config.BackendTLSConfig{
			Enabled:  true,
			Mode:     config.BackendTLSModeMutual,
			CertFile: clientCert.CertFile,
			KeyFile:  clientCert.KeyFile,
			CAFile:   clientCert.CAFile,
			// The compose server cert carries SANs localhost/127.0.0.1.
			ServerName: "localhost",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	gi, err := helpers.StartGatewayWithConfigAndVault(
		ctx, buildLiveBackendGatewayConfig(liveAuthGatewayPort, backendCfg), nil)
	require.NoError(t, err, "failed to start gateway with mTLS backend")
	t.Cleanup(func() { _ = gi.Stop(ctx) })

	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/gw-health", 10*time.Second))

	t.Run("request reaches mTLS backend through gateway", func(t *testing.T) {
		status := requestThroughGateway(t, gi.BaseURL, "/api/v1/items")
		assert.Equal(t, http.StatusOK, status,
			"gateway with Vault-issued client cert must reach the mTLS backend")
		t.Logf("mTLS journey OK: client -> gateway -> rest_api_4 (%s)", live.MTLSRestAddr)
	})

	t.Run("gateway without client cert is rejected by backend", func(t *testing.T) {
		noCert := backendCfg
		noCert.Name = "rest-mtls-nocert"
		noCert.TLS = &config.BackendTLSConfig{
			Enabled:    true,
			Mode:       config.BackendTLSModeSimple,
			CAFile:     clientCert.CAFile,
			ServerName: "localhost",
		}

		gi2, err := helpers.StartGatewayWithConfigAndVault(
			ctx, buildLiveBackendGatewayConfig(liveAuthGatewayPort+1, noCert), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = gi2.Stop(ctx) })
		require.NoError(t, helpers.WaitForReady(gi2.BaseURL+"/gw-health", 10*time.Second))

		status := requestThroughGateway(t, gi2.BaseURL, "/api/v1/items")
		assert.Equal(t, http.StatusBadGateway, status,
			"missing client certificate must surface as 502 from the gateway")
	})
}

// TestIntegration_LiveBackend_MTLS_VaultRuntimeCerts verifies the same
// journey with the backend tls.vault flow: the GATEWAY itself obtains the
// client certificate from the live Vault PKI at startup (no cert files).
func TestIntegration_LiveBackend_MTLS_VaultRuntimeCerts(t *testing.T) {
	live := helpers.GetLiveAuthBackendConfig()
	helpers.SkipIfVaultUnavailable(t)
	helpers.SkipIfTCPUnreachable(t, live.MTLSRestAddr, "rest_api_4 (mTLS)")

	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	// CA for server verification still comes from PKI (exported to a file).
	caCert := helpers.IssueVaultClientCert(
		t, vaultSetup, live.VaultClientCertRole, "avapigw-ca-probe")

	host, port := splitHostPortOrFatal(t, live.MTLSRestAddr)

	backendCfg := config.Backend{
		Name:  "rest-mtls-vault-backend",
		Hosts: []config.BackendHost{{Address: host, Port: port, Weight: 1}},
		TLS: &config.BackendTLSConfig{
			Enabled:    true,
			Mode:       config.BackendTLSModeMutual,
			CAFile:     caCert.CAFile,
			ServerName: "localhost",
			Vault: &config.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   vaultSetup.PKIMount,
				Role:       live.VaultClientCertRole,
				CommonName: "avapigw-runtime-client",
				TTL:        "1h",
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vaultClient := helpers.NewInternalVaultClient(t)

	gi, err := helpers.StartGatewayWithConfigAndVault(
		ctx, buildLiveBackendGatewayConfig(liveAuthGatewayPort+2, backendCfg), vaultClient)
	require.NoError(t, err, "failed to start gateway with tls.vault backend")
	t.Cleanup(func() { _ = gi.Stop(ctx) })

	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/gw-health", 10*time.Second))

	status := requestThroughGateway(t, gi.BaseURL, "/api/v1/items")
	assert.Equal(t, http.StatusOK, status,
		"gateway with Vault-runtime client cert must reach the mTLS backend")
	t.Log("tls.vault journey OK: gateway issued its client cert from live Vault PKI")
}

// TestIntegration_LiveBackend_OIDC_S2S verifies the gateway route ->
// rest_api_3 journey with backend OIDC: the gateway acquires a
// client_credentials token from the LIVE Keycloak backend-test realm and
// attaches it to backend requests.
//
// The compose backend validates iss=http://host.docker.internal:8090/... ,
// which is not resolvable from the test host; the issuer-rewrite proxy
// bridges the DNS gap while keeping Keycloak minting backend-valid tokens
// (see helpers.StartIssuerRewriteProxy).
func TestIntegration_LiveBackend_OIDC_S2S(t *testing.T) {
	live := helpers.GetLiveAuthBackendConfig()
	helpers.SkipIfKeycloakUnavailable(t)
	helpers.SkipIfBackendUnavailable(t, live.OIDCRestURL)

	issuerProxy := helpers.StartIssuerRewriteProxy(t, live.KeycloakURL, live.BackendIssuerHost)
	issuerURL := fmt.Sprintf("%s/realms/%s", issuerProxy, live.BackendRealm)

	host, port := parseURLHostPortForTest(t, live.OIDCRestURL)

	backendCfg := config.Backend{
		Name:  "rest-oidc-backend",
		Hosts: []config.BackendHost{{Address: host, Port: port, Weight: 1}},
		Authentication: &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &config.BackendOIDCConfig{
					IssuerURL:    issuerURL,
					ClientID:     live.BackendClientID,
					ClientSecret: live.BackendClientSecret,
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	gi, err := helpers.StartGatewayWithConfigAndVault(
		ctx, buildLiveBackendGatewayConfig(liveAuthGatewayPort+3, backendCfg), nil)
	require.NoError(t, err, "failed to start gateway with OIDC backend auth")
	t.Cleanup(func() { _ = gi.Stop(ctx) })

	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/gw-health", 10*time.Second))

	t.Run("token attached and accepted by live backend", func(t *testing.T) {
		status := requestThroughGateway(t, gi.BaseURL, "/api/v1/items")
		assert.Equal(t, http.StatusOK, status,
			"gateway-acquired client_credentials token must be accepted by rest_api_3")
		t.Logf("OIDC S2S journey OK: gateway -> Keycloak(%s) -> rest_api_3", live.BackendRealm)
	})

	t.Run("without backend auth the live backend rejects", func(t *testing.T) {
		noAuth := backendCfg
		noAuth.Name = "rest-oidc-noauth"
		noAuth.Authentication = nil

		gi2, err := helpers.StartGatewayWithConfigAndVault(
			ctx, buildLiveBackendGatewayConfig(liveAuthGatewayPort+4, noAuth), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = gi2.Stop(ctx) })
		require.NoError(t, helpers.WaitForReady(gi2.BaseURL+"/gw-health", 10*time.Second))

		status := requestThroughGateway(t, gi2.BaseURL, "/api/v1/items")
		assert.Equal(t, http.StatusUnauthorized, status,
			"request without a token must pass through as 401 from the backend")
	})
}

// TestIntegration_LiveBackend_BasicAuth_VaultKV verifies the gateway route
// -> rest_api_5 journey with backend basic auth whose credentials are read
// from the LIVE Vault KV (secret/backend-auth/basic, provisioned by
// setup-vault.sh).
func TestIntegration_LiveBackend_BasicAuth_VaultKV(t *testing.T) {
	live := helpers.GetLiveAuthBackendConfig()
	helpers.SkipIfVaultUnavailable(t)
	helpers.SkipIfBackendUnavailable(t, live.BasicRestURL)

	vaultClient := helpers.NewInternalVaultClient(t)

	host, port := parseURLHostPortForTest(t, live.BasicRestURL)

	backendCfg := config.Backend{
		Name:  "rest-basic-backend",
		Hosts: []config.BackendHost{{Address: host, Port: port, Weight: 1}},
		Authentication: &config.BackendAuthConfig{
			Type: "basic",
			Basic: &config.BackendBasicAuthConfig{
				Enabled:   true,
				VaultPath: live.VaultBasicAuthPath,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	gi, err := helpers.StartGatewayWithConfigAndVault(
		ctx, buildLiveBackendGatewayConfig(liveAuthGatewayPort+5, backendCfg), vaultClient)
	require.NoError(t, err, "failed to start gateway with Vault-KV basic auth")
	t.Cleanup(func() { _ = gi.Stop(ctx) })

	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/gw-health", 10*time.Second))

	t.Run("Vault KV credentials accepted by live backend", func(t *testing.T) {
		status := requestThroughGateway(t, gi.BaseURL, "/api/v1/items")
		assert.Equal(t, http.StatusOK, status,
			"credentials from Vault KV %s must be accepted by rest_api_5",
			live.VaultBasicAuthPath)
		t.Logf("basic-auth journey OK: gateway -> Vault KV(%s) -> rest_api_5",
			live.VaultBasicAuthPath)
	})

	t.Run("without backend auth the live backend rejects", func(t *testing.T) {
		noAuth := backendCfg
		noAuth.Name = "rest-basic-noauth"
		noAuth.Authentication = nil

		gi2, err := helpers.StartGatewayWithConfigAndVault(
			ctx, buildLiveBackendGatewayConfig(liveAuthGatewayPort+6, noAuth), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = gi2.Stop(ctx) })
		require.NoError(t, helpers.WaitForReady(gi2.BaseURL+"/gw-health", 10*time.Second))

		status := requestThroughGateway(t, gi2.BaseURL, "/api/v1/items")
		assert.Equal(t, http.StatusUnauthorized, status,
			"request without credentials must pass through as 401 from the backend")
	})
}

// splitHostPortOrFatal splits host:port, failing the test on error.
func splitHostPortOrFatal(t *testing.T, hostport string) (string, int) {
	t.Helper()
	info := helpers.GetGRPCBackendInfo(hostport)
	if info.Host == "" || info.Port == 0 {
		t.Fatalf("invalid host:port %q", hostport)
	}
	return info.Host, info.Port
}

// parseURLHostPortForTest extracts host/port from a URL, failing on error.
func parseURLHostPortForTest(t *testing.T, url string) (string, int) {
	t.Helper()
	info := helpers.GetGraphQLBackendInfo(url)
	if info.Host == "" || info.Port == 0 {
		t.Fatalf("invalid URL %q", url)
	}
	return info.Host, info.Port
}
