//go:build integration
// +build integration

// Package integration contains integration tests for the API Gateway.
//
// Live backend-auth tests drive a REAL gateway against the LIVE
// docker-compose auth backends:
//
//	rest_api_4 (:8804)  mTLS     — client certs from the live Vault PKI
//	rest_api_3 (:8803)  OIDC     — service-to-service client_credentials
//	                                against the live Keycloak backend-test realm
//	rest_api_5 (:8805)  basic    — credentials read from the live Vault KV
//
// Every test is guarded twice: it skips cleanly when Vault/Keycloak/the
// backend is not reachable AND it pre-flights the backend auth contract
// DIRECTLY (bypassing the gateway) with the exact material the gateway will
// use. Pre-flight failure means environment drift (CA generation mismatch,
// stale backend certs, image/auth-mode drift) and skips with a precise
// diagnostic; pre-flight success makes every gateway-path assertion STRICT.
// Env vars in helpers.GetLiveAuthBackendConfig control all endpoints.
package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

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

// Bounded retry for the first gateway-path request of a journey: absorbs
// transient 502s while backends churn without ever weakening the final
// assertion (the caller still require.Equal's the returned status).
const (
	gatewayJourneyAttempts = 5
	gatewayJourneyBackoff  = 250 * time.Millisecond
)

// requestThroughGatewayEventually GETs the path through the gateway,
// retrying up to gatewayJourneyAttempts with linear backoff (~5s total)
// while the status differs from want. The FINAL status is returned for a
// strict assertion by the caller.
func requestThroughGatewayEventually(t *testing.T, baseURL, path string, want int) int {
	t.Helper()

	status := 0
	for attempt := 1; attempt <= gatewayJourneyAttempts; attempt++ {
		status = requestThroughGateway(t, baseURL, path)
		if status == want {
			return status
		}
		t.Logf("gateway journey attempt %d/%d: got %d, want %d — retrying",
			attempt, gatewayJourneyAttempts, status, want)
		if attempt < gatewayJourneyAttempts {
			time.Sleep(time.Duration(attempt) * gatewayJourneyBackoff)
		}
	}
	return status
}

// TestIntegration_LiveBackend_MTLS_VaultPKIFileCerts verifies the gateway
// route -> rest_api_4 journey with backend mTLS using the client
// certificate files provisioned from the LIVE Vault PKI by setup-vault.sh
// (test/docker-compose/certs), configured file-based on the backend TLS
// block — the same CA generation the backend loaded at container start.
func TestIntegration_LiveBackend_MTLS_VaultPKIFileCerts(t *testing.T) {
	live := helpers.GetLiveAuthBackendConfig()
	helpers.SkipIfTCPUnreachable(t, live.MTLSRestAddr, "rest_api_4 (mTLS)")

	// The exact TLS material the with-cert journey will use (gitignored;
	// provisioned by setup-vault.sh). Resolution failure only skips the
	// with-cert subtest: the no-cert rejection subtest below is
	// deliberately file-independent so it runs under every drift mode.
	clientCert, certErr := helpers.ProvisionedClientCert()

	host, port := splitHostPortOrFatal(t, live.MTLSRestAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("request reaches mTLS backend through gateway", func(t *testing.T) {
		if certErr != nil {
			t.Skipf("backend mTLS contract not satisfied: %v — "+
				"run test/docker-compose/scripts/setup-vault.sh "+
				"(environment not provisioned); skipping", certErr)
		}
		// Pre-flight: prove the backend accepts EXACTLY this material
		// directly, so a gateway-path failure below is a gateway bug.
		if pfErr := helpers.PreflightDirectMTLS(live.MTLSRestAddr, "localhost", clientCert); pfErr != nil {
			t.Skipf("backend mTLS contract not satisfied: direct handshake failed (%v) — "+
				"CA generation mismatch, stale backend certs, or a non-mTLS service on the port "+
				"(run setup-vault.sh + make test-env-restart-auth-backends); environment drift; skipping", pfErr)
		}

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

		gi, err := helpers.StartGatewayWithConfigAndVault(
			ctx, buildLiveBackendGatewayConfig(liveAuthGatewayPort, backendCfg), nil)
		require.NoError(t, err, "failed to start gateway with mTLS backend")
		t.Cleanup(func() { _ = gi.Stop(ctx) })
		require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/gw-health", 10*time.Second))

		status := requestThroughGatewayEventually(t, gi.BaseURL, "/api/v1/items", http.StatusOK)
		require.Equal(t, http.StatusOK, status,
			"gateway with the provisioned Vault PKI client cert must reach the mTLS backend")
		t.Logf("mTLS journey OK: client -> gateway -> rest_api_4 (%s)", live.MTLSRestAddr)
	})

	// Runs under EVERY drift mode (missing cert files, CA generation
	// mismatch): rejecting a certificate-less connection depends only on
	// the backend requiring client certs, so server verification is
	// intentionally skipped to avoid any dependency on provisioned files.
	t.Run("gateway without client cert is rejected by backend", func(t *testing.T) {
		noCert := config.Backend{
			Name:  "rest-mtls-nocert",
			Hosts: []config.BackendHost{{Address: host, Port: port, Weight: 1}},
			TLS: &config.BackendTLSConfig{
				Enabled:            true,
				Mode:               config.BackendTLSModeSimple,
				InsecureSkipVerify: true,
				ServerName:         "localhost",
			},
		}

		gi2, err := helpers.StartGatewayWithConfigAndVault(
			ctx, buildLiveBackendGatewayConfig(liveAuthGatewayPort+1, noCert), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = gi2.Stop(ctx) })
		require.NoError(t, helpers.WaitForReady(gi2.BaseURL+"/gw-health", 10*time.Second))

		status := requestThroughGatewayEventually(t, gi2.BaseURL, "/api/v1/items", http.StatusBadGateway)
		require.Equal(t, http.StatusBadGateway, status,
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

	// Probe material: a cert freshly issued from the live PKI client role.
	// It carries the CURRENT Vault CA generation — exactly what the
	// gateway's tls.vault flow will obtain at startup. Its issuing CA also
	// serves as the CAFile for server verification.
	caCert := helpers.IssueVaultClientCert(
		t, vaultSetup, live.VaultClientCertRole, "avapigw-ca-probe")

	// Pre-flight: the backend must accept the CURRENT Vault CA generation
	// directly. A fresh Vault (or rotated PKI root) without a backend
	// restart fails here — that is environment drift, not a gateway bug.
	if pfErr := helpers.PreflightDirectMTLS(live.MTLSRestAddr, "localhost", caCert); pfErr != nil {
		t.Skipf("backend mTLS contract not satisfied: direct handshake with a freshly "+
			"Vault-issued client cert failed (%v) — CA generation mismatch between Vault and "+
			"the backend's startup-loaded certs, or a non-mTLS service on the port "+
			"(run setup-vault.sh + make test-env-restart-auth-backends); environment drift; skipping", pfErr)
	}

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

	status := requestThroughGatewayEventually(t, gi.BaseURL, "/api/v1/items", http.StatusOK)
	// require (not assert): the success log below must NEVER print after a
	// failed journey assertion.
	require.Equal(t, http.StatusOK, status,
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
	helpers.SkipIfKeycloakRealmMissing(t, live.KeycloakURL, live.BackendRealm)
	helpers.SkipIfBackendUnavailable(t, live.OIDCRestURL)

	issuerProxy := helpers.StartIssuerRewriteProxy(t, live.KeycloakURL, live.BackendIssuerHost)
	issuerURL := fmt.Sprintf("%s/realms/%s", issuerProxy, live.BackendRealm)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Pre-flight the backend OIDC contract directly (bypassing the
	// gateway) with exactly the token material the gateway will acquire.
	itemsURL := live.OIDCRestURL + "/api/v1/items"
	if pfErr := helpers.PreflightHTTPStatus(ctx, itemsURL, nil, http.StatusUnauthorized); pfErr != nil {
		t.Skipf("backend OIDC contract not satisfied: %v — "+
			"auth mode/image drift on rest_api_3; environment drift; skipping", pfErr)
	}
	token, tokenErr := helpers.MintClientCredentialsToken(
		ctx, issuerURL, live.BackendClientID, live.BackendClientSecret)
	if tokenErr != nil {
		t.Skipf("backend OIDC contract not satisfied: cannot mint client_credentials token (%v) — "+
			"run test/docker-compose/scripts/setup-keycloak.sh; environment drift; skipping", tokenErr)
	}
	authHeader := http.Header{"Authorization": {"Bearer " + token}}
	if pfErr := helpers.PreflightHTTPStatus(ctx, itemsURL, authHeader, http.StatusOK); pfErr != nil {
		t.Skipf("backend OIDC contract not satisfied: direct request with a live-minted token "+
			"failed (%v) — issuer/audience drift between Keycloak and rest_api_3; "+
			"environment drift; skipping", pfErr)
	}

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

	gi, err := helpers.StartGatewayWithConfigAndVault(
		ctx, buildLiveBackendGatewayConfig(liveAuthGatewayPort+3, backendCfg), nil)
	require.NoError(t, err, "failed to start gateway with OIDC backend auth")
	t.Cleanup(func() { _ = gi.Stop(ctx) })

	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/gw-health", 10*time.Second))

	t.Run("token attached and accepted by live backend", func(t *testing.T) {
		status := requestThroughGatewayEventually(t, gi.BaseURL, "/api/v1/items", http.StatusOK)
		require.Equal(t, http.StatusOK, status,
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

		status := requestThroughGatewayEventually(t, gi2.BaseURL, "/api/v1/items", http.StatusUnauthorized)
		require.Equal(t, http.StatusUnauthorized, status,
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Pre-flight the backend basic-auth contract directly with exactly the
	// credentials the gateway will read from Vault KV.
	username, password, credErr := helpers.ReadVaultKVCredentials(ctx, live.VaultBasicAuthPath)
	if credErr != nil {
		t.Skipf("backend basic-auth contract not satisfied: cannot read credentials from "+
			"Vault KV %s (%v) — run test/docker-compose/scripts/setup-vault.sh; "+
			"environment drift; skipping", live.VaultBasicAuthPath, credErr)
	}
	itemsURL := live.BasicRestURL + "/api/v1/items"
	if pfErr := helpers.PreflightHTTPStatus(ctx, itemsURL, nil, http.StatusUnauthorized); pfErr != nil {
		t.Skipf("backend basic-auth contract not satisfied: %v — "+
			"auth mode/image drift on rest_api_5; environment drift; skipping", pfErr)
	}
	basicHeader := http.Header{"Authorization": {
		"Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))}}
	if pfErr := helpers.PreflightHTTPStatus(ctx, itemsURL, basicHeader, http.StatusOK); pfErr != nil {
		t.Skipf("backend basic-auth contract not satisfied: direct request with Vault KV "+
			"credentials failed (%v) — credential drift between Vault and rest_api_5; "+
			"environment drift; skipping", pfErr)
	}

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

	gi, err := helpers.StartGatewayWithConfigAndVault(
		ctx, buildLiveBackendGatewayConfig(liveAuthGatewayPort+5, backendCfg), vaultClient)
	require.NoError(t, err, "failed to start gateway with Vault-KV basic auth")
	t.Cleanup(func() { _ = gi.Stop(ctx) })

	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/gw-health", 10*time.Second))

	t.Run("Vault KV credentials accepted by live backend", func(t *testing.T) {
		status := requestThroughGatewayEventually(t, gi.BaseURL, "/api/v1/items", http.StatusOK)
		require.Equal(t, http.StatusOK, status,
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

		status := requestThroughGatewayEventually(t, gi2.BaseURL, "/api/v1/items", http.StatusUnauthorized)
		require.Equal(t, http.StatusUnauthorized, status,
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
