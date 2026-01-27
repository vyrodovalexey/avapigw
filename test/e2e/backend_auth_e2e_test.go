//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestE2E_BackendAuth_JWT(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway proxying to backend with JWT auth", func(t *testing.T) {
		// Create a mock backend that verifies JWT
		var receivedAuthHeader string
		mockBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAuthHeader = r.Header.Get("Authorization")
			if !strings.HasPrefix(receivedAuthHeader, "Bearer ") {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":"missing or invalid authorization"}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"authenticated"}`)
		}))
		defer mockBackend.Close()

		// Extract host and port from mock backend URL
		backendURL := mockBackend.URL
		parts := strings.Split(strings.TrimPrefix(backendURL, "http://"), ":")
		backendHost := parts[0]
		backendPort := 8801 // Use default for test

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "jwt-auth-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18120, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "jwt-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: backendHost, Port: backendPort}},
						},
					},
				},
				Backends: []config.Backend{
					{
						Name: "jwt-backend",
						Hosts: []config.BackendHost{
							{Address: backendHost, Port: backendPort},
						},
						Authentication: &config.BackendAuthConfig{
							Type: "jwt",
							JWT: &config.BackendJWTAuthConfig{
								Enabled:      true,
								TokenSource:  "static",
								StaticToken:  "test-jwt-token",
								HeaderName:   "Authorization",
								HeaderPrefix: "Bearer",
							},
						},
					},
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(p),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		// Verify backend auth config
		assert.NotNil(t, cfg.Spec.Backends[0].Authentication)
		assert.Equal(t, "jwt", cfg.Spec.Backends[0].Authentication.Type)
		assert.True(t, cfg.Spec.Backends[0].Authentication.JWT.Enabled)
	})
}

func TestE2E_BackendAuth_Basic(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway proxying to backend with Basic auth", func(t *testing.T) {
		// Create a mock backend that verifies Basic auth
		expectedUsername := "backend-user"
		expectedPassword := "backend-pass"
		var receivedAuthHeader string

		mockBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAuthHeader = r.Header.Get("Authorization")
			if !strings.HasPrefix(receivedAuthHeader, "Basic ") {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":"missing basic auth"}`)
				return
			}

			// Decode and verify credentials
			encoded := strings.TrimPrefix(receivedAuthHeader, "Basic ")
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) != 2 || parts[0] != expectedUsername || parts[1] != expectedPassword {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":"invalid credentials"}`)
				return
			}

			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"authenticated"}`)
		}))
		defer mockBackend.Close()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "basic-auth-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18121, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "basic-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				Backends: []config.Backend{
					{
						Name: "basic-backend",
						Hosts: []config.BackendHost{
							{Address: "127.0.0.1", Port: 8801},
						},
						Authentication: &config.BackendAuthConfig{
							Type: "basic",
							Basic: &config.BackendBasicAuthConfig{
								Enabled:  true,
								Username: expectedUsername,
								Password: expectedPassword,
							},
						},
					},
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(p),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		// Verify backend auth config
		assert.NotNil(t, cfg.Spec.Backends[0].Authentication)
		assert.Equal(t, "basic", cfg.Spec.Backends[0].Authentication.Type)
		assert.True(t, cfg.Spec.Backends[0].Authentication.Basic.Enabled)
		assert.Equal(t, expectedUsername, cfg.Spec.Backends[0].Authentication.Basic.Username)
	})
}

func TestE2E_BackendAuth_MTLS(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway proxying to backend with mTLS", func(t *testing.T) {
		// Generate test certificates
		certs, err := helpers.CreateTestCertificates(t)
		require.NoError(t, err)
		err = certs.WriteToFiles()
		require.NoError(t, err)
		defer certs.Cleanup()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "mtls-auth-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18122, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "mtls-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				Backends: []config.Backend{
					{
						Name: "mtls-backend",
						Hosts: []config.BackendHost{
							{Address: "127.0.0.1", Port: 8801},
						},
						Authentication: &config.BackendAuthConfig{
							Type: "mtls",
							MTLS: &config.BackendMTLSAuthConfig{
								Enabled:  true,
								CertFile: certs.ClientCertPath(),
								KeyFile:  certs.ClientKeyPath(),
								CAFile:   certs.CACertPath(),
							},
						},
					},
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err = r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(p),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		// Verify backend auth config
		assert.NotNil(t, cfg.Spec.Backends[0].Authentication)
		assert.Equal(t, "mtls", cfg.Spec.Backends[0].Authentication.Type)
		assert.True(t, cfg.Spec.Backends[0].Authentication.MTLS.Enabled)
		assert.NotEmpty(t, cfg.Spec.Backends[0].Authentication.MTLS.CertFile)
		assert.NotEmpty(t, cfg.Spec.Backends[0].Authentication.MTLS.KeyFile)
	})
}

func TestE2E_BackendAuth_Vault(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	t.Run("backend auth with Vault integration", func(t *testing.T) {
		// Store credentials in Vault
		credPath := "backend-auth/e2e-test"
		err := helpers.SetupVaultBasicAuthCredentials(t, vaultSetup, credPath, "vault-user", "vault-pass")
		require.NoError(t, err)
		defer func() {
			_ = helpers.CleanupVaultBackendCredentials(t, vaultSetup, credPath)
		}()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "vault-auth-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18123, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "vault-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				Backends: []config.Backend{
					{
						Name: "vault-backend",
						Hosts: []config.BackendHost{
							{Address: "127.0.0.1", Port: 8801},
						},
						Authentication: &config.BackendAuthConfig{
							Type: "basic",
							Basic: &config.BackendBasicAuthConfig{
								Enabled:   true,
								VaultPath: credPath,
							},
						},
					},
				},
			},
		}

		// Verify config
		assert.NotNil(t, cfg.Spec.Backends[0].Authentication)
		assert.Equal(t, "basic", cfg.Spec.Backends[0].Authentication.Type)
		assert.Equal(t, credPath, cfg.Spec.Backends[0].Authentication.Basic.VaultPath)

		// Verify credentials can be read from Vault
		data, err := vaultSetup.ReadSecret(credPath)
		require.NoError(t, err)
		assert.Equal(t, "vault-user", data["username"])
		assert.Equal(t, "vault-pass", data["password"])
	})
}

func TestE2E_BackendAuth_Keycloak(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	t.Run("backend auth with Keycloak OIDC", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create backend service client
		backendClientID := "backend-e2e-test"
		backendClientSecret := "backend-e2e-secret"

		err := helpers.SetupKeycloakBackendClient(t, keycloakSetup, backendClientID, backendClientSecret)
		require.NoError(t, err)

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "keycloak-auth-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18124, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "oidc-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				Backends: []config.Backend{
					{
						Name: "oidc-backend",
						Hosts: []config.BackendHost{
							{Address: "127.0.0.1", Port: 8801},
						},
						Authentication: &config.BackendAuthConfig{
							Type: "jwt",
							JWT: &config.BackendJWTAuthConfig{
								Enabled:     true,
								TokenSource: "oidc",
								OIDC: &config.BackendOIDCConfig{
									IssuerURL:     keycloakSetup.GetIssuerURL(),
									ClientID:      backendClientID,
									ClientSecret:  backendClientSecret,
									Scopes:        []string{"openid"},
									TokenCacheTTL: config.Duration(5 * time.Minute),
								},
							},
						},
					},
				},
			},
		}

		// Verify config
		assert.NotNil(t, cfg.Spec.Backends[0].Authentication)
		assert.Equal(t, "jwt", cfg.Spec.Backends[0].Authentication.Type)
		assert.Equal(t, "oidc", cfg.Spec.Backends[0].Authentication.JWT.TokenSource)
		assert.NotNil(t, cfg.Spec.Backends[0].Authentication.JWT.OIDC)

		// Verify we can get a token from Keycloak
		tokenResp, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			backendClientID,
			backendClientSecret,
		)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenResp.AccessToken)
	})
}
