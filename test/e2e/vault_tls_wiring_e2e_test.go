//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// e2eCreateVaultClient creates a Vault client for E2E tests.
func e2eCreateVaultClient(t *testing.T) vault.Client {
	t.Helper()

	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)

	err = client.Authenticate(context.Background())
	require.NoError(t, err)

	return client
}

// e2eCreateVaultProviderFactory creates a VaultProviderFactory for E2E tests.
func e2eCreateVaultProviderFactory(client vault.Client) internaltls.VaultProviderFactory {
	return func(config *internaltls.VaultTLSConfig, logger observability.Logger) (internaltls.CertificateProvider, error) {
		providerCfg := &vault.VaultProviderConfig{
			PKIMount:    config.PKIMount,
			Role:        config.Role,
			CommonName:  config.CommonName,
			AltNames:    config.AltNames,
			TTL:         config.TTL,
			RenewBefore: config.RenewBefore,
		}

		provider, err := vault.NewVaultProvider(client, providerCfg,
			vault.WithVaultProviderLogger(logger),
		)
		if err != nil {
			return nil, err
		}

		return provider, nil
	}
}

func TestE2E_VaultPKI_ListenerTLS(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := e2eCreateVaultClient(t)
	defer client.Close()

	factory := e2eCreateVaultProviderFactory(client)
	logger := observability.NopLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create TLS Manager with Vault provider
	vaultTLSCfg := &internaltls.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "localhost",
		AltNames:   []string{"localhost"},
		TTL:        1 * time.Hour,
	}

	tlsConfig := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: vaultTLSCfg,
	}

	manager, err := internaltls.NewManager(tlsConfig,
		internaltls.WithManagerLogger(logger),
		internaltls.WithVaultProviderFactory(factory),
	)
	require.NoError(t, err)
	defer manager.Close()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Create HTTPS listener using manager's TLS config
	serverTLSConfig := manager.GetTLSConfig()
	require.NotNil(t, serverTLSConfig)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Start HTTP server on TLS listener
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"healthy","tls":"vault"}`)
	})

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	// Get CA from Vault for client verification
	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)

	// Create HTTPS client
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 10 * time.Second,
	}

	// Make HTTPS request
	resp, err := httpClient.Get(fmt.Sprintf("https://%s/api/health", listener.Addr().String()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "healthy")
	assert.Contains(t, string(body), "vault")
}

func TestE2E_VaultPKI_mTLS(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := e2eCreateVaultClient(t)
	defer client.Close()

	logger := observability.NopLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get CA pool for mTLS
	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)

	// Create TLS Manager with mTLS mode
	vaultTLSCfg := &internaltls.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "localhost",
		AltNames:   []string{"localhost"},
		TTL:        1 * time.Hour,
	}

	// For mTLS, we need client validation config with CA
	// Write CA to temp file for client validation
	caPEM, err := setup.GetCA()
	require.NoError(t, err)

	caCerts, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	err = caCerts.WriteToFiles()
	require.NoError(t, err)
	defer caCerts.Cleanup()

	// We'll use the Vault CA directly in the server config
	// Create server with Vault cert and mTLS
	serverProviderCfg := &vault.VaultProviderConfig{
		PKIMount:   setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "localhost",
		AltNames:   []string{"localhost"},
		IPSANs:     []string{"127.0.0.1"},
		TTL:        1 * time.Hour,
	}

	serverProvider, err := vault.NewVaultProvider(client, serverProviderCfg,
		vault.WithVaultProviderLogger(logger),
	)
	require.NoError(t, err)
	defer serverProvider.Close()

	err = serverProvider.Start(ctx)
	require.NoError(t, err)

	serverCert, err := serverProvider.GetCertificate(ctx, nil)
	require.NoError(t, err)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	// Create mTLS server
	var receivedClientCN string
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				state := tlsConn.ConnectionState()
				if len(state.PeerCertificates) > 0 {
					receivedClientCN = state.PeerCertificates[0].Subject.CommonName
				}
				// Read request
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nmTLS OK"))
			}(conn)
		}
	}()

	// Issue client certificate from Vault
	clientCertData, err := client.PKI().IssueCertificate(ctx, &vault.PKIIssueOptions{
		Mount:      setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "e2e-mtls-client.local",
		TTL:        1 * time.Hour,
	})
	require.NoError(t, err)

	clientTLSCert, err := tls.X509KeyPair(
		[]byte(clientCertData.CertificatePEM),
		[]byte(clientCertData.PrivateKeyPEM),
	)
	require.NoError(t, err)

	// Create client with Vault-issued cert
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{clientTLSCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "e2e-mtls-client.local", receivedClientCN)

	_ = vaultTLSCfg
	_ = caPEM
}

func TestE2E_VaultPKI_RouteTLS_SNI(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := e2eCreateVaultClient(t)
	defer client.Close()

	factory := e2eCreateVaultProviderFactory(client)
	logger := observability.NopLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create route TLS manager with Vault provider
	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(logger),
		internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer routeManager.Close()

	// Add route with Vault TLS for specific SNI
	routeCfg := &internaltls.RouteTLSConfig{
		SNIHosts: []string{"api.example.local"},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "api.example.local",
			AltNames:   []string{"api.example.local"},
			TTL:        1 * time.Hour,
		},
	}

	err := routeManager.AddRoute("api-route", routeCfg)
	require.NoError(t, err)

	err = routeManager.Start(ctx)
	require.NoError(t, err)

	// Get TLS config from route manager
	tlsConfig := routeManager.GetTLSConfig()
	require.NotNil(t, tlsConfig)

	// Create TLS listener
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Start server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nRoute TLS OK"))
			}(conn)
		}
	}()

	// Get CA for client
	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)

	// Connect with correct SNI
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				ServerName: "api.example.local",
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Route TLS OK", string(body))
}

func TestE2E_VaultPKI_BackendmTLS(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client := e2eCreateVaultClient(t)
	defer client.Close()

	logger := observability.NopLogger()

	// Issue server certificate for backend
	serverCertData, err := client.PKI().IssueCertificate(ctx, &vault.PKIIssueOptions{
		Mount:      setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "backend-server.local",
		AltNames:   []string{"localhost"},
		IPSANs:     []string{"127.0.0.1"},
		TTL:        1 * time.Hour,
	})
	require.NoError(t, err)

	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)

	// Create backend server requiring client certs
	serverTLSCert, err := tls.X509KeyPair(
		[]byte(serverCertData.CertificatePEM),
		[]byte(serverCertData.PrivateKeyPEM),
	)
	require.NoError(t, err)

	var clientCN string
	backendServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"client":"%s","status":"ok"}`, clientCN)
	}))
	backendServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	backendServer.StartTLS()
	defer backendServer.Close()

	// Create TLSConfigBuilder with Vault client cert
	backendTLSCfg := &config.BackendTLSConfig{
		Enabled:            true,
		Mode:               config.BackendTLSModeMutual,
		InsecureSkipVerify: true,
		Vault: &config.VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "gateway-client.local",
			TTL:        "1h",
		},
	}

	builder := backend.NewTLSConfigBuilder(backendTLSCfg,
		backend.WithTLSLogger(logger),
		backend.WithTLSVaultClient(client),
	)
	defer builder.Close()

	tlsConfig, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// Create HTTP client with Vault-issued client cert
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}

	// Make request to backend requiring mTLS
	resp, err := httpClient.Get(backendServer.URL + "/api/data")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "gateway-client.local")
	assert.Contains(t, string(body), "ok")
}

func TestE2E_VaultPKI_CertRenewal_NoDowntime(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping certificate renewal test in short mode")
	}

	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := e2eCreateVaultClient(t)
	defer client.Close()

	factory := e2eCreateVaultProviderFactory(client)
	logger := observability.NopLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create TLS Manager with short TTL for renewal testing
	vaultTLSCfg := &internaltls.VaultTLSConfig{
		Enabled:     true,
		PKIMount:    setup.PKIMount,
		Role:        setup.PKIRole,
		CommonName:  "localhost",
		AltNames:    []string{"localhost"},
		TTL:         10 * time.Second,
		RenewBefore: 5 * time.Second,
	}

	tlsConfig := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: vaultTLSCfg,
	}

	manager, err := internaltls.NewManager(tlsConfig,
		internaltls.WithManagerLogger(logger),
		internaltls.WithVaultProviderFactory(factory),
	)
	require.NoError(t, err)
	defer manager.Close()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Create TLS listener
	serverTLSConfig := manager.GetTLSConfig()
	require.NotNil(t, serverTLSConfig)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Start server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			}(conn)
		}
	}()

	// Get CA for client
	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)

	addr := listener.Addr().String()

	// Make initial connection
	makeRequest := func() error {
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    caPool,
					MinVersion: tls.VersionTLS12,
				},
			},
			Timeout: 5 * time.Second,
		}

		resp, err := httpClient.Get(fmt.Sprintf("https://%s/", addr))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status: %d", resp.StatusCode)
		}
		return nil
	}

	// Initial request should succeed
	err = makeRequest()
	require.NoError(t, err, "Initial request should succeed")

	// Wait for certificate renewal to happen (TTL=10s, renewBefore=5s, so renewal at ~5s)
	t.Log("Waiting for certificate renewal...")
	time.Sleep(8 * time.Second)

	// Request after renewal should still succeed (no downtime)
	err = makeRequest()
	require.NoError(t, err, "Request after certificate renewal should succeed (no downtime)")

	// Make a few more requests to ensure stability
	for i := 0; i < 3; i++ {
		err = makeRequest()
		assert.NoError(t, err, "Request %d after renewal should succeed", i+1)
	}
}

func TestE2E_VaultPKI_MultiRoute_SNI_Selection(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := e2eCreateVaultClient(t)
	defer client.Close()

	factory := e2eCreateVaultProviderFactory(client)
	logger := observability.NopLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create route TLS manager with multiple Vault routes
	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(logger),
		internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer routeManager.Close()

	// Add multiple routes with different SNI hosts
	routes := []struct {
		name       string
		sniHost    string
		commonName string
	}{
		{"api-route", "api.service.local", "api.service.local"},
		{"web-route", "web.service.local", "web.service.local"},
		{"admin-route", "admin.service.local", "admin.service.local"},
	}

	for _, r := range routes {
		cfg := &internaltls.RouteTLSConfig{
			SNIHosts: []string{r.sniHost},
			Vault: &internaltls.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   setup.PKIMount,
				Role:       setup.PKIRole,
				CommonName: r.commonName,
				AltNames:   []string{r.sniHost},
				TTL:        1 * time.Hour,
			},
		}
		err := routeManager.AddRoute(r.name, cfg)
		require.NoError(t, err)
	}

	err := routeManager.Start(ctx)
	require.NoError(t, err)

	// Get TLS config
	tlsConfig := routeManager.GetTLSConfig()
	require.NotNil(t, tlsConfig)

	// Create listener
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Start server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			}(conn)
		}
	}()

	// Get CA
	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)

	// Test each route with correct SNI
	for _, r := range routes {
		t.Run(r.name, func(t *testing.T) {
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    caPool,
						ServerName: r.sniHost,
						MinVersion: tls.VersionTLS12,
					},
				},
				Timeout: 10 * time.Second,
			}

			resp, err := httpClient.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
			require.NoError(t, err, "Request with SNI %s should succeed", r.sniHost)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func TestE2E_VaultPKI_FullGatewayWorkflow(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := e2eCreateVaultClient(t)
	defer client.Close()

	factory := e2eCreateVaultProviderFactory(client)
	logger := observability.NopLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Step 1: Create listener-level TLS with Vault
	t.Run("step1_create_listener_tls", func(t *testing.T) {
		vaultTLSCfg := &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "localhost",
			AltNames:   []string{"localhost"},
			TTL:        1 * time.Hour,
		}

		tlsConfig := &internaltls.Config{
			Mode: internaltls.TLSModeSimple,
			ServerCertificate: &internaltls.CertificateConfig{
				Source: internaltls.CertificateSourceVault,
			},
			Vault: vaultTLSCfg,
		}

		manager, err := internaltls.NewManager(tlsConfig,
			internaltls.WithManagerLogger(logger),
			internaltls.WithVaultProviderFactory(factory),
		)
		require.NoError(t, err)
		defer manager.Close()

		err = manager.Start(ctx)
		require.NoError(t, err)

		assert.True(t, manager.IsEnabled())
		assert.NotNil(t, manager.GetTLSConfig())
	})

	// Step 2: Create route-level TLS with Vault
	t.Run("step2_create_route_tls", func(t *testing.T) {
		routeManager := internaltls.NewRouteTLSManager(
			internaltls.WithRouteTLSManagerLogger(logger),
			internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
		)
		defer routeManager.Close()

		err := routeManager.AddRoute("api", &internaltls.RouteTLSConfig{
			SNIHosts: []string{"api.gateway.local"},
			Vault: &internaltls.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   setup.PKIMount,
				Role:       setup.PKIRole,
				CommonName: "api.gateway.local",
				TTL:        1 * time.Hour,
			},
		})
		require.NoError(t, err)

		err = routeManager.Start(ctx)
		require.NoError(t, err)

		assert.Equal(t, 1, routeManager.RouteCount())
	})

	// Step 3: Create backend TLS with Vault client cert
	t.Run("step3_create_backend_tls", func(t *testing.T) {
		backendTLSCfg := &config.BackendTLSConfig{
			Enabled:            true,
			Mode:               config.BackendTLSModeMutual,
			InsecureSkipVerify: true,
			Vault: &config.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   setup.PKIMount,
				Role:       setup.PKIRole,
				CommonName: "gateway-backend-client.local",
				TTL:        "1h",
			},
		}

		builder := backend.NewTLSConfigBuilder(backendTLSCfg,
			backend.WithTLSLogger(logger),
			backend.WithTLSVaultClient(client),
		)
		defer builder.Close()

		builtConfig, err := builder.Build()
		require.NoError(t, err)
		require.NotNil(t, builtConfig)
		assert.NotNil(t, builtConfig.GetClientCertificate)
	})

	// Step 4: Verify end-to-end HTTPS request
	t.Run("step4_e2e_https_request", func(t *testing.T) {
		vaultTLSCfg := &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "localhost",
			AltNames:   []string{"localhost"},
			TTL:        1 * time.Hour,
		}

		tlsConfig := &internaltls.Config{
			Mode: internaltls.TLSModeSimple,
			ServerCertificate: &internaltls.CertificateConfig{
				Source: internaltls.CertificateSourceVault,
			},
			Vault: vaultTLSCfg,
		}

		manager, err := internaltls.NewManager(tlsConfig,
			internaltls.WithManagerLogger(logger),
			internaltls.WithVaultProviderFactory(factory),
		)
		require.NoError(t, err)
		defer manager.Close()

		err = manager.Start(ctx)
		require.NoError(t, err)

		serverTLSConfig := manager.GetTLSConfig()
		listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
		require.NoError(t, err)
		defer listener.Close()

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "E2E Vault TLS OK")
		})

		server := &http.Server{Handler: mux}
		go func() {
			_ = server.Serve(listener)
		}()
		defer server.Close()

		caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
		require.NoError(t, err)

		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    caPool,
					MinVersion: tls.VersionTLS12,
				},
			},
			Timeout: 10 * time.Second,
		}

		resp, err := httpClient.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "E2E Vault TLS OK", string(body))
	})
}
