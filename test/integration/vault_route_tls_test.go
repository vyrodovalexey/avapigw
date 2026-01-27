//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_RouteTLSManager_VaultProvider(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(logger),
		internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer routeManager.Close()

	// Add a route with Vault TLS config
	routeCfg := &internaltls.RouteTLSConfig{
		SNIHosts: []string{"vault-route.local"},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "vault-route.local",
			TTL:        1 * time.Hour,
		},
	}

	err := routeManager.AddRoute("vault-route", routeCfg)
	require.NoError(t, err)

	// Start the route manager
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = routeManager.Start(ctx)
	require.NoError(t, err)

	// Verify route was added
	assert.True(t, routeManager.HasRoute("vault-route"))
	assert.Equal(t, 1, routeManager.RouteCount())

	// Get certificate via SNI
	hello := &tls.ClientHelloInfo{
		ServerName: "vault-route.local",
	}

	cert, err := routeManager.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert, "Certificate should be returned for vault-route.local")
	assert.NotEmpty(t, cert.Certificate)
}

func TestIntegration_RouteTLSManager_MixedProviders(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	// Generate file-based certificates for the file route
	fileCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"file-route.local", "localhost"})
	require.NoError(t, err)
	err = fileCerts.WriteToFiles()
	require.NoError(t, err)
	defer fileCerts.Cleanup()

	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(logger),
		internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer routeManager.Close()

	// Add file-based route
	fileRouteCfg := &internaltls.RouteTLSConfig{
		CertFile: fileCerts.ServerCertPath(),
		KeyFile:  fileCerts.ServerKeyPath(),
		SNIHosts: []string{"file-route.local"},
	}
	err = routeManager.AddRoute("file-route", fileRouteCfg)
	require.NoError(t, err)

	// Add Vault-based route
	vaultRouteCfg := &internaltls.RouteTLSConfig{
		SNIHosts: []string{"vault-route.local"},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "vault-route.local",
			TTL:        1 * time.Hour,
		},
	}
	err = routeManager.AddRoute("vault-route", vaultRouteCfg)
	require.NoError(t, err)

	// Start the route manager
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = routeManager.Start(ctx)
	require.NoError(t, err)

	// Verify both routes exist
	assert.Equal(t, 2, routeManager.RouteCount())
	assert.True(t, routeManager.HasRoute("file-route"))
	assert.True(t, routeManager.HasRoute("vault-route"))

	// Get certificate for file-based route
	fileCert, err := routeManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "file-route.local",
	})
	require.NoError(t, err)
	require.NotNil(t, fileCert, "Certificate should be returned for file-route.local")

	// Get certificate for Vault-based route
	vaultCert, err := routeManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "vault-route.local",
	})
	require.NoError(t, err)
	require.NotNil(t, vaultCert, "Certificate should be returned for vault-route.local")

	// Certificates should be different
	assert.NotEqual(t, fileCert.Certificate, vaultCert.Certificate,
		"File and Vault certificates should be different")
}

func TestIntegration_RouteTLSManager_VaultProvider_TLSHandshake(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(logger),
		internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer routeManager.Close()

	// Add route with Vault TLS
	routeCfg := &internaltls.RouteTLSConfig{
		SNIHosts: []string{"localhost"},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "localhost",
			AltNames:   []string{"localhost"},
			TTL:        1 * time.Hour,
		},
	}

	err := routeManager.AddRoute("tls-handshake-route", routeCfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("route TLS OK"))
	}()

	// Get CA for client
	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)

	// Perform TLS handshake
	clientTLSConfig := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLSConfig)
	require.NoError(t, err, "TLS handshake should succeed with Vault-issued route certificate")
	defer conn.Close()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "route TLS OK", string(buf[:n]))

	<-serverDone
}

func TestIntegration_RouteTLSManager_VaultProvider_MissingFactory(t *testing.T) {
	// Create route manager WITHOUT vault provider factory
	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(observability.NopLogger()),
	)
	defer routeManager.Close()

	// Try to add a route with Vault TLS config
	routeCfg := &internaltls.RouteTLSConfig{
		SNIHosts: []string{"test.local"},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.local",
		},
	}

	err := routeManager.AddRoute("vault-route", routeCfg)
	require.Error(t, err, "Should fail when vault is enabled but no factory is provided")
	assert.Contains(t, err.Error(), "vault provider factory is required")
}

func TestIntegration_RouteTLSManager_VaultProvider_MultipleRoutes(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(logger),
		internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer routeManager.Close()

	// Add multiple Vault-based routes
	routes := []struct {
		name       string
		sniHost    string
		commonName string
	}{
		{"route-a", "route-a.local", "route-a.local"},
		{"route-b", "route-b.local", "route-b.local"},
		{"route-c", "route-c.local", "route-c.local"},
	}

	for _, r := range routes {
		cfg := &internaltls.RouteTLSConfig{
			SNIHosts: []string{r.sniHost},
			Vault: &internaltls.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   setup.PKIMount,
				Role:       setup.PKIRole,
				CommonName: r.commonName,
				TTL:        1 * time.Hour,
			},
		}
		err := routeManager.AddRoute(r.name, cfg)
		require.NoError(t, err, "Failed to add route %s", r.name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := routeManager.Start(ctx)
	require.NoError(t, err)

	assert.Equal(t, 3, routeManager.RouteCount())

	// Verify each route returns a certificate
	for _, r := range routes {
		t.Run(r.name, func(t *testing.T) {
			cert, err := routeManager.GetCertificate(&tls.ClientHelloInfo{
				ServerName: r.sniHost,
			})
			require.NoError(t, err)
			require.NotNil(t, cert, "Certificate should be returned for %s", r.sniHost)
			assert.NotEmpty(t, cert.Certificate)
		})
	}
}

func TestIntegration_RouteTLSManager_VaultProvider_SNIFallback(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	// Create a base manager with file-based cert as fallback
	fileCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"fallback.local", "localhost"})
	require.NoError(t, err)
	err = fileCerts.WriteToFiles()
	require.NoError(t, err)
	defer fileCerts.Cleanup()

	baseConfig := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source:   internaltls.CertificateSourceFile,
			CertFile: fileCerts.ServerCertPath(),
			KeyFile:  fileCerts.ServerKeyPath(),
		},
	}

	baseManager, err := internaltls.NewManager(baseConfig,
		internaltls.WithManagerLogger(logger),
	)
	require.NoError(t, err)
	defer baseManager.Close()

	// Create route manager with base manager as fallback
	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(logger),
		internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
		internaltls.WithBaseManager(baseManager),
	)
	defer routeManager.Close()

	// Add Vault-based route
	vaultRouteCfg := &internaltls.RouteTLSConfig{
		SNIHosts: []string{"vault-sni.local"},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "vault-sni.local",
			TTL:        1 * time.Hour,
		},
	}
	err = routeManager.AddRoute("vault-sni-route", vaultRouteCfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = routeManager.Start(ctx)
	require.NoError(t, err)

	// Request for vault route should return vault cert
	vaultCert, err := routeManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "vault-sni.local",
	})
	require.NoError(t, err)
	require.NotNil(t, vaultCert)

	// Request for unknown SNI should fall back to base manager
	fallbackCert, err := routeManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "fallback.local",
	})
	require.NoError(t, err)
	require.NotNil(t, fallbackCert, "Should fall back to base manager for unknown SNI")

	// Certificates should be different
	assert.NotEqual(t, vaultCert.Certificate, fallbackCert.Certificate,
		"Vault and fallback certificates should be different")
}

func TestIntegration_RouteTLSManager_VaultProvider_WildcardSNI(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(logger),
		internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer routeManager.Close()

	// Add route with wildcard SNI
	routeCfg := &internaltls.RouteTLSConfig{
		SNIHosts: []string{"*.wildcard.local"},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "wildcard.local",
			AltNames:   []string{"*.wildcard.local"},
			TTL:        1 * time.Hour,
		},
	}

	err := routeManager.AddRoute("wildcard-route", routeCfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = routeManager.Start(ctx)
	require.NoError(t, err)

	// Test wildcard matching
	cert, err := routeManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "app.wildcard.local",
	})
	require.NoError(t, err)
	require.NotNil(t, cert, "Wildcard SNI should match app.wildcard.local")

	// Test another subdomain
	cert2, err := routeManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "api.wildcard.local",
	})
	require.NoError(t, err)
	require.NotNil(t, cert2, "Wildcard SNI should match api.wildcard.local")

	// Non-matching should fail
	_, err = routeManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "other.domain.local",
	})
	assert.Error(t, err, "Non-matching SNI should return error")
}

func TestIntegration_RouteTLSManager_VaultProvider_RemoveRoute(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(logger),
		internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer routeManager.Close()

	// Add route
	routeCfg := &internaltls.RouteTLSConfig{
		SNIHosts: []string{"removable.local"},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "removable.local",
			TTL:        1 * time.Hour,
		},
	}

	err := routeManager.AddRoute("removable-route", routeCfg)
	require.NoError(t, err)
	assert.True(t, routeManager.HasRoute("removable-route"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = routeManager.Start(ctx)
	require.NoError(t, err)

	// Verify certificate is available
	cert, err := routeManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "removable.local",
	})
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Remove route
	routeManager.RemoveRoute("removable-route")
	assert.False(t, routeManager.HasRoute("removable-route"))
	assert.Equal(t, 0, routeManager.RouteCount())

	// Certificate should no longer be available
	_, err = routeManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "removable.local",
	})
	assert.Error(t, err, "Certificate should not be available after route removal")
}

func TestIntegration_RouteTLSManager_VaultProvider_ConcurrentHandshakes(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithRouteTLSManagerLogger(logger),
		internaltls.WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer routeManager.Close()

	routeCfg := &internaltls.RouteTLSConfig{
		SNIHosts: []string{"localhost"},
		Vault: &internaltls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "localhost",
			AltNames:   []string{"localhost"},
			TTL:        1 * time.Hour,
		},
	}

	err := routeManager.AddRoute("concurrent-route", routeCfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = routeManager.Start(ctx)
	require.NoError(t, err)

	tlsConfig := routeManager.GetTLSConfig()
	require.NotNil(t, tlsConfig)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("OK"))
			}(conn)
		}
	}()

	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)

	// Perform concurrent TLS handshakes
	const numClients = 5
	errCh := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		go func() {
			clientTLSConfig := &tls.Config{
				RootCAs:    caPool,
				ServerName: "localhost",
				MinVersion: tls.VersionTLS12,
			}

			conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLSConfig)
			if err != nil {
				errCh <- err
				return
			}
			conn.Close()
			errCh <- nil
		}()
	}

	for i := 0; i < numClients; i++ {
		err := <-errCh
		assert.NoError(t, err, "Concurrent TLS handshake %d should succeed", i)
	}
}
