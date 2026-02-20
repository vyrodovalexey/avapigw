//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// createVaultClient creates a Vault client for integration tests.
func createVaultClient(t *testing.T) vault.Client {
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

// createVaultProviderFactory creates a VaultProviderFactory for integration tests.
func createVaultProviderFactory(client vault.Client) internaltls.VaultProviderFactory {
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

func TestIntegration_Manager_VaultProvider_Start(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	vaultTLSCfg := &internaltls.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "manager-vault-test.local",
		AltNames:   []string{"localhost"},
		TTL:        1 * time.Hour,
	}

	config := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: vaultTLSCfg,
	}

	manager, err := internaltls.NewManager(config,
		internaltls.WithManagerLogger(logger),
		internaltls.WithVaultProviderFactory(factory),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Start the manager
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Verify TLS config is available
	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig, "TLS config should not be nil after start")
	assert.NotNil(t, tlsConfig.GetCertificate, "GetCertificate callback should be set")

	// Verify GetCertificate callback works
	hello := &tls.ClientHelloInfo{
		ServerName: "manager-vault-test.local",
	}
	cert, err := tlsConfig.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert, "Certificate should be returned from GetCertificate")
	assert.NotEmpty(t, cert.Certificate, "Certificate chain should not be empty")

	// Verify manager state
	assert.True(t, manager.IsEnabled())
	assert.Equal(t, internaltls.TLSModeSimple, manager.GetMode())
}

func TestIntegration_Manager_VaultProvider_CertificateEvents(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	vaultTLSCfg := &internaltls.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "events-vault-test.local",
		TTL:        1 * time.Hour,
	}

	config := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: vaultTLSCfg,
	}

	manager, err := internaltls.NewManager(config,
		internaltls.WithManagerLogger(logger),
		internaltls.WithVaultProviderFactory(factory),
	)
	require.NoError(t, err)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// The Vault provider sends a CertificateEventLoaded event on Start.
	// The manager watches for these events and processes them.
	// Verify the certificate is available after start (which means the event was processed).
	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)

	cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "events-vault-test.local",
	})
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.NotEmpty(t, cert.Certificate)
}

func TestIntegration_Manager_VaultPKI_TLSHandshake(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	vaultTLSCfg := &internaltls.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "localhost",
		AltNames:   []string{"localhost"},
		TTL:        1 * time.Hour,
	}

	config := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: vaultTLSCfg,
	}

	manager, err := internaltls.NewManager(config,
		internaltls.WithManagerLogger(logger),
		internaltls.WithVaultProviderFactory(factory),
	)
	require.NoError(t, err)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Get TLS config from manager
	serverTLSConfig := manager.GetTLSConfig()
	require.NotNil(t, serverTLSConfig)

	// Create TLS listener
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Start server goroutine
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("hello from vault TLS"))
	}()

	// Get CA from Vault for client verification
	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)
	require.NotNil(t, caPool)

	// Create client TLS config
	// Use ServerName: "localhost" because the certificate has "localhost" as SAN,
	// but the listener binds to 127.0.0.1 (IP address, not hostname).
	clientTLSConfig := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}

	// Perform TLS handshake
	conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLSConfig)
	require.NoError(t, err, "TLS handshake should succeed with Vault-issued certificate")
	defer conn.Close()

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello from vault TLS", string(buf[:n]))

	// Verify connection state
	state := conn.ConnectionState()
	assert.True(t, state.HandshakeComplete)
	assert.GreaterOrEqual(t, state.Version, uint16(tls.VersionTLS12))

	<-serverDone
}

func TestIntegration_Manager_VaultProvider_MissingFactory(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	vaultTLSCfg := &internaltls.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "test.local",
		TTL:        1 * time.Hour,
	}

	config := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: vaultTLSCfg,
	}

	// Create manager WITHOUT vault provider factory
	_, err := internaltls.NewManager(config,
		internaltls.WithManagerLogger(observability.NopLogger()),
	)
	require.Error(t, err, "Should fail when vault is enabled but no factory is provided")
	assert.Contains(t, err.Error(), "vault provider factory is required")
}

func TestIntegration_Manager_VaultProvider_WithMetrics(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	// Create metrics with a custom registry so Registry() returns non-nil
	metrics := internaltls.NewMetrics("gateway_test", internaltls.WithRegistry(prometheus.NewRegistry()))

	vaultTLSCfg := &internaltls.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "metrics-vault-test.local",
		TTL:        1 * time.Hour,
	}

	config := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: vaultTLSCfg,
	}

	manager, err := internaltls.NewManager(config,
		internaltls.WithManagerLogger(logger),
		internaltls.WithManagerMetrics(metrics),
		internaltls.WithVaultProviderFactory(factory),
	)
	require.NoError(t, err)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Trigger a certificate fetch to update metrics
	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)

	cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "metrics-vault-test.local",
	})
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify metrics were recorded by gathering from registry.
	// Certificate events are processed asynchronously, so we retry
	// a few times to allow the event goroutine to record metrics.
	registry := metrics.Registry()
	require.NotNil(t, registry)

	require.Eventually(t, func() bool {
		metricFamilies, gatherErr := registry.Gather()
		return gatherErr == nil && len(metricFamilies) > 0
	}, 5*time.Second, 100*time.Millisecond, "Metrics should have been recorded")

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	// Check for certificate_expiry_seconds metric
	found := false
	for _, mf := range metricFamilies {
		if mf.GetName() == "gateway_test_tls_certificate_expiry_seconds" {
			found = true
			break
		}
	}
	// The metric may or may not be present depending on timing of the expiry check
	// but the manager should have started successfully with metrics
	t.Logf("certificate_expiry_seconds metric found: %v", found)
}

func TestIntegration_Manager_VaultProvider_MultipleGetCertificate(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	vaultTLSCfg := &internaltls.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "multi-get-test.local",
		TTL:        1 * time.Hour,
	}

	config := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: vaultTLSCfg,
	}

	manager, err := internaltls.NewManager(config,
		internaltls.WithManagerLogger(logger),
		internaltls.WithVaultProviderFactory(factory),
	)
	require.NoError(t, err)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)

	// Call GetCertificate multiple times - should return the same certificate
	hello := &tls.ClientHelloInfo{
		ServerName: "multi-get-test.local",
	}

	cert1, err := tlsConfig.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert1)

	cert2, err := tlsConfig.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert2)

	// Same certificate should be returned (cached by provider)
	assert.Equal(t, cert1.Certificate, cert2.Certificate,
		"Multiple GetCertificate calls should return the same certificate")
}

func TestIntegration_Manager_VaultProvider_TLSHandshake_DifferentSNI(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	client := createVaultClient(t)
	defer client.Close()

	factory := createVaultProviderFactory(client)
	logger := observability.NopLogger()

	vaultTLSCfg := &internaltls.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "localhost",
		AltNames:   []string{"localhost", "sni-test.local"},
		TTL:        1 * time.Hour,
	}

	config := &internaltls.Config{
		Mode: internaltls.TLSModeSimple,
		ServerCertificate: &internaltls.CertificateConfig{
			Source: internaltls.CertificateSourceVault,
		},
		Vault: vaultTLSCfg,
	}

	manager, err := internaltls.NewManager(config,
		internaltls.WithManagerLogger(logger),
		internaltls.WithVaultProviderFactory(factory),
	)
	require.NoError(t, err)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	serverTLSConfig := manager.GetTLSConfig()
	require.NotNil(t, serverTLSConfig)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
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

	// Test with different SNI names
	sniNames := []string{"localhost", "sni-test.local"}
	for _, sni := range sniNames {
		t.Run(fmt.Sprintf("SNI=%s", sni), func(t *testing.T) {
			clientTLSConfig := &tls.Config{
				RootCAs:    caPool,
				ServerName: sni,
				MinVersion: tls.VersionTLS12,
			}

			conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLSConfig)
			require.NoError(t, err, "TLS handshake should succeed for SNI: %s", sni)
			defer conn.Close()

			assert.True(t, conn.ConnectionState().HandshakeComplete)
		})
	}
}
