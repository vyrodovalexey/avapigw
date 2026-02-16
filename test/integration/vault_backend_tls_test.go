//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_BackendTLS_VaultClientCert(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
	vaultClientCfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	vaultClient, err := vault.New(vaultClientCfg, logger)
	require.NoError(t, err)
	defer vaultClient.Close()

	err = vaultClient.Authenticate(ctx)
	require.NoError(t, err)

	// Issue server certificate for the backend server
	serverCertData, err := vaultClient.PKI().IssueCertificate(ctx, &vault.PKIIssueOptions{
		Mount:      vaultSetup.PKIMount,
		Role:       vaultSetup.PKIRole,
		CommonName: "localhost",
		AltNames:   []string{"localhost"},
		IPSANs:     []string{"127.0.0.1"},
		TTL:        1 * time.Hour,
	})
	require.NoError(t, err)

	// Get CA pool
	caPool, err := vaultClient.PKI().GetCA(ctx, vaultSetup.PKIMount)
	require.NoError(t, err)

	// Create backend server with mTLS
	serverTLSCert, err := tls.X509KeyPair(
		[]byte(serverCertData.CertificatePEM),
		[]byte(serverCertData.PrivateKeyPEM),
	)
	require.NoError(t, err)

	var receivedCN string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			receivedCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Create TLSConfigBuilder with Vault client cert
	backendTLSCfg := &config.BackendTLSConfig{
		Enabled:            true,
		Mode:               config.BackendTLSModeMutual,
		InsecureSkipVerify: true, // For test with self-signed certs
		Vault: &config.VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   vaultSetup.PKIMount,
			Role:       vaultSetup.PKIRole,
			CommonName: "backend-client.local",
			TTL:        "1h",
		},
	}

	builder := backend.NewTLSConfigBuilder(backendTLSCfg,
		backend.WithTLSLogger(logger),
		backend.WithTLSVaultClient(vaultClient),
	)
	defer builder.Close()

	// Build TLS config
	tlsConfig, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// Verify GetClientCertificate callback is set
	assert.NotNil(t, tlsConfig.GetClientCertificate,
		"GetClientCertificate callback should be set for Vault-based mTLS")

	// Create HTTP client with the built TLS config
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}

	// Make request to mTLS backend
	resp, err := httpClient.Get(server.URL + "/api/resource")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend-client.local", receivedCN,
		"Backend should receive the Vault-issued client certificate CN")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "ok")
}

func TestIntegration_BackendTLS_VaultClientCert_Metrics(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	vaultClientCfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	vaultClient, err := vault.New(vaultClientCfg, logger)
	require.NoError(t, err)
	defer vaultClient.Close()

	err = vaultClient.Authenticate(ctx)
	require.NoError(t, err)

	// Issue server certificate
	serverCertData, err := vaultClient.PKI().IssueCertificate(ctx, &vault.PKIIssueOptions{
		Mount:      vaultSetup.PKIMount,
		Role:       vaultSetup.PKIRole,
		CommonName: "localhost",
		AltNames:   []string{"localhost"},
		IPSANs:     []string{"127.0.0.1"},
		TTL:        1 * time.Hour,
	})
	require.NoError(t, err)

	caPool, err := vaultClient.PKI().GetCA(ctx, vaultSetup.PKIMount)
	require.NoError(t, err)

	// Create backend server with mTLS
	serverTLSCert, err := tls.X509KeyPair(
		[]byte(serverCertData.CertificatePEM),
		[]byte(serverCertData.PrivateKeyPEM),
	)
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Create metrics with a custom registry so Registry() returns non-nil
	metrics := internaltls.NewMetrics("gateway_backend_test", internaltls.WithRegistry(prometheus.NewRegistry()))

	backendTLSCfg := &config.BackendTLSConfig{
		Enabled:            true,
		Mode:               config.BackendTLSModeMutual,
		InsecureSkipVerify: true,
		Vault: &config.VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   vaultSetup.PKIMount,
			Role:       vaultSetup.PKIRole,
			CommonName: "metrics-client.local",
			TTL:        "1h",
		},
	}

	builder := backend.NewTLSConfigBuilder(backendTLSCfg,
		backend.WithTLSLogger(logger),
		backend.WithTLSMetrics(metrics),
		backend.WithTLSVaultClient(vaultClient),
	)
	defer builder.Close()

	tlsConfig, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// Make a request to trigger GetClientCertificate callback
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Get(server.URL + "/api/metrics-test")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify metrics were recorded
	registry := metrics.Registry()
	require.NotNil(t, registry)

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	// Check for certificate_expiry_seconds metric with backend_client type
	found := false
	for _, mf := range metricFamilies {
		if mf.GetName() == "gateway_backend_test_tls_certificate_expiry_seconds" {
			for _, m := range mf.GetMetric() {
				for _, label := range m.GetLabel() {
					if label.GetName() == "type" && label.GetValue() == "backend_client" {
						found = true
						// Verify the expiry value is positive (cert is not expired)
						assert.Greater(t, m.GetGauge().GetValue(), float64(0),
							"Certificate expiry should be positive (not expired)")
					}
				}
			}
		}
	}
	assert.True(t, found, "Should find certificate_expiry_seconds metric with type=backend_client")
}

func TestIntegration_BackendTLS_VaultClientCert_MissingVaultClient(t *testing.T) {
	backendTLSCfg := &config.BackendTLSConfig{
		Enabled: true,
		Mode:    config.BackendTLSModeMutual,
		Vault: &config.VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.local",
			TTL:        "1h",
		},
	}

	// Create builder WITHOUT vault client
	builder := backend.NewTLSConfigBuilder(backendTLSCfg,
		backend.WithTLSLogger(observability.NopLogger()),
	)
	defer builder.Close()

	_, err := builder.Build()
	require.Error(t, err, "Should fail when vault is enabled but no vault client is provided")
	assert.Contains(t, err.Error(), "vault client is required")
}

func TestIntegration_BackendTLS_VaultClientCert_DynamicCertFetch(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	vaultClientCfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	vaultClient, err := vault.New(vaultClientCfg, logger)
	require.NoError(t, err)
	defer vaultClient.Close()

	err = vaultClient.Authenticate(ctx)
	require.NoError(t, err)

	backendTLSCfg := &config.BackendTLSConfig{
		Enabled:            true,
		Mode:               config.BackendTLSModeMutual,
		InsecureSkipVerify: true,
		Vault: &config.VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   vaultSetup.PKIMount,
			Role:       vaultSetup.PKIRole,
			CommonName: "dynamic-client.local",
			TTL:        "1h",
		},
	}

	builder := backend.NewTLSConfigBuilder(backendTLSCfg,
		backend.WithTLSLogger(logger),
		backend.WithTLSVaultClient(vaultClient),
	)
	defer builder.Close()

	tlsConfig, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// Call GetClientCertificate multiple times to verify dynamic cert fetching
	require.NotNil(t, tlsConfig.GetClientCertificate)

	cert1, err := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.NotNil(t, cert1)
	assert.NotEmpty(t, cert1.Certificate)

	cert2, err := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.NotNil(t, cert2)
	assert.NotEmpty(t, cert2.Certificate)

	// Same certificate should be returned (cached by provider)
	assert.Equal(t, cert1.Certificate, cert2.Certificate,
		"Multiple GetClientCertificate calls should return the same certificate")
}

func TestIntegration_BackendTLS_VaultClientCert_BuilderClose(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	vaultClientCfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	vaultClient, err := vault.New(vaultClientCfg, logger)
	require.NoError(t, err)
	defer vaultClient.Close()

	err = vaultClient.Authenticate(ctx)
	require.NoError(t, err)

	backendTLSCfg := &config.BackendTLSConfig{
		Enabled:            true,
		Mode:               config.BackendTLSModeMutual,
		InsecureSkipVerify: true,
		Vault: &config.VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   vaultSetup.PKIMount,
			Role:       vaultSetup.PKIRole,
			CommonName: "close-test.local",
			TTL:        "1h",
		},
	}

	builder := backend.NewTLSConfigBuilder(backendTLSCfg,
		backend.WithTLSLogger(logger),
		backend.WithTLSVaultClient(vaultClient),
	)

	// Build to trigger vault provider creation
	_, err = builder.Build()
	require.NoError(t, err)

	// Close should not error
	err = builder.Close()
	assert.NoError(t, err, "Builder close should not error")
}

func TestIntegration_BackendTLS_VaultClientCert_Invalidate(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	vaultClientCfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	vaultClient, err := vault.New(vaultClientCfg, logger)
	require.NoError(t, err)
	defer vaultClient.Close()

	err = vaultClient.Authenticate(ctx)
	require.NoError(t, err)

	backendTLSCfg := &config.BackendTLSConfig{
		Enabled:            true,
		Mode:               config.BackendTLSModeMutual,
		InsecureSkipVerify: true,
		Vault: &config.VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   vaultSetup.PKIMount,
			Role:       vaultSetup.PKIRole,
			CommonName: "invalidate-test.local",
			TTL:        "1h",
		},
	}

	builder := backend.NewTLSConfigBuilder(backendTLSCfg,
		backend.WithTLSLogger(logger),
		backend.WithTLSVaultClient(vaultClient),
	)
	defer builder.Close()

	// First build
	cfg1, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, cfg1)

	// Invalidate cache
	builder.Invalidate()

	// Second build should create a new config
	cfg2, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, cfg2)
}
