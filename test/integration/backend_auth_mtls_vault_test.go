//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_BackendAuth_MTLS_Vault(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("backend mTLS with Vault PKI certificates", func(t *testing.T) {
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
		defer client.Close()

		err = client.Authenticate(ctx)
		require.NoError(t, err)

		// Issue certificate for backend client
		opts := &vault.PKIIssueOptions{
			Mount:      vaultSetup.PKIMount,
			Role:       vaultSetup.PKIRole,
			CommonName: "backend-client.local",
			AltNames:   []string{"localhost"},
			TTL:        1 * time.Hour,
		}

		cert, err := client.PKI().IssueCertificate(ctx, opts)
		require.NoError(t, err)
		require.NotNil(t, cert)

		assert.NotEmpty(t, cert.CertificatePEM)
		assert.NotEmpty(t, cert.PrivateKeyPEM)
		assert.NotEmpty(t, cert.SerialNumber)
		assert.NotNil(t, cert.Certificate)
		assert.False(t, cert.Expiration.IsZero())

		// Verify certificate subject
		assert.Contains(t, cert.Certificate.Subject.CommonName, "backend-client")
	})

	t.Run("certificate rotation", func(t *testing.T) {
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
		defer client.Close()

		err = client.Authenticate(ctx)
		require.NoError(t, err)

		// Issue first certificate
		opts := &vault.PKIIssueOptions{
			Mount:      vaultSetup.PKIMount,
			Role:       vaultSetup.PKIRole,
			CommonName: "rotation-test.local",
			TTL:        1 * time.Hour,
		}

		cert1, err := client.PKI().IssueCertificate(ctx, opts)
		require.NoError(t, err)

		// Issue second certificate (rotation)
		cert2, err := client.PKI().IssueCertificate(ctx, opts)
		require.NoError(t, err)

		// Certificates should be different
		assert.NotEqual(t, cert1.SerialNumber, cert2.SerialNumber)
		assert.NotEqual(t, cert1.CertificatePEM, cert2.CertificatePEM)
	})

	t.Run("error handling for PKI errors", func(t *testing.T) {
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
		defer client.Close()

		err = client.Authenticate(ctx)
		require.NoError(t, err)

		// Invalid mount
		opts := &vault.PKIIssueOptions{
			Mount:      "invalid-mount",
			Role:       vaultSetup.PKIRole,
			CommonName: "test.local",
		}
		_, err = client.PKI().IssueCertificate(ctx, opts)
		assert.Error(t, err)

		// Invalid role
		opts = &vault.PKIIssueOptions{
			Mount:      vaultSetup.PKIMount,
			Role:       "invalid-role",
			CommonName: "test.local",
		}
		_, err = client.PKI().IssueCertificate(ctx, opts)
		assert.Error(t, err)
	})
}

func TestIntegration_BackendAuth_MTLS_TLSConnection(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("mTLS connection with Vault-issued certificates", func(t *testing.T) {
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
		defer client.Close()

		err = client.Authenticate(ctx)
		require.NoError(t, err)

		// Issue server certificate
		serverOpts := &vault.PKIIssueOptions{
			Mount:      vaultSetup.PKIMount,
			Role:       vaultSetup.PKIRole,
			CommonName: "localhost",
			AltNames:   []string{"localhost", "127.0.0.1"},
			IPSANs:     []string{"127.0.0.1"},
			TTL:        1 * time.Hour,
		}

		serverCert, err := client.PKI().IssueCertificate(ctx, serverOpts)
		require.NoError(t, err)

		// Issue client certificate
		clientOpts := &vault.PKIIssueOptions{
			Mount:      vaultSetup.PKIMount,
			Role:       vaultSetup.PKIRole,
			CommonName: "client.local",
			TTL:        1 * time.Hour,
		}

		clientCert, err := client.PKI().IssueCertificate(ctx, clientOpts)
		require.NoError(t, err)

		// Get CA
		caPool, err := client.PKI().GetCA(ctx, vaultSetup.PKIMount)
		require.NoError(t, err)

		// Create server TLS config
		serverTLSCert, err := tls.X509KeyPair(
			[]byte(serverCert.CertificatePEM),
			[]byte(serverCert.PrivateKeyPEM),
		)
		require.NoError(t, err)

		serverTLSConfig := &tls.Config{
			Certificates: []tls.Certificate{serverTLSCert},
			ClientCAs:    caPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		}

		// Create test server with mTLS
		var receivedCN string
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				receivedCN = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		}))
		server.TLS = serverTLSConfig
		server.StartTLS()
		defer server.Close()

		// Create client TLS config
		clientTLSCert, err := tls.X509KeyPair(
			[]byte(clientCert.CertificatePEM),
			[]byte(clientCert.PrivateKeyPEM),
		)
		require.NoError(t, err)

		clientTLSConfig := &tls.Config{
			Certificates:       []tls.Certificate{clientTLSCert},
			RootCAs:            caPool,
			InsecureSkipVerify: true, // For test with self-signed certs
			MinVersion:         tls.VersionTLS12,
		}

		// Create HTTP client with mTLS
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 10 * time.Second,
		}

		// Make request
		resp, err := httpClient.Get(server.URL + "/api/resource")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "client.local", receivedCN)
	})
}

func TestIntegration_BackendAuth_MTLS_CertificateValidation(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("certificate chain validation", func(t *testing.T) {
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
		defer client.Close()

		err = client.Authenticate(ctx)
		require.NoError(t, err)

		// Issue certificate
		opts := &vault.PKIIssueOptions{
			Mount:      vaultSetup.PKIMount,
			Role:       vaultSetup.PKIRole,
			CommonName: "chain-test.local",
			TTL:        1 * time.Hour,
		}

		cert, err := client.PKI().IssueCertificate(ctx, opts)
		require.NoError(t, err)

		// Get CA
		caPool, err := client.PKI().GetCA(ctx, vaultSetup.PKIMount)
		require.NoError(t, err)

		// Verify certificate against CA
		opts2 := x509.VerifyOptions{
			Roots: caPool,
		}

		_, err = cert.Certificate.Verify(opts2)
		assert.NoError(t, err, "Certificate should be valid against CA")
	})

	t.Run("certificate expiration", func(t *testing.T) {
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
		defer client.Close()

		err = client.Authenticate(ctx)
		require.NoError(t, err)

		// Issue certificate with short TTL
		opts := &vault.PKIIssueOptions{
			Mount:      vaultSetup.PKIMount,
			Role:       vaultSetup.PKIRole,
			CommonName: "expiry-test.local",
			TTL:        1 * time.Hour,
		}

		cert, err := client.PKI().IssueCertificate(ctx, opts)
		require.NoError(t, err)

		// Verify expiration is in the future
		assert.True(t, cert.Expiration.After(time.Now()))
		assert.True(t, cert.Expiration.Before(time.Now().Add(2*time.Hour)))
	})
}

func TestIntegration_BackendAuth_MTLS_Provider(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("vault provider for mTLS", func(t *testing.T) {
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
		defer client.Close()

		err = client.Authenticate(ctx)
		require.NoError(t, err)

		providerCfg := &vault.VaultProviderConfig{
			PKIMount:    vaultSetup.PKIMount,
			Role:        vaultSetup.PKIRole,
			CommonName:  "provider-mtls-test.local",
			TTL:         1 * time.Hour,
			RenewBefore: 10 * time.Minute,
		}

		provider, err := vault.NewVaultProvider(client, providerCfg,
			vault.WithVaultProviderLogger(logger),
		)
		require.NoError(t, err)
		defer provider.Close()

		// Start provider
		err = provider.Start(ctx)
		require.NoError(t, err)

		// Get certificate
		cert, err := provider.GetCertificate(ctx, nil)
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.NotEmpty(t, cert.Certificate)

		// Get certificate info
		info := provider.GetCertificateInfo()
		require.NotNil(t, info)
		assert.Contains(t, info.Subject, "provider-mtls-test.local")
	})
}
