// Package main provides tests for writeWebhookCertificates and related functions.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
)

// ============================================================================
// writeWebhookCertificates Tests
// ============================================================================

func TestWriteWebhookCertificates_Success(t *testing.T) {
	ctx := context.Background()

	// Create a real self-signed cert manager
	certManager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
		CACommonName: "test-ca-webhook-cert",
		KeySize:      2048,
	})
	require.NoError(t, err)
	defer certManager.Close()

	cfg := &Config{
		CertServiceName: "test-webhook-service",
		CertNamespace:   "test-namespace",
	}

	certDir, err := writeWebhookCertificates(ctx, cfg, certManager)
	require.NoError(t, err)
	assert.NotEmpty(t, certDir)

	// Verify cert files were written
	certPath := filepath.Join(certDir, "tls.crt")
	keyPath := filepath.Join(certDir, "tls.key")

	certData, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.NotEmpty(t, certData)

	keyData, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.NotEmpty(t, keyData)

	// Verify file permissions (0o600)
	certInfo, err := os.Stat(certPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), certInfo.Mode().Perm())

	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())

	// Clean up
	os.RemoveAll(certDir)
}

func TestWriteWebhookCertificates_WithCustomDNSNames(t *testing.T) {
	ctx := context.Background()

	certManager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
		CACommonName: "test-ca-custom-dns",
		KeySize:      2048,
	})
	require.NoError(t, err)
	defer certManager.Close()

	cfg := &Config{
		CertServiceName: "test-service",
		CertNamespace:   "test-namespace",
		CertDNSNames:    []string{"custom.example.com", "custom2.example.com"},
	}

	certDir, err := writeWebhookCertificates(ctx, cfg, certManager)
	require.NoError(t, err)
	assert.NotEmpty(t, certDir)

	// Verify files exist
	_, err = os.Stat(filepath.Join(certDir, "tls.crt"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(certDir, "tls.key"))
	assert.NoError(t, err)

	// Clean up
	os.RemoveAll(certDir)
}

func TestWriteWebhookCertificates_CertManagerError(t *testing.T) {
	ctx := context.Background()

	mockMgr := &mockCertManagerForWebhook{
		getCertErr: errors.New("certificate generation failed"),
	}

	cfg := &Config{
		CertServiceName: "test-service",
		CertNamespace:   "test-namespace",
	}

	_, err := writeWebhookCertificates(ctx, cfg, mockMgr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get webhook certificate")
}

// mockCertManagerForWebhook implements cert.Manager for testing.
type mockCertManagerForWebhook struct {
	getCertErr error
	getCAErr   error
	certPEM    []byte
	keyPEM     []byte
}

func (m *mockCertManagerForWebhook) GetCertificate(_ context.Context, _ *cert.CertificateRequest) (*cert.Certificate, error) {
	if m.getCertErr != nil {
		return nil, m.getCertErr
	}
	certPEM := m.certPEM
	if certPEM == nil {
		certPEM = []byte("test-cert-pem")
	}
	keyPEM := m.keyPEM
	if keyPEM == nil {
		keyPEM = []byte("test-key-pem")
	}
	return &cert.Certificate{
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

func (m *mockCertManagerForWebhook) GetCA(_ context.Context) (*x509.CertPool, error) {
	if m.getCAErr != nil {
		return nil, m.getCAErr
	}
	return x509.NewCertPool(), nil
}

func (m *mockCertManagerForWebhook) RotateCertificate(ctx context.Context, req *cert.CertificateRequest) (*cert.Certificate, error) {
	return m.GetCertificate(ctx, req)
}

func (m *mockCertManagerForWebhook) Close() error {
	return nil
}

// ============================================================================
// createManagerWithConfig Tests - with WebhookCertDir
// ============================================================================

func TestCreateManagerWithConfig_WithWebhookCertDir(t *testing.T) {
	// Create a test HTTP server to simulate K8s API
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"APIVersions","versions":["v1"]}`))
	}))
	defer ts.Close()

	restConfig := &rest.Config{
		Host: ts.URL,
	}

	certDir := t.TempDir()

	cfg := &Config{
		MetricsAddr:          "0",
		ProbeAddr:            "0",
		EnableLeaderElection: false,
		WebhookPort:          0,
		WebhookCertDir:       certDir,
	}

	mgr, err := createManagerWithConfig(restConfig, cfg)
	require.NoError(t, err)
	assert.NotNil(t, mgr)
}

func TestCreateManagerWithConfig_WithoutWebhookCertDir(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"APIVersions","versions":["v1"]}`))
	}))
	defer ts.Close()

	restConfig := &rest.Config{
		Host: ts.URL,
	}

	cfg := &Config{
		MetricsAddr:          "0",
		ProbeAddr:            "0",
		EnableLeaderElection: false,
		WebhookPort:          0,
		WebhookCertDir:       "", // Empty cert dir
	}

	mgr, err := createManagerWithConfig(restConfig, cfg)
	require.NoError(t, err)
	assert.NotNil(t, mgr)
}

// ============================================================================
// setupCertManagerAndControllerManager Tests - error paths
// ============================================================================

func TestSetupCertManagerAndControllerManager_CertManagerError(t *testing.T) {
	cfg := &Config{
		CertProvider:     "vault",
		VaultAddr:        "", // Empty address will cause error
		VaultPKIMount:    "pki",
		VaultPKIRole:     "operator",
		VaultInitTimeout: 1,
	}

	ctx := context.Background()
	_, _, err := setupCertManagerAndControllerManager(ctx, cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to setup certificate manager")
}

func TestSetupCertManagerAndControllerManager_WithWebhooksEnabled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"APIVersions","versions":["v1"]}`))
	}))
	defer ts.Close()

	restConfig := &rest.Config{
		Host: ts.URL,
	}

	cfg := &Config{
		CertProvider:         "selfsigned",
		EnableWebhooks:       true,
		MetricsAddr:          "0",
		ProbeAddr:            "0",
		EnableLeaderElection: false,
		WebhookPort:          0,
		CertServiceName:      "test-service",
		CertNamespace:        "test-namespace",
	}

	ctx := context.Background()
	certMgr, mgr, err := setupCertManagerAndControllerManager(ctx, cfg, restConfig)
	require.NoError(t, err)
	assert.NotNil(t, certMgr)
	assert.NotNil(t, mgr)
	// WebhookCertDir should have been set
	assert.NotEmpty(t, cfg.WebhookCertDir)

	// Clean up
	certMgr.Close()
	os.RemoveAll(cfg.WebhookCertDir)
}

func TestSetupCertManagerAndControllerManager_WithoutWebhooks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"APIVersions","versions":["v1"]}`))
	}))
	defer ts.Close()

	restConfig := &rest.Config{
		Host: ts.URL,
	}

	cfg := &Config{
		CertProvider:         "selfsigned",
		EnableWebhooks:       false,
		MetricsAddr:          "0",
		ProbeAddr:            "0",
		EnableLeaderElection: false,
		WebhookPort:          0,
	}

	ctx := context.Background()
	certMgr, mgr, err := setupCertManagerAndControllerManager(ctx, cfg, restConfig)
	require.NoError(t, err)
	assert.NotNil(t, certMgr)
	assert.NotNil(t, mgr)

	certMgr.Close()
}

// ============================================================================
// setupOperatorComponents Tests - error paths
// ============================================================================

func TestSetupOperatorComponents_GRPCServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"APIVersions","versions":["v1"]}`))
	}))
	defer ts.Close()

	testScheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(testScheme))
	require.NoError(t, clientgoscheme.AddToScheme(testScheme))
	require.NoError(t, networkingv1.AddToScheme(testScheme))

	restConfig := &rest.Config{Host: ts.URL}
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme: testScheme,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
		HealthProbeBindAddress: "0",
	})
	require.NoError(t, err)

	// Use a mock cert manager that fails
	mockCertMgr := &mockCertManagerForWebhook{
		getCertErr: errors.New("cert error"),
	}

	cfg := &Config{
		EnableGRPCServer: true,
		GRPCPort:         0,
		CertServiceName:  "test",
		CertNamespace:    "test",
		EnableWebhooks:   false,
	}

	ctx := context.Background()
	_, err = setupOperatorComponents(ctx, cfg, mgr, mockCertMgr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to setup gRPC server")
}
