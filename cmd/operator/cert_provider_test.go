// Package main tests for certificate provider selection, the cert-manager
// webhook cert-dir handling, and selfsigned Secret persistence wiring.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
)

// writeCertFixtures writes tls.crt/tls.key/ca.crt into dir using a
// throwaway self-signed provider and returns the paths.
func writeCertFixtures(t *testing.T, dir string) (certFile, keyFile, caFile string) {
	t.Helper()

	helper, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{KeySize: 2048})
	require.NoError(t, err)
	defer helper.Close()

	issued, err := helper.GetCertificate(context.Background(), &cert.CertificateRequest{
		CommonName: "cert-provider-test",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)

	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	caFile = filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(certFile, issued.CertificatePEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, issued.PrivateKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(caFile, issued.CAChainPEM, 0o600))
	return certFile, keyFile, caFile
}

// TestSetupCertManager_FileProvider verifies explicit cert/key/ca paths.
func TestSetupCertManager_FileProvider(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeCertFixtures(t, dir)

	mgr, err := setupCertManager(context.Background(), &Config{
		CertProvider: "file",
		CertFile:     certFile,
		KeyFile:      keyFile,
		CACertFile:   caFile,
	}, nil)
	require.NoError(t, err)
	defer mgr.Close()

	issued, err := mgr.GetCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "cert-provider-test", issued.Certificate.Subject.CommonName)

	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, caPEM)
}

// TestSetupCertManager_FileProvider_MissingFiles verifies fail-fast.
func TestSetupCertManager_FileProvider_MissingFiles(t *testing.T) {
	_, err := setupCertManager(context.Background(), &Config{
		CertProvider: "file",
		CertFile:     "/nonexistent/tls.crt",
		KeyFile:      "/nonexistent/tls.key",
	}, nil)
	require.Error(t, err)
}

// TestSetupCertManager_CertManagerProvider_UsesWebhookCertDir verifies the
// cert-manager provider loads from the configured (mounted) cert dir.
func TestSetupCertManager_CertManagerProvider_UsesWebhookCertDir(t *testing.T) {
	dir := t.TempDir()
	writeCertFixtures(t, dir)

	mgr, err := setupCertManager(context.Background(), &Config{
		CertProvider:   "cert-manager",
		WebhookCertDir: dir,
	}, nil)
	require.NoError(t, err)
	defer mgr.Close()

	issued, err := mgr.GetCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "cert-provider-test", issued.Certificate.Subject.CommonName)

	// ca.crt exists in the dir, so the CA bundle must come from it.
	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	expected, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	require.NoError(t, err)
	assert.Equal(t, expected, caPEM)
}

// TestSetupCertManager_CertManagerProvider_NoCAFile verifies ca.crt is
// optional (ACME issuers do not provide it).
func TestSetupCertManager_CertManagerProvider_NoCAFile(t *testing.T) {
	dir := t.TempDir()
	writeCertFixtures(t, dir)
	require.NoError(t, os.Remove(filepath.Join(dir, "ca.crt")))

	mgr, err := setupCertManager(context.Background(), &Config{
		CertProvider:   "cert-manager",
		WebhookCertDir: dir,
	}, nil)
	require.NoError(t, err)
	defer mgr.Close()

	_, err = mgr.GetCertificate(context.Background(), nil)
	require.NoError(t, err)
}

// TestUsesExternalWebhookCerts covers the provider classification.
func TestUsesExternalWebhookCerts(t *testing.T) {
	tests := []struct {
		provider string
		want     bool
	}{
		{provider: "cert-manager", want: true},
		{provider: "file", want: true},
		{provider: "selfsigned", want: false},
		{provider: "vault", want: false},
		{provider: "", want: false},
	}
	for _, tt := range tests {
		t.Run("provider_"+tt.provider, func(t *testing.T) {
			assert.Equal(t, tt.want, usesExternalWebhookCerts(&Config{CertProvider: tt.provider}))
		})
	}
}

// TestResolveExternalWebhookCertDir verifies fix #3: the configured
// webhook cert dir is HONORED for externally provisioned certificates
// (never overridden by internal provisioning), with sensible derivation.
func TestResolveExternalWebhookCertDir(t *testing.T) {
	t.Run("explicit dir honored verbatim", func(t *testing.T) {
		cfg := &Config{
			CertProvider:   "cert-manager",
			WebhookCertDir: "/mnt/certs",
		}
		require.NoError(t, resolveExternalWebhookCertDir(cfg))
		assert.Equal(t, "/mnt/certs", cfg.WebhookCertDir,
			"a configured cert dir must never be overridden")
		assert.Empty(t, cfg.WebhookCertName)
		assert.Empty(t, cfg.WebhookKeyName)
	})

	t.Run("cert-manager default dir when unset", func(t *testing.T) {
		cfg := &Config{CertProvider: "cert-manager"}
		require.NoError(t, resolveExternalWebhookCertDir(cfg))
		assert.Equal(t, defaultCertManagerCertDir, cfg.WebhookCertDir)
	})

	t.Run("file provider derives dir and names from cert paths", func(t *testing.T) {
		cfg := &Config{
			CertProvider: "file",
			CertFile:     "/mnt/certs/server.crt",
			KeyFile:      "/mnt/certs/server.key",
		}
		require.NoError(t, resolveExternalWebhookCertDir(cfg))
		assert.Equal(t, "/mnt/certs", cfg.WebhookCertDir)
		assert.Equal(t, "server.crt", cfg.WebhookCertName)
		assert.Equal(t, "server.key", cfg.WebhookKeyName)
	})

	t.Run("file provider with split dirs errors", func(t *testing.T) {
		cfg := &Config{
			CertProvider: "file",
			CertFile:     "/mnt/a/tls.crt",
			KeyFile:      "/mnt/b/tls.key",
		}
		require.Error(t, resolveExternalWebhookCertDir(cfg))
	})
}

// TestSetupCertManagerAndControllerManager_CertManagerSkipsProvisioning
// verifies the full wiring: with the cert-manager provider the internal
// webhook certificate provisioning is skipped and the mounted dir is used.
func TestSetupCertManagerAndControllerManager_CertManagerSkipsProvisioning(t *testing.T) {
	dir := t.TempDir()
	writeCertFixtures(t, dir)

	cfg := &Config{
		CertProvider:   "cert-manager",
		WebhookCertDir: dir,
		EnableWebhooks: true,
		MetricsAddr:    "0",
		ProbeAddr:      "0",
	}

	certManager, mgr, err := setupCertManagerAndControllerManager(
		context.Background(), cfg, newFakeRESTConfig())
	require.NoError(t, err)
	defer certManager.Close()
	require.NotNil(t, mgr)

	assert.Equal(t, dir, cfg.WebhookCertDir,
		"cert-manager mode must honor the configured cert dir (no temp-dir override)")
}

// newFakeRESTConfig returns a REST config pointing at a non-routable
// address; manager creation does not contact the API server.
func newFakeRESTConfig() *rest.Config {
	return &rest.Config{Host: "https://127.0.0.1:1"}
}

// TestResolveCertSecretNamespace covers precedence: flag > POD_NAMESPACE > cert namespace.
func TestResolveCertSecretNamespace(t *testing.T) {
	t.Run("explicit flag wins", func(t *testing.T) {
		t.Setenv("POD_NAMESPACE", "pod-ns")
		cfg := &Config{CertSecretNamespace: "explicit-ns", CertNamespace: "cert-ns"}
		assert.Equal(t, "explicit-ns", resolveCertSecretNamespace(cfg))
	})
	t.Run("pod namespace fallback", func(t *testing.T) {
		t.Setenv("POD_NAMESPACE", "pod-ns")
		cfg := &Config{CertNamespace: "cert-ns"}
		assert.Equal(t, "pod-ns", resolveCertSecretNamespace(cfg))
	})
	t.Run("cert namespace fallback", func(t *testing.T) {
		t.Setenv("POD_NAMESPACE", "")
		cfg := &Config{CertNamespace: "cert-ns"}
		assert.Equal(t, "cert-ns", resolveCertSecretNamespace(cfg))
	})
}

// TestSetupSelfSignedCertManager_PersistenceWired verifies CERT_SECRET_NAME
// wiring persists the CA through the injected secret client.
func TestSetupSelfSignedCertManager_PersistenceWired(t *testing.T) {
	scheme2 := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme2))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme2).Build()

	origNewSecretClient := newSecretClient
	newSecretClient = func(_ *rest.Config) (cert.SecretStore, error) {
		return fakeClient, nil
	}
	t.Cleanup(func() { newSecretClient = origNewSecretClient })

	cfg := &Config{
		CertProvider:        "selfsigned",
		CertSecretName:      "op-grpc-cert",
		CertSecretNamespace: "op-ns",
	}

	mgr, err := setupCertManager(context.Background(), cfg, newFakeRESTConfig())
	require.NoError(t, err)
	defer mgr.Close()

	secret := &corev1.Secret{}
	require.NoError(t, fakeClient.Get(context.Background(),
		types.NamespacedName{Namespace: "op-ns", Name: "op-grpc-cert"}, secret))
	assert.NotEmpty(t, secret.Data["ca.crt"], "CA must be persisted to the configured Secret")
	assert.NotEmpty(t, secret.Data["ca.key"])
}

// TestSetupSelfSignedCertManager_ClientErrorFallsBack verifies graceful
// degradation when the secret client cannot be built.
func TestSetupSelfSignedCertManager_ClientErrorFallsBack(t *testing.T) {
	origNewSecretClient := newSecretClient
	newSecretClient = func(_ *rest.Config) (cert.SecretStore, error) {
		return nil, fmt.Errorf("no kubeconfig")
	}
	t.Cleanup(func() { newSecretClient = origNewSecretClient })

	cfg := &Config{
		CertProvider:   "selfsigned",
		CertSecretName: "op-grpc-cert",
	}

	mgr, err := setupCertManager(context.Background(), cfg, newFakeRESTConfig())
	require.NoError(t, err, "persistence failures must not block startup")
	defer mgr.Close()

	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, caPEM)
}

// TestNewSecretClient_NilConfig verifies the guard.
func TestNewSecretClient_NilConfig(t *testing.T) {
	_, err := newSecretClient(nil)
	require.Error(t, err)
}
