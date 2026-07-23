// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFileProviderFixtures issues a certificate from a throwaway
// self-signed provider and writes tls.crt/tls.key/ca.crt into dir.
func writeFileProviderFixtures(t *testing.T, dir string) (certFile, keyFile, caFile string) {
	t.Helper()

	helper, err := NewSelfSignedProvider(&SelfSignedProviderConfig{KeySize: 2048})
	require.NoError(t, err)
	defer helper.Close()

	issued, err := helper.GetCertificate(context.Background(), &CertificateRequest{
		CommonName: "file-provider-test",
		DNSNames:   []string{"operator.test.svc"},
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

func TestNewFileProvider_LoadsCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeFileProviderFixtures(t, dir)

	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	require.NoError(t, err)
	defer mgr.Close()

	cert, err := mgr.GetCertificate(context.Background(), &CertificateRequest{CommonName: "ignored"})
	require.NoError(t, err)
	assert.Equal(t, "file-provider-test", cert.Certificate.Subject.CommonName)
	assert.Contains(t, cert.Certificate.DNSNames, "operator.test.svc")
	assert.NotEmpty(t, cert.CAChainPEM, "CA chain must be loaded from caFile")
}

func TestNewFileProvider_ConfigErrors(t *testing.T) {
	tests := []struct {
		name   string
		config *FileProviderConfig
	}{
		{name: "nil config", config: nil},
		{name: "missing cert file path", config: &FileProviderConfig{KeyFile: "/k"}},
		{name: "missing key file path", config: &FileProviderConfig{CertFile: "/c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFileProvider(tt.config)
			require.Error(t, err)
		})
	}
}

func TestNewFileProvider_LoadErrors(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeFileProviderFixtures(t, dir)

	missing := filepath.Join(dir, "missing.pem")
	garbage := filepath.Join(dir, "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("not a pem"), 0o600))

	tests := []struct {
		name     string
		certFile string
		keyFile  string
	}{
		{name: "cert file missing", certFile: missing, keyFile: keyFile},
		{name: "key file missing", certFile: certFile, keyFile: missing},
		{name: "garbage cert", certFile: garbage, keyFile: keyFile},
		{name: "garbage key", certFile: certFile, keyFile: garbage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFileProvider(&FileProviderConfig{
				CertFile: tt.certFile,
				KeyFile:  tt.keyFile,
			})
			require.Error(t, err)
		})
	}
}

func TestNewFileProvider_MismatchedKeyPair(t *testing.T) {
	dir := t.TempDir()
	certFile, _, _ := writeFileProviderFixtures(t, dir)

	otherDir := t.TempDir()
	_, otherKey, _ := writeFileProviderFixtures(t, otherDir)

	_, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  otherKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate/key pair")
}

func TestFileProvider_GetCA_FromCAFile(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeFileProviderFixtures(t, dir)

	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	require.NoError(t, err)
	defer mgr.Close()

	pool, err := mgr.GetCA(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, pool)

	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	expected, err := os.ReadFile(caFile)
	require.NoError(t, err)
	assert.Equal(t, expected, caPEM, "GetCAPEM must return the caFile content verbatim")
}

func TestFileProvider_GetCAPEM_FallsBackToBundleChain(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeFileProviderFixtures(t, dir)

	// Append the CA to the cert file (PEM bundle: leaf + chain), no caFile.
	caPEM, err := os.ReadFile(caFile)
	require.NoError(t, err)
	leafPEM, err := os.ReadFile(certFile)
	require.NoError(t, err)
	bundle := filepath.Join(dir, "bundle.crt")
	require.NoError(t, os.WriteFile(bundle, append(leafPEM, caPEM...), 0o600))

	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: bundle,
		KeyFile:  keyFile,
	})
	require.NoError(t, err)
	defer mgr.Close()

	got, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	assert.Equal(t, string(caPEM), string(got),
		"chain blocks after the leaf must serve as the CA bundle")

	pool, err := mgr.GetCA(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestFileProvider_GetCAPEM_NoCASource(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeFileProviderFixtures(t, dir)

	// Single-cert file, no caFile: no CA available.
	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.NoError(t, err)
	defer mgr.Close()

	_, err = mgr.GetCAPEM(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no CA bundle available")

	_, err = mgr.GetCA(context.Background())
	require.Error(t, err)
}

func TestFileProvider_ReloadOnFileChange(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeFileProviderFixtures(t, dir)

	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.NoError(t, err)
	defer mgr.Close()

	first, err := mgr.GetCertificate(context.Background(), nil)
	require.NoError(t, err)

	// Rotate on disk (external rotation: helm upgrade / cert-manager).
	otherDir := t.TempDir()
	newCert, newKey, _ := writeFileProviderFixtures(t, otherDir)
	copyFile(t, newCert, certFile)
	copyFile(t, newKey, keyFile)
	// Ensure a distinct mtime even on coarse-grained filesystems.
	future := time.Now().Add(2 * time.Second)
	require.NoError(t, os.Chtimes(certFile, future, future))

	second, err := mgr.GetCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.NotEqual(t, first.SerialNumber, second.SerialNumber,
		"changed files must be reloaded")
}

func TestFileProvider_RotateCertificate_Reloads(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeFileProviderFixtures(t, dir)

	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.NoError(t, err)
	defer mgr.Close()

	rotated, err := mgr.RotateCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.NotNil(t, rotated)
}

func TestFileProvider_CachedCertificateServed(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeFileProviderFixtures(t, dir)

	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.NoError(t, err)
	defer mgr.Close()

	first, err := mgr.GetCertificate(context.Background(), nil)
	require.NoError(t, err)
	second, err := mgr.GetCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.Same(t, first, second, "unchanged files must serve the cached certificate")
}

func TestFileProvider_Closed(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeFileProviderFixtures(t, dir)

	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	require.NoError(t, err)
	require.NoError(t, mgr.Close())

	_, err = mgr.GetCertificate(context.Background(), nil)
	require.Error(t, err)
	_, err = mgr.GetCAPEM(context.Background())
	require.Error(t, err)
	_, err = mgr.RotateCertificate(context.Background(), nil)
	require.Error(t, err)
}

func TestFileProvider_ContextCanceled(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeFileProviderFixtures(t, dir)

	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.NoError(t, err)
	defer mgr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = mgr.GetCertificate(ctx, nil)
	require.Error(t, err)
	_, err = mgr.RotateCertificate(ctx, nil)
	require.Error(t, err)
}

// TestNewManager_FileModes verifies NewManager dispatches file and
// cert-manager modes to the file provider.
func TestNewManager_FileModes(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeFileProviderFixtures(t, dir)

	for _, mode := range []CertificateMode{CertModeFile, CertModeCertManager} {
		t.Run(string(mode), func(t *testing.T) {
			mgr, err := NewManager(context.Background(), &ManagerConfig{
				Mode: mode,
				File: &FileProviderConfig{
					CertFile: certFile,
					KeyFile:  keyFile,
					CAFile:   caFile,
				},
			})
			require.NoError(t, err)
			defer mgr.Close()

			caPEM, err := mgr.GetCAPEM(context.Background())
			require.NoError(t, err)
			assert.NotEmpty(t, caPEM)
		})
	}
}

// TestNewManager_FileModeRequiresConfig verifies the config guard.
func TestNewManager_FileModeRequiresConfig(t *testing.T) {
	_, err := NewManager(context.Background(), &ManagerConfig{Mode: CertModeFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file configuration required")
}

// copyFile copies src to dst.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, data, 0o600))
}
