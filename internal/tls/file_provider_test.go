package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// generateTestCertificateFiles creates test certificate files for testing.
func generateTestCertificateFiles(t *testing.T) (certFile, keyFile, caFile, tempDir string, cleanup func()) {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "file-provider-test-*")
	require.NoError(t, err)

	cleanup = func() {
		os.RemoveAll(tempDir)
	}

	// Generate CA key and certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Generate server key and certificate
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"test.example.com", "localhost"},
		BasicConstraintsValid: true,
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})

	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Write files
	certFile = filepath.Join(tempDir, "server.crt")
	keyFile = filepath.Join(tempDir, "server.key")
	caFile = filepath.Join(tempDir, "ca.crt")

	require.NoError(t, os.WriteFile(certFile, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0600))
	require.NoError(t, os.WriteFile(caFile, caPEM, 0600))

	return certFile, keyFile, caFile, tempDir, cleanup
}

// generateInlineCertificates generates PEM-encoded certificate and key data.
func generateInlineCertificates(t *testing.T) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()

	// Generate CA key and certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Generate server key and certificate
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"test.example.com", "localhost"},
		BasicConstraintsValid: true,
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})

	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, caPEM
}

func TestNewFileProvider_NilConfig(t *testing.T) {
	t.Parallel()

	provider, err := NewFileProvider(nil, nil)
	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "certificate configuration is required")
}

func TestNewFileProvider_FileSource(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.NotEmpty(t, cert.Certificate)
}

func TestNewFileProvider_InlineSource(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, _ := generateInlineCertificates(t)

	config := &CertificateConfig{
		Source:   CertificateSourceInline,
		CertData: string(certPEM),
		KeyData:  string(keyPEM),
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.NotEmpty(t, cert.Certificate)
}

func TestNewFileProvider_InvalidCertFile(t *testing.T) {
	t.Parallel()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}

	provider, err := NewFileProvider(config, nil)
	assert.Error(t, err)
	assert.Nil(t, provider)
}

func TestNewFileProvider_InvalidInlineCert(t *testing.T) {
	t.Parallel()

	config := &CertificateConfig{
		Source:   CertificateSourceInline,
		CertData: "invalid cert data",
		KeyData:  "invalid key data",
	}

	provider, err := NewFileProvider(config, nil)
	assert.Error(t, err)
	assert.Nil(t, provider)
}

func TestNewFileProvider_UnsupportedSource(t *testing.T) {
	t.Parallel()

	config := &CertificateConfig{
		Source: CertificateSource("unsupported"),
	}

	provider, err := NewFileProvider(config, nil)
	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "unsupported certificate source")
}

func TestNewFileProvider_WithClientCA(t *testing.T) {
	t.Parallel()

	certFile, keyFile, caFile, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	clientConfig := &ClientValidationConfig{
		Enabled: true,
		CAFile:  caFile,
	}

	provider, err := NewFileProvider(config, clientConfig)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	ctx := context.Background()
	pool, err := provider.GetClientCA(ctx)
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestNewFileProvider_WithInlineClientCA(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, caPEM := generateInlineCertificates(t)

	config := &CertificateConfig{
		Source:   CertificateSourceInline,
		CertData: string(certPEM),
		KeyData:  string(keyPEM),
	}

	clientConfig := &ClientValidationConfig{
		Enabled: true,
		CAData:  string(caPEM),
	}

	provider, err := NewFileProvider(config, clientConfig)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	ctx := context.Background()
	pool, err := provider.GetClientCA(ctx)
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestNewFileProvider_InvalidClientCAFile(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	clientConfig := &ClientValidationConfig{
		Enabled: true,
		CAFile:  "/nonexistent/ca.pem",
	}

	provider, err := NewFileProvider(config, clientConfig)
	assert.Error(t, err)
	assert.Nil(t, provider)
}

func TestNewFileProvider_InvalidClientCAData(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	clientConfig := &ClientValidationConfig{
		Enabled: true,
		CAData:  "invalid CA data",
	}

	provider, err := NewFileProvider(config, clientConfig)
	assert.Error(t, err)
	assert.Nil(t, provider)
}

func TestNewFileProvider_WithOptions(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	logger := observability.NopLogger()

	provider, err := NewFileProvider(config, nil,
		WithFileProviderLogger(logger),
		WithDebounceDelay(200*time.Millisecond),
	)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	assert.Equal(t, 200*time.Millisecond, provider.debounceDelay)
}

func TestFileProvider_GetCertificate(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	ctx := context.Background()
	hello := &tls.ClientHelloInfo{
		ServerName: "test.example.com",
	}

	cert, err := provider.GetCertificate(ctx, hello)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.NotEmpty(t, cert.Certificate)
	assert.NotNil(t, cert.Leaf)
	assert.Equal(t, "test.example.com", cert.Leaf.Subject.CommonName)
}

func TestFileProvider_GetCertificate_Closed(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)

	err = provider.Close()
	require.NoError(t, err)

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, nil)
	assert.ErrorIs(t, err, ErrProviderClosed)
	assert.Nil(t, cert)
}

func TestFileProvider_GetClientCA(t *testing.T) {
	t.Parallel()

	certFile, keyFile, caFile, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	clientConfig := &ClientValidationConfig{
		Enabled: true,
		CAFile:  caFile,
	}

	provider, err := NewFileProvider(config, clientConfig)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	ctx := context.Background()
	pool, err := provider.GetClientCA(ctx)
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestFileProvider_GetClientCA_Closed(t *testing.T) {
	t.Parallel()

	certFile, keyFile, caFile, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	clientConfig := &ClientValidationConfig{
		Enabled: true,
		CAFile:  caFile,
	}

	provider, err := NewFileProvider(config, clientConfig)
	require.NoError(t, err)
	require.NotNil(t, provider)

	err = provider.Close()
	require.NoError(t, err)

	ctx := context.Background()
	pool, err := provider.GetClientCA(ctx)
	assert.ErrorIs(t, err, ErrProviderClosed)
	assert.Nil(t, pool)
}

func TestFileProvider_GetClientCA_NoConfig(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	ctx := context.Background()
	pool, err := provider.GetClientCA(ctx)
	require.NoError(t, err)
	assert.Nil(t, pool)
}

func TestFileProvider_Watch(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	ctx := context.Background()
	ch := provider.Watch(ctx)
	require.NotNil(t, ch)
}

func TestFileProvider_Start_NoReloadInterval(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:         CertificateSourceFile,
		CertFile:       certFile,
		KeyFile:        keyFile,
		ReloadInterval: 0, // No reload
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)

	ctx := context.Background()
	err = provider.Start(ctx)
	require.NoError(t, err)

	// Starting again should be a no-op
	err = provider.Start(ctx)
	require.NoError(t, err)

	// Note: When ReloadInterval is 0, the watchLoop is not started,
	// so we don't call Close() here as it would wait on stoppedCh forever.
	// The provider can still be used for getting certificates.
	cert, err := provider.GetCertificate(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestFileProvider_Start_WithReloadInterval(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:         CertificateSourceFile,
		CertFile:       certFile,
		KeyFile:        keyFile,
		ReloadInterval: 1 * time.Second,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Wait for the initial loaded event
	select {
	case event := <-provider.eventCh:
		assert.Equal(t, CertificateEventLoaded, event.Type)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for loaded event")
	}

	provider.Close()
}

func TestFileProvider_Start_WithClientCA(t *testing.T) {
	t.Parallel()

	certFile, keyFile, caFile, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:         CertificateSourceFile,
		CertFile:       certFile,
		KeyFile:        keyFile,
		ReloadInterval: 1 * time.Second,
	}

	clientConfig := &ClientValidationConfig{
		Enabled: true,
		CAFile:  caFile,
	}

	provider, err := NewFileProvider(config, clientConfig)
	require.NoError(t, err)
	require.NotNil(t, provider)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	provider.Close()
}

func TestFileProvider_Start_KeyInDifferentDirectory(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, tempDir, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	// Create a subdirectory for the key
	keyDir := filepath.Join(tempDir, "keys")
	require.NoError(t, os.MkdirAll(keyDir, 0755))

	newKeyFile := filepath.Join(keyDir, "server.key")
	keyData, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(newKeyFile, keyData, 0600))

	config := &CertificateConfig{
		Source:         CertificateSourceFile,
		CertFile:       certFile,
		KeyFile:        newKeyFile,
		ReloadInterval: 1 * time.Second,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	provider.Close()
}

func TestFileProvider_Close(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)

	err = provider.Close()
	require.NoError(t, err)

	// Closing again should be a no-op
	err = provider.Close()
	require.NoError(t, err)
}

func TestFileProvider_Close_WithWatcher(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:         CertificateSourceFile,
		CertFile:       certFile,
		KeyFile:        keyFile,
		ReloadInterval: 1 * time.Second,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Give time for watcher to start
	time.Sleep(50 * time.Millisecond)

	err = provider.Close()
	require.NoError(t, err)
}

func TestFileProvider_HandleFileEvent_Irrelevant(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// Test with irrelevant file
	event := fsnotify.Event{
		Name: "/some/other/file.txt",
		Op:   fsnotify.Write,
	}

	timer, ch := provider.handleFileEvent(event, nil, nil)
	assert.Nil(t, timer)
	assert.Nil(t, ch)
}

func TestFileProvider_HandleFileEvent_Relevant(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// Test with relevant file (cert file)
	event := fsnotify.Event{
		Name: certFile,
		Op:   fsnotify.Write,
	}

	timer, ch := provider.handleFileEvent(event, nil, nil)
	assert.NotNil(t, timer)
	assert.NotNil(t, ch)

	// Stop the timer to clean up
	timer.Stop()
}

func TestFileProvider_HandleFileEvent_KeyFile(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// Test with key file
	event := fsnotify.Event{
		Name: keyFile,
		Op:   fsnotify.Write,
	}

	timer, ch := provider.handleFileEvent(event, nil, nil)
	assert.NotNil(t, timer)
	assert.NotNil(t, ch)

	timer.Stop()
}

func TestFileProvider_HandleFileEvent_CAFile(t *testing.T) {
	t.Parallel()

	certFile, keyFile, caFile, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	clientConfig := &ClientValidationConfig{
		Enabled: true,
		CAFile:  caFile,
	}

	provider, err := NewFileProvider(config, clientConfig)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// Test with CA file
	event := fsnotify.Event{
		Name: caFile,
		Op:   fsnotify.Write,
	}

	timer, ch := provider.handleFileEvent(event, nil, nil)
	assert.NotNil(t, timer)
	assert.NotNil(t, ch)

	timer.Stop()
}

func TestFileProvider_HandleFileEvent_NonWriteOp(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// Test with non-write operation
	event := fsnotify.Event{
		Name: certFile,
		Op:   fsnotify.Chmod, // Not a write or create
	}

	timer, ch := provider.handleFileEvent(event, nil, nil)
	assert.Nil(t, timer)
	assert.Nil(t, ch)
}

func TestFileProvider_HandleFileEvent_CreateOp(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// Test with create operation
	event := fsnotify.Event{
		Name: certFile,
		Op:   fsnotify.Create,
	}

	timer, ch := provider.handleFileEvent(event, nil, nil)
	assert.NotNil(t, timer)
	assert.NotNil(t, ch)

	timer.Stop()
}

func TestFileProvider_HandleFileEvent_ResetTimer(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// First event
	event := fsnotify.Event{
		Name: certFile,
		Op:   fsnotify.Write,
	}

	timer1, ch1 := provider.handleFileEvent(event, nil, nil)
	assert.NotNil(t, timer1)
	assert.NotNil(t, ch1)

	// Second event should reset the timer
	timer2, ch2 := provider.handleFileEvent(event, timer1, ch1)
	assert.NotNil(t, timer2)
	assert.NotNil(t, ch2)

	timer2.Stop()
}

func TestFileProvider_IsRelevantFile(t *testing.T) {
	t.Parallel()

	certFile, keyFile, caFile, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	clientConfig := &ClientValidationConfig{
		Enabled: true,
		CAFile:  caFile,
	}

	provider, err := NewFileProvider(config, clientConfig)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"cert file", certFile, true},
		{"key file", keyFile, true},
		{"ca file", caFile, true},
		{"other file", "/some/other/file.txt", false},
		{"empty path", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.isRelevantFile(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFileProvider_Reload(t *testing.T) {
	t.Parallel()

	certFile, keyFile, caFile, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	clientConfig := &ClientValidationConfig{
		Enabled: true,
		CAFile:  caFile,
	}

	provider, err := NewFileProvider(config, clientConfig)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// Trigger reload
	provider.reload()

	// Check for reloaded event
	select {
	case event := <-provider.eventCh:
		assert.Equal(t, CertificateEventReloaded, event.Type)
		assert.NotNil(t, event.Certificate)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for reload event")
	}
}

func TestFileProvider_Reload_CertError(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, tempDir, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// Delete the cert file to cause an error
	require.NoError(t, os.Remove(certFile))

	// Trigger reload
	provider.reload()

	// Check for error event
	select {
	case event := <-provider.eventCh:
		assert.Equal(t, CertificateEventError, event.Type)
		assert.NotNil(t, event.Error)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for error event")
	}

	// Restore the file for cleanup
	certPEM, keyPEM, _ := generateInlineCertificates(t)
	require.NoError(t, os.WriteFile(certFile, certPEM, 0600))
	_ = keyPEM
	_ = tempDir
}

func TestFileProvider_Reload_CAError(t *testing.T) {
	t.Parallel()

	certFile, keyFile, caFile, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	clientConfig := &ClientValidationConfig{
		Enabled: true,
		CAFile:  caFile,
	}

	provider, err := NewFileProvider(config, clientConfig)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// Delete the CA file to cause an error
	require.NoError(t, os.Remove(caFile))

	// Trigger reload
	provider.reload()

	// Check for error event
	select {
	case event := <-provider.eventCh:
		assert.Equal(t, CertificateEventError, event.Type)
		assert.NotNil(t, event.Error)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for error event")
	}
}

func TestFileProvider_SendEvent_ChannelFull(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// Fill the channel
	for i := 0; i < 10; i++ {
		provider.sendEvent(CertificateEvent{
			Type:    CertificateEventLoaded,
			Message: "test",
		})
	}

	// This should not block (channel is full, event is dropped)
	provider.sendEvent(CertificateEvent{
		Type:    CertificateEventLoaded,
		Message: "dropped",
	})
}

func TestFileProvider_ImplementsInterface(t *testing.T) {
	t.Parallel()

	var _ CertificateProvider = (*FileProvider)(nil)
}

func TestLoadCertificateFromFile(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	cert, err := LoadCertificateFromFile(certFile, keyFile)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.NotEmpty(t, cert.Certificate)
	assert.NotNil(t, cert.Leaf)
}

func TestLoadCertificateFromFile_InvalidFile(t *testing.T) {
	t.Parallel()

	cert, err := LoadCertificateFromFile("/nonexistent/cert.pem", "/nonexistent/key.pem")
	assert.Error(t, err)
	assert.Nil(t, cert)
}

func TestLoadCertificateFromPEM(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, _ := generateInlineCertificates(t)

	cert, err := LoadCertificateFromPEM(certPEM, keyPEM)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.NotEmpty(t, cert.Certificate)
	assert.NotNil(t, cert.Leaf)
}

func TestLoadCertificateFromPEM_Invalid(t *testing.T) {
	t.Parallel()

	cert, err := LoadCertificateFromPEM([]byte("invalid"), []byte("invalid"))
	assert.Error(t, err)
	assert.Nil(t, cert)
}

func TestLoadCAFromFile(t *testing.T) {
	t.Parallel()

	_, _, caFile, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	pool, err := LoadCAFromFile(caFile)
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestLoadCAFromFile_InvalidFile(t *testing.T) {
	t.Parallel()

	pool, err := LoadCAFromFile("/nonexistent/ca.pem")
	assert.Error(t, err)
	assert.Nil(t, pool)
}

func TestLoadCAFromPEM(t *testing.T) {
	t.Parallel()

	_, _, caPEM := generateInlineCertificates(t)

	pool, err := LoadCAFromPEM(caPEM)
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestLoadCAFromPEM_Invalid(t *testing.T) {
	t.Parallel()

	pool, err := LoadCAFromPEM([]byte("invalid"))
	assert.Error(t, err)
	assert.Nil(t, pool)
}

func TestParsePEMCertificates(t *testing.T) {
	t.Parallel()

	certPEM, _, caPEM := generateInlineCertificates(t)

	// Test with single certificate
	certs, err := ParsePEMCertificates(certPEM)
	require.NoError(t, err)
	assert.Len(t, certs, 1)

	// Test with CA certificate
	certs, err = ParsePEMCertificates(caPEM)
	require.NoError(t, err)
	assert.Len(t, certs, 1)
}

func TestParsePEMCertificates_MultipleCerts(t *testing.T) {
	t.Parallel()

	certPEM, _, caPEM := generateInlineCertificates(t)

	// Combine certificates
	combined := append(certPEM, caPEM...)

	certs, err := ParsePEMCertificates(combined)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestParsePEMCertificates_NoCerts(t *testing.T) {
	t.Parallel()

	certs, err := ParsePEMCertificates([]byte("not a certificate"))
	assert.Error(t, err)
	assert.Nil(t, certs)
	assert.Contains(t, err.Error(), "no certificates found")
}

func TestParsePEMCertificates_InvalidCert(t *testing.T) {
	t.Parallel()

	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid certificate data"),
	})

	certs, err := ParsePEMCertificates(invalidPEM)
	assert.Error(t, err)
	assert.Nil(t, certs)
}

func TestParsePEMCertificates_SkipsNonCertBlocks(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, _ := generateInlineCertificates(t)

	// Combine cert and key (key should be skipped)
	combined := append(certPEM, keyPEM...)

	certs, err := ParsePEMCertificates(combined)
	require.NoError(t, err)
	assert.Len(t, certs, 1)
}

func TestDecryptPEMBlock_NotEncrypted(t *testing.T) {
	t.Parallel()

	_, keyPEM, _ := generateInlineCertificates(t)

	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block)

	decrypted, err := DecryptPEMBlock(block, nil)
	require.NoError(t, err)
	assert.Equal(t, block.Bytes, decrypted)
}

func TestLoadEncryptedKeyFromFile_NotEncrypted(t *testing.T) {
	t.Parallel()

	_, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	keyData, err := LoadEncryptedKeyFromFile(keyFile, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, keyData)
}

func TestLoadEncryptedKeyFromFile_InvalidFile(t *testing.T) {
	t.Parallel()

	keyData, err := LoadEncryptedKeyFromFile("/nonexistent/key.pem", nil)
	assert.Error(t, err)
	assert.Nil(t, keyData)
}

func TestLoadEncryptedKeyFromFile_InvalidPEM(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	keyFile := filepath.Join(tempDir, "invalid.key")
	require.NoError(t, os.WriteFile(keyFile, []byte("not a pem block"), 0600))

	keyData, err := LoadEncryptedKeyFromFile(keyFile, nil)
	assert.Error(t, err)
	assert.Nil(t, keyData)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestValidateCertificateKeyPair(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, _ := generateInlineCertificates(t)

	err := ValidateCertificateKeyPair(certPEM, keyPEM)
	require.NoError(t, err)
}

func TestValidateCertificateKeyPair_Mismatch(t *testing.T) {
	t.Parallel()

	certPEM1, _, _ := generateInlineCertificates(t)
	_, keyPEM2, _ := generateInlineCertificates(t)

	err := ValidateCertificateKeyPair(certPEM1, keyPEM2)
	assert.Error(t, err)
}

func TestValidateCertificateKeyPair_Invalid(t *testing.T) {
	t.Parallel()

	err := ValidateCertificateKeyPair([]byte("invalid"), []byte("invalid"))
	assert.Error(t, err)
}

func TestWithFileProviderLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	opt := WithFileProviderLogger(logger)

	p := &FileProvider{}
	opt(p)

	assert.NotNil(t, p.logger)
}

func TestWithDebounceDelay(t *testing.T) {
	t.Parallel()

	opt := WithDebounceDelay(500 * time.Millisecond)

	p := &FileProvider{}
	opt(p)

	assert.Equal(t, 500*time.Millisecond, p.debounceDelay)
}

func TestFileProvider_CertificateRotation(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, tempDir, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:         CertificateSourceFile,
		CertFile:       certFile,
		KeyFile:        keyFile,
		ReloadInterval: 100 * time.Millisecond,
	}

	provider, err := NewFileProvider(config, nil,
		WithDebounceDelay(50*time.Millisecond),
	)
	require.NoError(t, err)
	require.NotNil(t, provider)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Wait for initial loaded event
	select {
	case event := <-provider.eventCh:
		assert.Equal(t, CertificateEventLoaded, event.Type)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for loaded event")
	}

	// Get the original certificate
	origCert, err := provider.GetCertificate(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, origCert)

	// Generate new certificates
	newCertPEM, newKeyPEM, _ := generateInlineCertificates(t)

	// Write new certificates
	require.NoError(t, os.WriteFile(certFile, newCertPEM, 0600))
	require.NoError(t, os.WriteFile(keyFile, newKeyPEM, 0600))

	// Wait for reload event
	select {
	case event := <-provider.eventCh:
		assert.Equal(t, CertificateEventReloaded, event.Type)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for reload event")
	}

	// Get the new certificate
	newCert, err := provider.GetCertificate(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, newCert)

	// Certificates should be different
	assert.NotEqual(t, origCert.Certificate[0], newCert.Certificate[0])

	provider.Close()
	_ = tempDir
}

func TestFileProvider_WatchLoop_ContextCancellation(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:         CertificateSourceFile,
		CertFile:       certFile,
		KeyFile:        keyFile,
		ReloadInterval: 1 * time.Second,
	}

	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)

	ctx, cancel := context.WithCancel(context.Background())

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Wait for initial event
	select {
	case <-provider.eventCh:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for initial event")
	}

	// Cancel context
	cancel()

	// Give time for goroutine to exit
	time.Sleep(100 * time.Millisecond)

	provider.Close()
}

func TestFileProvider_ReadCAData_NoConfig(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _, _, cleanup := generateTestCertificateFiles(t)
	defer cleanup()

	config := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	// Create provider with nil client config
	provider, err := NewFileProvider(config, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
	defer provider.Close()

	// Set client to empty config (no CA file or data)
	provider.client = &ClientValidationConfig{
		Enabled: true,
		// No CAFile or CAData
	}

	// readCAData should return nil, nil
	data, err := provider.readCAData()
	require.NoError(t, err)
	assert.Nil(t, data)
}
