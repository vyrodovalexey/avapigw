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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// testCertificates holds test certificate data.
type testCertificates struct {
	certPEM   []byte
	keyPEM    []byte
	caPEM     []byte
	certFile  string
	keyFile   string
	caFile    string
	tempDir   string
	notBefore time.Time
	notAfter  time.Time
}

// generateTestCertificates creates test certificates for testing.
func generateTestCertificates(t *testing.T) *testCertificates {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "tls-test-*")
	require.NoError(t, err)

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

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
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
	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	caFile := filepath.Join(tempDir, "ca.crt")

	require.NoError(t, os.WriteFile(certFile, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0600))
	require.NoError(t, os.WriteFile(caFile, caPEM, 0600))

	return &testCertificates{
		certPEM:   certPEM,
		keyPEM:    keyPEM,
		caPEM:     caPEM,
		certFile:  certFile,
		keyFile:   keyFile,
		caFile:    caFile,
		tempDir:   tempDir,
		notBefore: notBefore,
		notAfter:  notAfter,
	}
}

// cleanup removes temporary test files.
func (tc *testCertificates) cleanup() {
	if tc.tempDir != "" {
		os.RemoveAll(tc.tempDir)
	}
}

// mockMetrics is a mock implementation of MetricsRecorder for testing.
type mockMetrics struct {
	mu                       sync.Mutex
	connectionCount          int
	handshakeDurationCount   int
	certExpiryCount          int
	certReloadSuccessCount   int
	certReloadFailureCount   int
	handshakeErrorCount      int
	clientCertValidCount     int
	clientCertInvalidCount   int
	lastHandshakeErrorReason string
	lastValidationReason     string
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{}
}

func (m *mockMetrics) RecordConnection(_ uint16, _ uint16, _ TLSMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectionCount++
}

func (m *mockMetrics) RecordHandshakeDuration(_ time.Duration, _ uint16, _ TLSMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handshakeDurationCount++
}

func (m *mockMetrics) UpdateCertificateExpiry(_ *x509.Certificate, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certExpiryCount++
}

func (m *mockMetrics) UpdateCertificateExpiryFromTLS(_ *tls.Certificate, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certExpiryCount++
}

func (m *mockMetrics) RecordCertificateReload(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if success {
		m.certReloadSuccessCount++
	} else {
		m.certReloadFailureCount++
	}
}

func (m *mockMetrics) RecordHandshakeError(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handshakeErrorCount++
	m.lastHandshakeErrorReason = reason
}

func (m *mockMetrics) RecordClientCertValidation(success bool, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if success {
		m.clientCertValidCount++
	} else {
		m.clientCertInvalidCount++
		m.lastValidationReason = reason
	}
}

// Thread-safe getters for test assertions
func (m *mockMetrics) getCertReloadSuccessCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.certReloadSuccessCount
}

func (m *mockMetrics) getCertReloadFailureCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.certReloadFailureCount
}

func (m *mockMetrics) getConnectionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connectionCount
}

func (m *mockMetrics) getHandshakeDurationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handshakeDurationCount
}

func (m *mockMetrics) getCertExpiryCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.certExpiryCount
}

func (m *mockMetrics) getHandshakeErrorCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handshakeErrorCount
}

func (m *mockMetrics) getClientCertValidCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clientCertValidCount
}

func (m *mockMetrics) getClientCertInvalidCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clientCertInvalidCount
}

func (m *mockMetrics) getLastValidationReason() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastValidationReason
}

// mockProvider is a mock implementation of CertificateProvider for testing.
type mockProvider struct {
	mu          sync.RWMutex
	cert        *tls.Certificate
	clientCA    *x509.CertPool
	certErr     error
	clientCAErr error
	eventCh     chan CertificateEvent
	closed      bool
	started     bool
}

func newMockProvider() *mockProvider {
	return &mockProvider{
		eventCh: make(chan CertificateEvent, 10),
	}
}

func (p *mockProvider) GetCertificate(_ context.Context, _ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrProviderClosed
	}
	if p.certErr != nil {
		return nil, p.certErr
	}
	return p.cert, nil
}

func (p *mockProvider) GetClientCA(_ context.Context) (*x509.CertPool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrProviderClosed
	}
	if p.clientCAErr != nil {
		return nil, p.clientCAErr
	}
	return p.clientCA, nil
}

func (p *mockProvider) Watch(_ context.Context) <-chan CertificateEvent {
	return p.eventCh
}

func (p *mockProvider) Start(_ context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started = true
	return nil
}

func (p *mockProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	close(p.eventCh)
	return nil
}

func (p *mockProvider) setCertificate(cert *tls.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cert = cert
}

func (p *mockProvider) setClientCA(pool *x509.CertPool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clientCA = pool
}

func (p *mockProvider) setCertError(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.certErr = err
}

func (p *mockProvider) sendEvent(event CertificateEvent) {
	p.eventCh <- event
}

// Ensure mockProvider implements CertificateProvider.
var _ CertificateProvider = (*mockProvider)(nil)

func TestNewManager_NilConfig(t *testing.T) {
	t.Parallel()

	// Nil config uses DefaultConfig() which is SIMPLE mode,
	// but SIMPLE mode requires a certificate, so this should fail
	manager, err := NewManager(nil)
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "server certificate required")
}

func TestNewManager_InvalidConfig(t *testing.T) {
	t.Parallel()

	config := &Config{
		Mode: TLSMode("INVALID"),
	}

	manager, err := NewManager(config)
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "invalid TLS mode")
}

func TestNewManager_SimpleMode(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		MaxVersion: TLSVersion13,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.Equal(t, TLSModeSimple, manager.GetMode())
	assert.True(t, manager.IsEnabled())
	assert.False(t, manager.IsMTLSEnabled())

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MaxVersion)
	assert.Equal(t, tls.NoClientCert, tlsConfig.ClientAuth)
}

func TestNewManager_MutualMode(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeMutual,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		ClientValidation: &ClientValidationConfig{
			Enabled: true,
			CAFile:  certs.caFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.Equal(t, TLSModeMutual, manager.GetMode())
	assert.True(t, manager.IsEnabled())
	assert.True(t, manager.IsMTLSEnabled())

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	assert.NotNil(t, tlsConfig.ClientCAs)
}

func TestNewManager_OptionalMutualMode(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeOptionalMutual,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		ClientValidation: &ClientValidationConfig{
			Enabled: true,
			CAFile:  certs.caFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.Equal(t, TLSModeOptionalMutual, manager.GetMode())
	assert.True(t, manager.IsMTLSEnabled())

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	assert.Equal(t, tls.VerifyClientCertIfGiven, tlsConfig.ClientAuth)
}

func TestNewManager_InsecureMode(t *testing.T) {
	t.Parallel()

	config := &Config{
		Mode: TLSModeInsecure,
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.Equal(t, TLSModeInsecure, manager.GetMode())
	assert.False(t, manager.IsEnabled())
	assert.False(t, manager.IsMTLSEnabled())

	tlsConfig := manager.GetTLSConfig()
	assert.Nil(t, tlsConfig)
}

func TestNewManager_PassthroughMode(t *testing.T) {
	t.Parallel()

	config := &Config{
		Mode: TLSModePassthrough,
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.Equal(t, TLSModePassthrough, manager.GetMode())
	assert.True(t, manager.IsEnabled())
	assert.False(t, manager.IsMTLSEnabled())

	tlsConfig := manager.GetTLSConfig()
	assert.Nil(t, tlsConfig)
}

func TestNewManager_AutoPassthroughMode(t *testing.T) {
	t.Parallel()

	config := &Config{
		Mode: TLSModeAutoPassthrough,
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.Equal(t, TLSModeAutoPassthrough, manager.GetMode())
	tlsConfig := manager.GetTLSConfig()
	assert.Nil(t, tlsConfig)
}

func TestNewManager_WithOptions(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	logger := observability.NopLogger()
	metrics := newMockMetrics()
	provider := newMockProvider()

	// Load certificate for mock provider
	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	provider.setCertificate(&cert)

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config,
		WithManagerLogger(logger),
		WithManagerMetrics(metrics),
		WithCertificateProvider(provider),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.Equal(t, TLSModeSimple, manager.GetMode())
}

func TestNewManager_InlineCertificate(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			Source:   CertificateSourceInline,
			CertData: string(certs.certPEM),
			KeyData:  string(certs.keyPEM),
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
}

func TestNewManager_VaultNotImplemented(t *testing.T) {
	t.Parallel()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
		},
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "example.com",
		},
	}

	manager, err := NewManager(config)
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "vault provider factory is required when vault TLS is enabled")
}

func TestNewManager_InvalidCertificateFile(t *testing.T) {
	t.Parallel()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		},
	}

	manager, err := NewManager(config)
	assert.Error(t, err)
	assert.Nil(t, manager)
}

func TestNewManager_LegacyTLSVersion(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion10, // Legacy version
		MaxVersion: TLSVersion13,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	assert.Equal(t, uint16(tls.VersionTLS10), tlsConfig.MinVersion)
}

func TestNewManager_WithCipherSuites(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		MaxVersion: TLSVersion12, // TLS 1.2 to use cipher suites
		CipherSuites: []string{
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	assert.Len(t, tlsConfig.CipherSuites, 2)
}

func TestNewManager_WithCurvePreferences(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		CurvePreferences: []string{
			"X25519",
			"P256",
		},
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	assert.Len(t, tlsConfig.CurvePreferences, 2)
}

func TestNewManager_WithALPN(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ALPN:       []string{"h2", "http/1.1"},
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	assert.Equal(t, []string{"h2", "http/1.1"}, tlsConfig.NextProtos)
}

func TestNewManager_SessionTicketsDisabled(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:                   TLSModeSimple,
		MinVersion:             TLSVersion12,
		SessionTicketsDisabled: true,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	assert.True(t, tlsConfig.SessionTicketsDisabled)
}

func TestNewManager_InsecureSkipVerify(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:               TLSModeSimple,
		MinVersion:         TLSVersion12,
		InsecureSkipVerify: true,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	assert.True(t, tlsConfig.InsecureSkipVerify)
}

func TestNewManager_WithClientValidation(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeMutual,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		ClientValidation: &ClientValidationConfig{
			Enabled:    true,
			CAFile:     certs.caFile,
			AllowedCNs: []string{"client.example.com"},
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.NotNil(t, manager.validator)
}

func TestManager_Start(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	provider := newMockProvider()
	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	provider.setCertificate(&cert)

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config, WithCertificateProvider(provider))
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Starting again should be a no-op
	err = manager.Start(ctx)
	require.NoError(t, err)

	assert.True(t, provider.started)
}

func TestManager_Close(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	err = manager.Close()
	require.NoError(t, err)

	// Closing again should be a no-op
	err = manager.Close()
	require.NoError(t, err)
}

func TestManager_GetConfig(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		MaxVersion: TLSVersion13,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	clonedConfig := manager.GetConfig()
	require.NotNil(t, clonedConfig)
	assert.Equal(t, TLSModeSimple, clonedConfig.Mode)
	assert.Equal(t, TLSVersion12, clonedConfig.MinVersion)
	assert.Equal(t, TLSVersion13, clonedConfig.MaxVersion)
}

func TestManager_GetMode_EmptyMode(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode: "", // Empty mode should default to SIMPLE
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.Equal(t, TLSModeSimple, manager.GetMode())
}

func TestManager_GetCertificateCallback(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()
	provider := newMockProvider()

	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	provider.setCertificate(&cert)

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config,
		WithCertificateProvider(provider),
		WithManagerMetrics(metrics),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	require.NotNil(t, tlsConfig.GetCertificate)

	// Test the callback
	hello := &tls.ClientHelloInfo{
		ServerName: "test.example.com",
	}

	resultCert, err := tlsConfig.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, resultCert)
}

func TestManager_GetCertificateCallback_Error(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()
	provider := newMockProvider()
	provider.setCertError(ErrCertificateNotFound)

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config,
		WithCertificateProvider(provider),
		WithManagerMetrics(metrics),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)

	hello := &tls.ClientHelloInfo{
		ServerName: "test.example.com",
	}

	resultCert, err := tlsConfig.GetCertificate(hello)
	assert.Error(t, err)
	assert.Nil(t, resultCert)
	assert.Equal(t, 1, metrics.handshakeErrorCount)
}

func TestManager_VerifyClientCertificate_NoCerts(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()

	config := &Config{
		Mode:       TLSModeMutual,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		ClientValidation: &ClientValidationConfig{
			Enabled: true,
			CAFile:  certs.caFile,
		},
	}

	manager, err := NewManager(config, WithManagerMetrics(metrics))
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Test with no certificates in MUTUAL mode
	err = manager.verifyClientCertificate(nil, nil)
	assert.ErrorIs(t, err, ErrClientCertRequired)
	assert.Equal(t, 1, metrics.clientCertInvalidCount)
	assert.Equal(t, "no_certificate", metrics.lastValidationReason)
}

func TestManager_VerifyClientCertificate_OptionalMutual_NoCerts(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeOptionalMutual,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		ClientValidation: &ClientValidationConfig{
			Enabled: true,
			CAFile:  certs.caFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Test with no certificates in OPTIONAL_MUTUAL mode - should succeed
	err = manager.verifyClientCertificate(nil, nil)
	assert.NoError(t, err)
}

func TestManager_VerifyClientCertificate_InvalidCert(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()

	config := &Config{
		Mode:       TLSModeMutual,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		ClientValidation: &ClientValidationConfig{
			Enabled: true,
			CAFile:  certs.caFile,
		},
	}

	manager, err := NewManager(config, WithManagerMetrics(metrics))
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Test with invalid certificate data
	invalidCert := []byte{0x00, 0x01, 0x02}
	err = manager.verifyClientCertificate([][]byte{invalidCert}, nil)
	assert.Error(t, err)
	assert.Equal(t, 1, metrics.clientCertInvalidCount)
	assert.Equal(t, "parse_error", metrics.lastValidationReason)
}

func TestManager_VerifyClientCertificate_ValidCert(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()

	config := &Config{
		Mode:       TLSModeMutual,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		ClientValidation: &ClientValidationConfig{
			Enabled: true,
			CAFile:  certs.caFile,
		},
	}

	manager, err := NewManager(config, WithManagerMetrics(metrics))
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Load the certificate
	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)

	err = manager.verifyClientCertificate(cert.Certificate, nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, metrics.clientCertValidCount)
}

func TestManager_VerifyClientCertificate_ValidationFailed(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()

	config := &Config{
		Mode:       TLSModeMutual,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		ClientValidation: &ClientValidationConfig{
			Enabled:    true,
			CAFile:     certs.caFile,
			AllowedCNs: []string{"different.example.com"}, // Won't match
		},
	}

	manager, err := NewManager(config, WithManagerMetrics(metrics))
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Load the certificate
	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)

	err = manager.verifyClientCertificate(cert.Certificate, nil)
	assert.Error(t, err)
	assert.Equal(t, 1, metrics.clientCertInvalidCount)
	assert.Equal(t, "validation_failed", metrics.lastValidationReason)
}

func TestManager_HandleCertificateEvent(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()
	provider := newMockProvider()

	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	provider.setCertificate(&cert)

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config,
		WithCertificateProvider(provider),
		WithManagerMetrics(metrics),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Test CertificateEventLoaded
	manager.handleCertificateEvent(CertificateEvent{
		Type:        CertificateEventLoaded,
		Certificate: &cert,
		Message:     "certificate loaded",
	})
	assert.Equal(t, 1, metrics.certReloadSuccessCount)

	// Test CertificateEventReloaded
	manager.handleCertificateEvent(CertificateEvent{
		Type:        CertificateEventReloaded,
		Certificate: &cert,
		Message:     "certificate reloaded",
	})
	assert.Equal(t, 2, metrics.certReloadSuccessCount)

	// Test CertificateEventExpiring
	manager.handleCertificateEvent(CertificateEvent{
		Type:    CertificateEventExpiring,
		Message: "certificate expiring",
	})
	// No metric change for expiring

	// Test CertificateEventError
	manager.handleCertificateEvent(CertificateEvent{
		Type:    CertificateEventError,
		Error:   assert.AnError,
		Message: "certificate error",
	})
	assert.Equal(t, 1, metrics.certReloadFailureCount)
}

func TestManager_RebuildTLSConfig(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	provider := newMockProvider()

	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	provider.setCertificate(&cert)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(certs.caPEM)
	provider.setClientCA(caPool)

	config := &Config{
		Mode:       TLSModeMutual,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		ClientValidation: &ClientValidationConfig{
			Enabled: true,
			CAFile:  certs.caFile,
		},
	}

	manager, err := NewManager(config, WithCertificateProvider(provider))
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	err = manager.rebuildTLSConfig()
	require.NoError(t, err)
}

func TestManager_RecordConnection(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config, WithManagerMetrics(metrics))
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Test with nil state
	manager.RecordConnection(nil)
	assert.Equal(t, 0, metrics.connectionCount)

	// Test with valid state
	state := &tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
	manager.RecordConnection(state)
	assert.Equal(t, 1, metrics.connectionCount)
}

func TestManager_RecordHandshake(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config, WithManagerMetrics(metrics))
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Test with nil state
	manager.RecordHandshake(100*time.Millisecond, nil)
	assert.Equal(t, 0, metrics.handshakeDurationCount)

	// Test with valid state
	state := &tls.ConnectionState{
		Version: tls.VersionTLS12,
	}
	manager.RecordHandshake(100*time.Millisecond, state)
	assert.Equal(t, 1, metrics.handshakeDurationCount)
}

func TestManager_CreateClientTLSConfig(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		MaxVersion: TLSVersion13,
		ALPN:       []string{"h2", "http/1.1"},
		CipherSuites: []string{
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		},
		CurvePreferences: []string{"X25519", "P256"},
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	clientConfig := manager.CreateClientTLSConfig("example.com")
	require.NotNil(t, clientConfig)
	assert.Equal(t, "example.com", clientConfig.ServerName)
	assert.Equal(t, uint16(tls.VersionTLS12), clientConfig.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), clientConfig.MaxVersion)
	assert.Equal(t, []string{"h2", "http/1.1"}, clientConfig.NextProtos)
}

func TestManager_CreateClientTLSConfig_Disabled(t *testing.T) {
	t.Parallel()

	config := &Config{
		Mode: TLSModeInsecure,
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	clientConfig := manager.CreateClientTLSConfig("example.com")
	assert.Nil(t, clientConfig)
}

func TestManager_CreateClientTLSConfig_InsecureSkipVerify(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:               TLSModeSimple,
		MinVersion:         TLSVersion12,
		InsecureSkipVerify: true,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	clientConfig := manager.CreateClientTLSConfig("example.com")
	require.NotNil(t, clientConfig)
	assert.True(t, clientConfig.InsecureSkipVerify)
}

func TestManager_WatchCertificateEvents(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()
	provider := newMockProvider()

	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	provider.setCertificate(&cert)

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config,
		WithCertificateProvider(provider),
		WithManagerMetrics(metrics),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)

	ctx, cancel := context.WithCancel(context.Background())

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Send an event
	provider.sendEvent(CertificateEvent{
		Type:        CertificateEventLoaded,
		Certificate: &cert,
		Message:     "test event",
	})

	// Give time for the event to be processed
	time.Sleep(50 * time.Millisecond)

	cancel()
	manager.Close()

	assert.GreaterOrEqual(t, metrics.getCertReloadSuccessCount(), 1)
}

func TestManager_CheckCertificateExpiry(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()
	provider := newMockProvider()

	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	provider.setCertificate(&cert)

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config,
		WithCertificateProvider(provider),
		WithManagerMetrics(metrics),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Call checkCertificateExpiry
	manager.checkCertificateExpiry()

	assert.Equal(t, 1, metrics.certExpiryCount)
}

func TestManager_CheckCertificateExpiry_NoCert(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()
	provider := newMockProvider()
	// Don't set a certificate

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config,
		WithCertificateProvider(provider),
		WithManagerMetrics(metrics),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Call checkCertificateExpiry - should not panic
	manager.checkCertificateExpiry()

	assert.Equal(t, 0, metrics.certExpiryCount)
}

func TestManager_CheckCertificateExpiry_Error(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()
	provider := newMockProvider()
	provider.setCertError(ErrCertificateNotFound)

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config,
		WithCertificateProvider(provider),
		WithManagerMetrics(metrics),
	)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Call checkCertificateExpiry - should not panic
	manager.checkCertificateExpiry()

	assert.Equal(t, 0, metrics.certExpiryCount)
}

func TestManager_InvalidCipherSuites(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:         TLSModeSimple,
		MinVersion:   TLSVersion12,
		CipherSuites: []string{"INVALID_CIPHER"},
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "invalid cipher suite")
}

func TestManager_InvalidCurvePreferences(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:             TLSModeSimple,
		MinVersion:       TLSVersion12,
		CurvePreferences: []string{"INVALID_CURVE"},
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "invalid curve")
}

func TestManager_MutualModeWithoutClientCA(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	provider := newMockProvider()
	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	provider.setCertificate(&cert)
	// Don't set client CA - should fail

	config := &Config{
		Mode:       TLSModeMutual,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		ClientValidation: &ClientValidationConfig{
			Enabled: true,
			CAFile:  certs.caFile,
		},
	}

	manager, err := NewManager(config, WithCertificateProvider(provider))
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "client CA required")
}

func TestManager_Concurrency(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = manager.GetTLSConfig()
			_ = manager.GetMode()
			_ = manager.IsEnabled()
			_ = manager.IsMTLSEnabled()
			_ = manager.GetConfig()
		}()
	}
	wg.Wait()
}

func TestWithManagerLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	opt := WithManagerLogger(logger)

	m := &Manager{}
	opt(m)

	assert.NotNil(t, m.logger)
}

func TestWithManagerMetrics(t *testing.T) {
	t.Parallel()

	metrics := newMockMetrics()
	opt := WithManagerMetrics(metrics)

	m := &Manager{}
	opt(m)

	assert.NotNil(t, m.metrics)
}

func TestWithCertificateProvider(t *testing.T) {
	t.Parallel()

	provider := newMockProvider()
	opt := WithCertificateProvider(provider)

	m := &Manager{}
	opt(m)

	assert.NotNil(t, m.provider)
}

func TestWithVaultProviderFactory(t *testing.T) {
	t.Parallel()

	factory := func(_ *VaultTLSConfig, _ observability.Logger) (CertificateProvider, error) {
		return newMockProvider(), nil
	}
	opt := WithVaultProviderFactory(factory)

	m := &Manager{}
	opt(m)

	assert.NotNil(t, m.vaultProviderFactory)
}

func TestNewManager_WithVaultProviderFactory(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	factoryCalled := false
	mockProv := newMockProvider()
	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	mockProv.setCertificate(&cert)

	factory := func(_ *VaultTLSConfig, _ observability.Logger) (CertificateProvider, error) {
		factoryCalled = true
		return mockProv, nil
	}

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			Source:   CertificateSourceVault,
			CertFile: "unused",
			KeyFile:  "unused",
		},
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "role",
			CommonName: "test.example.com",
		},
	}

	manager, err := NewManager(config, WithVaultProviderFactory(factory))
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.True(t, factoryCalled, "vault provider factory should have been called")
}

func TestNewManager_VaultEnabled_NoFactory(t *testing.T) {
	t.Parallel()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
		},
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "example.com",
		},
	}

	manager, err := NewManager(config)
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "vault provider factory is required")
}

func TestNewManager_VaultEnabled_FactoryError(t *testing.T) {
	t.Parallel()

	factoryErr := fmt.Errorf("vault connection failed")
	factory := func(_ *VaultTLSConfig, _ observability.Logger) (CertificateProvider, error) {
		return nil, factoryErr
	}

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
		},
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "example.com",
		},
	}

	manager, err := NewManager(config, WithVaultProviderFactory(factory))
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "failed to create vault provider")
	assert.ErrorIs(t, err, factoryErr)
}

func TestNewManager_VaultDisabled_FileProvider(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		// No Vault config
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.True(t, manager.IsEnabled())
	assert.NotNil(t, manager.GetTLSConfig())
}

func TestNewManager_WithVaultProviderFactory_NilFactory(t *testing.T) {
	t.Parallel()

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
		},
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "example.com",
		},
	}

	manager, err := NewManager(config, WithVaultProviderFactory(nil))
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "vault provider factory is required")
}

func TestNewManager_VaultEnabled_PassthroughMode(t *testing.T) {
	t.Parallel()

	// Passthrough mode should use NopProvider even with Vault enabled
	config := &Config{
		Mode: TLSModePassthrough,
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "example.com",
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	assert.Equal(t, TLSModePassthrough, manager.GetMode())
}

func TestNewManager_HandleCertificateEvent_LoadedWithCert(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	metrics := newMockMetrics()
	provider := newMockProvider()

	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	provider.setCertificate(&cert)

	config := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	manager, err := NewManager(config,
		WithCertificateProvider(provider),
		WithManagerMetrics(metrics),
	)
	require.NoError(t, err)
	defer manager.Close()

	// Test CertificateEventLoaded with certificate - should update expiry
	manager.handleCertificateEvent(CertificateEvent{
		Type:        CertificateEventLoaded,
		Certificate: &cert,
		Message:     "certificate loaded",
	})
	assert.Equal(t, 1, metrics.getCertReloadSuccessCount())
	assert.Equal(t, 1, metrics.getCertExpiryCount())

	// Test CertificateEventLoaded with nil certificate - should not update expiry
	manager.handleCertificateEvent(CertificateEvent{
		Type:    CertificateEventLoaded,
		Message: "certificate loaded without cert",
	})
	assert.Equal(t, 2, metrics.getCertReloadSuccessCount())
	assert.Equal(t, 1, metrics.getCertExpiryCount()) // unchanged

	// Test CertificateEventReloaded with certificate - should update expiry
	manager.handleCertificateEvent(CertificateEvent{
		Type:        CertificateEventReloaded,
		Certificate: &cert,
		Message:     "certificate reloaded",
	})
	assert.Equal(t, 3, metrics.getCertReloadSuccessCount())
	assert.Equal(t, 2, metrics.getCertExpiryCount())

	// Test CertificateEventReloaded with nil certificate - should not update expiry
	manager.handleCertificateEvent(CertificateEvent{
		Type:    CertificateEventReloaded,
		Message: "certificate reloaded without cert",
	})
	assert.Equal(t, 4, metrics.getCertReloadSuccessCount())
	assert.Equal(t, 2, metrics.getCertExpiryCount()) // unchanged
}
