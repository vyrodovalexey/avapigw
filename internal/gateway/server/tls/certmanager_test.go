// Package tls provides the TLS server implementation for the API Gateway.
package tls

import (
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// generateTestCertificate generates a self-signed certificate for testing.
func generateTestCertificate(hostname string) (certPEM, keyPEM []byte, err error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// generateTestCA generates a CA certificate for testing.
func generateTestCA() (caPEM []byte, err error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create CA certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	// Encode certificate to PEM
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return caPEM, nil
}

// writeTempCertFiles writes certificate and key to temporary files.
func writeTempCertFiles(t *testing.T, certPEM, keyPEM []byte) (certFile, keyFile string) {
	t.Helper()

	tempDir := t.TempDir()

	certFile = filepath.Join(tempDir, "cert.pem")
	keyFile = filepath.Join(tempDir, "key.pem")

	err := os.WriteFile(certFile, certPEM, 0600)
	require.NoError(t, err)

	err = os.WriteFile(keyFile, keyPEM, 0600)
	require.NoError(t, err)

	return certFile, keyFile
}

func TestNewCertificateManager(t *testing.T) {
	tests := []struct {
		name   string
		logger *zap.Logger
	}{
		{
			name:   "with logger",
			logger: zap.NewNop(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCertificateManager(tt.logger)

			require.NotNil(t, cm)
			assert.NotNil(t, cm.certificates)
			assert.NotNil(t, cm.watchedFiles)
			assert.NotNil(t, cm.stopCh)
			assert.Nil(t, cm.defaultCert)
			assert.Equal(t, tt.logger, cm.logger)
		})
	}
}

func TestCertificateManager_LoadCertificate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		hostname      string
		setupCert     bool
		expectError   bool
		errorContains string
	}{
		{
			name:        "load valid certificate",
			hostname:    "example.com",
			setupCert:   true,
			expectError: false,
		},
		{
			name:          "load non-existent certificate",
			hostname:      "example.com",
			setupCert:     false,
			expectError:   true,
			errorContains: "failed to load certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCertificateManager(logger)

			var certFile, keyFile string
			if tt.setupCert {
				certPEM, keyPEM, err := generateTestCertificate(tt.hostname)
				require.NoError(t, err)
				certFile, keyFile = writeTempCertFiles(t, certPEM, keyPEM)
			} else {
				certFile = "/non/existent/cert.pem"
				keyFile = "/non/existent/key.pem"
			}

			err := cm.LoadCertificate(tt.hostname, certFile, keyFile)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				// Verify certificate was loaded
				certs := cm.ListCertificates()
				assert.Contains(t, certs, tt.hostname)
			}
		})
	}
}

func TestCertificateManager_LoadCertificateFromSecret(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		hostname      string
		validCert     bool
		expectError   bool
		errorContains string
	}{
		{
			name:        "load valid certificate from secret",
			hostname:    "example.com",
			validCert:   true,
			expectError: false,
		},
		{
			name:          "load invalid certificate from secret",
			hostname:      "example.com",
			validCert:     false,
			expectError:   true,
			errorContains: "failed to parse certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCertificateManager(logger)

			var certData, keyData []byte
			if tt.validCert {
				var err error
				certData, keyData, err = generateTestCertificate(tt.hostname)
				require.NoError(t, err)
			} else {
				certData = []byte("invalid cert")
				keyData = []byte("invalid key")
			}

			err := cm.LoadCertificateFromSecret(tt.hostname, certData, keyData)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				// Verify certificate was loaded
				certs := cm.ListCertificates()
				assert.Contains(t, certs, tt.hostname)
			}
		})
	}
}

func TestCertificateManager_GetCertificate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		setupCerts    map[string]bool // hostname -> isWildcard
		defaultCert   bool
		serverName    string
		expectError   bool
		errorContains string
	}{
		{
			name: "exact match",
			setupCerts: map[string]bool{
				"example.com": false,
			},
			serverName:  "example.com",
			expectError: false,
		},
		{
			name: "wildcard match",
			setupCerts: map[string]bool{
				"*.example.com": true,
			},
			serverName:  "api.example.com",
			expectError: false,
		},
		{
			name: "default certificate",
			setupCerts: map[string]bool{
				"other.com": false,
			},
			defaultCert: true,
			serverName:  "unknown.com",
			expectError: false,
		},
		{
			name:          "no certificate found",
			setupCerts:    map[string]bool{},
			defaultCert:   false,
			serverName:    "unknown.com",
			expectError:   true,
			errorContains: "no certificate found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCertificateManager(logger)

			// Setup certificates
			for hostname := range tt.setupCerts {
				certPEM, keyPEM, err := generateTestCertificate(hostname)
				require.NoError(t, err)
				err = cm.LoadCertificateFromSecret(hostname, certPEM, keyPEM)
				require.NoError(t, err)
			}

			// Setup default certificate
			if tt.defaultCert {
				certPEM, keyPEM, err := generateTestCertificate("default.com")
				require.NoError(t, err)
				cert, err := tls.X509KeyPair(certPEM, keyPEM)
				require.NoError(t, err)
				cm.SetDefaultCertificate(&cert)
			}

			// Create ClientHelloInfo
			hello := &tls.ClientHelloInfo{
				ServerName: tt.serverName,
			}

			// Get certificate
			cert, err := cm.GetCertificate(hello)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, cert)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cert)
			}
		})
	}
}

func TestCertificateManager_SetDefaultCertificate(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Generate test certificate
	certPEM, keyPEM, err := generateTestCertificate("default.com")
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	// Set default certificate
	cm.SetDefaultCertificate(&cert)

	// Verify default certificate is set
	hello := &tls.ClientHelloInfo{
		ServerName: "unknown.com",
	}

	gotCert, err := cm.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, gotCert)
}

func TestCertificateManager_SetDefaultCertificateFromFiles(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		setupCert     bool
		expectError   bool
		errorContains string
	}{
		{
			name:        "load valid default certificate",
			setupCert:   true,
			expectError: false,
		},
		{
			name:          "load non-existent default certificate",
			setupCert:     false,
			expectError:   true,
			errorContains: "failed to load default certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCertificateManager(logger)

			var certFile, keyFile string
			if tt.setupCert {
				certPEM, keyPEM, err := generateTestCertificate("default.com")
				require.NoError(t, err)
				certFile, keyFile = writeTempCertFiles(t, certPEM, keyPEM)
			} else {
				certFile = "/non/existent/cert.pem"
				keyFile = "/non/existent/key.pem"
			}

			err := cm.SetDefaultCertificateFromFiles(certFile, keyFile)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				// Verify default certificate is set
				hello := &tls.ClientHelloInfo{
					ServerName: "unknown.com",
				}
				cert, err := cm.GetCertificate(hello)
				require.NoError(t, err)
				require.NotNil(t, cert)
			}
		})
	}
}

func TestCertificateManager_RemoveCertificate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name       string
		setupCerts []string
		removeCert string
	}{
		{
			name:       "remove existing certificate",
			setupCerts: []string{"example.com"},
			removeCert: "example.com",
		},
		{
			name:       "remove non-existent certificate",
			setupCerts: []string{},
			removeCert: "non-existent.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCertificateManager(logger)

			// Setup certificates
			for _, hostname := range tt.setupCerts {
				certPEM, keyPEM, err := generateTestCertificate(hostname)
				require.NoError(t, err)
				err = cm.LoadCertificateFromSecret(hostname, certPEM, keyPEM)
				require.NoError(t, err)
			}

			// Remove certificate
			cm.RemoveCertificate(tt.removeCert)

			// Verify certificate was removed
			certs := cm.ListCertificates()
			assert.NotContains(t, certs, tt.removeCert)
		})
	}
}

func TestCertificateManager_ListCertificates(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		setupCerts    []string
		expectedCount int
	}{
		{
			name:          "empty manager",
			setupCerts:    []string{},
			expectedCount: 0,
		},
		{
			name:          "single certificate",
			setupCerts:    []string{"example.com"},
			expectedCount: 1,
		},
		{
			name:          "multiple certificates",
			setupCerts:    []string{"example.com", "example.org", "example.net"},
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCertificateManager(logger)

			// Setup certificates
			for _, hostname := range tt.setupCerts {
				certPEM, keyPEM, err := generateTestCertificate(hostname)
				require.NoError(t, err)
				err = cm.LoadCertificateFromSecret(hostname, certPEM, keyPEM)
				require.NoError(t, err)
			}

			// List certificates
			certs := cm.ListCertificates()

			assert.Len(t, certs, tt.expectedCount)
		})
	}
}

func TestCertificateManager_TLSConfig(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Get TLS config
	config := cm.TLSConfig()

	require.NotNil(t, config)
	assert.NotNil(t, config.GetCertificate)
	assert.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
	assert.NotEmpty(t, config.CipherSuites)
	assert.NotEmpty(t, config.CurvePreferences)
}

func TestCertificateManager_TLSConfigWithClientAuth(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Generate CA certificate
	caPEM, err := generateTestCA()
	require.NoError(t, err)

	// Create CA pool
	caPool := x509.NewCertPool()
	ok := caPool.AppendCertsFromPEM(caPEM)
	require.True(t, ok)

	tests := []struct {
		name     string
		authType tls.ClientAuthType
	}{
		{
			name:     "require and verify client cert",
			authType: tls.RequireAndVerifyClientCert,
		},
		{
			name:     "verify client cert if given",
			authType: tls.VerifyClientCertIfGiven,
		},
		{
			name:     "request client cert",
			authType: tls.RequestClientCert,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := cm.TLSConfigWithClientAuth(caPool, tt.authType)

			require.NotNil(t, config)
			assert.Equal(t, caPool, config.ClientCAs)
			assert.Equal(t, tt.authType, config.ClientAuth)
		})
	}
}

func TestLoadClientCAs(t *testing.T) {
	tests := []struct {
		name          string
		setupCA       bool
		invalidCA     bool
		expectError   bool
		errorContains string
	}{
		{
			name:        "load valid CA",
			setupCA:     true,
			expectError: false,
		},
		{
			name:          "load non-existent CA",
			setupCA:       false,
			expectError:   true,
			errorContains: "failed to read CA file",
		},
		{
			name:          "load invalid CA",
			setupCA:       true,
			invalidCA:     true,
			expectError:   true,
			errorContains: "failed to parse CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var caFile string
			if tt.setupCA {
				tempDir := t.TempDir()
				caFile = filepath.Join(tempDir, "ca.pem")

				var caData []byte
				if tt.invalidCA {
					caData = []byte("invalid CA data")
				} else {
					var err error
					caData, err = generateTestCA()
					require.NoError(t, err)
				}

				err := os.WriteFile(caFile, caData, 0600)
				require.NoError(t, err)
			} else {
				caFile = "/non/existent/ca.pem"
			}

			caPool, err := LoadClientCAs(caFile)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, caPool)
			} else {
				require.NoError(t, err)
				require.NotNil(t, caPool)
			}
		})
	}
}

func TestSplitHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		expected []string
	}{
		{
			name:     "simple hostname",
			hostname: "example.com",
			expected: []string{"example", "com"},
		},
		{
			name:     "subdomain",
			hostname: "api.example.com",
			expected: []string{"api", "example", "com"},
		},
		{
			name:     "deep subdomain",
			hostname: "a.b.c.example.com",
			expected: []string{"a", "b", "c", "example", "com"},
		},
		{
			name:     "single part",
			hostname: "localhost",
			expected: []string{"localhost"},
		},
		{
			name:     "empty hostname",
			hostname: "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := splitHostname(tt.hostname)
			assert.Equal(t, tt.expected, parts)
		})
	}
}

func TestJoinHostname(t *testing.T) {
	tests := []struct {
		name     string
		parts    []string
		expected string
	}{
		{
			name:     "simple hostname",
			parts:    []string{"example", "com"},
			expected: "example.com",
		},
		{
			name:     "subdomain",
			parts:    []string{"api", "example", "com"},
			expected: "api.example.com",
		},
		{
			name:     "single part",
			parts:    []string{"localhost"},
			expected: "localhost",
		},
		{
			name:     "empty parts",
			parts:    []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := joinHostname(tt.parts)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCertificateManager_Close(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Close should not panic
	err := cm.Close()
	assert.NoError(t, err)
}

func TestCertificateManager_WildcardCertLookup(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Load wildcard certificate
	certPEM, keyPEM, err := generateTestCertificate("*.example.com")
	require.NoError(t, err)
	err = cm.LoadCertificateFromSecret("*.example.com", certPEM, keyPEM)
	require.NoError(t, err)

	// Test wildcard lookup
	hello := &tls.ClientHelloInfo{
		ServerName: "api.example.com",
	}

	cert, err := cm.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestCertificateManager_WatchCertificates(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Generate and write test certificate
	certPEM, keyPEM, err := generateTestCertificate("example.com")
	require.NoError(t, err)
	certFile, keyFile := writeTempCertFiles(t, certPEM, keyPEM)

	// Load certificate
	err = cm.LoadCertificate("example.com", certFile, keyFile)
	require.NoError(t, err)

	// Start watching
	stopCh := make(chan struct{})
	err = cm.WatchCertificates(stopCh)
	require.NoError(t, err)

	// Wait a bit for watcher to start
	time.Sleep(100 * time.Millisecond)

	// Stop watching
	close(stopCh)

	// Wait for watcher to stop
	time.Sleep(100 * time.Millisecond)
}

func TestCertificateManager_HandleFileChange(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Generate and write test certificate
	certPEM, keyPEM, err := generateTestCertificate("example.com")
	require.NoError(t, err)
	certFile, keyFile := writeTempCertFiles(t, certPEM, keyPEM)

	// Load certificate
	err = cm.LoadCertificate("example.com", certFile, keyFile)
	require.NoError(t, err)

	// Trigger file change handler
	cm.handleFileChange(certFile)

	// Verify certificate is still loaded
	certs := cm.ListCertificates()
	assert.Contains(t, certs, "example.com")
}

func TestCertificateManager_HandleFileChange_NonWatchedFile(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Trigger file change handler for non-watched file
	cm.handleFileChange("/non/existent/file.pem")

	// Should not panic or error
}

func TestCertificateManager_FindWildcardCert_ShortHostname(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Load wildcard certificate
	certPEM, keyPEM, err := generateTestCertificate("*.example.com")
	require.NoError(t, err)
	err = cm.LoadCertificateFromSecret("*.example.com", certPEM, keyPEM)
	require.NoError(t, err)

	// Test with single-part hostname (should not match wildcard)
	hello := &tls.ClientHelloInfo{
		ServerName: "localhost",
	}

	cert, err := cm.GetCertificate(hello)
	require.Error(t, err)
	assert.Nil(t, cert)
}

func TestCertificateManager_CloseWithWatcher(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Generate and write test certificate
	certPEM, keyPEM, err := generateTestCertificate("example.com")
	require.NoError(t, err)
	certFile, keyFile := writeTempCertFiles(t, certPEM, keyPEM)

	// Load certificate
	err = cm.LoadCertificate("example.com", certFile, keyFile)
	require.NoError(t, err)

	// Start watching
	stopCh := make(chan struct{})
	err = cm.WatchCertificates(stopCh)
	require.NoError(t, err)

	// Wait a bit for watcher to start
	time.Sleep(100 * time.Millisecond)

	// Close should stop the watcher
	err = cm.Close()
	assert.NoError(t, err)
}

func TestCertificateManager_WatchCertificates_DifferentDirectories(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Create two different temp directories
	tempDir1 := t.TempDir()
	tempDir2 := t.TempDir()

	// Generate and write test certificate to different directories
	certPEM, keyPEM, err := generateTestCertificate("example.com")
	require.NoError(t, err)

	certFile := filepath.Join(tempDir1, "cert.pem")
	keyFile := filepath.Join(tempDir2, "key.pem")

	err = os.WriteFile(certFile, certPEM, 0600)
	require.NoError(t, err)

	err = os.WriteFile(keyFile, keyPEM, 0600)
	require.NoError(t, err)

	// Load certificate
	err = cm.LoadCertificate("example.com", certFile, keyFile)
	require.NoError(t, err)

	// Start watching
	stopCh := make(chan struct{})
	err = cm.WatchCertificates(stopCh)
	require.NoError(t, err)

	// Wait a bit for watcher to start
	time.Sleep(100 * time.Millisecond)

	// Stop watching
	close(stopCh)

	// Wait for watcher to stop
	time.Sleep(100 * time.Millisecond)
}

func TestCertificateManager_HandleFileChange_ReloadError(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Generate and write test certificate
	certPEM, keyPEM, err := generateTestCertificate("example.com")
	require.NoError(t, err)
	certFile, keyFile := writeTempCertFiles(t, certPEM, keyPEM)

	// Load certificate
	err = cm.LoadCertificate("example.com", certFile, keyFile)
	require.NoError(t, err)

	// Corrupt the certificate file
	err = os.WriteFile(certFile, []byte("invalid cert"), 0600)
	require.NoError(t, err)

	// Trigger file change handler - should log error but not panic
	cm.handleFileChange(certFile)

	// Certificate should still be in the list (old one)
	certs := cm.ListCertificates()
	assert.Contains(t, certs, "example.com")
}

func TestCertificateManager_WatchLoop_WatcherClosed(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Generate and write test certificate
	certPEM, keyPEM, err := generateTestCertificate("example.com")
	require.NoError(t, err)
	certFile, keyFile := writeTempCertFiles(t, certPEM, keyPEM)

	// Load certificate
	err = cm.LoadCertificate("example.com", certFile, keyFile)
	require.NoError(t, err)

	// Start watching
	stopCh := make(chan struct{})
	err = cm.WatchCertificates(stopCh)
	require.NoError(t, err)

	// Wait a bit for watcher to start
	time.Sleep(100 * time.Millisecond)

	// Close the watcher directly (simulating watcher error)
	cm.mu.Lock()
	if cm.watcher != nil {
		_ = cm.watcher.Close()
	}
	cm.mu.Unlock()

	// Wait for watchLoop to exit
	time.Sleep(100 * time.Millisecond)

	// Stop channel should still work
	close(stopCh)
}

func TestCertificateManager_WatchCertificates_FileChange(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Generate and write test certificate
	certPEM, keyPEM, err := generateTestCertificate("example.com")
	require.NoError(t, err)
	certFile, keyFile := writeTempCertFiles(t, certPEM, keyPEM)

	// Load certificate
	err = cm.LoadCertificate("example.com", certFile, keyFile)
	require.NoError(t, err)

	// Start watching
	stopCh := make(chan struct{})
	err = cm.WatchCertificates(stopCh)
	require.NoError(t, err)

	// Wait a bit for watcher to start
	time.Sleep(200 * time.Millisecond)

	// Modify the certificate file (write same content to trigger event)
	err = os.WriteFile(certFile, certPEM, 0600)
	require.NoError(t, err)

	// Wait for file change to be processed
	time.Sleep(200 * time.Millisecond)

	// Stop watching
	close(stopCh)

	// Wait for watcher to stop
	time.Sleep(100 * time.Millisecond)

	// Certificate should still be loaded
	certs := cm.ListCertificates()
	assert.Contains(t, certs, "example.com")
}

func TestCertificateManager_FindWildcardCert_NoMatch(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Load wildcard certificate for different domain
	certPEM, keyPEM, err := generateTestCertificate("*.other.com")
	require.NoError(t, err)
	err = cm.LoadCertificateFromSecret("*.other.com", certPEM, keyPEM)
	require.NoError(t, err)

	// Test with hostname that doesn't match
	hello := &tls.ClientHelloInfo{
		ServerName: "api.example.com",
	}

	cert, err := cm.GetCertificate(hello)
	require.Error(t, err)
	assert.Nil(t, cert)
}

func TestCertificateManager_GetCertificate_EmptyServerName(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Load a certificate
	certPEM, keyPEM, err := generateTestCertificate("example.com")
	require.NoError(t, err)
	err = cm.LoadCertificateFromSecret("example.com", certPEM, keyPEM)
	require.NoError(t, err)

	// Test with empty server name
	hello := &tls.ClientHelloInfo{
		ServerName: "",
	}

	cert, err := cm.GetCertificate(hello)
	require.Error(t, err)
	assert.Nil(t, cert)
}

func TestCertificateManager_GetCertificate_EmptyServerNameWithDefault(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Set default certificate
	certPEM, keyPEM, err := generateTestCertificate("default.com")
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	cm.SetDefaultCertificate(&cert)

	// Test with empty server name - should return default
	hello := &tls.ClientHelloInfo{
		ServerName: "",
	}

	gotCert, err := cm.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, gotCert)
}

func TestCertificateManager_MultipleCertificates(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Load multiple certificates
	hostnames := []string{"example.com", "example.org", "example.net", "*.wildcard.com"}
	for _, hostname := range hostnames {
		certPEM, keyPEM, err := generateTestCertificate(hostname)
		require.NoError(t, err)
		err = cm.LoadCertificateFromSecret(hostname, certPEM, keyPEM)
		require.NoError(t, err)
	}

	// Verify all certificates are loaded
	certs := cm.ListCertificates()
	assert.Len(t, certs, len(hostnames))

	// Test each hostname
	for _, hostname := range hostnames {
		testHostname := hostname
		if hostname == "*.wildcard.com" {
			testHostname = "api.wildcard.com"
		}
		hello := &tls.ClientHelloInfo{
			ServerName: testHostname,
		}
		cert, err := cm.GetCertificate(hello)
		require.NoError(t, err, "Failed for hostname: %s", testHostname)
		require.NotNil(t, cert)
	}
}

func TestCertificateManager_RemoveCertificate_WithWatchedFiles(t *testing.T) {
	logger := zap.NewNop()
	cm := NewCertificateManager(logger)

	// Generate and write test certificate
	certPEM, keyPEM, err := generateTestCertificate("example.com")
	require.NoError(t, err)
	certFile, keyFile := writeTempCertFiles(t, certPEM, keyPEM)

	// Load certificate (this adds to watchedFiles)
	err = cm.LoadCertificate("example.com", certFile, keyFile)
	require.NoError(t, err)

	// Verify it's in watchedFiles
	cm.mu.RLock()
	_, exists := cm.watchedFiles["example.com"]
	cm.mu.RUnlock()
	assert.True(t, exists)

	// Remove certificate
	cm.RemoveCertificate("example.com")

	// Verify it's removed from watchedFiles
	cm.mu.RLock()
	_, exists = cm.watchedFiles["example.com"]
	cm.mu.RUnlock()
	assert.False(t, exists)
}
