package listener

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TLSTestCertificates holds test certificate and key data for TLS tests
type TLSTestCertificates struct {
	CertFile string
	KeyFile  string
	CAFile   string
	CertPEM  []byte
	KeyPEM   []byte
	CAPEM    []byte
}

// generateTLSTestCertificates creates temporary test certificates for TLS tests
func generateTLSTestCertificates(t *testing.T) *TLSTestCertificates {
	t.Helper()

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Create temporary files
	certFile, err := os.CreateTemp("", "tls-cert-*.pem")
	require.NoError(t, err)
	_, err = certFile.Write(certPEM)
	require.NoError(t, err)
	certFile.Close()

	keyFile, err := os.CreateTemp("", "tls-key-*.pem")
	require.NoError(t, err)
	_, err = keyFile.Write(keyPEM)
	require.NoError(t, err)
	keyFile.Close()

	caFile, err := os.CreateTemp("", "tls-ca-*.pem")
	require.NoError(t, err)
	_, err = caFile.Write(certPEM) // Use same cert as CA for testing
	require.NoError(t, err)
	caFile.Close()

	t.Cleanup(func() {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
		os.Remove(caFile.Name())
	})

	return &TLSTestCertificates{
		CertFile: certFile.Name(),
		KeyFile:  keyFile.Name(),
		CAFile:   caFile.Name(),
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		CAPEM:    certPEM,
	}
}

// createInvalidCertFile creates a file with invalid certificate content
func createInvalidCertFile(t *testing.T) string {
	t.Helper()

	file, err := os.CreateTemp("", "invalid-cert-*.pem")
	require.NoError(t, err)
	_, err = file.Write([]byte("invalid certificate content"))
	require.NoError(t, err)
	file.Close()

	t.Cleanup(func() {
		os.Remove(file.Name())
	})

	return file.Name()
}

// TestNewCertificateManager tests creating a new certificate manager
func TestNewCertificateManager(t *testing.T) {
	certs := generateTLSTestCertificates(t)

	tests := []struct {
		name        string
		certFile    string
		keyFile     string
		caFile      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "create with valid cert and key",
			certFile:    certs.CertFile,
			keyFile:     certs.KeyFile,
			caFile:      "",
			expectError: false,
		},
		{
			name:        "create with valid cert, key, and CA",
			certFile:    certs.CertFile,
			keyFile:     certs.KeyFile,
			caFile:      certs.CAFile,
			expectError: false,
		},
		{
			name:        "create with empty files (no cert loading)",
			certFile:    "",
			keyFile:     "",
			caFile:      "",
			expectError: false,
		},
		{
			name:        "create with nonexistent cert file fails",
			certFile:    "/nonexistent/cert.pem",
			keyFile:     "/nonexistent/key.pem",
			caFile:      "",
			expectError: true,
			errorMsg:    "failed to load certificate",
		},
		{
			name:        "create with nonexistent CA file fails",
			certFile:    certs.CertFile,
			keyFile:     certs.KeyFile,
			caFile:      "/nonexistent/ca.pem",
			expectError: true,
			errorMsg:    "failed to read CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)

			cm, err := NewCertificateManager(tt.certFile, tt.keyFile, tt.caFile, logger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, cm)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cm)
			}
		})
	}
}

// TestNewCertificateManager_InvalidCA tests creating manager with invalid CA
func TestNewCertificateManager_InvalidCA(t *testing.T) {
	certs := generateTLSTestCertificates(t)
	invalidCAFile := createInvalidCertFile(t)
	logger := zaptest.NewLogger(t)

	cm, err := NewCertificateManager(certs.CertFile, certs.KeyFile, invalidCAFile, logger)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
	assert.Nil(t, cm)
}

// TestCertificateManager_Reload tests reloading certificates
func TestCertificateManager_Reload(t *testing.T) {
	certs := generateTLSTestCertificates(t)
	logger := zaptest.NewLogger(t)

	cm, err := NewCertificateManager(certs.CertFile, certs.KeyFile, certs.CAFile, logger)
	require.NoError(t, err)

	// Reload should succeed
	err = cm.Reload()
	assert.NoError(t, err)
}

// TestCertificateManager_Reload_AfterFileChange tests reloading after file change
func TestCertificateManager_Reload_AfterFileChange(t *testing.T) {
	certs := generateTLSTestCertificates(t)
	logger := zaptest.NewLogger(t)

	cm, err := NewCertificateManager(certs.CertFile, certs.KeyFile, "", logger)
	require.NoError(t, err)

	// Get initial certificate
	cert1, err := cm.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert1)

	// Generate new certificate and overwrite file
	newCerts := generateTLSTestCertificates(t)
	err = os.WriteFile(certs.CertFile, newCerts.CertPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(certs.KeyFile, newCerts.KeyPEM, 0644)
	require.NoError(t, err)

	// Reload
	err = cm.Reload()
	assert.NoError(t, err)

	// Get new certificate
	cert2, err := cm.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert2)
}

// TestCertificateManager_GetCertificate tests getting certificates
func TestCertificateManager_GetCertificate(t *testing.T) {
	tests := []struct {
		name        string
		hasCert     bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "get certificate success",
			hasCert:     true,
			expectError: false,
		},
		{
			name:        "get certificate when no cert loaded",
			hasCert:     false,
			expectError: true,
			errorMsg:    "no certificate loaded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)

			var cm *CertificateManager
			var err error

			if tt.hasCert {
				certs := generateTLSTestCertificates(t)
				cm, err = NewCertificateManager(certs.CertFile, certs.KeyFile, "", logger)
				require.NoError(t, err)
			} else {
				cm, err = NewCertificateManager("", "", "", logger)
				require.NoError(t, err)
			}

			cert, err := cm.GetCertificate(nil)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, cert)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cert)
			}
		})
	}
}

// TestCertificateManager_GetCAPool tests getting CA pool
func TestCertificateManager_GetCAPool(t *testing.T) {
	tests := []struct {
		name      string
		hasCA     bool
		expectNil bool
	}{
		{
			name:      "get CA pool with CA loaded",
			hasCA:     true,
			expectNil: false,
		},
		{
			name:      "get CA pool without CA loaded",
			hasCA:     false,
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs := generateTLSTestCertificates(t)
			logger := zaptest.NewLogger(t)

			var caFile string
			if tt.hasCA {
				caFile = certs.CAFile
			}

			cm, err := NewCertificateManager(certs.CertFile, certs.KeyFile, caFile, logger)
			require.NoError(t, err)

			pool := cm.GetCAPool()

			if tt.expectNil {
				assert.Nil(t, pool)
			} else {
				assert.NotNil(t, pool)
			}
		})
	}
}

// TestLoadTLSConfig tests loading TLS configuration
func TestLoadTLSConfig(t *testing.T) {
	certs := generateTLSTestCertificates(t)

	tests := []struct {
		name        string
		config      *TLSConfig
		expectNil   bool
		expectError bool
		errorMsg    string
		checkFunc   func(*testing.T, *tls.Config)
	}{
		{
			name:      "nil config returns nil",
			config:    nil,
			expectNil: true,
		},
		{
			name: "config with cert and key",
			config: &TLSConfig{
				CertFile: certs.CertFile,
				KeyFile:  certs.KeyFile,
			},
			expectNil: false,
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.Len(t, cfg.Certificates, 1)
				assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)
			},
		},
		{
			name: "config with CA",
			config: &TLSConfig{
				CertFile: certs.CertFile,
				KeyFile:  certs.KeyFile,
				CAFile:   certs.CAFile,
			},
			expectNil: false,
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.NotNil(t, cfg.ClientCAs)
				assert.Equal(t, tls.VerifyClientCertIfGiven, cfg.ClientAuth)
			},
		},
		{
			name: "config with custom versions",
			config: &TLSConfig{
				CertFile:   certs.CertFile,
				KeyFile:    certs.KeyFile,
				MinVersion: tls.VersionTLS13,
				MaxVersion: tls.VersionTLS13,
			},
			expectNil: false,
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)
			},
		},
		{
			name: "config with nonexistent cert fails",
			config: &TLSConfig{
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  "/nonexistent/key.pem",
			},
			expectError: true,
			errorMsg:    "failed to load certificate",
		},
		{
			name: "config with nonexistent CA fails",
			config: &TLSConfig{
				CertFile: certs.CertFile,
				KeyFile:  certs.KeyFile,
				CAFile:   "/nonexistent/ca.pem",
			},
			expectError: true,
			errorMsg:    "failed to read CA certificate",
		},
		{
			name: "config with empty cert and key uses defaults",
			config: &TLSConfig{
				MinVersion: 0,
				MaxVersion: 0,
			},
			expectNil: false,
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)
				assert.Len(t, cfg.Certificates, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadTLSConfig(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}

			assert.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, cfg)
			} else {
				assert.NotNil(t, cfg)
				if tt.checkFunc != nil {
					tt.checkFunc(t, cfg)
				}
			}
		})
	}
}

// TestLoadTLSConfig_InvalidCA tests loading TLS config with invalid CA
func TestLoadTLSConfig_InvalidCA(t *testing.T) {
	certs := generateTLSTestCertificates(t)
	invalidCAFile := createInvalidCertFile(t)

	cfg, err := LoadTLSConfig(&TLSConfig{
		CertFile: certs.CertFile,
		KeyFile:  certs.KeyFile,
		CAFile:   invalidCAFile,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
	assert.Nil(t, cfg)
}

// TestCreateTLSConfigWithManager tests creating TLS config with certificate manager
func TestCreateTLSConfigWithManager(t *testing.T) {
	certs := generateTLSTestCertificates(t)
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name  string
		hasCA bool
	}{
		{
			name:  "create config with CA",
			hasCA: true,
		},
		{
			name:  "create config without CA",
			hasCA: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var caFile string
			if tt.hasCA {
				caFile = certs.CAFile
			}

			cm, err := NewCertificateManager(certs.CertFile, certs.KeyFile, caFile, logger)
			require.NoError(t, err)

			cfg := CreateTLSConfigWithManager(cm)

			assert.NotNil(t, cfg)
			assert.NotNil(t, cfg.GetCertificate)
			assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
			assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)

			if tt.hasCA {
				assert.NotNil(t, cfg.ClientCAs)
			} else {
				assert.Nil(t, cfg.ClientCAs)
			}

			// Test that GetCertificate works
			cert, err := cfg.GetCertificate(nil)
			assert.NoError(t, err)
			assert.NotNil(t, cert)
		})
	}
}

// TestDefaultTLSConfig tests the default TLS configuration
func TestDefaultTLSConfig(t *testing.T) {
	cfg := DefaultTLSConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)
	assert.True(t, cfg.PreferServerCipherSuites)

	// Check cipher suites
	expectedCiphers := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	assert.Equal(t, expectedCiphers, cfg.CipherSuites)

	// Check curve preferences
	expectedCurves := []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
	}
	assert.Equal(t, expectedCurves, cfg.CurvePreferences)
}

// TestMergeTLSConfig tests merging TLS configurations
func TestMergeTLSConfig(t *testing.T) {
	certs := generateTLSTestCertificates(t)

	// Load a certificate for testing
	cert, err := tls.LoadX509KeyPair(certs.CertFile, certs.KeyFile)
	require.NoError(t, err)

	// Create a CA pool for testing
	caCert, err := os.ReadFile(certs.CAFile)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	tests := []struct {
		name      string
		custom    *tls.Config
		checkFunc func(*testing.T, *tls.Config)
	}{
		{
			name:   "nil custom returns defaults",
			custom: nil,
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)
				assert.True(t, cfg.PreferServerCipherSuites)
			},
		},
		{
			name: "custom with certificates",
			custom: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.Len(t, cfg.Certificates, 1)
				// Should still have defaults
				assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
			},
		},
		{
			name: "custom with GetCertificate",
			custom: &tls.Config{
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return &cert, nil
				},
			},
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.NotNil(t, cfg.GetCertificate)
			},
		},
		{
			name: "custom with ClientCAs",
			custom: &tls.Config{
				ClientCAs: caPool,
			},
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.NotNil(t, cfg.ClientCAs)
			},
		},
		{
			name: "custom with RootCAs",
			custom: &tls.Config{
				RootCAs: caPool,
			},
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.NotNil(t, cfg.RootCAs)
			},
		},
		{
			name: "custom with ClientAuth",
			custom: &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
			},
		},
		{
			name: "custom with MinVersion",
			custom: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
			},
		},
		{
			name: "custom with MaxVersion",
			custom: &tls.Config{
				MaxVersion: tls.VersionTLS12,
			},
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS12), cfg.MaxVersion)
			},
		},
		{
			name: "custom with NoClientCert does not override",
			custom: &tls.Config{
				ClientAuth: tls.NoClientCert,
			},
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				// NoClientCert is the zero value, so it should not override
				assert.Equal(t, tls.NoClientCert, cfg.ClientAuth)
			},
		},
		{
			name: "custom with all options",
			custom: &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientCAs:    caPool,
				RootCAs:      caPool,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				MinVersion:   tls.VersionTLS13,
				MaxVersion:   tls.VersionTLS13,
			},
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				assert.Len(t, cfg.Certificates, 1)
				assert.NotNil(t, cfg.ClientCAs)
				assert.NotNil(t, cfg.RootCAs)
				assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := MergeTLSConfig(tt.custom)

			assert.NotNil(t, cfg)
			tt.checkFunc(t, cfg)
		})
	}
}

// TestCertificateManager_Concurrency tests concurrent access to certificate manager
func TestCertificateManager_Concurrency(t *testing.T) {
	certs := generateTLSTestCertificates(t)
	logger := zaptest.NewLogger(t)

	cm, err := NewCertificateManager(certs.CertFile, certs.KeyFile, certs.CAFile, logger)
	require.NoError(t, err)

	done := make(chan bool)

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_, _ = cm.GetCertificate(nil)
				_ = cm.GetCAPool()
			}
			done <- true
		}()
	}

	// Concurrent reloads
	for i := 0; i < 3; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				_ = cm.Reload()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 13; i++ {
		<-done
	}
}

// TestLoadTLSConfig_OnlyCertNoKey tests loading config with only cert file
func TestLoadTLSConfig_OnlyCertNoKey(t *testing.T) {
	certs := generateTLSTestCertificates(t)

	// Only cert file, no key - should not load certificate
	cfg, err := LoadTLSConfig(&TLSConfig{
		CertFile: certs.CertFile,
		KeyFile:  "",
	})

	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Len(t, cfg.Certificates, 0)
}

// TestLoadTLSConfig_OnlyKeyNoCert tests loading config with only key file
func TestLoadTLSConfig_OnlyKeyNoCert(t *testing.T) {
	certs := generateTLSTestCertificates(t)

	// Only key file, no cert - should not load certificate
	cfg, err := LoadTLSConfig(&TLSConfig{
		CertFile: "",
		KeyFile:  certs.KeyFile,
	})

	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Len(t, cfg.Certificates, 0)
}

// TestLoadTLSConfig_OnlyCA tests loading config with only CA file
func TestLoadTLSConfig_OnlyCA(t *testing.T) {
	certs := generateTLSTestCertificates(t)

	cfg, err := LoadTLSConfig(&TLSConfig{
		CAFile: certs.CAFile,
	})

	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.ClientCAs)
	assert.Equal(t, tls.VerifyClientCertIfGiven, cfg.ClientAuth)
}

// TestCertificateManager_EmptyFiles tests certificate manager with empty file paths
func TestCertificateManager_EmptyFiles(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cm, err := NewCertificateManager("", "", "", logger)
	require.NoError(t, err)
	require.NotNil(t, cm)

	// GetCertificate should fail
	cert, err := cm.GetCertificate(nil)
	assert.Error(t, err)
	assert.Nil(t, cert)

	// GetCAPool should return nil
	pool := cm.GetCAPool()
	assert.Nil(t, pool)
}

// TestCertificateManager_OnlyCert tests certificate manager with only cert (no CA)
func TestCertificateManager_OnlyCert(t *testing.T) {
	certs := generateTLSTestCertificates(t)
	logger := zaptest.NewLogger(t)

	cm, err := NewCertificateManager(certs.CertFile, certs.KeyFile, "", logger)
	require.NoError(t, err)
	require.NotNil(t, cm)

	// GetCertificate should succeed
	cert, err := cm.GetCertificate(nil)
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// GetCAPool should return nil
	pool := cm.GetCAPool()
	assert.Nil(t, pool)
}

// TestMergeTLSConfig_PreservesDefaults tests that merge preserves default cipher suites
func TestMergeTLSConfig_PreservesDefaults(t *testing.T) {
	custom := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	cfg := MergeTLSConfig(custom)

	// Should preserve default cipher suites
	assert.NotEmpty(t, cfg.CipherSuites)
	assert.NotEmpty(t, cfg.CurvePreferences)
	assert.True(t, cfg.PreferServerCipherSuites)
}
