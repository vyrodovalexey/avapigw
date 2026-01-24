package server

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// generateTestCertificate generates a self-signed certificate for testing.
func generateTestCertificate(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// createTestCertFiles creates temporary certificate files for testing.
func createTestCertFiles(t *testing.T) (certFile, keyFile string, cleanup func()) {
	t.Helper()

	certPEM, keyPEM := generateTestCertificate(t)

	tmpDir := t.TempDir()
	certFile = filepath.Join(tmpDir, "cert.pem")
	keyFile = filepath.Join(tmpDir, "key.pem")

	err := os.WriteFile(certFile, certPEM, 0600)
	require.NoError(t, err)

	err = os.WriteFile(keyFile, keyPEM, 0600)
	require.NoError(t, err)

	cleanup = func() {
		// tmpDir is automatically cleaned up by t.TempDir()
	}

	return certFile, keyFile, cleanup
}

func TestServer_BuildTLSOptions_Insecure(t *testing.T) {
	t.Parallel()

	s := &Server{
		insecure: true,
		logger:   observability.NopLogger(),
	}

	opts, err := s.buildTLSOptions()
	require.NoError(t, err)
	assert.Empty(t, opts)
}

func TestServer_BuildTLSOptions_NoTLS(t *testing.T) {
	t.Parallel()

	s := &Server{
		insecure: false,
		logger:   observability.NopLogger(),
	}

	opts, err := s.buildTLSOptions()
	require.NoError(t, err)
	assert.Empty(t, opts)
}

func TestServer_BuildTLSOptions_FromFiles(t *testing.T) {
	t.Parallel()

	certFile, keyFile, cleanup := createTestCertFiles(t)
	defer cleanup()

	s := &Server{
		tlsCertFile: certFile,
		tlsKeyFile:  keyFile,
		logger:      observability.NopLogger(),
	}

	opts, err := s.buildTLSOptions()
	require.NoError(t, err)
	assert.Len(t, opts, 1)
}

func TestServer_BuildTLSOptions_FromFiles_InvalidCert(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "invalid-cert.pem")
	keyFile := filepath.Join(tmpDir, "invalid-key.pem")

	err := os.WriteFile(certFile, []byte("invalid cert"), 0600)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, []byte("invalid key"), 0600)
	require.NoError(t, err)

	s := &Server{
		tlsCertFile: certFile,
		tlsKeyFile:  keyFile,
		logger:      observability.NopLogger(),
	}

	_, err = s.buildTLSOptions()
	assert.Error(t, err)
}

func TestServer_BuildTLSOptions_FromFiles_MissingFiles(t *testing.T) {
	t.Parallel()

	s := &Server{
		tlsCertFile: "/nonexistent/cert.pem",
		tlsKeyFile:  "/nonexistent/key.pem",
		logger:      observability.NopLogger(),
	}

	_, err := s.buildTLSOptions()
	assert.Error(t, err)
}

func TestServer_BuildTLSOptions_FromConfig(t *testing.T) {
	t.Parallel()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	s := &Server{
		tlsConfig: tlsConfig,
		logger:    observability.NopLogger(),
	}

	opts, err := s.buildTLSOptions()
	require.NoError(t, err)
	assert.Len(t, opts, 1)
}

func TestServer_ConfigureGRPCTLS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		tlsConfig   *tls.Config
		requireALPN bool
		checkConfig func(t *testing.T, cfg *tls.Config)
	}{
		{
			name: "sets minimum TLS version",
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS10,
			},
			checkConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
			},
		},
		{
			name: "preserves higher TLS version",
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
			checkConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
			},
		},
		{
			name: "sets ALPN protocols",
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			checkConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Contains(t, cfg.NextProtos, "h2")
			},
		},
		{
			name: "preserves existing ALPN protocols",
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"custom-proto"},
			},
			checkConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, []string{"custom-proto"}, cfg.NextProtos)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &Server{
				logger:      observability.NopLogger(),
				requireALPN: tt.requireALPN,
			}

			s.configureGRPCTLS(tt.tlsConfig)
			tt.checkConfig(t, tt.tlsConfig)
		})
	}
}

func TestServer_VerifyALPNProtocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		negotiated    string
		allowedProtos []string
		expectError   bool
	}{
		{
			name:          "valid protocol",
			negotiated:    "h2",
			allowedProtos: []string{"h2"},
			expectError:   false,
		},
		{
			name:          "valid protocol from multiple",
			negotiated:    "h2",
			allowedProtos: []string{"http/1.1", "h2"},
			expectError:   false,
		},
		{
			name:          "empty negotiated protocol",
			negotiated:    "",
			allowedProtos: []string{"h2"},
			expectError:   true,
		},
		{
			name:          "invalid protocol",
			negotiated:    "http/1.1",
			allowedProtos: []string{"h2"},
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &Server{
				logger: observability.NopLogger(),
			}

			cs := tls.ConnectionState{
				NegotiatedProtocol: tt.negotiated,
			}

			err := s.verifyALPNProtocol(cs, tt.allowedProtos)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestServer_ApplyTLSConfigFromGRPCConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		grpcTLSCfg  *config.TLSConfig
		checkConfig func(t *testing.T, cfg *tls.Config)
	}{
		{
			name: "sets min version",
			grpcTLSCfg: &config.TLSConfig{
				Enabled:    true,
				MinVersion: "TLS13",
			},
			checkConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
			},
		},
		{
			name: "sets max version",
			grpcTLSCfg: &config.TLSConfig{
				Enabled:    true,
				MinVersion: "TLS12",
				MaxVersion: "TLS12",
			},
			checkConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS12), cfg.MaxVersion)
			},
		},
		{
			name: "sets ALPN protocols",
			grpcTLSCfg: &config.TLSConfig{
				Enabled: true,
				ALPN:    []string{"h2", "http/1.1"},
			},
			checkConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, []string{"h2", "http/1.1"}, cfg.NextProtos)
			},
		},
		{
			name: "sets insecure skip verify",
			grpcTLSCfg: &config.TLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true,
			},
			checkConfig: func(t *testing.T, cfg *tls.Config) {
				assert.True(t, cfg.InsecureSkipVerify)
			},
		},
		{
			name: "sets mutual TLS client auth",
			grpcTLSCfg: &config.TLSConfig{
				Enabled: true,
				Mode:    config.TLSModeMutual,
			},
			checkConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
			},
		},
		{
			name: "sets optional mutual TLS client auth",
			grpcTLSCfg: &config.TLSConfig{
				Enabled: true,
				Mode:    config.TLSModeOptionalMutual,
			},
			checkConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, tls.VerifyClientCertIfGiven, cfg.ClientAuth)
			},
		},
		{
			name: "sets no client cert for simple mode",
			grpcTLSCfg: &config.TLSConfig{
				Enabled: true,
				Mode:    config.TLSModeSimple,
			},
			checkConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, tls.NoClientCert, cfg.ClientAuth)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &Server{
				logger: observability.NopLogger(),
			}

			tlsConfig := &tls.Config{}
			s.applyTLSConfigFromGRPCConfig(tlsConfig, tt.grpcTLSCfg)
			tt.checkConfig(t, tlsConfig)
		})
	}
}

func TestServer_LoadClientCA(t *testing.T) {
	t.Parallel()

	// Create a test CA certificate
	certPEM, _ := generateTestCertificate(t)
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	err := os.WriteFile(caFile, certPEM, 0600)
	require.NoError(t, err)

	tests := []struct {
		name      string
		caFile    string
		expectErr bool
	}{
		{
			name:      "valid CA file",
			caFile:    caFile,
			expectErr: false,
		},
		{
			name:      "missing CA file",
			caFile:    "/nonexistent/ca.pem",
			expectErr: true,
		},
		{
			name: "invalid CA file",
			caFile: func() string {
				invalidFile := filepath.Join(tmpDir, "invalid-ca.pem")
				_ = os.WriteFile(invalidFile, []byte("invalid"), 0600)
				return invalidFile
			}(),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &Server{
				logger: observability.NopLogger(),
			}

			tlsConfig := &tls.Config{}
			err := s.loadClientCA(tlsConfig, tt.caFile)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tlsConfig.ClientCAs)
			}
		})
	}
}

func TestServer_CreateClientCertValidator(t *testing.T) {
	t.Parallel()

	s := &Server{
		logger: observability.NopLogger(),
	}

	cfg := &config.TLSConfig{
		Enabled:    true,
		Mode:       config.TLSModeMutual,
		AllowedCNs: []string{"allowed-cn"},
	}

	validator := s.createClientCertValidator(cfg)
	assert.NotNil(t, validator)
}

func TestServer_ValidateClientCert(t *testing.T) {
	t.Parallel()

	// Generate a test certificate
	certPEM, _ := generateTestCertificate(t)
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)

	tests := []struct {
		name        string
		rawCerts    [][]byte
		requireCert bool
		expectErr   bool
	}{
		{
			name:        "no certs when not required",
			rawCerts:    [][]byte{},
			requireCert: false,
			expectErr:   false,
		},
		{
			name:        "no certs when required",
			rawCerts:    [][]byte{},
			requireCert: true,
			expectErr:   true,
		},
		{
			name:        "valid cert",
			rawCerts:    [][]byte{block.Bytes},
			requireCert: true,
			expectErr:   false,
		},
		{
			name:        "invalid cert bytes",
			rawCerts:    [][]byte{[]byte("invalid")},
			requireCert: true,
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &Server{
				logger: observability.NopLogger(),
			}

			// Create a permissive validator for testing
			validator := tlspkg.NewValidator(&tlspkg.ClientValidationConfig{
				Enabled: false, // Disable validation to test parsing
			})

			err := s.validateClientCert(tt.rawCerts, validator, tt.requireCert)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestServer_ExtractClientCertToContext(t *testing.T) {
	t.Parallel()

	s := &Server{
		logger: observability.NopLogger(),
	}

	// Test with no peer info
	ctx := context.Background()
	result := s.extractClientCertToContext(ctx)
	assert.Equal(t, ctx, result)
}

func TestServer_ClientCertMetadataUnaryInterceptor(t *testing.T) {
	t.Parallel()

	s := &Server{
		logger: observability.NopLogger(),
	}

	interceptor := s.clientCertMetadataUnaryInterceptor()
	assert.NotNil(t, interceptor)
}

func TestServer_ClientCertMetadataStreamInterceptor(t *testing.T) {
	t.Parallel()

	s := &Server{
		logger: observability.NopLogger(),
	}

	interceptor := s.clientCertMetadataStreamInterceptor()
	assert.NotNil(t, interceptor)
}

func TestServer_WithTLSManager(t *testing.T) {
	t.Parallel()

	s := &Server{}

	// Create a mock TLS manager config
	tlsConfig := &tlspkg.Config{
		Mode: tlspkg.TLSModeInsecure,
	}
	manager, err := tlspkg.NewManager(tlsConfig)
	require.NoError(t, err)

	opt := WithTLSManager(manager)
	opt(s)

	assert.Equal(t, manager, s.tlsManager)
}

func TestServer_WithTLSConfig(t *testing.T) {
	t.Parallel()

	s := &Server{}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	opt := WithTLSConfig(tlsConfig)
	opt(s)

	assert.Equal(t, tlsConfig, s.tlsConfig)
}

func TestServer_WithTLSMetrics(t *testing.T) {
	t.Parallel()

	s := &Server{}

	metrics := tlspkg.NewNopMetrics()

	opt := WithTLSMetrics(metrics)
	opt(s)

	assert.Equal(t, metrics, s.tlsMetrics)
}

func TestServer_RecordClientCertMetric(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		metrics tlspkg.MetricsRecorder
		success bool
		reason  string
	}{
		{
			name:    "with metrics - success",
			metrics: tlspkg.NewNopMetrics(),
			success: true,
			reason:  "",
		},
		{
			name:    "with metrics - failure",
			metrics: tlspkg.NewNopMetrics(),
			success: false,
			reason:  "validation_failed",
		},
		{
			name:    "without metrics",
			metrics: nil,
			success: true,
			reason:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &Server{
				logger:     observability.NopLogger(),
				tlsMetrics: tt.metrics,
			}

			// Should not panic
			s.recordClientCertMetric(tt.success, tt.reason)
		})
	}
}

func TestServer_ConfigureALPNVerification(t *testing.T) {
	t.Parallel()

	s := &Server{
		logger:      observability.NopLogger(),
		requireALPN: true,
	}

	tlsConfig := &tls.Config{
		NextProtos: []string{"h2"},
	}

	s.configureALPNVerification(tlsConfig)
	assert.NotNil(t, tlsConfig.VerifyConnection)
}

func TestServer_BuildTLSOptionsFromManager_NilConfig(t *testing.T) {
	t.Parallel()

	// Create a manager that returns nil config (insecure mode)
	tlsConfig := &tlspkg.Config{
		Mode: tlspkg.TLSModeInsecure,
	}
	manager, err := tlspkg.NewManager(tlsConfig)
	require.NoError(t, err)

	s := &Server{
		logger:     observability.NopLogger(),
		tlsManager: manager,
	}

	opts, err := s.buildTLSOptionsFromManager()
	require.NoError(t, err)
	assert.Empty(t, opts)
}

func TestServer_Start_WithTLSFromFiles(t *testing.T) {
	t.Parallel()

	certFile, keyFile, cleanup := createTestCertFiles(t)
	defer cleanup()

	cfg := &config.GRPCListenerConfig{
		TLS: &config.TLSConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	}

	s, err := New(cfg, WithAddress("127.0.0.1:0"))
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	assert.Equal(t, StateRunning, s.State())

	err = s.Stop(ctx)
	require.NoError(t, err)
}
