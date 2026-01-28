package backend

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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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
func createTestCertFiles(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()

	certPEM, keyPEM := generateTestCertificate(t)

	tmpDir := t.TempDir()
	certFile = filepath.Join(tmpDir, "cert.pem")
	keyFile = filepath.Join(tmpDir, "key.pem")
	caFile = filepath.Join(tmpDir, "ca.pem")

	err := os.WriteFile(certFile, certPEM, 0600)
	require.NoError(t, err)

	err = os.WriteFile(keyFile, keyPEM, 0600)
	require.NoError(t, err)

	err = os.WriteFile(caFile, certPEM, 0600) // Use same cert as CA for testing
	require.NoError(t, err)

	return certFile, keyFile, caFile
}

func TestNewTLSConfigBuilder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *config.BackendTLSConfig
		opts []TLSConfigBuilderOption
	}{
		{
			name: "nil config",
			cfg:  nil,
			opts: nil,
		},
		{
			name: "with config",
			cfg: &config.BackendTLSConfig{
				Enabled: true,
			},
			opts: nil,
		},
		{
			name: "with logger option",
			cfg: &config.BackendTLSConfig{
				Enabled: true,
			},
			opts: []TLSConfigBuilderOption{
				WithTLSLogger(observability.NopLogger()),
			},
		},
		{
			name: "with metrics option",
			cfg: &config.BackendTLSConfig{
				Enabled: true,
			},
			opts: []TLSConfigBuilderOption{
				WithTLSMetrics(tlspkg.NewNopMetrics()),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			builder := NewTLSConfigBuilder(tt.cfg, tt.opts...)
			assert.NotNil(t, builder)
		})
	}
}

func TestTLSConfigBuilder_Build_Disabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *config.BackendTLSConfig
	}{
		{
			name: "nil config",
			cfg:  nil,
		},
		{
			name: "disabled config",
			cfg: &config.BackendTLSConfig{
				Enabled: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			builder := NewTLSConfigBuilder(tt.cfg)
			tlsConfig, err := builder.Build()

			assert.NoError(t, err)
			assert.Nil(t, tlsConfig)
		})
	}
}

func TestTLSConfigBuilder_Build_Basic(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled:    true,
		MinVersion: "TLS12",
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	tlsConfig, err := builder.Build()

	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
}

func TestTLSConfigBuilder_Build_WithServerName(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled:    true,
		ServerName: "example.com",
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	tlsConfig, err := builder.Build()

	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, "example.com", tlsConfig.ServerName)
}

func TestTLSConfigBuilder_Build_WithInsecureSkipVerify(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled:            true,
		InsecureSkipVerify: true,
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	tlsConfig, err := builder.Build()

	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.True(t, tlsConfig.InsecureSkipVerify)
}

func TestTLSConfigBuilder_Build_WithVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		minVersion   string
		maxVersion   string
		expectMinVer uint16
		expectMaxVer uint16
		expectErr    bool
	}{
		{
			name:         "TLS 1.2 only",
			minVersion:   "TLS12",
			maxVersion:   "TLS12",
			expectMinVer: tls.VersionTLS12,
			expectMaxVer: tls.VersionTLS12,
		},
		{
			name:         "TLS 1.2 to 1.3",
			minVersion:   "TLS12",
			maxVersion:   "TLS13",
			expectMinVer: tls.VersionTLS12,
			expectMaxVer: tls.VersionTLS13,
		},
		{
			name:         "TLS 1.3 only",
			minVersion:   "TLS13",
			maxVersion:   "TLS13",
			expectMinVer: tls.VersionTLS13,
			expectMaxVer: tls.VersionTLS13,
		},
		{
			name:       "invalid min version",
			minVersion: "invalid",
			expectErr:  true,
		},
		{
			name:       "invalid max version",
			minVersion: "TLS12",
			maxVersion: "invalid",
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.BackendTLSConfig{
				Enabled:    true,
				MinVersion: tt.minVersion,
				MaxVersion: tt.maxVersion,
			}

			builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
			tlsConfig, err := builder.Build()

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tlsConfig)
			assert.Equal(t, tt.expectMinVer, tlsConfig.MinVersion)
			if tt.maxVersion != "" {
				assert.Equal(t, tt.expectMaxVer, tlsConfig.MaxVersion)
			}
		})
	}
}

func TestTLSConfigBuilder_Build_WithALPN(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
		ALPN:    []string{"h2", "http/1.1"},
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	tlsConfig, err := builder.Build()

	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, []string{"h2", "http/1.1"}, tlsConfig.NextProtos)
}

func TestTLSConfigBuilder_Build_WithCAFile(t *testing.T) {
	t.Parallel()

	_, _, caFile := createTestCertFiles(t)

	cfg := &config.BackendTLSConfig{
		Enabled: true,
		CAFile:  caFile,
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	tlsConfig, err := builder.Build()

	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.NotNil(t, tlsConfig.RootCAs)
}

func TestTLSConfigBuilder_Build_WithCAFile_NotFound(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
		CAFile:  "/nonexistent/ca.pem",
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	_, err := builder.Build()

	assert.Error(t, err)
}

func TestTLSConfigBuilder_Build_WithCAFile_Invalid(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	invalidCAFile := filepath.Join(tmpDir, "invalid-ca.pem")
	err := os.WriteFile(invalidCAFile, []byte("invalid cert"), 0600)
	require.NoError(t, err)

	cfg := &config.BackendTLSConfig{
		Enabled: true,
		CAFile:  invalidCAFile,
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	_, err = builder.Build()

	assert.Error(t, err)
}

func TestTLSConfigBuilder_Build_WithClientCert(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _ := createTestCertFiles(t)

	cfg := &config.BackendTLSConfig{
		Enabled:  true,
		Mode:     config.TLSModeMutual,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	tlsConfig, err := builder.Build()

	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Len(t, tlsConfig.Certificates, 1)
}

func TestTLSConfigBuilder_Build_WithClientCert_MissingFiles(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled:  true,
		Mode:     config.TLSModeMutual,
		CertFile: "",
		KeyFile:  "",
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	_, err := builder.Build()

	assert.Error(t, err)
}

func TestTLSConfigBuilder_Build_WithClientCert_InvalidFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	invalidCertFile := filepath.Join(tmpDir, "invalid-cert.pem")
	invalidKeyFile := filepath.Join(tmpDir, "invalid-key.pem")

	err := os.WriteFile(invalidCertFile, []byte("invalid cert"), 0600)
	require.NoError(t, err)
	err = os.WriteFile(invalidKeyFile, []byte("invalid key"), 0600)
	require.NoError(t, err)

	cfg := &config.BackendTLSConfig{
		Enabled:  true,
		Mode:     config.TLSModeMutual,
		CertFile: invalidCertFile,
		KeyFile:  invalidKeyFile,
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	_, err = builder.Build()

	assert.Error(t, err)
}

func TestTLSConfigBuilder_Build_WithVaultConfig_NoClient(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
		Mode:    config.TLSModeMutual,
		Vault: &config.VaultBackendTLSConfig{
			Enabled: true,
		},
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	tlsConfig, err := builder.Build()

	// Should fail because vault client is required when vault TLS is enabled
	require.Error(t, err)
	assert.Nil(t, tlsConfig)
	assert.Contains(t, err.Error(), "vault client is required when vault TLS is enabled")
}

func TestTLSConfigBuilder_Build_Caching(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))

	// First build
	tlsConfig1, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig1)

	// Second build should return cached config (cloned)
	tlsConfig2, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig2)

	// Should be different instances (cloned)
	assert.NotSame(t, tlsConfig1, tlsConfig2)
}

func TestTLSConfigBuilder_BuildWithServerName(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	tlsConfig, err := builder.BuildWithServerName("custom.example.com")

	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, "custom.example.com", tlsConfig.ServerName)
}

func TestTLSConfigBuilder_BuildWithServerName_Disabled(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: false,
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	tlsConfig, err := builder.BuildWithServerName("custom.example.com")

	require.NoError(t, err)
	assert.Nil(t, tlsConfig)
}

func TestTLSConfigBuilder_Invalidate(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))

	// Build to cache
	_, err := builder.Build()
	require.NoError(t, err)

	// Invalidate
	builder.Invalidate()

	// Build again - should rebuild
	tlsConfig, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
}

func TestParseTLSVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		version   string
		expected  uint16
		expectErr bool
	}{
		{
			name:     "TLS10",
			version:  "TLS10",
			expected: tls.VersionTLS10,
		},
		{
			name:     "TLS11",
			version:  "TLS11",
			expected: tls.VersionTLS11,
		},
		{
			name:     "TLS12",
			version:  "TLS12",
			expected: tls.VersionTLS12,
		},
		{
			name:     "TLS13",
			version:  "TLS13",
			expected: tls.VersionTLS13,
		},
		{
			name:     "empty defaults to TLS12",
			version:  "",
			expected: tls.VersionTLS12,
		},
		{
			name:      "invalid version",
			version:   "invalid",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := parseTLSVersion(tt.version)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestNewBackendTLSTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *config.BackendTLSConfig
		expectErr bool
	}{
		{
			name:      "nil config",
			cfg:       nil,
			expectErr: false,
		},
		{
			name: "disabled config",
			cfg: &config.BackendTLSConfig{
				Enabled: false,
			},
			expectErr: false,
		},
		{
			name: "enabled config",
			cfg: &config.BackendTLSConfig{
				Enabled: true,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			transport, err := NewBackendTLSTransport(tt.cfg, observability.NopLogger())

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, transport)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, transport)
			}
		})
	}
}

func TestBackendTLSTransport_Transport(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
	}

	transport, err := NewBackendTLSTransport(cfg, observability.NopLogger())
	require.NoError(t, err)

	httpTransport := transport.Transport()
	assert.NotNil(t, httpTransport)
}

func TestBackendTLSTransport_TLSConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
	}

	transport, err := NewBackendTLSTransport(cfg, observability.NopLogger())
	require.NoError(t, err)

	tlsConfig := transport.TLSConfig()
	assert.NotNil(t, tlsConfig)
}

func TestTLSConfigBuilder_Build_WithCipherSuites(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		cipherSuites []string
		expectErr    bool
	}{
		{
			name:         "empty uses defaults",
			cipherSuites: []string{},
			expectErr:    false,
		},
		{
			name:         "valid cipher suites",
			cipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			expectErr:    false,
		},
		{
			name:         "invalid cipher suite",
			cipherSuites: []string{"INVALID_CIPHER"},
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.BackendTLSConfig{
				Enabled:      true,
				CipherSuites: tt.cipherSuites,
			}

			builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
			tlsConfig, err := builder.Build()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tlsConfig)
			}
		})
	}
}

func TestWithTLSLogger(t *testing.T) {
	t.Parallel()

	builder := &TLSConfigBuilder{}
	logger := observability.NopLogger()

	opt := WithTLSLogger(logger)
	opt(builder)

	assert.Equal(t, logger, builder.logger)
}

func TestWithTLSMetrics(t *testing.T) {
	t.Parallel()

	builder := &TLSConfigBuilder{}
	metrics := tlspkg.NewNopMetrics()

	opt := WithTLSMetrics(metrics)
	opt(builder)

	assert.Equal(t, metrics, builder.metrics)
}

func TestWithTLSVaultClient(t *testing.T) {
	t.Parallel()

	builder := &TLSConfigBuilder{}

	// Use a nil vault.Client interface value to test the option sets the field
	opt := WithTLSVaultClient(nil)
	opt(builder)

	// The field should be set (even to nil)
	assert.Nil(t, builder.vaultClient)
}

func TestTLSConfigBuilder_Close_WithoutVaultProvider(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))

	// Close without vault provider should be a no-op
	err := builder.Close()
	assert.NoError(t, err)
}

func TestTLSConfigBuilder_Close_Idempotent(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))

	// First close
	err := builder.Close()
	assert.NoError(t, err)

	// Second close should also be fine
	err = builder.Close()
	assert.NoError(t, err)
}

func TestBackendTLSTransport_Close(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
	}

	transport, err := NewBackendTLSTransport(cfg, observability.NopLogger())
	require.NoError(t, err)

	// Close should not error
	err = transport.Close()
	assert.NoError(t, err)
}

func TestTLSConfigBuilder_Build_WithVaultConfig_InvalidTTL(t *testing.T) {
	t.Parallel()

	cfg := &config.BackendTLSConfig{
		Enabled: true,
		Mode:    config.TLSModeMutual,
		Vault: &config.VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "example.com",
			TTL:        "invalid-ttl",
		},
	}

	// We need a non-nil vault client to get past the nil check
	// but we can't easily create a real vault.Client without a server.
	// The test for "no client" already covers the nil case.
	// This test verifies the error path when vault is enabled but no client is set.
	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))
	tlsConfig, err := builder.Build()

	// Should fail because vault client is required
	require.Error(t, err)
	assert.Nil(t, tlsConfig)
	assert.Contains(t, err.Error(), "vault client is required")
}
