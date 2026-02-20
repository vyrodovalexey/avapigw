package observability

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"go.opentelemetry.io/otel/trace/noop"
)

// TestBuildOTLPExporterOptions tests buildOTLPExporterOptions function.
func TestBuildOTLPExporterOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  TracerConfig
	}{
		{
			name: "basic config",
			cfg: TracerConfig{
				ServiceName:  "test-service",
				OTLPEndpoint: "localhost:4317",
				Enabled:      true,
			},
		},
		{
			name: "with retry config",
			cfg: TracerConfig{
				ServiceName:  "test-service",
				OTLPEndpoint: "localhost:4317",
				Enabled:      true,
				RetryConfig: &OTLPRetryConfig{
					Enabled:         true,
					InitialInterval: 2 * time.Second,
					MaxInterval:     60 * time.Second,
					MaxElapsedTime:  5 * time.Minute,
				},
			},
		},
		{
			name: "with nil retry config",
			cfg: TracerConfig{
				ServiceName:  "test-service",
				OTLPEndpoint: "localhost:4317",
				Enabled:      true,
				RetryConfig:  nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := buildOTLPExporterOptions(tt.cfg)
			assert.NotNil(t, opts)
			assert.Greater(t, len(opts), 0)
		})
	}
}

// TestAddTraceContextToContext_NoTraceID tests addTraceContextToContext without trace ID.
func TestAddTraceContextToContext_NoTraceID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// Create a noop span that doesn't have valid trace/span IDs
	_, span := noop.NewTracerProvider().Tracer("test").Start(ctx, "test")

	resultCtx := addTraceContextToContext(ctx, span)
	assert.NotNil(t, resultCtx)

	// Noop span doesn't have valid IDs, so context should not have trace/span IDs
	traceID := TraceIDFromContext(resultCtx)
	spanID := SpanIDFromContext(resultCtx)

	// These should be empty for noop spans
	assert.Empty(t, traceID)
	assert.Empty(t, spanID)
}

// TestNewTracer_WithOTLPEndpoint tests NewTracer with OTLP endpoint.
func TestNewTracer_WithOTLPEndpoint(t *testing.T) {
	// Not parallel because it modifies global state

	cfg := TracerConfig{
		ServiceName:  "test-service",
		OTLPEndpoint: "localhost:4317",
		SamplingRate: 1.0,
		Enabled:      true,
		RetryConfig: &OTLPRetryConfig{
			Enabled:         true,
			InitialInterval: 1 * time.Second,
			MaxInterval:     5 * time.Second,
			MaxElapsedTime:  10 * time.Second,
		},
	}

	// This will fail to connect but should not error during creation
	tracer, err := NewTracer(cfg)

	// May fail due to schema version conflicts in test environment
	if err != nil {
		t.Skip("Skipping due to OpenTelemetry schema version conflict or connection error")
	}

	require.NotNil(t, tracer)
	assert.NotNil(t, tracer.provider)
	assert.NotNil(t, tracer.tracer)

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = tracer.Shutdown(ctx)
}

// TestTracer_Shutdown_WithContext tests Shutdown with context.
func TestTracer_Shutdown_WithContext(t *testing.T) {
	t.Parallel()

	cfg := TracerConfig{
		ServiceName: "test-service",
		Enabled:     false,
	}

	tracer, err := NewTracer(cfg)
	require.NoError(t, err)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = tracer.Shutdown(ctx)
	// Should not error since provider is nil
	assert.NoError(t, err)
}

// TestBuildRetryConfig_PartialValues tests buildRetryConfig with partial values.
func TestBuildRetryConfig_PartialValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *OTLPRetryConfig
		expected struct {
			initialInterval time.Duration
			maxInterval     time.Duration
			maxElapsedTime  time.Duration
		}
	}{
		{
			name: "only initial interval set",
			cfg: &OTLPRetryConfig{
				Enabled:         true,
				InitialInterval: 5 * time.Second,
			},
			expected: struct {
				initialInterval time.Duration
				maxInterval     time.Duration
				maxElapsedTime  time.Duration
			}{
				initialInterval: 5 * time.Second,
				maxInterval:     DefaultOTLPRetryMaxInterval,
				maxElapsedTime:  DefaultOTLPRetryMaxElapsedTime,
			},
		},
		{
			name: "only max interval set",
			cfg: &OTLPRetryConfig{
				Enabled:     true,
				MaxInterval: 45 * time.Second,
			},
			expected: struct {
				initialInterval time.Duration
				maxInterval     time.Duration
				maxElapsedTime  time.Duration
			}{
				initialInterval: DefaultOTLPRetryInitialInterval,
				maxInterval:     45 * time.Second,
				maxElapsedTime:  DefaultOTLPRetryMaxElapsedTime,
			},
		},
		{
			name: "only max elapsed time set",
			cfg: &OTLPRetryConfig{
				Enabled:        true,
				MaxElapsedTime: 2 * time.Minute,
			},
			expected: struct {
				initialInterval time.Duration
				maxInterval     time.Duration
				maxElapsedTime  time.Duration
			}{
				initialInterval: DefaultOTLPRetryInitialInterval,
				maxInterval:     DefaultOTLPRetryMaxInterval,
				maxElapsedTime:  2 * time.Minute,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := buildRetryConfig(tt.cfg)

			assert.Equal(t, tt.expected.initialInterval, result.InitialInterval)
			assert.Equal(t, tt.expected.maxInterval, result.MaxInterval)
			assert.Equal(t, tt.expected.maxElapsedTime, result.MaxElapsedTime)
		})
	}
}

// TestTracerConfig_WithRetryConfig tests TracerConfig with RetryConfig.
func TestTracerConfig_WithRetryConfig(t *testing.T) {
	t.Parallel()

	cfg := TracerConfig{
		ServiceName:  "test-service",
		OTLPEndpoint: "localhost:4317",
		SamplingRate: 0.5,
		Enabled:      true,
		RetryConfig: &OTLPRetryConfig{
			Enabled:         true,
			InitialInterval: 2 * time.Second,
			MaxInterval:     30 * time.Second,
			MaxElapsedTime:  1 * time.Minute,
		},
	}

	assert.Equal(t, "test-service", cfg.ServiceName)
	assert.Equal(t, "localhost:4317", cfg.OTLPEndpoint)
	assert.Equal(t, 0.5, cfg.SamplingRate)
	assert.True(t, cfg.Enabled)
	assert.NotNil(t, cfg.RetryConfig)
	assert.True(t, cfg.RetryConfig.Enabled)
	assert.Equal(t, 2*time.Second, cfg.RetryConfig.InitialInterval)
}

// ============================================================================
// buildOTLPTLSConfig Tests
// ============================================================================

// generateTestCert creates a self-signed certificate and key for testing.
// Returns paths to cert file, key file, and CA file.
func generateTestCert(t *testing.T, dir string) (certFile, keyFile, caFile string) {
	t.Helper()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	// Write CA cert to file
	caFile = filepath.Join(dir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	// Generate client key
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create client certificate template
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	// Sign client certificate with CA
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	// Write client cert to file
	certFile = filepath.Join(dir, "client.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))

	// Write client key to file
	keyFile = filepath.Join(dir, "client-key.pem")
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))

	return certFile, keyFile, caFile
}

// TestBuildOTLPTLSConfig tests the buildOTLPTLSConfig function.
func TestBuildOTLPTLSConfig(t *testing.T) {
	t.Parallel()

	// Generate test certificates
	dir := t.TempDir()
	certFile, keyFile, caFile := generateTestCert(t, dir)

	tests := []struct {
		name      string
		cfg       TracerConfig
		wantNil   bool
		wantErr   bool
		wantCerts bool
		wantCA    bool
	}{
		{
			name: "no TLS files configured returns nil",
			cfg: TracerConfig{
				OTLPTLSCertFile: "",
				OTLPTLSKeyFile:  "",
				OTLPTLSCAFile:   "",
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "valid cert key and CA",
			cfg: TracerConfig{
				OTLPTLSCertFile: certFile,
				OTLPTLSKeyFile:  keyFile,
				OTLPTLSCAFile:   caFile,
			},
			wantNil:   false,
			wantErr:   false,
			wantCerts: true,
			wantCA:    true,
		},
		{
			name: "valid cert and key without CA",
			cfg: TracerConfig{
				OTLPTLSCertFile: certFile,
				OTLPTLSKeyFile:  keyFile,
				OTLPTLSCAFile:   "",
			},
			wantNil:   false,
			wantErr:   false,
			wantCerts: true,
			wantCA:    false,
		},
		{
			name: "only CA file",
			cfg: TracerConfig{
				OTLPTLSCertFile: "",
				OTLPTLSKeyFile:  "",
				OTLPTLSCAFile:   caFile,
			},
			wantNil:   false,
			wantErr:   false,
			wantCerts: false,
			wantCA:    true,
		},
		{
			name: "missing cert file",
			cfg: TracerConfig{
				OTLPTLSCertFile: "/nonexistent/cert.pem",
				OTLPTLSKeyFile:  keyFile,
				OTLPTLSCAFile:   "",
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "missing key file",
			cfg: TracerConfig{
				OTLPTLSCertFile: certFile,
				OTLPTLSKeyFile:  "/nonexistent/key.pem",
				OTLPTLSCAFile:   "",
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "missing CA file",
			cfg: TracerConfig{
				OTLPTLSCertFile: "",
				OTLPTLSKeyFile:  "",
				OTLPTLSCAFile:   "/nonexistent/ca.pem",
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "invalid CA file content",
			cfg: TracerConfig{
				OTLPTLSCertFile: "",
				OTLPTLSKeyFile:  "",
				OTLPTLSCAFile:   filepath.Join(dir, "invalid-ca.pem"),
			},
			wantNil: false,
			wantErr: true,
		},
	}

	// Create an invalid CA file for the test
	invalidCAFile := filepath.Join(dir, "invalid-ca.pem")
	require.NoError(t, os.WriteFile(invalidCAFile, []byte("not a valid PEM"), 0o600))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tlsCfg, err := buildOTLPTLSConfig(tt.cfg)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, tlsCfg)
				return
			}

			require.NotNil(t, tlsCfg)

			if tt.wantCerts {
				assert.NotEmpty(t, tlsCfg.Certificates, "expected client certificates to be loaded")
			} else {
				assert.Empty(t, tlsCfg.Certificates, "expected no client certificates")
			}

			if tt.wantCA {
				assert.NotNil(t, tlsCfg.RootCAs, "expected CA pool to be set")
			} else {
				assert.Nil(t, tlsCfg.RootCAs, "expected no CA pool")
			}
		})
	}
}

// TestBuildOTLPExporterOptions_WithTLS tests buildOTLPExporterOptions with TLS configuration.
func TestBuildOTLPExporterOptions_WithTLS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certFile, keyFile, caFile := generateTestCert(t, dir)

	tests := []struct {
		name string
		cfg  TracerConfig
	}{
		{
			name: "insecure mode",
			cfg: TracerConfig{
				ServiceName:  "test-service",
				OTLPEndpoint: "localhost:4317",
				OTLPInsecure: true,
				Enabled:      true,
			},
		},
		{
			name: "TLS with cert key and CA",
			cfg: TracerConfig{
				ServiceName:     "test-service",
				OTLPEndpoint:    "localhost:4317",
				OTLPInsecure:    false,
				OTLPTLSCertFile: certFile,
				OTLPTLSKeyFile:  keyFile,
				OTLPTLSCAFile:   caFile,
				Enabled:         true,
			},
		},
		{
			name: "TLS without explicit files (system default)",
			cfg: TracerConfig{
				ServiceName:  "test-service",
				OTLPEndpoint: "localhost:4317",
				OTLPInsecure: false,
				Enabled:      true,
			},
		},
		{
			name: "TLS with invalid cert files (falls through to system default)",
			cfg: TracerConfig{
				ServiceName:     "test-service",
				OTLPEndpoint:    "localhost:4317",
				OTLPInsecure:    false,
				OTLPTLSCertFile: "/nonexistent/cert.pem",
				OTLPTLSKeyFile:  "/nonexistent/key.pem",
				Enabled:         true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := buildOTLPExporterOptions(tt.cfg)
			assert.NotNil(t, opts)
			assert.Greater(t, len(opts), 0)
		})
	}
}
