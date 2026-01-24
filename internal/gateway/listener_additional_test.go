package gateway

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

func TestListener_WrapHandler_HSTS(t *testing.T) {
	t.Parallel()

	// Create HTTP listener (not HTTPS) to avoid TLS initialization
	// but with TLS config for HSTS middleware testing
	cfg := config.Listener{
		Name:     "http-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP, // Use HTTP to avoid TLS init
		TLS: &config.ListenerTLSConfig{
			Mode: "SIMPLE",
			HSTS: &config.HSTSConfig{
				Enabled:           true,
				MaxAge:            31536000,
				IncludeSubDomains: true,
				Preload:           true,
			},
		},
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, baseHandler)
	require.NoError(t, err)

	// Test the wrapped handler
	wrappedHandler := listener.wrapHandler(baseHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	// Check HSTS header
	hstsHeader := w.Header().Get("Strict-Transport-Security")
	assert.Contains(t, hstsHeader, "max-age=31536000")
	assert.Contains(t, hstsHeader, "includeSubDomains")
	assert.Contains(t, hstsHeader, "preload")
}

func TestListener_WrapHandler_HSTSDefaultMaxAge(t *testing.T) {
	t.Parallel()

	// Create HTTP listener (not HTTPS) to avoid TLS initialization
	cfg := config.Listener{
		Name:     "http-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP, // Use HTTP to avoid TLS init
		TLS: &config.ListenerTLSConfig{
			Mode: "SIMPLE",
			HSTS: &config.HSTSConfig{
				Enabled: true,
				MaxAge:  0, // Should use default
			},
		},
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, baseHandler)
	require.NoError(t, err)

	wrappedHandler := listener.wrapHandler(baseHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	// Check HSTS header with default max-age
	hstsHeader := w.Header().Get("Strict-Transport-Security")
	assert.Contains(t, hstsHeader, "max-age=31536000") // Default 1 year
}

func TestListener_WrapHandler_HTTPSRedirect(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "http-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
		TLS: &config.ListenerTLSConfig{
			HTTPSRedirect: true,
		},
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, baseHandler)
	require.NoError(t, err)

	wrappedHandler := listener.wrapHandler(baseHandler)

	// Test HTTP request (no TLS)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	// Should redirect to HTTPS
	assert.Equal(t, http.StatusMovedPermanently, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://")
}

func TestListener_WrapHandler_HTTPSRedirectWithTLS(t *testing.T) {
	t.Parallel()

	// Create HTTP listener (not HTTPS) to avoid TLS initialization
	cfg := config.Listener{
		Name:     "http-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP, // Use HTTP to avoid TLS init
		TLS: &config.ListenerTLSConfig{
			HTTPSRedirect: true,
		},
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	listener, err := NewListener(cfg, baseHandler)
	require.NoError(t, err)

	wrappedHandler := listener.wrapHandler(baseHandler)

	// Test HTTPS request (with TLS)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{} // Simulate TLS connection
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	// Should not redirect, should pass through
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListener_WithTimeouts(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
		Timeouts: &config.ListenerTimeouts{
			ReadTimeout:       config.Duration(10 * time.Second),
			ReadHeaderTimeout: config.Duration(5 * time.Second),
			WriteTimeout:      config.Duration(15 * time.Second),
			IdleTimeout:       config.Duration(60 * time.Second),
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler)
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = listener.Stop(ctx) }()

	assert.True(t, listener.IsRunning())
}

func TestListener_WithDefaultTimeouts(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
		// No timeouts specified - should use defaults
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler)
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = listener.Stop(ctx) }()

	assert.True(t, listener.IsRunning())
}

func TestListener_ConvertToTLSConfig_WithAllOptions(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: config.ProtocolHTTPS,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	tlsCfg := &config.ListenerTLSConfig{
		Mode:               "MUTUAL",
		MinVersion:         "TLS12",
		MaxVersion:         "TLS13",
		CertFile:           "/path/to/cert.pem",
		KeyFile:            "/path/to/key.pem",
		CAFile:             "/path/to/ca.pem",
		RequireClientCert:  true,
		InsecureSkipVerify: false,
		ALPN:               []string{"h2", "http/1.1"},
		CipherSuites:       []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		Vault: &config.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "example.com",
			AltNames:   []string{"www.example.com", "api.example.com"},
		},
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)

	assert.Equal(t, tlspkg.TLSMode("MUTUAL"), result.Mode)
	assert.Equal(t, tlspkg.TLSVersion("TLS12"), result.MinVersion)
	assert.Equal(t, tlspkg.TLSVersion("TLS13"), result.MaxVersion)
	assert.NotNil(t, result.ServerCertificate)
	assert.Equal(t, "/path/to/cert.pem", result.ServerCertificate.CertFile)
	assert.Equal(t, "/path/to/key.pem", result.ServerCertificate.KeyFile)
	assert.NotNil(t, result.ClientValidation)
	assert.True(t, result.ClientValidation.Enabled)
	assert.Equal(t, "/path/to/ca.pem", result.ClientValidation.CAFile)
	assert.True(t, result.ClientValidation.RequireClientCert)
	assert.Equal(t, []string{"h2", "http/1.1"}, result.ALPN)
	assert.Equal(t, []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}, result.CipherSuites)
	assert.NotNil(t, result.Vault)
	assert.True(t, result.Vault.Enabled)
	assert.Equal(t, "pki", result.Vault.PKIMount)
	assert.Equal(t, "my-role", result.Vault.Role)
	assert.Equal(t, "example.com", result.Vault.CommonName)
	assert.Equal(t, []string{"www.example.com", "api.example.com"}, result.Vault.AltNames)
}

func TestListener_ConvertToTLSConfig_OnlyCertFile(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: config.ProtocolHTTPS,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	// Only cert file, no key file
	tlsCfg := &config.ListenerTLSConfig{
		Mode:     "SIMPLE",
		CertFile: "/path/to/cert.pem",
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)
	assert.NotNil(t, result.ServerCertificate)
	assert.Equal(t, "/path/to/cert.pem", result.ServerCertificate.CertFile)
}

func TestListener_ConvertToTLSConfig_OnlyKeyFile(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: config.ProtocolHTTPS,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	// Only key file, no cert file
	tlsCfg := &config.ListenerTLSConfig{
		Mode:    "SIMPLE",
		KeyFile: "/path/to/key.pem",
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)
	assert.NotNil(t, result.ServerCertificate)
	assert.Equal(t, "/path/to/key.pem", result.ServerCertificate.KeyFile)
}

func TestListener_ConvertToTLSConfig_OnlyCAFile(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: config.ProtocolHTTPS,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	// Only CA file for client validation
	tlsCfg := &config.ListenerTLSConfig{
		Mode:   "SIMPLE",
		CAFile: "/path/to/ca.pem",
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)
	assert.NotNil(t, result.ClientValidation)
	assert.True(t, result.ClientValidation.Enabled)
	assert.Equal(t, "/path/to/ca.pem", result.ClientValidation.CAFile)
}

func TestListener_ConvertToTLSConfig_RequireClientCertOnly(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: config.ProtocolHTTPS,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	// Only require client cert flag
	tlsCfg := &config.ListenerTLSConfig{
		Mode:              "MUTUAL",
		RequireClientCert: true,
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)
	assert.NotNil(t, result.ClientValidation)
	assert.True(t, result.ClientValidation.Enabled)
	assert.True(t, result.ClientValidation.RequireClientCert)
}

func TestListener_ConvertToTLSConfig_VaultDisabled(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: config.ProtocolHTTPS,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	// Vault config present but disabled
	tlsCfg := &config.ListenerTLSConfig{
		Mode: "SIMPLE",
		Vault: &config.VaultTLSConfig{
			Enabled: false,
		},
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)
	assert.Nil(t, result.Vault)
}

func TestListener_StopWithCancelledContext(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)

	// Create a cancelled context
	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()

	// Stop should still work even with cancelled context
	err = listener.Stop(cancelledCtx)
	// May return error due to cancelled context, but should not panic
	_ = err
}

func TestListener_MultipleStartStop(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	ctx := context.Background()

	// First start/stop cycle
	err = listener.Start(ctx)
	require.NoError(t, err)
	assert.True(t, listener.IsRunning())

	err = listener.Stop(ctx)
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)
	assert.False(t, listener.IsRunning())
}

func TestListener_AddressWithEmptyBind(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: config.ProtocolHTTP,
		Bind:     "", // Empty bind should default to 0.0.0.0
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0:8080", listener.Address())
}

func TestListener_AddressWithIPv6Bind(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: config.ProtocolHTTP,
		Bind:     "::",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	assert.Equal(t, ":::8080", listener.Address())
}

func TestListener_WithTLSMetricsOption(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: config.ProtocolHTTP,
	}

	metrics := tlspkg.NewNopMetrics()
	listener, err := NewListener(cfg,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		WithTLSMetrics(metrics),
	)
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, metrics, listener.tlsMetrics)
}

func TestListener_WithLoggerOption(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: config.ProtocolHTTP,
	}

	logger := observability.NopLogger()
	listener, err := NewListener(cfg,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		WithListenerLogger(logger),
	)
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, logger, listener.logger)
}
