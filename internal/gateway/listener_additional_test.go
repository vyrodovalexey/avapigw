package gateway

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
	"net/http"
	"net/http/httptest"
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
		Hosts:    []string{"example.com"},
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

func TestExtractHostWithoutPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "host without port",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "host with port",
			input:    "example.com:8080",
			expected: "example.com",
		},
		{
			name:     "IPv4 with port",
			input:    "192.168.1.1:8080",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv4 without port",
			input:    "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv6 with port",
			input:    "[::1]:8080",
			expected: "[::1]",
		},
		{
			name:     "IPv6 without port",
			input:    "[::1]",
			expected: "[::1]",
		},
		{
			name:     "IPv6 full address with port",
			input:    "[2001:db8::1]:443",
			expected: "[2001:db8::1]",
		},
		{
			name:     "localhost with port",
			input:    "localhost:3000",
			expected: "localhost",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := extractHostWithoutPort(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestListener_IsAllowedHost(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: config.ProtocolHTTP,
		Hosts:    []string{"example.com", "api.example.com", "UPPERCASE.COM"},
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "exact match",
			host:     "example.com",
			expected: true,
		},
		{
			name:     "case insensitive match",
			host:     "EXAMPLE.COM",
			expected: true,
		},
		{
			name:     "subdomain match",
			host:     "api.example.com",
			expected: true,
		},
		{
			name:     "uppercase config lowercase input",
			host:     "uppercase.com",
			expected: true,
		},
		{
			name:     "not allowed",
			host:     "other.com",
			expected: false,
		},
		{
			name:     "empty host",
			host:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := listener.isAllowedHost(tt.host)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestListener_GetSafeRedirectHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		hosts        []string
		requestHost  string
		expectedHost string
		expectedOK   bool
	}{
		{
			name:         "no hosts configured",
			hosts:        []string{},
			requestHost:  "example.com",
			expectedHost: "",
			expectedOK:   false,
		},
		{
			name:         "allowed host",
			hosts:        []string{"example.com", "api.example.com"},
			requestHost:  "example.com",
			expectedHost: "example.com",
			expectedOK:   true,
		},
		{
			name:         "allowed host with port",
			hosts:        []string{"example.com"},
			requestHost:  "example.com:8080",
			expectedHost: "example.com:8080",
			expectedOK:   true,
		},
		{
			name:         "untrusted host - use first configured",
			hosts:        []string{"trusted.com", "also-trusted.com"},
			requestHost:  "untrusted.com",
			expectedHost: "trusted.com",
			expectedOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Listener{
				Name:     "test-listener",
				Port:     8080,
				Protocol: config.ProtocolHTTP,
				Hosts:    tt.hosts,
			}

			listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			require.NoError(t, err)

			host, ok := listener.getSafeRedirectHost(tt.requestHost)
			assert.Equal(t, tt.expectedOK, ok)
			assert.Equal(t, tt.expectedHost, host)
		})
	}
}

func TestListener_HTTPSRedirectMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		hosts          []string
		requestHost    string
		hasTLS         bool
		expectedStatus int
		checkLocation  bool
	}{
		{
			name:           "HTTPS request passes through",
			hosts:          []string{"example.com"},
			requestHost:    "example.com",
			hasTLS:         true,
			expectedStatus: http.StatusOK,
			checkLocation:  false,
		},
		{
			name:           "HTTP request redirects to HTTPS",
			hosts:          []string{"example.com"},
			requestHost:    "example.com",
			hasTLS:         false,
			expectedStatus: http.StatusMovedPermanently,
			checkLocation:  true,
		},
		{
			name:           "HTTP request with no hosts configured",
			hosts:          []string{},
			requestHost:    "example.com",
			hasTLS:         false,
			expectedStatus: http.StatusBadRequest,
			checkLocation:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Listener{
				Name:     "test-listener",
				Port:     8080,
				Protocol: config.ProtocolHTTP,
				Hosts:    tt.hosts,
			}

			baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			listener, err := NewListener(cfg, baseHandler)
			require.NoError(t, err)

			middleware := listener.httpsRedirectMiddleware(baseHandler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Host = tt.requestHost
			if tt.hasTLS {
				req.TLS = &tls.ConnectionState{}
			}

			w := httptest.NewRecorder()
			middleware.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkLocation {
				location := w.Header().Get("Location")
				assert.Contains(t, location, "https://")
			}
		})
	}
}

func TestListener_Serve_WithTLSManager(t *testing.T) {
	t.Parallel()

	// This test verifies the serve function handles TLS correctly
	// We can't easily test the actual TLS serving without certificates,
	// but we can test the non-TLS path
	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler)
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)

	// Give it time to start serving
	time.Sleep(10 * time.Millisecond)

	assert.True(t, listener.IsRunning())

	err = listener.Stop(ctx)
	require.NoError(t, err)
}

func TestListener_Stop_WithTLSManager(t *testing.T) {
	t.Parallel()

	// Create a listener and manually set a TLS manager to test the close path
	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler)
	require.NoError(t, err)

	// Create a mock TLS manager
	tlsConfig := &tlspkg.Config{
		Mode: tlspkg.TLSModeInsecure,
	}
	manager, err := tlspkg.NewManager(tlsConfig)
	require.NoError(t, err)
	listener.tlsManager = manager

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)

	// Stop should close the TLS manager
	err = listener.Stop(ctx)
	require.NoError(t, err)
}

func TestListener_WithRouteTLSManager(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create a route TLS manager
	routeTLSManager := tlspkg.NewRouteTLSManager()
	defer routeTLSManager.Close()

	// Create listener with route TLS manager option
	listener, err := NewListener(cfg, handler, WithRouteTLSManager(routeTLSManager))
	require.NoError(t, err)

	// Verify the route TLS manager is set
	assert.Equal(t, routeTLSManager, listener.GetRouteTLSManager())
}

func TestListener_GetRouteTLSManager_Nil(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create listener without route TLS manager
	listener, err := NewListener(cfg, handler)
	require.NoError(t, err)

	// Verify the route TLS manager is nil
	assert.Nil(t, listener.GetRouteTLSManager())
}

func TestListener_IsRouteTLSEnabled_NoManager(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create listener without route TLS manager
	listener, err := NewListener(cfg, handler)
	require.NoError(t, err)

	// Should return false when no route TLS manager
	assert.False(t, listener.IsRouteTLSEnabled())
}

func TestListener_IsRouteTLSEnabled_EmptyManager(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create a route TLS manager with no routes
	routeTLSManager := tlspkg.NewRouteTLSManager()
	defer routeTLSManager.Close()

	// Create listener with empty route TLS manager
	listener, err := NewListener(cfg, handler, WithRouteTLSManager(routeTLSManager))
	require.NoError(t, err)

	// Should return false when route TLS manager has no routes
	assert.False(t, listener.IsRouteTLSEnabled())
}

func TestListener_IsRouteTLSEnabled_WithRoutes(t *testing.T) {
	t.Parallel()

	// Create test certificates using the helper
	certs, err := createListenerTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create a route TLS manager with a route
	routeTLSManager := tlspkg.NewRouteTLSManager()
	defer routeTLSManager.Close()

	// Add a route
	routeCfg := &tlspkg.RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	err = routeTLSManager.AddRoute("test-route", routeCfg)
	require.NoError(t, err)

	// Create listener with route TLS manager that has routes
	listener, err := NewListener(cfg, handler, WithRouteTLSManager(routeTLSManager))
	require.NoError(t, err)

	// Should return true when route TLS manager has routes
	assert.True(t, listener.IsRouteTLSEnabled())
}

// listenerTestCertificates holds test certificate data for listener tests.
type listenerTestCertificates struct {
	certFile string
	keyFile  string
	tempDir  string
}

// cleanup removes temporary test files.
func (tc *listenerTestCertificates) cleanup() {
	if tc.tempDir != "" {
		os.RemoveAll(tc.tempDir)
	}
}

func TestListener_WithVaultProviderFactory(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: config.ProtocolHTTP,
	}

	factory := func(_ *tlspkg.VaultTLSConfig, _ observability.Logger) (tlspkg.CertificateProvider, error) {
		return tlspkg.NewNopProvider(), nil
	}

	listener, err := NewListener(cfg,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		WithVaultProviderFactory(factory),
	)
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.NotNil(t, listener.vaultProviderFactory)
}

func TestListener_WithVaultProviderFactory_NilFactory(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: config.ProtocolHTTP,
	}

	listener, err := NewListener(cfg,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		WithVaultProviderFactory(nil),
	)
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Nil(t, listener.vaultProviderFactory)
}

func TestListener_InitTLS_WithVaultProviderFactory(t *testing.T) {
	t.Parallel()

	certs, err := createListenerTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	factory := func(_ *tlspkg.VaultTLSConfig, _ observability.Logger) (tlspkg.CertificateProvider, error) {
		return tlspkg.NewNopProvider(), nil
	}

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: config.ProtocolHTTPS,
		TLS: &config.ListenerTLSConfig{
			Mode:     "SIMPLE",
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	listener, err := NewListener(cfg,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		WithVaultProviderFactory(factory),
	)
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.NotNil(t, listener.tlsManager)
}

// createListenerTestCertificates creates test certificates for listener tests.
func createListenerTestCertificates(t *testing.T) (*listenerTestCertificates, error) {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "listener-tls-test-*")
	if err != nil {
		return nil, err
	}

	// Generate a self-signed certificate using crypto/ecdsa
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "api.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"api.example.com", "localhost"},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	return &listenerTestCertificates{
		certFile: certFile,
		keyFile:  keyFile,
		tempDir:  tempDir,
	}, nil
}
