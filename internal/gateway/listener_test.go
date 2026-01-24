package gateway

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewListener(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: "HTTP",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler)

	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, cfg, listener.config)
	assert.NotNil(t, listener.handler)
}

func TestNewListener_WithLogger(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: "HTTP",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	logger := observability.NopLogger()

	listener, err := NewListener(cfg, handler, WithListenerLogger(logger))

	require.NoError(t, err)
	assert.Equal(t, logger, listener.logger)
}

func TestListener_Name(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "my-listener",
		Port:     8080,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	assert.Equal(t, "my-listener", listener.Name())
}

func TestListener_Port(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     9090,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	assert.Equal(t, 9090, listener.Port())
}

func TestListener_Address(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   config.Listener
		expected string
	}{
		{
			name: "default bind address",
			config: config.Listener{
				Name:     "test",
				Port:     8080,
				Protocol: "HTTP",
			},
			expected: "0.0.0.0:8080",
		},
		{
			name: "custom bind address",
			config: config.Listener{
				Name:     "test",
				Port:     8080,
				Bind:     "127.0.0.1",
				Protocol: "HTTP",
			},
			expected: "127.0.0.1:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			listener, err := NewListener(tt.config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			require.NoError(t, err)

			assert.Equal(t, tt.expected, listener.Address())
		})
	}
}

func TestListener_IsRunning(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0, // Random port
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	assert.False(t, listener.IsRunning())
}

func TestListener_StartStop(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0, // Random port
		Protocol: "HTTP",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler)
	require.NoError(t, err)

	ctx := context.Background()

	// Start
	err = listener.Start(ctx)
	require.NoError(t, err)
	assert.True(t, listener.IsRunning())

	// Give it time to start
	time.Sleep(10 * time.Millisecond)

	// Stop
	err = listener.Stop(ctx)
	require.NoError(t, err)

	// Give it time to stop
	time.Sleep(10 * time.Millisecond)
	assert.False(t, listener.IsRunning())
}

func TestListener_Start_AlreadyRunning(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	ctx := context.Background()

	// Start first time
	err = listener.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = listener.Stop(ctx) }()

	// Try to start again
	err = listener.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestListener_Stop_NotRunning(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	ctx := context.Background()

	// Stop without starting - should be no-op
	err = listener.Stop(ctx)
	assert.NoError(t, err)
}

func TestListener_Start_InvalidPort(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     99999, // Invalid port
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	ctx := context.Background()

	err = listener.Start(ctx)
	assert.Error(t, err)
}

func TestListener_Stop_WithTimeout(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	ctx := context.Background()

	err = listener.Start(ctx)
	require.NoError(t, err)

	// Stop with timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err = listener.Stop(timeoutCtx)
	assert.NoError(t, err)
}

func TestListener_IsTLSEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     config.Listener
		tlsEnabled bool
	}{
		{
			name: "HTTP listener without TLS",
			config: config.Listener{
				Name:     "http-listener",
				Port:     8080,
				Protocol: "HTTP",
			},
			tlsEnabled: false,
		},
		{
			name: "HTTPS listener without TLS config",
			config: config.Listener{
				Name:     "https-listener",
				Port:     8443,
				Protocol: "HTTPS",
			},
			tlsEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			listener, err := NewListener(tt.config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			require.NoError(t, err)

			assert.Equal(t, tt.tlsEnabled, listener.IsTLSEnabled())
		})
	}
}

func TestListener_GetTLSManager(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	// HTTP listener should not have TLS manager
	assert.Nil(t, listener.GetTLSManager())
}

func TestListener_WithTLSMetrics(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: "HTTP",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	listener, err := NewListener(cfg, handler, WithTLSMetrics(nil))
	require.NoError(t, err)
	assert.NotNil(t, listener)
}

func TestListener_ConvertToTLSConfig_Nil(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	// Test that nil TLS config returns nil
	result := listener.convertToTLSConfig(nil)
	assert.Nil(t, result)
}

func TestListener_ConvertToTLSConfig_Basic(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: "HTTPS",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	tlsCfg := &config.ListenerTLSConfig{
		Mode:       "SIMPLE",
		MinVersion: "TLS12",
		MaxVersion: "TLS13",
		CertFile:   "/path/to/cert.pem",
		KeyFile:    "/path/to/key.pem",
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)
	assert.Equal(t, "SIMPLE", string(result.Mode))
	assert.Equal(t, "TLS12", string(result.MinVersion))
	assert.Equal(t, "TLS13", string(result.MaxVersion))
	assert.NotNil(t, result.ServerCertificate)
	assert.Equal(t, "/path/to/cert.pem", result.ServerCertificate.CertFile)
	assert.Equal(t, "/path/to/key.pem", result.ServerCertificate.KeyFile)
}

func TestListener_ConvertToTLSConfig_WithClientValidation(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: "HTTPS",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	tlsCfg := &config.ListenerTLSConfig{
		Mode:              "MUTUAL",
		CertFile:          "/path/to/cert.pem",
		KeyFile:           "/path/to/key.pem",
		CAFile:            "/path/to/ca.pem",
		RequireClientCert: true,
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)
	assert.NotNil(t, result.ClientValidation)
	assert.True(t, result.ClientValidation.Enabled)
	assert.Equal(t, "/path/to/ca.pem", result.ClientValidation.CAFile)
	assert.True(t, result.ClientValidation.RequireClientCert)
}

func TestListener_ConvertToTLSConfig_WithVault(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: "HTTPS",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	tlsCfg := &config.ListenerTLSConfig{
		Mode: "SIMPLE",
		Vault: &config.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "example.com",
			AltNames:   []string{"www.example.com"},
		},
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)
	assert.NotNil(t, result.Vault)
	assert.True(t, result.Vault.Enabled)
	assert.Equal(t, "pki", result.Vault.PKIMount)
	assert.Equal(t, "my-role", result.Vault.Role)
	assert.Equal(t, "example.com", result.Vault.CommonName)
	assert.Equal(t, []string{"www.example.com"}, result.Vault.AltNames)
}

func TestListener_ConvertToTLSConfig_WithALPN(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: "HTTPS",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	tlsCfg := &config.ListenerTLSConfig{
		Mode:     "SIMPLE",
		CertFile: "/path/to/cert.pem",
		KeyFile:  "/path/to/key.pem",
		ALPN:     []string{"h2", "http/1.1"},
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)
	assert.Equal(t, []string{"h2", "http/1.1"}, result.ALPN)
}

func TestListener_ConvertToTLSConfig_WithCipherSuites(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: "HTTPS",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	tlsCfg := &config.ListenerTLSConfig{
		Mode:         "SIMPLE",
		CertFile:     "/path/to/cert.pem",
		KeyFile:      "/path/to/key.pem",
		CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)
	assert.Equal(t, []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}, result.CipherSuites)
}

func TestListener_ConvertToTLSConfig_InsecureSkipVerify(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8443,
		Protocol: "HTTPS",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	tlsCfg := &config.ListenerTLSConfig{
		Mode:               "SIMPLE",
		CertFile:           "/path/to/cert.pem",
		KeyFile:            "/path/to/key.pem",
		InsecureSkipVerify: true,
	}

	result := listener.convertToTLSConfig(tlsCfg)
	require.NotNil(t, result)
	assert.True(t, result.InsecureSkipVerify)
}
