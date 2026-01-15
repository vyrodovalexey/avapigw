// Package tls provides the TLS server implementation for the API Gateway.
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
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
)

// generateServerTestCertificate generates a self-signed certificate for testing.
func generateServerTestCertificate(hostname string) (certPEM, keyPEM []byte, err error) {
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

// writeServerTempCertFiles writes certificate and key to temporary files.
func writeServerTempCertFiles(t *testing.T, certPEM, keyPEM []byte) (certFile, keyFile string) {
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

func TestDefaultServerConfig(t *testing.T) {
	config := DefaultServerConfig()

	require.NotNil(t, config)
	assert.Equal(t, 8443, config.Port)
	assert.Equal(t, "", config.Address)
	assert.Equal(t, TLSModePassthrough, config.Mode)
	assert.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
	assert.NotEmpty(t, config.CipherSuites)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Equal(t, 30*time.Second, config.ReadTimeout)
	assert.Equal(t, 30*time.Second, config.WriteTimeout)
	assert.Equal(t, 5*time.Minute, config.IdleTimeout)
	assert.Equal(t, 10000, config.MaxConnections)
	assert.Equal(t, 30*time.Second, config.ConnectTimeout)
	assert.Equal(t, DefaultTLSShutdownTimeout, config.ShutdownTimeout)
	assert.Equal(t, DefaultTLSAcceptDeadline, config.AcceptDeadline)
}

func TestNewServer(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name   string
		config *ServerConfig
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
		},
		{
			name: "custom config",
			config: &ServerConfig{
				Port:           9443,
				Address:        "127.0.0.1",
				Mode:           TLSModeTerminate,
				MaxConnections: 5000,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(tt.config, logger)

			require.NotNil(t, server)
			assert.NotNil(t, server.router)
			assert.NotNil(t, server.certManager)
			assert.NotNil(t, server.connections)
			assert.NotNil(t, server.stopCh)
			assert.Equal(t, logger, server.logger)
			assert.Nil(t, server.proxy) // No proxy without backend manager
		})
	}
}

func TestNewServerWithBackend(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	tests := []struct {
		name   string
		config *ServerConfig
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
		},
		{
			name: "custom config",
			config: &ServerConfig{
				Port:           9443,
				Address:        "127.0.0.1",
				Mode:           TLSModePassthrough,
				MaxConnections: 5000,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServerWithBackend(tt.config, manager, logger)

			require.NotNil(t, server)
			assert.NotNil(t, server.router)
			assert.NotNil(t, server.certManager)
			assert.NotNil(t, server.connections)
			assert.NotNil(t, server.proxy) // Proxy should be set
			assert.NotNil(t, server.stopCh)
			assert.Equal(t, logger, server.logger)
		})
	}
}

func TestServer_SetProxy(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	// Initially no proxy
	assert.Nil(t, server.GetProxy())

	// Set proxy
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)
	server.SetProxy(proxy)

	// Verify proxy is set
	assert.Equal(t, proxy, server.GetProxy())
}

func TestServer_GetRouter(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	router := server.GetRouter()

	require.NotNil(t, router)
}

func TestServer_GetProxy(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		withBackend bool
		expectNil   bool
	}{
		{
			name:        "without backend",
			withBackend: false,
			expectNil:   true,
		},
		{
			name:        "with backend",
			withBackend: true,
			expectNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *Server
			if tt.withBackend {
				manager := backend.NewManager(logger)
				server = NewServerWithBackend(nil, manager, logger)
			} else {
				server = NewServer(nil, logger)
			}

			proxy := server.GetProxy()

			if tt.expectNil {
				assert.Nil(t, proxy)
			} else {
				assert.NotNil(t, proxy)
			}
		})
	}
}

func TestServer_GetCertificateManager(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	certManager := server.GetCertificateManager()

	require.NotNil(t, certManager)
}

func TestServer_GetConnectionTracker(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	tracker := server.GetConnectionTracker()

	require.NotNil(t, tracker)
}

func TestServer_IsRunning(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	// Initially not running
	assert.False(t, server.IsRunning())
}

func TestServer_UpdateRoutes(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	tests := []struct {
		name        string
		routes      []TLSRouteConfig
		expectError bool
	}{
		{
			name: "add new routes",
			routes: []TLSRouteConfig{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			expectError: false,
		},
		{
			name: "update existing route",
			routes: []TLSRouteConfig{
				{
					Name:      "route1",
					Hostnames: []string{"updated.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend2", Port: 8443},
					},
				},
			},
			expectError: false,
		},
		{
			name: "add multiple routes",
			routes: []TLSRouteConfig{
				{
					Name:      "route2",
					Hostnames: []string{"example.org"},
				},
				{
					Name:      "route3",
					Hostnames: []string{"example.net"},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := server.UpdateRoutes(tt.routes)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				// Verify routes were added/updated
				for _, routeConfig := range tt.routes {
					route := server.router.GetRoute(routeConfig.Name)
					require.NotNil(t, route)
					assert.Equal(t, routeConfig.Hostnames, route.Hostnames)
				}
			}
		})
	}
}

func TestServer_RemoveRoute(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	// Add a route first
	err := server.UpdateRoutes([]TLSRouteConfig{
		{
			Name:      "route1",
			Hostnames: []string{"example.com"},
		},
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		routeName   string
		expectError bool
	}{
		{
			name:        "remove existing route",
			routeName:   "route1",
			expectError: false,
		},
		{
			name:        "remove non-existent route",
			routeName:   "non-existent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := server.RemoveRoute(tt.routeName)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				// Verify route was removed
				route := server.router.GetRoute(tt.routeName)
				assert.Nil(t, route)
			}
		})
	}
}

func TestServer_GetActiveConnections(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	// Initially no connections
	count := server.GetActiveConnections()
	assert.Equal(t, 0, count)
}

func TestServer_ListActiveConnections(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	// Initially no connections
	connections := server.ListActiveConnections()
	assert.Empty(t, connections)
}

func TestServer_LoadCertificate(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

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
			var certFile, keyFile string
			if tt.setupCert {
				certPEM, keyPEM, err := generateServerTestCertificate(tt.hostname)
				require.NoError(t, err)
				certFile, keyFile = writeServerTempCertFiles(t, certPEM, keyPEM)
			} else {
				certFile = "/non/existent/cert.pem"
				keyFile = "/non/existent/key.pem"
			}

			err := server.LoadCertificate(tt.hostname, certFile, keyFile)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestServer_LoadCertificateFromSecret(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

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
			var certData, keyData []byte
			if tt.validCert {
				var err error
				certData, keyData, err = generateServerTestCertificate(tt.hostname)
				require.NoError(t, err)
			} else {
				certData = []byte("invalid cert")
				keyData = []byte("invalid key")
			}

			err := server.LoadCertificateFromSecret(tt.hostname, certData, keyData)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestServer_SetDefaultCertificate(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	tests := []struct {
		name          string
		setupCert     bool
		expectError   bool
		errorContains string
	}{
		{
			name:        "set valid default certificate",
			setupCert:   true,
			expectError: false,
		},
		{
			name:          "set non-existent default certificate",
			setupCert:     false,
			expectError:   true,
			errorContains: "failed to load default certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var certFile, keyFile string
			if tt.setupCert {
				certPEM, keyPEM, err := generateServerTestCertificate("default.com")
				require.NoError(t, err)
				certFile, keyFile = writeServerTempCertFiles(t, certPEM, keyPEM)
			} else {
				certFile = "/non/existent/cert.pem"
				keyFile = "/non/existent/key.pem"
			}

			err := server.SetDefaultCertificate(certFile, keyFile)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestServer_buildTLSConfig(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name   string
		config *ServerConfig
	}{
		{
			name:   "default config",
			config: DefaultServerConfig(),
		},
		{
			name: "custom cipher suites",
			config: &ServerConfig{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				},
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
		},
		{
			name: "empty cipher suites",
			config: &ServerConfig{
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS13,
				CipherSuites: []uint16{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(tt.config, logger)

			tlsConfig := server.buildTLSConfig()

			require.NotNil(t, tlsConfig)
			assert.NotNil(t, tlsConfig.GetCertificate)
			assert.Equal(t, tt.config.MinVersion, tlsConfig.MinVersion)
			assert.Equal(t, tt.config.MaxVersion, tlsConfig.MaxVersion)
			assert.Equal(t, tt.config.ClientAuth, tlsConfig.ClientAuth)

			if len(tt.config.CipherSuites) > 0 {
				assert.Equal(t, tt.config.CipherSuites, tlsConfig.CipherSuites)
			}
		})
	}
}

func TestServer_buildTLSConfig_WithDefaultCert(t *testing.T) {
	logger := zap.NewNop()

	// Generate test certificate
	certPEM, keyPEM, err := generateServerTestCertificate("default.com")
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	config := &ServerConfig{
		MinVersion:  tls.VersionTLS12,
		MaxVersion:  tls.VersionTLS13,
		DefaultCert: &cert,
	}

	server := NewServer(config, logger)

	tlsConfig := server.buildTLSConfig()

	require.NotNil(t, tlsConfig)
	assert.Len(t, tlsConfig.Certificates, 1)
}

func TestServer_StartStop(t *testing.T) {
	logger := zap.NewNop()

	// Use a random available port
	config := &ServerConfig{
		Port:            0, // Let the system assign a port
		Address:         "127.0.0.1",
		Mode:            TLSModePassthrough,
		MaxConnections:  100,
		ShutdownTimeout: 1 * time.Second,
		AcceptDeadline:  100 * time.Millisecond,
	}

	server := NewServer(config, logger)

	// Start server in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErr := make(chan error, 1)
	go func() {
		startErr <- server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Verify server is running
	assert.True(t, server.IsRunning())

	// Stop server
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()

	err := server.Stop(stopCtx)
	require.NoError(t, err)

	// Verify server is stopped
	assert.False(t, server.IsRunning())

	// Cancel context to clean up
	cancel()

	// Wait for start goroutine to finish
	select {
	case err := <-startErr:
		// Expected - either nil or context.Canceled
		if err != nil {
			assert.Equal(t, context.Canceled, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to stop")
	}
}

func TestServer_StartAlreadyRunning(t *testing.T) {
	logger := zap.NewNop()

	config := &ServerConfig{
		Port:           0,
		Address:        "127.0.0.1",
		Mode:           TLSModePassthrough,
		AcceptDeadline: 100 * time.Millisecond,
	}

	server := NewServer(config, logger)

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Try to start again
	err := server.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server already running")

	// Clean up
	cancel()
	_ = server.Stop(context.Background())
}

func TestServer_StopNotRunning(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	// Stop server that's not running
	err := server.Stop(context.Background())
	require.NoError(t, err)
}

func TestServer_TLSModes(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name string
		mode TLSMode
	}{
		{
			name: "passthrough mode",
			mode: TLSModePassthrough,
		},
		{
			name: "terminate mode",
			mode: TLSModeTerminate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ServerConfig{
				Port:           0,
				Address:        "127.0.0.1",
				Mode:           tt.mode,
				AcceptDeadline: 100 * time.Millisecond,
			}

			server := NewServer(config, logger)
			assert.Equal(t, tt.mode, server.config.Mode)
		})
	}
}

func TestServer_ConnectionTracking(t *testing.T) {
	logger := zap.NewNop()

	config := &ServerConfig{
		Port:           0,
		Address:        "127.0.0.1",
		Mode:           TLSModePassthrough,
		MaxConnections: 100,
		AcceptDeadline: 100 * time.Millisecond,
	}

	server := NewServer(config, logger)

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Get listener address
	server.mu.RLock()
	listener := server.listener
	server.mu.RUnlock()

	if listener == nil {
		t.Skip("Server listener not available")
	}

	addr := listener.Addr().String()

	// Connect to server
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Skipf("Could not connect to server: %v", err)
	}
	defer conn.Close()

	// Wait a bit for connection to be tracked
	time.Sleep(100 * time.Millisecond)

	// Check active connections
	count := server.GetActiveConnections()
	// Connection might be closed quickly due to invalid TLS handshake
	t.Logf("Active connections: %d", count)

	// Clean up
	cancel()
	_ = server.Stop(context.Background())
}

func TestTLSRouteConfig(t *testing.T) {
	config := TLSRouteConfig{
		Name:      "test-route",
		Hostnames: []string{"example.com", "*.example.org"},
		BackendRefs: []TLSBackendRef{
			{
				Name:      "backend1",
				Namespace: "default",
				Port:      443,
				Weight:    100,
			},
		},
		Priority: 10,
	}

	assert.Equal(t, "test-route", config.Name)
	assert.Len(t, config.Hostnames, 2)
	assert.Len(t, config.BackendRefs, 1)
	assert.Equal(t, 10, config.Priority)
}

func TestTLSBackendRef(t *testing.T) {
	ref := TLSBackendRef{
		Name:      "backend1",
		Namespace: "default",
		Port:      443,
		Weight:    100,
	}

	assert.Equal(t, "backend1", ref.Name)
	assert.Equal(t, "default", ref.Namespace)
	assert.Equal(t, 443, ref.Port)
	assert.Equal(t, 100, ref.Weight)
}

func TestServer_Constants(t *testing.T) {
	assert.Equal(t, 500*time.Millisecond, DefaultTLSAcceptDeadline)
	assert.Equal(t, 30*time.Second, DefaultTLSShutdownTimeout)
}

func TestTLSMode_Values(t *testing.T) {
	assert.Equal(t, TLSMode("Terminate"), TLSModeTerminate)
	assert.Equal(t, TLSMode("Passthrough"), TLSModePassthrough)
}

func TestServer_ConcurrentOperations(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	// Concurrent route operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			routes := []TLSRouteConfig{
				{
					Name:      "route-" + string(rune('a'+idx)),
					Hostnames: []string{"host-" + string(rune('a'+idx)) + ".example.com"},
				},
			}
			_ = server.UpdateRoutes(routes)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify routes were added
	routeNames := server.router.ListRoutes()
	assert.NotEmpty(t, routeNames)
}

func TestServer_GracefulShutdown(t *testing.T) {
	logger := zap.NewNop()

	config := &ServerConfig{
		Port:            0,
		Address:         "127.0.0.1",
		Mode:            TLSModePassthrough,
		MaxConnections:  100,
		ShutdownTimeout: 2 * time.Second,
		AcceptDeadline:  100 * time.Millisecond,
	}

	server := NewServer(config, logger)

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErr := make(chan error, 1)
	go func() {
		startErr <- server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Verify server is running
	require.True(t, server.IsRunning())

	// Stop server with context
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()

	err := server.Stop(stopCtx)
	require.NoError(t, err)

	// Verify server is stopped
	assert.False(t, server.IsRunning())

	// Cancel start context
	cancel()

	// Wait for start to complete
	select {
	case <-startErr:
		// Expected
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server start to complete")
	}
}

func TestServer_StopWithNilContext(t *testing.T) {
	logger := zap.NewNop()

	config := &ServerConfig{
		Port:            0,
		Address:         "127.0.0.1",
		Mode:            TLSModePassthrough,
		MaxConnections:  100,
		ShutdownTimeout: 1 * time.Second,
		AcceptDeadline:  100 * time.Millisecond,
	}

	server := NewServer(config, logger)

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Stop server with nil context
	err := server.Stop(nil)
	require.NoError(t, err)

	// Verify server is stopped
	assert.False(t, server.IsRunning())

	cancel()
}

func TestServer_TerminateMode(t *testing.T) {
	logger := zap.NewNop()

	// Generate test certificate
	certPEM, keyPEM, err := generateServerTestCertificate("localhost")
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	config := &ServerConfig{
		Port:            0,
		Address:         "127.0.0.1",
		Mode:            TLSModeTerminate,
		DefaultCert:     &cert,
		MaxConnections:  100,
		ShutdownTimeout: 1 * time.Second,
		AcceptDeadline:  100 * time.Millisecond,
	}

	server := NewServer(config, logger)

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Verify server is running
	assert.True(t, server.IsRunning())

	// Stop server
	err = server.Stop(context.Background())
	require.NoError(t, err)

	cancel()
}

func TestServer_HandleConnection_ContextCancelled(t *testing.T) {
	logger := zap.NewNop()

	config := &ServerConfig{
		Port:            0,
		Address:         "127.0.0.1",
		Mode:            TLSModePassthrough,
		MaxConnections:  100,
		ShutdownTimeout: 1 * time.Second,
		AcceptDeadline:  100 * time.Millisecond,
	}

	server := NewServer(config, logger)

	// Start server
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		_ = server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Get listener address
	server.mu.RLock()
	listener := server.listener
	server.mu.RUnlock()

	if listener == nil {
		t.Skip("Server listener not available")
	}

	addr := listener.Addr().String()

	// Connect to server
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Skipf("Could not connect to server: %v", err)
	}

	// Cancel context immediately
	cancel()

	// Wait a bit for connection to be handled
	time.Sleep(100 * time.Millisecond)

	// Close connection
	conn.Close()

	// Stop server
	_ = server.Stop(context.Background())
}

func TestServer_UpdateRoutes_AddAndUpdate(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	// Add initial route
	routes := []TLSRouteConfig{
		{
			Name:      "route1",
			Hostnames: []string{"example.com"},
			BackendRefs: []TLSBackendRef{
				{Name: "backend1", Port: 443},
			},
		},
	}

	err := server.UpdateRoutes(routes)
	require.NoError(t, err)

	// Update the same route
	routes[0].Hostnames = []string{"updated.com"}
	err = server.UpdateRoutes(routes)
	require.NoError(t, err)

	// Verify route was updated
	route := server.router.GetRoute("route1")
	require.NotNil(t, route)
	assert.Equal(t, []string{"updated.com"}, route.Hostnames)
}

func TestServer_setAcceptDeadline_NonTCPListener(t *testing.T) {
	logger := zap.NewNop()
	server := NewServer(nil, logger)

	// Create a mock listener that doesn't support SetDeadline
	mockListener := &mockListener{}
	server.listener = mockListener

	// Should not return error for unsupported listener
	err := server.setAcceptDeadline(100 * time.Millisecond)
	assert.NoError(t, err)
}

// mockListener is a mock net.Listener that doesn't support SetDeadline
type mockListener struct{}

func (m *mockListener) Accept() (net.Conn, error) {
	return nil, nil
}

func (m *mockListener) Close() error {
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}
}

func TestServer_DoubleStop(t *testing.T) {
	logger := zap.NewNop()

	config := &ServerConfig{
		Port:            0,
		Address:         "127.0.0.1",
		Mode:            TLSModePassthrough,
		MaxConnections:  100,
		ShutdownTimeout: 1 * time.Second,
		AcceptDeadline:  100 * time.Millisecond,
	}

	server := NewServer(config, logger)

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Stop server twice
	err := server.Stop(context.Background())
	require.NoError(t, err)

	err = server.Stop(context.Background())
	require.NoError(t, err)

	cancel()
}
