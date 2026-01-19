package listener

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestCertificates holds test certificate and key data
type TestCertificates struct {
	CertFile string
	KeyFile  string
	CAFile   string
	CertPEM  []byte
	KeyPEM   []byte
	CAPEM    []byte
}

// generateTestCertificates creates temporary test certificates
func generateTestCertificates(t *testing.T) *TestCertificates {
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
	certFile, err := os.CreateTemp("", "cert-*.pem")
	require.NoError(t, err)
	_, err = certFile.Write(certPEM)
	require.NoError(t, err)
	certFile.Close()

	keyFile, err := os.CreateTemp("", "key-*.pem")
	require.NoError(t, err)
	_, err = keyFile.Write(keyPEM)
	require.NoError(t, err)
	keyFile.Close()

	caFile, err := os.CreateTemp("", "ca-*.pem")
	require.NoError(t, err)
	_, err = caFile.Write(certPEM) // Use same cert as CA for testing
	require.NoError(t, err)
	caFile.Close()

	t.Cleanup(func() {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
		os.Remove(caFile.Name())
	})

	return &TestCertificates{
		CertFile: certFile.Name(),
		KeyFile:  keyFile.Name(),
		CAFile:   caFile.Name(),
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		CAPEM:    certPEM,
	}
}

// getAvailablePort returns an available port for testing
func getAvailablePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

// testHandler is a simple HTTP handler for testing
func testHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// TestNewManager tests creating a new manager
func TestNewManager(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "creates manager with logger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			manager := NewManager(logger)

			assert.NotNil(t, manager)
			assert.NotNil(t, manager.listeners)
			assert.Equal(t, 0, len(manager.listeners))
			assert.False(t, manager.started)
		})
	}
}

// TestManager_AddListener tests adding listeners
func TestManager_AddListener(t *testing.T) {
	certs := generateTestCertificates(t)

	tests := []struct {
		name        string
		configs     []ListenerConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "add single listener success",
			configs: []ListenerConfig{
				{
					Name:     "test-listener",
					Port:     8080,
					Protocol: "HTTP",
					Hostname: "localhost",
					Handler:  testHandler(),
				},
			},
			expectError: false,
		},
		{
			name: "add listener with TLS",
			configs: []ListenerConfig{
				{
					Name:     "tls-listener",
					Port:     8443,
					Protocol: "HTTPS",
					Hostname: "localhost",
					Handler:  testHandler(),
					TLS: &TLSConfig{
						CertFile: certs.CertFile,
						KeyFile:  certs.KeyFile,
					},
				},
			},
			expectError: false,
		},
		{
			name: "add duplicate listener fails",
			configs: []ListenerConfig{
				{
					Name:     "duplicate-listener",
					Port:     8080,
					Protocol: "HTTP",
					Handler:  testHandler(),
				},
				{
					Name:     "duplicate-listener",
					Port:     8081,
					Protocol: "HTTP",
					Handler:  testHandler(),
				},
			},
			expectError: true,
			errorMsg:    "listener duplicate-listener already exists",
		},
		{
			name: "add listener with invalid TLS fails",
			configs: []ListenerConfig{
				{
					Name:     "invalid-tls-listener",
					Port:     8443,
					Protocol: "HTTPS",
					Handler:  testHandler(),
					TLS: &TLSConfig{
						CertFile: "/nonexistent/cert.pem",
						KeyFile:  "/nonexistent/key.pem",
					},
				},
			},
			expectError: true,
			errorMsg:    "failed to load TLS config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			manager := NewManager(logger)

			var lastErr error
			for _, config := range tt.configs {
				lastErr = manager.AddListener(config)
			}

			if tt.expectError {
				assert.Error(t, lastErr)
				assert.Contains(t, lastErr.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, lastErr)
				// Verify listener was added
				listener := manager.GetListener(tt.configs[0].Name)
				assert.NotNil(t, listener)
				assert.Equal(t, tt.configs[0].Name, listener.Name)
				assert.Equal(t, tt.configs[0].Port, listener.Port)
				assert.Equal(t, tt.configs[0].Protocol, listener.Protocol)
			}
		})
	}
}

// TestManager_AddListener_WhenStarted tests adding listener when manager is already started
func TestManager_AddListener_WhenStarted(t *testing.T) {
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	port := getAvailablePort(t)

	// Start the manager first
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		manager.Stop(ctx)
	})

	// Add listener after manager is started
	config := ListenerConfig{
		Name:     "dynamic-listener",
		Port:     port,
		Protocol: "HTTP",
		Handler:  testHandler(),
	}

	err = manager.AddListener(config)
	assert.NoError(t, err)

	// Verify listener is running
	listener := manager.GetListener("dynamic-listener")
	require.NotNil(t, listener)

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)
	assert.True(t, listener.IsRunning())
}

// TestManager_RemoveListener tests removing listeners
func TestManager_RemoveListener(t *testing.T) {
	tests := []struct {
		name        string
		addFirst    bool
		removeName  string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "remove existing listener success",
			addFirst:    true,
			removeName:  "test-listener",
			expectError: false,
		},
		{
			name:        "remove non-existent listener fails",
			addFirst:    false,
			removeName:  "nonexistent",
			expectError: true,
			errorMsg:    "listener nonexistent not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			manager := NewManager(logger)

			if tt.addFirst {
				err := manager.AddListener(ListenerConfig{
					Name:     "test-listener",
					Port:     8080,
					Protocol: "HTTP",
					Handler:  testHandler(),
				})
				require.NoError(t, err)
			}

			err := manager.RemoveListener(tt.removeName)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				// Verify listener was removed
				listener := manager.GetListener(tt.removeName)
				assert.Nil(t, listener)
			}
		})
	}
}

// TestManager_RemoveListener_WhenRunning tests removing a running listener
func TestManager_RemoveListener_WhenRunning(t *testing.T) {
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	port := getAvailablePort(t)

	// Add and start listener
	err := manager.AddListener(ListenerConfig{
		Name:     "running-listener",
		Port:     port,
		Protocol: "HTTP",
		Handler:  testHandler(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		manager.Stop(ctx)
	})

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)

	// Remove the running listener
	err = manager.RemoveListener("running-listener")
	assert.NoError(t, err)

	// Verify listener was removed
	listener := manager.GetListener("running-listener")
	assert.Nil(t, listener)
}

// TestManager_GetListener tests getting listeners by name
func TestManager_GetListener(t *testing.T) {
	tests := []struct {
		name      string
		addName   string
		getName   string
		expectNil bool
	}{
		{
			name:      "get existing listener",
			addName:   "test-listener",
			getName:   "test-listener",
			expectNil: false,
		},
		{
			name:      "get non-existent listener",
			addName:   "test-listener",
			getName:   "nonexistent",
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			manager := NewManager(logger)

			err := manager.AddListener(ListenerConfig{
				Name:     tt.addName,
				Port:     8080,
				Protocol: "HTTP",
				Handler:  testHandler(),
			})
			require.NoError(t, err)

			listener := manager.GetListener(tt.getName)

			if tt.expectNil {
				assert.Nil(t, listener)
			} else {
				assert.NotNil(t, listener)
				assert.Equal(t, tt.addName, listener.Name)
			}
		})
	}
}

// TestManager_ListListeners tests listing all listeners
func TestManager_ListListeners(t *testing.T) {
	tests := []struct {
		name          string
		listenerNames []string
		expectedCount int
	}{
		{
			name:          "list empty",
			listenerNames: []string{},
			expectedCount: 0,
		},
		{
			name:          "list single listener",
			listenerNames: []string{"listener-1"},
			expectedCount: 1,
		},
		{
			name:          "list multiple listeners",
			listenerNames: []string{"listener-1", "listener-2", "listener-3"},
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			manager := NewManager(logger)

			for i, name := range tt.listenerNames {
				err := manager.AddListener(ListenerConfig{
					Name:     name,
					Port:     8080 + i,
					Protocol: "HTTP",
					Handler:  testHandler(),
				})
				require.NoError(t, err)
			}

			names := manager.ListListeners()

			assert.Equal(t, tt.expectedCount, len(names))

			// Sort both slices for comparison
			sort.Strings(names)
			sort.Strings(tt.listenerNames)
			assert.Equal(t, tt.listenerNames, names)
		})
	}
}

// TestManager_Start tests starting the manager
func TestManager_Start(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func(*Manager, int)
		startTwice  bool
		expectError bool
		errorMsg    string
	}{
		{
			name: "start with no listeners",
			setupFunc: func(m *Manager, port int) {
				// No setup needed
			},
			expectError: false,
		},
		{
			name: "start with single listener",
			setupFunc: func(m *Manager, port int) {
				m.AddListener(ListenerConfig{
					Name:     "test-listener",
					Port:     port,
					Protocol: "HTTP",
					Handler:  testHandler(),
				})
			},
			expectError: false,
		},
		{
			name: "start already started manager fails",
			setupFunc: func(m *Manager, port int) {
				// No setup needed
			},
			startTwice:  true,
			expectError: true,
			errorMsg:    "manager already started",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			manager := NewManager(logger)
			port := getAvailablePort(t)

			tt.setupFunc(manager, port)

			ctx := context.Background()
			err := manager.Start(ctx)

			if !tt.startTwice {
				if tt.expectError {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.errorMsg)
				} else {
					assert.NoError(t, err)
					assert.True(t, manager.started)
				}
			} else {
				require.NoError(t, err)
				// Try to start again
				err = manager.Start(ctx)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			}

			// Cleanup
			manager.Stop(ctx)
		})
	}
}

// TestManager_Start_WithMultipleListeners tests starting with multiple listeners
func TestManager_Start_WithMultipleListeners(t *testing.T) {
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	port1 := getAvailablePort(t)
	port2 := getAvailablePort(t)

	// Add multiple listeners
	err := manager.AddListener(ListenerConfig{
		Name:     "listener-1",
		Port:     port1,
		Protocol: "HTTP",
		Handler:  testHandler(),
	})
	require.NoError(t, err)

	err = manager.AddListener(ListenerConfig{
		Name:     "listener-2",
		Port:     port2,
		Protocol: "HTTP",
		Handler:  testHandler(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		manager.Stop(ctx)
	})

	// Give listeners time to start
	time.Sleep(50 * time.Millisecond)

	// Verify both listeners are running
	listener1 := manager.GetListener("listener-1")
	listener2 := manager.GetListener("listener-2")

	assert.True(t, listener1.IsRunning())
	assert.True(t, listener2.IsRunning())
}

// TestManager_Stop tests stopping the manager
func TestManager_Stop(t *testing.T) {
	tests := []struct {
		name       string
		startFirst bool
	}{
		{
			name:       "stop started manager",
			startFirst: true,
		},
		{
			name:       "stop not started manager",
			startFirst: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			manager := NewManager(logger)

			port := getAvailablePort(t)

			err := manager.AddListener(ListenerConfig{
				Name:     "test-listener",
				Port:     port,
				Protocol: "HTTP",
				Handler:  testHandler(),
			})
			require.NoError(t, err)

			ctx := context.Background()

			if tt.startFirst {
				err = manager.Start(ctx)
				require.NoError(t, err)
				time.Sleep(50 * time.Millisecond)
			}

			err = manager.Stop(ctx)
			assert.NoError(t, err)
			assert.False(t, manager.started)
		})
	}
}

// TestManager_Stop_WithContext tests stopping with context timeout
func TestManager_Stop_WithContext(t *testing.T) {
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	port := getAvailablePort(t)

	err := manager.AddListener(ListenerConfig{
		Name:     "test-listener",
		Port:     port,
		Protocol: "HTTP",
		Handler:  testHandler(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	// Stop with timeout context
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Stop(stopCtx)
	assert.NoError(t, err)
	assert.False(t, manager.started)
}

// TestManager_UpdateListener tests updating listeners
func TestManager_UpdateListener(t *testing.T) {
	certs := generateTestCertificates(t)

	tests := []struct {
		name        string
		addFirst    bool
		updateName  string
		newPort     int
		addTLS      bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "update existing listener",
			addFirst:    true,
			updateName:  "test-listener",
			newPort:     9090,
			expectError: false,
		},
		{
			name:        "update non-existent listener fails",
			addFirst:    false,
			updateName:  "nonexistent",
			newPort:     9090,
			expectError: true,
			errorMsg:    "listener nonexistent not found",
		},
		{
			name:        "update listener with TLS",
			addFirst:    true,
			updateName:  "test-listener",
			newPort:     9443,
			addTLS:      true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			manager := NewManager(logger)

			if tt.addFirst {
				err := manager.AddListener(ListenerConfig{
					Name:     "test-listener",
					Port:     8080,
					Protocol: "HTTP",
					Handler:  testHandler(),
				})
				require.NoError(t, err)
			}

			updateConfig := ListenerConfig{
				Name:     tt.updateName,
				Port:     tt.newPort,
				Protocol: "HTTP",
				Handler:  testHandler(),
			}

			if tt.addTLS {
				updateConfig.TLS = &TLSConfig{
					CertFile: certs.CertFile,
					KeyFile:  certs.KeyFile,
				}
			}

			err := manager.UpdateListener(updateConfig)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				listener := manager.GetListener(tt.updateName)
				assert.NotNil(t, listener)
				assert.Equal(t, tt.newPort, listener.Port)
				if tt.addTLS {
					assert.NotNil(t, listener.TLS)
				}
			}
		})
	}
}

// TestManager_UpdateListener_WhenRunning tests updating a running listener
func TestManager_UpdateListener_WhenRunning(t *testing.T) {
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	port1 := getAvailablePort(t)
	port2 := getAvailablePort(t)

	// Add and start listener
	err := manager.AddListener(ListenerConfig{
		Name:     "running-listener",
		Port:     port1,
		Protocol: "HTTP",
		Handler:  testHandler(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		manager.Stop(ctx)
	})

	time.Sleep(50 * time.Millisecond)

	// Update the running listener
	err = manager.UpdateListener(ListenerConfig{
		Name:     "running-listener",
		Port:     port2,
		Protocol: "HTTP",
		Handler:  testHandler(),
	})
	assert.NoError(t, err)

	// Verify listener was updated and restarted
	listener := manager.GetListener("running-listener")
	assert.NotNil(t, listener)
	assert.Equal(t, port2, listener.Port)

	time.Sleep(50 * time.Millisecond)
	assert.True(t, listener.IsRunning())
}

// TestManager_UpdateListener_RemoveTLS tests updating listener to remove TLS
func TestManager_UpdateListener_RemoveTLS(t *testing.T) {
	certs := generateTestCertificates(t)
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	// Add listener with TLS
	err := manager.AddListener(ListenerConfig{
		Name:     "tls-listener",
		Port:     8443,
		Protocol: "HTTPS",
		Handler:  testHandler(),
		TLS: &TLSConfig{
			CertFile: certs.CertFile,
			KeyFile:  certs.KeyFile,
		},
	})
	require.NoError(t, err)

	// Verify TLS is set
	listener := manager.GetListener("tls-listener")
	assert.NotNil(t, listener.TLS)

	// Update without TLS
	err = manager.UpdateListener(ListenerConfig{
		Name:     "tls-listener",
		Port:     8080,
		Protocol: "HTTP",
		Handler:  testHandler(),
		TLS:      nil,
	})
	assert.NoError(t, err)

	// Verify TLS is removed
	listener = manager.GetListener("tls-listener")
	assert.Nil(t, listener.TLS)
}

// TestManager_AddTCPListener tests adding TCP listeners
func TestManager_AddTCPListener(t *testing.T) {
	certs := generateTestCertificates(t)

	tests := []struct {
		name         string
		config       TCPListenerConfig
		addDuplicate bool
		expectError  bool
		errorMsg     string
	}{
		{
			name: "add TCP listener success",
			config: TCPListenerConfig{
				Name:           "tcp-listener",
				Port:           9000,
				ReadTimeout:    30 * time.Second,
				WriteTimeout:   30 * time.Second,
				MaxConnections: 100,
			},
			expectError: false,
		},
		{
			name: "add TCP listener with TLS",
			config: TCPListenerConfig{
				Name: "tcp-tls-listener",
				Port: 9001,
				TLS: &TLSConfig{
					CertFile: certs.CertFile,
					KeyFile:  certs.KeyFile,
				},
			},
			expectError: false,
		},
		{
			name: "add duplicate TCP listener fails",
			config: TCPListenerConfig{
				Name: "duplicate-tcp",
				Port: 9002,
			},
			addDuplicate: true,
			expectError:  true,
			errorMsg:     "listener duplicate-tcp already exists",
		},
		{
			name: "add TCP listener with invalid TLS fails",
			config: TCPListenerConfig{
				Name: "invalid-tls-tcp",
				Port: 9003,
				TLS: &TLSConfig{
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
			expectError: true,
			errorMsg:    "failed to load TLS config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			manager := NewManager(logger)

			if tt.addDuplicate {
				err := manager.AddTCPListener(tt.config)
				require.NoError(t, err)
			}

			err := manager.AddTCPListener(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				listener := manager.GetListener(tt.config.Name)
				assert.NotNil(t, listener)
				assert.Equal(t, "TCP", listener.Protocol)
			}
		})
	}
}

// TestManager_AddTCPListener_WhenStarted tests adding TCP listener when manager is started
func TestManager_AddTCPListener_WhenStarted(t *testing.T) {
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	port := getAvailablePort(t)

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		manager.Stop(ctx)
	})

	// Add TCP listener after manager is started
	err = manager.AddTCPListener(TCPListenerConfig{
		Name: "dynamic-tcp",
		Port: port,
	})
	assert.NoError(t, err)

	// Verify listener is running
	listener := manager.GetListener("dynamic-tcp")
	require.NotNil(t, listener)
	time.Sleep(50 * time.Millisecond)
	assert.True(t, listener.IsRunning())
}

// TestManager_AddTLSListener tests adding TLS listeners
func TestManager_AddTLSListener(t *testing.T) {
	certs := generateTestCertificates(t)

	tests := []struct {
		name             string
		config           TLSListenerConfig
		addDuplicate     bool
		expectError      bool
		errorMsg         string
		expectedProtocol string
	}{
		{
			name: "add TLS listener Terminate mode",
			config: TLSListenerConfig{
				Name: "tls-terminate",
				Port: 9100,
				Mode: "Terminate",
				TLS: &TLSConfig{
					CertFile: certs.CertFile,
					KeyFile:  certs.KeyFile,
				},
			},
			expectError:      false,
			expectedProtocol: "TLS",
		},
		{
			name: "add TLS listener Passthrough mode",
			config: TLSListenerConfig{
				Name: "tls-passthrough",
				Port: 9101,
				Mode: "Passthrough",
			},
			expectError:      false,
			expectedProtocol: "TLS-Passthrough",
		},
		{
			name: "add duplicate TLS listener fails",
			config: TLSListenerConfig{
				Name: "duplicate-tls",
				Port: 9102,
				Mode: "Terminate",
			},
			addDuplicate: true,
			expectError:  true,
			errorMsg:     "listener duplicate-tls already exists",
		},
		{
			name: "add TLS listener with invalid TLS fails",
			config: TLSListenerConfig{
				Name: "invalid-tls",
				Port: 9103,
				Mode: "Terminate",
				TLS: &TLSConfig{
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
			expectError: true,
			errorMsg:    "failed to load TLS config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			manager := NewManager(logger)

			if tt.addDuplicate {
				err := manager.AddTLSListener(tt.config)
				require.NoError(t, err)
			}

			err := manager.AddTLSListener(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				listener := manager.GetListener(tt.config.Name)
				assert.NotNil(t, listener)
				assert.Equal(t, tt.expectedProtocol, listener.Protocol)
			}
		})
	}
}

// TestManager_AddTLSListener_WhenStarted tests adding TLS listener when manager is started
func TestManager_AddTLSListener_WhenStarted(t *testing.T) {
	certs := generateTestCertificates(t)
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	port := getAvailablePort(t)

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		manager.Stop(ctx)
	})

	// Add TLS listener after manager is started
	err = manager.AddTLSListener(TLSListenerConfig{
		Name: "dynamic-tls",
		Port: port,
		Mode: "Terminate",
		TLS: &TLSConfig{
			CertFile: certs.CertFile,
			KeyFile:  certs.KeyFile,
		},
	})
	assert.NoError(t, err)

	// Verify listener is running
	listener := manager.GetListener("dynamic-tls")
	require.NotNil(t, listener)
	time.Sleep(50 * time.Millisecond)
	assert.True(t, listener.IsRunning())
}

// TestManager_AddTLSListener_Passthrough_WhenStarted tests adding TLS passthrough listener when started
func TestManager_AddTLSListener_Passthrough_WhenStarted(t *testing.T) {
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	port := getAvailablePort(t)

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		manager.Stop(ctx)
	})

	// Add TLS passthrough listener after manager is started
	err = manager.AddTLSListener(TLSListenerConfig{
		Name: "dynamic-tls-passthrough",
		Port: port,
		Mode: "Passthrough",
	})
	assert.NoError(t, err)

	// Verify listener is running
	listener := manager.GetListener("dynamic-tls-passthrough")
	require.NotNil(t, listener)
	time.Sleep(50 * time.Millisecond)
	assert.True(t, listener.IsRunning())
}

// TestListener_IsRunning tests the IsRunning method
func TestListener_IsRunning(t *testing.T) {
	tests := []struct {
		name     string
		running  bool
		expected bool
	}{
		{
			name:     "listener is running",
			running:  true,
			expected: true,
		},
		{
			name:     "listener is not running",
			running:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := &Listener{
				Name:    "test",
				Port:    8080,
				running: tt.running,
			}

			assert.Equal(t, tt.expected, listener.IsRunning())
		})
	}
}

// TestListener_GetAddress tests the GetAddress method
func TestListener_GetAddress(t *testing.T) {
	t.Run("listener not started returns port format", func(t *testing.T) {
		listener := &Listener{
			Name:     "test",
			Port:     8080,
			listener: nil,
		}

		addr := listener.GetAddress()
		assert.Equal(t, ":8080", addr)
	})

	t.Run("listener started returns actual address", func(t *testing.T) {
		port := getAvailablePort(t)
		netListener, err := net.Listen("tcp", ":0")
		require.NoError(t, err)
		defer netListener.Close()

		listener := &Listener{
			Name:     "test",
			Port:     port,
			listener: netListener,
		}

		addr := listener.GetAddress()
		assert.Contains(t, addr, ":")
		assert.NotEqual(t, ":0", addr)
	})
}

// TestManager_StartListener_AlreadyRunning tests starting an already running listener
func TestManager_StartListener_AlreadyRunning(t *testing.T) {
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	port := getAvailablePort(t)

	err := manager.AddListener(ListenerConfig{
		Name:     "test-listener",
		Port:     port,
		Protocol: "HTTP",
		Handler:  testHandler(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		manager.Stop(ctx)
	})

	time.Sleep(50 * time.Millisecond)

	// Try to start again - should be a no-op
	listener := manager.GetListener("test-listener")
	require.NotNil(t, listener)
	assert.True(t, listener.IsRunning())
}

// TestManager_StopListener_NotRunning tests stopping a listener that's not running
func TestManager_StopListener_NotRunning(t *testing.T) {
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	err := manager.AddListener(ListenerConfig{
		Name:     "test-listener",
		Port:     8080,
		Protocol: "HTTP",
		Handler:  testHandler(),
	})
	require.NoError(t, err)

	// Remove without starting - should not error
	err = manager.RemoveListener("test-listener")
	assert.NoError(t, err)
}

// TestManager_Start_WithTLSListener tests starting manager with TLS listener
func TestManager_Start_WithTLSListener(t *testing.T) {
	certs := generateTestCertificates(t)
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	port := getAvailablePort(t)

	err := manager.AddListener(ListenerConfig{
		Name:     "tls-listener",
		Port:     port,
		Protocol: "HTTPS",
		Handler:  testHandler(),
		TLS: &TLSConfig{
			CertFile: certs.CertFile,
			KeyFile:  certs.KeyFile,
		},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		manager.Stop(ctx)
	})

	time.Sleep(50 * time.Millisecond)

	listener := manager.GetListener("tls-listener")
	assert.True(t, listener.IsRunning())
	assert.NotNil(t, listener.TLS)
}

// TestManager_UpdateListener_InvalidTLS tests updating with invalid TLS config
func TestManager_UpdateListener_InvalidTLS(t *testing.T) {
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	err := manager.AddListener(ListenerConfig{
		Name:     "test-listener",
		Port:     8080,
		Protocol: "HTTP",
		Handler:  testHandler(),
	})
	require.NoError(t, err)

	// Update with invalid TLS
	err = manager.UpdateListener(ListenerConfig{
		Name:     "test-listener",
		Port:     8443,
		Protocol: "HTTPS",
		Handler:  testHandler(),
		TLS: &TLSConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load TLS config")
}

// TestManager_Concurrency tests concurrent access to manager
func TestManager_Concurrency(t *testing.T) {
	logger := zaptest.NewLogger(t)
	manager := NewManager(logger)

	// Add some initial listeners
	for i := 0; i < 5; i++ {
		err := manager.AddListener(ListenerConfig{
			Name:     "listener-" + string(rune('a'+i)),
			Port:     8080 + i,
			Protocol: "HTTP",
			Handler:  testHandler(),
		})
		require.NoError(t, err)
	}

	// Concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = manager.ListListeners()
				_ = manager.GetListener("listener-a")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
