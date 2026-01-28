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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// routeTestCertificates holds test certificate data for route TLS testing.
type routeTestCertificates struct {
	certPEM   []byte
	keyPEM    []byte
	caPEM     []byte
	certFile  string
	keyFile   string
	caFile    string
	tempDir   string
	notBefore time.Time
	notAfter  time.Time
	dnsNames  []string
}

// generateRouteTestCertificates creates test certificates for route TLS testing.
func generateRouteTestCertificates(t *testing.T, dnsNames []string) *routeTestCertificates {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "route-tls-test-*")
	require.NoError(t, err)

	// Generate CA key and certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Generate server key and certificate
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	if len(dnsNames) == 0 {
		dnsNames = []string{"test.example.com", "localhost"}
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   dnsNames[0],
			Organization: []string{"Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		BasicConstraintsValid: true,
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})

	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Write files
	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	caFile := filepath.Join(tempDir, "ca.crt")

	require.NoError(t, os.WriteFile(certFile, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0600))
	require.NoError(t, os.WriteFile(caFile, caPEM, 0600))

	return &routeTestCertificates{
		certPEM:   certPEM,
		keyPEM:    keyPEM,
		caPEM:     caPEM,
		certFile:  certFile,
		keyFile:   keyFile,
		caFile:    caFile,
		tempDir:   tempDir,
		notBefore: notBefore,
		notAfter:  notAfter,
		dnsNames:  dnsNames,
	}
}

// cleanup removes temporary test files.
func (tc *routeTestCertificates) cleanup() {
	if tc.tempDir != "" {
		os.RemoveAll(tc.tempDir)
	}
}

func TestNewRouteTLSManager(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	require.NotNil(t, manager)

	assert.NotNil(t, manager.routeEntries)
	assert.NotNil(t, manager.sniMapping)
	assert.NotNil(t, manager.wildcardSNI)
	assert.NotNil(t, manager.stopCh)
	assert.False(t, manager.started)
	assert.False(t, manager.closed)
	assert.Equal(t, 0, manager.RouteCount())
}

func TestNewRouteTLSManager_WithOptions(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	metrics := newMockMetrics()

	manager := NewRouteTLSManager(
		WithRouteTLSManagerLogger(logger),
		WithRouteTLSManagerMetrics(metrics),
	)
	require.NotNil(t, manager)

	assert.NotNil(t, manager.logger)
	assert.NotNil(t, manager.metrics)
}

func TestNewRouteTLSManager_WithBaseManager(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, nil)
	defer certs.cleanup()

	baseConfig := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	baseManager, err := NewManager(baseConfig)
	require.NoError(t, err)
	defer baseManager.Close()

	manager := NewRouteTLSManager(
		WithBaseManager(baseManager),
	)
	require.NotNil(t, manager)
	assert.Equal(t, baseManager, manager.baseManager)
}

func TestRouteTLSManager_AddRoute_Valid(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"api.example.com", "www.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com", "www.example.com"},
	}

	err := manager.AddRoute("test-route", cfg)
	require.NoError(t, err)

	assert.Equal(t, 1, manager.RouteCount())
	assert.True(t, manager.HasRoute("test-route"))

	names := manager.GetRouteNames()
	assert.Contains(t, names, "test-route")
}

func TestRouteTLSManager_AddRoute_EmptyName(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: "/path/to/cert.pem",
		KeyFile:  "/path/to/key.pem",
	}

	err := manager.AddRoute("", cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "route name cannot be empty")
}

func TestRouteTLSManager_AddRoute_NilConfig(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	defer manager.Close()

	err := manager.AddRoute("test-route", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "route TLS config cannot be nil")
}

func TestRouteTLSManager_AddRoute_MissingCertFile(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		KeyFile:  "/path/to/key.pem",
		SNIHosts: []string{"example.com"},
	}

	err := manager.AddRoute("test-route", cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certFile is required")
}

func TestRouteTLSManager_AddRoute_MissingKeyFile(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: "/path/to/cert.pem",
		SNIHosts: []string{"example.com"},
	}

	err := manager.AddRoute("test-route", cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "keyFile is required")
}

func TestRouteTLSManager_AddRoute_NoCertOrVault(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		SNIHosts: []string{"example.com"},
	}

	err := manager.AddRoute("test-route", cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "either certFile/keyFile or vault configuration is required")
}

func TestRouteTLSManager_AddRoute_InvalidCertFile(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
		SNIHosts: []string{"example.com"},
	}

	err := manager.AddRoute("test-route", cfg)
	assert.Error(t, err)
}

func TestRouteTLSManager_AddRoute_WithWildcardSNI(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"*.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"*.example.com"},
	}

	err := manager.AddRoute("wildcard-route", cfg)
	require.NoError(t, err)

	assert.Equal(t, 1, manager.RouteCount())
	assert.True(t, manager.HasRoute("wildcard-route"))
}

func TestRouteTLSManager_AddRoute_UpdateExisting(t *testing.T) {
	t.Parallel()

	certs1 := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs1.cleanup()

	certs2 := generateRouteTestCertificates(t, []string{"api2.example.com"})
	defer certs2.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	// Add first route
	cfg1 := &RouteTLSConfig{
		CertFile: certs1.certFile,
		KeyFile:  certs1.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	err := manager.AddRoute("test-route", cfg1)
	require.NoError(t, err)

	// Update with new config
	cfg2 := &RouteTLSConfig{
		CertFile: certs2.certFile,
		KeyFile:  certs2.keyFile,
		SNIHosts: []string{"api2.example.com"},
	}
	err = manager.AddRoute("test-route", cfg2)
	require.NoError(t, err)

	// Should still have only one route
	assert.Equal(t, 1, manager.RouteCount())
}

func TestRouteTLSManager_RemoveRoute(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}

	err := manager.AddRoute("test-route", cfg)
	require.NoError(t, err)
	assert.Equal(t, 1, manager.RouteCount())

	manager.RemoveRoute("test-route")
	assert.Equal(t, 0, manager.RouteCount())
	assert.False(t, manager.HasRoute("test-route"))
}

func TestRouteTLSManager_RemoveRoute_NonExistent(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	defer manager.Close()

	// Should not panic
	manager.RemoveRoute("nonexistent-route")
	assert.Equal(t, 0, manager.RouteCount())
}

func TestRouteTLSManager_GetCertificate_ExactMatch(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}

	err := manager.AddRoute("test-route", cfg)
	require.NoError(t, err)

	hello := &tls.ClientHelloInfo{
		ServerName: "api.example.com",
	}

	cert, err := manager.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestRouteTLSManager_GetCertificate_CaseInsensitive(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}

	err := manager.AddRoute("test-route", cfg)
	require.NoError(t, err)

	hello := &tls.ClientHelloInfo{
		ServerName: "API.EXAMPLE.COM",
	}

	cert, err := manager.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestRouteTLSManager_GetCertificate_WildcardMatch(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"*.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"*.example.com"},
	}

	err := manager.AddRoute("wildcard-route", cfg)
	require.NoError(t, err)

	// Test matching subdomain
	hello := &tls.ClientHelloInfo{
		ServerName: "api.example.com",
	}

	cert, err := manager.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestRouteTLSManager_GetCertificate_WildcardNoMatchMultiLevel(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"*.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"*.example.com"},
	}

	err := manager.AddRoute("wildcard-route", cfg)
	require.NoError(t, err)

	// Multi-level subdomain should NOT match *.example.com
	hello := &tls.ClientHelloInfo{
		ServerName: "api.v1.example.com",
	}

	cert, err := manager.GetCertificate(hello)
	// Should return error since no match and no base manager
	assert.Error(t, err)
	assert.Nil(t, cert)
}

func TestRouteTLSManager_GetCertificate_NoMatch(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}

	err := manager.AddRoute("test-route", cfg)
	require.NoError(t, err)

	hello := &tls.ClientHelloInfo{
		ServerName: "other.example.com",
	}

	cert, err := manager.GetCertificate(hello)
	assert.Error(t, err)
	assert.Equal(t, ErrNoCertificateFound, err)
	assert.Nil(t, cert)
}

func TestRouteTLSManager_GetCertificate_FallbackToBaseManager(t *testing.T) {
	t.Parallel()

	baseCerts := generateRouteTestCertificates(t, []string{"default.example.com"})
	defer baseCerts.cleanup()

	routeCerts := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer routeCerts.cleanup()

	// Create base manager
	baseConfig := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: baseCerts.certFile,
			KeyFile:  baseCerts.keyFile,
		},
	}

	baseManager, err := NewManager(baseConfig)
	require.NoError(t, err)
	defer baseManager.Close()

	// Create route manager with base manager
	manager := NewRouteTLSManager(
		WithBaseManager(baseManager),
	)
	defer manager.Close()

	// Add route for specific SNI
	cfg := &RouteTLSConfig{
		CertFile: routeCerts.certFile,
		KeyFile:  routeCerts.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	err = manager.AddRoute("api-route", cfg)
	require.NoError(t, err)

	// Request for non-matching SNI should fall back to base manager
	hello := &tls.ClientHelloInfo{
		ServerName: "other.example.com",
	}

	cert, err := manager.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestRouteTLSManager_GetCertificate_MultipleRoutes(t *testing.T) {
	t.Parallel()

	certs1 := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs1.cleanup()

	certs2 := generateRouteTestCertificates(t, []string{"www.example.com"})
	defer certs2.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	// Add first route
	cfg1 := &RouteTLSConfig{
		CertFile: certs1.certFile,
		KeyFile:  certs1.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	err := manager.AddRoute("api-route", cfg1)
	require.NoError(t, err)

	// Add second route
	cfg2 := &RouteTLSConfig{
		CertFile: certs2.certFile,
		KeyFile:  certs2.keyFile,
		SNIHosts: []string{"www.example.com"},
	}
	err = manager.AddRoute("www-route", cfg2)
	require.NoError(t, err)

	assert.Equal(t, 2, manager.RouteCount())

	// Test first route
	hello1 := &tls.ClientHelloInfo{ServerName: "api.example.com"}
	cert1, err := manager.GetCertificate(hello1)
	require.NoError(t, err)
	require.NotNil(t, cert1)

	// Test second route
	hello2 := &tls.ClientHelloInfo{ServerName: "www.example.com"}
	cert2, err := manager.GetCertificate(hello2)
	require.NoError(t, err)
	require.NotNil(t, cert2)
}

func TestRouteTLSManager_GetTLSConfig(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	defer manager.Close()

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	assert.NotNil(t, tlsConfig.GetCertificate)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
}

func TestRouteTLSManager_GetTLSConfig_WithBaseManager(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, nil)
	defer certs.cleanup()

	baseConfig := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion13,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	baseManager, err := NewManager(baseConfig)
	require.NoError(t, err)
	defer baseManager.Close()

	manager := NewRouteTLSManager(
		WithBaseManager(baseManager),
	)
	defer manager.Close()

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	assert.NotNil(t, tlsConfig.GetCertificate)
	// Should inherit min version from base manager
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
}

func TestRouteTLSManager_Start(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	err := manager.AddRoute("test-route", cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Starting again should be a no-op
	err = manager.Start(ctx)
	require.NoError(t, err)

	// Cancel context first to allow goroutines to exit gracefully
	cancel()

	// Give goroutines time to exit
	time.Sleep(50 * time.Millisecond)

	err = manager.Close()
	require.NoError(t, err)
}

func TestRouteTLSManager_Close(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	err := manager.AddRoute("test-route", cfg)
	require.NoError(t, err)

	err = manager.Close()
	require.NoError(t, err)

	// Closing again should be a no-op
	err = manager.Close()
	require.NoError(t, err)

	// Routes should be cleared
	assert.Equal(t, 0, manager.RouteCount())
}

func TestRouteTLSManager_ReloadRoute(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	err := manager.AddRoute("test-route", cfg)
	require.NoError(t, err)

	// Reload should work (even if provider doesn't support it)
	err = manager.ReloadRoute("test-route")
	require.NoError(t, err)
}

func TestRouteTLSManager_ReloadRoute_NonExistent(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	defer manager.Close()

	err := manager.ReloadRoute("nonexistent-route")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "route nonexistent-route not found")
}

func TestRouteTLSManager_RouteCount(t *testing.T) {
	t.Parallel()

	certs1 := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs1.cleanup()

	certs2 := generateRouteTestCertificates(t, []string{"www.example.com"})
	defer certs2.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	assert.Equal(t, 0, manager.RouteCount())

	cfg1 := &RouteTLSConfig{
		CertFile: certs1.certFile,
		KeyFile:  certs1.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	_ = manager.AddRoute("route1", cfg1)
	assert.Equal(t, 1, manager.RouteCount())

	cfg2 := &RouteTLSConfig{
		CertFile: certs2.certFile,
		KeyFile:  certs2.keyFile,
		SNIHosts: []string{"www.example.com"},
	}
	_ = manager.AddRoute("route2", cfg2)
	assert.Equal(t, 2, manager.RouteCount())

	manager.RemoveRoute("route1")
	assert.Equal(t, 1, manager.RouteCount())
}

func TestRouteTLSManager_HasRoute(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	assert.False(t, manager.HasRoute("test-route"))

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	_ = manager.AddRoute("test-route", cfg)

	assert.True(t, manager.HasRoute("test-route"))
	assert.False(t, manager.HasRoute("other-route"))
}

func TestRouteTLSManager_GetRouteNames(t *testing.T) {
	t.Parallel()

	certs1 := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs1.cleanup()

	certs2 := generateRouteTestCertificates(t, []string{"www.example.com"})
	defer certs2.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	names := manager.GetRouteNames()
	assert.Empty(t, names)

	cfg1 := &RouteTLSConfig{
		CertFile: certs1.certFile,
		KeyFile:  certs1.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	_ = manager.AddRoute("api-route", cfg1)

	cfg2 := &RouteTLSConfig{
		CertFile: certs2.certFile,
		KeyFile:  certs2.keyFile,
		SNIHosts: []string{"www.example.com"},
	}
	_ = manager.AddRoute("www-route", cfg2)

	names = manager.GetRouteNames()
	assert.Len(t, names, 2)
	assert.Contains(t, names, "api-route")
	assert.Contains(t, names, "www-route")
}

func TestRouteTLSManager_Concurrency(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	err := manager.AddRoute("test-route", cfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = manager.RouteCount()
			_ = manager.HasRoute("test-route")
			_ = manager.GetRouteNames()
			_ = manager.GetTLSConfig()

			hello := &tls.ClientHelloInfo{ServerName: "api.example.com"}
			_, _ = manager.GetCertificate(hello)
		}()
	}
	wg.Wait()
}

func TestMatchWildcard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pattern    string
		serverName string
		expected   bool
	}{
		{
			name:       "exact subdomain match",
			pattern:    "*.example.com",
			serverName: "api.example.com",
			expected:   true,
		},
		{
			name:       "www subdomain match",
			pattern:    "*.example.com",
			serverName: "www.example.com",
			expected:   true,
		},
		{
			name:       "multi-level subdomain no match",
			pattern:    "*.example.com",
			serverName: "api.v1.example.com",
			expected:   false,
		},
		{
			name:       "root domain no match",
			pattern:    "*.example.com",
			serverName: "example.com",
			expected:   false,
		},
		{
			name:       "different domain no match",
			pattern:    "*.example.com",
			serverName: "api.other.com",
			expected:   false,
		},
		{
			name:       "case insensitive match",
			pattern:    "*.example.com",
			serverName: "API.EXAMPLE.COM",
			expected:   true,
		},
		{
			name:       "non-wildcard pattern",
			pattern:    "api.example.com",
			serverName: "api.example.com",
			expected:   false,
		},
		{
			name:       "empty server name",
			pattern:    "*.example.com",
			serverName: "",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := matchWildcard(tt.pattern, tt.serverName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRouteTLSManager_VaultNotImplemented(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		SNIHosts: []string{"api.example.com"},
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "api.example.com",
		},
	}

	err := manager.AddRoute("vault-route", cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vault provider factory is required when vault TLS is enabled")
}

func TestRouteTLSManager_WithClientValidation(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"api.example.com"})
	defer certs.cleanup()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
		ClientValidation: &ClientValidationConfig{
			Enabled: true,
			CAFile:  certs.caFile,
		},
	}

	err := manager.AddRoute("test-route", cfg)
	require.NoError(t, err)

	assert.True(t, manager.HasRoute("test-route"))
}

func TestWithRouteTLSManagerLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	opt := WithRouteTLSManagerLogger(logger)

	m := &RouteTLSManager{}
	opt(m)

	assert.NotNil(t, m.logger)
}

func TestWithRouteTLSManagerMetrics(t *testing.T) {
	t.Parallel()

	metrics := newMockMetrics()
	opt := WithRouteTLSManagerMetrics(metrics)

	m := &RouteTLSManager{}
	opt(m)

	assert.NotNil(t, m.metrics)
}

func TestWithBaseManager(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, nil)
	defer certs.cleanup()

	baseConfig := &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	baseManager, err := NewManager(baseConfig)
	require.NoError(t, err)
	defer baseManager.Close()

	opt := WithBaseManager(baseManager)

	m := &RouteTLSManager{}
	opt(m)

	assert.Equal(t, baseManager, m.baseManager)
}

func TestWithRouteTLSManagerVaultProviderFactory(t *testing.T) {
	t.Parallel()

	factory := func(_ *VaultTLSConfig, _ observability.Logger) (CertificateProvider, error) {
		return newMockProvider(), nil
	}
	opt := WithRouteTLSManagerVaultProviderFactory(factory)

	m := &RouteTLSManager{}
	opt(m)

	assert.NotNil(t, m.vaultProviderFactory)
}

func TestRouteTLSManager_AddRoute_VaultEnabled_WithFactory(t *testing.T) {
	t.Parallel()

	factoryCalled := false
	mockProv := newMockProvider()

	// Generate a real cert so the mock provider can return it
	certs := generateRouteTestCertificates(t, []string{"vault.example.com"})
	defer certs.cleanup()

	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	mockProv.setCertificate(&cert)

	factory := func(_ *VaultTLSConfig, _ observability.Logger) (CertificateProvider, error) {
		factoryCalled = true
		return mockProv, nil
	}

	manager := NewRouteTLSManager(
		WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer manager.Close()

	cfg := &RouteTLSConfig{
		SNIHosts: []string{"vault.example.com"},
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "vault.example.com",
		},
	}

	err = manager.AddRoute("vault-route", cfg)
	require.NoError(t, err)

	assert.True(t, factoryCalled, "vault provider factory should have been called")
	assert.True(t, manager.HasRoute("vault-route"))
	assert.Equal(t, 1, manager.RouteCount())
}

func TestRouteTLSManager_AddRoute_VaultEnabled_NoFactory(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		SNIHosts: []string{"vault.example.com"},
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "vault.example.com",
		},
	}

	err := manager.AddRoute("vault-route", cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vault provider factory is required")
	assert.False(t, manager.HasRoute("vault-route"))
}

func TestRouteTLSManager_AddRoute_VaultEnabled_FactoryError(t *testing.T) {
	t.Parallel()

	factoryErr := fmt.Errorf("vault connection failed")
	factory := func(_ *VaultTLSConfig, _ observability.Logger) (CertificateProvider, error) {
		return nil, factoryErr
	}

	manager := NewRouteTLSManager(
		WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer manager.Close()

	cfg := &RouteTLSConfig{
		SNIHosts: []string{"vault.example.com"},
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "vault.example.com",
		},
	}

	err := manager.AddRoute("vault-route", cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create vault provider")
	assert.ErrorIs(t, err, factoryErr)
	assert.False(t, manager.HasRoute("vault-route"))
}

func TestRouteTLSManager_AddRoute_FileProvider_StillWorks(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"file.example.com"})
	defer certs.cleanup()

	// Even with a vault factory set, file-based routes should still work
	factory := func(_ *VaultTLSConfig, _ observability.Logger) (CertificateProvider, error) {
		t.Fatal("vault factory should not be called for file-based routes")
		return nil, nil
	}

	manager := NewRouteTLSManager(
		WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"file.example.com"},
	}

	err := manager.AddRoute("file-route", cfg)
	require.NoError(t, err)

	assert.True(t, manager.HasRoute("file-route"))
	assert.Equal(t, 1, manager.RouteCount())
}

func TestRouteTLSManager_HandleRouteEvent_UpdatesExpiryMetrics(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"metrics.example.com"})
	defer certs.cleanup()

	metrics := newMockMetrics()

	manager := NewRouteTLSManager(
		WithRouteTLSManagerMetrics(metrics),
	)
	defer manager.Close()

	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)

	// Test CertificateEventLoaded with certificate - should update expiry
	manager.handleRouteEvent("test-route", CertificateEvent{
		Type:        CertificateEventLoaded,
		Certificate: &cert,
		Message:     "certificate loaded",
	})
	assert.Equal(t, 1, metrics.getCertReloadSuccessCount())
	assert.Equal(t, 1, metrics.getCertExpiryCount())

	// Test CertificateEventLoaded with nil certificate - should not update expiry
	manager.handleRouteEvent("test-route", CertificateEvent{
		Type:    CertificateEventLoaded,
		Message: "certificate loaded without cert",
	})
	assert.Equal(t, 2, metrics.getCertReloadSuccessCount())
	assert.Equal(t, 1, metrics.getCertExpiryCount()) // unchanged

	// Test CertificateEventReloaded with certificate - should update expiry
	manager.handleRouteEvent("test-route", CertificateEvent{
		Type:        CertificateEventReloaded,
		Certificate: &cert,
		Message:     "certificate reloaded",
	})
	assert.Equal(t, 3, metrics.getCertReloadSuccessCount())
	assert.Equal(t, 2, metrics.getCertExpiryCount())

	// Test CertificateEventReloaded with nil certificate - should not update expiry
	manager.handleRouteEvent("test-route", CertificateEvent{
		Type:    CertificateEventReloaded,
		Message: "certificate reloaded without cert",
	})
	assert.Equal(t, 4, metrics.getCertReloadSuccessCount())
	assert.Equal(t, 2, metrics.getCertExpiryCount()) // unchanged
}

func TestRouteTLSManager_HandleRouteEvent_NilCertificate(t *testing.T) {
	t.Parallel()

	metrics := newMockMetrics()

	manager := NewRouteTLSManager(
		WithRouteTLSManagerMetrics(metrics),
	)
	defer manager.Close()

	// Should not panic with nil certificate
	manager.handleRouteEvent("test-route", CertificateEvent{
		Type:    CertificateEventLoaded,
		Message: "loaded without cert",
	})
	assert.Equal(t, 1, metrics.getCertReloadSuccessCount())
	assert.Equal(t, 0, metrics.getCertExpiryCount())
}

func TestRouteTLSManager_HandleRouteEvent_Expiring(t *testing.T) {
	t.Parallel()

	metrics := newMockMetrics()

	manager := NewRouteTLSManager(
		WithRouteTLSManagerMetrics(metrics),
	)
	defer manager.Close()

	// Expiring event should not record reload success/failure
	manager.handleRouteEvent("test-route", CertificateEvent{
		Type:    CertificateEventExpiring,
		Message: "certificate expiring soon",
	})
	assert.Equal(t, 0, metrics.getCertReloadSuccessCount())
	assert.Equal(t, 0, metrics.getCertReloadFailureCount())
}

func TestRouteTLSManager_HandleRouteEvent_Error(t *testing.T) {
	t.Parallel()

	metrics := newMockMetrics()

	manager := NewRouteTLSManager(
		WithRouteTLSManagerMetrics(metrics),
	)
	defer manager.Close()

	// Error event should record reload failure
	manager.handleRouteEvent("test-route", CertificateEvent{
		Type:    CertificateEventError,
		Error:   fmt.Errorf("certificate error"),
		Message: "failed to load certificate",
	})
	assert.Equal(t, 0, metrics.getCertReloadSuccessCount())
	assert.Equal(t, 1, metrics.getCertReloadFailureCount())
}

func TestRouteTLSManager_AddRoute_VaultEnabled_NilFactory(t *testing.T) {
	t.Parallel()

	manager := NewRouteTLSManager(
		WithRouteTLSManagerVaultProviderFactory(nil),
	)
	defer manager.Close()

	cfg := &RouteTLSConfig{
		SNIHosts: []string{"vault.example.com"},
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "vault.example.com",
		},
	}

	err := manager.AddRoute("vault-route", cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vault provider factory is required")
}

func TestRouteTLSManager_AddRoute_VaultDisabled_FileProvider(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"file.example.com"})
	defer certs.cleanup()

	// No vault factory set, vault disabled - should use file provider
	manager := NewRouteTLSManager()
	defer manager.Close()

	cfg := &RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"file.example.com"},
	}

	err := manager.AddRoute("file-route", cfg)
	require.NoError(t, err)

	assert.True(t, manager.HasRoute("file-route"))
}

func TestRouteTLSManager_GetCertificate_VaultRoute(t *testing.T) {
	t.Parallel()

	certs := generateRouteTestCertificates(t, []string{"vault.example.com"})
	defer certs.cleanup()

	mockProv := newMockProvider()
	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	mockProv.setCertificate(&cert)

	factory := func(_ *VaultTLSConfig, _ observability.Logger) (CertificateProvider, error) {
		return mockProv, nil
	}

	manager := NewRouteTLSManager(
		WithRouteTLSManagerVaultProviderFactory(factory),
	)
	defer manager.Close()

	cfg := &RouteTLSConfig{
		SNIHosts: []string{"vault.example.com"},
		Vault: &VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "my-role",
			CommonName: "vault.example.com",
		},
	}

	err = manager.AddRoute("vault-route", cfg)
	require.NoError(t, err)

	hello := &tls.ClientHelloInfo{
		ServerName: "vault.example.com",
	}

	gotCert, err := manager.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, gotCert)
}
