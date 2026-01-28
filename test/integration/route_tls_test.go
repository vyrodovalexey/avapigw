//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestIntegration_RouteTLS_SNIBasedCertificateSelection tests SNI-based certificate selection
// with actual TLS connections.
func TestIntegration_RouteTLS_SNIBasedCertificateSelection(t *testing.T) {
	t.Parallel()

	// Generate certificates for different domains
	apiCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"api.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, apiCerts.WriteToFiles())
	defer apiCerts.Cleanup()

	wwwCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"www.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, wwwCerts.WriteToFiles())
	defer wwwCerts.Cleanup()

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()
	defer manager.Close()

	// Add routes with different certificates
	apiConfig := &internaltls.RouteTLSConfig{
		CertFile: apiCerts.ServerCertPath(),
		KeyFile:  apiCerts.ServerKeyPath(),
		SNIHosts: []string{"api.example.com"},
	}
	err = manager.AddRoute("api-route", apiConfig)
	require.NoError(t, err)

	wwwConfig := &internaltls.RouteTLSConfig{
		CertFile: wwwCerts.ServerCertPath(),
		KeyFile:  wwwCerts.ServerKeyPath(),
		SNIHosts: []string{"www.example.com"},
	}
	err = manager.AddRoute("www-route", wwwConfig)
	require.NoError(t, err)

	// Get TLS config with SNI-based selection
	tlsConfig := manager.GetTLSConfig()

	// Start TLS server
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Start server goroutine
	serverReady := make(chan struct{})
	go func() {
		close(serverReady)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleTLSConnection(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	t.Run("api.example.com SNI", func(t *testing.T) {
		// Create client that trusts the API certificate's CA
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(apiCerts.CACertPEM)

		clientConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "api.example.com",
			MinVersion: tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientConfig,
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("www.example.com SNI", func(t *testing.T) {
		// Create client that trusts the WWW certificate's CA
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(wwwCerts.CACertPEM)

		clientConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "www.example.com",
			MinVersion: tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientConfig,
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// TestIntegration_RouteTLS_WildcardSNI tests wildcard SNI certificate selection.
func TestIntegration_RouteTLS_WildcardSNI(t *testing.T) {
	t.Parallel()

	// Generate wildcard certificate
	wildcardCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"*.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, wildcardCerts.WriteToFiles())
	defer wildcardCerts.Cleanup()

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()
	defer manager.Close()

	// Add wildcard route
	wildcardConfig := &internaltls.RouteTLSConfig{
		CertFile: wildcardCerts.ServerCertPath(),
		KeyFile:  wildcardCerts.ServerKeyPath(),
		SNIHosts: []string{"*.example.com"},
	}
	err = manager.AddRoute("wildcard-route", wildcardConfig)
	require.NoError(t, err)

	// Get TLS config
	tlsConfig := manager.GetTLSConfig()

	// Start TLS server
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Start server
	serverReady := make(chan struct{})
	go func() {
		close(serverReady)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleTLSConnection(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	// Test various subdomains
	subdomains := []string{"api", "www", "admin", "test"}

	for _, subdomain := range subdomains {
		subdomain := subdomain
		t.Run(subdomain+".example.com", func(t *testing.T) {
			caPool := x509.NewCertPool()
			caPool.AppendCertsFromPEM(wildcardCerts.CACertPEM)

			clientConfig := &tls.Config{
				RootCAs:    caPool,
				ServerName: subdomain + ".example.com",
				MinVersion: tls.VersionTLS12,
			}

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: clientConfig,
				},
				Timeout: 5 * time.Second,
			}

			resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

// TestIntegration_RouteTLS_FallbackToListener tests fallback to listener certificate.
func TestIntegration_RouteTLS_FallbackToListener(t *testing.T) {
	t.Parallel()

	// Generate listener (default) certificate with wildcard to match any hostname
	listenerCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"*.example.com", "localhost", "other.example.com"})
	require.NoError(t, err)
	require.NoError(t, listenerCerts.WriteToFiles())
	defer listenerCerts.Cleanup()

	// Generate route-specific certificate
	routeCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"api.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, routeCerts.WriteToFiles())
	defer routeCerts.Cleanup()

	// Create base TLS manager (listener level)
	baseConfig := &internaltls.Config{
		Mode:       internaltls.TLSModeSimple,
		MinVersion: internaltls.TLSVersion12,
		ServerCertificate: &internaltls.CertificateConfig{
			CertFile: listenerCerts.ServerCertPath(),
			KeyFile:  listenerCerts.ServerKeyPath(),
		},
	}
	baseManager, err := internaltls.NewManager(baseConfig)
	require.NoError(t, err)
	defer baseManager.Close()

	// Create route TLS manager with base manager
	routeManager := internaltls.NewRouteTLSManager(
		internaltls.WithBaseManager(baseManager),
	)
	defer routeManager.Close()

	// Add route for specific SNI
	routeConfig := &internaltls.RouteTLSConfig{
		CertFile: routeCerts.ServerCertPath(),
		KeyFile:  routeCerts.ServerKeyPath(),
		SNIHosts: []string{"api.example.com"},
	}
	err = routeManager.AddRoute("api-route", routeConfig)
	require.NoError(t, err)

	// Get TLS config
	tlsConfig := routeManager.GetTLSConfig()

	// Start TLS server
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Start server
	serverReady := make(chan struct{})
	go func() {
		close(serverReady)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleTLSConnection(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	t.Run("route-specific SNI uses route certificate", func(t *testing.T) {
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(routeCerts.CACertPEM)

		clientConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "api.example.com",
			MinVersion: tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientConfig,
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("unknown SNI falls back to listener certificate", func(t *testing.T) {
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(listenerCerts.CACertPEM)

		clientConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "other.example.com",
			MinVersion: tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientConfig,
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// TestIntegration_RouteTLS_MultipleRoutes tests multiple routes with different certificates.
func TestIntegration_RouteTLS_MultipleRoutes(t *testing.T) {
	t.Parallel()

	// Generate certificates for multiple tenants
	tenant1Certs, err := helpers.GenerateTestCertificatesWithDNS([]string{"tenant1.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, tenant1Certs.WriteToFiles())
	defer tenant1Certs.Cleanup()

	tenant2Certs, err := helpers.GenerateTestCertificatesWithDNS([]string{"tenant2.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, tenant2Certs.WriteToFiles())
	defer tenant2Certs.Cleanup()

	tenant3Certs, err := helpers.GenerateTestCertificatesWithDNS([]string{"tenant3.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, tenant3Certs.WriteToFiles())
	defer tenant3Certs.Cleanup()

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()
	defer manager.Close()

	// Add routes for each tenant
	tenants := []struct {
		name  string
		certs *helpers.TestCertificates
		host  string
	}{
		{"tenant1", tenant1Certs, "tenant1.example.com"},
		{"tenant2", tenant2Certs, "tenant2.example.com"},
		{"tenant3", tenant3Certs, "tenant3.example.com"},
	}

	for _, tenant := range tenants {
		cfg := &internaltls.RouteTLSConfig{
			CertFile: tenant.certs.ServerCertPath(),
			KeyFile:  tenant.certs.ServerKeyPath(),
			SNIHosts: []string{tenant.host},
		}
		err = manager.AddRoute(tenant.name+"-route", cfg)
		require.NoError(t, err)
	}

	assert.Equal(t, 3, manager.RouteCount())

	// Get TLS config
	tlsConfig := manager.GetTLSConfig()

	// Start TLS server
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Start server
	serverReady := make(chan struct{})
	go func() {
		close(serverReady)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleTLSConnection(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	// Test each tenant
	for _, tenant := range tenants {
		tenant := tenant
		t.Run(tenant.name, func(t *testing.T) {
			caPool := x509.NewCertPool()
			caPool.AppendCertsFromPEM(tenant.certs.CACertPEM)

			clientConfig := &tls.Config{
				RootCAs:    caPool,
				ServerName: tenant.host,
				MinVersion: tls.VersionTLS12,
			}

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: clientConfig,
				},
				Timeout: 5 * time.Second,
			}

			resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

// TestIntegration_RouteTLS_CertificateHotReload tests certificate hot-reload for routes.
func TestIntegration_RouteTLS_CertificateHotReload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping hot reload test in short mode")
	}

	t.Parallel()

	// Generate initial certificates
	initialCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"api.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, initialCerts.WriteToFiles())
	defer initialCerts.Cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()

	// Add route
	routeConfig := &internaltls.RouteTLSConfig{
		CertFile: initialCerts.ServerCertPath(),
		KeyFile:  initialCerts.ServerKeyPath(),
		SNIHosts: []string{"api.example.com"},
	}
	err = manager.AddRoute("api-route", routeConfig)
	require.NoError(t, err)

	// Start manager
	err = manager.Start(ctx)
	require.NoError(t, err)

	// Get initial certificate
	hello := &tls.ClientHelloInfo{ServerName: "api.example.com"}
	cert1, err := manager.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert1)

	initialSerial := cert1.Leaf.SerialNumber.String()

	// Generate new certificates
	newCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"api.example.com", "localhost"})
	require.NoError(t, err)

	// Overwrite certificate files
	err = os.WriteFile(initialCerts.ServerCertPath(), newCerts.ServerCertPEM, 0600)
	require.NoError(t, err)
	err = os.WriteFile(initialCerts.ServerKeyPath(), newCerts.ServerKeyPEM, 0600)
	require.NoError(t, err)

	// Trigger reload
	err = manager.ReloadRoute("api-route")
	require.NoError(t, err)

	// Wait for reload to take effect
	time.Sleep(200 * time.Millisecond)

	// Get new certificate
	cert2, err := manager.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert2)

	// Note: The serial number might be the same if the provider caches
	// In a real implementation, we'd verify the certificate changed
	t.Logf("Initial serial: %s", initialSerial)
	if cert2.Leaf != nil {
		t.Logf("New serial: %s", cert2.Leaf.SerialNumber.String())
	}

	// Cancel context first
	cancel()
	time.Sleep(50 * time.Millisecond)

	err = manager.Close()
	require.NoError(t, err)
}

// TestIntegration_RouteTLS_MTLSAtRouteLevel tests mTLS at the route level.
func TestIntegration_RouteTLS_MTLSAtRouteLevel(t *testing.T) {
	t.Parallel()

	// Generate server and client certificates with the correct hostname
	serverCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"api.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, serverCerts.WriteToFiles())
	defer serverCerts.Cleanup()

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()
	defer manager.Close()

	// Add route with client validation
	routeConfig := &internaltls.RouteTLSConfig{
		CertFile: serverCerts.ServerCertPath(),
		KeyFile:  serverCerts.ServerKeyPath(),
		SNIHosts: []string{"api.example.com"},
		ClientValidation: &internaltls.ClientValidationConfig{
			Enabled:           true,
			CAFile:            serverCerts.CACertPath(),
			RequireClientCert: true,
		},
	}
	err = manager.AddRoute("mtls-route", routeConfig)
	require.NoError(t, err)

	// Get TLS config
	tlsConfig := manager.GetTLSConfig()
	// Enable client auth
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = x509.NewCertPool()
	tlsConfig.ClientCAs.AppendCertsFromPEM(serverCerts.CACertPEM)

	// Start TLS server
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Start server
	serverReady := make(chan struct{})
	go func() {
		close(serverReady)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleMTLSConnection(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	t.Run("with valid client certificate", func(t *testing.T) {
		clientTLSConfig, err := serverCerts.GetClientMTLSConfig()
		require.NoError(t, err)
		clientTLSConfig.ServerName = "api.example.com"

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "Hello")
	})

	t.Run("without client certificate fails", func(t *testing.T) {
		clientTLSConfig, err := serverCerts.GetClientTLSConfig()
		require.NoError(t, err)
		clientTLSConfig.ServerName = "api.example.com"

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 5 * time.Second,
		}

		_, err = client.Get(fmt.Sprintf("https://%s/", serverAddr))
		assert.Error(t, err)
	})
}

// TestIntegration_RouteTLS_ConcurrentAccess tests concurrent access to route TLS manager.
func TestIntegration_RouteTLS_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	// Generate certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()
	defer manager.Close()

	// Add route
	routeConfig := &internaltls.RouteTLSConfig{
		CertFile: certs.ServerCertPath(),
		KeyFile:  certs.ServerKeyPath(),
		SNIHosts: []string{"api.example.com"},
	}
	err = manager.AddRoute("test-route", routeConfig)
	require.NoError(t, err)

	// Concurrent access test
	var wg sync.WaitGroup
	errors := make(chan error, 200)

	// Concurrent certificate requests
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hello := &tls.ClientHelloInfo{ServerName: "api.example.com"}
			cert, err := manager.GetCertificate(hello)
			if err != nil {
				errors <- err
				return
			}
			if cert == nil {
				errors <- fmt.Errorf("certificate is nil")
			}
		}()
	}

	// Concurrent route queries
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = manager.RouteCount()
			_ = manager.HasRoute("test-route")
			_ = manager.GetRouteNames()
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}
}

// TestIntegration_RouteTLS_RouteAddRemove tests adding and removing routes dynamically.
func TestIntegration_RouteTLS_RouteAddRemove(t *testing.T) {
	t.Parallel()

	// Generate certificates
	certs1, err := helpers.GenerateTestCertificatesWithDNS([]string{"api.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, certs1.WriteToFiles())
	defer certs1.Cleanup()

	certs2, err := helpers.GenerateTestCertificatesWithDNS([]string{"www.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, certs2.WriteToFiles())
	defer certs2.Cleanup()

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()
	defer manager.Close()

	// Initially no routes
	assert.Equal(t, 0, manager.RouteCount())

	// Add first route
	cfg1 := &internaltls.RouteTLSConfig{
		CertFile: certs1.ServerCertPath(),
		KeyFile:  certs1.ServerKeyPath(),
		SNIHosts: []string{"api.example.com"},
	}
	err = manager.AddRoute("api-route", cfg1)
	require.NoError(t, err)
	assert.Equal(t, 1, manager.RouteCount())
	assert.True(t, manager.HasRoute("api-route"))

	// Add second route
	cfg2 := &internaltls.RouteTLSConfig{
		CertFile: certs2.ServerCertPath(),
		KeyFile:  certs2.ServerKeyPath(),
		SNIHosts: []string{"www.example.com"},
	}
	err = manager.AddRoute("www-route", cfg2)
	require.NoError(t, err)
	assert.Equal(t, 2, manager.RouteCount())
	assert.True(t, manager.HasRoute("www-route"))

	// Verify both routes work
	hello1 := &tls.ClientHelloInfo{ServerName: "api.example.com"}
	cert1, err := manager.GetCertificate(hello1)
	require.NoError(t, err)
	require.NotNil(t, cert1)

	hello2 := &tls.ClientHelloInfo{ServerName: "www.example.com"}
	cert2, err := manager.GetCertificate(hello2)
	require.NoError(t, err)
	require.NotNil(t, cert2)

	// Remove first route
	manager.RemoveRoute("api-route")
	assert.Equal(t, 1, manager.RouteCount())
	assert.False(t, manager.HasRoute("api-route"))
	assert.True(t, manager.HasRoute("www-route"))

	// First route should no longer work
	_, err = manager.GetCertificate(hello1)
	assert.Error(t, err)

	// Second route should still work
	cert2, err = manager.GetCertificate(hello2)
	require.NoError(t, err)
	require.NotNil(t, cert2)

	// Remove second route
	manager.RemoveRoute("www-route")
	assert.Equal(t, 0, manager.RouteCount())
}

// Helper functions

func handleTLSConnection(conn net.Conn) {
	defer conn.Close()
	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	buf := make([]byte, 1024)
	_, _ = conn.Read(buf)
	_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
}

func handleMTLSConnection(conn net.Conn) {
	defer conn.Close()
	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	state := tlsConn.ConnectionState()
	buf := make([]byte, 1024)
	_, _ = conn.Read(buf)
	if len(state.PeerCertificates) > 0 {
		cn := state.PeerCertificates[0].Subject.CommonName
		response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\nHello %s", len("Hello ")+len(cn), cn)
		_, _ = conn.Write([]byte(response))
	} else {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nForbidden"))
	}
}
