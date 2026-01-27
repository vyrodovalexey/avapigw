//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
Route-Level TLS E2E Test Setup Instructions:

These tests verify route-level TLS functionality including:
- Multi-tenant scenarios with different certificates per tenant
- Route-level mTLS with client certificates
- Certificate expiry handling
- Integration with gateway routing
- SNI-based certificate selection in realistic scenarios

No external dependencies required - tests generate their own certificates.

Run tests:
  go test -tags=e2e ./test/e2e/route_tls_e2e_test.go -v
*/

// TestE2E_RouteTLS_MultiTenantScenario tests a multi-tenant scenario where
// different tenants have different TLS certificates.
func TestE2E_RouteTLS_MultiTenantScenario(t *testing.T) {
	// Generate certificates for multiple tenants
	tenants := []struct {
		name string
		host string
	}{
		{"tenant-alpha", "alpha.example.com"},
		{"tenant-beta", "beta.example.com"},
		{"tenant-gamma", "gamma.example.com"},
	}

	tenantCerts := make(map[string]*helpers.TestCertificates)
	for _, tenant := range tenants {
		certs, err := helpers.GenerateTestCertificatesWithDNS([]string{tenant.host, "localhost"})
		require.NoError(t, err)
		require.NoError(t, certs.WriteToFiles())
		defer certs.Cleanup()
		tenantCerts[tenant.name] = certs
	}

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()
	defer manager.Close()

	// Add routes for each tenant
	for _, tenant := range tenants {
		certs := tenantCerts[tenant.name]
		cfg := &internaltls.RouteTLSConfig{
			CertFile: certs.ServerCertPath(),
			KeyFile:  certs.ServerKeyPath(),
			SNIHosts: []string{tenant.host},
		}
		err := manager.AddRoute(tenant.name+"-route", cfg)
		require.NoError(t, err)
	}

	// Get TLS config
	tlsConfig := manager.GetTLSConfig()

	// Start TLS server
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Start server that identifies the tenant
	serverReady := make(chan struct{})
	go func() {
		close(serverReady)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				state := tlsConn.ConnectionState()
				serverName := state.ServerName
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n{\"tenant\":\"%s\"}",
					len(fmt.Sprintf("{\"tenant\":\"%s\"}", serverName)), serverName)
				_, _ = c.Write([]byte(response))
			}(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	// Test each tenant
	for _, tenant := range tenants {
		tenant := tenant
		t.Run(tenant.name, func(t *testing.T) {
			certs := tenantCerts[tenant.name]

			caPool := x509.NewCertPool()
			caPool.AppendCertsFromPEM(certs.CACertPEM)

			clientConfig := &tls.Config{
				RootCAs:    caPool,
				ServerName: tenant.host,
				MinVersion: tls.VersionTLS12,
			}

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: clientConfig,
				},
				Timeout: 10 * time.Second,
			}

			resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), tenant.host)
		})
	}
}

// TestE2E_RouteTLS_MTLSWithClientCertificates tests route-level mTLS
// where different routes require different client certificates.
func TestE2E_RouteTLS_MTLSWithClientCertificates(t *testing.T) {
	// Generate server certificates with the correct hostname
	serverCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"secure.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, serverCerts.WriteToFiles())
	defer serverCerts.Cleanup()

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()
	defer manager.Close()

	// Add route with mTLS
	routeConfig := &internaltls.RouteTLSConfig{
		CertFile: serverCerts.ServerCertPath(),
		KeyFile:  serverCerts.ServerKeyPath(),
		SNIHosts: []string{"secure.example.com"},
		ClientValidation: &internaltls.ClientValidationConfig{
			Enabled:           true,
			CAFile:            serverCerts.CACertPath(),
			RequireClientCert: true,
		},
	}
	err = manager.AddRoute("secure-route", routeConfig)
	require.NoError(t, err)

	// Get TLS config and enable client auth
	tlsConfig := manager.GetTLSConfig()
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = x509.NewCertPool()
	tlsConfig.ClientCAs.AppendCertsFromPEM(serverCerts.CACertPEM)

	// Start TLS server
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Start server that extracts client certificate info
	serverReady := make(chan struct{})
	go func() {
		close(serverReady)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				state := tlsConn.ConnectionState()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)

				if len(state.PeerCertificates) > 0 {
					cn := state.PeerCertificates[0].Subject.CommonName
					response := fmt.Sprintf("HTTP/1.1 200 OK\r\nX-Client-CN: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\nAuthenticated: %s",
						cn, len("Authenticated: ")+len(cn), cn)
					_, _ = c.Write([]byte(response))
				} else {
					_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 12\r\nConnection: close\r\n\r\nUnauthorized"))
				}
			}(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	t.Run("with valid client certificate", func(t *testing.T) {
		clientTLSConfig, err := serverCerts.GetClientMTLSConfig()
		require.NoError(t, err)
		clientTLSConfig.ServerName = "secure.example.com"

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 10 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify client CN was extracted
		clientCN := resp.Header.Get("X-Client-CN")
		assert.NotEmpty(t, clientCN)

		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "Authenticated")
	})

	t.Run("without client certificate fails", func(t *testing.T) {
		clientTLSConfig, err := serverCerts.GetClientTLSConfig()
		require.NoError(t, err)
		clientTLSConfig.ServerName = "secure.example.com"

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 10 * time.Second,
		}

		_, err = client.Get(fmt.Sprintf("https://%s/", serverAddr))
		assert.Error(t, err)
	})

	t.Run("with invalid client certificate fails", func(t *testing.T) {
		// Generate a different CA and client cert
		otherCerts, err := helpers.GenerateTestCertificates()
		require.NoError(t, err)

		// Use client cert from different CA
		clientCert, err := tls.X509KeyPair(otherCerts.ClientCertPEM, otherCerts.ClientKeyPEM)
		require.NoError(t, err)

		// But use the correct server CA for verification
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(serverCerts.CACertPEM)

		clientTLSConfig := &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caPool,
			ServerName:   "secure.example.com",
			MinVersion:   tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 10 * time.Second,
		}

		_, err = client.Get(fmt.Sprintf("https://%s/", serverAddr))
		assert.Error(t, err)
	})
}

// TestE2E_RouteTLS_CertificateExpiryHandling tests handling of certificate expiry.
func TestE2E_RouteTLS_CertificateExpiryHandling(t *testing.T) {
	// Generate expired certificate
	expiredCertPEM, expiredKeyPEM, err := helpers.GenerateExpiredCertificate()
	require.NoError(t, err)

	// Write to temp files
	tempDir, err := os.MkdirTemp("", "expired-cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	expiredCertFile := tempDir + "/expired.crt"
	expiredKeyFile := tempDir + "/expired.key"
	err = os.WriteFile(expiredCertFile, expiredCertPEM, 0600)
	require.NoError(t, err)
	err = os.WriteFile(expiredKeyFile, expiredKeyPEM, 0600)
	require.NoError(t, err)

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()
	defer manager.Close()

	// Add route with expired certificate
	routeConfig := &internaltls.RouteTLSConfig{
		CertFile: expiredCertFile,
		KeyFile:  expiredKeyFile,
		SNIHosts: []string{"expired.example.com"},
	}
	err = manager.AddRoute("expired-route", routeConfig)
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
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
			}(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	// Client should reject expired certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: "expired.example.com",
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 5 * time.Second,
	}

	_, err = client.Get(fmt.Sprintf("https://%s/", serverAddr))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate")
}

// TestE2E_RouteTLS_GatewayRoutingIntegration tests route-level TLS with gateway routing.
func TestE2E_RouteTLS_GatewayRoutingIntegration(t *testing.T) {
	// Generate certificates for different API versions
	v1Certs, err := helpers.GenerateTestCertificatesWithDNS([]string{"api-v1.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, v1Certs.WriteToFiles())
	defer v1Certs.Cleanup()

	v2Certs, err := helpers.GenerateTestCertificatesWithDNS([]string{"api-v2.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, v2Certs.WriteToFiles())
	defer v2Certs.Cleanup()

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()
	defer manager.Close()

	// Add routes for different API versions
	v1Config := &internaltls.RouteTLSConfig{
		CertFile: v1Certs.ServerCertPath(),
		KeyFile:  v1Certs.ServerKeyPath(),
		SNIHosts: []string{"api-v1.example.com"},
	}
	err = manager.AddRoute("api-v1-route", v1Config)
	require.NoError(t, err)

	v2Config := &internaltls.RouteTLSConfig{
		CertFile: v2Certs.ServerCertPath(),
		KeyFile:  v2Certs.ServerKeyPath(),
		SNIHosts: []string{"api-v2.example.com"},
	}
	err = manager.AddRoute("api-v2-route", v2Config)
	require.NoError(t, err)

	// Get TLS config
	tlsConfig := manager.GetTLSConfig()

	// Start TLS server that routes based on SNI
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Start server that returns different responses based on SNI
	serverReady := make(chan struct{})
	go func() {
		close(serverReady)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				state := tlsConn.ConnectionState()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)

				var version string
				switch state.ServerName {
				case "api-v1.example.com":
					version = "v1"
				case "api-v2.example.com":
					version = "v2"
				default:
					version = "unknown"
				}

				response := fmt.Sprintf("HTTP/1.1 200 OK\r\nX-API-Version: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n{\"version\":\"%s\"}",
					version, len(fmt.Sprintf("{\"version\":\"%s\"}", version)), version)
				_, _ = c.Write([]byte(response))
			}(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	t.Run("API v1 route", func(t *testing.T) {
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(v1Certs.CACertPEM)

		clientConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "api-v1.example.com",
			MinVersion: tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientConfig,
			},
			Timeout: 10 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/api/items", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "v1", resp.Header.Get("X-API-Version"))

		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "v1")
	})

	t.Run("API v2 route", func(t *testing.T) {
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(v2Certs.CACertPEM)

		clientConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "api-v2.example.com",
			MinVersion: tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientConfig,
			},
			Timeout: 10 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/api/items", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "v2", resp.Header.Get("X-API-Version"))

		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "v2")
	})
}

// TestE2E_RouteTLS_WildcardCertificateScenario tests wildcard certificate scenarios.
func TestE2E_RouteTLS_WildcardCertificateScenario(t *testing.T) {
	// Generate wildcard certificate
	wildcardCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"*.example.com", "example.com", "localhost"})
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
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				state := tlsConn.ConnectionState()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				response := fmt.Sprintf("HTTP/1.1 200 OK\r\nX-Server-Name: %s\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK", state.ServerName)
				_, _ = c.Write([]byte(response))
			}(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	// Test various subdomains
	subdomains := []string{"api", "www", "admin", "dashboard", "metrics"}

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
				Timeout: 10 * time.Second,
			}

			resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, subdomain+".example.com", resp.Header.Get("X-Server-Name"))
		})
	}
}

// TestE2E_RouteTLS_CertificateHotReloadScenario tests certificate hot-reload in a realistic scenario.
func TestE2E_RouteTLS_CertificateHotReloadScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping hot reload test in short mode")
	}

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
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
			}(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	// Make initial request
	t.Run("initial certificate", func(t *testing.T) {
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(initialCerts.CACertPEM)

		clientConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "api.example.com",
			MinVersion: tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientConfig,
			},
			Timeout: 10 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Generate new certificates (same CA for simplicity)
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

	// Wait for reload
	time.Sleep(200 * time.Millisecond)

	// Make request with new certificate
	t.Run("after certificate reload", func(t *testing.T) {
		// Use the new CA (in this case, same as initial since we're using the same helper)
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(initialCerts.CACertPEM)

		clientConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "api.example.com",
			MinVersion: tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientConfig,
			},
			Timeout: 10 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Cancel context and close manager
	cancel()
	time.Sleep(50 * time.Millisecond)
	err = manager.Close()
	require.NoError(t, err)
}

// TestE2E_RouteTLS_MixedExactAndWildcard tests mixed exact and wildcard SNI matching.
func TestE2E_RouteTLS_MixedExactAndWildcard(t *testing.T) {
	// Generate certificates
	exactCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"api.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, exactCerts.WriteToFiles())
	defer exactCerts.Cleanup()

	wildcardCerts, err := helpers.GenerateTestCertificatesWithDNS([]string{"*.example.com", "localhost"})
	require.NoError(t, err)
	require.NoError(t, wildcardCerts.WriteToFiles())
	defer wildcardCerts.Cleanup()

	// Create route TLS manager
	manager := internaltls.NewRouteTLSManager()
	defer manager.Close()

	// Add exact match route (should take precedence)
	exactConfig := &internaltls.RouteTLSConfig{
		CertFile: exactCerts.ServerCertPath(),
		KeyFile:  exactCerts.ServerKeyPath(),
		SNIHosts: []string{"api.example.com"},
	}
	err = manager.AddRoute("exact-route", exactConfig)
	require.NoError(t, err)

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
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
			}(conn)
		}
	}()
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	t.Run("exact match takes precedence", func(t *testing.T) {
		// Use exact certificate's CA
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(exactCerts.CACertPEM)

		clientConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "api.example.com",
			MinVersion: tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientConfig,
			},
			Timeout: 10 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("wildcard matches other subdomains", func(t *testing.T) {
		// Use wildcard certificate's CA
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(wildcardCerts.CACertPEM)

		clientConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "www.example.com",
			MinVersion: tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientConfig,
			},
			Timeout: 10 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", serverAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
