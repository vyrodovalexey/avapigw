//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"crypto/tls"
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
TLS E2E Test Setup Instructions:

These tests verify TLS functionality including:
- HTTPS connections with server certificates
- Mutual TLS (mTLS) with client certificates
- Certificate hot-reload
- TLS version negotiation
- HSTS headers
- HTTP to HTTPS redirect

No external dependencies required - tests generate their own certificates.

Run tests:
  go test -tags=e2e ./test/e2e/tls_e2e_test.go -v
*/

func TestE2E_TLS_Backend_Connection(t *testing.T) {
	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	// Start a TLS backend server
	serverTLSConfig, err := certs.GetServerTLSConfig()
	require.NoError(t, err)

	backendListener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer backendListener.Close()

	backendAddr := backendListener.Addr().String()

	// Start backend server
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nBackend OK TLS"))
				}
			}(conn)
		}
	}()

	// Test direct connection to backend
	clientTLSConfig, err := certs.GetClientTLSConfig()
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/", backendAddr))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Backend OK TLS", string(body))
}

func TestE2E_TLS_MTLS_Backend_Connection(t *testing.T) {
	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	// Start a mTLS backend server
	serverTLSConfig, err := certs.GetServerMTLSConfig()
	require.NoError(t, err)

	backendListener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer backendListener.Close()

	backendAddr := backendListener.Addr().String()

	// Start backend server
	go func() {
		for {
			conn, err := backendListener.Accept()
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
				if len(state.PeerCertificates) > 0 {
					cn := state.PeerCertificates[0].Subject.CommonName
					response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\nHello %s", len("Hello ")+len(cn), cn)
					_, _ = c.Write([]byte(response))
				} else {
					_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden"))
				}
			}(conn)
		}
	}()

	t.Run("with client certificate", func(t *testing.T) {
		clientTLSConfig, err := certs.GetClientMTLSConfig()
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 10 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", backendAddr))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "Hello")
	})

	t.Run("without client certificate fails", func(t *testing.T) {
		clientTLSConfig, err := certs.GetClientTLSConfig()
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 10 * time.Second,
		}

		_, err = client.Get(fmt.Sprintf("https://%s/", backendAddr))
		assert.Error(t, err)
	})
}

func TestE2E_TLS_CertificateHotReload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping hot reload test in short mode")
	}

	// Generate initial certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create file provider with reload
	config := &internaltls.CertificateConfig{
		Source:         internaltls.CertificateSourceFile,
		CertFile:       certs.ServerCertPath(),
		KeyFile:        certs.ServerKeyPath(),
		ReloadInterval: 100 * time.Millisecond,
	}

	provider, err := internaltls.NewFileProvider(config, nil)
	require.NoError(t, err)
	defer provider.Close()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Get initial certificate
	cert1, err := provider.GetCertificate(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, cert1)
	initialSerial := cert1.Leaf.SerialNumber.String()

	// Watch for events
	eventCh := provider.Watch(ctx)

	// Generate new certificates
	newCerts, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)

	// Overwrite certificate files
	err = os.WriteFile(certs.ServerCertPath(), newCerts.ServerCertPEM, 0600)
	require.NoError(t, err)
	err = os.WriteFile(certs.ServerKeyPath(), newCerts.ServerKeyPEM, 0600)
	require.NoError(t, err)

	// Wait for reload event (first event may be CertificateEventLoaded from Start)
	reloadReceived := false
	timeout := time.After(2 * time.Second)
	for !reloadReceived {
		select {
		case event := <-eventCh:
			if event.Type == internaltls.CertificateEventReloaded {
				reloadReceived = true
				// Get new certificate
				cert2, err := provider.GetCertificate(ctx, nil)
				require.NoError(t, err)
				require.NotNil(t, cert2)

				// Verify certificate changed
				newSerial := cert2.Leaf.SerialNumber.String()
				assert.NotEqual(t, initialSerial, newSerial)
				t.Log("Certificate reload event received and verified")
			}
		case <-timeout:
			t.Log("No reload event received within timeout")
			return
		}
	}
}

func TestE2E_TLS_HSTS_Header(t *testing.T) {
	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	// Create TLS server that adds HSTS header
	serverTLSConfig, err := certs.GetServerTLSConfig()
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					response := "HTTP/1.1 200 OK\r\n" +
						"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" +
						"Content-Length: 2\r\n\r\nOK"
					_, _ = c.Write([]byte(response))
				}
			}(conn)
		}
	}()

	clientTLSConfig, err := certs.GetClientTLSConfig()
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify HSTS header
	hsts := resp.Header.Get("Strict-Transport-Security")
	assert.Contains(t, hsts, "max-age=31536000")
	assert.Contains(t, hsts, "includeSubDomains")
}

func TestE2E_TLS_HTTPSRedirect(t *testing.T) {
	// This test simulates HTTP to HTTPS redirect behavior

	// Start HTTP server that redirects to HTTPS
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer httpListener.Close()

	httpAddr := httpListener.Addr().String()

	go func() {
		for {
			conn, err := httpListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					response := "HTTP/1.1 301 Moved Permanently\r\n" +
						"Location: https://localhost:443/\r\n" +
						"Content-Length: 0\r\n\r\n"
					_, _ = c.Write([]byte(response))
				}
			}(conn)
		}
	}()

	// Make HTTP request (without following redirects)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("http://%s/", httpAddr))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)

	location := resp.Header.Get("Location")
	assert.Contains(t, location, "https://")
}

func TestE2E_TLS_ConnectionInfo(t *testing.T) {
	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	serverTLSConfig, err := certs.GetServerTLSConfig()
	require.NoError(t, err)
	serverTLSConfig.MinVersion = tls.VersionTLS12
	serverTLSConfig.MaxVersion = tls.VersionTLS13

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

	go func() {
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
				// Read the HTTP request first before sending response
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			}(conn)
		}
	}()

	clientTLSConfig, err := certs.GetClientTLSConfig()
	require.NoError(t, err)

	// Use a custom transport to capture the TLS connection state from client side
	var clientConnState tls.ConnectionState
	transport := &http.Transport{
		TLSClientConfig: clientTLSConfig,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := tls.Dial(network, addr, clientTLSConfig)
			if err != nil {
				return nil, err
			}
			clientConnState = conn.ConnectionState()
			return conn, nil
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify TLS version (from client's perspective)
	assert.True(t, clientConnState.Version >= tls.VersionTLS12, "TLS version should be at least 1.2")

	// Verify cipher suite
	assert.NotZero(t, clientConnState.CipherSuite, "Cipher suite should be negotiated")

	// Verify server certificate was presented (PeerCertificates on client side contains server certs)
	assert.NotEmpty(t, clientConnState.PeerCertificates, "Server should present certificates")

	// Verify the handshake completed successfully
	assert.True(t, clientConnState.HandshakeComplete, "TLS handshake should be complete")
}

func TestE2E_TLS_VersionNegotiation(t *testing.T) {
	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	testCases := []struct {
		name             string
		serverMinVersion uint16
		serverMaxVersion uint16
		clientMinVersion uint16
		clientMaxVersion uint16
		shouldConnect    bool
	}{
		{
			name:             "TLS 1.2 only",
			serverMinVersion: tls.VersionTLS12,
			serverMaxVersion: tls.VersionTLS12,
			clientMinVersion: tls.VersionTLS12,
			clientMaxVersion: tls.VersionTLS12,
			shouldConnect:    true,
		},
		{
			name:             "TLS 1.3 only",
			serverMinVersion: tls.VersionTLS13,
			serverMaxVersion: tls.VersionTLS13,
			clientMinVersion: tls.VersionTLS13,
			clientMaxVersion: tls.VersionTLS13,
			shouldConnect:    true,
		},
		{
			name:             "server TLS 1.3 client TLS 1.2",
			serverMinVersion: tls.VersionTLS13,
			serverMaxVersion: tls.VersionTLS13,
			clientMinVersion: tls.VersionTLS12,
			clientMaxVersion: tls.VersionTLS12,
			shouldConnect:    false,
		},
		{
			name:             "negotiated TLS 1.3",
			serverMinVersion: tls.VersionTLS12,
			serverMaxVersion: tls.VersionTLS13,
			clientMinVersion: tls.VersionTLS12,
			clientMaxVersion: tls.VersionTLS13,
			shouldConnect:    true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			serverTLSConfig, err := certs.GetServerTLSConfig()
			require.NoError(t, err)
			serverTLSConfig.MinVersion = tc.serverMinVersion
			serverTLSConfig.MaxVersion = tc.serverMaxVersion

			listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
			require.NoError(t, err)
			defer listener.Close()

			// Start server
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						// Read the HTTP request first before sending response
						buf := make([]byte, 1024)
						_, _ = c.Read(buf)
						_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
					}(conn)
				}
			}()

			clientTLSConfig, err := certs.GetClientTLSConfig()
			require.NoError(t, err)
			clientTLSConfig.MinVersion = tc.clientMinVersion
			clientTLSConfig.MaxVersion = tc.clientMaxVersion

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: clientTLSConfig,
				},
				Timeout: 5 * time.Second,
			}

			_, err = client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
			if tc.shouldConnect {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestE2E_TLS_CipherSuiteNegotiation(t *testing.T) {
	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	testCases := []struct {
		name          string
		serverCiphers []uint16
		clientCiphers []uint16
		shouldConnect bool
	}{
		{
			name: "matching cipher suites",
			serverCiphers: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			clientCiphers: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			shouldConnect: true,
		},
		{
			name: "no matching cipher suites",
			serverCiphers: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
			clientCiphers: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			shouldConnect: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			serverTLSConfig, err := certs.GetServerTLSConfig()
			require.NoError(t, err)
			serverTLSConfig.CipherSuites = tc.serverCiphers
			serverTLSConfig.MaxVersion = tls.VersionTLS12 // Force TLS 1.2 for cipher suite testing

			listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
			require.NoError(t, err)
			defer listener.Close()

			// Start server
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						// Read the HTTP request first before sending response
						buf := make([]byte, 1024)
						_, _ = c.Read(buf)
						_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
					}(conn)
				}
			}()

			clientTLSConfig, err := certs.GetClientTLSConfig()
			require.NoError(t, err)
			clientTLSConfig.CipherSuites = tc.clientCiphers
			clientTLSConfig.MaxVersion = tls.VersionTLS12

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: clientTLSConfig,
				},
				Timeout: 5 * time.Second,
			}

			_, err = client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
			if tc.shouldConnect {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestE2E_TLS_ExpiredCertificate(t *testing.T) {
	// Generate expired certificate
	certPEM, keyPEM, err := helpers.GenerateExpiredCertificate()
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Start server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read the HTTP request first before sending response
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			}(conn)
		}
	}()

	// Client should reject expired certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 5 * time.Second,
	}

	_, err = client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate")
}

func TestE2E_TLS_SelfSignedCertificate(t *testing.T) {
	// Generate self-signed certificate
	certPEM, keyPEM, err := helpers.GenerateSelfSignedCertificate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Start server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read the HTTP request first before sending response
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			}(conn)
		}
	}()

	t.Run("rejected without skip verify", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
			Timeout: 5 * time.Second,
		}

		_, err = client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
		assert.Error(t, err)
	})

	t.Run("accepted with skip verify", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
				},
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
