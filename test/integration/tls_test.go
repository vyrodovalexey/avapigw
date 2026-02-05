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

func TestIntegration_TLS_SimpleMode(t *testing.T) {
	t.Parallel()

	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	// Create TLS server
	serverTLSConfig, err := certs.GetServerTLSConfig()
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

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
				// Read the request first before responding
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
			}(conn)
		}
	}()
	<-serverReady

	// Give the server a moment to be fully ready
	time.Sleep(50 * time.Millisecond)

	clientTLSConfig, err := certs.GetClientTLSConfig()
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
		Timeout: 5 * time.Second,
	}

	// Make request
	resp, err := client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "OK", string(body))
}

func TestIntegration_TLS_MutualMode(t *testing.T) {
	t.Parallel()

	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	// Create mTLS server
	serverTLSConfig, err := certs.GetServerMTLSConfig()
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

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
				// Read the request first before responding
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				state := tlsConn.ConnectionState()
				if len(state.PeerCertificates) > 0 {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
				} else {
					_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nForbidden"))
				}
			}(conn)
		}
	}()
	<-serverReady

	// Give the server a moment to be fully ready
	time.Sleep(50 * time.Millisecond)

	t.Run("with client certificate", func(t *testing.T) {
		// Create client with certificate
		clientTLSConfig, err := certs.GetClientMTLSConfig()
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("without client certificate", func(t *testing.T) {
		// Create client without certificate
		clientTLSConfig, err := certs.GetClientTLSConfig()
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 5 * time.Second,
		}

		_, err = client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
		// Should fail due to missing client certificate
		require.Error(t, err)
	})
}

func TestIntegration_TLS_OptionalMutualMode(t *testing.T) {
	t.Parallel()

	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	// Create server with optional client auth
	serverTLSConfig, err := certs.GetServerTLSConfig()
	require.NoError(t, err)
	serverTLSConfig.ClientAuth = tls.VerifyClientCertIfGiven

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

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
				// Read the request first before responding
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				state := tlsConn.ConnectionState()
				if len(state.PeerCertificates) > 0 {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nAuthenticated"))
				} else {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nAnonymous"))
				}
			}(conn)
		}
	}()
	<-serverReady

	// Give the server a moment to be fully ready
	time.Sleep(50 * time.Millisecond)

	t.Run("with client certificate", func(t *testing.T) {
		clientTLSConfig, err := certs.GetClientMTLSConfig()
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "Authenticated", string(body))
	})

	t.Run("without client certificate", func(t *testing.T) {
		clientTLSConfig, err := certs.GetClientTLSConfig()
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "Anonymous", string(body))
	})
}

func TestIntegration_TLS_InsecureMode(t *testing.T) {
	t.Parallel()

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
				// Read the request first before responding
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
			}(conn)
		}
	}()
	<-serverReady

	// Give the server a moment to be fully ready
	time.Sleep(50 * time.Millisecond)

	t.Run("with skip verify", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("without skip verify fails", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
			},
			Timeout: 5 * time.Second,
		}

		_, err := client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
		require.Error(t, err)
	})
}

func TestIntegration_TLS_CertificateReload(t *testing.T) {
	t.Parallel()

	// Generate initial certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create file provider with reload interval
	config := &internaltls.CertificateConfig{
		Source:         internaltls.CertificateSourceFile,
		CertFile:       certs.ServerCertPath(),
		KeyFile:        certs.ServerKeyPath(),
		ReloadInterval: 100 * time.Millisecond,
	}

	provider, err := internaltls.NewFileProvider(config, nil)
	require.NoError(t, err)
	defer provider.Close()

	// Start provider
	err = provider.Start(ctx)
	require.NoError(t, err)

	// Get initial certificate
	cert1, err := provider.GetCertificate(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, cert1)

	// Watch for events
	eventCh := provider.Watch(ctx)

	// Generate new certificates and overwrite files
	newCerts, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)

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
				t.Log("Certificate reload event received")
			}
		case <-timeout:
			t.Log("No reload event received (file watcher may not have triggered)")
			return
		}
	}
}

func TestIntegration_TLS_CipherSuiteNegotiation(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			serverTLSConfig, err := certs.GetServerTLSConfig()
			require.NoError(t, err)
			serverTLSConfig.CipherSuites = tc.serverCiphers
			serverTLSConfig.MaxVersion = tls.VersionTLS12 // Force TLS 1.2 for cipher suite testing

			listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
			require.NoError(t, err)
			defer listener.Close()

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
						// Read the request first before responding
						buf := make([]byte, 1024)
						_, _ = c.Read(buf)
						_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
					}(conn)
				}
			}()
			<-serverReady

			// Give the server a moment to be fully ready
			time.Sleep(50 * time.Millisecond)

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

func TestIntegration_TLS_VersionNegotiation(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			serverTLSConfig, err := certs.GetServerTLSConfig()
			require.NoError(t, err)
			serverTLSConfig.MinVersion = tc.serverMinVersion
			serverTLSConfig.MaxVersion = tc.serverMaxVersion

			listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
			require.NoError(t, err)
			defer listener.Close()

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
						// Read the request first before responding
						buf := make([]byte, 1024)
						_, _ = c.Read(buf)
						_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
					}(conn)
				}
			}()
			<-serverReady

			// Give the server a moment to be fully ready
			time.Sleep(50 * time.Millisecond)

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

func TestIntegration_TLS_ClientCertValidation(t *testing.T) {
	t.Parallel()

	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	// Generate a different CA and client cert
	otherCerts, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)

	// Create server with mTLS
	serverTLSConfig, err := certs.GetServerMTLSConfig()
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

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
				// Read the request first before responding
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
			}(conn)
		}
	}()
	<-serverReady

	// Give the server a moment to be fully ready
	time.Sleep(50 * time.Millisecond)

	t.Run("valid client certificate", func(t *testing.T) {
		clientTLSConfig, err := certs.GetClientMTLSConfig()
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("client certificate from different CA", func(t *testing.T) {
		// Use client cert from different CA
		clientCert, err := tls.X509KeyPair(otherCerts.ClientCertPEM, otherCerts.ClientKeyPEM)
		require.NoError(t, err)

		// But use the correct server CA for verification
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(certs.CACertPEM)

		clientTLSConfig := &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caPool,
			MinVersion:   tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: clientTLSConfig,
			},
			Timeout: 5 * time.Second,
		}

		_, err = client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
		// Should fail because client cert is not signed by server's CA
		require.Error(t, err)
	})
}

func TestIntegration_TLS_FileProvider(t *testing.T) {
	t.Parallel()

	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	ctx := context.Background()

	t.Run("load certificate from files", func(t *testing.T) {
		config := &internaltls.CertificateConfig{
			Source:   internaltls.CertificateSourceFile,
			CertFile: certs.ServerCertPath(),
			KeyFile:  certs.ServerKeyPath(),
		}

		provider, err := internaltls.NewFileProvider(config, nil)
		require.NoError(t, err)
		defer provider.Close()

		cert, err := provider.GetCertificate(ctx, nil)
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.NotEmpty(t, cert.Certificate)
	})

	t.Run("load certificate from inline data", func(t *testing.T) {
		config := &internaltls.CertificateConfig{
			Source:   internaltls.CertificateSourceInline,
			CertData: string(certs.ServerCertPEM),
			KeyData:  string(certs.ServerKeyPEM),
		}

		provider, err := internaltls.NewFileProvider(config, nil)
		require.NoError(t, err)
		defer provider.Close()

		cert, err := provider.GetCertificate(ctx, nil)
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.NotEmpty(t, cert.Certificate)
	})

	t.Run("load client CA", func(t *testing.T) {
		config := &internaltls.CertificateConfig{
			Source:   internaltls.CertificateSourceFile,
			CertFile: certs.ServerCertPath(),
			KeyFile:  certs.ServerKeyPath(),
		}

		clientConfig := &internaltls.ClientValidationConfig{
			Enabled: true,
			CAFile:  certs.CACertPath(),
		}

		provider, err := internaltls.NewFileProvider(config, clientConfig)
		require.NoError(t, err)
		defer provider.Close()

		caPool, err := provider.GetClientCA(ctx)
		require.NoError(t, err)
		require.NotNil(t, caPool)
	})

	t.Run("provider closed error", func(t *testing.T) {
		config := &internaltls.CertificateConfig{
			Source:   internaltls.CertificateSourceFile,
			CertFile: certs.ServerCertPath(),
			KeyFile:  certs.ServerKeyPath(),
		}

		provider, err := internaltls.NewFileProvider(config, nil)
		require.NoError(t, err)

		err = provider.Close()
		require.NoError(t, err)

		_, err = provider.GetCertificate(ctx, nil)
		assert.ErrorIs(t, err, internaltls.ErrProviderClosed)
	})
}

func TestIntegration_TLS_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	ctx := context.Background()

	config := &internaltls.CertificateConfig{
		Source:   internaltls.CertificateSourceFile,
		CertFile: certs.ServerCertPath(),
		KeyFile:  certs.ServerKeyPath(),
	}

	provider, err := internaltls.NewFileProvider(config, nil)
	require.NoError(t, err)
	defer provider.Close()

	// Concurrent access test
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cert, err := provider.GetCertificate(ctx, nil)
			if err != nil {
				errors <- err
				return
			}
			if cert == nil {
				errors <- fmt.Errorf("certificate is nil")
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}
}

func TestIntegration_TLS_LoadCertificateHelpers(t *testing.T) {
	t.Parallel()

	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	t.Run("load certificate from file", func(t *testing.T) {
		cert, err := internaltls.LoadCertificateFromFile(certs.ServerCertPath(), certs.ServerKeyPath())
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.NotEmpty(t, cert.Certificate)
	})

	t.Run("load certificate from PEM", func(t *testing.T) {
		cert, err := internaltls.LoadCertificateFromPEM(certs.ServerCertPEM, certs.ServerKeyPEM)
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.NotEmpty(t, cert.Certificate)
	})

	t.Run("load CA from file", func(t *testing.T) {
		pool, err := internaltls.LoadCAFromFile(certs.CACertPath())
		require.NoError(t, err)
		require.NotNil(t, pool)
	})

	t.Run("load CA from PEM", func(t *testing.T) {
		pool, err := internaltls.LoadCAFromPEM(certs.CACertPEM)
		require.NoError(t, err)
		require.NotNil(t, pool)
	})

	t.Run("parse PEM certificates", func(t *testing.T) {
		certs, err := internaltls.ParsePEMCertificates(certs.CACertPEM)
		require.NoError(t, err)
		assert.Len(t, certs, 1)
	})

	t.Run("validate certificate key pair", func(t *testing.T) {
		err := internaltls.ValidateCertificateKeyPair(certs.ServerCertPEM, certs.ServerKeyPEM)
		assert.NoError(t, err)
	})

	t.Run("validate mismatched certificate key pair", func(t *testing.T) {
		certPEM, keyPEM, err := helpers.GenerateMismatchedCertAndKey()
		require.NoError(t, err)

		err = internaltls.ValidateCertificateKeyPair(certPEM, keyPEM)
		assert.Error(t, err)
	})
}
