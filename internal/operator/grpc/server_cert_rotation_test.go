// Package grpc provides tests for serving-certificate hot-swap on the
// operator gRPC server (rotation support).
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
)

// newRotationTestCertManager creates a fast self-signed provider.
func newRotationTestCertManager(t *testing.T) cert.Manager {
	t.Helper()
	certManager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
		CACommonName: "rotation-test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = certManager.Close() })
	return certManager
}

func TestServer_UpdateCertificate_Validation(t *testing.T) {
	server := newTestServerWithRegistry(t, getFreePort(t))

	require.Error(t, server.UpdateCertificate(nil), "nil certificate must be rejected")

	err := server.UpdateCertificate(&cert.Certificate{
		CertificatePEM: []byte("garbage"),
		PrivateKeyPEM:  []byte("garbage"),
	})
	require.Error(t, err, "unparsable pair must be rejected")
	assert.Contains(t, err.Error(), "invalid certificate/key pair")
}

func TestServer_UpdateCertificate_SwapsServingCert(t *testing.T) {
	certManager := newRotationTestCertManager(t)
	ctx := context.Background()

	first, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: "rotation-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)

	server := newTestServerWithRegistry(t, getFreePort(t))
	require.NoError(t, server.UpdateCertificate(first))

	exp1 := server.ServingCertificateExpiration()
	assert.WithinDuration(t, first.Expiration, exp1, time.Second)

	// Rotate to a longer-lived certificate and verify the swap.
	rotated, err := certManager.RotateCertificate(ctx, &cert.CertificateRequest{
		CommonName: "rotation-server",
		DNSNames:   []string{"localhost"},
		TTL:        2 * time.Hour,
	})
	require.NoError(t, err)
	require.NoError(t, server.UpdateCertificate(rotated))

	exp2 := server.ServingCertificateExpiration()
	assert.True(t, exp2.After(exp1), "expiration must reflect the rotated certificate")
}

func TestServer_ServingCertificateExpiration_NoTLS(t *testing.T) {
	server := newTestServerWithRegistry(t, getFreePort(t))
	assert.True(t, server.ServingCertificateExpiration().IsZero(),
		"no serving certificate -> zero expiration")
}

// TestServer_TLSHandshake_PicksUpRotatedCertificate proves the
// GetCertificate-func pattern end to end: a running TLS server serves the
// ROTATED certificate to new handshakes without a restart.
func TestServer_TLSHandshake_PicksUpRotatedCertificate(t *testing.T) {
	certManager := newRotationTestCertManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initial, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: "rotation-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)

	port := getFreePort(t)
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{
		Port:        port,
		Certificate: initial,
	}, reg)
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-serverErr:
		case <-time.After(5 * time.Second):
		}
	})

	caPool, err := certManager.GetCA(ctx)
	require.NoError(t, err)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitForTLSServer(t, addr, caPool)

	require.Equal(t, initial.SerialNumber, handshakeSerial(t, addr, caPool),
		"initial handshakes must serve the initial certificate")

	// Rotate and swap: new handshakes must see the new serial.
	rotated, err := certManager.RotateCertificate(ctx, &cert.CertificateRequest{
		CommonName: "rotation-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)
	require.NotEqual(t, initial.SerialNumber, rotated.SerialNumber)
	require.NoError(t, server.UpdateCertificate(rotated))

	assert.Equal(t, rotated.SerialNumber, handshakeSerial(t, addr, caPool),
		"handshakes after UpdateCertificate must serve the rotated certificate")
}

// waitForTLSServer waits until the TLS server accepts handshakes.
func waitForTLSServer(t *testing.T, addr string, caPool *x509.CertPool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			RootCAs:    caPool,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		})
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("TLS server did not become ready")
}

// handshakeSerial dials the server and returns the serial number of the
// presented leaf certificate.
func handshakeSerial(t *testing.T, addr string, caPool *x509.CertPool) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer conn.Close()

	state := conn.ConnectionState()
	require.NotEmpty(t, state.PeerCertificates)
	return state.PeerCertificates[0].SerialNumber.String()
}
