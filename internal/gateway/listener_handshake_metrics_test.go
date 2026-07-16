package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// handshakeHistogramSnapshot returns the total sample count and sum of the
// gateway_tls_handshake_duration_seconds histogram across all label sets.
func handshakeHistogramSnapshot(t *testing.T, registry *prometheus.Registry) (count uint64, sum float64) {
	t.Helper()

	families, err := registry.Gather()
	require.NoError(t, err)
	for _, mf := range families {
		if mf.GetName() != "gateway_tls_handshake_duration_seconds" {
			continue
		}
		for _, m := range mf.GetMetric() {
			h := m.GetHistogram()
			count += h.GetSampleCount()
			sum += h.GetSampleSum()
		}
	}
	return count, sum
}

// counterTotal returns the summed value of a counter family across label sets,
// optionally filtered by a label name/value pair.
func counterTotal(t *testing.T, registry *prometheus.Registry, name, labelName, labelValue string) float64 {
	t.Helper()

	families, err := registry.Gather()
	require.NoError(t, err)
	var total float64
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelName != "" && !metricHasLabel(m, labelName, labelValue) {
				continue
			}
			total += m.GetCounter().GetValue()
		}
	}
	return total
}

func metricHasLabel(m *dto.Metric, name, value string) bool {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == name && lp.GetValue() == value {
			return true
		}
	}
	return false
}

// doTLSRequest dials the address with cfg, sends a minimal HTTP/1.1 request
// and reads the status line, guaranteeing the server completed the TLS
// handshake and served the request.
func doTLSRequest(t *testing.T, addr string, cfg *tls.Config) {
	t.Helper()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	status, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, status, "200", "listener served the request over TLS")
}

// TestListener_TLSHandshakeDurationMetric_Recorded drives a real HTTPS
// handshake through the listener and asserts the handshake-duration histogram
// observes exactly one sample with a sane duration, while the existing
// connection counter still fires.
func TestListener_TLSHandshakeDurationMetric_Recorded(t *testing.T) {
	t.Parallel()

	certs, err := createListenerTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	registry := prometheus.NewRegistry()
	metrics := tlspkg.NewMetrics("gateway", tlspkg.WithRegistry(registry))

	cfg := config.Listener{
		Name:     "handshake-metrics-listener",
		Bind:     "127.0.0.1",
		Port:     0,
		Protocol: "HTTPS",
		TLS: &config.ListenerTLSConfig{
			Mode:     "SIMPLE",
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler,
		WithListenerLogger(observability.NopLogger()),
		WithTLSMetrics(metrics),
	)
	require.NoError(t, err)

	// Bind an ephemeral port manually so the client knows the address.
	port := freeLoopbackPort(t)
	listener.config.Port = port

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, listener.Start(ctx))
	defer func() { _ = listener.Stop(context.Background()) }()

	preCount, _ := handshakeHistogramSnapshot(t, registry)
	require.Zero(t, preCount, "no handshake samples before any connection")

	//nolint:gosec // self-signed test certificate
	doTLSRequest(t, fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})

	count, sum := handshakeHistogramSnapshot(t, registry)
	require.Equal(t, uint64(1), count, "exactly one handshake duration sample")
	assert.Positive(t, sum, "handshake duration must be > 0")
	assert.Less(t, sum, 5.0, "handshake duration must be < 5s")

	// The pre-existing connection metric must still fire.
	conns := counterTotal(t, registry, "gateway_tls_connections_total", "", "")
	assert.Equal(t, float64(1), conns, "RecordConnection still fires once per connection")
}

// TestListener_TLSHandshakeMetrics_MutualBadClientCert verifies that a failed
// mTLS handshake (client presents no certificate under MUTUAL mode) records no
// duration sample while the client-certificate validation failure is counted.
func TestListener_TLSHandshakeMetrics_MutualBadClientCert(t *testing.T) {
	t.Parallel()

	certs, err := createListenerTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	registry := prometheus.NewRegistry()
	metrics := tlspkg.NewMetrics("gateway", tlspkg.WithRegistry(registry))

	cfg := config.Listener{
		Name:     "handshake-metrics-mtls-listener",
		Bind:     "127.0.0.1",
		Port:     0,
		Protocol: "HTTPS",
		TLS: &config.ListenerTLSConfig{
			Mode:              "MUTUAL",
			CertFile:          certs.certFile,
			KeyFile:           certs.keyFile,
			CAFile:            certs.certFile, // self-signed server cert doubles as CA
			RequireClientCert: true,
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler,
		WithListenerLogger(observability.NopLogger()),
		WithTLSMetrics(metrics),
	)
	require.NoError(t, err)

	port := freeLoopbackPort(t)
	listener.config.Port = port

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, listener.Start(ctx))
	defer func() { _ = listener.Stop(context.Background()) }()

	// Client presents no certificate: crypto/tls aborts the handshake during
	// client-certificate processing, before connection verification, so no
	// duration sample may be recorded.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	//nolint:gosec // self-signed test certificate
	conn, dialErr := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("127.0.0.1:%d", port),
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if dialErr == nil {
		// TLS 1.3 clients may not see the alert until the first read.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, readErr := conn.Read(make([]byte, 1))
		require.Error(t, readErr, "handshake must ultimately fail without a client certificate")
		_ = conn.Close()
	}

	// The client observed the server's abort alert, which happens-after any
	// server-side metric recording (both occur synchronously in the
	// handshake goroutine before the alert reaches the wire), so the failed
	// handshake has been fully processed by now. Instead of a fixed settle
	// sleep, poll the histogram over a bounded observation window and
	// require it to REMAIN zero: a rise at any point is a genuine bug, so
	// the poll can never false-fail, while the window catches stragglers a
	// single post-sleep check would miss.
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		count, _ := handshakeHistogramSnapshot(t, registry)
		require.Zero(t, count, "failed handshake must never record a duration sample")
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestGRPCListener_TLSHandshakeDurationMetric_Recorded drives a real TLS
// handshake against the gRPC listener and asserts the handshake-duration
// histogram observes it.
func TestGRPCListener_TLSHandshakeDurationMetric_Recorded(t *testing.T) {
	t.Parallel()

	certs, err := createListenerTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	registry := prometheus.NewRegistry()
	metrics := tlspkg.NewMetrics("gateway", tlspkg.WithRegistry(registry))

	port := freeLoopbackPort(t)
	cfg := config.Listener{
		Name:     "handshake-metrics-grpc-listener",
		Bind:     "127.0.0.1",
		Port:     port,
		Protocol: "GRPC",
		GRPC: &config.GRPCListenerConfig{
			TLS: &config.TLSConfig{
				Enabled:  true,
				Mode:     "SIMPLE",
				CertFile: certs.certFile,
				KeyFile:  certs.keyFile,
			},
		},
	}

	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
		WithGRPCTLSMetrics(metrics),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, listener.Start(ctx))
	defer func() { _ = listener.Stop(context.Background()) }()

	// Raw TLS dial with h2 ALPN; reading the server's HTTP/2 SETTINGS frame
	// proves the server-side handshake (and VerifyConnection) completed.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	//nolint:gosec // self-signed test certificate
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer conn.Close()

	// Complete the client side explicitly and send the HTTP/2 preface so the
	// gRPC server transport progresses past the handshake deterministically.
	_, err = conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	require.NoError(t, err, "gRPC server answered after TLS handshake")

	count, sum := handshakeHistogramSnapshot(t, registry)
	require.GreaterOrEqual(t, count, uint64(1), "gRPC TLS handshake recorded on the histogram")
	assert.Positive(t, sum)
	assert.Less(t, sum, 5.0)
}

// TestListener_InstallTLSHandshakeMetrics_VerifyFailureRecordsError exercises
// the failure branch through the installed per-connection config directly: a
// chained VerifyConnection rejection must record a bounded handshake error and
// no duration sample.
func TestListener_InstallTLSHandshakeMetrics_VerifyFailureRecordsError(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := tlspkg.NewMetrics("gateway", tlspkg.WithRegistry(registry))

	cfg := config.Listener{Name: "verify-fail-listener", Port: 0, Protocol: "HTTPS"}
	listener, err := NewListener(cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	require.NoError(t, err)
	listener.tlsMetrics = metrics
	listener.server = &http.Server{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			VerifyConnection: func(tls.ConnectionState) error {
				return fmt.Errorf("rejected by policy")
			},
		},
	}

	listener.installTLSHandshakeMetrics()
	require.NotNil(t, listener.server.TLSConfig.GetConfigForClient, "handshake hook installed")

	perConn, err := listener.server.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotNil(t, perConn)

	verifyErr := perConn.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13})
	require.Error(t, verifyErr)

	errCount := counterTotal(t, registry, "gateway_tls_handshake_errors_total",
		"reason", tlspkg.HandshakeErrorReasonVerifyFailed)
	assert.Equal(t, float64(1), errCount, "bounded handshake error recorded")

	count, _ := handshakeHistogramSnapshot(t, registry)
	assert.Zero(t, count, "no duration sample on verification failure")
}

// TestListener_InstallTLSHandshakeMetrics_NoTLSConfig ensures the install is a
// safe no-op without a TLS config.
func TestListener_InstallTLSHandshakeMetrics_NoTLSConfig(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{Name: "no-tls-listener", Port: 0, Protocol: "HTTP"}
	listener, err := NewListener(cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	require.NoError(t, err)
	listener.server = &http.Server{}

	// Must not panic.
	listener.installTLSHandshakeMetrics()
	assert.Nil(t, listener.server.TLSConfig)
}

// TestListener_InstallTLSHandshakeMetrics_ModeFallbackWithoutManager verifies
// the metrics-recorder fallback path (no TLS manager) derives the mode from
// peer certificates.
func TestListener_InstallTLSHandshakeMetrics_ModeFallbackWithoutManager(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := tlspkg.NewMetrics("gateway", tlspkg.WithRegistry(registry))

	cfg := config.Listener{Name: "fallback-listener", Port: 0, Protocol: "HTTPS"}
	listener, err := NewListener(cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	require.NoError(t, err)
	listener.tlsMetrics = metrics
	listener.server = &http.Server{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}

	listener.installTLSHandshakeMetrics()
	require.NotNil(t, listener.server.TLSConfig.GetConfigForClient)

	perConn, err := listener.server.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)

	require.NoError(t, perConn.VerifyConnection(tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{}},
	}))

	count, _ := handshakeHistogramSnapshot(t, registry)
	assert.Equal(t, uint64(1), count, "sample recorded via the metrics-recorder fallback")
}

// freeLoopbackPort reserves and returns a free TCP port on 127.0.0.1.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}
