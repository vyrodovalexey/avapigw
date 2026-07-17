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
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
TLS Handshake Duration Metrics E2E Test:

Verifies the full user journey for the gateway_tls_handshake_duration_seconds
histogram: a gateway configured with an HTTPS listener via
gateway.New(cfg, gateway.WithGatewayTLSMetrics(...)) serves TLS traffic and the
handshake-duration histogram becomes observable on the metrics registry. This
covers the gateway -> listener metrics WIRING end-to-end; the listener-level
recording semantics (single sample per handshake, failure paths, gRPC listener)
are covered by unit tests in internal/gateway and internal/grpc/server.

No external dependencies required - the test generates its own certificates
and uses a direct-response route.
*/

// reserveLoopbackPort reserves and returns a free TCP port on 127.0.0.1.
func reserveLoopbackPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// tlsHandshakeHistogramSample returns the total sample count and sum of the
// gateway_tls_handshake_duration_seconds histogram across all label sets.
func tlsHandshakeHistogramSample(t *testing.T, registry *prometheus.Registry) (count uint64, sum float64) {
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

// TestE2E_TLS_HandshakeDurationMetric_GatewayJourney drives HTTPS traffic
// through a fully assembled gateway (config -> gateway.New -> HTTPS listener)
// and asserts the TLS handshake duration histogram observes the handshakes.
func TestE2E_TLS_HandshakeDurationMetric_GatewayJourney(t *testing.T) {
	// Generate self-signed certificates for the gateway listener.
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	port := reserveLoopbackPort(t)

	// Gateway config: one HTTPS listener (SIMPLE mode) + a direct-response
	// route so no backend is required.
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners = []config.Listener{
		{
			Name:     "https-handshake-metrics",
			Bind:     "127.0.0.1",
			Port:     port,
			Protocol: "HTTPS",
			Hosts:    []string{"*"},
			TLS: &config.ListenerTLSConfig{
				Mode:     "SIMPLE",
				CertFile: certs.ServerCertPath(),
				KeyFile:  certs.ServerKeyPath(),
			},
		},
	}
	cfg.Spec.Routes = []config.Route{
		{
			Name: "handshake-metrics-health",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Exact: "/health"},
					Methods: []string{"GET"},
				},
			},
			DirectResponse: &config.DirectResponseConfig{
				Status: 200,
				Body:   `{"status":"healthy"}`,
			},
		},
	}

	logger := observability.NopLogger()

	// Production-style wiring: real router + proxy as the route handler.
	r := router.New()
	require.NoError(t, r.LoadRoutes(cfg.Spec.Routes))
	registry := backend.NewRegistry(logger)
	require.NoError(t, registry.LoadFromConfig(cfg.Spec.Backends))
	p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

	// Isolated Prometheus registry so parallel tests cannot interfere.
	promRegistry := prometheus.NewRegistry()
	tlsMetrics := internaltls.NewMetrics("gateway", internaltls.WithRegistry(promRegistry))

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(p),
		gateway.WithGatewayTLSMetrics(tlsMetrics),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	require.NoError(t, gw.Start(ctx))
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = gw.Stop(stopCtx)
	})

	// No handshake samples before any TLS traffic.
	preCount, _ := tlsHandshakeHistogramSample(t, promRegistry)
	require.Zero(t, preCount, "no handshake samples before any TLS connection")

	baseURL := fmt.Sprintf("https://127.0.0.1:%d", port)
	client := &http.Client{
		Transport: &http.Transport{
			//nolint:gosec // self-signed test certificate
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
			// Force a fresh TLS handshake per request.
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}

	// Wait for the HTTPS listener to accept connections (bounded retry).
	var resp *http.Response
	require.Eventually(t, func() bool {
		var reqErr error
		resp, reqErr = client.Get(baseURL + "/health") //nolint:bodyclose // closed below
		return reqErr == nil
	}, 15*time.Second, 200*time.Millisecond, "gateway HTTPS listener must become ready")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, resp.Body.Close())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "healthy", "direct-response route served over TLS")

	// Drive one more independent handshake to prove per-connection recording.
	resp2, err := client.Get(baseURL + "/health")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp2.Body)
	require.NoError(t, resp2.Body.Close())

	count, sum := tlsHandshakeHistogramSample(t, promRegistry)
	assert.GreaterOrEqual(t, count, uint64(2),
		"handshake duration histogram must observe each TLS handshake served by the gateway")
	assert.Positive(t, sum, "handshake durations must be > 0")
	assert.Less(t, sum, float64(count)*5.0, "handshake durations must be sane (< 5s each)")
}
