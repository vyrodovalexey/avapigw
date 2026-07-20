// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// WSSGatewayConfigOption customizes the TLS gateway config built by
// BuildTLSWebSocketGatewayConfig.
type WSSGatewayConfigOption func(*config.GatewayConfig)

// WithWSSAllowedOrigins sets spec.websocket.allowedOrigins on the built
// config, enabling the production Cross-Site WebSocket Hijacking policy.
func WithWSSAllowedOrigins(origins []string) WSSGatewayConfigOption {
	return func(cfg *config.GatewayConfig) {
		cfg.Spec.WebSocket = &config.WebSocketConfig{AllowedOrigins: origins}
	}
}

// BuildTLSWebSocketGatewayConfig builds a gateway configuration with a single
// HTTPS listener (TLS mode SIMPLE, file-based server certificate) exposing:
//   - GET /health          direct response (readiness probe)
//   - GET(prefix) /ws      proxied WebSocket route to the backend
//   - catch-all /          proxied to the backend
//
// The certificate files must already exist (use TestCertificates.WriteToFiles).
func BuildTLSWebSocketGatewayConfig(
	port int,
	certs *TestCertificates,
	backendHost string,
	backendPort int,
	opts ...WSSGatewayConfigOption,
) *config.GatewayConfig {
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "wss-test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "https",
					Port:     port,
					Protocol: config.ProtocolHTTPS,
					Bind:     "127.0.0.1",
					TLS: &config.ListenerTLSConfig{
						Mode:       "SIMPLE",
						MinVersion: "TLS12",
						CertFile:   certs.ServerCertPath(),
						KeyFile:    certs.ServerKeyPath(),
					},
				},
			},
			Routes: []config.Route{
				{
					Name: "health-check",
					Match: []config.RouteMatch{
						{
							URI:     &config.URIMatch{Exact: "/health"},
							Methods: []string{http.MethodGet},
						},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status: http.StatusOK,
						Body:   `{"status":"healthy","gateway":"wss-test"}`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
					},
				},
				{
					Name: "websocket-route",
					Match: []config.RouteMatch{
						{
							URI:     &config.URIMatch{Prefix: "/ws"},
							Methods: []string{http.MethodGet},
						},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: backendHost,
								Port: backendPort,
							},
						},
					},
					// WebSocket routes must not enforce a request timeout:
					// the tunnel is long-lived by design.
					Timeout: config.Duration(0),
				},
				{
					Name: "catch-all",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/"}},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: backendHost,
								Port: backendPort,
							},
						},
					},
				},
			},
			Backends: []config.Backend{
				{
					Name: "wss-backend-1",
					Hosts: []config.BackendHost{
						{Address: backendHost, Port: backendPort, Weight: 1},
					},
					HealthCheck: &config.HealthCheck{
						Path:               "/health",
						Interval:           config.Duration(5 * time.Second),
						Timeout:            config.Duration(3 * time.Second),
						HealthyThreshold:   2,
						UnhealthyThreshold: 3,
					},
				},
			},
		},
	}

	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// WSSDialer returns a WebSocket dialer that trusts the test CA, suitable for
// wss:// connections to a gateway using certificates from TestCertificates.
func WSSDialer(certs *TestCertificates) *websocket.Dialer {
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(certs.CACertPEM)

	return &websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs:    caPool,
			MinVersion: tls.VersionTLS12,
		},
	}
}

// WSSURL builds a wss:// URL for the given HTTPS base URL and path.
// The base URL may use the https:// scheme (it is rewritten to wss://).
func WSSURL(httpsBaseURL, path string) string {
	return strings.Replace(httpsBaseURL, "https://", "wss://", 1) + path
}

// HTTPSClientForCerts returns an HTTP client that trusts the test CA.
func HTTPSClientForCerts(certs *TestCertificates) *http.Client {
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(certs.CACertPEM)

	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// WaitForReadyTLS waits for an HTTPS URL to become ready using a client that
// trusts the test CA.
func WaitForReadyTLS(url string, timeout time.Duration, certs *TestCertificates) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := HTTPSClientForCerts(certs)
	client.Timeout = 2 * time.Second

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for %s to become ready over TLS", url)
		case <-ticker.C:
			resp, err := client.Get(url)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode < http.StatusInternalServerError {
					return nil
				}
			}
		}
	}
}
