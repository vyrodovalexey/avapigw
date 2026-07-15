// Package main: tests proving the WebSocket origin allowlist configuration
// (spec.websocket.allowedOrigins) is wired from the gateway config into the
// reverse proxy by initApplication (proxy.WithWebSocketConfig). Without this
// wiring the allowlist would be a config no-op and cross-site WebSocket
// hijacking protection would silently stay disabled in production.
package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// reservedDeadPort binds an ephemeral port and KEEPS the listener open for the
// whole test (closed via t.Cleanup), immediately closing every accepted
// connection. Holding the port eliminates the reserve-then-release reuse race
// (another process re-binding it between Close and the proxy dial), while the
// accept-and-close behavior still makes any WebSocket backend handshake fail
// deterministically (EOF before an HTTP response -> 502 Bad Gateway).
func reservedDeadPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return // Listener closed at cleanup.
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok, "listener address must be *net.TCPAddr")
	return tcpAddr.Port
}

// websocketWiringConfig builds a minimal gateway config with one HTTP
// listener, one /ws route pointing at backendPort, and the given WebSocket
// configuration (nil keeps the permissive legacy behavior).
func websocketWiringConfig(name string, ws *config.WebSocketConfig, backendPort int) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: name},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Bind: "127.0.0.1", Port: 0, Protocol: config.ProtocolHTTP},
			},
			Routes: []config.Route{
				{
					Name:  "ws-route",
					Match: []config.RouteMatch{{URI: &config.URIMatch{Prefix: "/ws"}}},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "127.0.0.1", Port: backendPort}},
					},
				},
			},
			WebSocket: ws,
		},
	}
}

// newWSUpgradeRequest builds a WebSocket upgrade request for /ws with the
// given Origin header.
func newWSUpgradeRequest(origin string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Origin", origin)
	return req
}

// startWSWiringApp initializes the application from cfg, starts the gateway
// (so the gin engine exists), and registers cleanup.
func startWSWiringApp(t *testing.T, cfg *config.GatewayConfig) *application {
	t.Helper()

	logger := observability.NopLogger()
	app := initApplication(cfg, logger)
	require.NotNil(t, app)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = app.tracer.Shutdown(ctx)
		if app.rateLimiter != nil {
			app.rateLimiter.Stop()
		}
		if app.maxSessionsLimiter != nil {
			app.maxSessionsLimiter.Stop()
		}
	})

	startCtx := context.Background()
	require.NoError(t, app.gateway.Start(startCtx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = app.gateway.Stop(stopCtx)
	})

	return app
}

// TestInitApplication_WebSocketOriginAllowlistWired proves that
// initApplication passes cfg.Spec.WebSocket to the reverse proxy: with an
// allowlist configured, a cross-origin upgrade is rejected with 403 BEFORE
// any backend work; without WebSocket config, the same request passes the
// origin gate and fails later at the (dead) backend dial with 502.
func TestInitApplication_WebSocketOriginAllowlistWired(t *testing.T) {
	t.Run("allowlist rejects disallowed origin with 403", func(t *testing.T) {
		cfg := websocketWiringConfig("test-ws-allowlist",
			&config.WebSocketConfig{
				AllowedOrigins: []string{"https://app.example.com"},
			},
			reservedDeadPort(t),
		)
		app := startWSWiringApp(t, cfg)

		rec := httptest.NewRecorder()
		app.gateway.Engine().ServeHTTP(rec, newWSUpgradeRequest("https://evil.example.com"))

		assert.Equal(t, http.StatusForbidden, rec.Code,
			"cross-origin WS upgrade must be rejected by the wired allowlist")
	})

	t.Run("nil websocket config keeps permissive origin behavior", func(t *testing.T) {
		cfg := websocketWiringConfig("test-ws-permissive", nil, reservedDeadPort(t))
		app := startWSWiringApp(t, cfg)

		rec := httptest.NewRecorder()
		app.gateway.Engine().ServeHTTP(rec, newWSUpgradeRequest("https://evil.example.com"))

		// The origin gate passes (permissive default) and the proxy reaches
		// the dead backend, so the failure is a dial error — not a 403.
		assert.NotEqual(t, http.StatusForbidden, rec.Code,
			"permissive default must not reject on origin")
		assert.Equal(t, http.StatusBadGateway, rec.Code,
			"request must reach the backend dial stage")
	})
}
