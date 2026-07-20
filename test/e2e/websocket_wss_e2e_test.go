//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for the API Gateway.
//
// WSS (WebSocket-over-TLS) E2E tests verify the full secure WebSocket user
// journey: client dials wss:// against an HTTPS gateway listener (TLS mode
// SIMPLE with self-signed test certificates), the gateway terminates TLS,
// upgrades the connection, and proxies WebSocket frames to the plain-ws
// backend /ws endpoint. Covers the happy path (message exchange), the origin
// policy on the TLS listener, and TLS failure modes.
package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// wssTestPort is a dedicated listener port range base for WSS e2e tests to
// avoid collisions with other e2e gateway instances.
const wssTestPort = 18441

// startWSSGateway generates certificates, builds an HTTPS gateway config
// routing /ws to the live backend, starts the gateway, and waits for TLS
// readiness. It returns the gateway instance, its certificates, and the
// https base URL.
func startWSSGateway(
	t *testing.T, ctx context.Context, port int, opts ...helpers.WSSGatewayConfigOption,
) (*helpers.GatewayInstance, *helpers.TestCertificates, string) {
	t.Helper()

	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err, "Failed to generate test certificates")
	require.NoError(t, certs.WriteToFiles(), "Failed to write certificates")
	t.Cleanup(certs.Cleanup)

	backendInfo := helpers.GetGraphQLBackendInfo(testCfg.Backend1URL)
	cfg := helpers.BuildTLSWebSocketGatewayConfig(
		port, certs, backendInfo.Host, backendInfo.Port, opts...)

	gi, err := helpers.StartGatewayWithConfig(ctx, cfg)
	require.NoError(t, err, "Failed to start WSS gateway")
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = gi.Stop(stopCtx)
	})

	httpsBase := fmt.Sprintf("https://127.0.0.1:%d", port)
	err = helpers.WaitForReadyTLS(httpsBase+"/health", 10*time.Second, certs)
	require.NoError(t, err, "Gateway HTTPS listener did not become ready")

	return gi, certs, httpsBase
}

// TestE2E_WSS_UpgradeAndStream verifies the primary secure WebSocket user
// journey: wss:// handshake through the HTTPS listener, then streamed data
// from the backend /ws endpoint through the TLS-terminating gateway.
func TestE2E_WSS_UpgradeAndStream(t *testing.T) {
	ctx := context.Background()
	_, certs, httpsBase := startWSSGateway(t, ctx, wssTestPort)

	t.Run("wss upgrade through gateway TLS listener", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		dialer := helpers.WSSDialer(certs)
		wssEndpoint := helpers.WSSURL(httpsBase, "/ws")
		t.Logf("Connecting over TLS: %s", wssEndpoint)

		conn, resp, err := dialer.DialContext(dialCtx, wssEndpoint, nil)
		require.NoError(t, err, "Failed to establish WSS connection through gateway")
		defer conn.Close()
		if resp != nil {
			defer resp.Body.Close()
			assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode,
				"expected 101 Switching Protocols on wss upgrade")
		}

		// TLS is proven by the dial itself: the WSSDialer verifies the
		// server certificate against the generated test CA and refuses
		// non-TLS transports for the wss scheme.
		require.NotNil(t, conn.UnderlyingConn(),
			"wss connection must expose the underlying TLS transport")
		_, isTLS := conn.UnderlyingConn().(*tls.Conn)
		assert.True(t, isTLS, "underlying transport must be TLS")

		t.Log("WSS connection through gateway established")
	})

	t.Run("streamed messages arrive over wss", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()

		dialer := helpers.WSSDialer(certs)
		conn, resp, err := dialer.DialContext(dialCtx, helpers.WSSURL(httpsBase, "/ws"), nil)
		require.NoError(t, err, "Failed to connect WSS")
		defer conn.Close()
		if resp != nil {
			defer resp.Body.Close()
		}

		// The backend streams a message every second; read 3 through TLS.
		const expectedMessages = 3
		messages := make([]string, 0, expectedMessages)
		for i := 0; i < expectedMessages; i++ {
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
			_, msg, readErr := conn.ReadMessage()
			require.NoError(t, readErr, "Failed to read streamed message %d over wss", i+1)
			messages = append(messages, string(msg))
			t.Logf("WSS streamed message %d: %s", i+1, string(msg))
		}
		assert.Len(t, messages, expectedMessages)
	})
}

// TestE2E_WSS_MessageExchange verifies bidirectional message exchange over
// the TLS tunnel: the client writes a message through the gateway to the
// backend, and continues receiving the backend's streamed data.
//
// NOTE: the reference backend's /ws endpoint streams random values and
// accepts (but does not echo) client messages, so the write path is
// asserted by a successful frame write followed by continued streaming.
func TestE2E_WSS_MessageExchange(t *testing.T) {
	ctx := context.Background()
	_, certs, httpsBase := startWSSGateway(t, ctx, wssTestPort+1)

	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	dialer := helpers.WSSDialer(certs)
	conn, resp, err := dialer.DialContext(dialCtx, helpers.WSSURL(httpsBase, "/ws"), nil)
	require.NoError(t, err, "Failed to connect WSS")
	defer conn.Close()
	if resp != nil {
		defer resp.Body.Close()
	}

	// Client -> gateway -> backend over TLS.
	testMessage := "wss e2e message through TLS gateway"
	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(testMessage)),
		"Failed to write message over wss through gateway")
	t.Logf("Sent over wss: %s", testMessage)

	// Backend -> gateway -> client over TLS continues after the write.
	for i := 0; i < 2; i++ {
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, msg, readErr := conn.ReadMessage()
		require.NoError(t, readErr, "Failed to read message %d after write over wss", i+1)
		assert.NotEmpty(t, msg)
		t.Logf("Received over wss after write: %s", string(msg))
	}

	// Graceful close through the TLS tunnel.
	closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "wss e2e done")
	if err := conn.WriteControl(
		websocket.CloseMessage, closeMsg, time.Now().Add(5*time.Second)); err != nil {
		t.Logf("close frame write returned (may be expected): %v", err)
	}
}

// TestE2E_WSS_OriginPolicy verifies the production Cross-Site WebSocket
// Hijacking policy on the TLS listener: allowed origins connect, disallowed
// origins are rejected during the upgrade, and non-browser clients (no
// Origin header) are allowed.
func TestE2E_WSS_OriginPolicy(t *testing.T) {
	ctx := context.Background()
	_, certs, httpsBase := startWSSGateway(t, ctx, wssTestPort+2,
		helpers.WithWSSAllowedOrigins([]string{"https://app.example.com"}))

	dialer := helpers.WSSDialer(certs)
	wssEndpoint := helpers.WSSURL(httpsBase, "/ws")

	t.Run("allowed origin connects", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		header := http.Header{"Origin": []string{"https://app.example.com"}}
		conn, resp, err := dialer.DialContext(dialCtx, wssEndpoint, header)
		require.NoError(t, err, "Allowed origin must connect over wss")
		defer conn.Close()
		if resp != nil {
			resp.Body.Close()
		}

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, msg, readErr := conn.ReadMessage()
		require.NoError(t, readErr)
		assert.NotEmpty(t, msg)
	})

	t.Run("disallowed origin rejected during upgrade", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		header := http.Header{"Origin": []string{"https://evil.example.org"}}
		conn, resp, err := dialer.DialContext(dialCtx, wssEndpoint, header)
		if conn != nil {
			conn.Close()
		}
		require.Error(t, err, "Disallowed origin must be rejected on wss upgrade")
		if resp != nil {
			defer resp.Body.Close()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode,
				"origin rejection should produce 403 Forbidden")
		}
		t.Logf("Disallowed origin rejected (expected): %v", err)
	})

	t.Run("no origin header connects (non-browser client)", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		conn, resp, err := dialer.DialContext(dialCtx, wssEndpoint, nil)
		require.NoError(t, err, "Client without Origin header must connect")
		defer conn.Close()
		if resp != nil {
			resp.Body.Close()
		}
	})
}

// TestE2E_WSS_TLSFailureModes verifies that the TLS layer rejects clients
// with broken trust configuration before any WebSocket traffic flows.
func TestE2E_WSS_TLSFailureModes(t *testing.T) {
	ctx := context.Background()
	_, _, httpsBase := startWSSGateway(t, ctx, wssTestPort+3)

	t.Run("dialer without CA trust fails certificate verification", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		dialer := &websocket.Dialer{
			HandshakeTimeout: 5 * time.Second,
			TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
		}
		conn, resp, err := dialer.DialContext(dialCtx, helpers.WSSURL(httpsBase, "/ws"), nil)
		if conn != nil {
			conn.Close()
		}
		if resp != nil {
			resp.Body.Close()
		}
		require.Error(t, err, "Untrusted certificate must fail the wss handshake")
		assert.Contains(t, err.Error(), "certificate",
			"error should be a TLS certificate verification failure")
		t.Logf("TLS trust failure (expected): %v", err)
	})

	t.Run("plain ws to TLS listener fails", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		dialer := &websocket.Dialer{HandshakeTimeout: 5 * time.Second}
		wsEndpoint := "ws" + httpsBase[len("https"):] + "/ws" // ws://host:port/ws
		conn, resp, err := dialer.DialContext(dialCtx, wsEndpoint, nil)
		if conn != nil {
			conn.Close()
		}
		if resp != nil {
			resp.Body.Close()
		}
		require.Error(t, err, "Plaintext ws:// to an HTTPS listener must fail")
		t.Logf("Plaintext-to-TLS failure (expected): %v", err)
	})
}

// TestE2E_WSS_ConcurrentConnections verifies the TLS listener sustains
// multiple concurrent WSS tunnels.
func TestE2E_WSS_ConcurrentConnections(t *testing.T) {
	ctx := context.Background()
	_, certs, httpsBase := startWSSGateway(t, ctx, wssTestPort+4)

	const numConnections = 5
	var wg sync.WaitGroup
	var connected, received atomic.Int64

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()

			dialer := helpers.WSSDialer(certs)
			conn, resp, err := dialer.DialContext(dialCtx, helpers.WSSURL(httpsBase, "/ws"), nil)
			if err != nil {
				t.Logf("WSS conn %d: dial failed: %v", id, err)
				return
			}
			defer conn.Close()
			if resp != nil {
				resp.Body.Close()
			}
			connected.Add(1)

			for j := 0; j < 2; j++ {
				if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return
				}
				if _, _, err := conn.ReadMessage(); err != nil {
					t.Logf("WSS conn %d: read %d failed: %v", id, j+1, err)
					return
				}
				received.Add(1)
			}
		}(i)
	}
	wg.Wait()

	assert.EqualValues(t, numConnections, connected.Load(),
		"all concurrent WSS connections should establish")
	assert.GreaterOrEqual(t, received.Load(), int64(numConnections),
		"each WSS connection should stream at least one message")
	t.Logf("Concurrent WSS: %d/%d connected, %d messages",
		connected.Load(), numConnections, received.Load())
}
