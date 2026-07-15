//go:build e2e
// +build e2e

// WebSocket origin allowlist E2E tests verify the Cross-Site WebSocket
// Hijacking (CSWSH) protection added via spec.websocket.allowedOrigins:
// the full user journey is exercised through a real gateway instance —
// handshakes from allowed origins (and same-origin / origin-less clients)
// are proxied to the backend while disallowed cross-origin handshakes are
// rejected with HTTP 403 before any backend work happens.
package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// dialWSWithOrigin performs a WebSocket handshake through the gateway with
// the given Origin header value (empty means "no Origin header") and returns
// the connection, the HTTP handshake response, and the dial error.
func dialWSWithOrigin(
	ctx context.Context,
	t *testing.T,
	wsEndpoint, origin string,
) (*websocket.Conn, *http.Response, error) {
	t.Helper()

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	header := http.Header{}
	if origin != "" {
		header.Set("Origin", origin)
	}

	return e2eWSDialer().DialContext(dialCtx, wsEndpoint, header)
}

// requireWSStream reads one message to prove the tunnel to the backend
// WebSocket stream is fully established, then closes the connection.
func requireWSStream(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	defer func() {
		_ = conn.Close()
	}()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err, "expected streamed message from backend through gateway")
	assert.NotEmpty(t, string(msg))
	t.Logf("received streamed message: %s", string(msg))
}

// TestE2E_WebSocket_OriginAllowlist verifies handshake-time origin
// enforcement when spec.websocket.allowedOrigins is configured.
func TestE2E_WebSocket_OriginAllowlist(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-origin-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

	t.Run("allowed scheme+host origin connects", func(t *testing.T) {
		conn, resp, dialErr := dialWSWithOrigin(ctx, t, wsEndpoint, "https://app.example.com")
		if resp != nil {
			defer resp.Body.Close()
		}
		require.NoError(t, dialErr, "allowlisted origin must be able to connect")
		requireWSStream(t, conn)
	})

	t.Run("bare-host allowlist entry matches any scheme", func(t *testing.T) {
		conn, resp, dialErr := dialWSWithOrigin(ctx, t, wsEndpoint, "http://trusted.example.com")
		if resp != nil {
			defer resp.Body.Close()
		}
		require.NoError(t, dialErr, "bare-host entry must match the origin regardless of scheme")
		requireWSStream(t, conn)
	})

	t.Run("no Origin header connects (non-browser client)", func(t *testing.T) {
		conn, resp, dialErr := dialWSWithOrigin(ctx, t, wsEndpoint, "")
		if resp != nil {
			defer resp.Body.Close()
		}
		require.NoError(t, dialErr, "clients without an Origin header must keep working")
		requireWSStream(t, conn)
	})

	t.Run("same-origin request connects", func(t *testing.T) {
		// Origin host equals the gateway listener host:port (r.Host).
		sameOrigin := "http://" + gi.BaseURL[len("http://"):]
		conn, resp, dialErr := dialWSWithOrigin(ctx, t, wsEndpoint, sameOrigin)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.NoError(t, dialErr, "same-origin handshake must be allowed with a configured allowlist")
		requireWSStream(t, conn)
	})

	t.Run("disallowed cross-origin rejected with 403", func(t *testing.T) {
		conn, resp, dialErr := dialWSWithOrigin(ctx, t, wsEndpoint, "https://evil.example.com")
		if conn != nil {
			_ = conn.Close()
		}
		require.Error(t, dialErr, "handshake from a non-allowlisted origin must fail")
		require.NotNil(t, resp, "handshake rejection should carry an HTTP response")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"origin rejection must respond 403 Forbidden during the handshake")
		t.Logf("cross-origin handshake rejected as expected: %v (status %d)",
			dialErr, resp.StatusCode)
	})

	t.Run("allowlisted host with wrong scheme rejected", func(t *testing.T) {
		// "https://app.example.com" is listed with an explicit scheme, so a
		// plain-HTTP origin from the same host must not match it.
		conn, resp, dialErr := dialWSWithOrigin(ctx, t, wsEndpoint, "http://app.example.com")
		if conn != nil {
			_ = conn.Close()
		}
		require.Error(t, dialErr, "scheme-qualified entries must not match other schemes")
		require.NotNil(t, resp)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("gateway healthy after rejected handshakes", func(t *testing.T) {
		require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/health", 5*time.Second),
			"gateway must stay healthy after rejecting cross-origin handshakes")
	})
}

// TestE2E_WebSocket_OriginPermissiveDefault verifies backward compatibility:
// without spec.websocket.allowedOrigins any cross-origin handshake is
// accepted (a startup warning is logged instead).
func TestE2E_WebSocket_OriginPermissiveDefault(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	// websocket-test.yaml has no websocket.allowedOrigins section.
	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	t.Run("cross-origin connects when no allowlist configured", func(t *testing.T) {
		wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"
		conn, resp, dialErr := dialWSWithOrigin(ctx, t, wsEndpoint, "https://anything.example.org")
		if resp != nil {
			defer resp.Body.Close()
		}
		require.NoError(t, dialErr,
			"empty allowedOrigins must preserve the permissive legacy behavior")
		requireWSStream(t, conn)
	})
}
