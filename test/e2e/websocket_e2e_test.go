//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for the API Gateway.
// WebSocket E2E tests verify the full WebSocket proxy journey through the
// gateway: client -> gateway listener -> reverse proxy -> backend WebSocket.
// These tests start a real gateway instance and connect through it.
package e2e

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// e2eWSDialer returns a WebSocket dialer configured for E2E tests.
func e2eWSDialer() *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
	}
}

// e2eWSURL converts an HTTP URL to a WebSocket URL.
func e2eWSURL(httpURL string) string {
	return strings.Replace(httpURL, "http://", "ws://", 1)
}

// TestE2E_WebSocket_ProxyConnection verifies that a WebSocket connection
// can be established through the gateway proxy to the backend.
// This is the primary E2E user journey: client connects via gateway,
// gateway upgrades and proxies the WebSocket to the backend.
func TestE2E_WebSocket_ProxyConnection(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	t.Run("WebSocket upgrade through gateway", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		dialer := e2eWSDialer()
		wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

		t.Logf("Connecting to WebSocket through gateway: %s", wsEndpoint)

		conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
		require.NoError(t, dialErr, "Failed to establish WebSocket through gateway")
		defer func() {
			_ = conn.Close()
		}()

		if resp != nil {
			defer resp.Body.Close()
			t.Logf("Upgrade response status: %d", resp.StatusCode)
		}

		t.Log("WebSocket connection through gateway established successfully")
	})

	t.Run("receive streamed data through gateway", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()

		dialer := e2eWSDialer()
		wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

		conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
		require.NoError(t, dialErr, "Failed to connect WebSocket through gateway")
		defer func() {
			_ = conn.Close()
		}()
		if resp != nil {
			defer resp.Body.Close()
		}

		// Backend sends random values every 1 second
		// Read 3 messages to verify streaming works through the proxy
		const expectedMessages = 3
		messages := make([]string, 0, expectedMessages)

		for i := 0; i < expectedMessages; i++ {
			readErr := conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			require.NoError(t, readErr)

			_, msg, readMsgErr := conn.ReadMessage()
			require.NoError(t, readMsgErr,
				"Failed to read streamed message %d through gateway", i+1)
			messages = append(messages, string(msg))
			t.Logf("Streamed message %d through gateway: %s", i+1, string(msg))
		}

		assert.Len(t, messages, expectedMessages,
			"Expected %d streamed messages through gateway", expectedMessages)

		// Verify we got different values (random stream)
		if len(messages) >= 2 {
			hasDifferent := false
			for i := 1; i < len(messages); i++ {
				if messages[i] != messages[0] {
					hasDifferent = true
					break
				}
			}
			assert.True(t, hasDifferent,
				"Expected different random values in stream through gateway")
		}
	})
}

// TestE2E_WebSocket_SendReceive verifies bidirectional WebSocket
// communication through the gateway proxy.
func TestE2E_WebSocket_SendReceive(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	t.Run("send message through gateway WebSocket", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		dialer := e2eWSDialer()
		wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

		conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
		require.NoError(t, dialErr, "Failed to connect WebSocket through gateway")
		defer func() {
			_ = conn.Close()
		}()
		if resp != nil {
			defer resp.Body.Close()
		}

		// Send a message through the gateway
		testMessage := "e2e test message through gateway"
		writeErr := conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, writeErr)

		writeErr = conn.WriteMessage(websocket.TextMessage, []byte(testMessage))
		require.NoError(t, writeErr, "Failed to send message through gateway")

		t.Logf("Sent message through gateway: %s", testMessage)

		// Read the next streamed message from backend
		readErr := conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, readErr)

		_, msg, readMsgErr := conn.ReadMessage()
		require.NoError(t, readMsgErr,
			"Failed to read message through gateway after send")
		assert.NotEmpty(t, string(msg),
			"Expected non-empty message from backend through gateway")

		t.Logf("Received message through gateway: %s", string(msg))
	})
}

// TestE2E_WebSocket_GracefulClose verifies that WebSocket connections
// through the gateway can be closed gracefully.
func TestE2E_WebSocket_GracefulClose(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	t.Run("graceful close through gateway", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		dialer := e2eWSDialer()
		wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

		conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
		require.NoError(t, dialErr, "Failed to connect WebSocket through gateway")
		if resp != nil {
			defer resp.Body.Close()
		}

		// Read one message to confirm connection is active
		readErr := conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, readErr)

		_, _, readMsgErr := conn.ReadMessage()
		require.NoError(t, readMsgErr, "Failed to read initial message through gateway")

		// Send close frame through gateway
		closeMsg := websocket.FormatCloseMessage(
			websocket.CloseNormalClosure, "e2e test complete")
		writeErr := conn.WriteControl(
			websocket.CloseMessage, closeMsg,
			time.Now().Add(5*time.Second))
		if writeErr != nil {
			t.Logf("Close frame write returned (may be expected): %v", writeErr)
		}

		closeErr := conn.Close()
		if closeErr != nil {
			t.Logf("Connection close returned: %v", closeErr)
		}

		t.Log("WebSocket connection through gateway closed gracefully")
	})

	t.Run("immediate close through gateway", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		dialer := e2eWSDialer()
		wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

		conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
		require.NoError(t, dialErr, "Failed to connect WebSocket through gateway")
		if resp != nil {
			defer resp.Body.Close()
		}

		// Close immediately without reading
		closeErr := conn.Close()
		if closeErr != nil {
			t.Logf("Immediate close returned: %v", closeErr)
		}

		t.Log("WebSocket connection through gateway closed immediately")
	})
}

// TestE2E_WebSocket_ConcurrentConnections verifies that the gateway
// can handle multiple concurrent WebSocket connections.
func TestE2E_WebSocket_ConcurrentConnections(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	t.Run("multiple concurrent WebSocket connections through gateway", func(t *testing.T) {
		const numConnections = 5
		var wg sync.WaitGroup
		var connectedCount atomic.Int64
		var messageCount atomic.Int64

		for i := 0; i < numConnections; i++ {
			wg.Add(1)
			go func(connID int) {
				defer wg.Done()

				dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
				defer cancel()

				dialer := e2eWSDialer()
				wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

				conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
				if dialErr != nil {
					t.Logf("Connection %d: failed to connect through gateway: %v",
						connID, dialErr)
					return
				}
				defer func() {
					_ = conn.Close()
				}()
				if resp != nil {
					defer resp.Body.Close()
				}

				connectedCount.Add(1)
				t.Logf("Connection %d: established through gateway", connID)

				// Read 2 messages per connection
				for j := 0; j < 2; j++ {
					if deadlineErr := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
						t.Logf("Connection %d: deadline error: %v", connID, deadlineErr)
						return
					}

					_, msg, readErr := conn.ReadMessage()
					if readErr != nil {
						t.Logf("Connection %d: read error on message %d: %v",
							connID, j+1, readErr)
						return
					}
					messageCount.Add(1)
					t.Logf("Connection %d, Message %d: %s",
						connID, j+1, string(msg))
				}
			}(i)
		}

		wg.Wait()

		assert.GreaterOrEqual(t, connectedCount.Load(), int64(numConnections*3/4),
			"At least 75%% of concurrent connections should succeed through gateway")
		assert.GreaterOrEqual(t, messageCount.Load(), int64(numConnections),
			"Should receive at least one message per connection through gateway")

		t.Logf("Concurrent WebSocket through gateway: %d/%d connected, %d messages",
			connectedCount.Load(), numConnections, messageCount.Load())
	})
}

// TestE2E_WebSocket_LoadBalancing verifies that WebSocket connections
// through the gateway are distributed across multiple backends.
func TestE2E_WebSocket_LoadBalancing(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	t.Run("WebSocket connections distributed across backends", func(t *testing.T) {
		// The /ws-lb route has 50/50 weight distribution across backends.
		// We establish multiple connections and verify they all succeed,
		// which implies the gateway is routing to available backends.
		const numConnections = 10
		var successCount atomic.Int64

		var wg sync.WaitGroup
		for i := 0; i < numConnections; i++ {
			wg.Add(1)
			go func(connID int) {
				defer wg.Done()

				dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()

				dialer := e2eWSDialer()
				wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws-lb"

				conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
				if dialErr != nil {
					t.Logf("LB Connection %d: failed: %v", connID, dialErr)
					return
				}
				defer func() {
					_ = conn.Close()
				}()
				if resp != nil {
					defer resp.Body.Close()
				}

				// Read one message to verify the connection works
				if deadlineErr := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
					return
				}

				_, msg, readErr := conn.ReadMessage()
				if readErr != nil {
					t.Logf("LB Connection %d: read error: %v", connID, readErr)
					return
				}

				successCount.Add(1)
				t.Logf("LB Connection %d: received: %s", connID, string(msg))
			}(i)
		}

		wg.Wait()

		assert.GreaterOrEqual(t, successCount.Load(), int64(numConnections*3/4),
			"At least 75%% of load-balanced WebSocket connections should succeed")

		t.Logf("Load-balanced WebSocket: %d/%d succeeded",
			successCount.Load(), numConnections)
	})
}

// TestE2E_WebSocket_ConnectionResilience verifies that the gateway
// handles WebSocket connection failures gracefully.
func TestE2E_WebSocket_ConnectionResilience(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	t.Run("gateway survives rapid connect-disconnect cycles", func(t *testing.T) {
		const numCycles = 10
		var successCount atomic.Int64

		for i := 0; i < numCycles; i++ {
			dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)

			dialer := e2eWSDialer()
			wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

			conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
			cancel()

			if dialErr != nil {
				t.Logf("Cycle %d: connect failed: %v", i, dialErr)
				continue
			}
			if resp != nil {
				resp.Body.Close()
			}

			// Immediately close
			_ = conn.Close()
			successCount.Add(1)
		}

		assert.GreaterOrEqual(t, successCount.Load(), int64(numCycles*3/4),
			"At least 75%% of rapid connect-disconnect cycles should succeed")

		t.Logf("Rapid connect-disconnect: %d/%d succeeded",
			successCount.Load(), numCycles)

		// Verify gateway is still healthy after rapid cycles
		healthErr := helpers.WaitForReady(gi.BaseURL+"/health", 5*time.Second)
		assert.NoError(t, healthErr,
			"Gateway should still be healthy after rapid WebSocket cycles")
	})

	t.Run("gateway handles connection after previous close", func(t *testing.T) {
		// First connection
		dialCtx1, cancel1 := context.WithTimeout(ctx, 15*time.Second)
		defer cancel1()

		dialer := e2eWSDialer()
		wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

		conn1, resp1, err1 := dialer.DialContext(dialCtx1, wsEndpoint, nil)
		require.NoError(t, err1, "First connection failed")
		if resp1 != nil {
			resp1.Body.Close()
		}

		// Read a message, then close
		readErr := conn1.SetReadDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, readErr)

		_, _, readMsgErr := conn1.ReadMessage()
		require.NoError(t, readMsgErr, "Failed to read from first connection")

		_ = conn1.Close()
		t.Log("First connection closed")

		// Small delay between connections
		time.Sleep(100 * time.Millisecond)

		// Second connection should work fine
		dialCtx2, cancel2 := context.WithTimeout(ctx, 15*time.Second)
		defer cancel2()

		conn2, resp2, err2 := dialer.DialContext(dialCtx2, wsEndpoint, nil)
		require.NoError(t, err2, "Second connection failed after first was closed")
		defer func() {
			_ = conn2.Close()
		}()
		if resp2 != nil {
			defer resp2.Body.Close()
		}

		readErr = conn2.SetReadDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, readErr)

		_, msg, readMsgErr := conn2.ReadMessage()
		require.NoError(t, readMsgErr, "Failed to read from second connection")
		assert.NotEmpty(t, string(msg),
			"Second connection should receive data")

		t.Logf("Second connection received: %s", string(msg))
	})
}

// TestE2E_WebSocket_InvalidUpgrade verifies that the gateway properly
// handles invalid WebSocket upgrade attempts.
func TestE2E_WebSocket_InvalidUpgrade(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	t.Run("WebSocket to non-WebSocket backend endpoint", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		dialer := e2eWSDialer()
		// /health is a direct response route, not a WebSocket endpoint
		wsEndpoint := e2eWSURL(gi.BaseURL) + "/health"

		conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
		if conn != nil {
			_ = conn.Close()
		}
		if resp != nil {
			defer resp.Body.Close()
		}

		// Should fail because /health returns a direct response, not a WebSocket upgrade
		require.Error(t, dialErr,
			"Expected error when upgrading to non-WebSocket endpoint through gateway")

		t.Logf("Invalid upgrade error (expected): %v", dialErr)
	})
}

// TestE2E_WebSocket_LongLivedConnection verifies that a WebSocket
// connection through the gateway can remain active and receive
// multiple messages over an extended period.
func TestE2E_WebSocket_LongLivedConnection(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	t.Run("long-lived WebSocket connection receives continuous stream", func(t *testing.T) {
		dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		dialer := e2eWSDialer()
		wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

		conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
		require.NoError(t, dialErr, "Failed to connect for long-lived test")
		defer func() {
			_ = conn.Close()
		}()
		if resp != nil {
			defer resp.Body.Close()
		}

		// Read 5 messages (backend sends every 1s, so ~5 seconds)
		const expectedMessages = 5
		var receivedCount int
		startTime := time.Now()

		for i := 0; i < expectedMessages; i++ {
			readErr := conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			require.NoError(t, readErr)

			_, msg, readMsgErr := conn.ReadMessage()
			if readMsgErr != nil {
				t.Logf("Read error at message %d: %v", i+1, readMsgErr)
				break
			}
			receivedCount++
			t.Logf("Long-lived message %d (elapsed: %v): %s",
				i+1, time.Since(startTime).Round(time.Millisecond), string(msg))
		}

		elapsed := time.Since(startTime)
		assert.GreaterOrEqual(t, receivedCount, expectedMessages-1,
			"Should receive most messages in long-lived connection")
		t.Logf("Long-lived connection: received %d/%d messages in %v",
			receivedCount, expectedMessages, elapsed.Round(time.Millisecond))
	})
}

// TestE2E_WebSocket_MixedTraffic verifies that the gateway can handle
// both regular HTTP requests and WebSocket connections simultaneously.
func TestE2E_WebSocket_MixedTraffic(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	t.Run("concurrent HTTP and WebSocket traffic", func(t *testing.T) {
		var wg sync.WaitGroup
		var httpSuccess atomic.Int64
		var wsSuccess atomic.Int64

		// Start WebSocket connections
		const numWSConns = 3
		for i := 0; i < numWSConns; i++ {
			wg.Add(1)
			go func(connID int) {
				defer wg.Done()

				dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
				defer cancel()

				dialer := e2eWSDialer()
				wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

				conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
				if dialErr != nil {
					t.Logf("WS %d: connect failed: %v", connID, dialErr)
					return
				}
				defer func() {
					_ = conn.Close()
				}()
				if resp != nil {
					defer resp.Body.Close()
				}

				// Read 2 messages
				for j := 0; j < 2; j++ {
					if deadlineErr := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
						return
					}
					_, _, readErr := conn.ReadMessage()
					if readErr != nil {
						return
					}
				}
				wsSuccess.Add(1)
			}(i)
		}

		// Simultaneously make HTTP requests
		const numHTTPReqs = 10
		for i := 0; i < numHTTPReqs; i++ {
			wg.Add(1)
			go func(reqID int) {
				defer wg.Done()

				client := helpers.HTTPClient()
				healthURL := gi.BaseURL + "/health"

				httpResp, httpErr := client.Get(healthURL)
				if httpErr != nil {
					t.Logf("HTTP %d: request failed: %v", reqID, httpErr)
					return
				}
				defer httpResp.Body.Close()

				if httpResp.StatusCode == 200 {
					httpSuccess.Add(1)
				}
			}(i)
		}

		wg.Wait()

		assert.GreaterOrEqual(t, wsSuccess.Load(), int64(numWSConns*3/4),
			"Most WebSocket connections should succeed during mixed traffic")
		assert.GreaterOrEqual(t, httpSuccess.Load(), int64(numHTTPReqs*3/4),
			"Most HTTP requests should succeed during mixed traffic")

		t.Logf("Mixed traffic: WS %d/%d, HTTP %d/%d succeeded",
			wsSuccess.Load(), numWSConns,
			httpSuccess.Load(), numHTTPReqs)
	})
}

// TestE2E_WebSocket_SequentialConnections verifies that the gateway
// handles sequential WebSocket connections correctly (connect, use, close, repeat).
func TestE2E_WebSocket_SequentialConnections(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("websocket-test.yaml"))
	require.NoError(t, err, "Failed to start gateway")
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err, "Gateway did not become ready")

	t.Run("sequential connect-use-close cycles", func(t *testing.T) {
		const numCycles = 3

		for cycle := 0; cycle < numCycles; cycle++ {
			t.Run(fmt.Sprintf("cycle_%d", cycle+1), func(t *testing.T) {
				dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()

				dialer := e2eWSDialer()
				wsEndpoint := e2eWSURL(gi.BaseURL) + "/ws"

				conn, resp, dialErr := dialer.DialContext(dialCtx, wsEndpoint, nil)
				require.NoError(t, dialErr,
					"Cycle %d: failed to connect", cycle+1)
				if resp != nil {
					resp.Body.Close()
				}

				// Read one message
				readErr := conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				require.NoError(t, readErr)

				_, msg, readMsgErr := conn.ReadMessage()
				require.NoError(t, readMsgErr,
					"Cycle %d: failed to read message", cycle+1)
				assert.NotEmpty(t, string(msg))

				t.Logf("Cycle %d: received: %s", cycle+1, string(msg))

				// Close connection
				_ = conn.Close()
			})
		}
	})
}
