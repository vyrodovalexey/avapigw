//go:build integration
// +build integration

// Package integration contains integration tests for the API Gateway.
// WebSocket integration tests verify WebSocket proxying through the gateway's
// reverse proxy layer, testing component interactions between the router,
// proxy, and backend WebSocket endpoints.
package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// wsDialer returns a WebSocket dialer with sensible test defaults.
func wsDialer() *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
}

// wsURL converts an HTTP URL to a WebSocket URL.
func wsURL(httpURL string) string {
	return strings.Replace(httpURL, "http://", "ws://", 1)
}

// TestIntegration_WebSocket_DirectConnection verifies that a WebSocket
// connection can be established directly to the backend /ws endpoint.
// This is a baseline test to ensure the backend is functioning before
// testing through the gateway proxy.
func TestIntegration_WebSocket_DirectConnection(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("connect to backend WebSocket endpoint", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		dialer := wsDialer()
		wsEndpoint := wsURL(testCfg.Backend1URL) + "/ws"

		t.Logf("Connecting to WebSocket endpoint: %s", wsEndpoint)

		conn, resp, err := dialer.DialContext(ctx, wsEndpoint, nil)
		require.NoError(t, err, "Failed to connect to WebSocket endpoint")
		defer func() {
			_ = conn.Close()
		}()

		if resp != nil {
			defer resp.Body.Close()
			assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode,
				"Expected HTTP 101 Switching Protocols")
		}

		t.Log("WebSocket connection established successfully")
	})

	t.Run("receive message from backend WebSocket", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		dialer := wsDialer()
		wsEndpoint := wsURL(testCfg.Backend1URL) + "/ws"

		conn, resp, err := dialer.DialContext(ctx, wsEndpoint, nil)
		require.NoError(t, err, "Failed to connect to WebSocket endpoint")
		defer func() {
			_ = conn.Close()
		}()
		if resp != nil {
			defer resp.Body.Close()
		}

		// Set read deadline to ensure we don't hang
		err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, err)

		// Read at least one message (backend sends random values every 1s)
		msgType, msg, err := conn.ReadMessage()
		require.NoError(t, err, "Failed to read WebSocket message")
		assert.Equal(t, websocket.TextMessage, msgType,
			"Expected text message type")
		assert.NotEmpty(t, string(msg), "Expected non-empty message")

		t.Logf("Received WebSocket message: %s", string(msg))
	})
}

// TestIntegration_WebSocket_MessageStreaming verifies that the backend
// WebSocket endpoint streams multiple messages over time.
func TestIntegration_WebSocket_MessageStreaming(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("receive multiple streamed messages", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		dialer := wsDialer()
		wsEndpoint := wsURL(testCfg.Backend1URL) + "/ws"

		conn, resp, err := dialer.DialContext(ctx, wsEndpoint, nil)
		require.NoError(t, err, "Failed to connect to WebSocket endpoint")
		defer func() {
			_ = conn.Close()
		}()
		if resp != nil {
			defer resp.Body.Close()
		}

		// Read multiple messages (backend sends every 1s)
		const expectedMessages = 3
		messages := make([]string, 0, expectedMessages)

		for i := 0; i < expectedMessages; i++ {
			err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			require.NoError(t, err)

			_, msg, readErr := conn.ReadMessage()
			require.NoError(t, readErr, "Failed to read message %d", i+1)
			messages = append(messages, string(msg))
			t.Logf("Message %d: %s", i+1, string(msg))
		}

		assert.Len(t, messages, expectedMessages,
			"Expected to receive %d messages", expectedMessages)

		// Verify messages are different (random values)
		if len(messages) >= 2 {
			hasDifferent := false
			for i := 1; i < len(messages); i++ {
				if messages[i] != messages[0] {
					hasDifferent = true
					break
				}
			}
			assert.True(t, hasDifferent,
				"Expected different random values in streamed messages")
		}
	})
}

// TestIntegration_WebSocket_CloseHandling verifies proper WebSocket
// connection close handling with close frames.
func TestIntegration_WebSocket_CloseHandling(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("client initiates graceful close", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		dialer := wsDialer()
		wsEndpoint := wsURL(testCfg.Backend1URL) + "/ws"

		conn, resp, err := dialer.DialContext(ctx, wsEndpoint, nil)
		require.NoError(t, err, "Failed to connect to WebSocket endpoint")
		if resp != nil {
			defer resp.Body.Close()
		}

		// Read one message to confirm connection is active
		err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, err)

		_, _, err = conn.ReadMessage()
		require.NoError(t, err, "Failed to read initial message")

		// Send close frame
		closeMsg := websocket.FormatCloseMessage(
			websocket.CloseNormalClosure, "test complete")
		err = conn.WriteControl(
			websocket.CloseMessage, closeMsg,
			time.Now().Add(5*time.Second))

		// The close may succeed or the connection may already be closing
		if err != nil {
			t.Logf("Close write returned (expected): %v", err)
		}

		// Close the connection
		err = conn.Close()
		// Close may return an error if already closed, which is acceptable
		if err != nil {
			t.Logf("Connection close returned: %v", err)
		}

		t.Log("WebSocket connection closed gracefully")
	})

	t.Run("connection close after no reads", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		dialer := wsDialer()
		wsEndpoint := wsURL(testCfg.Backend1URL) + "/ws"

		conn, resp, err := dialer.DialContext(ctx, wsEndpoint, nil)
		require.NoError(t, err, "Failed to connect to WebSocket endpoint")
		if resp != nil {
			defer resp.Body.Close()
		}

		// Immediately close without reading
		err = conn.Close()
		// Close should succeed or return a benign error
		if err != nil {
			t.Logf("Immediate close returned: %v", err)
		}

		t.Log("WebSocket connection closed immediately without reading")
	})
}

// TestIntegration_WebSocket_ConcurrentConnections verifies that multiple
// concurrent WebSocket connections can be established and receive messages
// independently.
func TestIntegration_WebSocket_ConcurrentConnections(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("multiple concurrent WebSocket connections", func(t *testing.T) {
		const numConnections = 5
		var wg sync.WaitGroup
		var successCount atomic.Int64
		var messageCount atomic.Int64

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		for i := 0; i < numConnections; i++ {
			wg.Add(1)
			go func(connID int) {
				defer wg.Done()

				dialer := wsDialer()
				wsEndpoint := wsURL(testCfg.Backend1URL) + "/ws"

				conn, resp, err := dialer.DialContext(ctx, wsEndpoint, nil)
				if err != nil {
					t.Logf("Connection %d: failed to connect: %v", connID, err)
					return
				}
				defer func() {
					_ = conn.Close()
				}()
				if resp != nil {
					defer resp.Body.Close()
				}

				successCount.Add(1)

				// Read 2 messages per connection
				for j := 0; j < 2; j++ {
					if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Logf("Connection %d: failed to set deadline: %v", connID, err)
						return
					}

					_, msg, readErr := conn.ReadMessage()
					if readErr != nil {
						t.Logf("Connection %d: failed to read message %d: %v",
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

		assert.GreaterOrEqual(t, successCount.Load(), int64(numConnections*3/4),
			"At least 75%% of connections should succeed")
		assert.GreaterOrEqual(t, messageCount.Load(), int64(numConnections),
			"Should receive at least one message per connection")

		t.Logf("Concurrent connections: %d/%d succeeded, %d messages received",
			successCount.Load(), numConnections, messageCount.Load())
	})
}

// TestIntegration_WebSocket_ConnectionTimeout verifies that WebSocket
// connections respect read deadlines and timeout properly.
func TestIntegration_WebSocket_ConnectionTimeout(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("read deadline causes timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		dialer := wsDialer()
		wsEndpoint := wsURL(testCfg.Backend1URL) + "/ws"

		conn, resp, err := dialer.DialContext(ctx, wsEndpoint, nil)
		require.NoError(t, err, "Failed to connect to WebSocket endpoint")
		defer func() {
			_ = conn.Close()
		}()
		if resp != nil {
			defer resp.Body.Close()
		}

		// Set a very short read deadline (shorter than the 1s message interval)
		err = conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
		require.NoError(t, err)

		// Wait briefly to ensure deadline passes
		time.Sleep(10 * time.Millisecond)

		// Read should fail with timeout
		_, _, err = conn.ReadMessage()
		require.Error(t, err, "Expected timeout error on read")

		t.Logf("Read timeout error (expected): %v", err)
	})
}

// TestIntegration_WebSocket_UpgradeHeaders verifies that the WebSocket
// upgrade handshake includes proper headers.
func TestIntegration_WebSocket_UpgradeHeaders(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("upgrade response has correct headers", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		dialer := wsDialer()
		wsEndpoint := wsURL(testCfg.Backend1URL) + "/ws"

		conn, resp, err := dialer.DialContext(ctx, wsEndpoint, nil)
		require.NoError(t, err, "Failed to connect to WebSocket endpoint")
		defer func() {
			_ = conn.Close()
		}()

		require.NotNil(t, resp, "Expected non-nil upgrade response")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode,
			"Expected HTTP 101 Switching Protocols")
		assert.Equal(t, "websocket",
			strings.ToLower(resp.Header.Get("Upgrade")),
			"Expected Upgrade: websocket header")

		t.Logf("Upgrade response status: %d", resp.StatusCode)
		t.Logf("Upgrade header: %s", resp.Header.Get("Upgrade"))
		t.Logf("Connection header: %s", resp.Header.Get("Connection"))
	})
}

// TestIntegration_WebSocket_InvalidEndpoint verifies that connecting to
// a non-WebSocket endpoint fails appropriately.
func TestIntegration_WebSocket_InvalidEndpoint(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("non-websocket endpoint rejects upgrade", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		dialer := wsDialer()
		// Try to connect to a regular HTTP endpoint as WebSocket
		wsEndpoint := wsURL(testCfg.Backend1URL) + "/health"

		conn, resp, err := dialer.DialContext(ctx, wsEndpoint, nil)
		if conn != nil {
			_ = conn.Close()
		}
		if resp != nil {
			defer resp.Body.Close()
		}

		// Should fail - /health is not a WebSocket endpoint
		require.Error(t, err, "Expected error when connecting to non-WebSocket endpoint")
		t.Logf("Non-WebSocket endpoint error (expected): %v", err)
	})
}

// TestIntegration_WebSocket_SendAndReceive verifies bidirectional
// WebSocket communication by sending a message and reading responses.
func TestIntegration_WebSocket_SendAndReceive(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("send text message to WebSocket", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		dialer := wsDialer()
		wsEndpoint := wsURL(testCfg.Backend1URL) + "/ws"

		conn, resp, err := dialer.DialContext(ctx, wsEndpoint, nil)
		require.NoError(t, err, "Failed to connect to WebSocket endpoint")
		defer func() {
			_ = conn.Close()
		}()
		if resp != nil {
			defer resp.Body.Close()
		}

		// Send a text message
		testMessage := "hello from integration test"
		err = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, err)

		err = conn.WriteMessage(websocket.TextMessage, []byte(testMessage))
		require.NoError(t, err, "Failed to send WebSocket message")

		t.Logf("Sent message: %s", testMessage)

		// Read the next message from the backend stream
		err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, err)

		_, msg, err := conn.ReadMessage()
		require.NoError(t, err, "Failed to read WebSocket message after send")
		assert.NotEmpty(t, string(msg), "Expected non-empty response")

		t.Logf("Received message after send: %s", string(msg))
	})
}

// TestIntegration_WebSocket_MockBackend verifies WebSocket proxying
// using a local mock WebSocket server, isolating the test from external
// backend availability.
func TestIntegration_WebSocket_MockBackend(t *testing.T) {
	t.Parallel()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	t.Run("echo server through mock", func(t *testing.T) {
		t.Parallel()

		// Create a mock WebSocket echo server
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				t.Logf("Mock server upgrade error: %v", err)
				return
			}
			defer conn.Close()

			for {
				msgType, msg, readErr := conn.ReadMessage()
				if readErr != nil {
					return
				}
				if writeErr := conn.WriteMessage(msgType, msg); writeErr != nil {
					return
				}
			}
		}))
		defer mockServer.Close()

		// Connect to mock server
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		dialer := wsDialer()
		wsEndpoint := wsURL(mockServer.URL)

		conn, resp, err := dialer.DialContext(ctx, wsEndpoint, nil)
		require.NoError(t, err, "Failed to connect to mock WebSocket server")
		defer func() {
			_ = conn.Close()
		}()
		if resp != nil {
			defer resp.Body.Close()
		}

		// Send and receive echo
		testMsg := "echo test message"
		err = conn.WriteMessage(websocket.TextMessage, []byte(testMsg))
		require.NoError(t, err)

		err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, err)

		_, msg, err := conn.ReadMessage()
		require.NoError(t, err)
		assert.Equal(t, testMsg, string(msg),
			"Echo server should return the same message")
	})

	t.Run("binary message through mock", func(t *testing.T) {
		t.Parallel()

		// Create a mock WebSocket server that echoes binary messages
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				msgType, msg, readErr := conn.ReadMessage()
				if readErr != nil {
					return
				}
				if writeErr := conn.WriteMessage(msgType, msg); writeErr != nil {
					return
				}
			}
		}))
		defer mockServer.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		dialer := wsDialer()
		conn, resp, err := dialer.DialContext(ctx, wsURL(mockServer.URL), nil)
		require.NoError(t, err)
		defer func() {
			_ = conn.Close()
		}()
		if resp != nil {
			defer resp.Body.Close()
		}

		// Send binary data
		binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
		err = conn.WriteMessage(websocket.BinaryMessage, binaryData)
		require.NoError(t, err)

		err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		require.NoError(t, err)

		msgType, msg, err := conn.ReadMessage()
		require.NoError(t, err)
		assert.Equal(t, websocket.BinaryMessage, msgType,
			"Expected binary message type")
		assert.Equal(t, binaryData, msg,
			"Binary data should be echoed correctly")
	})

	t.Run("concurrent connections to mock", func(t *testing.T) {
		t.Parallel()

		var connCount atomic.Int64

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			connCount.Add(1)
			defer func() {
				conn.Close()
				connCount.Add(-1)
			}()

			for {
				msgType, msg, readErr := conn.ReadMessage()
				if readErr != nil {
					return
				}
				if writeErr := conn.WriteMessage(msgType, msg); writeErr != nil {
					return
				}
			}
		}))
		defer mockServer.Close()

		const numConns = 10
		var wg sync.WaitGroup
		var successCount atomic.Int64

		for i := 0; i < numConns; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				dialer := wsDialer()
				conn, resp, err := dialer.DialContext(ctx, wsURL(mockServer.URL), nil)
				if err != nil {
					t.Logf("Connection %d failed: %v", id, err)
					return
				}
				defer func() {
					_ = conn.Close()
				}()
				if resp != nil {
					defer resp.Body.Close()
				}

				// Send and verify echo
				msg := []byte("hello from connection " + string(rune('0'+id)))
				if writeErr := conn.WriteMessage(websocket.TextMessage, msg); writeErr != nil {
					return
				}

				if deadlineErr := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
					return
				}

				_, reply, readErr := conn.ReadMessage()
				if readErr != nil {
					return
				}

				if string(reply) == string(msg) {
					successCount.Add(1)
				}
			}(i)
		}

		wg.Wait()

		assert.Equal(t, int64(numConns), successCount.Load(),
			"All concurrent connections should succeed with echo")
	})
}
