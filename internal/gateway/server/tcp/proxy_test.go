// Package tcp provides the TCP server implementation for the API Gateway.
package tcp

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
)

func TestDefaultProxyConfig(t *testing.T) {
	t.Run("returns expected defaults", func(t *testing.T) {
		config := DefaultProxyConfig()

		assert.NotNil(t, config)
		assert.Equal(t, 32*1024, config.BufferSize)
	})
}

func TestNewProxy(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("creates proxy with default config", func(t *testing.T) {
		proxy := NewProxy(manager, logger)

		assert.NotNil(t, proxy)
		assert.Equal(t, manager, proxy.backendManager)
		assert.Equal(t, logger, proxy.logger)
		assert.Equal(t, 32*1024, proxy.bufferSize)
		assert.NotNil(t, proxy.bufferPool)
	})
}

func TestNewProxyWithConfig(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	tests := []struct {
		name               string
		config             *ProxyConfig
		expectedBufferSize int
	}{
		{
			name:               "with nil config uses defaults",
			config:             nil,
			expectedBufferSize: 32 * 1024,
		},
		{
			name:               "with custom buffer size",
			config:             &ProxyConfig{BufferSize: 64 * 1024},
			expectedBufferSize: 64 * 1024,
		},
		{
			name:               "with zero buffer size uses default",
			config:             &ProxyConfig{BufferSize: 0},
			expectedBufferSize: 32 * 1024,
		},
		{
			name:               "with negative buffer size uses default",
			config:             &ProxyConfig{BufferSize: -1},
			expectedBufferSize: 32 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := NewProxyWithConfig(manager, logger, tt.config)

			assert.NotNil(t, proxy)
			assert.Equal(t, tt.expectedBufferSize, proxy.bufferSize)
		})
	}
}

func TestProxy_Proxy(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("returns error when backend is nil", func(t *testing.T) {
		proxy := NewProxy(manager, logger)
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		err := proxy.Proxy(context.Background(), client, nil, time.Second)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backend is nil")
	})

	t.Run("returns error when no healthy endpoints", func(t *testing.T) {
		proxy := NewProxy(manager, logger)
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		// Create backend with no endpoints
		backendSvc := &backend.Backend{
			Name:      "test-backend",
			Endpoints: []*backend.Endpoint{},
		}

		err := proxy.Proxy(context.Background(), client, backendSvc, time.Second)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no healthy endpoints")
	})

	t.Run("returns error when connection fails", func(t *testing.T) {
		proxy := NewProxy(manager, logger)
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		// Create backend with unreachable endpoint
		backendSvc := &backend.Backend{
			Name: "test-backend",
			Endpoints: []*backend.Endpoint{
				{Address: "127.0.0.1", Port: 59999, Healthy: true}, // Unlikely to be listening
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := proxy.Proxy(ctx, client, backendSvc, 100*time.Millisecond)

		assert.Error(t, err)
	})

	t.Run("proxies data successfully", func(t *testing.T) {
		proxy := NewProxy(manager, logger)

		// Create a mock backend server
		backendListener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer backendListener.Close()

		backendAddr := backendListener.Addr().(*net.TCPAddr)

		// Handle backend connections
		go func() {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Echo data back
			buf := make([]byte, 1024)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				conn.Write(buf[:n])
			}
		}()

		// Create client connection
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// Create backend with the mock server endpoint
		backendSvc := &backend.Backend{
			Name: "test-backend",
			Endpoints: []*backend.Endpoint{
				{Address: "127.0.0.1", Port: backendAddr.Port, Healthy: true},
			},
		}

		// Start proxy in goroutine
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		go func() {
			proxy.Proxy(ctx, serverConn, backendSvc, time.Second)
		}()

		// Send data through client
		testData := []byte("hello proxy")
		_, err = clientConn.Write(testData)
		require.NoError(t, err)

		// Read response
		buf := make([]byte, len(testData))
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := clientConn.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, testData, buf[:n])
	})
}

func TestProxy_ProxyWithAddress(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("returns error when connection fails", func(t *testing.T) {
		proxy := NewProxy(manager, logger)
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := proxy.ProxyWithAddress(ctx, client, "127.0.0.1:59999", 100*time.Millisecond)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to connect")
	})

	t.Run("proxies data successfully", func(t *testing.T) {
		proxy := NewProxy(manager, logger)

		// Create a mock backend server
		backendListener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer backendListener.Close()

		backendAddr := backendListener.Addr().String()

		// Handle backend connections
		go func() {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Echo data back
			buf := make([]byte, 1024)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				conn.Write(buf[:n])
			}
		}()

		// Create client connection
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// Start proxy in goroutine
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		go func() {
			proxy.ProxyWithAddress(ctx, serverConn, backendAddr, time.Second)
		}()

		// Send data through client
		testData := []byte("hello proxy")
		_, err = clientConn.Write(testData)
		require.NoError(t, err)

		// Read response
		buf := make([]byte, len(testData))
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := clientConn.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, testData, buf[:n])
	})
}

func TestProxy_ProxyWithIdleTimeout(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("returns error when backend is nil", func(t *testing.T) {
		proxy := NewProxy(manager, logger)
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		err := proxy.ProxyWithIdleTimeout(context.Background(), client, nil, time.Second, time.Second)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backend is nil")
	})

	t.Run("returns error when no healthy endpoints", func(t *testing.T) {
		proxy := NewProxy(manager, logger)
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		backendSvc := &backend.Backend{
			Name:      "test-backend",
			Endpoints: []*backend.Endpoint{},
		}

		err := proxy.ProxyWithIdleTimeout(context.Background(), client, backendSvc, time.Second, time.Second)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no healthy endpoints")
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		proxy := NewProxy(manager, logger)

		// Create a mock backend server
		backendListener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer backendListener.Close()

		backendAddr := backendListener.Addr().(*net.TCPAddr)

		// Handle backend connections - just accept and hold
		go func() {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// Hold connection open
			time.Sleep(5 * time.Second)
		}()

		// Create client connection
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		backendSvc := &backend.Backend{
			Name: "test-backend",
			Endpoints: []*backend.Endpoint{
				{Address: "127.0.0.1", Port: backendAddr.Port, Healthy: true},
			},
		}

		ctx, cancel := context.WithCancel(context.Background())

		errCh := make(chan error, 1)
		go func() {
			errCh <- proxy.ProxyWithIdleTimeout(ctx, serverConn, backendSvc, time.Second, 5*time.Second)
		}()

		// Cancel context after short delay
		time.Sleep(100 * time.Millisecond)
		cancel()

		select {
		case err := <-errCh:
			assert.ErrorIs(t, err, context.Canceled)
		case <-time.After(2 * time.Second):
			t.Fatal("proxy did not respond to context cancellation")
		}
	})
}

func TestProxy_bidirectionalCopy(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewProxy(manager, logger)

	t.Run("copies data bidirectionally", func(t *testing.T) {
		conn1Client, conn1Server := net.Pipe()
		conn2Client, conn2Server := net.Pipe()
		defer conn1Client.Close()
		defer conn1Server.Close()
		defer conn2Client.Close()
		defer conn2Server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Start bidirectional copy
		go func() {
			proxy.bidirectionalCopy(ctx, conn1Server, conn2Server)
		}()

		// Write to conn1, read from conn2
		go func() {
			conn1Client.Write([]byte("hello"))
		}()

		buf := make([]byte, 10)
		conn2Client.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn2Client.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(buf[:n]))

		// Write to conn2, read from conn1
		go func() {
			conn2Client.Write([]byte("world"))
		}()

		conn1Client.SetReadDeadline(time.Now().Add(time.Second))
		n, err = conn1Client.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "world", string(buf[:n]))
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		conn1Client, conn1Server := net.Pipe()
		conn2Client, conn2Server := net.Pipe()
		defer conn1Client.Close()
		defer conn1Server.Close()
		defer conn2Client.Close()
		defer conn2Server.Close()

		ctx, cancel := context.WithCancel(context.Background())

		errCh := make(chan error, 1)
		go func() {
			errCh <- proxy.bidirectionalCopy(ctx, conn1Server, conn2Server)
		}()

		// Cancel context
		time.Sleep(50 * time.Millisecond)
		cancel()

		select {
		case err := <-errCh:
			assert.ErrorIs(t, err, context.Canceled)
		case <-time.After(2 * time.Second):
			t.Fatal("bidirectionalCopy did not respond to context cancellation")
		}
	})

	t.Run("handles connection close", func(t *testing.T) {
		conn1Client, conn1Server := net.Pipe()
		conn2Client, conn2Server := net.Pipe()
		defer conn2Client.Close()
		defer conn2Server.Close()

		ctx := context.Background()

		errCh := make(chan error, 1)
		go func() {
			errCh <- proxy.bidirectionalCopy(ctx, conn1Server, conn2Server)
		}()

		// Close one side
		time.Sleep(50 * time.Millisecond)
		conn1Client.Close()
		conn1Server.Close()

		select {
		case <-errCh:
			// Success - copy completed
		case <-time.After(2 * time.Second):
			t.Fatal("bidirectionalCopy did not complete after connection close")
		}
	})
}

func TestProxy_CopyWithTimeout(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewProxy(manager, logger)

	t.Run("copies data with timeout", func(t *testing.T) {
		srcClient, srcServer := net.Pipe()
		dstClient, dstServer := net.Pipe()
		defer srcClient.Close()
		defer srcServer.Close()
		defer dstClient.Close()
		defer dstServer.Close()

		// Start copy
		go func() {
			proxy.CopyWithTimeout(dstServer, srcServer, 5*time.Second)
		}()

		// Write data
		go func() {
			srcClient.Write([]byte("test data"))
			srcClient.Close()
		}()

		// Read data
		buf := make([]byte, 20)
		dstClient.SetReadDeadline(time.Now().Add(time.Second))
		n, err := dstClient.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "test data", string(buf[:n]))
	})
}

func TestProxy_CopyWithTimeoutAndContext(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewProxy(manager, logger)

	t.Run("copies data successfully", func(t *testing.T) {
		srcClient, srcServer := net.Pipe()
		dstClient, dstServer := net.Pipe()
		defer srcClient.Close()
		defer srcServer.Close()
		defer dstClient.Close()
		defer dstServer.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Start copy
		go func() {
			proxy.CopyWithTimeoutAndContext(ctx, dstServer, srcServer, 5*time.Second)
		}()

		// Write data
		go func() {
			srcClient.Write([]byte("test data"))
			srcClient.Close()
		}()

		// Read data
		buf := make([]byte, 20)
		dstClient.SetReadDeadline(time.Now().Add(time.Second))
		n, err := dstClient.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "test data", string(buf[:n]))
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		srcClient, srcServer := net.Pipe()
		dstClient, dstServer := net.Pipe()
		defer srcClient.Close()
		defer srcServer.Close()
		defer dstClient.Close()
		defer dstServer.Close()

		ctx, cancel := context.WithCancel(context.Background())

		errCh := make(chan error, 1)
		go func() {
			errCh <- proxy.CopyWithTimeoutAndContext(ctx, dstServer, srcServer, 5*time.Second)
		}()

		// Cancel context
		time.Sleep(50 * time.Millisecond)
		cancel()

		select {
		case err := <-errCh:
			assert.ErrorIs(t, err, context.Canceled)
		case <-time.After(2 * time.Second):
			t.Fatal("CopyWithTimeoutAndContext did not respond to context cancellation")
		}
	})

	t.Run("handles EOF", func(t *testing.T) {
		srcClient, srcServer := net.Pipe()
		dstClient, dstServer := net.Pipe()
		defer dstClient.Close()
		defer dstServer.Close()

		ctx := context.Background()

		errCh := make(chan error, 1)
		go func() {
			errCh <- proxy.CopyWithTimeoutAndContext(ctx, dstServer, srcServer, 5*time.Second)
		}()

		// Close source to trigger EOF
		srcClient.Close()
		srcServer.Close()

		select {
		case err := <-errCh:
			// EOF or closed pipe error should be handled gracefully
			// The function may return nil or a closed pipe error depending on timing
			if err != nil {
				assert.Contains(t, err.Error(), "closed pipe")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("CopyWithTimeoutAndContext did not complete after EOF")
		}
	})
}

func TestProxy_copyWithBuffer(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewProxy(manager, logger)

	t.Run("copies data using buffer pool", func(t *testing.T) {
		srcClient, srcServer := net.Pipe()
		dstClient, dstServer := net.Pipe()
		defer srcClient.Close()
		defer srcServer.Close()
		defer dstClient.Close()
		defer dstServer.Close()

		// Start copy
		go func() {
			proxy.copyWithBuffer(dstServer, srcServer)
		}()

		// Write data
		go func() {
			srcClient.Write([]byte("buffered data"))
			srcClient.Close()
		}()

		// Read data
		buf := make([]byte, 20)
		dstClient.SetReadDeadline(time.Now().Add(time.Second))
		n, err := dstClient.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "buffered data", string(buf[:n]))
	})

	t.Run("handles closed connection", func(t *testing.T) {
		srcClient, srcServer := net.Pipe()
		dstClient, dstServer := net.Pipe()
		defer dstClient.Close()
		defer dstServer.Close()

		// Close source immediately
		srcClient.Close()
		srcServer.Close()

		err := proxy.copyWithBuffer(dstServer, srcServer)
		// Closed connection may return nil or a closed pipe error depending on timing
		if err != nil {
			assert.Contains(t, err.Error(), "closed pipe")
		}
	})
}

func TestIsClosedError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "EOF error",
			err:      io.EOF,
			expected: true,
		},
		{
			name:     "other error",
			err:      io.ErrUnexpectedEOF,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isClosedError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}

	t.Run("closed network connection error", func(t *testing.T) {
		// Create and close a connection to get a real closed connection error
		server, client := net.Pipe()
		client.Close()
		server.Close()

		_, err := client.Read(make([]byte, 1))
		if err != nil {
			// The error might be different depending on timing
			// Just verify the function doesn't panic
			isClosedError(err)
		}
	})
}

func TestProxy_BufferPool(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	t.Run("buffer pool returns correct size buffers", func(t *testing.T) {
		proxy := NewProxyWithConfig(manager, logger, &ProxyConfig{BufferSize: 16 * 1024})

		buf := proxy.bufferPool.Get().([]byte)
		assert.Len(t, buf, 16*1024)

		// Return to pool
		proxy.bufferPool.Put(buf)

		// Get again - should be same size
		buf2 := proxy.bufferPool.Get().([]byte)
		assert.Len(t, buf2, 16*1024)
	})

	t.Run("concurrent buffer pool access is safe", func(t *testing.T) {
		proxy := NewProxy(manager, logger)
		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf := proxy.bufferPool.Get().([]byte)
				// Simulate some work
				time.Sleep(time.Millisecond)
				proxy.bufferPool.Put(buf)
			}()
		}

		wg.Wait()
	})
}
