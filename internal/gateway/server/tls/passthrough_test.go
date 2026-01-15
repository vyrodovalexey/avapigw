// Package tls provides the TLS server implementation for the API Gateway.
package tls

import (
	"context"
	"errors"
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

func TestNewPassthroughProxy(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	proxy := NewPassthroughProxy(manager, logger)

	require.NotNil(t, proxy)
	assert.Equal(t, manager, proxy.backendManager)
	assert.Equal(t, logger, proxy.logger)
	assert.NotNil(t, proxy.bufferPool)
	assert.Equal(t, 32*1024, proxy.bufferSize)
}

func TestNewPassthroughProxyWithConfig(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)

	tests := []struct {
		name               string
		config             *PassthroughProxyConfig
		expectedBufferSize int
	}{
		{
			name:               "nil config uses defaults",
			config:             nil,
			expectedBufferSize: 32 * 1024,
		},
		{
			name: "custom buffer size",
			config: &PassthroughProxyConfig{
				BufferSize: 64 * 1024,
			},
			expectedBufferSize: 64 * 1024,
		},
		{
			name: "zero buffer size uses default",
			config: &PassthroughProxyConfig{
				BufferSize: 0,
			},
			expectedBufferSize: 32 * 1024,
		},
		{
			name: "negative buffer size uses default",
			config: &PassthroughProxyConfig{
				BufferSize: -1,
			},
			expectedBufferSize: 32 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := NewPassthroughProxyWithConfig(manager, logger, tt.config)

			require.NotNil(t, proxy)
			assert.Equal(t, tt.expectedBufferSize, proxy.bufferSize)
		})
	}
}

func TestDefaultPassthroughProxyConfig(t *testing.T) {
	config := DefaultPassthroughProxyConfig()

	require.NotNil(t, config)
	assert.Equal(t, 32*1024, config.BufferSize)
}

func TestPassthroughProxy_Proxy_NilBackend(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create pipe for testing
	clientConn, _ := net.Pipe()
	defer clientConn.Close()

	ctx := context.Background()
	err := proxy.Proxy(ctx, clientConn, []byte("hello"), nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend is nil")
}

func TestPassthroughProxy_Proxy_NoEndpoints(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Add backend with no endpoints
	err := manager.AddBackend(backend.BackendConfig{
		Name:      "test-backend",
		Endpoints: []backend.EndpointConfig{},
	})
	require.NoError(t, err)

	backendSvc := manager.GetBackend("test-backend")
	require.NotNil(t, backendSvc)

	// Create pipe for testing
	clientConn, _ := net.Pipe()
	defer clientConn.Close()

	ctx := context.Background()
	err = proxy.Proxy(ctx, clientConn, []byte("hello"), backendSvc)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no healthy endpoints")
}

func TestPassthroughProxy_ProxyWithAddress(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Accept connections and echo data
	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read and echo back
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write(buf[:n])
	}()

	// Create client connection
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	// Start proxy in goroutine
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var proxyErr error
	var proxyWg sync.WaitGroup
	proxyWg.Add(1)
	go func() {
		defer proxyWg.Done()
		proxyErr = proxy.ProxyWithAddress(ctx, proxyConn, []byte("hello"), serverAddr, 5*time.Second)
	}()

	// Read response from client side
	buf := make([]byte, 1024)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(buf)
	if err == nil {
		assert.Equal(t, "hello", string(buf[:n]))
	}

	// Close connections to end proxy
	clientConn.Close()
	proxyConn.Close()

	proxyWg.Wait()
	serverWg.Wait()

	// Proxy error should be nil or a closed connection error
	if proxyErr != nil {
		assert.True(t, isClosedConnError(proxyErr) || errors.Is(proxyErr, context.Canceled))
	}
}

func TestPassthroughProxy_ProxyWithAddress_ConnectionFailed(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create client connection
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	ctx := context.Background()
	// Use an address that will fail to connect
	err := proxy.ProxyWithAddress(ctx, proxyConn, []byte("hello"), "127.0.0.1:1", 100*time.Millisecond)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to backend")
}

func TestPassthroughProxy_ProxyWithIdleTimeout(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Add backend with the test server endpoint
	err = manager.AddBackend(backend.BackendConfig{
		Name: "test-backend",
		Endpoints: []backend.EndpointConfig{
			{
				Address: "127.0.0.1",
				Port:    listener.Addr().(*net.TCPAddr).Port,
			},
		},
	})
	require.NoError(t, err)

	backendSvc := manager.GetBackend("test-backend")
	require.NotNil(t, backendSvc)

	// Accept connections and echo data
	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read and echo back
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write(buf[:n])
	}()

	// Create client connection
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	// Start proxy in goroutine
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var proxyErr error
	var proxyWg sync.WaitGroup
	proxyWg.Add(1)
	go func() {
		defer proxyWg.Done()
		proxyErr = proxy.ProxyWithIdleTimeout(ctx, proxyConn, []byte("hello"), backendSvc, 5*time.Second, 1*time.Second)
	}()

	// Read response from client side
	buf := make([]byte, 1024)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(buf)
	if err == nil {
		assert.Equal(t, "hello", string(buf[:n]))
	}

	// Close connections to end proxy
	clientConn.Close()
	proxyConn.Close()

	proxyWg.Wait()
	serverWg.Wait()

	// Proxy error should be nil or a closed connection error or context deadline exceeded
	if proxyErr != nil {
		isExpectedError := isClosedConnError(proxyErr) ||
			errors.Is(proxyErr, context.Canceled) ||
			errors.Is(proxyErr, context.DeadlineExceeded)
		if !isExpectedError {
			// Check if it's a network timeout error
			var netErr net.Error
			if errors.As(proxyErr, &netErr) && netErr.Timeout() {
				isExpectedError = true
			}
		}
		assert.True(t, isExpectedError, "unexpected error: %v", proxyErr)
	}

	// Clean up
	_ = manager.RemoveBackend("test-backend")
	_ = serverAddr // Use the variable
}

func TestPassthroughProxy_ProxyWithIdleTimeout_NilBackend(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create pipe for testing
	clientConn, _ := net.Pipe()
	defer clientConn.Close()

	ctx := context.Background()
	err := proxy.ProxyWithIdleTimeout(ctx, clientConn, []byte("hello"), nil, 5*time.Second, 1*time.Second)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend is nil")
}

func TestPassthroughProxy_ProxyWithIdleTimeout_NoEndpoints(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Add backend with no endpoints
	err := manager.AddBackend(backend.BackendConfig{
		Name:      "test-backend",
		Endpoints: []backend.EndpointConfig{},
	})
	require.NoError(t, err)

	backendSvc := manager.GetBackend("test-backend")
	require.NotNil(t, backendSvc)

	// Create pipe for testing
	clientConn, _ := net.Pipe()
	defer clientConn.Close()

	ctx := context.Background()
	err = proxy.ProxyWithIdleTimeout(ctx, clientConn, []byte("hello"), backendSvc, 5*time.Second, 1*time.Second)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no healthy endpoints")
}

func TestIsClosedConnError(t *testing.T) {
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
			name:     "regular error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name: "net.OpError with closed connection",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: errors.New("use of closed network connection"),
			},
			expected: true,
		},
		{
			name: "net.OpError with other error",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: errors.New("connection refused"),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isClosedConnError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPassthroughProxy_BufferPool(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Get buffer from pool (now stores *[]byte)
	bufPtr := proxy.bufferPool.Get().(*[]byte)
	require.NotNil(t, bufPtr)
	buf := *bufPtr
	assert.Len(t, buf, proxy.bufferSize)

	// Put buffer back
	proxy.bufferPool.Put(bufPtr)

	// Get buffer again - should be the same or a new one
	bufPtr2 := proxy.bufferPool.Get().(*[]byte)
	require.NotNil(t, bufPtr2)
	buf2 := *bufPtr2
	assert.Len(t, buf2, proxy.bufferSize)
}

func TestPassthroughProxy_ContextCancellation(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Start a test server that holds connections
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Accept connections but don't respond
	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Hold the connection open
		time.Sleep(5 * time.Second)
	}()

	// Create client connection
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	// Create a context that we'll cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Start proxy in goroutine
	var proxyErr error
	var proxyWg sync.WaitGroup
	proxyWg.Add(1)
	go func() {
		defer proxyWg.Done()
		proxyErr = proxy.ProxyWithAddress(ctx, proxyConn, []byte("hello"), serverAddr, 5*time.Second)
	}()

	// Wait a bit then cancel context
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Wait for proxy to finish
	proxyWg.Wait()

	// Close listener to unblock server goroutine
	listener.Close()
	serverWg.Wait()

	// Proxy should have returned due to context cancellation
	if proxyErr != nil {
		assert.True(t, errors.Is(proxyErr, context.Canceled) || isClosedConnError(proxyErr))
	}
}

func TestPassthroughProxy_BidirectionalCopy(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Start a test server that echoes data
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Accept connections and echo data
	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := listener.Accept()
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
			_, err = conn.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	// Create client connection
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	// Start proxy in goroutine
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var proxyWg sync.WaitGroup
	proxyWg.Add(1)
	go func() {
		defer proxyWg.Done()
		_ = proxy.ProxyWithAddress(ctx, proxyConn, nil, serverAddr, 5*time.Second)
	}()

	// Send data and verify echo
	testData := []byte("test message")
	_, err = clientConn.Write(testData)
	require.NoError(t, err)

	// Read response
	buf := make([]byte, 1024)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n])

	// Close connections
	clientConn.Close()
	proxyConn.Close()

	proxyWg.Wait()
	listener.Close()
	serverWg.Wait()
}

func TestPassthroughProxy_EmptyClientHello(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Accept connections
	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Just close immediately
	}()

	// Create client connection
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	// Start proxy with empty clientHello
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var proxyWg sync.WaitGroup
	proxyWg.Add(1)
	go func() {
		defer proxyWg.Done()
		_ = proxy.ProxyWithAddress(ctx, proxyConn, []byte{}, serverAddr, 5*time.Second)
	}()

	// Close connections
	time.Sleep(100 * time.Millisecond)
	clientConn.Close()
	proxyConn.Close()

	proxyWg.Wait()
	listener.Close()
	serverWg.Wait()
}

func TestPassthroughProxy_Proxy_Success(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Add backend with the test server endpoint
	err = manager.AddBackend(backend.BackendConfig{
		Name: "test-backend",
		Endpoints: []backend.EndpointConfig{
			{
				Address: "127.0.0.1",
				Port:    listener.Addr().(*net.TCPAddr).Port,
			},
		},
	})
	require.NoError(t, err)

	backendSvc := manager.GetBackend("test-backend")
	require.NotNil(t, backendSvc)

	// Accept connections and echo data
	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read and echo back
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write(buf[:n])
	}()

	// Create client connection
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	// Start proxy in goroutine
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var proxyErr error
	var proxyWg sync.WaitGroup
	proxyWg.Add(1)
	go func() {
		defer proxyWg.Done()
		proxyErr = proxy.Proxy(ctx, proxyConn, []byte("hello"), backendSvc)
	}()

	// Read response from client side
	buf := make([]byte, 1024)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(buf)
	if err == nil {
		assert.Equal(t, "hello", string(buf[:n]))
	}

	// Close connections to end proxy
	clientConn.Close()
	proxyConn.Close()

	proxyWg.Wait()
	serverWg.Wait()

	// Proxy error should be nil or a closed connection error
	if proxyErr != nil {
		assert.True(t, isClosedConnError(proxyErr) || errors.Is(proxyErr, context.Canceled))
	}

	// Clean up
	_ = manager.RemoveBackend("test-backend")
}
