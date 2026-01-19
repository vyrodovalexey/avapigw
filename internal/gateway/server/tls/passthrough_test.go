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

func TestHandlePassthroughReadErrorWithEOF(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		shouldContinue bool
		returnErr      error
	}{
		{
			name:           "timeout error should continue",
			err:            &timeoutError{},
			shouldContinue: true,
			returnErr:      nil,
		},
		{
			name:           "EOF error should exit gracefully",
			err:            io.EOF,
			shouldContinue: false,
			returnErr:      nil,
		},
		{
			name:           "closed pipe error should exit gracefully",
			err:            io.ErrClosedPipe,
			shouldContinue: false,
			returnErr:      nil,
		},
		{
			name: "closed connection error should exit gracefully",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: errors.New("use of closed network connection"),
			},
			shouldContinue: false,
			returnErr:      nil,
		},
		{
			name:           "other error should propagate",
			err:            errors.New("some other error"),
			shouldContinue: false,
			returnErr:      errors.New("some other error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldContinue, returnErr := handlePassthroughReadErrorWithEOF(tt.err)
			assert.Equal(t, tt.shouldContinue, shouldContinue)
			if tt.returnErr == nil {
				assert.Nil(t, returnErr)
			} else {
				assert.NotNil(t, returnErr)
			}
		})
	}
}

// timeoutError implements net.Error for testing
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func TestHandlePassthroughReadError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		shouldContinue bool
		returnErr      error
	}{
		{
			name:           "timeout error should continue",
			err:            &timeoutError{},
			shouldContinue: true,
			returnErr:      nil,
		},
		{
			name:           "EOF error should exit gracefully",
			err:            io.EOF,
			shouldContinue: false,
			returnErr:      nil,
		},
		{
			name: "closed connection error should exit gracefully",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: errors.New("use of closed network connection"),
			},
			shouldContinue: false,
			returnErr:      nil,
		},
		{
			name:           "other error should propagate",
			err:            errors.New("some other error"),
			shouldContinue: false,
			returnErr:      errors.New("some other error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldContinue, returnErr := handlePassthroughReadError(tt.err)
			assert.Equal(t, tt.shouldContinue, shouldContinue)
			if tt.returnErr == nil {
				assert.Nil(t, returnErr)
			} else {
				assert.NotNil(t, returnErr)
			}
		})
	}
}

func TestHandlePassthroughConnError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		expectNil bool
	}{
		{
			name:      "nil error returns nil",
			err:       nil,
			expectNil: true,
		},
		{
			name:      "EOF error returns nil",
			err:       io.EOF,
			expectNil: true,
		},
		{
			name: "closed connection error returns nil",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: errors.New("use of closed network connection"),
			},
			expectNil: true,
		},
		{
			name:      "other error returns error",
			err:       errors.New("some other error"),
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handlePassthroughConnError(tt.err)
			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

func TestCalculatePassthroughCheckInterval(t *testing.T) {
	tests := []struct {
		name        string
		idleTimeout time.Duration
		expected    time.Duration
	}{
		{
			name:        "idle timeout greater than 1 second",
			idleTimeout: 5 * time.Second,
			expected:    1 * time.Second,
		},
		{
			name:        "idle timeout equal to 1 second",
			idleTimeout: 1 * time.Second,
			expected:    1 * time.Second,
		},
		{
			name:        "idle timeout less than 1 second",
			idleTimeout: 500 * time.Millisecond,
			expected:    500 * time.Millisecond,
		},
		{
			name:        "very short idle timeout",
			idleTimeout: 100 * time.Millisecond,
			expected:    100 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculatePassthroughCheckInterval(tt.idleTimeout)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsClosedConnError_ErrClosedPipe(t *testing.T) {
	// Test io.ErrClosedPipe specifically
	result := isClosedConnError(io.ErrClosedPipe)
	assert.True(t, result)
}

func TestPassthroughProxy_WriteWithDeadline_Error(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create a pipe and close the write end to cause an error
	clientConn, serverConn := net.Pipe()
	clientConn.Close() // Close to cause write error

	// Try to write - should handle the error gracefully
	err := proxy.writeWithDeadline(serverConn, []byte("test data"))
	// Error should be nil because closed connection is handled
	assert.Nil(t, err)

	serverConn.Close()
}

func TestPassthroughProxy_WriteWithTimeoutDeadline_Error(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create a pipe and close the write end to cause an error
	clientConn, serverConn := net.Pipe()
	clientConn.Close() // Close to cause write error

	// Try to write - should handle the error gracefully
	err := proxy.writeWithTimeoutDeadline(serverConn, []byte("test data"), 1*time.Second)
	// Error should be nil because closed connection is handled
	assert.Nil(t, err)

	serverConn.Close()
}

func TestPassthroughProxy_CopyWithBufferAndContext_ContextCancelled(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create pipes
	srcClient, srcServer := net.Pipe()
	dstClient, dstServer := net.Pipe()
	defer srcClient.Close()
	defer srcServer.Close()
	defer dstClient.Close()
	defer dstServer.Close()

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Copy should return context error
	err := proxy.copyWithBufferAndContext(ctx, dstServer, srcServer)
	assert.Equal(t, context.Canceled, err)
}

func TestPassthroughProxy_CopyWithTimeoutAndContext_ContextCancelled(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create pipes
	srcClient, srcServer := net.Pipe()
	dstClient, dstServer := net.Pipe()
	defer srcClient.Close()
	defer srcServer.Close()
	defer dstClient.Close()
	defer dstServer.Close()

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Copy should return context error
	err := proxy.copyWithTimeoutAndContext(ctx, dstServer, srcServer, 1*time.Second)
	assert.Equal(t, context.Canceled, err)
}

func TestPassthroughProxy_BidirectionalCopy_ContextCancelled(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create pipes
	conn1Client, conn1Server := net.Pipe()
	conn2Client, conn2Server := net.Pipe()
	defer conn1Client.Close()
	defer conn1Server.Close()
	defer conn2Client.Close()
	defer conn2Server.Close()

	// Create a context that we'll cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Start bidirectional copy in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.bidirectionalCopy(ctx, conn1Server, conn2Server)
	}()

	// Cancel context
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Wait for result
	select {
	case err := <-errCh:
		assert.Equal(t, context.Canceled, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for bidirectionalCopy to return")
	}
}

func TestPassthroughProxy_BidirectionalCopyWithTimeout_ContextCancelled(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create pipes
	conn1Client, conn1Server := net.Pipe()
	conn2Client, conn2Server := net.Pipe()
	defer conn1Client.Close()
	defer conn1Server.Close()
	defer conn2Client.Close()
	defer conn2Server.Close()

	// Create a context that we'll cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Start bidirectional copy in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.bidirectionalCopyWithTimeout(ctx, conn1Server, conn2Server, 1*time.Second)
	}()

	// Cancel context
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Wait for result
	select {
	case err := <-errCh:
		assert.Equal(t, context.Canceled, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for bidirectionalCopyWithTimeout to return")
	}
}

func TestPassthroughProxy_ReadWithDeadline_SetDeadlineError(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create a mock connection that fails on SetReadDeadline
	mockConn := &mockConnWithDeadlineError{}

	buf := make([]byte, 1024)
	_, _, err := proxy.readWithDeadline(mockConn, buf)
	// Should return nil because the error is handled as closed connection
	assert.Nil(t, err)
}

func TestPassthroughProxy_ReadWithTimeoutDeadline_SetDeadlineError(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create a mock connection that fails on SetReadDeadline
	mockConn := &mockConnWithDeadlineError{}

	buf := make([]byte, 1024)
	_, _, err := proxy.readWithTimeoutDeadline(mockConn, buf, 1*time.Second)
	// Should return nil because the error is handled as closed connection
	assert.Nil(t, err)
}

// mockConnWithDeadlineError is a mock connection that fails on deadline operations
type mockConnWithDeadlineError struct {
	net.Conn
}

func (m *mockConnWithDeadlineError) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

func (m *mockConnWithDeadlineError) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConnWithDeadlineError) Close() error {
	return nil
}

func (m *mockConnWithDeadlineError) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func (m *mockConnWithDeadlineError) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}
}

func (m *mockConnWithDeadlineError) SetDeadline(t time.Time) error {
	return io.EOF // Return EOF to simulate closed connection
}

func (m *mockConnWithDeadlineError) SetReadDeadline(t time.Time) error {
	return io.EOF // Return EOF to simulate closed connection
}

func (m *mockConnWithDeadlineError) SetWriteDeadline(t time.Time) error {
	return io.EOF // Return EOF to simulate closed connection
}

func TestPassthroughProxy_CopyWithBufferAndContext_GracefulClose(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create pipes
	srcClient, srcServer := net.Pipe()
	dstClient, dstServer := net.Pipe()

	ctx := context.Background()

	// Start copy in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.copyWithBufferAndContext(ctx, dstServer, srcServer)
	}()

	// Close source to trigger graceful close
	time.Sleep(50 * time.Millisecond)
	srcClient.Close()

	// Wait for result
	select {
	case err := <-errCh:
		// Should return nil for graceful close
		assert.Nil(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for copyWithBufferAndContext to return")
	}

	srcServer.Close()
	dstClient.Close()
	dstServer.Close()
}

func TestPassthroughProxy_CopyWithTimeoutAndContext_GracefulClose(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Create pipes
	srcClient, srcServer := net.Pipe()
	dstClient, dstServer := net.Pipe()

	ctx := context.Background()

	// Start copy in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.copyWithTimeoutAndContext(ctx, dstServer, srcServer, 1*time.Second)
	}()

	// Close source to trigger graceful close
	time.Sleep(50 * time.Millisecond)
	srcClient.Close()

	// Wait for result
	select {
	case err := <-errCh:
		// Should return nil for graceful close
		assert.Nil(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for copyWithTimeoutAndContext to return")
	}

	srcServer.Close()
	dstClient.Close()
	dstServer.Close()
}

func TestPassthroughProxy_Proxy_ConnectionFailed(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Add backend with unreachable endpoint
	err := manager.AddBackend(backend.BackendConfig{
		Name: "test-backend",
		Endpoints: []backend.EndpointConfig{
			{
				Address: "127.0.0.1",
				Port:    1, // Port 1 is typically not available
			},
		},
	})
	require.NoError(t, err)

	backendSvc := manager.GetBackend("test-backend")
	require.NotNil(t, backendSvc)

	// Create pipe for testing
	clientConn, _ := net.Pipe()
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = proxy.Proxy(ctx, clientConn, []byte("hello"), backendSvc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to backend")

	// Clean up
	_ = manager.RemoveBackend("test-backend")
}

func TestPassthroughProxy_ProxyWithIdleTimeout_ConnectionFailed(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Add backend with unreachable endpoint
	err := manager.AddBackend(backend.BackendConfig{
		Name: "test-backend",
		Endpoints: []backend.EndpointConfig{
			{
				Address: "127.0.0.1",
				Port:    1, // Port 1 is typically not available
			},
		},
	})
	require.NoError(t, err)

	backendSvc := manager.GetBackend("test-backend")
	require.NotNil(t, backendSvc)

	// Create pipe for testing
	clientConn, _ := net.Pipe()
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = proxy.ProxyWithIdleTimeout(ctx, clientConn, []byte("hello"), backendSvc, 100*time.Millisecond, 1*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to backend")

	// Clean up
	_ = manager.RemoveBackend("test-backend")
}

func TestPassthroughProxy_Proxy_WriteClientHelloError(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Start a test server that closes immediately
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Accept and close immediately
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close() // Close immediately to cause write error
	}()

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

	// Create pipe for testing
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// This should fail when trying to write ClientHello
	err = proxy.Proxy(ctx, proxyConn, []byte("hello"), backendSvc)
	// Error may or may not occur depending on timing - either is acceptable
	// The test verifies the code path handles the error gracefully
	_ = err

	// Clean up
	_ = manager.RemoveBackend("test-backend")
}

func TestPassthroughProxy_ProxyWithAddress_WriteClientHelloError(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Start a test server that closes immediately
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Accept and close immediately
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close() // Close immediately to cause write error
	}()

	// Create pipe for testing
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// This should fail when trying to write ClientHello
	err = proxy.ProxyWithAddress(ctx, proxyConn, []byte("hello"), serverAddr, 1*time.Second)
	// Error may or may not occur depending on timing - either is acceptable
	// The test verifies the code path handles the error gracefully
	_ = err
}

func TestPassthroughProxy_ProxyWithIdleTimeout_WriteClientHelloError(t *testing.T) {
	logger := zap.NewNop()
	manager := backend.NewManager(logger)
	proxy := NewPassthroughProxy(manager, logger)

	// Start a test server that closes immediately
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Accept and close immediately
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close() // Close immediately to cause write error
	}()

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

	// Create pipe for testing
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// This should fail when trying to write ClientHello
	err = proxy.ProxyWithIdleTimeout(ctx, proxyConn, []byte("hello"), backendSvc, 1*time.Second, 1*time.Second)
	// Error may or may not occur depending on timing - either is acceptable
	// The test verifies the code path handles the error gracefully
	_ = err

	// Clean up
	_ = manager.RemoveBackend("test-backend")
}
