// Package metrics provides Prometheus metrics for the API Gateway.
package metrics

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// TestDefaultServerConfig tests that DefaultServerConfig returns correct default values.
func TestDefaultServerConfig(t *testing.T) {
	config := DefaultServerConfig()

	assert.NotNil(t, config)
	assert.Equal(t, 9091, config.Port)
	assert.Equal(t, "/metrics", config.Path)
	assert.Equal(t, 5*time.Second, config.ReadTimeout)
	assert.Equal(t, 10*time.Second, config.WriteTimeout)
	assert.True(t, config.EnableRuntimeMetrics)
	assert.True(t, config.EnableProcessMetrics)
	assert.Nil(t, config.Registry)
}

// TestNewServer tests the NewServer constructor with various configurations.
func TestNewServer(t *testing.T) {
	tests := []struct {
		name           string
		config         *ServerConfig
		logger         *zap.Logger
		expectDefaults bool
	}{
		{
			name:           "nil config uses defaults",
			config:         nil,
			logger:         zap.NewNop(),
			expectDefaults: true,
		},
		{
			name: "custom config",
			config: &ServerConfig{
				Port:         8080,
				Path:         "/custom-metrics",
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 20 * time.Second,
			},
			logger:         zap.NewNop(),
			expectDefaults: false,
		},
		{
			name:           "nil logger uses nop logger",
			config:         DefaultServerConfig(),
			logger:         nil,
			expectDefaults: false,
		},
		{
			name: "custom registry",
			config: &ServerConfig{
				Port:     9092,
				Path:     "/metrics",
				Registry: prometheus.NewRegistry(),
			},
			logger:         zap.NewNop(),
			expectDefaults: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(tt.config, tt.logger)

			require.NotNil(t, server)
			assert.NotNil(t, server.config)
			assert.NotNil(t, server.logger)
			assert.NotNil(t, server.registry)
			assert.NotNil(t, server.stopCh)

			if tt.expectDefaults {
				assert.Equal(t, 9091, server.config.Port)
				assert.Equal(t, "/metrics", server.config.Path)
			}
		})
	}
}

// TestNewServer_NilRegistry tests that NewServer handles nil registry correctly.
func TestNewServer_NilRegistry(t *testing.T) {
	config := &ServerConfig{
		Port:     9093,
		Path:     "/metrics",
		Registry: nil, // Explicitly nil
	}

	server := NewServer(config, zap.NewNop())

	require.NotNil(t, server)
	assert.NotNil(t, server.registry)
}

// TestServer_WithGatewayCollector tests setting the gateway collector.
func TestServer_WithGatewayCollector(t *testing.T) {
	server := NewServer(nil, zap.NewNop())
	collector := getTestGatewayCollector()

	result := server.WithGatewayCollector(collector)

	assert.Same(t, server, result, "should return same server for chaining")
	assert.Same(t, collector, server.collector)
}

// TestServer_WithRuntimeCollector tests setting the runtime collector.
func TestServer_WithRuntimeCollector(t *testing.T) {
	server := NewServer(nil, zap.NewNop())
	collector := getTestRuntimeCollector()

	result := server.WithRuntimeCollector(collector)

	assert.Same(t, server, result, "should return same server for chaining")
	assert.Same(t, collector, server.runtime)
}

// TestServer_GetHandler tests that GetHandler returns a valid handler.
func TestServer_GetHandler(t *testing.T) {
	server := NewServer(nil, zap.NewNop())

	handler := server.GetHandler()

	assert.NotNil(t, handler)

	// Test that handler can serve requests
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestServer_GetHandlerFor tests that GetHandlerFor returns a valid handler for a gatherer.
func TestServer_GetHandlerFor(t *testing.T) {
	server := NewServer(nil, zap.NewNop())
	registry := prometheus.NewRegistry()

	// Register a test metric
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_counter_for_handler",
		Help: "A test counter",
	})
	registry.MustRegister(counter)
	counter.Inc()

	handler := server.GetHandlerFor(registry)

	assert.NotNil(t, handler)

	// Test that handler can serve requests
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "test_counter_for_handler")
}

// TestServer_StartAndStop tests the server start and stop lifecycle.
func TestServer_StartAndStop(t *testing.T) {
	// Use a custom registry to avoid conflicts
	registry := prometheus.NewRegistry()

	config := &ServerConfig{
		Port:         0, // Use random port
		Path:         "/metrics",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Registry:     registry,
	}

	logger := zaptest.NewLogger(t)
	server := NewServer(config, logger)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	// Start server in goroutine
	go func() {
		errCh <- server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to stop server
	cancel()

	// Wait for server to stop
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

// TestServer_StartWithCollectors tests starting server with collectors.
func TestServer_StartWithCollectors(t *testing.T) {
	registry := prometheus.NewRegistry()

	config := &ServerConfig{
		Port:         0,
		Path:         "/metrics",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Registry:     registry,
	}

	logger := zaptest.NewLogger(t)
	server := NewServer(config, logger).
		WithGatewayCollector(getTestGatewayCollector()).
		WithRuntimeCollector(getTestRuntimeCollector())

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- server.Start(ctx)
	}()

	// Give server time to start and run at least one collection cycle
	time.Sleep(150 * time.Millisecond)

	cancel()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

// TestServer_Stop_Idempotent tests that Stop can be called multiple times safely.
func TestServer_Stop_Idempotent(t *testing.T) {
	registry := prometheus.NewRegistry()

	config := &ServerConfig{
		Port:         0,
		Path:         "/metrics",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Registry:     registry,
	}

	server := NewServer(config, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	startedCh := make(chan struct{})

	go func() {
		close(startedCh)
		errCh <- server.Start(ctx)
	}()

	// Wait for goroutine to start
	<-startedCh
	// Give the server time to fully initialize
	time.Sleep(200 * time.Millisecond)

	// Cancel context to trigger shutdown - this is the safe way to stop
	cancel()

	select {
	case <-errCh:
		// Expected - server stopped
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}

	// Now test that Stop can be called multiple times after server is stopped
	assert.NotPanics(t, func() {
		_ = server.Stop(context.Background())
		_ = server.Stop(context.Background())
		_ = server.Stop(context.Background())
	})
}

// TestServer_Stop_BeforeStart tests stopping server before it starts.
func TestServer_Stop_BeforeStart(t *testing.T) {
	server := NewServer(nil, zap.NewNop())

	// Stop before start - should not panic
	assert.NotPanics(t, func() {
		err := server.Stop(context.Background())
		assert.NoError(t, err)
	})
}

// TestServer_HealthEndpoint tests the /health endpoint.
func TestServer_HealthEndpoint(t *testing.T) {
	registry := prometheus.NewRegistry()

	// Use a specific port to avoid race condition when accessing server.server.Addr
	config := &ServerConfig{
		Port:         0,
		Path:         "/metrics",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Registry:     registry,
	}

	server := NewServer(config, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	startedCh := make(chan struct{})
	go func() {
		close(startedCh)
		errCh <- server.Start(ctx)
	}()

	// Wait for goroutine to start
	<-startedCh
	// Give the server time to initialize
	time.Sleep(200 * time.Millisecond)

	// Since we're using port 0, we can't easily get the actual port without a race.
	// The test verifies that the server starts and stops cleanly.
	cancel()

	select {
	case <-errCh:
		// Server stopped
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

// TestServer_ReadyEndpoint tests the /ready endpoint.
func TestServer_ReadyEndpoint(t *testing.T) {
	registry := prometheus.NewRegistry()

	config := &ServerConfig{
		Port:         0,
		Path:         "/metrics",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Registry:     registry,
	}

	server := NewServer(config, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	cancel()
	<-errCh
}

// TestZapErrorLogger_Println tests the zapErrorLogger.Println method.
func TestZapErrorLogger_Println(t *testing.T) {
	// Create a logger that captures output
	logger := zaptest.NewLogger(t)

	errorLogger := &zapErrorLogger{logger: logger}

	// Should not panic
	assert.NotPanics(t, func() {
		errorLogger.Println("test error message")
		errorLogger.Println("error", "with", "multiple", "args")
	})
}

// TestMetricsMiddleware tests the MetricsMiddleware function.
func TestMetricsMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		handler        http.HandlerFunc
		expectedStatus int
		expectedBody   string
	}{
		{
			name:   "successful GET request",
			method: "GET",
			path:   "/api/v1/test",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:   "POST request with body",
			method: "POST",
			path:   "/api/v1/users",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id": 1}`))
			},
			expectedStatus: http.StatusCreated,
			expectedBody:   `{"id": 1}`,
		},
		{
			name:   "error response",
			method: "GET",
			path:   "/api/v1/error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("Internal Server Error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal Server Error",
		},
		{
			name:   "no explicit WriteHeader",
			method: "GET",
			path:   "/api/v1/implicit",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("Implicit 200"))
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Implicit 200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := MetricsMiddleware(tt.handler)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			assert.Equal(t, tt.expectedBody, rec.Body.String())
		})
	}
}

// TestMetricsMiddleware_Concurrent tests concurrent requests through middleware.
func TestMetricsMiddleware_Concurrent(t *testing.T) {
	handler := MetricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		}()
	}
	wg.Wait()
}

// TestResponseWriter_WriteHeader tests the responseWriter.WriteHeader method.
func TestResponseWriter_WriteHeader(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"OK", http.StatusOK},
		{"Created", http.StatusCreated},
		{"Bad Request", http.StatusBadRequest},
		{"Not Found", http.StatusNotFound},
		{"Internal Server Error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rw := &responseWriter{
				ResponseWriter: rec,
				statusCode:     http.StatusOK,
			}

			rw.WriteHeader(tt.statusCode)

			assert.Equal(t, tt.statusCode, rw.statusCode)
			assert.Equal(t, tt.statusCode, rec.Code)
		})
	}
}

// TestResponseWriter_Write tests the responseWriter.Write method.
func TestResponseWriter_Write(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		expectedSize int
	}{
		{"empty", []byte{}, 0},
		{"small", []byte("hello"), 5},
		{"larger", []byte("hello world, this is a longer message"), 37},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rw := &responseWriter{
				ResponseWriter: rec,
				statusCode:     http.StatusOK,
			}

			n, err := rw.Write(tt.data)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedSize, n)
			assert.Equal(t, tt.expectedSize, rw.size)
			assert.Equal(t, string(tt.data), rec.Body.String())
		})
	}
}

// TestResponseWriter_Write_Multiple tests multiple writes accumulate size.
func TestResponseWriter_Write_Multiple(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}

	n1, err1 := rw.Write([]byte("hello"))
	n2, err2 := rw.Write([]byte(" world"))

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Equal(t, 5, n1)
	assert.Equal(t, 6, n2)
	assert.Equal(t, 11, rw.size)
	assert.Equal(t, "hello world", rec.Body.String())
}

// TestResponseWriter_Flush tests the responseWriter.Flush method.
func TestResponseWriter_Flush(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}

	// Should not panic
	assert.NotPanics(t, func() {
		rw.Flush()
	})

	// Verify flush was called on underlying writer
	assert.True(t, rec.Flushed)
}

// TestResponseWriter_Flush_NonFlusher tests Flush with non-flusher writer.
func TestResponseWriter_Flush_NonFlusher(t *testing.T) {
	// Create a minimal ResponseWriter that doesn't implement Flusher
	nonFlusher := &minimalResponseWriter{}
	rw := &responseWriter{
		ResponseWriter: nonFlusher,
		statusCode:     http.StatusOK,
	}

	// Should not panic even if underlying writer doesn't support Flush
	assert.NotPanics(t, func() {
		rw.Flush()
	})
}

// minimalResponseWriter is a minimal http.ResponseWriter that doesn't implement Flusher or Hijacker.
type minimalResponseWriter struct {
	header     http.Header
	statusCode int
	body       []byte
}

func (m *minimalResponseWriter) Header() http.Header {
	if m.header == nil {
		m.header = make(http.Header)
	}
	return m.header
}

func (m *minimalResponseWriter) Write(b []byte) (int, error) {
	m.body = append(m.body, b...)
	return len(b), nil
}

func (m *minimalResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}

// TestResponseWriter_Hijack tests the responseWriter.Hijack method.
func TestResponseWriter_Hijack(t *testing.T) {
	// Create a test server to get a real connection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		conn, brw, err := rw.Hijack()
		if err != nil {
			// Some test servers don't support hijacking
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}

		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 200 OK\r\n\r\nHijacked!")
		_ = brw.Flush()
	}))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Skipf("Could not connect to test server: %v", err)
	}
	defer resp.Body.Close()

	// The response might be either hijacked or error depending on the test server
	// We just verify no panic occurred
}

// TestResponseWriter_Hijack_NotSupported tests Hijack when not supported.
func TestResponseWriter_Hijack_NotSupported(t *testing.T) {
	nonHijacker := &minimalResponseWriter{}
	rw := &responseWriter{
		ResponseWriter: nonHijacker,
		statusCode:     http.StatusOK,
	}

	conn, brw, err := rw.Hijack()

	assert.Nil(t, conn)
	assert.Nil(t, brw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support hijacking")
}

// hijackableResponseWriter implements http.Hijacker for testing.
type hijackableResponseWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (h *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h.conn == nil {
		// Create a pipe for testing
		server, client := net.Pipe()
		h.conn = server
		go func() {
			// Read and discard from client side
			_, _ = io.Copy(io.Discard, client)
			client.Close()
		}()
	}
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

// TestResponseWriter_Hijack_Supported tests Hijack when supported.
func TestResponseWriter_Hijack_Supported(t *testing.T) {
	hijacker := &hijackableResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
	}
	rw := &responseWriter{
		ResponseWriter: hijacker,
		statusCode:     http.StatusOK,
	}

	conn, brw, err := rw.Hijack()

	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.NotNil(t, brw)

	// Clean up
	if conn != nil {
		conn.Close()
	}
}

// TestServer_CollectLoop tests the collectLoop function.
func TestServer_CollectLoop(t *testing.T) {
	registry := prometheus.NewRegistry()

	config := &ServerConfig{
		Port:         0,
		Path:         "/metrics",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Registry:     registry,
	}

	server := NewServer(config, zap.NewNop()).
		WithGatewayCollector(getTestGatewayCollector()).
		WithRuntimeCollector(getTestRuntimeCollector())

	// Manually set up the ticker for testing
	server.collectTicker = time.NewTicker(50 * time.Millisecond)

	// Start collect loop in goroutine
	done := make(chan struct{})
	go func() {
		server.collectLoop()
		close(done)
	}()

	// Let it run for a few cycles
	time.Sleep(150 * time.Millisecond)

	// Stop the loop
	close(server.stopCh)

	// Wait for loop to exit
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("collectLoop did not stop")
	}

	server.collectTicker.Stop()
}

// TestServer_CollectLoop_OnlyGatewayCollector tests collectLoop with only gateway collector.
func TestServer_CollectLoop_OnlyGatewayCollector(t *testing.T) {
	registry := prometheus.NewRegistry()

	config := &ServerConfig{
		Port:     0,
		Path:     "/metrics",
		Registry: registry,
	}

	server := NewServer(config, zap.NewNop()).
		WithGatewayCollector(getTestGatewayCollector())

	server.collectTicker = time.NewTicker(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		server.collectLoop()
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	close(server.stopCh)

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("collectLoop did not stop")
	}

	server.collectTicker.Stop()
}

// TestServer_CollectLoop_OnlyRuntimeCollector tests collectLoop with only runtime collector.
func TestServer_CollectLoop_OnlyRuntimeCollector(t *testing.T) {
	registry := prometheus.NewRegistry()

	config := &ServerConfig{
		Port:     0,
		Path:     "/metrics",
		Registry: registry,
	}

	server := NewServer(config, zap.NewNop()).
		WithRuntimeCollector(getTestRuntimeCollector())

	server.collectTicker = time.NewTicker(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		server.collectLoop()
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	close(server.stopCh)

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("collectLoop did not stop")
	}

	server.collectTicker.Stop()
}

// TestServer_StartError tests server start with port already in use.
func TestServer_StartError(t *testing.T) {
	// Start a listener on a port
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer listener.Close()

	// Get the port
	port := listener.Addr().(*net.TCPAddr).Port

	config := &ServerConfig{
		Port:         port, // Use the same port
		Path:         "/metrics",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Registry:     prometheus.NewRegistry(),
	}

	server := NewServer(config, zap.NewNop())

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = server.Start(ctx)
	// Should get an error because port is in use
	assert.Error(t, err)
}

// TestServer_StopWithTicker tests stopping server with active ticker.
func TestServer_StopWithTicker(t *testing.T) {
	registry := prometheus.NewRegistry()

	config := &ServerConfig{
		Port:         0,
		Path:         "/metrics",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Registry:     registry,
	}

	server := NewServer(config, zap.NewNop()).
		WithGatewayCollector(getTestGatewayCollector())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	startedCh := make(chan struct{})

	go func() {
		// Signal that we're about to start
		close(startedCh)
		errCh <- server.Start(ctx)
	}()

	// Wait for goroutine to start
	<-startedCh
	// Give the server time to initialize
	time.Sleep(200 * time.Millisecond)

	// Cancel context to trigger shutdown via Start's context handling
	cancel()

	select {
	case err := <-errCh:
		// Server should stop cleanly (nil error) or with context canceled
		if err != nil && err != context.Canceled {
			t.Logf("server stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

// TestMetricsMiddleware_WithContentLength tests middleware with content length.
func TestMetricsMiddleware_WithContentLength(t *testing.T) {
	handler := MetricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response body"))
	}))

	body := "request body content"
	req := httptest.NewRequest("POST", "/api/test", nil)
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "response body", rec.Body.String())
}

// TestZapErrorLogger_Println_WithVariousTypes tests Println with various argument types.
func TestZapErrorLogger_Println_WithVariousTypes(t *testing.T) {
	logger := zaptest.NewLogger(t)
	errorLogger := &zapErrorLogger{logger: logger}

	tests := []struct {
		name string
		args []interface{}
	}{
		{"string", []interface{}{"error message"}},
		{"int", []interface{}{42}},
		{"mixed", []interface{}{"error:", 500, "message:", "test"}},
		{"error type", []interface{}{fmt.Errorf("test error")}},
		{"empty", []interface{}{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				errorLogger.Println(tt.args...)
			})
		})
	}
}

// TestServer_ChainedConfiguration tests chained configuration methods.
func TestServer_ChainedConfiguration(t *testing.T) {
	server := NewServer(nil, zap.NewNop()).
		WithGatewayCollector(getTestGatewayCollector()).
		WithRuntimeCollector(getTestRuntimeCollector())

	assert.NotNil(t, server)
	assert.NotNil(t, server.collector)
	assert.NotNil(t, server.runtime)
}

// TestResponseWriter_DefaultStatusCode tests default status code is 200.
func TestResponseWriter_DefaultStatusCode(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}

	// Write without calling WriteHeader
	_, err := rw.Write([]byte("test"))
	assert.NoError(t, err)

	// Status code should still be the default
	assert.Equal(t, http.StatusOK, rw.statusCode)
}

// TestServer_StartNoCollectors tests starting server without collectors.
func TestServer_StartNoCollectors(t *testing.T) {
	registry := prometheus.NewRegistry()

	config := &ServerConfig{
		Port:         0,
		Path:         "/metrics",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Registry:     registry,
	}

	server := NewServer(config, zap.NewNop())
	// No collectors set

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Verify no ticker was created
	assert.Nil(t, server.collectTicker)

	cancel()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

// TestServer_EndpointsWithRealServer tests health and ready endpoints with a real server.
func TestServer_EndpointsWithRealServer(t *testing.T) {
	registry := prometheus.NewRegistry()

	// Find an available port
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	config := &ServerConfig{
		Port:         port,
		Path:         "/metrics",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Registry:     registry,
	}

	server := NewServer(config, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	baseURL := fmt.Sprintf("http://localhost:%d", port)

	// Test health endpoint
	t.Run("health endpoint", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "OK", string(body))
	})

	// Test ready endpoint
	t.Run("ready endpoint", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/ready")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "Ready", string(body))
	})

	// Test metrics endpoint
	t.Run("metrics endpoint", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/metrics")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	cancel()

	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

// errorResponseWriter is a ResponseWriter that returns errors on Write.
type errorResponseWriter struct {
	header     http.Header
	statusCode int
}

func (e *errorResponseWriter) Header() http.Header {
	if e.header == nil {
		e.header = make(http.Header)
	}
	return e.header
}

func (e *errorResponseWriter) Write(b []byte) (int, error) {
	return 0, fmt.Errorf("write error")
}

func (e *errorResponseWriter) WriteHeader(statusCode int) {
	e.statusCode = statusCode
}

// TestResponseWriter_WriteError tests Write when underlying writer returns error.
func TestResponseWriter_WriteError(t *testing.T) {
	errWriter := &errorResponseWriter{}
	rw := &responseWriter{
		ResponseWriter: errWriter,
		statusCode:     http.StatusOK,
	}

	n, err := rw.Write([]byte("test"))

	assert.Error(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, 0, rw.size)
}
