package backend

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Helper function to create a test backend
func createTestBackend(name string) *Backend {
	return &Backend{
		Name:      name,
		Endpoints: make([]*Endpoint, 0),
	}
}

// testProxyConfig returns a ProxyConfig suitable for testing.
// URL validation is disabled since httptest.Server uses localhost.
func testProxyConfig() *ProxyConfig {
	config := DefaultProxyConfig()
	config.EnableURLValidation = false
	return config
}

// Helper function to create a test proxy with retry enabled
// URL validation is disabled for tests since httptest.Server uses localhost
func createTestProxyWithRetry(maxRetries int, retryBackoff time.Duration) *Proxy {
	config := &ProxyConfig{
		RetryEnabled:        true,
		MaxRetries:          maxRetries,
		RetryBackoff:        retryBackoff,
		Timeout:             30 * time.Second,
		BufferSize:          32 * 1024,
		PreserveHost:        false,
		AddForwardedHeaders: true,
		EnableURLValidation: false, // Disable for tests using localhost
	}
	logger, _ := zap.NewDevelopment()
	manager := NewManager(logger)
	return NewProxy(manager, logger, config)
}

// Helper to create endpoint from server URL
func endpointFromServer(server *httptest.Server) *Endpoint {
	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		// Fallback for tests - should not happen with httptest.Server
		return &Endpoint{
			Address: strings.TrimPrefix(strings.TrimPrefix(server.URL, "http://"), "https://"),
			Port:    80,
			Healthy: true,
		}
	}

	// Parse port from URL
	port := 80
	if parsedURL.Port() != "" {
		if p, err := strconv.Atoi(parsedURL.Port()); err == nil {
			port = p
		}
	}

	return &Endpoint{
		Address: parsedURL.Hostname(),
		Port:    port,
		Healthy: true,
	}
}

// ============================================================================
// Test Cases for Context Cancellation During Retry
// ============================================================================

func TestProxy_ProxyWithRetry_ContextCancellationDuringRetry(t *testing.T) {
	// Create a backend that always fails
	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{
		{
			Address: "invalid.example.com",
			Port:    80,
			Healthy: false,
		},
	}

	proxy := createTestProxyWithRetry(3, 50*time.Millisecond)

	// Create a request
	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	rec := httptest.NewRecorder()

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req = req.WithContext(ctx)

	// This should return context.Canceled error
	err := proxy.ProxyWithRetry(rec, req, backend, 5*time.Second)
	assert.Equal(t, context.Canceled, err)
}

func TestProxy_ProxyWithRetry_ContextCancellationDuringBackoff(t *testing.T) {
	// Create a backend with no healthy endpoints to force retries
	// The proxy will retry when it can't find healthy endpoints
	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{
		{
			Address: "invalid.example.com",
			Port:    80,
			Healthy: false, // Unhealthy endpoint forces "no healthy endpoints" error
		},
	}

	proxy := createTestProxyWithRetry(3, 100*time.Millisecond)

	// Create a request
	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	rec := httptest.NewRecorder()

	// Create a context that will be cancelled during backoff
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		// Cancel after first retry backoff starts (100ms backoff * 1 = 100ms)
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	req = req.WithContext(ctx)

	// This should return context.Canceled error during backoff
	err := proxy.ProxyWithRetry(rec, req, backend, 5*time.Second)
	assert.Equal(t, context.Canceled, err)
}

// ============================================================================
// Test Cases for Successful Request Without Cancellation
// ============================================================================

func TestProxy_ProxyWithRetry_SuccessfulRequest(t *testing.T) {
	// Create a backend with a successful server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{endpointFromServer(server)}

	proxy := createTestProxyWithRetry(3, 50*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, server.URL, nil)
	rec := httptest.NewRecorder()

	err := proxy.ProxyWithRetry(rec, req, backend, 5*time.Second)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "success")
}

func TestProxy_ServeHTTP_SuccessfulRequest(t *testing.T) {
	// Create a backend with a successful server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{endpointFromServer(server)}

	config := testProxyConfig()
	logger, _ := zap.NewDevelopment()
	manager := NewManager(logger)
	proxy := NewProxy(manager, logger, config)

	req := httptest.NewRequest(http.MethodGet, server.URL, nil)
	rec := httptest.NewRecorder()

	err := proxy.ServeHTTP(rec, req, backend, 5*time.Second)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// Test Cases for Retry Exhaustion
// ============================================================================

func TestProxy_ProxyWithRetry_RetryExhaustion(t *testing.T) {
	// Create a backend that always fails (invalid endpoint)
	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{
		{
			Address: "invalid.example.com",
			Port:    80,
			Healthy: false,
		},
	}

	proxy := createTestProxyWithRetry(3, 20*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	rec := httptest.NewRecorder()

	// This should return an error after all retries are exhausted
	err := proxy.ProxyWithRetry(rec, req, backend, 5*time.Second)
	assert.Error(t, err)
}

// ============================================================================
// Test Cases for Circuit Breaker Integration
// ============================================================================

func TestProxy_ServeHTTP_CircuitBreakerOpen(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create a circuit breaker that's open
	cbConfig := &CircuitBreakerConfig{
		Enabled:           true,
		ConsecutiveErrors: 1,
		Interval:          30,
		BaseEjectionTime:  30,
		MaxEjectionPct:    50,
	}
	cb := NewCircuitBreaker(cbConfig)
	// Open the circuit by recording failures
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	backend := createTestBackend("test-backend")
	backend.CircuitBreaker = cb
	backend.Endpoints = []*Endpoint{
		{
			Address: "example.com",
			Port:    80,
			Healthy: true,
		},
	}

	config := testProxyConfig()
	manager := NewManager(logger)
	proxy := NewProxy(manager, logger, config)

	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	rec := httptest.NewRecorder()

	err := proxy.ServeHTTP(rec, req, backend, 5*time.Second)

	assert.Error(t, err)
}

func TestProxy_ServeHTTP_CircuitBreakerRecordsSuccess(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create a circuit breaker
	cbConfig := &CircuitBreakerConfig{
		Enabled:           true,
		ConsecutiveErrors: 5,
		Interval:          30,
		BaseEjectionTime:  30,
		MaxEjectionPct:    50,
	}
	cb := NewCircuitBreaker(cbConfig)

	// Create a backend with a successful server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend := createTestBackend("test-backend")
	backend.CircuitBreaker = cb
	backend.Endpoints = []*Endpoint{endpointFromServer(server)}

	config := testProxyConfig()
	manager := NewManager(logger)
	proxy := NewProxy(manager, logger, config)

	req := httptest.NewRequest(http.MethodGet, server.URL, nil)
	rec := httptest.NewRecorder()

	err := proxy.ServeHTTP(rec, req, backend, 5*time.Second)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// Test Cases for Error Handling
// ============================================================================

func TestProxy_ServeHTTP_NilBackend(t *testing.T) {
	config := testProxyConfig()
	logger, _ := zap.NewDevelopment()
	manager := NewManager(logger)
	proxy := NewProxy(manager, logger, config)

	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	rec := httptest.NewRecorder()

	err := proxy.ServeHTTP(rec, req, nil, 5*time.Second)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backend is nil")
}

func TestProxy_ServeHTTP_NoHealthyEndpoints(t *testing.T) {
	backend := createTestBackend("test-backend")
	// No endpoints configured or endpoints are unhealthy
	backend.Endpoints = make([]*Endpoint, 0)

	config := testProxyConfig()
	logger, _ := zap.NewDevelopment()
	manager := NewManager(logger)
	proxy := NewProxy(manager, logger, config)

	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	rec := httptest.NewRecorder()

	err := proxy.ServeHTTP(rec, req, backend, 5*time.Second)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no healthy endpoints available")
}

// ============================================================================
// Test Cases for Request Modification
// ============================================================================

func TestProxy_ModifyRequest_ForwardedHeaders(t *testing.T) {
	config := testProxyConfig()
	config.AddForwardedHeaders = true
	logger, _ := zap.NewDevelopment()
	manager := NewManager(logger)
	proxy := NewProxy(manager, logger, config)

	// Create original request (to capture original host for X-Forwarded-Host)
	originalReq := httptest.NewRequest(http.MethodGet, "http://original.com/test?foo=bar", nil)
	originalReq.Header.Set("X-Real-IP", "192.168.1.1")
	originalReq.Header.Set("User-Agent", "TestAgent")

	// Create a separate request to be modified (simulating what the reverse proxy does)
	modifiedReq := httptest.NewRequest(http.MethodGet, "http://original.com/test?foo=bar", nil)
	modifiedReq.Header.Set("X-Real-IP", "192.168.1.1")
	modifiedReq.Header.Set("User-Agent", "TestAgent")

	endpoint := &Endpoint{
		Address: "backend.example.com",
		Port:    8080,
		Healthy: true,
	}

	proxy.modifyRequest(modifiedReq, originalReq, endpoint)

	assert.Equal(t, "backend.example.com:8080", modifiedReq.Host)
	assert.Equal(t, "192.168.1.1", modifiedReq.Header.Get("X-Forwarded-For"))
	assert.Equal(t, "http", modifiedReq.Header.Get("X-Forwarded-Proto"))
	assert.Equal(t, "original.com", modifiedReq.Header.Get("X-Forwarded-Host"))
}

func TestProxy_ModifyRequest_HopByHopHeadersRemoved(t *testing.T) {
	config := testProxyConfig()
	logger, _ := zap.NewDevelopment()
	manager := NewManager(logger)
	proxy := NewProxy(manager, logger, config)

	originalReq := httptest.NewRequest(http.MethodGet, "http://original.com/test", nil)
	originalReq.Header.Set("Connection", "keep-alive")
	originalReq.Header.Set("Keep-Alive", "timeout=5")
	originalReq.Header.Set("Transfer-Encoding", "chunked")
	originalReq.Header.Set("Upgrade", "h2c")

	endpoint := &Endpoint{
		Address: "backend.example.com",
		Port:    8080,
		Healthy: true,
	}

	proxy.modifyRequest(originalReq, originalReq, endpoint)

	assert.Empty(t, originalReq.Header.Get("Connection"))
	assert.Empty(t, originalReq.Header.Get("Keep-Alive"))
	assert.Empty(t, originalReq.Header.Get("Transfer-Encoding"))
	assert.Empty(t, originalReq.Header.Get("Upgrade"))
}

// ============================================================================
// Test Cases for Timeout Handling
// ============================================================================

func TestProxy_ServeHTTP_WithTimeout(t *testing.T) {
	// Create a backend with a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{endpointFromServer(server)}

	config := testProxyConfig()
	logger, _ := zap.NewDevelopment()
	manager := NewManager(logger)
	proxy := NewProxy(manager, logger, config)

	req := httptest.NewRequest(http.MethodGet, server.URL, nil)
	rec := httptest.NewRecorder()

	// Set a short timeout
	err := proxy.ServeHTTP(rec, req, backend, 100*time.Millisecond)

	// ServeHTTP doesn't return an error on timeout - it handles it via error handler
	// and writes a 502 Bad Gateway response. The error is logged but not returned.
	// We verify the timeout occurred by checking the response status code.
	assert.NoError(t, err) // No error returned from ServeHTTP
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

// ============================================================================
// Test Cases for CopyResponse
// ============================================================================

func TestProxy_CopyResponse(t *testing.T) {
	src := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"message": "success"}`)),
	}

	dst := httptest.NewRecorder()

	err := CopyResponse(dst, src)

	require.NoError(t, err)
	assert.Equal(t, 200, dst.Code)
	assert.Equal(t, "application/json", dst.Header().Get("Content-Type"))
	assert.Contains(t, dst.Body.String(), "success")
}

// ============================================================================
// Test Cases for ProxyHandler
// ============================================================================

func TestProxy_ProxyHandler_BackendNotFound(t *testing.T) {
	config := testProxyConfig()
	logger, _ := zap.NewDevelopment()
	manager := NewManager(logger)
	proxy := NewProxy(manager, logger, config)

	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	rec := httptest.NewRecorder()

	handler := proxy.ProxyHandler("non-existent", 5*time.Second)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ============================================================================
// Test Cases for getClientIP
// ============================================================================

func TestGetClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.100")

	ip := getClientIP(req)
	assert.Equal(t, "192.168.1.100", ip)
}

func TestGetClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100, 10.0.0.1")

	ip := getClientIP(req)
	assert.Equal(t, "192.168.1.100", ip)
}

func TestGetClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	// RemoteAddr is not set in httptest.Request, so we test the fallback

	ip := getClientIP(req)
	// Should be empty or contain port
	assert.NotEqual(t, "", ip)
}

// ============================================================================
// Test Cases for Proxy Retry Logic (TASK-004)
// ============================================================================

func TestProxyWithRetry_DoesNotDoubleWrite(t *testing.T) {
	// Create a backend with a successful server that tracks write count
	writeCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{endpointFromServer(server)}

	proxy := createTestProxyWithRetry(3, 50*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, server.URL, nil)
	rec := httptest.NewRecorder()

	err := proxy.ProxyWithRetry(rec, req, backend, 5*time.Second)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, writeCount, "Server should only be called once on success")
}

func TestProxyWithRetry_FirstAttemptSuccess(t *testing.T) {
	// Create a backend with a successful server
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{endpointFromServer(server)}

	proxy := createTestProxyWithRetry(3, 50*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, server.URL, nil)
	rec := httptest.NewRecorder()

	err := proxy.ProxyWithRetry(rec, req, backend, 5*time.Second)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, attemptCount, "Should succeed on first attempt without retries")
}

func TestProxyWithRetry_AllAttemptsFail(t *testing.T) {
	// Create a backend with no healthy endpoints to force all retries to fail
	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{
		{
			Address: "invalid.example.com",
			Port:    80,
			Healthy: false,
		},
	}

	proxy := createTestProxyWithRetry(2, 10*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	rec := httptest.NewRecorder()

	err := proxy.ProxyWithRetry(rec, req, backend, 5*time.Second)

	// Should return an error after all retries are exhausted
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no healthy endpoints")
}

func TestProxyWithRetry_ContextCancellation(t *testing.T) {
	// Create a backend with no healthy endpoints to force retries
	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{
		{
			Address: "invalid.example.com",
			Port:    80,
			Healthy: false,
		},
	}

	proxy := createTestProxyWithRetry(5, 100*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "http://test.com/test", nil)
	rec := httptest.NewRecorder()

	// Create a context that will be cancelled during retry
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		// Cancel after a short delay (during backoff)
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	req = req.WithContext(ctx)

	err := proxy.ProxyWithRetry(rec, req, backend, 5*time.Second)

	// Should return context.Canceled error
	assert.Equal(t, context.Canceled, err)
}

func TestProxyWithRetry_RetryDisabled(t *testing.T) {
	// Create a backend with a successful server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{endpointFromServer(server)}

	// Create proxy with retry disabled
	config := &ProxyConfig{
		RetryEnabled:        false,
		MaxRetries:          3,
		RetryBackoff:        50 * time.Millisecond,
		Timeout:             30 * time.Second,
		BufferSize:          32 * 1024,
		PreserveHost:        false,
		AddForwardedHeaders: true,
	}
	logger, _ := zap.NewDevelopment()
	manager := NewManager(logger)
	proxy := NewProxy(manager, logger, config)

	req := httptest.NewRequest(http.MethodGet, server.URL, nil)
	rec := httptest.NewRecorder()

	err := proxy.ProxyWithRetry(rec, req, backend, 5*time.Second)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestProxyWithRetry_RequestBodyPreserved(t *testing.T) {
	// Create a backend that echoes the request body
	receivedBodies := make([]string, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBodies = append(receivedBodies, string(body))
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{endpointFromServer(server)}

	proxy := createTestProxyWithRetry(3, 50*time.Millisecond)

	requestBody := "test request body"
	req := httptest.NewRequest(http.MethodPost, server.URL, strings.NewReader(requestBody))
	rec := httptest.NewRecorder()

	err := proxy.ProxyWithRetry(rec, req, backend, 5*time.Second)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, requestBody, rec.Body.String())
}

func TestProxyWithRetry_ResponseHeadersCopied(t *testing.T) {
	// Create a backend that sets custom headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom-value")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	backend := createTestBackend("test-backend")
	backend.Endpoints = []*Endpoint{endpointFromServer(server)}

	proxy := createTestProxyWithRetry(3, 50*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, server.URL, nil)
	rec := httptest.NewRecorder()

	err := proxy.ProxyWithRetry(rec, req, backend, 5*time.Second)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "custom-value", rec.Header().Get("X-Custom-Header"))
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}
