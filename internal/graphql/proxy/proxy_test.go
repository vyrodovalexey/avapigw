package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockMetricsRecorder implements MetricsRecorder for testing.
type mockMetricsRecorder struct {
	requests []mockRequest
	errors   []mockError
}

type mockRequest struct {
	backend    string
	operation  string
	statusCode int
	duration   time.Duration
}

type mockError struct {
	backend   string
	operation string
	errorType string
}

func (m *mockMetricsRecorder) RecordRequest(backend, operation string, statusCode int, duration time.Duration) {
	m.requests = append(m.requests, mockRequest{backend, operation, statusCode, duration})
}

func (m *mockMetricsRecorder) RecordError(backend, operation, errorType string) {
	m.errors = append(m.errors, mockError{backend, operation, errorType})
}

// mockRoundTripper implements http.RoundTripper for testing.
type mockRoundTripper struct {
	response *http.Response
	err      error
}

func (m *mockRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return m.response, m.err
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []Option
	}{
		{
			name: "default proxy",
			opts: nil,
		},
		{
			name: "with logger",
			opts: []Option{WithLogger(observability.NopLogger())},
		},
		{
			name: "with timeout",
			opts: []Option{WithTimeout(10 * time.Second)},
		},
		{
			name: "with max body size",
			opts: []Option{WithMaxBodySize(1024)},
		},
		{
			name: "with transport",
			opts: []Option{WithTransport(&mockRoundTripper{})},
		},
		{
			name: "with metrics",
			opts: []Option{WithMetrics(&mockMetricsRecorder{})},
		},
		{
			name: "with all options",
			opts: []Option{
				WithLogger(observability.NopLogger()),
				WithTimeout(15 * time.Second),
				WithMaxBodySize(2048),
				WithTransport(&mockRoundTripper{}),
				WithMetrics(&mockMetricsRecorder{}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := New(tt.opts...)
			require.NotNil(t, p)
			assert.NotNil(t, p.backends)
			assert.NotNil(t, p.transport)
		})
	}
}

func TestProxy_DefaultValues(t *testing.T) {
	t.Parallel()

	p := New()
	assert.Equal(t, defaultTimeout, p.timeout)
	assert.Equal(t, int64(defaultMaxBodySize), p.maxBodySize)
	assert.NotNil(t, p.transport)
}

func TestProxy_UpdateBackends(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))

	backends := []config.GraphQLBackend{
		{
			Name: "backend-1",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 4000},
			},
		},
		{
			Name: "backend-2",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.2", Port: 4001},
				{Address: "10.0.0.3", Port: 4001},
			},
		},
	}

	p.UpdateBackends(backends)

	p.mu.RLock()
	defer p.mu.RUnlock()
	assert.Len(t, p.backends, 2)
	assert.Contains(t, p.backends, "backend-1")
	assert.Contains(t, p.backends, "backend-2")
	assert.Len(t, p.backends["backend-2"].hosts, 2)
}

func TestProxy_UpdateBackends_Replaces(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))

	// First update
	p.UpdateBackends([]config.GraphQLBackend{
		{Name: "old-backend", Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}}},
	})

	// Second update replaces
	p.UpdateBackends([]config.GraphQLBackend{
		{Name: "new-backend", Hosts: []config.BackendHost{{Address: "10.0.0.2", Port: 4001}}},
	})

	p.mu.RLock()
	defer p.mu.RUnlock()
	assert.Len(t, p.backends, 1)
	assert.Contains(t, p.backends, "new-backend")
	assert.NotContains(t, p.backends, "old-backend")
}

func TestProxy_UpdateBackends_Empty(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))
	p.UpdateBackends([]config.GraphQLBackend{
		{Name: "be", Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}}},
	})

	// Update with empty list clears all backends
	p.UpdateBackends([]config.GraphQLBackend{})

	p.mu.RLock()
	defer p.mu.RUnlock()
	assert.Empty(t, p.backends)
}

func TestProxy_ResolveBackend(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))
	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 4000},
			},
		},
	})

	tests := []struct {
		name      string
		backend   string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "existing backend",
			backend: "test-backend",
			wantErr: false,
		},
		{
			name:      "non-existing backend",
			backend:   "unknown",
			wantErr:   true,
			errSubstr: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target, err := p.resolveBackend(tt.backend)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				assert.Nil(t, target)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, target)
			}
		})
	}
}

func TestProxy_ResolveBackend_NoHosts(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))
	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "empty-backend",
			Hosts: []config.BackendHost{},
		},
	})

	target, err := p.resolveBackend("empty-backend")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no hosts")
	assert.Nil(t, target)
}

func TestProxy_BuildTargetURL_RoundRobin(t *testing.T) {
	t.Parallel()

	p := New()
	target := &backendTarget{
		name: "test",
		hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 4000},
			{Address: "10.0.0.2", Port: 4001},
			{Address: "10.0.0.3", Port: 4002},
		},
		current: 0,
	}

	// First call should use host 0
	url1 := p.buildTargetURL(target)
	assert.Equal(t, "http://10.0.0.1:4000", url1.String())

	// Second call should use host 1
	url2 := p.buildTargetURL(target)
	assert.Equal(t, "http://10.0.0.2:4001", url2.String())

	// Third call should use host 2
	url3 := p.buildTargetURL(target)
	assert.Equal(t, "http://10.0.0.3:4002", url3.String())

	// Fourth call should wrap around to host 0
	url4 := p.buildTargetURL(target)
	assert.Equal(t, "http://10.0.0.1:4000", url4.String())
}

func TestProxy_Forward_Success(t *testing.T) {
	t.Parallel()

	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"user":{"name":"test"}}}`))
	}))
	defer backendServer.Close()

	metrics := &mockMetricsRecorder{}
	p := New(
		WithLogger(observability.NopLogger()),
		WithMetrics(metrics),
		WithTimeout(5*time.Second),
	)

	// Parse the backend server URL to get host and port
	host := backendServer.Listener.Addr().String()
	parts := strings.Split(host, ":")
	addr := parts[0]
	port := 0
	fmt.Sscanf(parts[1], "%d", &port)

	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: addr, Port: port},
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ user { name } }"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.168.1.1:12345"

	resp, err := p.Forward(context.Background(), "test-backend", req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Verify metrics were recorded
	assert.Len(t, metrics.requests, 1)
	assert.Equal(t, "test-backend", metrics.requests[0].backend)
}

func TestProxy_Forward_BackendNotFound(t *testing.T) {
	t.Parallel()

	metrics := &mockMetricsRecorder{}
	p := New(
		WithLogger(observability.NopLogger()),
		WithMetrics(metrics),
	)

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ user { name } }"}`))

	resp, err := p.Forward(context.Background(), "nonexistent", req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "not found")

	// Verify error metrics were recorded
	assert.Len(t, metrics.errors, 1)
	assert.Equal(t, "backend_not_found", metrics.errors[0].errorType)
}

func TestProxy_Forward_TransportError(t *testing.T) {
	t.Parallel()

	metrics := &mockMetricsRecorder{}
	p := New(
		WithLogger(observability.NopLogger()),
		WithMetrics(metrics),
		WithTransport(&mockRoundTripper{
			err: fmt.Errorf("connection refused"),
		}),
	)

	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "test-backend",
			Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ user { name } }"}`))

	resp, err := p.Forward(context.Background(), "test-backend", req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to forward request")

	// Verify error metrics were recorded
	assert.Len(t, metrics.errors, 1)
	assert.Equal(t, "transport_error", metrics.errors[0].errorType)
}

func TestProxy_Forward_WithoutMetrics(t *testing.T) {
	t.Parallel()

	p := New(
		WithLogger(observability.NopLogger()),
		WithTransport(&mockRoundTripper{
			err: fmt.Errorf("connection refused"),
		}),
	)

	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "test-backend",
			Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ user { name } }"}`))

	// Should not panic even without metrics
	resp, err := p.Forward(context.Background(), "test-backend", req)
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestProxy_Forward_WithoutMetrics_BackendNotFound(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ user { name } }"}`))

	// Should not panic even without metrics when backend not found
	resp, err := p.Forward(context.Background(), "nonexistent", req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "not found")
}

func TestProxy_Forward_NilBody(t *testing.T) {
	t.Parallel()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	p := New(WithLogger(observability.NopLogger()))

	host := backendServer.Listener.Addr().String()
	parts := strings.Split(host, ":")
	addr := parts[0]
	port := 0
	fmt.Sscanf(parts[1], "%d", &port)

	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "test-backend",
			Hosts: []config.BackendHost{{Address: addr, Port: port}},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	req.Body = nil

	resp, err := p.Forward(context.Background(), "test-backend", req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	_ = resp.Body.Close()
}

func TestProxy_Forward_WithContextDeadline(t *testing.T) {
	t.Parallel()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	p := New(
		WithLogger(observability.NopLogger()),
		WithTimeout(30*time.Second),
	)

	host := backendServer.Listener.Addr().String()
	parts := strings.Split(host, ":")
	addr := parts[0]
	port := 0
	fmt.Sscanf(parts[1], "%d", &port)

	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "test-backend",
			Hosts: []config.BackendHost{{Address: addr, Port: port}},
		},
	})

	// Create a context with a shorter deadline than the proxy timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ user { name } }"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.Forward(ctx, "test-backend", req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	_ = resp.Body.Close()
}

func TestProxy_Forward_SuccessWithMetrics(t *testing.T) {
	t.Parallel()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer backendServer.Close()

	metrics := &mockMetricsRecorder{}
	p := New(
		WithLogger(observability.NopLogger()),
		WithMetrics(metrics),
	)

	host := backendServer.Listener.Addr().String()
	parts := strings.Split(host, ":")
	addr := parts[0]
	port := 0
	fmt.Sscanf(parts[1], "%d", &port)

	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "test-backend",
			Hosts: []config.BackendHost{{Address: addr, Port: port}},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ user { name } }"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.1:9999"

	resp, err := p.Forward(context.Background(), "test-backend", req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Verify metrics
	require.Len(t, metrics.requests, 1)
	assert.Equal(t, "test-backend", metrics.requests[0].backend)
	assert.Equal(t, "forward", metrics.requests[0].operation)
	assert.Equal(t, http.StatusOK, metrics.requests[0].statusCode)
	assert.Greater(t, metrics.requests[0].duration, time.Duration(0))
}

func TestProxy_Close(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))
	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "test-backend",
			Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}},
		},
	})

	p.Close()

	p.mu.RLock()
	defer p.mu.RUnlock()
	assert.Empty(t, p.backends)
}

func TestProxy_Close_WithCustomTransport(t *testing.T) {
	t.Parallel()

	p := New(
		WithLogger(observability.NopLogger()),
		WithTransport(&mockRoundTripper{}),
	)

	// Should not panic with non-*http.Transport
	p.Close()
}

func TestCopyHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		srcHeaders     http.Header
		expectedKeys   []string
		unexpectedKeys []string
	}{
		{
			name: "copies regular headers",
			srcHeaders: http.Header{
				"Content-Type":  {"application/json"},
				"Authorization": {"Bearer token"},
			},
			expectedKeys:   []string{"Content-Type", "Authorization"},
			unexpectedKeys: []string{},
		},
		{
			name: "skips hop-by-hop headers",
			srcHeaders: http.Header{
				"Content-Type":       {"application/json"},
				"Connection":         {"keep-alive"},
				"Keep-Alive":         {"timeout=5"},
				"Transfer-Encoding":  {"chunked"},
				"Proxy-Authenticate": {"Basic"},
			},
			expectedKeys:   []string{"Content-Type"},
			unexpectedKeys: []string{"Connection", "Keep-Alive", "Transfer-Encoding", "Proxy-Authenticate"},
		},
		{
			name: "skips Upgrade header",
			srcHeaders: http.Header{
				"Content-Type": {"application/json"},
				"Upgrade":      {"websocket"},
			},
			expectedKeys:   []string{"Content-Type"},
			unexpectedKeys: []string{"Upgrade"},
		},
		{
			name: "copies multiple values for same header",
			srcHeaders: http.Header{
				"Accept": {"application/json", "text/html"},
			},
			expectedKeys: []string{"Accept"},
		},
		{
			name:           "empty source headers",
			srcHeaders:     http.Header{},
			expectedKeys:   []string{},
			unexpectedKeys: []string{},
		},
		{
			name: "skips Proxy-Authorization",
			srcHeaders: http.Header{
				"Content-Type":        {"application/json"},
				"Proxy-Authorization": {"Basic abc"},
			},
			expectedKeys:   []string{"Content-Type"},
			unexpectedKeys: []string{"Proxy-Authorization"},
		},
		{
			name: "skips Te and Trailers",
			srcHeaders: http.Header{
				"Content-Type": {"application/json"},
				"Te":           {"trailers"},
				"Trailers":     {"Expires"},
			},
			expectedKeys:   []string{"Content-Type"},
			unexpectedKeys: []string{"Te", "Trailers"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dst := http.Header{}
			copyHeaders(dst, tt.srcHeaders)

			for _, key := range tt.expectedKeys {
				assert.NotEmpty(t, dst.Get(key), "expected header %s to be copied", key)
			}
			for _, key := range tt.unexpectedKeys {
				assert.Empty(t, dst.Get(key), "expected header %s to NOT be copied", key)
			}
		})
	}
}

func TestProxy_CreateProxyRequest_ForwardingHeaders(t *testing.T) {
	t.Parallel()

	p := New()

	tests := []struct {
		name          string
		remoteAddr    string
		host          string
		useTLS        bool
		expectedProto string
		expectedXFF   string
	}{
		{
			name:          "HTTP request",
			remoteAddr:    "192.168.1.1:12345",
			host:          "api.example.com",
			useTLS:        false,
			expectedProto: "http",
			expectedXFF:   "192.168.1.1",
		},
		{
			name:          "HTTPS request",
			remoteAddr:    "192.168.1.2:54321",
			host:          "secure.example.com",
			useTLS:        true,
			expectedProto: "https",
			expectedXFF:   "192.168.1.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			original := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader("test"))
			original.RemoteAddr = tt.remoteAddr
			original.Host = tt.host
			if tt.useTLS {
				original.TLS = &tls.ConnectionState{}
			}

			targetURL := p.buildTargetURL(&backendTarget{
				name:  "test",
				hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}},
			})

			proxyReq, err := p.createProxyRequest(context.Background(), original, targetURL)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedProto, proxyReq.Header.Get("X-Forwarded-Proto"))
			assert.Equal(t, tt.host, proxyReq.Header.Get("X-Forwarded-Host"))
			if tt.expectedXFF != "" {
				assert.Contains(t, proxyReq.Header.Get("X-Forwarded-For"), tt.expectedXFF)
			}
		})
	}
}

func TestProxy_CreateProxyRequest_ExistingXFF(t *testing.T) {
	t.Parallel()

	p := New()

	original := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader("test"))
	original.RemoteAddr = "192.168.1.1:12345"
	original.Host = "api.example.com"
	original.Header.Set("X-Forwarded-For", "10.0.0.1")

	targetURL := p.buildTargetURL(&backendTarget{
		name:  "test",
		hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}},
	})

	proxyReq, err := p.createProxyRequest(context.Background(), original, targetURL)
	require.NoError(t, err)

	// Should append to existing X-Forwarded-For
	xff := proxyReq.Header.Get("X-Forwarded-For")
	assert.Contains(t, xff, "10.0.0.1")
	assert.Contains(t, xff, "192.168.1.1")
}

func TestProxy_CreateProxyRequest_PreservesPath(t *testing.T) {
	t.Parallel()

	p := New()

	original := httptest.NewRequest(http.MethodPost, "/graphql?query=test", strings.NewReader("body"))
	original.RemoteAddr = "192.168.1.1:12345"
	original.Host = "api.example.com"

	targetURL := p.buildTargetURL(&backendTarget{
		name:  "test",
		hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}},
	})

	proxyReq, err := p.createProxyRequest(context.Background(), original, targetURL)
	require.NoError(t, err)

	assert.Equal(t, "/graphql", proxyReq.URL.Path)
	assert.Equal(t, "query=test", proxyReq.URL.RawQuery)
	assert.Equal(t, "10.0.0.1:4000", proxyReq.URL.Host)
}

func TestProxy_CreateProxyRequest_InvalidRemoteAddr(t *testing.T) {
	t.Parallel()

	p := New()

	original := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader("test"))
	original.RemoteAddr = "invalid-addr" // no port, SplitHostPort will fail
	original.Host = "api.example.com"

	targetURL := p.buildTargetURL(&backendTarget{
		name:  "test",
		hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}},
	})

	proxyReq, err := p.createProxyRequest(context.Background(), original, targetURL)
	require.NoError(t, err)

	// X-Forwarded-For should not be set when SplitHostPort fails
	assert.Empty(t, proxyReq.Header.Get("X-Forwarded-For"))
}

func TestProxy_CreateProxyRequest_EmptyRemoteAddr(t *testing.T) {
	t.Parallel()

	p := New()

	original := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader("test"))
	original.RemoteAddr = ""
	original.Host = "api.example.com"

	targetURL := p.buildTargetURL(&backendTarget{
		name:  "test",
		hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}},
	})

	proxyReq, err := p.createProxyRequest(context.Background(), original, targetURL)
	require.NoError(t, err)

	// X-Forwarded-For should not be set when RemoteAddr is empty
	assert.Empty(t, proxyReq.Header.Get("X-Forwarded-For"))
}

func TestProxy_CreateProxyRequest_ReadBody(t *testing.T) {
	t.Parallel()

	p := New(WithMaxBodySize(1024))

	bodyContent := `{"query":"{ user { name } }"}`
	original := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(bodyContent))
	original.RemoteAddr = "192.168.1.1:12345"
	original.Host = "api.example.com"

	targetURL := p.buildTargetURL(&backendTarget{
		name:  "test",
		hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}},
	})

	proxyReq, err := p.createProxyRequest(context.Background(), original, targetURL)
	require.NoError(t, err)

	// Read the body from the proxy request
	body, err := io.ReadAll(proxyReq.Body)
	require.NoError(t, err)
	assert.Equal(t, bodyContent, string(body))
}

func TestProxy_Forward_WithRequestCreationError(t *testing.T) {
	t.Parallel()

	metrics := &mockMetricsRecorder{}
	p := New(
		WithLogger(observability.NopLogger()),
		WithMetrics(metrics),
		WithTransport(&mockRoundTripper{
			response: &http.Response{StatusCode: http.StatusOK, Body: http.NoBody},
		}),
	)

	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "test-backend",
			Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}},
		},
	})

	// Create a request with a body that returns an error on read
	req := httptest.NewRequest(http.MethodPost, "/graphql", &errorReader{})
	req.RemoteAddr = "192.168.1.1:12345"

	resp, err := p.Forward(context.Background(), "test-backend", req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to create proxy request")

	// Verify error metrics were recorded
	assert.Len(t, metrics.errors, 1)
	assert.Equal(t, "request_creation_failed", metrics.errors[0].errorType)
}

// errorReader is an io.Reader that always returns an error.
type errorReader struct{}

func (e *errorReader) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("simulated read error")
}

func TestWithOptions(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transport := &mockRoundTripper{}
	metrics := &mockMetricsRecorder{}

	p := New(
		WithLogger(logger),
		WithTransport(transport),
		WithMetrics(metrics),
		WithTimeout(42*time.Second),
		WithMaxBodySize(999),
	)

	assert.Equal(t, 42*time.Second, p.timeout)
	assert.Equal(t, int64(999), p.maxBodySize)
	assert.Same(t, transport, p.transport)
	assert.Same(t, metrics, p.metrics)
}
