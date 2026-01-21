package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                    string
		config                  HeadersConfig
		initialRequestHeaders   map[string]string
		expectedRequestHeaders  map[string]string
		removedRequestHeaders   []string
		expectedResponseHeaders map[string]string
		removedResponseHeaders  []string
	}{
		{
			name: "sets request headers",
			config: HeadersConfig{
				RequestSet: map[string]string{
					"X-Custom-Header": "custom-value",
				},
			},
			expectedRequestHeaders: map[string]string{
				"X-Custom-Header": "custom-value",
			},
		},
		{
			name: "adds request headers",
			config: HeadersConfig{
				RequestAdd: map[string]string{
					"X-Added-Header": "added-value",
				},
			},
			expectedRequestHeaders: map[string]string{
				"X-Added-Header": "added-value",
			},
		},
		{
			name: "removes request headers",
			config: HeadersConfig{
				RequestRemove: []string{"X-Remove-Me"},
			},
			initialRequestHeaders: map[string]string{
				"X-Remove-Me": "should-be-removed",
				"X-Keep-Me":   "should-stay",
			},
			expectedRequestHeaders: map[string]string{
				"X-Keep-Me": "should-stay",
			},
			removedRequestHeaders: []string{"X-Remove-Me"},
		},
		{
			name: "sets response headers",
			config: HeadersConfig{
				ResponseSet: map[string]string{
					"X-Response-Header": "response-value",
				},
			},
			expectedResponseHeaders: map[string]string{
				"X-Response-Header": "response-value",
			},
		},
		{
			name: "adds response headers",
			config: HeadersConfig{
				ResponseAdd: map[string]string{
					"X-Added-Response": "added-response-value",
				},
			},
			expectedResponseHeaders: map[string]string{
				"X-Added-Response": "added-response-value",
			},
		},
		{
			name: "removes response headers",
			config: HeadersConfig{
				ResponseRemove: []string{"X-Remove-Response"},
			},
			removedResponseHeaders: []string{"X-Remove-Response"},
		},
		{
			name: "combined operations",
			config: HeadersConfig{
				RequestSet:     map[string]string{"X-Req-Set": "set-value"},
				RequestAdd:     map[string]string{"X-Req-Add": "add-value"},
				RequestRemove:  []string{"X-Req-Remove"},
				ResponseSet:    map[string]string{"X-Resp-Set": "resp-set-value"},
				ResponseAdd:    map[string]string{"X-Resp-Add": "resp-add-value"},
				ResponseRemove: []string{"X-Resp-Remove"},
			},
			initialRequestHeaders: map[string]string{
				"X-Req-Remove": "to-be-removed",
			},
			expectedRequestHeaders: map[string]string{
				"X-Req-Set": "set-value",
				"X-Req-Add": "add-value",
			},
			removedRequestHeaders: []string{"X-Req-Remove"},
			expectedResponseHeaders: map[string]string{
				"X-Resp-Set": "resp-set-value",
				"X-Resp-Add": "resp-add-value",
			},
			removedResponseHeaders: []string{"X-Resp-Remove"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			middleware := Headers(tt.config)

			var capturedRequestHeaders http.Header
			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedRequestHeaders = r.Header.Clone()
				// Set a header that might be removed
				w.Header().Set("X-Remove-Response", "to-be-removed")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			for k, v := range tt.initialRequestHeaders {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			// Check request headers
			for k, v := range tt.expectedRequestHeaders {
				assert.Equal(t, v, capturedRequestHeaders.Get(k), "request header %s", k)
			}
			for _, k := range tt.removedRequestHeaders {
				assert.Empty(t, capturedRequestHeaders.Get(k), "request header %s should be removed", k)
			}

			// Check response headers
			for k, v := range tt.expectedResponseHeaders {
				assert.Equal(t, v, rec.Header().Get(k), "response header %s", k)
			}
			for _, k := range tt.removedResponseHeaders {
				assert.Empty(t, rec.Header().Get(k), "response header %s should be removed", k)
			}
		})
	}
}

func TestHeadersFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                    string
		config                  *config.HeaderManipulation
		expectedRequestHeaders  map[string]string
		expectedResponseHeaders map[string]string
	}{
		{
			name:   "nil config returns passthrough",
			config: nil,
		},
		{
			name: "with request config",
			config: &config.HeaderManipulation{
				Request: &config.HeaderOperation{
					Set:    map[string]string{"X-Set": "value"},
					Add:    map[string]string{"X-Add": "value"},
					Remove: []string{"X-Remove"},
				},
			},
			expectedRequestHeaders: map[string]string{
				"X-Set": "value",
				"X-Add": "value",
			},
		},
		{
			name: "with response config",
			config: &config.HeaderManipulation{
				Response: &config.HeaderOperation{
					Set:    map[string]string{"X-Resp-Set": "value"},
					Add:    map[string]string{"X-Resp-Add": "value"},
					Remove: []string{"X-Resp-Remove"},
				},
			},
			expectedResponseHeaders: map[string]string{
				"X-Resp-Set": "value",
				"X-Resp-Add": "value",
			},
		},
		{
			name: "with both request and response config",
			config: &config.HeaderManipulation{
				Request: &config.HeaderOperation{
					Set: map[string]string{"X-Req": "req-value"},
				},
				Response: &config.HeaderOperation{
					Set: map[string]string{"X-Resp": "resp-value"},
				},
			},
			expectedRequestHeaders: map[string]string{
				"X-Req": "req-value",
			},
			expectedResponseHeaders: map[string]string{
				"X-Resp": "resp-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			middleware := HeadersFromConfig(tt.config)

			var capturedRequestHeaders http.Header
			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedRequestHeaders = r.Header.Clone()
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			for k, v := range tt.expectedRequestHeaders {
				assert.Equal(t, v, capturedRequestHeaders.Get(k))
			}
			for k, v := range tt.expectedResponseHeaders {
				assert.Equal(t, v, rec.Header().Get(k))
			}
		})
	}
}

func TestHeaderResponseWriter_WriteHeader(t *testing.T) {
	t.Parallel()

	cfg := HeadersConfig{
		ResponseSet: map[string]string{"X-Custom": "value"},
	}

	rec := httptest.NewRecorder()
	rw := &headerResponseWriter{
		ResponseWriter: rec,
		cfg:            cfg,
		headerWritten:  false,
	}

	rw.WriteHeader(http.StatusCreated)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "value", rec.Header().Get("X-Custom"))
	assert.True(t, rw.headerWritten)
}

func TestHeaderResponseWriter_Write(t *testing.T) {
	t.Parallel()

	cfg := HeadersConfig{
		ResponseSet: map[string]string{"X-Custom": "value"},
	}

	rec := httptest.NewRecorder()
	rw := &headerResponseWriter{
		ResponseWriter: rec,
		cfg:            cfg,
		headerWritten:  false,
	}

	n, err := rw.Write([]byte("test body"))

	assert.NoError(t, err)
	assert.Equal(t, 9, n)
	assert.Equal(t, "value", rec.Header().Get("X-Custom"))
	assert.True(t, rw.headerWritten)
	assert.Equal(t, "test body", rec.Body.String())
}

func TestHeaderResponseWriter_MultipleWrites(t *testing.T) {
	t.Parallel()

	cfg := HeadersConfig{
		ResponseSet: map[string]string{"X-Custom": "value"},
	}

	rec := httptest.NewRecorder()
	rw := &headerResponseWriter{
		ResponseWriter: rec,
		cfg:            cfg,
		headerWritten:  false,
	}

	_, _ = rw.Write([]byte("first"))
	_, _ = rw.Write([]byte("second"))

	// Headers should only be manipulated once
	assert.True(t, rw.headerWritten)
	assert.Equal(t, "firstsecond", rec.Body.String())
}

func TestHeaderResponseWriter_WriteHeaderThenWrite(t *testing.T) {
	t.Parallel()

	cfg := HeadersConfig{
		ResponseSet: map[string]string{"X-Custom": "value"},
	}

	rec := httptest.NewRecorder()
	rw := &headerResponseWriter{
		ResponseWriter: rec,
		cfg:            cfg,
		headerWritten:  false,
	}

	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte("body"))

	// Headers should only be manipulated once (during WriteHeader)
	assert.True(t, rw.headerWritten)
	assert.Equal(t, "value", rec.Header().Get("X-Custom"))
}
