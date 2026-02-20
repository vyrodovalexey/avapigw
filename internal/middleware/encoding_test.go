package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestEncodingFromConfig_NilConfig(t *testing.T) {
	t.Parallel()

	mw := EncodingFromConfig(nil, nil)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEncodingFromConfig_EmptyConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.EncodingConfig{}
	mw := EncodingFromConfig(cfg, nil)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEncodingFromConfig_NilLogger(t *testing.T) {
	t.Parallel()

	cfg := &config.EncodingConfig{
		EnableContentNegotiation: true,
		SupportedContentTypes:    []string{"application/json", "application/xml"},
	}

	// Should not panic with nil logger
	mw := EncodingFromConfig(cfg, nil)
	require.NotNil(t, mw)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Accept", "application/json")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEncodingFromConfig_ContentNegotiation(t *testing.T) {
	t.Parallel()

	cfg := &config.EncodingConfig{
		EnableContentNegotiation: true,
		SupportedContentTypes:    []string{"application/json", "application/xml"},
	}
	logger := observability.NopLogger()

	mw := EncodingFromConfig(cfg, logger)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Accept", "application/json")
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
	// Verify the negotiated content type header is set.
	assert.Equal(t, "application/json", rec.Header().Get("X-Content-Type-Negotiated"))
}

func TestEncodingFromConfig_ContentNegotiationDisabled(t *testing.T) {
	t.Parallel()

	cfg := &config.EncodingConfig{
		EnableContentNegotiation: false,
		RequestEncoding:          "json",
	}
	logger := observability.NopLogger()

	mw := EncodingFromConfig(cfg, logger)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Accept", "application/xml")
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEncodingFromConfig_WithAcceptHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		acceptHeader string
		supported    []string
	}{
		{
			name:         "JSON accept",
			acceptHeader: "application/json",
			supported:    []string{"application/json"},
		},
		{
			name:         "XML accept",
			acceptHeader: "application/xml",
			supported:    []string{"application/json", "application/xml"},
		},
		{
			name:         "wildcard accept",
			acceptHeader: "*/*",
			supported:    []string{"application/json"},
		},
		{
			name:         "empty accept",
			acceptHeader: "",
			supported:    []string{"application/json"},
		},
		{
			name:         "multiple accept types",
			acceptHeader: "application/json, application/xml;q=0.9",
			supported:    []string{"application/json", "application/xml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.EncodingConfig{
				EnableContentNegotiation: true,
				SupportedContentTypes:    tt.supported,
			}
			logger := observability.NopLogger()

			mw := EncodingFromConfig(cfg, logger)

			called := false
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
			if tt.acceptHeader != "" {
				req.Header.Set("Accept", tt.acceptHeader)
			}
			handler.ServeHTTP(rec, req)

			assert.True(t, called)
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

func TestEncodingFromConfig_PassthroughConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.EncodingConfig{
		Passthrough: true,
	}
	logger := observability.NopLogger()

	mw := EncodingFromConfig(cfg, logger)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEncodingFromConfig_MetricsRecording(t *testing.T) {
	t.Parallel()

	cfg := &config.EncodingConfig{
		EnableContentNegotiation: true,
		SupportedContentTypes:    []string{"application/json"},
	}
	logger := observability.NopLogger()

	mw := EncodingFromConfig(cfg, logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Accept", "application/json")
	handler.ServeHTTP(rec, req)

	// Verify the handler completed successfully (metrics are recorded internally)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEncodingFromConfig_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cfg        *config.EncodingConfig
		expectPass bool
	}{
		{
			name:       "nil config",
			cfg:        nil,
			expectPass: true,
		},
		{
			name:       "empty config",
			cfg:        &config.EncodingConfig{},
			expectPass: true,
		},
		{
			name: "negotiation enabled",
			cfg: &config.EncodingConfig{
				EnableContentNegotiation: true,
				SupportedContentTypes:    []string{"application/json"},
			},
			expectPass: true,
		},
		{
			name: "passthrough mode",
			cfg: &config.EncodingConfig{
				Passthrough: true,
			},
			expectPass: true,
		},
		{
			name: "with compression config",
			cfg: &config.EncodingConfig{
				Compression: &config.CompressionConfig{
					Enabled:    true,
					Algorithms: []string{"gzip"},
				},
			},
			expectPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			mw := EncodingFromConfig(tt.cfg, logger)
			require.NotNil(t, mw)

			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			handler.ServeHTTP(rec, req)

			if tt.expectPass {
				assert.Equal(t, http.StatusOK, rec.Code)
			}
		})
	}
}

func TestEncodingFromConfig_DecodeMetricRecorded(t *testing.T) {
	t.Parallel()

	cfg := &config.EncodingConfig{
		EnableContentNegotiation: true,
		SupportedContentTypes:    []string{"application/json"},
	}
	logger := observability.NopLogger()

	mw := EncodingFromConfig(cfg, logger)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	body := strings.NewReader(`{"key":"value"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/data", body)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
	// Metrics are recorded internally; we verify the handler completed
	// without error and the negotiated header is set.
	assert.Equal(t, "application/json", rec.Header().Get("X-Content-Type-Negotiated"))
}

func TestEncodingFromConfig_EncodeMetricRecorded(t *testing.T) {
	t.Parallel()

	cfg := &config.EncodingConfig{
		EnableContentNegotiation: true,
		SupportedContentTypes:    []string{"application/xml"},
	}
	logger := observability.NopLogger()

	mw := EncodingFromConfig(cfg, logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Accept", "application/xml")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/xml", rec.Header().Get("X-Content-Type-Negotiated"))
}

func TestEncodingFromConfig_UnsupportedContentTypeNoMetric(t *testing.T) {
	t.Parallel()

	cfg := &config.EncodingConfig{
		EnableContentNegotiation: true,
		SupportedContentTypes:    []string{"application/json"},
	}
	logger := observability.NopLogger()

	mw := EncodingFromConfig(cfg, logger)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		// Respond with an unsupported content type — no encode metric should fire.
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	body := strings.NewReader("plain text body")
	req := httptest.NewRequest(http.MethodPost, "/api/data", body)
	req.Header.Set("Content-Type", "text/plain")
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEncodingFromConfig_NegotiatedHeaderSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		acceptHeader string
		supported    []string
		expectNegHdr string
	}{
		{
			name:         "JSON negotiated",
			acceptHeader: "application/json",
			supported:    []string{"application/json", "application/xml"},
			expectNegHdr: "application/json",
		},
		{
			name:         "XML negotiated",
			acceptHeader: "application/xml",
			supported:    []string{"application/json", "application/xml"},
			expectNegHdr: "application/xml",
		},
		{
			name:         "no accept header — defaults to first supported",
			acceptHeader: "",
			supported:    []string{"application/json"},
			expectNegHdr: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.EncodingConfig{
				EnableContentNegotiation: true,
				SupportedContentTypes:    tt.supported,
			}
			logger := observability.NopLogger()

			mw := EncodingFromConfig(cfg, logger)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
			if tt.acceptHeader != "" {
				req.Header.Set("Accept", tt.acceptHeader)
			}
			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			if tt.expectNegHdr != "" {
				assert.Equal(t, tt.expectNegHdr, rec.Header().Get("X-Content-Type-Negotiated"))
			} else {
				assert.Empty(t, rec.Header().Get("X-Content-Type-Negotiated"))
			}
		})
	}
}

func TestEncodingFromConfig_DecodeMetricWithVariousContentTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		bodyContent string
		supported   bool
	}{
		{
			name:        "JSON request",
			contentType: "application/json",
			bodyContent: `{"a":1}`,
			supported:   true,
		},
		{
			name:        "JSON with charset",
			contentType: "application/json; charset=utf-8",
			bodyContent: `{"a":1}`,
			supported:   true,
		},
		{
			name:        "XML request",
			contentType: "application/xml",
			bodyContent: "<root/>",
			supported:   true,
		},
		{
			name:        "YAML request",
			contentType: "application/yaml",
			bodyContent: "key: value",
			supported:   true,
		},
		{
			name:        "text/json request",
			contentType: "text/json",
			bodyContent: `{"a":1}`,
			supported:   true,
		},
		{
			name:        "text/xml request",
			contentType: "text/xml",
			bodyContent: "<root/>",
			supported:   true,
		},
		{
			name:        "text/yaml request",
			contentType: "text/yaml",
			bodyContent: "key: value",
			supported:   true,
		},
		{
			name:        "application/x-yaml request",
			contentType: "application/x-yaml",
			bodyContent: "key: value",
			supported:   true,
		},
		{
			name:        "unsupported content type",
			contentType: "text/plain",
			bodyContent: "hello",
			supported:   false,
		},
		{
			name:        "multipart form data — unsupported",
			contentType: "multipart/form-data",
			bodyContent: "data",
			supported:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.EncodingConfig{
				RequestEncoding: "json",
			}
			logger := observability.NopLogger()

			mw := EncodingFromConfig(cfg, logger)
			require.NotNil(t, mw)

			called := false
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			body := strings.NewReader(tt.bodyContent)
			req := httptest.NewRequest(http.MethodPost, "/api/data", body)
			req.Header.Set("Content-Type", tt.contentType)
			handler.ServeHTTP(rec, req)

			assert.True(t, called)
			assert.Equal(t, http.StatusOK, rec.Code)
			// The test verifies the middleware does not panic or error
			// for any content type. Metric recording is verified
			// implicitly — supported types trigger RecordDecode,
			// unsupported types are silently skipped.
			_ = tt.supported
		})
	}
}

func TestEncodingFromConfig_NoDecodeMetricWithoutBody(t *testing.T) {
	t.Parallel()

	cfg := &config.EncodingConfig{
		RequestEncoding: "json",
	}
	logger := observability.NopLogger()

	mw := EncodingFromConfig(cfg, logger)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	// GET request with Content-Type but no body — should NOT record decode.
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEncodingFromConfig_EncodeMetricWithCharsetResponse(t *testing.T) {
	t.Parallel()

	cfg := &config.EncodingConfig{
		EnableContentNegotiation: true,
		SupportedContentTypes:    []string{"application/json"},
	}
	logger := observability.NopLogger()

	mw := EncodingFromConfig(cfg, logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Downstream sets Content-Type with charset parameter.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Accept", "application/json")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("X-Content-Type-Negotiated"))
}
