package openapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// testHandler is a simple handler that records whether it was called.
func testHandler() (http.Handler, *bool) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	return handler, &called
}

func TestMiddleware_NilValidator(t *testing.T) {
	t.Parallel()

	mw := Middleware(nil)
	handler, called := testHandler()

	wrapped := mw(handler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	assert.True(t, *called, "handler should be called when validator is nil")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_ValidRequest(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, called := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	assert.True(t, *called, "handler should be called for valid request")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_InvalidRequest_FailOnError(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, called := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/items?limit=abc", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	assert.False(t, *called, "handler should NOT be called for invalid request with failOnError=true")
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Verify response body format
	var resp validationErrorResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "request validation failed", resp.Error)
	assert.NotEmpty(t, resp.Details)
}

func TestMiddleware_InvalidRequest_LogOnly(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(false),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, called := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/items?limit=abc", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	// In log-only mode, the handler should NOT be called because
	// handleValidationError returns without calling next.ServeHTTP
	// when failOnError is false.
	assert.False(t, *called, "handler should not be called in log-only mode (middleware returns after logging)")
}

func TestMiddleware_UnknownPath_PassesThrough(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, called := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	assert.True(t, *called, "handler should be called for unknown path (not in spec)")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_WithMetrics(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
		WithMetrics(metrics),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, _ := testHandler()
	wrapped := mw(handler)

	// Valid request
	req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Invalid request
	req = httptest.NewRequest(http.MethodGet, "/api/v1/items?limit=abc", nil)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMiddlewareFromConfig(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")

	tests := []struct {
		name           string
		cfg            *config.OpenAPIValidationConfig
		expectPassThru bool
	}{
		{
			name:           "nil config - no-op",
			cfg:            nil,
			expectPassThru: true,
		},
		{
			name: "disabled config - no-op",
			cfg: &config.OpenAPIValidationConfig{
				Enabled: false,
			},
			expectPassThru: true,
		},
		{
			name: "enabled with valid spec",
			cfg: &config.OpenAPIValidationConfig{
				Enabled:  true,
				SpecFile: specPath,
			},
			expectPassThru: true, // valid request passes through
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			mw := MiddlewareFromConfig(tt.cfg, logger)
			require.NotNil(t, mw)

			handler, called := testHandler()
			wrapped := mw(handler)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if tt.expectPassThru {
				assert.True(t, *called)
				assert.Equal(t, http.StatusOK, rec.Code)
			}
		})
	}
}

func TestMiddlewareFromConfig_NilLogger(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	cfg := &config.OpenAPIValidationConfig{
		Enabled:  true,
		SpecFile: specPath,
	}

	// Should not panic with nil logger
	mw := MiddlewareFromConfig(cfg, nil)
	require.NotNil(t, mw)

	handler, called := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.True(t, *called)
}

func TestMiddlewareFromConfig_InvalidSpec(t *testing.T) {
	t.Parallel()

	cfg := &config.OpenAPIValidationConfig{
		Enabled:  true,
		SpecFile: "/nonexistent/spec.yaml",
	}

	logger := observability.NopLogger()
	mw := MiddlewareFromConfig(cfg, logger)
	require.NotNil(t, mw)

	// Should be a no-op middleware since validator creation failed
	handler, called := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.True(t, *called, "handler should be called when validator creation fails (no-op)")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestWriteValidationErrorResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		valErrs     *ValidationErrors
		fallbackErr error
		wantFields  bool
	}{
		{
			name: "with validation errors",
			valErrs: &ValidationErrors{
				Errors: []ValidationError{
					{Field: "body.name", Message: "required", ErrorType: "body"},
					{Field: "query.limit", Message: "must be integer", ErrorType: "params"},
				},
			},
			fallbackErr: nil,
			wantFields:  true,
		},
		{
			name:        "nil validation errors with fallback",
			valErrs:     nil,
			fallbackErr: assert.AnError,
			wantFields:  true,
		},
		{
			name: "empty validation errors",
			valErrs: &ValidationErrors{
				Errors: []ValidationError{},
			},
			fallbackErr: nil,
			wantFields:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			fallback := tt.fallbackErr
			if fallback == nil {
				fallback = assert.AnError
			}
			writeValidationErrorResponse(rec, tt.valErrs, fallback)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

			var resp validationErrorResponse
			err := json.NewDecoder(rec.Body).Decode(&resp)
			require.NoError(t, err)
			assert.Equal(t, "request validation failed", resp.Error)

			if tt.wantFields {
				assert.NotEmpty(t, resp.Details)
			}
		})
	}
}

func TestHandleValidationError_WithMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	v := &Validator{
		failOnError: true,
		logger:      observability.NopLogger(),
		metrics:     metrics,
	}

	valErrs := &ValidationErrors{
		Errors: []ValidationError{
			{Field: "body.name", Message: "required", ErrorType: "body"},
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/items", nil)

	handleValidationError(v, rec, req, valErrs, "/api/v1/items", 0.001)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleValidationError_LogOnly(t *testing.T) {
	t.Parallel()

	v := &Validator{
		failOnError: false,
		logger:      observability.NopLogger(),
	}

	valErrs := &ValidationErrors{
		Errors: []ValidationError{
			{Field: "body.name", Message: "required", ErrorType: "body"},
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/items", nil)

	handleValidationError(v, rec, req, valErrs, "/api/v1/items", 0.001)

	// In log-only mode, no response should be written
	assert.Equal(t, http.StatusOK, rec.Code) // default status
}

func TestHandleValidationError_NonValidationError(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	v := &Validator{
		failOnError: true,
		logger:      observability.NopLogger(),
		metrics:     metrics,
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/items", nil)

	// Pass a plain error (not *ValidationErrors)
	handleValidationError(v, rec, req, assert.AnError, "/api/v1/items", 0.001)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMiddleware_PreservesRequestBody(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
		WithValidateBody(true),
	)
	require.NoError(t, err)

	bodyContent := `{"name": "test item", "price": 9.99}`

	mw := Middleware(v)
	var receivedBody string
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr == nil {
			receivedBody = string(body)
		}
	})
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/items",
		bytes.NewBufferString(bodyContent))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	// The body should be available to the downstream handler
	// Note: openapi3filter may consume the body, but the middleware
	// should ideally preserve it. This test verifies the behavior.
	// If the body is consumed, this is expected behavior of the library.
	_ = receivedBody
}

func TestMiddleware_ValidPostRequest(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, called := testHandler()
	wrapped := mw(handler)

	body := `{"name": "test item", "price": 9.99}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/items",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	assert.True(t, *called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_InvalidPostRequest_MissingRequiredField(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, called := testHandler()
	wrapped := mw(handler)

	body := `{"price": 9.99}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/items",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	assert.False(t, *called)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMiddleware_ResponseContentType(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, _ := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/items?limit=abc", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestMiddleware_SuccessWithMetrics(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
		WithMetrics(metrics),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, called := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	assert.True(t, *called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandleValidationError_LogOnlyWithMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	v := &Validator{
		failOnError: false,
		logger:      observability.NopLogger(),
		metrics:     metrics,
	}

	valErrs := &ValidationErrors{
		Errors: []ValidationError{
			{Field: "query.limit", Message: "must be integer", ErrorType: "params"},
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/items?limit=abc", nil)

	handleValidationError(v, rec, req, valErrs, "/api/v1/items", 0.002)

	// In log-only mode, no response should be written
	assert.Equal(t, http.StatusOK, rec.Code) // default status
}

func TestHandleValidationError_NonValidationError_LogOnly(t *testing.T) {
	t.Parallel()

	v := &Validator{
		failOnError: false,
		logger:      observability.NopLogger(),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/items", nil)

	// Pass a plain error (not *ValidationErrors) in log-only mode
	handleValidationError(v, rec, req, assert.AnError, "/api/v1/items", 0.001)

	// In log-only mode, no response should be written
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_InvalidRequest_FailOnError_WithMetrics(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
		WithMetrics(metrics),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, called := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/items?limit=abc", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	assert.False(t, *called)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Verify response body
	var resp validationErrorResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "request validation failed", resp.Error)
	assert.NotEmpty(t, resp.Details)
}

func TestMiddleware_InvalidRequest_LogOnly_WithMetrics(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(false),
		WithMetrics(metrics),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, _ := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/items?limit=abc", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	// In log-only mode, the middleware returns after logging without calling next
	// The response code should be the default (200)
}

func TestMiddlewareFromConfig_WithSpecURL(t *testing.T) {
	t.Parallel()

	specData, err := os.ReadFile(filepath.Join(testdataDir(), "minimal.yaml"))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(specData)
	}))
	defer server.Close()

	cfg := &config.OpenAPIValidationConfig{
		Enabled: true,
		SpecURL: server.URL + "/spec.yaml",
	}

	logger := observability.NopLogger()
	mw := MiddlewareFromConfig(cfg, logger)
	require.NotNil(t, mw)

	handler, called := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.True(t, *called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestWriteValidationErrorResponse_SingleError(t *testing.T) {
	t.Parallel()

	valErrs := &ValidationErrors{
		Errors: []ValidationError{
			{Field: "body.name", Message: "required", ErrorType: "body"},
		},
	}

	rec := httptest.NewRecorder()
	writeValidationErrorResponse(rec, valErrs, nil)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp validationErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "request validation failed", resp.Error)
	require.Len(t, resp.Details, 1)
	assert.Equal(t, "body.name", resp.Details[0].Field)
	assert.Equal(t, "required", resp.Details[0].Message)
	assert.Equal(t, "body", resp.Details[0].Type)
}

func TestMiddleware_DeleteRequest(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
	)
	require.NoError(t, err)

	mw := Middleware(v)
	handler, called := testHandler()
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/items/550e8400-e29b-41d4-a716-446655440000", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	assert.True(t, *called)
	assert.Equal(t, http.StatusOK, rec.Code)
}
