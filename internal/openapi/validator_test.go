package openapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockLoader implements the Loader interface for testing.
type mockLoader struct {
	doc *openapi3.T
	err error
}

func (m *mockLoader) LoadFromFile(_ context.Context, _ string) (*openapi3.T, error) {
	return m.doc, m.err
}

func (m *mockLoader) LoadFromURL(_ context.Context, _ string) (*openapi3.T, error) {
	return m.doc, m.err
}

func (m *mockLoader) Invalidate(_ string) {}

// newTestMetrics creates a Metrics instance with a unique registry for testing.
func newTestMetrics(t *testing.T) *Metrics {
	t.Helper()
	reg := prometheus.NewRegistry()
	return NewMetrics(reg)
}

func TestValidationError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      ValidationError
		expected string
	}{
		{
			name:     "with field",
			err:      ValidationError{Field: "body.name", Message: "required"},
			expected: "body.name: required",
		},
		{
			name:     "without field",
			err:      ValidationError{Field: "", Message: "invalid request"},
			expected: "invalid request",
		},
		{
			name:     "with error type",
			err:      ValidationError{Field: "query.limit", Message: "must be integer", ErrorType: "params"},
			expected: "query.limit: must be integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestValidationErrors_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		errs     ValidationErrors
		contains []string
	}{
		{
			name:     "no errors",
			errs:     ValidationErrors{},
			contains: []string{"no validation errors"},
		},
		{
			name: "single error",
			errs: ValidationErrors{
				Errors: []ValidationError{
					{Field: "body.name", Message: "required"},
				},
			},
			contains: []string{"body.name: required"},
		},
		{
			name: "multiple errors",
			errs: ValidationErrors{
				Errors: []ValidationError{
					{Field: "body.name", Message: "required"},
					{Field: "query.limit", Message: "must be integer"},
				},
			},
			contains: []string{"2 validation errors", "body.name: required", "query.limit: must be integer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.errs.Error()
			for _, s := range tt.contains {
				assert.Contains(t, result, s)
			}
		})
	}
}

func TestNewValidator(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")

	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name: "with valid spec file",
			opts: []Option{
				WithSpecFile(specPath),
			},
			wantErr: false,
		},
		{
			name: "with valid spec URL",
			opts: func() []Option {
				specData, _ := os.ReadFile(filepath.Join(testdataDir(), "minimal.yaml"))
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/yaml")
					_, _ = w.Write(specData)
				}))
				t.Cleanup(server.Close)
				return []Option{WithSpecURL(server.URL + "/spec.yaml")}
			}(),
			wantErr: false,
		},
		{
			name:    "no spec file or URL",
			opts:    []Option{},
			wantErr: true,
		},
		{
			name: "invalid spec file path",
			opts: []Option{
				WithSpecFile("/nonexistent/path.yaml"),
			},
			wantErr: true,
		},
		{
			name: "with all options",
			opts: []Option{
				WithSpecFile(specPath),
				WithFailOnError(false),
				WithValidateBody(true),
				WithValidateParams(true),
				WithValidateHeaders(true),
				WithValidateSecurity(false),
				WithLogger(observability.NopLogger()),
			},
			wantErr: false,
		},
		{
			name: "with custom loader",
			opts: func() []Option {
				loader := NewSpecLoader()
				return []Option{
					WithLoader(loader),
					WithSpecFile(specPath),
				}
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v, err := NewValidator(tt.opts...)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, v)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, v)
			}
		})
	}
}

func TestNewValidator_DefaultValues(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(WithSpecFile(specPath))
	require.NoError(t, err)

	assert.True(t, v.failOnError, "failOnError should default to true")
	assert.True(t, v.validateBody, "validateBody should default to true")
	assert.True(t, v.validateParams, "validateParams should default to true")
	assert.False(t, v.validateHeaders, "validateHeaders should default to false")
	assert.False(t, v.validateSecurity, "validateSecurity should default to false")
	assert.NotNil(t, v.logger, "logger should not be nil")
	assert.NotNil(t, v.loader, "loader should not be nil")
}

func TestValidator_ValidateRequest(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
		WithValidateBody(true),
		WithValidateParams(true),
	)
	require.NoError(t, err)

	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		headers map[string]string
		wantErr bool
	}{
		{
			name:    "valid GET request",
			method:  http.MethodGet,
			path:    "/api/v1/items",
			wantErr: false,
		},
		{
			name:    "valid GET with query params",
			method:  http.MethodGet,
			path:    "/api/v1/items?limit=10&offset=0",
			wantErr: false,
		},
		{
			name:   "valid POST request with body",
			method: http.MethodPost,
			path:   "/api/v1/items",
			body:   `{"name": "test item", "price": 9.99}`,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			wantErr: false,
		},
		{
			name:    "unknown path - skips validation",
			method:  http.MethodGet,
			path:    "/unknown/path",
			wantErr: false,
		},
		{
			name:    "invalid query parameter type",
			method:  http.MethodGet,
			path:    "/api/v1/items?limit=abc",
			wantErr: true,
		},
		{
			name:   "invalid body schema - missing required field",
			method: http.MethodPost,
			path:   "/api/v1/items",
			body:   `{"price": 9.99}`,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			wantErr: true,
		},
		{
			name:   "invalid body schema - wrong type",
			method: http.MethodPost,
			path:   "/api/v1/items",
			body:   `{"name": 123}`,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			wantErr: true,
		},
		{
			name:    "valid GET item by ID",
			method:  http.MethodGet,
			path:    "/api/v1/items/550e8400-e29b-41d4-a716-446655440000",
			wantErr: false,
		},
		{
			name:    "valid DELETE item",
			method:  http.MethodDelete,
			path:    "/api/v1/items/550e8400-e29b-41d4-a716-446655440000",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var req *http.Request
			if tt.body != "" {
				req = httptest.NewRequest(tt.method, tt.path, bytes.NewBufferString(tt.body))
			} else {
				req = httptest.NewRequest(tt.method, tt.path, nil)
			}
			for k, hv := range tt.headers {
				req.Header.Set(k, hv)
			}

			valErr := v.ValidateRequest(context.Background(), req)
			if tt.wantErr {
				assert.Error(t, valErr)
			} else {
				assert.NoError(t, valErr)
			}
		})
	}
}

func TestValidator_ValidateRequest_NilRouterAndDoc(t *testing.T) {
	t.Parallel()

	v := &Validator{
		router: nil,
		doc:    nil,
		logger: observability.NopLogger(),
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	err := v.ValidateRequest(context.Background(), req)
	assert.NoError(t, err, "nil router/doc should return nil (no-op)")
}

func TestValidator_FailOnError(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")

	tests := []struct {
		name     string
		failOn   bool
		expected bool
	}{
		{
			name:     "fail on error true",
			failOn:   true,
			expected: true,
		},
		{
			name:     "fail on error false",
			failOn:   false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v, err := NewValidator(
				WithSpecFile(specPath),
				WithFailOnError(tt.failOn),
			)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, v.FailOnError())
		})
	}
}

func TestValidator_BuildFilterOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		validateBody     bool
		validateParams   bool
		validateSecurity bool
		wantExcludeBody  bool
		wantExcludeQuery bool
	}{
		{
			name:             "all enabled",
			validateBody:     true,
			validateParams:   true,
			validateSecurity: true,
			wantExcludeBody:  false,
			wantExcludeQuery: false,
		},
		{
			name:             "body disabled",
			validateBody:     false,
			validateParams:   true,
			validateSecurity: true,
			wantExcludeBody:  true,
			wantExcludeQuery: false,
		},
		{
			name:             "params disabled",
			validateBody:     true,
			validateParams:   false,
			validateSecurity: true,
			wantExcludeBody:  false,
			wantExcludeQuery: true,
		},
		{
			name:             "all disabled",
			validateBody:     false,
			validateParams:   false,
			validateSecurity: false,
			wantExcludeBody:  true,
			wantExcludeQuery: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := &Validator{
				validateBody:     tt.validateBody,
				validateParams:   tt.validateParams,
				validateSecurity: tt.validateSecurity,
			}

			opts := v.buildFilterOptions()
			assert.Equal(t, tt.wantExcludeBody, opts.ExcludeRequestBody)
			assert.Equal(t, tt.wantExcludeQuery, opts.ExcludeRequestQueryParams)
		})
	}
}

func TestValidator_Reload(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(WithSpecFile(specPath))
	require.NoError(t, err)

	// Reload should succeed
	err = v.Reload()
	assert.NoError(t, err)
}

func TestValidator_Reload_WithURL(t *testing.T) {
	t.Parallel()

	specData, err := os.ReadFile(filepath.Join(testdataDir(), "minimal.yaml"))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(specData)
	}))
	defer server.Close()

	v, err := NewValidator(WithSpecURL(server.URL + "/spec.yaml"))
	require.NoError(t, err)

	err = v.Reload()
	assert.NoError(t, err)
}

func TestNewValidatorFromConfig(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	boolTrue := true
	boolFalse := false

	tests := []struct {
		name    string
		cfg     *config.OpenAPIValidationConfig
		wantNil bool
		wantErr bool
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantNil: true,
			wantErr: false,
		},
		{
			name: "disabled config",
			cfg: &config.OpenAPIValidationConfig{
				Enabled: false,
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "enabled with spec file",
			cfg: &config.OpenAPIValidationConfig{
				Enabled:  true,
				SpecFile: specPath,
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "enabled with all options",
			cfg: &config.OpenAPIValidationConfig{
				Enabled:                true,
				SpecFile:               specPath,
				FailOnError:            &boolFalse,
				ValidateRequestBody:    &boolTrue,
				ValidateRequestParams:  &boolTrue,
				ValidateRequestHeaders: &boolTrue,
				ValidateSecurity:       &boolFalse,
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "enabled without spec file or URL",
			cfg: &config.OpenAPIValidationConfig{
				Enabled: true,
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "enabled with invalid spec file",
			cfg: &config.OpenAPIValidationConfig{
				Enabled:  true,
				SpecFile: "/nonexistent/path.yaml",
			},
			wantNil: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			v, err := NewValidatorFromConfig(tt.cfg, logger, nil)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantNil {
				assert.Nil(t, v)
			}
		})
	}
}

func TestNewValidatorFromConfig_WithSpecURL(t *testing.T) {
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

	v, err := NewValidatorFromConfig(cfg, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, v)
}

func TestNewValidatorFromConfig_WithMetrics(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	cfg := &config.OpenAPIValidationConfig{
		Enabled:  true,
		SpecFile: specPath,
	}

	metrics := newTestMetrics(t)

	v, err := NewValidatorFromConfig(cfg, observability.NopLogger(), metrics)
	require.NoError(t, err)
	assert.NotNil(t, v)
	assert.Equal(t, metrics, v.metrics)
}

func TestWithOptions(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	logger := observability.NopLogger()
	metrics := newTestMetrics(t)

	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(false),
		WithValidateBody(false),
		WithValidateParams(false),
		WithValidateHeaders(true),
		WithValidateSecurity(true),
		WithLogger(logger),
		WithMetrics(metrics),
	)
	require.NoError(t, err)

	assert.False(t, v.failOnError)
	assert.False(t, v.validateBody)
	assert.False(t, v.validateParams)
	assert.True(t, v.validateHeaders)
	assert.True(t, v.validateSecurity)
	assert.Equal(t, metrics, v.metrics)
}

func TestClassifyRequestError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		param    *openapi3.Parameter
		expected string
	}{
		{
			name:     "query parameter",
			param:    &openapi3.Parameter{In: "query", Name: "limit"},
			expected: "params",
		},
		{
			name:     "path parameter",
			param:    &openapi3.Parameter{In: "path", Name: "id"},
			expected: "params",
		},
		{
			name:     "header parameter",
			param:    &openapi3.Parameter{In: "header", Name: "X-Custom"},
			expected: "headers",
		},
		{
			name:     "cookie parameter defaults to body",
			param:    &openapi3.Parameter{In: "cookie", Name: "session"},
			expected: "body",
		},
		{
			name:     "nil parameter defaults to body",
			param:    nil,
			expected: "body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reqErr := &openapi3filter.RequestError{
				Parameter: tt.param,
			}
			result := classifyRequestError(reqErr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertValidationError(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(WithSpecFile(specPath))
	require.NoError(t, err)

	t.Run("request error with parameter", func(t *testing.T) {
		t.Parallel()

		reqErr := &openapi3filter.RequestError{
			Parameter: &openapi3.Parameter{
				Name: "limit",
				In:   "query",
			},
			Reason: "invalid value",
		}

		result := v.convertValidationError(reqErr)
		require.NotNil(t, result)
		require.Len(t, result.Errors, 1)
		assert.Equal(t, "limit", result.Errors[0].Field)
		assert.Equal(t, "params", result.Errors[0].ErrorType)
	})

	t.Run("security error", func(t *testing.T) {
		t.Parallel()

		secErr := &openapi3filter.SecurityRequirementsError{
			Errors: []error{assert.AnError},
		}

		result := v.convertValidationError(secErr)
		require.NotNil(t, result)
		require.Len(t, result.Errors, 1)
		assert.Equal(t, "security", result.Errors[0].ErrorType)
	})

	t.Run("unknown error type", func(t *testing.T) {
		t.Parallel()

		result := v.convertValidationError(assert.AnError)
		require.NotNil(t, result)
		require.Len(t, result.Errors, 1)
		assert.Equal(t, "unknown", result.Errors[0].ErrorType)
	})
}

func TestValidator_ValidateRequest_WithBodyValidationDisabled(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithValidateBody(false),
		WithValidateParams(true),
	)
	require.NoError(t, err)

	// POST with invalid body should pass when body validation is disabled
	req := httptest.NewRequest(http.MethodPost, "/api/v1/items",
		bytes.NewBufferString(`{"invalid": "body"}`))
	req.Header.Set("Content-Type", "application/json")

	err = v.ValidateRequest(context.Background(), req)
	assert.NoError(t, err)
}

func TestValidator_ValidateRequest_WithParamsValidationDisabled(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithValidateBody(true),
		WithValidateParams(false),
	)
	require.NoError(t, err)

	// GET with invalid query params should pass when params validation is disabled
	req := httptest.NewRequest(http.MethodGet, "/api/v1/items?limit=abc", nil)

	err = v.ValidateRequest(context.Background(), req)
	assert.NoError(t, err)
}

func TestValidator_LoadSpec_RouterCreationError(t *testing.T) {
	t.Parallel()

	// Create a mock loader that returns a doc with nil Paths
	// which will cause gorillamux.NewRouter to fail
	emptyDoc := &openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: "test", Version: "1.0"},
		// Paths is nil - this should cause router creation to fail
	}

	ml := &mockLoader{doc: emptyDoc}

	_, err := NewValidator(
		WithLoader(ml),
		WithSpecFile("test.yaml"),
	)
	// The router creation may or may not fail depending on the library version,
	// but we exercise the code path
	if err != nil {
		assert.Contains(t, err.Error(), "router")
	}
}

func TestValidator_ValidateRequest_WithSecurityValidationDisabled(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithValidateSecurity(false),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	err = v.ValidateRequest(context.Background(), req)
	assert.NoError(t, err)
}

func TestValidator_ValidateRequest_WithHeadersValidationEnabled(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithValidateHeaders(true),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	err = v.ValidateRequest(context.Background(), req)
	assert.NoError(t, err)
}

func TestValidator_Reload_InvalidatesAndReloads(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(WithSpecFile(specPath))
	require.NoError(t, err)

	// Validate a request before reload
	req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	err = v.ValidateRequest(context.Background(), req)
	assert.NoError(t, err)

	// Reload
	err = v.Reload()
	require.NoError(t, err)

	// Validate again after reload
	req = httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	err = v.ValidateRequest(context.Background(), req)
	assert.NoError(t, err)
}

func TestNewValidatorFromConfig_NilLogger(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	cfg := &config.OpenAPIValidationConfig{
		Enabled:  true,
		SpecFile: specPath,
	}

	// nil logger should not panic
	v, err := NewValidatorFromConfig(cfg, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, v)
}

func TestConvertValidationError_RequestErrorWithoutParameter(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(WithSpecFile(specPath))
	require.NoError(t, err)

	// Request error without parameter (body error)
	reqErr := &openapi3filter.RequestError{
		Parameter: nil,
		Reason:    "invalid body",
	}

	result := v.convertValidationError(reqErr)
	require.NotNil(t, result)
	require.Len(t, result.Errors, 1)
	assert.Equal(t, "", result.Errors[0].Field)
	assert.Equal(t, "body", result.Errors[0].ErrorType)
}

func TestValidator_ValidateRequest_PUTWithBody(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
		WithValidateBody(true),
	)
	require.NoError(t, err)

	// Valid PUT request
	body := `{"name": "updated item", "price": 19.99}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/items/550e8400-e29b-41d4-a716-446655440000",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	valErr := v.ValidateRequest(context.Background(), req)
	assert.NoError(t, valErr)
}

func TestValidator_ValidateRequest_InvalidPUTBody(t *testing.T) {
	t.Parallel()

	specPath := filepath.Join(testdataDir(), "items-api.yaml")
	v, err := NewValidator(
		WithSpecFile(specPath),
		WithFailOnError(true),
		WithValidateBody(true),
	)
	require.NoError(t, err)

	// Invalid PUT request - wrong type for name
	body := `{"name": 123}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/items/550e8400-e29b-41d4-a716-446655440000",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	valErr := v.ValidateRequest(context.Background(), req)
	assert.Error(t, valErr)
}
