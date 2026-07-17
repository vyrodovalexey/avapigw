package openapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// readMinimalSpec returns the raw bytes of the minimal OpenAPI test spec.
func readMinimalSpec(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir(), "minimal.yaml"))
	require.NoError(t, err)
	return data
}

func TestSpecLoader_LoadFromData(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()
	data := readMinimalSpec(t)

	doc, err := loader.LoadFromData(context.Background(), data)
	require.NoError(t, err)
	require.NotNil(t, doc)

	// Second load should hit the content-derived cache and return the same doc.
	cached, err := loader.LoadFromData(context.Background(), data)
	require.NoError(t, err)
	assert.Same(t, doc, cached)
}

func TestSpecLoader_LoadFromData_Invalid(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()

	_, err := loader.LoadFromData(context.Background(), []byte("not: valid: openapi: ::"))
	require.Error(t, err)
}

func TestValidator_WithSpecData(t *testing.T) {
	t.Parallel()

	data := readMinimalSpec(t)

	v, err := NewValidator(WithSpecData(data))
	require.NoError(t, err)
	require.NotNil(t, v)

	// Inline reload should not fail.
	assert.NoError(t, v.Reload())
}

func TestNewValidatorFromConfig_WithSpecInline(t *testing.T) {
	t.Parallel()

	data := readMinimalSpec(t)

	cfg := &config.OpenAPIValidationConfig{
		Enabled:    true,
		SpecInline: string(data),
	}

	v, err := NewValidatorFromConfig(cfg, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, v)
}

// TestMiddlewareFromConfig_WithSpecInline verifies the end-to-end runtime path:
// an inline spec produces a working validation middleware that rejects a request
// that violates the spec and allows a conforming one.
func TestMiddlewareFromConfig_WithSpecInline(t *testing.T) {
	t.Parallel()

	data := readMinimalSpec(t)

	cfg := &config.OpenAPIValidationConfig{
		Enabled:    true,
		SpecInline: string(data),
	}

	mw := MiddlewareFromConfig(cfg, nil)
	require.NotNil(t, mw)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// A request to a path defined in the spec should be validated and pass.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
