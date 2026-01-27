package cache

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestKeyGenerator_GenerateFromTemplate_Error tests generateFromTemplate with invalid template data.
func TestKeyGenerator_GenerateFromTemplate_Error(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheKeyConfig{
		KeyTemplate: "{{.Method}}:{{.Path}}:{{.Query.id}}",
	}

	kg, err := NewKeyGenerator(cfg, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users?id=123", nil)
	key, err := kg.GenerateKey(req)
	assert.NoError(t, err)
	assert.Contains(t, key, "GET")
	assert.Contains(t, key, "/api/users")
}

// TestKeyGenerator_HashBody tests the hashBody function.
func TestKeyGenerator_HashBody_WithContent(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheKeyConfig{
		IncludeMethod:   true,
		IncludePath:     true,
		IncludeBodyHash: true,
	}

	kg, err := NewKeyGenerator(cfg, logger)
	require.NoError(t, err)

	body := bytes.NewReader([]byte(`{"name":"test"}`))
	req := httptest.NewRequest(http.MethodPost, "/api/users", body)

	key, err := kg.GenerateKey(req)
	assert.NoError(t, err)
	assert.Contains(t, key, "POST")
	assert.Contains(t, key, "/api/users")
	assert.Contains(t, key, "b:") // body hash prefix

	// Verify body is restored
	restoredBody, err := io.ReadAll(req.Body)
	assert.NoError(t, err)
	assert.Equal(t, `{"name":"test"}`, string(restoredBody))
}

// TestKeyGenerator_HashBody_EmptyBody tests hashBody with empty body.
func TestKeyGenerator_HashBody_EmptyBody(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheKeyConfig{
		IncludeMethod:   true,
		IncludePath:     true,
		IncludeBodyHash: true,
	}

	kg, err := NewKeyGenerator(cfg, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader([]byte{}))

	key, err := kg.GenerateKey(req)
	assert.NoError(t, err)
	// Should not contain body hash for empty body
	assert.NotContains(t, key, "b:")
}

// TestKeyGenerator_HashBody_NilBody tests hashBody with nil body.
func TestKeyGenerator_HashBody_NilBody(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheKeyConfig{
		IncludeMethod:   true,
		IncludePath:     true,
		IncludeBodyHash: true,
	}

	kg, err := NewKeyGenerator(cfg, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Body = nil

	key, err := kg.GenerateKey(req)
	assert.NoError(t, err)
	assert.NotContains(t, key, "b:")
}

// TestKeyGenerator_BuildQueryPart_EmptyParams tests buildQueryPart with no matching params.
func TestKeyGenerator_BuildQueryPart_EmptyParams(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheKeyConfig{
		IncludeMethod:      true,
		IncludePath:        true,
		IncludeQueryParams: []string{"missing_param"},
	}

	kg, err := NewKeyGenerator(cfg, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users?other=value", nil)

	key, err := kg.GenerateKey(req)
	assert.NoError(t, err)
	// Should not contain query part since param doesn't exist
	assert.NotContains(t, key, "q:")
}

// TestKeyGenerator_BuildHeaderPart_EmptyHeaders tests buildHeaderPart with no matching headers.
func TestKeyGenerator_BuildHeaderPart_EmptyHeaders(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheKeyConfig{
		IncludeMethod:  true,
		IncludePath:    true,
		IncludeHeaders: []string{"X-Missing-Header"},
	}

	kg, err := NewKeyGenerator(cfg, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	key, err := kg.GenerateKey(req)
	assert.NoError(t, err)
	// Should not contain header part since header doesn't exist
	assert.NotContains(t, key, "h:")
}

// TestKeyGenerator_BuildQueryPart_WithMatchingParams tests buildQueryPart with matching params.
func TestKeyGenerator_BuildQueryPart_WithMatchingParams(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheKeyConfig{
		IncludeMethod:      true,
		IncludePath:        true,
		IncludeQueryParams: []string{"page", "limit"},
	}

	kg, err := NewKeyGenerator(cfg, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users?page=1&limit=10&other=value", nil)

	key, err := kg.GenerateKey(req)
	assert.NoError(t, err)
	assert.Contains(t, key, "q:")
	assert.Contains(t, key, "page=1")
	assert.Contains(t, key, "limit=10")
}

// TestKeyGenerator_BuildHeaderPart_WithMatchingHeaders tests buildHeaderPart with matching headers.
func TestKeyGenerator_BuildHeaderPart_WithMatchingHeaders(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheKeyConfig{
		IncludeMethod:  true,
		IncludePath:    true,
		IncludeHeaders: []string{"Accept", "Authorization"},
	}

	kg, err := NewKeyGenerator(cfg, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer token123")

	key, err := kg.GenerateKey(req)
	assert.NoError(t, err)
	assert.Contains(t, key, "h:")
	assert.Contains(t, key, "Accept=application/json")
}

// TestNew_MemoryCache tests creating a memory cache.
func TestNew_MemoryCache_Coverage(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    "memory",
		TTL:     config.Duration(60000000000), // 60s
	}

	c, err := New(cfg, logger)
	require.NoError(t, err)
	assert.NotNil(t, c)

	err = c.Close()
	assert.NoError(t, err)
}

// TestNew_InvalidRedisURL tests creating a Redis cache with invalid URL.
func TestNew_InvalidRedisURL(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    "redis",
		Redis: &config.RedisCacheConfig{
			URL: "invalid://url",
		},
	}

	_, err := New(cfg, logger)
	assert.Error(t, err)
}

// TestNew_NilConfig tests creating a cache with nil config.
func TestNew_NilConfig_Coverage(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	c, err := New(nil, logger)
	assert.Error(t, err)
	assert.Nil(t, c)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}
