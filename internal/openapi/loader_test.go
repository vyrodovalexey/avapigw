package openapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdataDir returns the path to the test data directory.
func testdataDir() string {
	return filepath.Join("..", "..", "test", "testdata", "openapi")
}

func TestNewSpecLoader(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()
	assert.NotNil(t, loader)
	assert.NotNil(t, loader.cache)
	assert.Empty(t, loader.cache)
}

func TestSpecLoader_LoadFromFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		path      string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid items-api spec",
			path:    filepath.Join(testdataDir(), "items-api.yaml"),
			wantErr: false,
		},
		{
			name:    "valid minimal spec",
			path:    filepath.Join(testdataDir(), "minimal.yaml"),
			wantErr: false,
		},
		{
			name:      "invalid spec file",
			path:      filepath.Join(testdataDir(), "invalid.yaml"),
			wantErr:   true,
			errSubstr: "invalid OpenAPI spec",
		},
		{
			name:      "non-existent file",
			path:      filepath.Join(testdataDir(), "nonexistent.yaml"),
			wantErr:   true,
			errSubstr: "failed to load OpenAPI spec from file",
		},
		{
			name:      "empty file path",
			path:      "",
			wantErr:   true,
			errSubstr: "failed to load OpenAPI spec from file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			loader := NewSpecLoader()
			ctx := context.Background()

			doc, err := loader.LoadFromFile(ctx, tt.path)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				assert.Nil(t, doc)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, doc)
				assert.NotEmpty(t, doc.Info.Title)
			}
		})
	}
}

func TestSpecLoader_LoadFromFile_Caching(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()
	ctx := context.Background()
	path := filepath.Join(testdataDir(), "minimal.yaml")

	// First load
	doc1, err := loader.LoadFromFile(ctx, path)
	require.NoError(t, err)
	require.NotNil(t, doc1)

	// Second load should return cached version (same pointer)
	doc2, err := loader.LoadFromFile(ctx, path)
	require.NoError(t, err)
	require.NotNil(t, doc2)

	// Should be the exact same pointer (cached)
	assert.Same(t, doc1, doc2)
}

func TestSpecLoader_LoadFromFile_CacheDoubleCheck(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()
	ctx := context.Background()
	path := filepath.Join(testdataDir(), "minimal.yaml")

	// Pre-populate cache manually to test the double-check path
	doc := &openapi3.T{Info: &openapi3.Info{Title: "cached"}}
	loader.cache[path] = doc

	// Should return the cached doc via the write-lock double-check path
	result, err := loader.LoadFromFile(ctx, path)
	require.NoError(t, err)
	assert.Same(t, doc, result)
}

func TestSpecLoader_LoadFromFile_ThreadSafety(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()
	ctx := context.Background()
	path := filepath.Join(testdataDir(), "minimal.yaml")

	const goroutines = 10
	var wg sync.WaitGroup
	docs := make([]*openapi3.T, goroutines)
	errs := make([]error, goroutines)

	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			docs[idx], errs[idx] = loader.LoadFromFile(ctx, path)
		}(i)
	}
	wg.Wait()

	// All should succeed and return the same cached doc
	for i := range goroutines {
		require.NoError(t, errs[i])
		require.NotNil(t, docs[i])
		assert.Same(t, docs[0], docs[i])
	}
}

func TestSpecLoader_LoadFromFile_InvalidContent(t *testing.T) {
	t.Parallel()

	// Create a temp file with invalid YAML
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "bad.yaml")
	err := os.WriteFile(invalidFile, []byte("not: valid: openapi: content: [[["), 0o644)
	require.NoError(t, err)

	loader := NewSpecLoader()
	ctx := context.Background()

	doc, err := loader.LoadFromFile(ctx, invalidFile)
	require.Error(t, err)
	assert.Nil(t, doc)
	assert.Contains(t, err.Error(), "failed to load OpenAPI spec from file")
}

func TestSpecLoader_LoadFromURL(t *testing.T) {
	t.Parallel()

	// Read the minimal spec to serve via HTTP
	specData, err := os.ReadFile(filepath.Join(testdataDir(), "minimal.yaml"))
	require.NoError(t, err)

	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantErr    bool
		errSubstr  string
		useRealURL bool
		realURL    string
	}{
		{
			name: "valid spec from URL",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/yaml")
				_, _ = w.Write(specData)
			},
			wantErr: false,
		},
		{
			name: "server returns 404",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr:   true,
			errSubstr: "failed to load OpenAPI spec from URL",
		},
		{
			name: "server returns invalid spec",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/yaml")
				_, _ = w.Write([]byte("not: valid: openapi"))
			},
			wantErr:   true,
			errSubstr: "failed to load OpenAPI spec from URL",
		},
		{
			name:       "unreachable URL",
			useRealURL: true,
			realURL:    "http://127.0.0.1:1/nonexistent",
			wantErr:    true,
			errSubstr:  "failed to load OpenAPI spec from URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			loader := NewSpecLoader()
			ctx := context.Background()

			var specURL string
			if tt.useRealURL {
				specURL = tt.realURL
			} else {
				server := httptest.NewServer(tt.handler)
				defer server.Close()
				specURL = server.URL + "/spec.yaml"
			}

			doc, loadErr := loader.LoadFromURL(ctx, specURL)
			if tt.wantErr {
				require.Error(t, loadErr)
				assert.Contains(t, loadErr.Error(), tt.errSubstr)
				assert.Nil(t, doc)
			} else {
				require.NoError(t, loadErr)
				assert.NotNil(t, doc)
			}
		})
	}
}

func TestSpecLoader_LoadFromURL_Caching(t *testing.T) {
	t.Parallel()

	specData, err := os.ReadFile(filepath.Join(testdataDir(), "minimal.yaml"))
	require.NoError(t, err)

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(specData)
	}))
	defer server.Close()

	loader := NewSpecLoader()
	ctx := context.Background()
	specURL := server.URL + "/spec.yaml"

	// First load
	doc1, err := loader.LoadFromURL(ctx, specURL)
	require.NoError(t, err)
	require.NotNil(t, doc1)

	// Second load should return cached version
	doc2, err := loader.LoadFromURL(ctx, specURL)
	require.NoError(t, err)
	require.NotNil(t, doc2)

	assert.Same(t, doc1, doc2)
	assert.Equal(t, 1, callCount, "server should only be called once due to caching")
}

func TestSpecLoader_LoadFromURL_CacheDoubleCheck(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()
	ctx := context.Background()
	specURL := "http://example.com/spec.yaml"

	// Pre-populate cache manually to test the double-check path
	doc := &openapi3.T{Info: &openapi3.Info{Title: "cached"}}
	loader.cache[specURL] = doc

	result, err := loader.LoadFromURL(ctx, specURL)
	require.NoError(t, err)
	assert.Same(t, doc, result)
}

func TestSpecLoader_LoadFromURL_InvalidSpec(t *testing.T) {
	t.Parallel()

	// Serve the invalid.yaml spec
	invalidData, err := os.ReadFile(filepath.Join(testdataDir(), "invalid.yaml"))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(invalidData)
	}))
	defer server.Close()

	loader := NewSpecLoader()
	ctx := context.Background()

	doc, loadErr := loader.LoadFromURL(ctx, server.URL+"/spec.yaml")
	require.Error(t, loadErr)
	assert.Nil(t, doc)
	assert.Contains(t, loadErr.Error(), "invalid OpenAPI spec from URL")
}

func TestSpecLoader_LoadFromURL_ThreadSafety(t *testing.T) {
	t.Parallel()

	specData, err := os.ReadFile(filepath.Join(testdataDir(), "minimal.yaml"))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(specData)
	}))
	defer server.Close()

	loader := NewSpecLoader()
	ctx := context.Background()
	specURL := server.URL + "/spec.yaml"

	const goroutines = 10
	var wg sync.WaitGroup
	docs := make([]*openapi3.T, goroutines)
	errs := make([]error, goroutines)

	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			docs[idx], errs[idx] = loader.LoadFromURL(ctx, specURL)
		}(i)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i])
		require.NotNil(t, docs[i])
		assert.Same(t, docs[0], docs[i])
	}
}

func TestSpecLoader_Invalidate(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()
	ctx := context.Background()
	path := filepath.Join(testdataDir(), "minimal.yaml")

	// Load and cache
	doc1, err := loader.LoadFromFile(ctx, path)
	require.NoError(t, err)
	require.NotNil(t, doc1)

	// Verify it's cached
	loader.mu.RLock()
	_, cached := loader.cache[path]
	loader.mu.RUnlock()
	assert.True(t, cached)

	// Invalidate
	loader.Invalidate(path)

	// Verify it's removed from cache
	loader.mu.RLock()
	_, cached = loader.cache[path]
	loader.mu.RUnlock()
	assert.False(t, cached)

	// Reload should work and return a new doc
	doc2, err := loader.LoadFromFile(ctx, path)
	require.NoError(t, err)
	require.NotNil(t, doc2)
}

func TestSpecLoader_Invalidate_NonExistentKey(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()

	// Should not panic
	loader.Invalidate("nonexistent-key")
	assert.Empty(t, loader.cache)
}

func TestSpecLoader_ImplementsLoaderInterface(t *testing.T) {
	t.Parallel()

	var _ Loader = (*SpecLoader)(nil)
}

func TestSpecLoader_LoadFromFile_ValidationError(t *testing.T) {
	t.Parallel()

	// Create a temp file with a parseable but invalid OpenAPI spec
	// (missing required info fields to trigger validation error)
	tmpDir := t.TempDir()
	invalidSpecFile := filepath.Join(tmpDir, "invalid-spec.yaml")
	invalidSpec := `openapi: "3.0.3"
info:
  title: ""
  version: ""
paths:
  /test:
    get:
      responses: {}
`
	err := os.WriteFile(invalidSpecFile, []byte(invalidSpec), 0o644)
	require.NoError(t, err)

	loader := NewSpecLoader()
	ctx := context.Background()

	doc, loadErr := loader.LoadFromFile(ctx, invalidSpecFile)
	require.Error(t, loadErr)
	assert.Nil(t, doc)
	assert.Contains(t, loadErr.Error(), "invalid OpenAPI spec in file")
}

func TestSpecLoader_LoadFromURL_ValidationError(t *testing.T) {
	t.Parallel()

	// Serve a parseable but invalid OpenAPI spec (triggers validation error path)
	invalidSpec := `openapi: "3.0.3"
info:
  title: ""
  version: ""
paths:
  /test:
    get:
      responses: {}
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write([]byte(invalidSpec))
	}))
	defer server.Close()

	loader := NewSpecLoader()
	ctx := context.Background()

	doc, loadErr := loader.LoadFromURL(ctx, server.URL+"/spec.yaml")
	require.Error(t, loadErr)
	assert.Nil(t, doc)
	assert.Contains(t, loadErr.Error(), "invalid OpenAPI spec from URL")
}

func TestSpecLoader_LoadFromFile_DirectoryPath(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()
	ctx := context.Background()

	// Try to load a directory instead of a file
	doc, err := loader.LoadFromFile(ctx, t.TempDir())
	require.Error(t, err)
	assert.Nil(t, doc)
	assert.Contains(t, err.Error(), "failed to load OpenAPI spec from file")
}

func TestSpecLoader_LoadFromURL_EmptyURL(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()
	ctx := context.Background()

	// Empty URL should fail
	doc, err := loader.LoadFromURL(ctx, "")
	require.Error(t, err)
	assert.Nil(t, doc)
}

func TestSpecLoader_Invalidate_ThenReloadFromFile(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()
	ctx := context.Background()
	path := filepath.Join(testdataDir(), "minimal.yaml")

	// First load
	doc1, err := loader.LoadFromFile(ctx, path)
	require.NoError(t, err)
	require.NotNil(t, doc1)

	// Verify it's cached
	loader.mu.RLock()
	_, cached := loader.cache[path]
	loader.mu.RUnlock()
	assert.True(t, cached)

	// Invalidate
	loader.Invalidate(path)

	// Verify it's removed from cache
	loader.mu.RLock()
	_, cached = loader.cache[path]
	loader.mu.RUnlock()
	assert.False(t, cached)

	// Reload should work and return a new doc (not the same pointer)
	doc2, err := loader.LoadFromFile(ctx, path)
	require.NoError(t, err)
	require.NotNil(t, doc2)
	// After invalidation, a fresh load should produce a new doc
	assert.NotSame(t, doc1, doc2)
}
