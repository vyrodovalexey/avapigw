// Package cache provides caching capabilities for the API Gateway.
package cache

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewKeyGenerator(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.CacheKeyConfig
		logger    observability.Logger
		wantErr   bool
		errString string
	}{
		{
			name:    "nil config uses defaults",
			cfg:     nil,
			logger:  nil,
			wantErr: false,
		},
		{
			name: "valid config with all options",
			cfg: &config.CacheKeyConfig{
				IncludeMethod:      true,
				IncludePath:        true,
				IncludeQueryParams: []string{"page", "limit"},
				IncludeHeaders:     []string{"Authorization"},
				IncludeBodyHash:    true,
			},
			logger:  observability.NopLogger(),
			wantErr: false,
		},
		{
			name: "valid config with key template",
			cfg: &config.CacheKeyConfig{
				KeyTemplate: "{{.Method}}:{{.Path}}",
			},
			logger:  observability.NopLogger(),
			wantErr: false,
		},
		{
			name: "invalid key template",
			cfg: &config.CacheKeyConfig{
				KeyTemplate: "{{.Method}:{{.Path}}", // Missing closing brace
			},
			logger:    observability.NopLogger(),
			wantErr:   true,
			errString: "template",
		},
		{
			name: "empty config",
			cfg: &config.CacheKeyConfig{
				IncludeMethod: false,
				IncludePath:   false,
			},
			logger:  nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kg, err := NewKeyGenerator(tt.cfg, tt.logger)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errString != "" {
					assert.Contains(t, err.Error(), tt.errString)
				}
				assert.Nil(t, kg)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, kg)
			}
		})
	}
}

func TestKeyGenerator_GenerateKey(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.CacheKeyConfig
		request     *http.Request
		wantKey     string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "default config - method and path",
			cfg: &config.CacheKeyConfig{
				IncludeMethod: true,
				IncludePath:   true,
			},
			request: createTestRequest("GET", "/api/users", nil, nil, ""),
			wantKey: "GET:/api/users",
			wantErr: false,
		},
		{
			name: "method only",
			cfg: &config.CacheKeyConfig{
				IncludeMethod: true,
				IncludePath:   false,
			},
			request: createTestRequest("POST", "/api/users", nil, nil, ""),
			wantKey: "POST",
			wantErr: false,
		},
		{
			name: "path only",
			cfg: &config.CacheKeyConfig{
				IncludeMethod: false,
				IncludePath:   true,
			},
			request: createTestRequest("GET", "/api/users", nil, nil, ""),
			wantKey: "/api/users",
			wantErr: false,
		},
		{
			name: "with query parameters",
			cfg: &config.CacheKeyConfig{
				IncludeMethod:      true,
				IncludePath:        true,
				IncludeQueryParams: []string{"page", "limit"},
			},
			request:     createTestRequest("GET", "/api/users", url.Values{"page": {"1"}, "limit": {"10"}, "sort": {"name"}}, nil, ""),
			wantContain: []string{"GET", "/api/users", "q:", "page=1", "limit=10"},
			wantErr:     false,
		},
		{
			name: "with headers",
			cfg: &config.CacheKeyConfig{
				IncludeMethod:  true,
				IncludePath:    true,
				IncludeHeaders: []string{"X-Tenant-Id"},
			},
			request:     createTestRequest("GET", "/api/users", nil, http.Header{"X-Tenant-Id": {"tenant-123"}}, ""),
			wantContain: []string{"GET", "/api/users", "h:", "X-Tenant-Id=tenant-123"},
			wantErr:     false,
		},
		{
			name: "with body hash",
			cfg: &config.CacheKeyConfig{
				IncludeMethod:   true,
				IncludePath:     true,
				IncludeBodyHash: true,
			},
			request:     createTestRequest("POST", "/api/users", nil, nil, `{"name":"test"}`),
			wantContain: []string{"POST", "/api/users", "b:"},
			wantErr:     false,
		},
		{
			name: "with empty body - no body hash",
			cfg: &config.CacheKeyConfig{
				IncludeMethod:   true,
				IncludePath:     true,
				IncludeBodyHash: true,
			},
			request: createTestRequest("GET", "/api/users", nil, nil, ""),
			wantKey: "GET:/api/users",
			wantErr: false,
		},
		{
			name: "query params not in request",
			cfg: &config.CacheKeyConfig{
				IncludeMethod:      true,
				IncludePath:        true,
				IncludeQueryParams: []string{"page", "limit"},
			},
			request: createTestRequest("GET", "/api/users", nil, nil, ""),
			wantKey: "GET:/api/users",
			wantErr: false,
		},
		{
			name: "headers not in request",
			cfg: &config.CacheKeyConfig{
				IncludeMethod:  true,
				IncludePath:    true,
				IncludeHeaders: []string{"X-Tenant-ID"},
			},
			request: createTestRequest("GET", "/api/users", nil, nil, ""),
			wantKey: "GET:/api/users",
			wantErr: false,
		},
		{
			name: "multiple query param values",
			cfg: &config.CacheKeyConfig{
				IncludeMethod:      true,
				IncludePath:        true,
				IncludeQueryParams: []string{"ids"},
			},
			request:     createTestRequest("GET", "/api/users", url.Values{"ids": {"1", "2", "3"}}, nil, ""),
			wantContain: []string{"GET", "/api/users", "q:", "ids=1", "ids=2", "ids=3"},
			wantErr:     false,
		},
		{
			name: "multiple header values",
			cfg: &config.CacheKeyConfig{
				IncludeMethod:  true,
				IncludePath:    true,
				IncludeHeaders: []string{"Accept"},
			},
			request:     createTestRequest("GET", "/api/users", nil, http.Header{"Accept": {"application/json", "text/plain"}}, ""),
			wantContain: []string{"GET", "/api/users", "h:", "Accept=application/json", "Accept=text/plain"},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kg, err := NewKeyGenerator(tt.cfg, observability.NopLogger())
			require.NoError(t, err)

			key, err := kg.GenerateKey(tt.request)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				if tt.wantKey != "" {
					assert.Equal(t, tt.wantKey, key)
				}

				for _, contain := range tt.wantContain {
					assert.Contains(t, key, contain, "key should contain %s", contain)
				}
			}
		})
	}
}

func TestKeyGenerator_GenerateKey_WithTemplate(t *testing.T) {
	tests := []struct {
		name        string
		template    string
		request     *http.Request
		wantKey     string
		wantContain []string
		wantErr     bool
	}{
		{
			name:     "simple template",
			template: "{{.Method}}:{{.Path}}",
			request:  createTestRequest("GET", "/api/users", nil, nil, ""),
			wantKey:  "GET:/api/users",
			wantErr:  false,
		},
		{
			name:     "template with host",
			template: "{{.Host}}:{{.Method}}:{{.Path}}",
			request:  createTestRequestWithHost("GET", "/api/users", "example.com"),
			wantKey:  "example.com:GET:/api/users",
			wantErr:  false,
		},
		{
			name:     "template with query param",
			template: "{{.Method}}:{{.Path}}:{{index .Query \"page\"}}",
			request:  createTestRequest("GET", "/api/users", url.Values{"page": {"1"}}, nil, ""),
			wantKey:  "GET:/api/users:1",
			wantErr:  false,
		},
		{
			name:     "template with header",
			template: "{{.Method}}:{{.Path}}:{{index .Header \"X-Tenant-ID\"}}",
			request:  createTestRequest("GET", "/api/users", nil, http.Header{"X-Tenant-ID": {"tenant-123"}}, ""),
			wantKey:  "GET:/api/users:tenant-123",
			wantErr:  false,
		},
		{
			name:     "template with missing query param",
			template: "{{.Method}}:{{.Path}}:{{index .Query \"missing\"}}",
			request:  createTestRequest("GET", "/api/users", nil, nil, ""),
			wantKey:  "GET:/api/users:",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CacheKeyConfig{
				KeyTemplate: tt.template,
			}

			kg, err := NewKeyGenerator(cfg, observability.NopLogger())
			require.NoError(t, err)

			key, err := kg.GenerateKey(tt.request)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				if tt.wantKey != "" {
					assert.Equal(t, tt.wantKey, key)
				}

				for _, contain := range tt.wantContain {
					assert.Contains(t, key, contain)
				}
			}
		})
	}
}

func TestGenerateSimpleKey(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		wantKey string
	}{
		{
			name:    "GET request",
			method:  "GET",
			path:    "/api/users",
			wantKey: "GET:/api/users",
		},
		{
			name:    "POST request",
			method:  "POST",
			path:    "/api/users",
			wantKey: "POST:/api/users",
		},
		{
			name:    "empty method",
			method:  "",
			path:    "/api/users",
			wantKey: ":/api/users",
		},
		{
			name:    "empty path",
			method:  "GET",
			path:    "",
			wantKey: "GET:",
		},
		{
			name:    "root path",
			method:  "GET",
			path:    "/",
			wantKey: "GET:/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := GenerateSimpleKey(tt.method, tt.path)
			assert.Equal(t, tt.wantKey, key)
		})
	}
}

func TestHashKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{
			name: "simple key",
			key:  "GET:/api/users",
		},
		{
			name: "empty key",
			key:  "",
		},
		{
			name: "long key",
			key:  strings.Repeat("a", 1000),
		},
		{
			name: "key with special characters",
			key:  "GET:/api/users?page=1&limit=10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := HashKey(tt.key)

			// Hash should be 64 characters (SHA256 hex encoded)
			assert.Len(t, hash, 64)

			// Same input should produce same hash
			hash2 := HashKey(tt.key)
			assert.Equal(t, hash, hash2)

			// Different input should produce different hash
			if tt.key != "" {
				hash3 := HashKey(tt.key + "x")
				assert.NotEqual(t, hash, hash3)
			}
		})
	}
}

func TestSanitizeKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantKey string
	}{
		{
			name:    "no special characters",
			key:     "GET:/api/users",
			wantKey: "GET:/api/users",
		},
		{
			name:    "with spaces",
			key:     "GET:/api/users with spaces",
			wantKey: "GET:/api/users_with_spaces",
		},
		{
			name:    "with newlines",
			key:     "GET:/api/users\nwith\nnewlines",
			wantKey: "GET:/api/userswithnewlines",
		},
		{
			name:    "with carriage returns",
			key:     "GET:/api/users\rwith\rreturns",
			wantKey: "GET:/api/userswithreturns",
		},
		{
			name:    "with tabs",
			key:     "GET:/api/users\twith\ttabs",
			wantKey: "GET:/api/userswithtabs",
		},
		{
			name:    "with mixed whitespace",
			key:     "GET:/api/users \n\r\t mixed",
			wantKey: "GET:/api/users__mixed",
		},
		{
			name:    "empty key",
			key:     "",
			wantKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitized := SanitizeKey(tt.key)
			assert.Equal(t, tt.wantKey, sanitized)
		})
	}
}

func TestKeyGenerator_BodyHashRestoresBody(t *testing.T) {
	cfg := &config.CacheKeyConfig{
		IncludeMethod:   true,
		IncludePath:     true,
		IncludeBodyHash: true,
	}

	kg, err := NewKeyGenerator(cfg, observability.NopLogger())
	require.NoError(t, err)

	bodyContent := `{"name":"test","value":123}`
	req := createTestRequest("POST", "/api/users", nil, nil, bodyContent)

	// Generate key (which reads the body)
	_, err = kg.GenerateKey(req)
	require.NoError(t, err)

	// Body should still be readable
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, bodyContent, string(body))
}

func TestKeyGenerator_ConsistentOrdering(t *testing.T) {
	cfg := &config.CacheKeyConfig{
		IncludeMethod:      true,
		IncludePath:        true,
		IncludeQueryParams: []string{"z", "a", "m"},
		IncludeHeaders:     []string{"Z-Header", "A-Header", "M-Header"},
	}

	kg, err := NewKeyGenerator(cfg, observability.NopLogger())
	require.NoError(t, err)

	req := createTestRequest("GET", "/api/users",
		url.Values{"z": {"1"}, "a": {"2"}, "m": {"3"}},
		http.Header{"Z-Header": {"z"}, "A-Header": {"a"}, "M-Header": {"m"}},
		"")

	// Generate key multiple times
	key1, err := kg.GenerateKey(req)
	require.NoError(t, err)

	// Reset request for second call
	req = createTestRequest("GET", "/api/users",
		url.Values{"z": {"1"}, "a": {"2"}, "m": {"3"}},
		http.Header{"Z-Header": {"z"}, "A-Header": {"a"}, "M-Header": {"m"}},
		"")

	key2, err := kg.GenerateKey(req)
	require.NoError(t, err)

	// Keys should be identical
	assert.Equal(t, key1, key2)

	// Query params should be sorted alphabetically
	assert.Contains(t, key1, "a=2")
	assert.Contains(t, key1, "m=3")
	assert.Contains(t, key1, "z=1")
}

func TestReadCloser(t *testing.T) {
	content := []byte("test content")
	rc := &readCloser{Reader: bytes.NewReader(content)}

	// Read content
	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, content, data)

	// Close should not error
	err = rc.Close()
	assert.NoError(t, err)
}

// Helper functions

func createTestRequest(method, path string, query url.Values, headers http.Header, body string) *http.Request {
	u, _ := url.Parse("http://example.com" + path)
	if query != nil {
		u.RawQuery = query.Encode()
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, _ := http.NewRequest(method, u.String(), bodyReader)
	if headers != nil {
		req.Header = headers
	}

	return req
}

func createTestRequestWithHost(method, path, host string) *http.Request {
	req := createTestRequest(method, path, nil, nil, "")
	req.Host = host
	return req
}
