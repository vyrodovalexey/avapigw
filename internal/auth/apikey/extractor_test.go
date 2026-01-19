package apikey

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHeaderExtractor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		header         string
		prefix         string
		expectedHeader string
		expectedPrefix string
	}{
		{
			name:           "Default header",
			header:         "",
			prefix:         "",
			expectedHeader: "X-API-Key",
			expectedPrefix: "",
		},
		{
			name:           "Custom header",
			header:         "Authorization",
			prefix:         "",
			expectedHeader: "Authorization",
			expectedPrefix: "",
		},
		{
			name:           "Custom header and prefix",
			header:         "Authorization",
			prefix:         "ApiKey ",
			expectedHeader: "Authorization",
			expectedPrefix: "ApiKey ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewHeaderExtractor(tt.header, tt.prefix)
			assert.Equal(t, tt.expectedHeader, extractor.header)
			assert.Equal(t, tt.expectedPrefix, extractor.prefix)
		})
	}
}

func TestHeaderExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		header        string
		prefix        string
		headerValue   string
		expectedKey   string
		expectedError error
	}{
		{
			name:        "Valid API key",
			header:      "X-API-Key",
			prefix:      "",
			headerValue: "my-api-key-12345",
			expectedKey: "my-api-key-12345",
		},
		{
			name:        "Valid API key with prefix",
			header:      "Authorization",
			prefix:      "ApiKey ",
			headerValue: "ApiKey my-api-key-12345",
			expectedKey: "my-api-key-12345",
		},
		{
			name:        "API key with whitespace",
			header:      "X-API-Key",
			prefix:      "",
			headerValue: "  my-api-key-12345  ",
			expectedKey: "my-api-key-12345",
		},
		{
			name:          "Missing header",
			header:        "X-API-Key",
			prefix:        "",
			headerValue:   "",
			expectedError: ErrMissingAPIKeyHeader,
		},
		{
			name:          "Missing prefix",
			header:        "Authorization",
			prefix:        "ApiKey ",
			headerValue:   "Bearer token",
			expectedError: ErrMissingAPIKeyHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewHeaderExtractor(tt.header, tt.prefix)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.headerValue != "" {
				req.Header.Set(tt.header, tt.headerValue)
			}

			key, err := extractor.Extract(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedKey, key)
			}
		})
	}
}

func TestNewQueryExtractor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		param         string
		expectedParam string
	}{
		{
			name:          "Default param",
			param:         "",
			expectedParam: "api_key",
		},
		{
			name:          "Custom param",
			param:         "key",
			expectedParam: "key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewQueryExtractor(tt.param)
			assert.Equal(t, tt.expectedParam, extractor.param)
		})
	}
}

func TestQueryExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		param         string
		queryString   string
		expectedKey   string
		expectedError error
	}{
		{
			name:        "Valid query parameter",
			param:       "api_key",
			queryString: "api_key=my-api-key-12345",
			expectedKey: "my-api-key-12345",
		},
		{
			name:        "Multiple query parameters",
			param:       "api_key",
			queryString: "foo=bar&api_key=my-api-key&baz=qux",
			expectedKey: "my-api-key",
		},
		{
			name:          "Missing query parameter",
			param:         "api_key",
			queryString:   "other=value",
			expectedError: ErrMissingAPIKeyQuery,
		},
		{
			name:          "Empty query parameter",
			param:         "api_key",
			queryString:   "api_key=",
			expectedError: ErrMissingAPIKeyQuery,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewQueryExtractor(tt.param)

			req := httptest.NewRequest(http.MethodGet, "/?"+tt.queryString, nil)

			key, err := extractor.Extract(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedKey, key)
			}
		})
	}
}

func TestNewCompositeExtractor(t *testing.T) {
	t.Parallel()

	header := NewHeaderExtractor("X-API-Key", "")
	query := NewQueryExtractor("api_key")

	extractor := NewCompositeExtractor(header, query)
	assert.Len(t, extractor.extractors, 2)
}

func TestCompositeExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		setupRequest  func(*http.Request)
		expectedKey   string
		expectedError error
	}{
		{
			name: "Key from header",
			setupRequest: func(r *http.Request) {
				r.Header.Set("X-API-Key", "header-key")
			},
			expectedKey: "header-key",
		},
		{
			name: "Key from query when header missing",
			setupRequest: func(r *http.Request) {
				r.URL.RawQuery = "api_key=query-key"
			},
			expectedKey: "query-key",
		},
		{
			name: "Header takes precedence",
			setupRequest: func(r *http.Request) {
				r.Header.Set("X-API-Key", "header-key")
				r.URL.RawQuery = "api_key=query-key"
			},
			expectedKey: "header-key",
		},
		{
			name: "No key found",
			setupRequest: func(r *http.Request) {
				// No key set
			},
			expectedError: ErrMissingAPIKeyQuery,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewCompositeExtractor(
				NewHeaderExtractor("X-API-Key", ""),
				NewQueryExtractor("api_key"),
			)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tt.setupRequest(req)

			key, err := extractor.Extract(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedKey, key)
			}
		})
	}
}

func TestCompositeExtractor_Add(t *testing.T) {
	t.Parallel()

	extractor := NewCompositeExtractor()
	assert.Len(t, extractor.extractors, 0)

	extractor.Add(NewHeaderExtractor("X-API-Key", ""))
	assert.Len(t, extractor.extractors, 1)

	extractor.Add(NewQueryExtractor("api_key"))
	assert.Len(t, extractor.extractors, 2)
}

func TestCompositeExtractor_EmptyExtractors(t *testing.T) {
	t.Parallel()

	extractor := NewCompositeExtractor()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := extractor.Extract(req)
	assert.ErrorIs(t, err, ErrNoAPIKeyFound)
}

func TestDefaultExtractor(t *testing.T) {
	t.Parallel()

	extractor := DefaultExtractor()
	assert.NotNil(t, extractor)

	// Test with header
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "header-key")

	key, err := extractor.Extract(req)
	require.NoError(t, err)
	assert.Equal(t, "header-key", key)

	// Test with query parameter
	req = httptest.NewRequest(http.MethodGet, "/?api_key=query-key", nil)

	key, err = extractor.Extract(req)
	require.NoError(t, err)
	assert.Equal(t, "query-key", key)
}

func TestExtractorFunc(t *testing.T) {
	t.Parallel()

	customExtractor := ExtractorFunc(func(r *http.Request) (string, error) {
		return r.Header.Get("X-Custom-Key"), nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Custom-Key", "custom-key")

	key, err := customExtractor.Extract(req)
	require.NoError(t, err)
	assert.Equal(t, "custom-key", key)
}

func TestNewAuthorizationHeaderExtractor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		scheme         string
		expectedScheme string
	}{
		{
			name:           "Default scheme",
			scheme:         "",
			expectedScheme: "ApiKey",
		},
		{
			name:           "Custom scheme",
			scheme:         "Bearer",
			expectedScheme: "Bearer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewAuthorizationHeaderExtractor(tt.scheme)
			assert.Equal(t, tt.expectedScheme, extractor.scheme)
		})
	}
}

func TestAuthorizationHeaderExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		scheme        string
		headerValue   string
		expectedKey   string
		expectedError error
	}{
		{
			name:        "Valid ApiKey scheme",
			scheme:      "ApiKey",
			headerValue: "ApiKey my-api-key",
			expectedKey: "my-api-key",
		},
		{
			name:        "Case insensitive scheme",
			scheme:      "ApiKey",
			headerValue: "apikey my-api-key",
			expectedKey: "my-api-key",
		},
		{
			name:        "Key with whitespace",
			scheme:      "ApiKey",
			headerValue: "ApiKey   my-api-key  ",
			expectedKey: "my-api-key",
		},
		{
			name:          "Missing header",
			scheme:        "ApiKey",
			headerValue:   "",
			expectedError: ErrMissingAPIKeyHeader,
		},
		{
			name:          "Wrong scheme",
			scheme:        "ApiKey",
			headerValue:   "Bearer token",
			expectedError: ErrMissingAPIKeyHeader,
		},
		{
			name:          "Header too short",
			scheme:        "ApiKey",
			headerValue:   "Api",
			expectedError: ErrMissingAPIKeyHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewAuthorizationHeaderExtractor(tt.scheme)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.headerValue != "" {
				req.Header.Set("Authorization", tt.headerValue)
			}

			key, err := extractor.Extract(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedKey, key)
			}
		})
	}
}

func TestNewCookieExtractor(t *testing.T) {
	t.Parallel()

	extractor := NewCookieExtractor("api_key")
	assert.Equal(t, "api_key", extractor.cookie)
}

func TestCookieExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		cookieName    string
		cookieValue   string
		setCookie     bool
		expectedKey   string
		expectedError error
	}{
		{
			name:        "Valid cookie",
			cookieName:  "api_key",
			cookieValue: "my-api-key",
			setCookie:   true,
			expectedKey: "my-api-key",
		},
		{
			name:          "Missing cookie",
			cookieName:    "api_key",
			setCookie:     false,
			expectedError: ErrNoAPIKeyFound,
		},
		{
			name:          "Empty cookie value",
			cookieName:    "api_key",
			cookieValue:   "",
			setCookie:     true,
			expectedError: ErrNoAPIKeyFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewCookieExtractor(tt.cookieName)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.setCookie {
				req.AddCookie(&http.Cookie{
					Name:  tt.cookieName,
					Value: tt.cookieValue,
				})
			}

			key, err := extractor.Extract(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedKey, key)
			}
		})
	}
}

// Test error variables
func TestExtractorErrorVariables(t *testing.T) {
	t.Parallel()

	assert.NotNil(t, ErrNoAPIKeyFound)
	assert.NotNil(t, ErrMissingAPIKeyHeader)
	assert.NotNil(t, ErrMissingAPIKeyQuery)

	assert.Equal(t, "no API key found", ErrNoAPIKeyFound.Error())
	assert.Equal(t, "missing API key header", ErrMissingAPIKeyHeader.Error())
	assert.Equal(t, "missing API key query parameter", ErrMissingAPIKeyQuery.Error())
}

// Benchmark tests
func BenchmarkHeaderExtractor_Extract(b *testing.B) {
	extractor := NewHeaderExtractor("X-API-Key", "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "my-api-key-12345")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractor.Extract(req)
	}
}

func BenchmarkQueryExtractor_Extract(b *testing.B) {
	extractor := NewQueryExtractor("api_key")
	req := httptest.NewRequest(http.MethodGet, "/?api_key=my-api-key-12345", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractor.Extract(req)
	}
}

func BenchmarkCompositeExtractor_Extract(b *testing.B) {
	extractor := NewCompositeExtractor(
		NewHeaderExtractor("X-API-Key", ""),
		NewQueryExtractor("api_key"),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "my-api-key-12345")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractor.Extract(req)
	}
}
