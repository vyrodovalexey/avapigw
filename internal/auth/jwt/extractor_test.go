package jwt

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
			name:           "Default values",
			header:         "",
			prefix:         "",
			expectedHeader: "Authorization",
			expectedPrefix: "Bearer ",
		},
		{
			name:           "Custom header",
			header:         "X-Token",
			prefix:         "",
			expectedHeader: "X-Token",
			expectedPrefix: "Bearer ",
		},
		{
			name:           "Custom prefix",
			header:         "",
			prefix:         "Token ",
			expectedHeader: "Authorization",
			expectedPrefix: "Token ",
		},
		{
			name:           "Custom header and prefix",
			header:         "X-Auth",
			prefix:         "JWT ",
			expectedHeader: "X-Auth",
			expectedPrefix: "JWT ",
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
		expectedToken string
		expectedError error
	}{
		{
			name:          "Valid Bearer token",
			header:        "Authorization",
			prefix:        "Bearer ",
			headerValue:   "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			name:          "Valid Bearer token lowercase",
			header:        "Authorization",
			prefix:        "Bearer ",
			headerValue:   "bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			name:          "Valid token with custom prefix",
			header:        "Authorization",
			prefix:        "Token ",
			headerValue:   "Token abc123",
			expectedToken: "abc123",
		},
		{
			name:          "Token with extra whitespace",
			header:        "Authorization",
			prefix:        "Bearer ",
			headerValue:   "Bearer   eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9  ",
			expectedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			name:          "No prefix required - custom header",
			header:        "X-Token",
			prefix:        "Token ",
			headerValue:   "Token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			name:          "Missing header",
			header:        "Authorization",
			prefix:        "Bearer ",
			headerValue:   "",
			expectedError: ErrMissingHeader,
		},
		{
			name:          "Invalid prefix",
			header:        "Authorization",
			prefix:        "Bearer ",
			headerValue:   "Basic abc123",
			expectedError: ErrInvalidPrefix,
		},
		{
			name:          "Header too short for prefix",
			header:        "Authorization",
			prefix:        "Bearer ",
			headerValue:   "Bear",
			expectedError: ErrInvalidPrefix,
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

			token, err := extractor.Extract(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

func TestNewCookieExtractor(t *testing.T) {
	t.Parallel()

	extractor := NewCookieExtractor("access_token")
	assert.Equal(t, "access_token", extractor.cookie)
}

func TestCookieExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		cookieName    string
		cookieValue   string
		setCookie     bool
		expectedToken string
		expectedError error
	}{
		{
			name:          "Valid cookie",
			cookieName:    "access_token",
			cookieValue:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			setCookie:     true,
			expectedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			name:          "Missing cookie",
			cookieName:    "access_token",
			setCookie:     false,
			expectedError: ErrMissingCookie,
		},
		{
			name:          "Empty cookie value",
			cookieName:    "access_token",
			cookieValue:   "",
			setCookie:     true,
			expectedError: ErrMissingCookie,
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

			token, err := extractor.Extract(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

func TestNewQueryExtractor(t *testing.T) {
	t.Parallel()

	extractor := NewQueryExtractor("token")
	assert.Equal(t, "token", extractor.param)
}

func TestQueryExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		paramName     string
		queryString   string
		expectedToken string
		expectedError error
	}{
		{
			name:          "Valid query parameter",
			paramName:     "access_token",
			queryString:   "access_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			name:          "Missing query parameter",
			paramName:     "access_token",
			queryString:   "other_param=value",
			expectedError: ErrMissingQueryParam,
		},
		{
			name:          "Empty query parameter",
			paramName:     "access_token",
			queryString:   "access_token=",
			expectedError: ErrMissingQueryParam,
		},
		{
			name:          "Multiple query parameters",
			paramName:     "token",
			queryString:   "foo=bar&token=abc123&baz=qux",
			expectedToken: "abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewQueryExtractor(tt.paramName)

			req := httptest.NewRequest(http.MethodGet, "/?"+tt.queryString, nil)

			token, err := extractor.Extract(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

func TestNewCompositeExtractor(t *testing.T) {
	t.Parallel()

	header := NewHeaderExtractor("Authorization", "Bearer ")
	query := NewQueryExtractor("access_token")

	extractor := NewCompositeExtractor(header, query)
	assert.Len(t, extractor.extractors, 2)
}

func TestCompositeExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		setupRequest  func(*http.Request)
		expectedToken string
		expectedError error
	}{
		{
			name: "Token from header",
			setupRequest: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer header_token")
			},
			expectedToken: "header_token",
		},
		{
			name: "Token from query when header missing",
			setupRequest: func(r *http.Request) {
				r.URL.RawQuery = "access_token=query_token"
			},
			expectedToken: "query_token",
		},
		{
			name: "Header takes precedence over query",
			setupRequest: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer header_token")
				r.URL.RawQuery = "access_token=query_token"
			},
			expectedToken: "header_token",
		},
		{
			name: "No token found",
			setupRequest: func(r *http.Request) {
				// No token set
			},
			expectedError: ErrMissingQueryParam, // Last error from the chain
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewCompositeExtractor(
				NewHeaderExtractor("Authorization", "Bearer "),
				NewQueryExtractor("access_token"),
			)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tt.setupRequest(req)

			token, err := extractor.Extract(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

func TestCompositeExtractor_Add(t *testing.T) {
	t.Parallel()

	extractor := NewCompositeExtractor()
	assert.Len(t, extractor.extractors, 0)

	extractor.Add(NewHeaderExtractor("Authorization", "Bearer "))
	assert.Len(t, extractor.extractors, 1)

	extractor.Add(NewQueryExtractor("access_token"))
	assert.Len(t, extractor.extractors, 2)
}

func TestCompositeExtractor_EmptyExtractors(t *testing.T) {
	t.Parallel()

	extractor := NewCompositeExtractor()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := extractor.Extract(req)
	assert.ErrorIs(t, err, ErrNoTokenFound)
}

func TestDefaultExtractor(t *testing.T) {
	t.Parallel()

	extractor := DefaultExtractor()
	assert.NotNil(t, extractor)

	// Test with header
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer header_token")

	token, err := extractor.Extract(req)
	require.NoError(t, err)
	assert.Equal(t, "header_token", token)

	// Test with query parameter
	req = httptest.NewRequest(http.MethodGet, "/?access_token=query_token", nil)

	token, err = extractor.Extract(req)
	require.NoError(t, err)
	assert.Equal(t, "query_token", token)
}

func TestExtractorFunc(t *testing.T) {
	t.Parallel()

	customExtractor := ExtractorFunc(func(r *http.Request) (string, error) {
		return r.Header.Get("X-Custom-Token"), nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Custom-Token", "custom_token")

	token, err := customExtractor.Extract(req)
	require.NoError(t, err)
	assert.Equal(t, "custom_token", token)
}

func TestNewMetadataExtractor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		key            string
		prefix         string
		expectedKey    string
		expectedPrefix string
	}{
		{
			name:           "Default key",
			key:            "",
			prefix:         "",
			expectedKey:    "authorization",
			expectedPrefix: "",
		},
		{
			name:           "Custom key",
			key:            "x-auth-token",
			prefix:         "",
			expectedKey:    "x-auth-token",
			expectedPrefix: "",
		},
		{
			name:           "Custom key and prefix",
			key:            "authorization",
			prefix:         "Bearer ",
			expectedKey:    "authorization",
			expectedPrefix: "Bearer ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewMetadataExtractor(tt.key, tt.prefix)
			assert.Equal(t, tt.expectedKey, extractor.key)
			assert.Equal(t, tt.expectedPrefix, extractor.prefix)
		})
	}
}

func TestMetadataExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		key           string
		prefix        string
		headerKey     string
		headerValue   string
		expectedToken string
		expectedError error
	}{
		{
			name:          "Valid metadata",
			key:           "authorization",
			prefix:        "Bearer ",
			headerKey:     "authorization",
			headerValue:   "Bearer token123",
			expectedToken: "token123",
		},
		{
			name:          "Lowercase header lookup",
			key:           "Authorization",
			prefix:        "",
			headerKey:     "authorization",
			headerValue:   "token123",
			expectedToken: "token123",
		},
		{
			name:          "No prefix",
			key:           "x-token",
			prefix:        "",
			headerKey:     "x-token",
			headerValue:   "token123",
			expectedToken: "token123",
		},
		{
			name:          "Missing header",
			key:           "authorization",
			prefix:        "",
			headerKey:     "",
			headerValue:   "",
			expectedError: ErrMissingHeader,
		},
		{
			name:          "Invalid prefix",
			key:           "authorization",
			prefix:        "Bearer ",
			headerKey:     "authorization",
			headerValue:   "Basic token123",
			expectedError: ErrInvalidPrefix,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewMetadataExtractor(tt.key, tt.prefix)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.headerKey != "" {
				req.Header.Set(tt.headerKey, tt.headerValue)
			}

			token, err := extractor.Extract(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

func TestNewFormExtractor(t *testing.T) {
	t.Parallel()

	extractor := NewFormExtractor("token")
	assert.Equal(t, "token", extractor.field)
}

func TestFormExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		fieldName     string
		formData      url.Values
		expectedToken string
		expectedError error
	}{
		{
			name:      "Valid form field",
			fieldName: "access_token",
			formData: url.Values{
				"access_token": []string{"form_token"},
			},
			expectedToken: "form_token",
		},
		{
			name:      "Missing form field",
			fieldName: "access_token",
			formData: url.Values{
				"other_field": []string{"value"},
			},
			expectedError: ErrNoTokenFound,
		},
		{
			name:      "Empty form field",
			fieldName: "access_token",
			formData: url.Values{
				"access_token": []string{""},
			},
			expectedError: ErrNoTokenFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractor := NewFormExtractor(tt.fieldName)

			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			token, err := extractor.Extract(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}
